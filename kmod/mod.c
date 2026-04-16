// SPDX-License-Identifier: GPL-2.0
/*
 * Tachyon Crypto Engine - Kernel Module
 *
 * Provides high-performance ChaCha20-Poly1305 AEAD encryption/decryption
 * as BPF kfuncs callable from XDP programs. Features twin-engine architecture
 * with separate TX/RX crypto transforms and zero-downtime key rotation via
 * RCU-protected active transform pointers.
 *
 * Architecture:
 *   Each session has 4 AEAD transforms (TX primary/secondary, RX primary/
 *   secondary). Key rotation sets the standby engine then atomically swaps
 *   the RCU pointer, so in-flight packets complete on the old key while
 *   new packets use the new key.
 *
 * Exported kfuncs:
 *   bpf_ghost_encrypt()  - Encrypt XDP packet payload with session TX key
 *   bpf_ghost_decrypt()  - Decrypt and authenticate with session RX key
 *   bpf_ghost_set_key()  - Install new session keys with atomic switchover
 */

#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <crypto/aead.h>
#include <linux/scatterlist.h>
#include <linux/percpu.h>
#include <linux/byteorder/generic.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <net/xdp.h>
#include <linux/random.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tachyon Project");
MODULE_DESCRIPTION("Tachyon XDP Fast-Path Crypto Engine (Twin TX/RX)");
MODULE_VERSION("1.1");

/* ══════════════════════════════════════════════════════════════════════════
 * Configuration Constants
 * ══════════════════════════════════════════════════════════════════════════ */

#define TACHYON_MAX_SESSIONS    256
#define TACHYON_GHOST_HDR_LEN   20
#define TACHYON_OUTER_HDR_LEN   48       /* ETH(14) + IP(20) + UDP(8) + Ghost reuses inner ETH */
#define TACHYON_TAG_LEN         16       /* Poly1305 authentication tag    */
#define TACHYON_KEY_LEN         32       /* ChaCha20 key size              */
#define TACHYON_IV_LEN          12       /* ChaCha20-Poly1305 nonce size   */
#define TACHYON_MIN_PACKET_LEN  (TACHYON_OUTER_HDR_LEN + TACHYON_GHOST_HDR_LEN + TACHYON_TAG_LEN)
#define TACHYON_CIPHER_CHACHA    "rfc7539(chacha20,poly1305)"
#define TACHYON_CIPHER_AES_GCM   "gcm(aes)"

#define TACHYON_CIPHER_TYPE_CHACHA20    0
#define TACHYON_CIPHER_TYPE_AES128_GCM  1
#define TACHYON_CIPHER_TYPE_AES256_GCM  2

#define TACHYON_CIPHER_NAME     TACHYON_CIPHER_CHACHA
#define TACHYON_LOG_PREFIX      "tachyon_crypto: "

/* Module parameters */
static int max_sessions = TACHYON_MAX_SESSIONS;
module_param(max_sessions, int, 0444);
MODULE_PARM_DESC(max_sessions, "Maximum number of concurrent sessions (default: 256)");

/* Forward declarations for kfunc prototypes (suppresses -Wmissing-prototypes) */
int bpf_ghost_set_key(u32 session_id, u8 *tx_key, u32 tx_key__sz,
		      u8 *rx_key, u32 rx_key__sz);
int bpf_ghost_encrypt(struct xdp_md *ctx, u32 session_id);
int bpf_ghost_decrypt(struct xdp_md *ctx, u32 session_id);
int bpf_ghost_set_cipher(u32 session_id, u32 cipher_type);

/* ══════════════════════════════════════════════════════════════════════════
 * Session Engine - Per-Session Crypto State
 *
 * Twin-engine design: primary and secondary transforms for both directions.
 * The active_*_tfm pointers are RCU-protected for lock-free hot-path reads.
 * The spinlock protects key rotation (cold path only).
 * ══════════════════════════════════════════════════════════════════════════ */

struct session_engine {
	struct crypto_aead *tfm_tx_primary;
	struct crypto_aead *tfm_tx_secondary;
	struct crypto_aead *tfm_rx_primary;
	struct crypto_aead *tfm_rx_secondary;

	struct crypto_aead __rcu *active_tx_tfm;
	struct crypto_aead __rcu *active_rx_tfm;

	spinlock_t lock;                       /* Protects key rotation          */
	u8  key_set;                           /* Non-zero after first key load  */
	u8  cipher_type;                       /* TACHYON_CIPHER_TYPE_*          */
	u8  _pad[2];
} ____cacheline_aligned;

static struct session_engine engines[TACHYON_MAX_SESSIONS];

/*
 * Dummy transform used solely for sizing the per-CPU aead_request allocations.
 * The actual per-request transform is set dynamically via aead_request_set_tfm().
 */
static struct crypto_aead *req_template_tfm;

DEFINE_PER_CPU(struct aead_request *, tachyon_aead_req);

/* ══════════════════════════════════════════════════════════════════════════
 * Ghost Header (must match struct tachyon_ghost_hdr in common.h)
 * Duplicated here to avoid userspace header dependencies in kernel module.
 * ══════════════════════════════════════════════════════════════════════════ */

struct ghost_hdr {
	u8  quic_flags;
	u8  pad[3];
	u32 session_id;
	u64 seq;
	u32 nonce_salt;
} __packed __aligned(4);

/* ══════════════════════════════════════════════════════════════════════════
 * Helper Functions
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * Build the 12-byte IV for ChaCha20-Poly1305 from the ghost header fields.
 * IV layout: [nonce_salt : 4 bytes][sequence_le : 8 bytes]
 *
 * Using the per-packet random nonce_salt combined with the monotonic sequence
 * number ensures IV uniqueness even across key rotation windows.
 */
static __always_inline void ghost_build_iv(const struct ghost_hdr *gh, u8 *iv)
{
	u64 seq_le = cpu_to_le64(be64_to_cpu(gh->seq));

	memcpy(iv, &gh->nonce_salt, 4);
	memcpy(iv + 4, &seq_le, 8);
}

/*
 * Allocate a single AEAD transform with the configured cipher and tag size.
 * Returns the transform or an ERR_PTR on failure.
 */
static struct crypto_aead *alloc_aead_tfm(void)
{
	struct crypto_aead *tfm;

	tfm = crypto_alloc_aead(TACHYON_CIPHER_NAME, 0, 0);
	if (IS_ERR(tfm))
		return tfm;

	crypto_aead_setauthsize(tfm, TACHYON_TAG_LEN);
	return tfm;
}

/* ══════════════════════════════════════════════════════════════════════════
 * BPF Kfuncs - Exported to XDP and Syscall BPF Programs
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * bpf_ghost_set_key - Install new session keys with zero-downtime rotation
 *
 * @session_id: Target session index (0..MAX_SESSIONS-1)
 * @tx_key:     32-byte transmit key
 * @tx_key__sz: Must be 32
 * @rx_key:     32-byte receive key
 * @rx_key__sz: Must be 32
 *
 * Determines which engine pair (primary/secondary) is currently standby,
 * sets the new keys on the standby engines, then atomically swaps the
 * active pointers via rcu_assign_pointer(). In-flight crypto operations
 * complete on the old key; new operations pick up the new key.
 *
 * Returns 0 on success, negative errno on failure.
 */
__bpf_kfunc int bpf_ghost_set_key(u32 session_id, u8 *tx_key, u32 tx_key__sz,
				   u8 *rx_key, u32 rx_key__sz)
{
	struct session_engine *se;
	struct crypto_aead *standby_tx, *standby_rx;
	unsigned long flags;
	int ret;

	if (unlikely(session_id >= TACHYON_MAX_SESSIONS))
		return -EINVAL;
	if (unlikely(tx_key__sz != TACHYON_KEY_LEN || rx_key__sz != TACHYON_KEY_LEN))
		return -EINVAL;

	se = &engines[session_id];
	if (unlikely(!se->tfm_tx_primary))
		return -ENODEV;

	spin_lock_irqsave(&se->lock, flags);

	/* Identify the standby engine pair (whichever is NOT active) */
	if (rcu_dereference_protected(se->active_tx_tfm,
				      lockdep_is_held(&se->lock)) == se->tfm_tx_primary) {
		standby_tx = se->tfm_tx_secondary;
		standby_rx = se->tfm_rx_secondary;
	} else {
		standby_tx = se->tfm_tx_primary;
		standby_rx = se->tfm_rx_primary;
	}

	/* Load keys onto standby engines */
	ret = crypto_aead_setkey(standby_tx, tx_key, TACHYON_KEY_LEN);
	if (ret) {
		pr_err_ratelimited(TACHYON_LOG_PREFIX
			"session %u: TX key set failed (%d)\n", session_id, ret);
		goto out;
	}
	/* authsize already set at allocation time in alloc_aead_tfm() */

	ret = crypto_aead_setkey(standby_rx, rx_key, TACHYON_KEY_LEN);
	if (ret) {
		pr_err_ratelimited(TACHYON_LOG_PREFIX
			"session %u: RX key set failed (%d)\n", session_id, ret);
		goto out;
	}

	/* Atomic switchover - zero downtime */
	rcu_assign_pointer(se->active_tx_tfm, standby_tx);
	rcu_assign_pointer(se->active_rx_tfm, standby_rx);
	se->key_set = 1;

	pr_info_ratelimited(TACHYON_LOG_PREFIX
		"session %u: keys rotated successfully\n", session_id);

out:
	spin_unlock_irqrestore(&se->lock, flags);
	return ret;
}

/*
 * bpf_ghost_set_cipher - Change the cipher algorithm for a session
 *
 * @session_id: Target session
 * @cipher_type: TACHYON_CIPHER_TYPE_CHACHA20, _AES128_GCM, or _AES256_GCM
 *
 * Reallocates all four AEAD transforms with the new cipher algorithm.
 * Must be called before bpf_ghost_set_key when changing ciphers.
 * Uses spinlock to ensure atomicity with key rotation.
 */
__bpf_kfunc int bpf_ghost_set_cipher(u32 session_id, u32 cipher_type)
{
	struct session_engine *se;
	const char *cipher_name;
	u32 key_len;
	unsigned long flags;
	int ret = 0;

	if (unlikely(session_id >= TACHYON_MAX_SESSIONS))
		return -EINVAL;

	switch (cipher_type) {
	case TACHYON_CIPHER_TYPE_CHACHA20:
		cipher_name = TACHYON_CIPHER_CHACHA;
		key_len = 32;
		break;
	case TACHYON_CIPHER_TYPE_AES128_GCM:
		cipher_name = TACHYON_CIPHER_AES_GCM;
		key_len = 16;
		break;
	case TACHYON_CIPHER_TYPE_AES256_GCM:
		cipher_name = TACHYON_CIPHER_AES_GCM;
		key_len = 32;
		break;
	default:
		return -EINVAL;
	}

	se = &engines[session_id];
	spin_lock_irqsave(&se->lock, flags);

	/* Only reallocate if cipher actually changed */
	if (se->cipher_type == cipher_type) {
		spin_unlock_irqrestore(&se->lock, flags);
		return 0;
	}

	/* Deactivate current transforms */
	RCU_INIT_POINTER(se->active_tx_tfm, NULL);
	RCU_INIT_POINTER(se->active_rx_tfm, NULL);
	se->key_set = 0;

	spin_unlock_irqrestore(&se->lock, flags);
	synchronize_rcu();

	/* Free old transforms */
	destroy_session_engine(se);

	/* Allocate new transforms with the selected cipher */
	spin_lock_init(&se->lock);

	se->tfm_tx_primary = crypto_alloc_aead(cipher_name, 0, 0);
	if (IS_ERR(se->tfm_tx_primary)) { ret = PTR_ERR(se->tfm_tx_primary); se->tfm_tx_primary = NULL; goto err; }
	crypto_aead_setauthsize(se->tfm_tx_primary, TACHYON_TAG_LEN);

	se->tfm_tx_secondary = crypto_alloc_aead(cipher_name, 0, 0);
	if (IS_ERR(se->tfm_tx_secondary)) { ret = PTR_ERR(se->tfm_tx_secondary); se->tfm_tx_secondary = NULL; goto err; }
	crypto_aead_setauthsize(se->tfm_tx_secondary, TACHYON_TAG_LEN);

	se->tfm_rx_primary = crypto_alloc_aead(cipher_name, 0, 0);
	if (IS_ERR(se->tfm_rx_primary)) { ret = PTR_ERR(se->tfm_rx_primary); se->tfm_rx_primary = NULL; goto err; }
	crypto_aead_setauthsize(se->tfm_rx_primary, TACHYON_TAG_LEN);

	se->tfm_rx_secondary = crypto_alloc_aead(cipher_name, 0, 0);
	if (IS_ERR(se->tfm_rx_secondary)) { ret = PTR_ERR(se->tfm_rx_secondary); se->tfm_rx_secondary = NULL; goto err; }
	crypto_aead_setauthsize(se->tfm_rx_secondary, TACHYON_TAG_LEN);

	RCU_INIT_POINTER(se->active_tx_tfm, NULL);
	RCU_INIT_POINTER(se->active_rx_tfm, NULL);
	se->cipher_type = cipher_type;

	pr_info(TACHYON_LOG_PREFIX "session %u: cipher changed to %s\n",
		session_id, cipher_name);
	return 0;

err:
	destroy_session_engine(se);
	pr_err(TACHYON_LOG_PREFIX "session %u: cipher change failed (%d)\n",
	       session_id, ret);
	return ret;
}

/*
 * bpf_ghost_encrypt - Encrypt an XDP packet in-place
 *
 * @ctx:        XDP metadata (cast to xdp_buff internally)
 * @session_id: Session whose TX key to use
 *
 * Encrypts the payload portion of an already-encapsulated packet.
 * The ghost header serves as AEAD associated data (authenticated but
 * not encrypted). The Poly1305 tag is appended in the pre-allocated
 * tail space.
 *
 * Packet layout expected:
 *   [Outer ETH+IP+UDP (48B)][Ghost HDR (20B)][Payload...][Space for TAG (16B)]
 *
 * Returns 0 on success, negative errno on failure.
 */
__bpf_kfunc int bpf_ghost_encrypt(struct xdp_md *ctx, u32 session_id)
{
	struct xdp_buff *xdp = (struct xdp_buff *)(void *)ctx;
	struct session_engine *se;
	struct aead_request *req;
	struct crypto_aead *tfm;
	struct scatterlist sg;
	struct ghost_hdr *gh;
	u8  iv[TACHYON_IV_LEN];
	u32 total_len, cryptlen;
	int ret;

	if (unlikely(!xdp || session_id >= TACHYON_MAX_SESSIONS))
		return -EINVAL;

	rcu_read_lock();

	se = &engines[session_id];
	tfm = rcu_dereference(se->active_tx_tfm);
	if (unlikely(!tfm)) {
		rcu_read_unlock();
		return -ENOKEY;
	}

	if (unlikely(xdp->data + TACHYON_MIN_PACKET_LEN > xdp->data_end)) {
		rcu_read_unlock();
		return -EINVAL;
	}

	total_len = xdp->data_end - xdp->data;
	cryptlen  = total_len - TACHYON_OUTER_HDR_LEN - TACHYON_GHOST_HDR_LEN - TACHYON_TAG_LEN;
	gh = (struct ghost_hdr *)(xdp->data + TACHYON_OUTER_HDR_LEN);

	ghost_build_iv(gh, iv);

	/* Single scatterlist covering ghost header + payload + tag space */
	sg_init_one(&sg, xdp->data + TACHYON_OUTER_HDR_LEN,
		     total_len - TACHYON_OUTER_HDR_LEN);

	req = this_cpu_read(tachyon_aead_req);
	if (unlikely(!req)) {
		rcu_read_unlock();
		return -ENOMEM;
	}

	aead_request_set_tfm(req, tfm);
	/* Callback set once at module init — no per-packet overhead */
	aead_request_set_crypt(req, &sg, &sg, cryptlen, iv);
	aead_request_set_ad(req, TACHYON_GHOST_HDR_LEN);

	ret = crypto_aead_encrypt(req);

	rcu_read_unlock();
	return ret;
}

/*
 * bpf_ghost_decrypt - Decrypt and authenticate an XDP packet in-place
 *
 * @ctx:        XDP metadata
 * @session_id: Session whose RX key to use
 *
 * Decrypts the payload and verifies the Poly1305 authentication tag.
 * On authentication failure, returns an error and the packet should be
 * dropped (potential tampering or wrong key).
 *
 * Returns 0 on success (authentic), negative errno on failure.
 */
__bpf_kfunc int bpf_ghost_decrypt(struct xdp_md *ctx, u32 session_id)
{
	struct xdp_buff *xdp = (struct xdp_buff *)(void *)ctx;
	struct session_engine *se;
	struct aead_request *req;
	struct crypto_aead *tfm;
	struct scatterlist sg;
	struct ghost_hdr *gh;
	u8  iv[TACHYON_IV_LEN];
	u32 total_len, cryptlen;
	int ret;

	if (unlikely(!xdp || session_id >= TACHYON_MAX_SESSIONS))
		return -EINVAL;

	rcu_read_lock();

	se = &engines[session_id];
	tfm = rcu_dereference(se->active_rx_tfm);
	if (unlikely(!tfm)) {
		rcu_read_unlock();
		return -ENOKEY;
	}

	if (unlikely(xdp->data + TACHYON_MIN_PACKET_LEN > xdp->data_end)) {
		rcu_read_unlock();
		return -EINVAL;
	}

	total_len = xdp->data_end - xdp->data;
	cryptlen  = total_len - TACHYON_OUTER_HDR_LEN - TACHYON_GHOST_HDR_LEN;
	gh = (struct ghost_hdr *)(xdp->data + TACHYON_OUTER_HDR_LEN);

	ghost_build_iv(gh, iv);

	sg_init_one(&sg, xdp->data + TACHYON_OUTER_HDR_LEN,
		     total_len - TACHYON_OUTER_HDR_LEN);

	req = this_cpu_read(tachyon_aead_req);
	if (unlikely(!req)) {
		rcu_read_unlock();
		return -ENOMEM;
	}

	aead_request_set_tfm(req, tfm);
	/* Callback set once at module init — no per-packet overhead */
	aead_request_set_crypt(req, &sg, &sg, cryptlen, iv);
	aead_request_set_ad(req, TACHYON_GHOST_HDR_LEN);

	ret = crypto_aead_decrypt(req);

	rcu_read_unlock();
	return ret;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Kfunc Registration
 * ══════════════════════════════════════════════════════════════════════════ */

BTF_SET8_START(tachyon_kfunc_ids)
BTF_ID_FLAGS(func, bpf_ghost_encrypt)
BTF_ID_FLAGS(func, bpf_ghost_decrypt)
BTF_ID_FLAGS(func, bpf_ghost_set_key)
BTF_ID_FLAGS(func, bpf_ghost_set_cipher)
BTF_SET8_END(tachyon_kfunc_ids)

static const struct btf_kfunc_id_set tachyon_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &tachyon_kfunc_ids,
};

/* ══════════════════════════════════════════════════════════════════════════
 * Session Engine Lifecycle
 * ══════════════════════════════════════════════════════════════════════════ */

static void destroy_session_engine(struct session_engine *se)
{
	if (se->tfm_tx_primary) {
		crypto_free_aead(se->tfm_tx_primary);
		se->tfm_tx_primary = NULL;
	}
	if (se->tfm_tx_secondary) {
		crypto_free_aead(se->tfm_tx_secondary);
		se->tfm_tx_secondary = NULL;
	}
	if (se->tfm_rx_primary) {
		crypto_free_aead(se->tfm_rx_primary);
		se->tfm_rx_primary = NULL;
	}
	if (se->tfm_rx_secondary) {
		crypto_free_aead(se->tfm_rx_secondary);
		se->tfm_rx_secondary = NULL;
	}
}

static int init_session_engine(struct session_engine *se)
{
	int ret;

	spin_lock_init(&se->lock);

	se->tfm_tx_primary = alloc_aead_tfm();
	if (IS_ERR(se->tfm_tx_primary)) {
		ret = PTR_ERR(se->tfm_tx_primary);
		se->tfm_tx_primary = NULL;
		return ret;
	}

	se->tfm_tx_secondary = alloc_aead_tfm();
	if (IS_ERR(se->tfm_tx_secondary)) {
		ret = PTR_ERR(se->tfm_tx_secondary);
		se->tfm_tx_secondary = NULL;
		goto err;
	}

	se->tfm_rx_primary = alloc_aead_tfm();
	if (IS_ERR(se->tfm_rx_primary)) {
		ret = PTR_ERR(se->tfm_rx_primary);
		se->tfm_rx_primary = NULL;
		goto err;
	}

	se->tfm_rx_secondary = alloc_aead_tfm();
	if (IS_ERR(se->tfm_rx_secondary)) {
		ret = PTR_ERR(se->tfm_rx_secondary);
		se->tfm_rx_secondary = NULL;
		goto err;
	}

	RCU_INIT_POINTER(se->active_tx_tfm, NULL);
	RCU_INIT_POINTER(se->active_rx_tfm, NULL);
	se->key_set = 0;

	return 0;

err:
	destroy_session_engine(se);
	return ret;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Module Init / Exit
 * ══════════════════════════════════════════════════════════════════════════ */

static int __init tachyon_crypto_init(void)
{
	int cpu, ret, i;

	pr_info(TACHYON_LOG_PREFIX "initializing twin-engine crypto (%d sessions)\n",
		TACHYON_MAX_SESSIONS);

	/* Allocate template transform for per-CPU request sizing */
	req_template_tfm = alloc_aead_tfm();
	if (IS_ERR(req_template_tfm)) {
		pr_err(TACHYON_LOG_PREFIX "failed to allocate template transform\n");
		return PTR_ERR(req_template_tfm);
	}

	/* Allocate per-CPU AEAD requests with callback pre-set (avoids per-packet overhead) */
	for_each_possible_cpu(cpu) {
		struct aead_request *req = aead_request_alloc(req_template_tfm, GFP_KERNEL);
		if (!req) {
			pr_err(TACHYON_LOG_PREFIX "failed to allocate request for CPU %d\n", cpu);
			ret = -ENOMEM;
			goto err_free_requests;
		}
		aead_request_set_callback(req, 0, NULL, NULL);
		per_cpu(tachyon_aead_req, cpu) = req;
	}

	/* Initialize all session engines with pre-allocated transforms */
	for (i = 0; i < TACHYON_MAX_SESSIONS; i++) {
		ret = init_session_engine(&engines[i]);
		if (ret) {
			pr_err(TACHYON_LOG_PREFIX "failed to init session %d (%d)\n", i, ret);
			goto err_free_sessions;
		}
	}

	/* Register kfuncs for XDP programs */
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &tachyon_kfunc_set);
	if (ret) {
		pr_err(TACHYON_LOG_PREFIX "failed to register XDP kfuncs (%d)\n", ret);
		goto err_free_sessions;
	}

	/* Register kfuncs for syscall programs (key injection) */
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &tachyon_kfunc_set);
	if (ret) {
		pr_err(TACHYON_LOG_PREFIX "failed to register syscall kfuncs (%d)\n", ret);
		goto err_free_sessions;
	}

	pr_info(TACHYON_LOG_PREFIX "ready: %d sessions, twin-engine %s\n",
		TACHYON_MAX_SESSIONS, TACHYON_CIPHER_NAME);
	return 0;

err_free_sessions:
	for (i = i - 1; i >= 0; i--)
		destroy_session_engine(&engines[i]);

err_free_requests:
	for_each_possible_cpu(cpu) {
		struct aead_request *req = per_cpu(tachyon_aead_req, cpu);
		if (req) {
			aead_request_free(req);
			per_cpu(tachyon_aead_req, cpu) = NULL;
		}
	}
	crypto_free_aead(req_template_tfm);

	return ret;
}

static void __exit tachyon_crypto_exit(void)
{
	int cpu, i;

	/* Wait for any in-flight RCU readers to complete */
	synchronize_rcu();

	for_each_possible_cpu(cpu) {
		struct aead_request *req = per_cpu(tachyon_aead_req, cpu);
		if (req) {
			aead_request_free(req);
			per_cpu(tachyon_aead_req, cpu) = NULL;
		}
	}
	crypto_free_aead(req_template_tfm);

	for (i = 0; i < TACHYON_MAX_SESSIONS; i++)
		destroy_session_engine(&engines[i]);

	pr_info(TACHYON_LOG_PREFIX "unloaded\n");
}

module_init(tachyon_crypto_init);
module_exit(tachyon_crypto_exit);
