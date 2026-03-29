// SPDX-License-Identifier: GPL
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
MODULE_AUTHOR("Tachyon Team");
MODULE_DESCRIPTION("Twin-Engine XDP Fast-Path Crypto (TX/RX Split)");

#define MAX_SESSIONS 256
#define GHOST_HDR_LEN 20
#define ETH_IP_UDP_LEN 48
#define POLY1305_TAG_LEN 16
#define MIN_PACKET_LEN 78

/* ── رفع هشدار نبود Prototype (Warning: no previous prototype) ── */
int bpf_ghost_set_key(u32 session_id, u8 *tx_key, u32 tx_key__sz, u8 *rx_key, u32 rx_key__sz);
int bpf_ghost_encrypt(struct xdp_md *ctx, u32 session_id);
int bpf_ghost_decrypt(struct xdp_md *ctx, u32 session_id);

/* ── ساختار جدید: ۴ موتور برای پشتیبانی کامل از کلیدهای مجزای ارسال و دریافت ── */
struct session_engine {
    struct crypto_aead *tfm_tx_primary;
    struct crypto_aead *tfm_tx_secondary;
    struct crypto_aead *tfm_rx_primary;
    struct crypto_aead *tfm_rx_secondary;
    struct crypto_aead __rcu *active_tx_tfm;
    struct crypto_aead __rcu *active_rx_tfm;
    spinlock_t lock;
    u8 key_set;                     
    u8 pad[3];
} ____cacheline_aligned;           

static struct session_engine engines[MAX_SESSIONS];
static struct crypto_aead *dummy_tfm;

DEFINE_PER_CPU(struct aead_request *, ghost_req);

struct ghost_hdr {
    u8  quic_flags;
    u8  pad[3];
    u32 session_id;
    u64 seq;
    u32 nonce_salt;
} __packed __aligned(4);

/* ==================== HELPER FUNCTIONS ==================== */

static __always_inline int ghost_build_iv(struct ghost_hdr *gh, u8 *iv) {
    u64 seq_le = cpu_to_le64(be64_to_cpu(gh->seq));
    memcpy(iv, &gh->nonce_salt, 4);
    memcpy(iv + 4, &seq_le, 8);
    return 0;
}

/* ==================== KFUNCS ==================== */

__bpf_kfunc int bpf_ghost_set_key(u32 session_id, u8 *tx_key, u32 tx_key__sz, u8 *rx_key, u32 rx_key__sz)
{
    struct session_engine *se;
    struct crypto_aead *standby_tx, *standby_rx;
    unsigned long flags;
    int ret;

    if (unlikely(session_id >= MAX_SESSIONS || tx_key__sz != 32 || rx_key__sz != 32)) 
        return -EINVAL;

    se = &engines[session_id];
    if (!se->tfm_tx_primary) return -ENODEV;

    spin_lock_irqsave(&se->lock, flags);
    
    /* پیدا کردن موتورهای TX و RX که الان در حال کار نیستند */
    if (rcu_dereference_protected(se->active_tx_tfm, lockdep_is_held(&se->lock)) == se->tfm_tx_primary) {
        standby_tx = se->tfm_tx_secondary;
        standby_rx = se->tfm_rx_secondary;
    } else {
        standby_tx = se->tfm_tx_primary;
        standby_rx = se->tfm_rx_primary;
    }

    /* ست کردن کلید روی موتورهای خاموش */
    ret = crypto_aead_setkey(standby_tx, tx_key, 32);
    if (ret) goto out;
    crypto_aead_setauthsize(standby_tx, POLY1305_TAG_LEN);

    ret = crypto_aead_setkey(standby_rx, rx_key, 32);
    if (ret) goto out;
    crypto_aead_setauthsize(standby_rx, POLY1305_TAG_LEN);

    /* سوئیچ کردن موتورها! (Zero Downtime) */
    rcu_assign_pointer(se->active_tx_tfm, standby_tx);
    rcu_assign_pointer(se->active_rx_tfm, standby_rx);
    se->key_set = 1;
    
out:
    spin_unlock_irqrestore(&se->lock, flags);
    return ret;
}

__bpf_kfunc int bpf_ghost_encrypt(struct xdp_md *ctx, u32 session_id)
{
    struct xdp_buff *xdp = (struct xdp_buff *)(void *)ctx;
    struct aead_request *req;
    struct scatterlist sg;
    struct crypto_aead *tfm;
    struct ghost_hdr *gh;
    u32 total_len, cryptlen;
    u8 iv[12];
    int ret;

    if (unlikely(!xdp || session_id >= MAX_SESSIONS)) 
        return -EINVAL;

    rcu_read_lock();
    
    struct session_engine *se = &engines[session_id];
    tfm = rcu_dereference(se->active_tx_tfm); /* استفاده از موتور TX */
    if (unlikely(!tfm)) { 
        rcu_read_unlock(); 
        return -ENOKEY; 
    }

    void *data = xdp->data;
    void *data_end = xdp->data_end;
    
    if (unlikely(data + MIN_PACKET_LEN > data_end)) { 
        rcu_read_unlock(); 
        return -EINVAL; 
    }

    total_len = data_end - data;
    cryptlen = total_len - ETH_IP_UDP_LEN - GHOST_HDR_LEN - POLY1305_TAG_LEN;
    gh = (struct ghost_hdr *)(data + ETH_IP_UDP_LEN);

    ghost_build_iv(gh, iv);
    
    sg_init_one(&sg, data + ETH_IP_UDP_LEN, total_len - ETH_IP_UDP_LEN);

    req = this_cpu_read(ghost_req);
    if (unlikely(!req)) {
        rcu_read_unlock();
        return -ENOMEM;
    }

    aead_request_set_tfm(req, tfm);
    aead_request_set_callback(req, 0, NULL, NULL);
    aead_request_set_crypt(req, &sg, &sg, cryptlen, iv);
    aead_request_set_ad(req, GHOST_HDR_LEN);

    ret = crypto_aead_encrypt(req);
    rcu_read_unlock();
    return ret;
}

__bpf_kfunc int bpf_ghost_decrypt(struct xdp_md *ctx, u32 session_id)
{
    struct xdp_buff *xdp = (struct xdp_buff *)(void *)ctx;
    struct aead_request *req;
    struct scatterlist sg;
    struct crypto_aead *tfm;
    struct ghost_hdr *gh;
    u32 total_len, cryptlen;
    u8 iv[12];
    int ret;

    if (unlikely(!xdp || session_id >= MAX_SESSIONS)) 
        return -EINVAL;

    rcu_read_lock();
    
    struct session_engine *se = &engines[session_id];
    tfm = rcu_dereference(se->active_rx_tfm); /* استفاده از موتور RX */
    if (unlikely(!tfm)) { 
        rcu_read_unlock(); 
        return -ENOKEY; 
    }

    void *data = xdp->data;
    void *data_end = xdp->data_end;
    
    if (unlikely(data + MIN_PACKET_LEN > data_end)) { 
        rcu_read_unlock(); 
        return -EINVAL; 
    }

    total_len = data_end - data;
    cryptlen = total_len - ETH_IP_UDP_LEN - GHOST_HDR_LEN;
    gh = (struct ghost_hdr *)(data + ETH_IP_UDP_LEN);

    ghost_build_iv(gh, iv);
    
    sg_init_one(&sg, data + ETH_IP_UDP_LEN, total_len - ETH_IP_UDP_LEN);

    req = this_cpu_read(ghost_req);
    if (unlikely(!req)) {
        rcu_read_unlock();
        return -ENOMEM;
    }

    aead_request_set_tfm(req, tfm);
    aead_request_set_callback(req, 0, NULL, NULL);
    aead_request_set_crypt(req, &sg, &sg, cryptlen, iv);
    aead_request_set_ad(req, GHOST_HDR_LEN);

    ret = crypto_aead_decrypt(req);
    rcu_read_unlock();
    return ret;
}

/* ================ ثبت Kfuncها ================ */
BTF_SET8_START(ghost_kfunc_ids)
BTF_ID_FLAGS(func, bpf_ghost_encrypt)   
BTF_ID_FLAGS(func, bpf_ghost_decrypt)   
BTF_ID_FLAGS(func, bpf_ghost_set_key)   
BTF_SET8_END(ghost_kfunc_ids)

static const struct btf_kfunc_id_set ghost_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &ghost_kfunc_ids,
};

/* ==================== INIT & CLEANUP ==================== */

static void cleanup_session(int i) {
    if (engines[i].tfm_tx_primary) { crypto_free_aead(engines[i].tfm_tx_primary); engines[i].tfm_tx_primary = NULL; }
    if (engines[i].tfm_tx_secondary) { crypto_free_aead(engines[i].tfm_tx_secondary); engines[i].tfm_tx_secondary = NULL; }
    if (engines[i].tfm_rx_primary) { crypto_free_aead(engines[i].tfm_rx_primary); engines[i].tfm_rx_primary = NULL; }
    if (engines[i].tfm_rx_secondary) { crypto_free_aead(engines[i].tfm_rx_secondary); engines[i].tfm_rx_secondary = NULL; }
}

static int __init ghost_crypto_init(void) {
    int cpu, ret = 0, i;
    
    printk(KERN_INFO "Tachyon Crypto: Initializing Twin-Engine (TX/RX)...\n");
    
    dummy_tfm = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
    if (IS_ERR(dummy_tfm)) {
        pr_err("Tachyon: Failed to allocate dummy tfm\n");
        return PTR_ERR(dummy_tfm);
    }
    crypto_aead_setauthsize(dummy_tfm, POLY1305_TAG_LEN);
    
    for_each_possible_cpu(cpu) {
        per_cpu(ghost_req, cpu) = aead_request_alloc(dummy_tfm, GFP_KERNEL);
        if (!per_cpu(ghost_req, cpu)) {
            ret = -ENOMEM;
            goto err_cleanup_requests;
        }
    }

    /* ساخت ۴ موتور برای هر سشن */
    for (i = 0; i < MAX_SESSIONS; i++) {
        spin_lock_init(&engines[i].lock);
                
        engines[i].tfm_tx_primary = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
        if (IS_ERR(engines[i].tfm_tx_primary)) { ret = PTR_ERR(engines[i].tfm_tx_primary); engines[i].tfm_tx_primary = NULL; goto err_cleanup_sessions; }
        crypto_aead_setauthsize(engines[i].tfm_tx_primary, POLY1305_TAG_LEN);

        engines[i].tfm_tx_secondary = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
        if (IS_ERR(engines[i].tfm_tx_secondary)) { ret = PTR_ERR(engines[i].tfm_tx_secondary); engines[i].tfm_tx_secondary = NULL; goto err_cleanup_sessions; }
        crypto_aead_setauthsize(engines[i].tfm_tx_secondary, POLY1305_TAG_LEN);

        engines[i].tfm_rx_primary = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
        if (IS_ERR(engines[i].tfm_rx_primary)) { ret = PTR_ERR(engines[i].tfm_rx_primary); engines[i].tfm_rx_primary = NULL; goto err_cleanup_sessions; }
        crypto_aead_setauthsize(engines[i].tfm_rx_primary, POLY1305_TAG_LEN);

        engines[i].tfm_rx_secondary = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
        if (IS_ERR(engines[i].tfm_rx_secondary)) { ret = PTR_ERR(engines[i].tfm_rx_secondary); engines[i].tfm_rx_secondary = NULL; goto err_cleanup_sessions; }
        crypto_aead_setauthsize(engines[i].tfm_rx_secondary, POLY1305_TAG_LEN);
        
        RCU_INIT_POINTER(engines[i].active_tx_tfm, NULL);
        RCU_INIT_POINTER(engines[i].active_rx_tfm, NULL);
        engines[i].key_set = 0;
    }

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &ghost_kfunc_set);
    if (ret) goto err_cleanup_sessions;

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &ghost_kfunc_set);
    if (ret) goto err_cleanup_sessions;

    printk(KERN_INFO "Tachyon Crypto: Twin-Engine armed with %d sessions\n", MAX_SESSIONS);
    return 0;

err_cleanup_sessions:
    /* حلقه پاکسازی به گونه‌ای نوشته شده که در صورت خطا (Memory Leak) رخ ندهد */
    for (; i >= 0; i--) {
        cleanup_session(i);
    }

err_cleanup_requests:
    for_each_possible_cpu(cpu) {
        if (per_cpu(ghost_req, cpu)) {
            aead_request_free(per_cpu(ghost_req, cpu));
            per_cpu(ghost_req, cpu) = NULL;
        }
    }
    crypto_free_aead(dummy_tfm);
    
    return ret;
}

static void __exit ghost_crypto_exit(void) {
    int cpu, i;
    for_each_possible_cpu(cpu) {
        if (per_cpu(ghost_req, cpu)) {
            aead_request_free(per_cpu(ghost_req, cpu));
            per_cpu(ghost_req, cpu) = NULL;
        }
    }
    crypto_free_aead(dummy_tfm);

    for (i = 0; i < MAX_SESSIONS; i++) {
        cleanup_session(i);
    }
    printk(KERN_INFO "Tachyon Crypto: Unloaded.\n");
}

module_init(ghost_crypto_init);
module_exit(ghost_crypto_exit);