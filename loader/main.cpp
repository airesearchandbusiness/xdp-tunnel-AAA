/* SPDX-License-Identifier: MIT */
/*
 * Tachyon XDP Tunnel - CLI Entry Point
 *
 * Usage:
 *   tachyon up <config>     - Create tunnel and start control plane
 *   tachyon down <config>   - Tear down tunnel
 *   tachyon show <config>   - Display tunnel statistics
 *   tachyon genkey          - Generate X25519 private key (hex)
 *   tachyon pubkey          - Derive public key from private (stdin)
 */

#include "tachyon.h"

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Tachyon XDP Tunnel v%d.0\n\n"
            "Usage:\n"
            "  %s up <config.conf>     Create tunnel and start daemon\n"
            "  %s down <config.conf>   Tear down tunnel\n"
            "  %s show <config.conf>   Display tunnel statistics\n"
            "  %s genkey               Generate X25519 private key\n"
            "  %s pubkey               Derive public key (reads private from stdin)\n",
            TACHYON_PROTO_VERSION, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    /* ── Key generation (no config file needed) ── */
    if (cmd == "genkey") {
        uint8_t priv[TACHYON_X25519_KEY_LEN], pub[TACHYON_X25519_KEY_LEN];
        if (!generate_x25519_keypair(priv, pub)) {
            LOG_ERR("Key generation failed");
            return 1;
        }
        for (int i = 0; i < TACHYON_X25519_KEY_LEN; i++)
            printf("%02x", priv[i]);
        printf("\n");
        OPENSSL_cleanse(priv, sizeof(priv));
        return 0;
    }

    if (cmd == "pubkey") {
        std::string priv_hex;
        if (!(std::cin >> priv_hex)) {
            LOG_ERR("No private key provided on stdin");
            return 1;
        }
        uint8_t priv[TACHYON_X25519_KEY_LEN];
        if (!hex2bin(priv_hex, priv, TACHYON_X25519_KEY_LEN)) {
            LOG_ERR("Invalid private key: expected %d hex characters", TACHYON_X25519_KEY_LEN * 2);
            return 1;
        }
        uint8_t pub[TACHYON_X25519_KEY_LEN];
        if (!get_public_key(priv, pub)) {
            OPENSSL_cleanse(priv, sizeof(priv));
            return 1;
        }
        for (int i = 0; i < TACHYON_X25519_KEY_LEN; i++)
            printf("%02x", pub[i]);
        printf("\n");
        OPENSSL_cleanse(priv, sizeof(priv));
        OPENSSL_cleanse(pub, sizeof(pub));
        return 0;
    }

    /* ── Commands requiring a config file ── */
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string conf = argv[2];

    if (cmd == "up")
        command_up(conf);
    else if (cmd == "down")
        command_down(conf);
    else if (cmd == "show")
        command_show(conf);
    else {
        LOG_ERR("Unknown command: %s", cmd.c_str());
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
