/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Control Plane - Tunnel Lifecycle Management
 *
 * Implements tunnel up/down/show commands: creates veth pairs, loads BPF
 * programs, initializes maps, and launches the control plane protocol.
 */

#include "tachyon.h"
#include <cerrno>

static void sig_handler(int) {
    g_exiting = 1;
}

/* ══════════════════════════════════════════════════════════════════════════
 * command_up - Create tunnel and start control plane
 * ══════════════════════════════════════════════════════════════════════════ */

void command_up(const std::string &conf_file) {
    TunnelConfig cfg = parse_config(conf_file);
    if (!validate_config(cfg))
        return;

    std::string bpf_dir = std::string(TACHYON_BPF_PIN_BASE) + "/" + cfg.name;
    struct stat st;
    if (stat(bpf_dir.c_str(), &st) == 0) {
        LOG_ERR("Tunnel '%s' already exists. Run 'down' first.", cfg.name.c_str());
        return;
    }

    std::string v_in = "t_" + cfg.name + "_in";
    std::string v_out = "t_" + cfg.name + "_out";

    /* Create veth pair */
    LOG_INFO("Creating data plane for tunnel '%s'...", cfg.name.c_str());
    if (!run_cmd("ip link add " + v_in + " type veth peer name " + v_out)) {
        LOG_ERR("Failed to create veth pair");
        return;
    }

    /* Configure interfaces */
    run_cmd("ip link set dev " + v_in + " mtu " + std::to_string(TACHYON_TUNNEL_MTU));
    run_cmd("ip link set dev " + v_out + " mtu " + std::to_string(TACHYON_TUNNEL_MTU));
    run_cmd("ip link set dev " + v_in + " arp off");
    run_cmd("ip link set dev " + v_out + " arp off");
    run_cmd("ip addr add " + cfg.virtual_ip + " peer " + cfg.peer_inner_ip + " dev " + v_in);
    run_cmd("ip link set dev " + v_in + " up");
    run_cmd("ip link set dev " + v_out + " up");
    run_cmd("sysctl -qw net.ipv4.conf.all.rp_filter=0");
    run_cmd("sysctl -qw net.ipv4.conf." + v_in + ".rp_filter=0");

    /* Resolve interface indices */
    unsigned int p_idx = if_nametoindex(cfg.physical_interface.c_str());
    unsigned int o_idx = if_nametoindex(v_out.c_str());
    unsigned int i_idx = if_nametoindex(v_in.c_str());

    if (!p_idx || !o_idx || !i_idx) {
        LOG_ERR("Failed to resolve interface indices (phys=%u, out=%u, in=%u)", p_idx, o_idx,
                i_idx);
        run_cmd("ip link del " + v_in, /*quiet=*/true);
        return;
    }

    /* Locate XDP object relative to executable */
    char exe_path[PATH_MAX];
    ssize_t exe_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (exe_len <= 0) {
        LOG_ERR("Failed to resolve executable path");
        run_cmd("ip link del " + v_in, /*quiet=*/true);
        return;
    }
    exe_path[exe_len] = '\0';
    std::string base_dir(exe_path);
    base_dir = base_dir.substr(0, base_dir.find_last_of('/'));
    std::string xdp_obj_path = base_dir + "/../src/xdp_core.o";
    struct stat xdp_st;
    if (stat(xdp_obj_path.c_str(), &xdp_st) != 0) {
        xdp_obj_path = base_dir + "/xdp_core.o";
        if (stat(xdp_obj_path.c_str(), &xdp_st) != 0)
            xdp_obj_path = "/usr/lib/tachyon/xdp_core.o";
    }

    /* Load BPF object */
    struct bpf_object *obj = bpf_object__open_file(xdp_obj_path.c_str(), nullptr);
    if (!obj) {
        LOG_ERR("Failed to open BPF object: %s", xdp_obj_path.c_str());
        run_cmd("ip link del " + v_in, /*quiet=*/true);
        return;
    }

    if (bpf_object__load(obj)) {
        LOG_ERR("Failed to load BPF object into kernel");
        bpf_object__close(obj);
        run_cmd("ip link del " + v_in, /*quiet=*/true);
        return;
    }

    /* Pin maps to BPF filesystem */
    run_cmd("mkdir -p " + bpf_dir);
    if (bpf_object__pin_maps(obj, bpf_dir.c_str())) {
        LOG_ERR("Failed to pin BPF maps to %s", bpf_dir.c_str());
    }

    /* Initialize config map */
    struct bpf_map *config_m = bpf_object__find_map_by_name(obj, "config_map");
    if (config_m) {
        int fd = bpf_map__fd(config_m);
        uint32_t zero = 0;
        userspace_config g{};
        g.listen_port_net = htons(cfg.listen_port);
        g.mimicry_type = cfg.mimicry_type;
        g.obfs_flags = cfg.obfs_flags;
        bpf_map_update_elem(fd, &zero, &g, BPF_ANY);
    }

    /* Initialize tx_port devmap */
    struct bpf_map *tx_m = bpf_object__find_map_by_name(obj, "tx_port");
    if (tx_m) {
        int fd = bpf_map__fd(tx_m);
        uint32_t k0 = TACHYON_TXPORT_VETH, k1 = TACHYON_TXPORT_PHYS;
        bpf_map_update_elem(fd, &k0, &o_idx, BPF_ANY);
        bpf_map_update_elem(fd, &k1, &p_idx, BPF_ANY);
    }

    /* Initialize session map */
    uint32_t session_id = 1;
    userspace_session sess{};
    inet_pton(AF_INET, cfg.peer_endpoint_ip.c_str(), &sess.peer_ip);
    struct in_addr la;
    inet_pton(AF_INET, cfg.local_physical_ip.c_str(), &la);
    sess.local_ip = la.s_addr;
    parse_mac(cfg.peer_endpoint_mac, sess.peer_mac);

    struct bpf_map *sess_m = bpf_object__find_map_by_name(obj, "session_map");
    if (sess_m)
        bpf_map_update_elem(bpf_map__fd(sess_m), &session_id, &sess, BPF_ANY);

    /* Initialize IP-to-session map */
    uint32_t inner_net;
    inet_pton(AF_INET, cfg.peer_inner_ip.c_str(), &inner_net);
    struct bpf_map *ipsess_m = bpf_object__find_map_by_name(obj, "ip_to_session_map");
    if (ipsess_m)
        bpf_map_update_elem(bpf_map__fd(ipsess_m), &inner_net, &session_id, BPF_ANY);

    /* Attach XDP programs with all-or-nothing transaction semantics.
     * A partial attach leaves the kernel in a half-armed state where packets
     * hit one side's BPF hook but not the other, silently dropping traffic.
     * If any attachment fails, detach everything we already armed. */
    auto attach_xdp = [&](const char *prog_name, unsigned int ifidx, const char *pin_name) -> bool {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
        if (!prog) {
            LOG_ERR("BPF program '%s' not found", prog_name);
            return false;
        }
        int prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            LOG_ERR("Invalid fd for '%s'", prog_name);
            return false;
        }
        if (bpf_xdp_attach(ifidx, prog_fd, 0, NULL) < 0) {
            LOG_ERR("Failed to attach '%s' to ifindex %u", prog_name, ifidx);
            return false;
        }
        /* Pin program fd for later detach */
        std::string pin_path = bpf_dir + "/" + pin_name;
        bpf_program__pin(prog, pin_path.c_str());
        return true;
    };

    unsigned int attached_ifaces[3];
    int attached_count = 0;
    auto rollback_attach = [&]() {
        for (int i = 0; i < attached_count; i++)
            bpf_xdp_attach(attached_ifaces[i], -1, 0, NULL);
        bpf_object__close(obj);
        run_cmd("ip link del " + v_in, /*quiet=*/true);
    };

    if (!attach_xdp("xdp_rx_path", p_idx, "rx")) {
        rollback_attach();
        return;
    }
    attached_ifaces[attached_count++] = p_idx;

    if (!attach_xdp("xdp_tx_path", o_idx, "tx")) {
        rollback_attach();
        return;
    }
    attached_ifaces[attached_count++] = o_idx;

    if (!attach_xdp("xdp_dummy", i_idx, "dummy")) {
        rollback_attach();
        return;
    }
    attached_ifaces[attached_count++] = i_idx;

    LOG_INFO("Datapath UP: %s <-> %s (phys: %s, port: %d)", v_in.c_str(),
             cfg.peer_endpoint_ip.c_str(), cfg.physical_interface.c_str(), cfg.listen_port);

    /* Install signal handlers and run control plane */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    uint32_t peer_ip_net = sess.peer_ip;
    uint32_t local_ip_net = sess.local_ip;
    uint8_t p_mac[6];
    memcpy(p_mac, sess.peer_mac, 6);

    run_control_plane(obj, cfg, session_id, peer_ip_net, local_ip_net, p_mac);

    LOG_INFO("Daemon stopped. XDP datapath remains active.");
}

/* ══════════════════════════════════════════════════════════════════════════
 * command_down - Tear down tunnel
 * ══════════════════════════════════════════════════════════════════════════ */

void command_down(const std::string &conf_file) {
    std::string name = tunnel_name_from_conf(conf_file);
    std::string bpf_dir = std::string(TACHYON_BPF_PIN_BASE) + "/" + name;

    run_cmd("ip link del t_" + name + "_in", /*quiet=*/true);
    run_cmd("rm -rf " + bpf_dir, /*quiet=*/true);
    LOG_INFO("Tunnel '%s' torn down.", name.c_str());
}

/* ══════════════════════════════════════════════════════════════════════════
 * command_show - Display tunnel statistics
 * ══════════════════════════════════════════════════════════════════════════ */

void command_show(const std::string &conf_file) {
    std::string name = tunnel_name_from_conf(conf_file);
    std::string bpf_dir = std::string(TACHYON_BPF_PIN_BASE) + "/" + name;

    struct stat st;
    if (stat(bpf_dir.c_str(), &st) != 0) {
        LOG_ERR("Tunnel '%s' is not running.", name.c_str());
        return;
    }

    /* Open pinned stats map */
    std::string stats_path = bpf_dir + "/stats_map";
    int fd = bpf_obj_get(stats_path.c_str());
    if (fd < 0) {
        LOG_ERR("Cannot open stats map: %s", stats_path.c_str());
        return;
    }

    /* Read per-CPU values and aggregate */
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) {
        LOG_ERR("Cannot determine CPU count");
        close(fd);
        return;
    }

    std::vector<userspace_stats> per_cpu(ncpus);
    uint32_t zero = 0;
    if (bpf_map_lookup_elem(fd, &zero, per_cpu.data()) != 0) {
        LOG_ERR("Failed to read stats map");
        close(fd);
        return;
    }
    close(fd);

    /* Aggregate across CPUs */
    userspace_stats total{};
    for (int i = 0; i < ncpus; i++) {
        total.rx_packets += per_cpu[i].rx_packets;
        total.rx_bytes += per_cpu[i].rx_bytes;
        total.tx_packets += per_cpu[i].tx_packets;
        total.tx_bytes += per_cpu[i].tx_bytes;
        total.rx_replay_drops += per_cpu[i].rx_replay_drops;
        total.rx_crypto_errors += per_cpu[i].rx_crypto_errors;
        total.rx_invalid_session += per_cpu[i].rx_invalid_session;
        total.rx_malformed += per_cpu[i].rx_malformed;
        total.rx_ratelimit_drops += per_cpu[i].rx_ratelimit_drops;
        total.tx_crypto_errors += per_cpu[i].tx_crypto_errors;
        total.tx_headroom_errors += per_cpu[i].tx_headroom_errors;
        total.tx_ratelimit_drops += per_cpu[i].tx_ratelimit_drops;
        total.rx_ratelimit_data_drops += per_cpu[i].rx_ratelimit_data_drops;
        total.rx_roam_events += per_cpu[i].rx_roam_events;
    }

    printf("\n  Tachyon Tunnel: %s\n", name.c_str());
    printf("  %-24s %s\n", "Interface:", ("t_" + name + "_in").c_str());
    printf("\n  %-24s %" PRIu64 " packets, %" PRIu64 " bytes\n", "TX:", total.tx_packets,
           total.tx_bytes);
    printf("  %-24s %" PRIu64 " packets, %" PRIu64 " bytes\n", "RX:", total.rx_packets,
           total.rx_bytes);
    printf("\n  Errors:\n");
    printf("    %-22s %" PRIu64 "\n", "Replay drops:", total.rx_replay_drops);
    printf("    %-22s %" PRIu64 "\n", "RX crypto errors:", total.rx_crypto_errors);
    printf("    %-22s %" PRIu64 "\n", "TX crypto errors:", total.tx_crypto_errors);
    printf("    %-22s %" PRIu64 "\n", "Invalid session:", total.rx_invalid_session);
    printf("    %-22s %" PRIu64 "\n", "Malformed packets:", total.rx_malformed);
    printf("    %-22s %" PRIu64 "\n", "CP rate-limited:", total.rx_ratelimit_drops);
    printf("    %-22s %" PRIu64 "\n", "TX rate-limited:", total.tx_ratelimit_drops);
    printf("    %-22s %" PRIu64 "\n", "RX rate-limited:", total.rx_ratelimit_data_drops);
    printf("    %-22s %" PRIu64 "\n", "TX headroom:", total.tx_headroom_errors);
    printf("    %-22s %" PRIu64 "\n", "Roaming events:", total.rx_roam_events);
    printf("\n");
}
