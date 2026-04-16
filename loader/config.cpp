/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Control Plane - Configuration Parsing & Validation
 */

#include "tachyon.h"

/* ══════════════════════════════════════════════════════════════════════════
 * INI Config Parser
 *
 * Parses WireGuard-style INI files with [Section] headers.
 * Keys are stored both as "Section.Key" and bare "Key" for flexibility.
 * ══════════════════════════════════════════════════════════════════════════ */

static std::unordered_map<std::string, std::string> parse_ini(const std::string &filename)
{
    std::unordered_map<std::string, std::string> kv;
    std::ifstream file(filename);

    if (!file.is_open()) {
        LOG_ERR("Cannot open config file: %s", filename.c_str());
        return kv;
    }

    std::string line, section;
    int lineno = 0;

    while (std::getline(file, line)) {
        lineno++;
        line = trim(line);

        if (line.empty() || line[0] == '#' || line[0] == ';')
            continue;

        /* Section header */
        if (line.front() == '[' && line.back() == ']') {
            section = line.substr(1, line.size() - 2) + ".";
            continue;
        }

        /* Key = Value */
        auto pos = line.find('=');
        if (pos == std::string::npos) {
            LOG_WARN("Config line %d: missing '=' separator", lineno);
            continue;
        }

        std::string key = trim(line.substr(0, pos));
        std::string val = trim(line.substr(pos + 1));

        kv[section + key] = val;
        kv[key] = val; /* Allow lookup without section prefix */
    }

    return kv;
}

/* Helper: look up a key with fallback alias */
static std::string get_val(const std::unordered_map<std::string, std::string> &kv,
                           const std::string &primary, const std::string &fallback = "")
{
    auto it = kv.find(primary);
    if (it != kv.end())
        return it->second;
    if (!fallback.empty()) {
        it = kv.find(fallback);
        if (it != kv.end())
            return it->second;
    }
    return "";
}

TunnelConfig parse_config(const std::string &filename) {
    auto kv = parse_ini(filename);
    TunnelConfig cfg;

    cfg.name = tunnel_name_from_conf(filename);
    cfg.private_key = get_val(kv, "PrivateKey");
    cfg.peer_public_key = get_val(kv, "PeerPublicKey");
    cfg.psk = get_val(kv, "PresharedKey", "Secret");
    cfg.virtual_ip = get_val(kv, "VirtualIP", "Interface.VirtualIP");
    cfg.local_physical_ip = get_val(kv, "LocalPhysicalIP", "LocalIP");
    cfg.physical_interface = get_val(kv, "PhysicalInterface", "PhysIface");
    cfg.peer_endpoint_ip = get_val(kv, "Peer.EndpointIP", "Endpoint");
    cfg.peer_endpoint_mac = get_val(kv, "Peer.EndpointMAC", "PeerMAC");
    cfg.peer_inner_ip = get_val(kv, "Peer.InnerIP", "InnerIP");

    std::string port_str = get_val(kv, "ListenPort");
    if (!port_str.empty()) {
        try {
            cfg.listen_port = std::stoi(port_str);
        } catch (const std::exception &) {
            LOG_WARN("Invalid ListenPort '%s', using default %d", port_str.c_str(),
                     cfg.listen_port);
        }
    }

    std::string mimicry_str = get_val(kv, "MimicryType");
    if (!mimicry_str.empty()) {
        try {
            cfg.mimicry_type = std::stoi(mimicry_str);
        } catch (const std::exception &) {
            LOG_WARN("Invalid MimicryType '%s', using default %d", mimicry_str.c_str(),
                     cfg.mimicry_type);
        }
    }

    std::string enc_str = get_val(kv, "EnableEncryption");
    if (enc_str == "false" || enc_str == "0")
        cfg.encryption = false;

    return cfg;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Config Validation
 * ══════════════════════════════════════════════════════════════════════════ */

bool validate_config(const TunnelConfig &cfg) {
    bool ok = true;
    auto check = [&](bool cond, const char *msg) {
        if (!cond) {
            LOG_ERR("Config: %s", msg);
            ok = false;
        }
    };

    check(!cfg.private_key.empty(), "PrivateKey is required (64 hex chars)");
    check(cfg.private_key.size() == 64 || cfg.private_key.empty(),
          "PrivateKey must be exactly 64 hex characters");
    check(!cfg.peer_public_key.empty(), "PeerPublicKey is required (64 hex chars)");
    check(cfg.peer_public_key.size() == 64 || cfg.peer_public_key.empty(),
          "PeerPublicKey must be exactly 64 hex characters");
    check(!cfg.virtual_ip.empty(), "VirtualIP is required (e.g. 10.8.0.1/24)");
    check(!cfg.local_physical_ip.empty(), "LocalPhysicalIP is required");
    check(!cfg.physical_interface.empty(), "PhysicalInterface is required (e.g. eth0)");
    check(!cfg.peer_endpoint_ip.empty(), "Peer.EndpointIP is required");
    check(!cfg.peer_endpoint_mac.empty(), "Peer.EndpointMAC is required (e.g. aa:bb:cc:dd:ee:ff)");
    check(!cfg.peer_inner_ip.empty(), "Peer.InnerIP is required (e.g. 10.8.0.2)");
    check(cfg.listen_port > 0 && cfg.listen_port < 65536, "ListenPort must be 1-65535");

    /* Validate MAC format */
    if (!cfg.peer_endpoint_mac.empty()) {
        uint8_t mac[6];
        check(parse_mac(cfg.peer_endpoint_mac, mac),
              "Peer.EndpointMAC format invalid (expected xx:xx:xx:xx:xx:xx)");
    }

    /* Validate IP format */
    if (!cfg.peer_endpoint_ip.empty()) {
        struct in_addr tmp;
        check(inet_pton(AF_INET, cfg.peer_endpoint_ip.c_str(), &tmp) == 1,
              "Peer.EndpointIP is not a valid IPv4 address");
    }

    return ok;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Tunnel Name Extraction
 * ══════════════════════════════════════════════════════════════════════════ */

std::string tunnel_name_from_conf(const std::string &conf_path) {
    std::string name = conf_path;

    /* Strip directory prefix */
    size_t p = name.find_last_of('/');
    if (p != std::string::npos)
        name = name.substr(p + 1);

    /* Strip file extension */
    p = name.find('.');
    if (p != std::string::npos)
        name = name.substr(0, p);

    return name;
}
