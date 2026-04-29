/* SPDX-License-Identifier: MIT */
/*
 * DNS-over-HTTPS wire-format mimicry (RFC 8484 + DNS wire format).
 *
 * Wraps tunnel payloads inside DNS message bodies that look like
 * legitimate DoH queries/responses. DPI sees HTTP/2 POST requests to
 * /dns-query with Content-Type: application/dns-message — the exact
 * traffic pattern produced by Firefox, Chrome, and system-level DoH
 * resolvers. This is extremely hard to block without also blocking
 * all DNS-over-HTTPS (which would break modern browsers).
 *
 * DNS message layout (RFC 1035 §4.1):
 *   ┌─ Header (12 bytes) ─────────────────────┐
 *   │  ID, Flags, QDCOUNT, ANCOUNT, etc.       │
 *   ├─ Question (variable) ────────────────────┤
 *   │  QNAME  QTYPE(TXT) QCLASS(IN)           │
 *   ├─ Answer (variable) ──────────────────────┤
 *   │  NAME   TYPE(TXT) CLASS(IN) TTL RDLENGTH │
 *   │  RDATA = tunnel payload                   │
 *   └─────────────────────────────────────────┘
 *
 * Payload encoding:
 *   The tunnel payload is placed directly in a single TXT RDATA record.
 *   TXT records naturally carry opaque binary data up to 65535 bytes per
 *   record (practical limit ~64KB) with character-string segmentation.
 *   Each 255-byte segment is prefixed by a 1-byte length — this is the
 *   standard TXT record wire format.
 */
#ifndef TACHYON_DOH_MIMIC_H
#define TACHYON_DOH_MIMIC_H

#include "transport.h"

namespace tachyon::doh_mimic {

constexpr size_t DNS_HEADER_LEN     = 12;
constexpr size_t DOH_MAX_PAYLOAD    = 4096; /* keep under typical MTU × 3 */
constexpr size_t DOH_OVERHEAD       = 64;   /* header + question + answer header */

void register_transport();

/* Build a DNS query message wrapping `payload` as a TXT record
 * in the answer section. `qname` is the query domain (label-encoded).
 * Returns total bytes written. */
size_t build_dns_message(uint8_t *out, size_t cap, uint16_t txn_id,
                         const char *qname,
                         const uint8_t *payload, size_t payload_len);

/* Parse a DNS message, extract the TXT record payload.
 * Returns the length of the extracted payload. */
struct DnsParseResult {
    bool   ok;
    size_t payload_offset;
    size_t payload_len;
};
DnsParseResult parse_dns_message(const uint8_t *buf, size_t len);

/* Encode a domain name into DNS label format (e.g., "example.com" →
 * \x07example\x03com\x00). Returns bytes written. */
size_t encode_qname(uint8_t *out, size_t cap, const char *domain);

} /* namespace tachyon::doh_mimic */

#endif /* TACHYON_DOH_MIMIC_H */
