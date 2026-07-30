// common.h — shared low-level helpers for tg-scan / tg-listen.
#ifndef SPOOF_COMMON_H
#define SPOOF_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

// ── IPv4 / L4 header layouts (network-byte-order fields) ─────────────────────
struct iphdr_m {
    uint8_t  ihl_ver;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};
struct udphdr_m { uint16_t sport, dport, len, check; };
struct tcphdr_m {
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t  off;          // data offset (high 4 bits)
    uint8_t  flags;
    uint16_t window, check, urg;
};
struct icmphdr_m { uint8_t type, code; uint16_t check, id, seq; };

// ── Internet checksum (RFC 1071) ─────────────────────────────────────────────
static inline uint16_t csum(const void *data, int len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t) ~sum;
}

// Pseudo-header sum for TCP/UDP
static inline uint32_t pseudo_sum(uint32_t saddr, uint32_t daddr,
                                  uint8_t proto, uint16_t l4len) {
    uint32_t s = 0;
    s += (saddr >> 16) & 0xffff; s += saddr & 0xffff;
    s += (daddr >> 16) & 0xffff; s += daddr & 0xffff;
    s += htons(proto);
    s += htons(l4len);
    return s;
}

static inline uint16_t l4_csum(uint32_t saddr, uint32_t daddr, uint8_t proto,
                               const void *l4, int l4len) {
    uint32_t sum = pseudo_sum(saddr, daddr, proto, l4len);
    const uint16_t *p = l4;
    int len = l4len;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t) ~sum;
}

static inline void fill_ip(struct iphdr_m *ip, uint32_t saddr, uint32_t daddr,
                           uint8_t proto, uint16_t total_len) {
    ip->ihl_ver  = (4 << 4) | 5;
    ip->tos      = 0;
    ip->tot_len  = htons(total_len);
    ip->id       = htons(rand() & 0xffff);
    ip->frag_off = htons(0x4000);    // Don't Fragment
    ip->ttl      = 64;
    ip->proto    = proto;
    ip->check    = 0;
    ip->saddr    = saddr;            // already network order
    ip->daddr    = daddr;
    ip->check    = csum(ip, sizeof(*ip));
}

// ── CIDR iteration ───────────────────────────────────────────────────────────
// Parses "1.2.3.0/24" and produces base + host count.
//   prefix < 31 → excludes network and broadcast, returns (2^h - 2) hosts
//   prefix 31/32 → returns 2 / 1 host(s)
// On success: *base is set to first usable host, *count is host count, returns 0.
static inline int parse_cidr(const char *s, uint32_t *base, uint32_t *count) {
    char tmp[64];
    strncpy(tmp, s, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = 0;
    char *slash = strchr(tmp, '/');
    int prefix = 32;
    if (slash) { *slash = 0; prefix = atoi(slash + 1); }
    if (prefix < 0 || prefix > 32) return -1;
    struct in_addr a;
    if (inet_aton(tmp, &a) == 0) return -1;
    uint32_t host = ntohl(a.s_addr);
    uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
    *base  = host & mask;
    *count = (prefix >= 31) ? (1u << (32 - prefix))
                            : ((1u << (32 - prefix)) - 2);
    if (prefix < 31) *base += 1;     // skip network address
    return 0;
}

// ── Human-friendly byte size ─────────────────────────────────────────────────
static inline void fmt_bytes(uint64_t n, char *out, size_t out_sz) {
    static const char *u[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    int idx = 0;
    double v = (double) n;
    while (v >= 1024.0 && idx < 4) { v /= 1024.0; idx++; }
    if (idx == 0) snprintf(out, out_sz, "%lu %s", (unsigned long) n, u[idx]);
    else          snprintf(out, out_sz, "%.2f %s", v, u[idx]);
}

// ── Monotonic seconds (for rate limiting / progress) ─────────────────────────
static inline double mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

// ── Rate limiter: token bucket -ish, but simple ──────────────────────────────
// Call rate_wait(rate_pps, &state) once per packet. rate_pps = 0 → no limit.
typedef struct { double next_t; double interval; } RateLimiter;

static inline void rate_init(RateLimiter *r, double rate_pps) {
    r->interval = rate_pps > 0 ? (1.0 / rate_pps) : 0.0;
    r->next_t   = 0.0;
}

static inline void rate_wait(RateLimiter *r) {
    if (r->interval <= 0) return;
    double now = mono_now();
    if (r->next_t == 0.0) { r->next_t = now + r->interval; return; }
    if (now < r->next_t) {
        double sleep_s = r->next_t - now;
        struct timespec ts = {
            .tv_sec  = (time_t) sleep_s,
            .tv_nsec = (long) ((sleep_s - (time_t) sleep_s) * 1e9),
        };
        nanosleep(&ts, NULL);
    }
    r->next_t += r->interval;
}

#endif
