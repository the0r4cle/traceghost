// config.h — INI-style config loaders.
//
// Two structs, one per binary:
//   SendCfg     loaded by tg-scan   from tg-scan.conf
//   ListenCfg   loaded by tg-listen from tg-listen.conf
//
// They overlap only on the "wire" fields (udp_port, tcp_port, icmp_id) which
// MUST match between the two sides.  All other fields are tool-specific.
#ifndef SPOOF_CONFIG_H
#define SPOOF_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RANGES 256

// ── Sender config ────────────────────────────────────────────────────────────
typedef struct {
    // wire (must match listener)
    int  udp_port;
    int  tcp_port;
    int  icmp_id;

    // sender-only
    char target[64];
    char ranges[MAX_RANGES][64];
    int  nranges;
    char ips_file[256];

    // behaviour
    int    protos;          // bitmask: 1=UDP 2=TCP 4=ICMP
    int    packet_size;     // throughput payload bytes (0..1400)
    int    packets_per_ip;  // throughput packets per source
    long   rate_pps;        // 0 = unlimited
    double report;          // progress interval (seconds)
} SendCfg;

// ── Listener config ──────────────────────────────────────────────────────────
typedef struct {
    // wire (must match sender)
    int  udp_port;
    int  tcp_port;
    int  icmp_id;           // 0 = match any

    // filtering — restricts which protocols are counted at all.
    // 0 means "leave as default = all".  Otherwise an OR of PROTO_*.
    int  protos;

    // listener-only
    double report;
    int    top;
    long   rcvbuf;
    char   output[256];
} ListenCfg;

#define PROTO_UDP  1
#define PROTO_TCP  2
#define PROTO_ICMP 4

// ── Shared helpers ───────────────────────────────────────────────────────────

static inline char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    if (*s == 0) return s;
    char *end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
        *end-- = 0;
    return s;
}

static inline int parse_protos(const char *s) {
    int m = 0;
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
        char *t = trim(tok);
        for (char *p = t; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
        if      (!strcmp(t, "udp"))  m |= PROTO_UDP;
        else if (!strcmp(t, "tcp"))  m |= PROTO_TCP;
        else if (!strcmp(t, "icmp")) m |= PROTO_ICMP;
        else if (!strcmp(t, "all"))  m |= PROTO_UDP | PROTO_TCP | PROTO_ICMP;
    }
    return m;
}

static inline const char *proto_name(int p) {
    switch (p) {
        case PROTO_UDP:  return "UDP";
        case PROTO_TCP:  return "TCP";
        case PROTO_ICMP: return "ICMP";
        default:         return "?";
    }
}

// Open `path`; returns NULL if missing.  We only warn loudly when the user
// passed -c explicitly — a missing default file is silent.
static inline FILE *try_open(const char *path, int explicit_path) {
    if (!path) return NULL;
    FILE *f = fopen(path, "r");
    if (!f && explicit_path)
        fprintf(stderr, "[!] cannot open config '%s' (using defaults)\n", path);
    return f;
}

// ── Sender loader ────────────────────────────────────────────────────────────
static inline int load_send_cfg(const char *path, int explicit_path, SendCfg *cfg) {
    // Defaults
    cfg->udp_port       = 54321;
    cfg->tcp_port       = 54322;
    cfg->icmp_id        = 0x1234;
    cfg->target[0]      = 0;
    cfg->nranges        = 0;
    cfg->ips_file[0]    = 0;
    cfg->protos         = PROTO_UDP | PROTO_TCP | PROTO_ICMP;
    cfg->packet_size    = 1024;
    cfg->packets_per_ip = 100;
    cfg->rate_pps       = 0;
    cfg->report         = 2.0;

    FILE *f = try_open(path, explicit_path);
    if (!f) return -1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (*p == 0 || *p == '#') continue;
        char *eq = strchr(p, '='); if (!eq) continue;
        *eq = 0;
        char *key = trim(p), *val = trim(eq + 1);

        if      (!strcmp(key, "udp_port"))       cfg->udp_port       = atoi(val);
        else if (!strcmp(key, "tcp_port"))       cfg->tcp_port       = atoi(val);
        else if (!strcmp(key, "icmp_id"))        cfg->icmp_id        = (int) strtol(val, NULL, 0);
        else if (!strcmp(key, "target"))         strncpy(cfg->target, val, sizeof(cfg->target) - 1);
        else if (!strcmp(key, "ips_file"))       strncpy(cfg->ips_file, val, sizeof(cfg->ips_file) - 1);
        else if (!strcmp(key, "protos"))         cfg->protos         = parse_protos(val);
        else if (!strcmp(key, "packet_size"))    cfg->packet_size    = atoi(val);
        else if (!strcmp(key, "packets_per_ip")) cfg->packets_per_ip = atoi(val);
        else if (!strcmp(key, "rate_pps"))       cfg->rate_pps       = atol(val);
        else if (!strcmp(key, "report"))         cfg->report         = atof(val);
        else if (!strcmp(key, "range") && cfg->nranges < MAX_RANGES)
            strncpy(cfg->ranges[cfg->nranges++], val, 63);
        // unknown keys are silently ignored
    }
    fclose(f);
    return 0;
}

// ── Listener loader ──────────────────────────────────────────────────────────
static inline int load_listen_cfg(const char *path, int explicit_path, ListenCfg *cfg) {
    cfg->udp_port = 54321;
    cfg->tcp_port = 54322;
    cfg->icmp_id  = 0x1234;          // match tg-scan.conf default; --icmp-id 0 → any
    cfg->protos   = PROTO_UDP | PROTO_TCP | PROTO_ICMP;
    cfg->report   = 2.0;
    cfg->top      = 10;
    cfg->rcvbuf   = 16 * 1024 * 1024;
    strcpy(cfg->output, "scan_report.txt");

    FILE *f = try_open(path, explicit_path);
    if (!f) return -1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (*p == 0 || *p == '#') continue;
        char *eq = strchr(p, '='); if (!eq) continue;
        *eq = 0;
        char *key = trim(p), *val = trim(eq + 1);

        if      (!strcmp(key, "udp_port")) cfg->udp_port = atoi(val);
        else if (!strcmp(key, "tcp_port")) cfg->tcp_port = atoi(val);
        else if (!strcmp(key, "icmp_id"))  cfg->icmp_id  = (int) strtol(val, NULL, 0);
        else if (!strcmp(key, "protos"))   cfg->protos   = parse_protos(val);
        else if (!strcmp(key, "report"))   cfg->report   = atof(val);
        else if (!strcmp(key, "top"))      cfg->top      = atoi(val);
        else if (!strcmp(key, "rcvbuf"))   cfg->rcvbuf   = atol(val);
        else if (!strcmp(key, "output"))   strncpy(cfg->output, val, sizeof(cfg->output) - 1);
    }
    fclose(f);
    return 0;
}

#endif
