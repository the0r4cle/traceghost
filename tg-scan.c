// tg-scan.c — spoofed-source scanner with two modes.
//
// Build:    make            (or: gcc -O2 -o tg-scan tg-scan.c)
// Run:      sudo ./tg-scan <discover|throughput> [opts]
//
// discover   — sends ONE probe from each spoofed source IP across the given
//              CIDR ranges. Use this first to find which spoofed sources make
//              it through your network's egress / the target's ingress filters.
//
// throughput — sends N packets of S bytes from each spoofed source IP, one
//              protocol at a time. Pair with `tg-listen throughput` on the
//              target to find which sources sustain throughput vs. which the
//              DPI / stateful firewall starts blocking.
//
// Both modes share the same INI-style config file (see tg-scan.conf or tg-listen.conf).
// All config keys can be overridden on the command line.
//
// Intended for use on YOUR OWN infrastructure only.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "common.h"
#include "config.h"

// ── Globals (running flag for clean Ctrl+C) ──────────────────────────────────
static volatile sig_atomic_t running = 1;
static void on_sigint(int sig) { (void) sig; running = 0; }

// ── Packet builders ──────────────────────────────────────────────────────────

// Builds an IPv4+UDP packet into `buf` and returns total length.
static int build_udp(uint8_t *buf, uint32_t saddr, uint32_t daddr,
                     uint16_t sport, uint16_t dport,
                     const uint8_t *payload, int plen) {
    struct iphdr_m  *ip  = (void *) buf;
    struct udphdr_m *udp = (void *) (buf + sizeof(*ip));
    uint8_t         *data = buf + sizeof(*ip) + sizeof(*udp);
    if (plen > 0) memcpy(data, payload, plen);

    int l4len = sizeof(*udp) + plen;
    udp->sport = htons(sport);
    udp->dport = htons(dport);
    udp->len   = htons(l4len);
    udp->check = 0;
    udp->check = l4_csum(saddr, daddr, 17, udp, l4len);

    int total = sizeof(*ip) + l4len;
    fill_ip(ip, saddr, daddr, 17, total);
    return total;
}

static int build_tcp_syn(uint8_t *buf, uint32_t saddr, uint32_t daddr,
                         uint16_t sport, uint16_t dport) {
    struct iphdr_m  *ip  = (void *) buf;
    struct tcphdr_m *tcp = (void *) (buf + sizeof(*ip));
    memset(tcp, 0, sizeof(*tcp));
    tcp->sport  = htons(sport);
    tcp->dport  = htons(dport);
    tcp->seq    = htonl(rand());
    tcp->off    = (5 << 4);
    tcp->flags  = 0x02;          // SYN
    tcp->window = htons(8192);
    tcp->check  = 0;
    tcp->check  = l4_csum(saddr, daddr, 6, tcp, sizeof(*tcp));

    int total = sizeof(*ip) + sizeof(*tcp);
    fill_ip(ip, saddr, daddr, 6, total);
    return total;
}

static int build_icmp(uint8_t *buf, uint32_t saddr, uint32_t daddr,
                      uint16_t icmp_id,
                      const uint8_t *payload, int plen) {
    struct iphdr_m   *ip   = (void *) buf;
    struct icmphdr_m *icmp = (void *) (buf + sizeof(*ip));
    uint8_t          *data = buf + sizeof(*ip) + sizeof(*icmp);
    if (plen > 0) memcpy(data, payload, plen);

    int l4len  = sizeof(*icmp) + plen;
    icmp->type  = 8;             // echo request
    icmp->code  = 0;
    icmp->id    = htons(icmp_id);
    icmp->seq   = htons(1);
    icmp->check = 0;
    icmp->check = csum(icmp, l4len);

    int total = sizeof(*ip) + l4len;
    fill_ip(ip, saddr, daddr, 1, total);
    return total;
}

// ── Source list resolution ───────────────────────────────────────────────────

// Materialise the source-IP list either from `ips_file` or by expanding CIDRs.
// Returns a malloc'd array of u32s (network-byte-order) and sets *out_n.
static uint32_t *resolve_sources(const SendCfg *cfg, uint32_t *out_n) {
    uint32_t *ips = NULL;
    uint32_t  n   = 0, cap = 0;

    // ── From file (one IP per line) ──────────────────────────────────────────
    if (cfg->ips_file[0]) {
        FILE *f = fopen(cfg->ips_file, "r");
        if (!f) { perror(cfg->ips_file); return NULL; }
        char line[64];
        while (fgets(line, sizeof(line), f)) {
            char *s = trim(line);
            if (*s == 0 || *s == '#') continue;
            struct in_addr a;
            if (inet_aton(s, &a) == 0) continue;
            if (n == cap) {
                cap = cap ? cap * 2 : 64;
                ips = realloc(ips, cap * sizeof(*ips));
            }
            ips[n++] = a.s_addr;
        }
        fclose(f);
    }
    // ── From CIDR ranges ─────────────────────────────────────────────────────
    else {
        for (int r = 0; r < cfg->nranges; r++) {
            uint32_t base, count;
            if (parse_cidr(cfg->ranges[r], &base, &count) < 0) {
                fprintf(stderr, "[!] bad CIDR: %s\n", cfg->ranges[r]);
                continue;
            }
            if (n + count > cap) {
                while (cap < n + count) cap = cap ? cap * 2 : 256;
                ips = realloc(ips, cap * sizeof(*ips));
            }
            for (uint32_t i = 0; i < count; i++) ips[n++] = htonl(base + i);
        }
    }
    *out_n = n;
    return ips;
}

// ── Raw send socket ──────────────────────────────────────────────────────────
static int open_raw_socket(void) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) { perror("socket (need root/CAP_NET_RAW)"); return -1; }
    int one = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    return fd;
}

// ── DISCOVER ─────────────────────────────────────────────────────────────────
//
// One probe per source IP per requested protocol.
//
static int cmd_discover(const SendCfg *cfg) {
    if (!cfg->target[0]) { fprintf(stderr, "[!] target IP required\n"); return 1; }

    struct in_addr ta;
    if (inet_aton(cfg->target, &ta) == 0) { fprintf(stderr, "[!] bad target\n"); return 1; }
    uint32_t daddr = ta.s_addr;

    int fd = open_raw_socket();
    if (fd < 0) return 1;

    uint32_t n_ips = 0;
    uint32_t *ips = resolve_sources(cfg, &n_ips);
    if (!ips || n_ips == 0) {
        fprintf(stderr, "[!] no source IPs (set ranges or ips_file)\n");
        free(ips); close(fd); return 1;
    }

    int nprotos = (!!(cfg->protos & PROTO_UDP)) + (!!(cfg->protos & PROTO_TCP)) +
                  (!!(cfg->protos & PROTO_ICMP));
    uint64_t total_packets = (uint64_t) n_ips * nprotos;

    printf("\n[*] discover mode\n");
    printf("    target          %s\n", cfg->target);
    printf("    sources         %u IPs\n", n_ips);
    printf("    protocols       %s%s%s\n",
        (cfg->protos & PROTO_UDP)  ? "UDP "  : "",
        (cfg->protos & PROTO_TCP)  ? "TCP "  : "",
        (cfg->protos & PROTO_ICMP) ? "ICMP " : "");
    if (cfg->rate_pps) printf("    rate            %ld pps\n", cfg->rate_pps);
    else               printf("    rate            unlimited\n");
    printf("    total packets   %lu\n\n", total_packets);

    srand((unsigned) time(NULL));
    uint8_t buf[1500];
    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_addr.s_addr = daddr };

    RateLimiter rl; rate_init(&rl, (double) cfg->rate_pps);
    double t0 = mono_now();
    double last_report = t0;
    uint64_t sent = 0;

    for (uint32_t i = 0; i < n_ips && running; i++) {
        uint32_t saddr = ips[i];
        struct in_addr sa = { .s_addr = saddr };
        char src[16];
        strcpy(src, inet_ntoa(sa));
        int slen = (int) strlen(src);

        if (cfg->protos & PROTO_UDP) {
            rate_wait(&rl);
            int n = build_udp(buf, saddr, daddr, 12345, cfg->udp_port,
                              (uint8_t *) src, slen);
            sendto(fd, buf, n, 0, (struct sockaddr *) &dst, sizeof(dst));
            sent++;
        }
        if (cfg->protos & PROTO_TCP) {
            rate_wait(&rl);
            int n = build_tcp_syn(buf, saddr, daddr, 12346, cfg->tcp_port);
            sendto(fd, buf, n, 0, (struct sockaddr *) &dst, sizeof(dst));
            sent++;
        }
        if (cfg->protos & PROTO_ICMP) {
            rate_wait(&rl);
            int n = build_icmp(buf, saddr, daddr, cfg->icmp_id,
                               (uint8_t *) src, slen);
            sendto(fd, buf, n, 0, (struct sockaddr *) &dst, sizeof(dst));
            sent++;
        }

        double now = mono_now();
        if (now - last_report >= cfg->report) {
            double elapsed = now - t0;
            double pps = sent / (elapsed > 0 ? elapsed : 1);
            double pct = 100.0 * (i + 1) / n_ips;
            printf("    [+] %5.1f%%  ips %u/%u  sent %lu  %.0f pps\n",
                pct, i + 1, n_ips, sent, pps);
            fflush(stdout);
            last_report = now;
        }
    }

    double total_s = mono_now() - t0;
    printf("\n[*] done. sent %lu packets in %.2fs (%.0f pps)\n",
        sent, total_s, sent / (total_s > 0 ? total_s : 1));

    free(ips);
    close(fd);
    return 0;
}

// ── THROUGHPUT ───────────────────────────────────────────────────────────────
//
// For each source IP, send N packets of size S using a single protocol.
//
static int cmd_throughput(const SendCfg *cfg) {
    if (!cfg->target[0]) { fprintf(stderr, "[!] target IP required\n"); return 1; }

    // Throughput mode wants exactly one protocol — pick the first set bit.
    int proto = 0;
    if      (cfg->protos & PROTO_UDP)  proto = PROTO_UDP;
    else if (cfg->protos & PROTO_TCP)  proto = PROTO_TCP;
    else if (cfg->protos & PROTO_ICMP) proto = PROTO_ICMP;
    else { fprintf(stderr, "[!] pick exactly one proto: --proto udp|tcp|icmp\n"); return 1; }

    if (cfg->packets_per_ip <= 0) {
        fprintf(stderr, "[!] packets_per_ip must be > 0\n"); return 1;
    }
    if (cfg->packet_size < 0 || cfg->packet_size > 1400) {
        fprintf(stderr, "[!] packet_size must be 0..1400 (avoid fragmentation)\n"); return 1;
    }

    struct in_addr ta;
    if (inet_aton(cfg->target, &ta) == 0) { fprintf(stderr, "[!] bad target\n"); return 1; }
    uint32_t daddr = ta.s_addr;

    int fd = open_raw_socket();
    if (fd < 0) return 1;

    uint32_t n_ips = 0;
    uint32_t *ips = resolve_sources(cfg, &n_ips);
    if (!ips || n_ips == 0) {
        fprintf(stderr, "[!] no source IPs (set ranges or ips_file)\n");
        free(ips); close(fd); return 1;
    }

    // ── payload: filled with a fixed pattern so the on-wire bytes are
    //    deterministic.  First 16 bytes carry a marker + source-IP echo, so a
    //    debugging packet capture can identify our probes by eye.
    int psize = cfg->packet_size;
    uint8_t *payload = calloc(psize > 0 ? psize : 1, 1);
    if (psize >= 4) memcpy(payload, "SPFL", 4);
    for (int i = 16; i < psize; i++) payload[i] = (uint8_t)(i & 0xff);

    uint64_t total_packets = (uint64_t) n_ips * cfg->packets_per_ip;
    uint64_t total_bytes   = total_packets * (psize + 28);  // approx with headers

    char bs[32]; fmt_bytes(total_bytes, bs, sizeof(bs));
    printf("\n[*] throughput mode  (%s)\n", proto_name(proto));
    printf("    target            %s\n", cfg->target);
    printf("    sources           %u IPs\n", n_ips);
    printf("    packet size       %d bytes (payload)\n", psize);
    printf("    packets per IP    %d\n", cfg->packets_per_ip);
    if (cfg->rate_pps) printf("    rate              %ld pps\n", cfg->rate_pps);
    else               printf("    rate              unlimited\n");
    printf("    total to send     %lu packets (~%s on wire)\n\n", total_packets, bs);

    srand((unsigned) time(NULL));
    uint8_t pktbuf[1500];
    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_addr.s_addr = daddr };

    RateLimiter rl; rate_init(&rl, (double) cfg->rate_pps);
    double t0 = mono_now();
    double last_report = t0;
    uint64_t sent = 0;
    uint64_t sent_bytes = 0;

    for (uint32_t i = 0; i < n_ips && running; i++) {
        uint32_t saddr = ips[i];

        // Update first 16 bytes of payload with source IP for identification.
        if (psize >= 16) {
            memcpy(payload + 4, &saddr, 4);
        }

        for (int j = 0; j < cfg->packets_per_ip && running; j++) {
            rate_wait(&rl);
            int n = 0;
            if (proto == PROTO_UDP) {
                n = build_udp(pktbuf, saddr, daddr,
                              12345 + (rand() & 0x3fff), cfg->udp_port,
                              payload, psize);
            } else if (proto == PROTO_TCP) {
                // TCP SYN doesn't carry payload usefully — payload ignored.
                n = build_tcp_syn(pktbuf, saddr, daddr,
                                  12346 + (rand() & 0x3fff), cfg->tcp_port);
            } else {
                n = build_icmp(pktbuf, saddr, daddr, cfg->icmp_id,
                               payload, psize);
            }
            sendto(fd, pktbuf, n, 0, (struct sockaddr *) &dst, sizeof(dst));
            sent++;
            sent_bytes += n;

            double now = mono_now();
            if (now - last_report >= cfg->report) {
                double elapsed = now - t0;
                double pps = sent / (elapsed > 0 ? elapsed : 1);
                char rs[32]; fmt_bytes((uint64_t)(sent_bytes / (elapsed > 0 ? elapsed : 1)), rs, sizeof(rs));
                double pct = 100.0 * sent / total_packets;
                printf("    [+] %5.1f%%  ips %u/%u  sent %lu  %.0f pps  %s/s\n",
                    pct, i + 1, n_ips, sent, pps, rs);
                fflush(stdout);
                last_report = now;
            }
        }
    }

    double total_s = mono_now() - t0;
    char bs2[32]; fmt_bytes(sent_bytes, bs2, sizeof(bs2));
    printf("\n[*] done. sent %lu packets / %s in %.2fs (%.0f pps)\n",
        sent, bs2, total_s, sent / (total_s > 0 ? total_s : 1));

    free(payload);
    free(ips);
    close(fd);
    return 0;
}

// ── CLI ──────────────────────────────────────────────────────────────────────

static void print_usage(void) {
    fprintf(stderr,
        "Usage:\n"
        "  tg-scan <command> [options]\n"
        "\n"
        "Commands:\n"
        "  discover     One probe per spoofed source IP across the given\n"
        "               ranges. Pair with `tg-listen discover` to find\n"
        "               which sources arrive at the target.\n"
        "\n"
        "  throughput   Send N packets of S bytes from each source. Pair\n"
        "               with `tg-listen throughput` to measure per-IP\n"
        "               success rate and detect DPI / rate-limit drops.\n"
        "\n"
        "Common options:\n"
        "  -c, --config <file>     INI config (default: tg-scan.conf)\n"
        "  -t, --target <ip>       target IP                              (overrides config)\n"
        "  -r, --range <cidr>      source CIDR (repeatable)               (overrides config)\n"
        "  -p, --proto <list>      udp,tcp,icmp  or  udp / tcp / icmp / all\n"
        "      --udp-port <p>      dest UDP port                          (default 54321)\n"
        "      --tcp-port <p>      dest TCP port                          (default 54322)\n"
        "      --icmp-id <n>       ICMP echo identifier                   (default 0x1234)\n"
        "      --rate <pps>        packets-per-second limit, 0 = unlimited\n"
        "      --report <secs>     progress update interval               (default 2.0)\n"
        "\n"
        "Throughput options:\n"
        "      --size <bytes>      payload bytes per packet (0..1400)     (default 1024)\n"
        "      --count <N>         packets per source IP                  (default 100)\n"
        "      --ips-file <file>   one IP per line; replaces --range\n"
        "\n"
        "Example:\n"
        "  sudo ./tg-scan discover -t 1.2.3.4 -r 5.0.0.0/24\n"
        "  sudo ./tg-scan throughput -t 1.2.3.4 -p udp --ips-file open_ips.txt --size 1200 --count 500 --rate 2000\n"
    );
}

// Parse CLI options that come AFTER the subcommand keyword.
// Returns 0 on success, sets cfg accordingly (CLI overrides config-file values).
static int parse_cli(int argc, char **argv, SendCfg *cfg, const char **cfg_path) {
    static struct option long_opts[] = {
        { "config",    required_argument, 0, 'c' },
        { "target",    required_argument, 0, 't' },
        { "range",     required_argument, 0, 'r' },
        { "proto",     required_argument, 0, 'p' },
        { "udp-port",  required_argument, 0,  1  },
        { "tcp-port",  required_argument, 0,  2  },
        { "icmp-id",   required_argument, 0,  3  },
        { "rate",      required_argument, 0,  4  },
        { "report",    required_argument, 0,  5  },
        { "size",      required_argument, 0,  6  },
        { "count",     required_argument, 0,  7  },
        { "ips-file",  required_argument, 0,  8  },
        { "help",      no_argument,       0, 'h' },
        { 0, 0, 0, 0 },
    };

    // First pass: locate --config so we load it BEFORE applying overrides.
    int explicit_cfg = 0;
    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "c:t:r:p:h", long_opts, NULL)) != -1) {
        if (c == 'c')      { *cfg_path = optarg; explicit_cfg = 1; }
        else if (c == 'h') { print_usage(); exit(0); }
    }

    // Load config (silent if default missing, loud if user-supplied missing).
    load_send_cfg(*cfg_path, explicit_cfg, cfg);

    // Reset, second pass: apply CLI overrides on top of file values.
    // Range overrides clear the config's range list on first use.
    int range_overridden = 0;

    optind = 1;
    while ((c = getopt_long(argc, argv, "c:t:r:p:h", long_opts, NULL)) != -1) {
        switch (c) {
            case 'c': /* already handled */ break;
            case 't': strncpy(cfg->target, optarg, sizeof(cfg->target) - 1); break;
            case 'r':
                if (!range_overridden) { cfg->nranges = 0; range_overridden = 1; }
                if (cfg->nranges < MAX_RANGES)
                    strncpy(cfg->ranges[cfg->nranges++], optarg, 63);
                break;
            case 'p': cfg->protos = parse_protos(optarg); break;
            case  1 : cfg->udp_port = atoi(optarg); break;
            case  2 : cfg->tcp_port = atoi(optarg); break;
            case  3 : cfg->icmp_id  = (int) strtol(optarg, NULL, 0); break;
            case  4 : cfg->rate_pps = atol(optarg); break;
            case  5 : cfg->report   = atof(optarg); break;
            case  6 : cfg->packet_size = atoi(optarg); break;
            case  7 : cfg->packets_per_ip = atoi(optarg); break;
            case  8 : strncpy(cfg->ips_file, optarg, sizeof(cfg->ips_file) - 1); break;
            default:  return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { print_usage(); return 1; }

    const char *sub = argv[1];
    if (!strcmp(sub, "-h") || !strcmp(sub, "--help")) { print_usage(); return 0; }

    signal(SIGINT, on_sigint);

    SendCfg cfg;
    const char *cfg_path = "tg-scan.conf";    // <- default file is now per-binary
    if (parse_cli(argc - 1, argv + 1, &cfg, &cfg_path) < 0) return 1;

    if      (!strcmp(sub, "discover"))   return cmd_discover(&cfg);
    else if (!strcmp(sub, "throughput")) return cmd_throughput(&cfg);

    fprintf(stderr, "[!] unknown command '%s'\n\n", sub);
    print_usage();
    return 1;
}
