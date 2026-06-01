// tg-listen.c — listener for tg-scan probes.
//
// Build:    make            (or: gcc -O2 -o tg-listen tg-listen.c)
// Run:      sudo ./tg-listen <discover|throughput> [opts]
//
// Both subcommands receive ALL packets matching the configured UDP / TCP /
// ICMP filters and tally them per (proto, source IP).  They differ only in
// how the final report is rendered:
//
// discover    — prints a flat list of unique source IPs per protocol, with
//               a packet count next to each.  Use to identify which spoofed
//               sources successfully traverse the network.
//
// throughput  — prints the top-N sources sorted by packet count + bytes,
//               then the full sorted table.  Use to identify which sources
//               sustain throughput and which the DPI drops mid-stream.
//
// The wire-level filtering (which UDP / TCP dport to listen on, which ICMP
// echo identifier) is identical to tg-scan and shares the same INI config.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "common.h"
#include "config.h"

// Available since Linux 4.20 — kernel drops outgoing packets at the socket
// layer when set, sparing us a per-packet recvfrom check.  Fallback below
// catches them in userspace for older kernels.
#ifndef PACKET_IGNORE_OUTGOING
#define PACKET_IGNORE_OUTGOING 23
#endif

#define MAP_CAP 131072    // power-of-two-ish hash slots (~26 MiB / map)

// ── Per-IP statistics map ────────────────────────────────────────────────────
//
// Open-addressed hash with linear probing.  Slot is empty when `ip == 0`.
typedef struct {
    uint32_t ip;        // network-byte-order, 0 = empty
    uint64_t pkts;
    uint64_t bytes;
} IPStat;

typedef struct {
    IPStat *slots;
    int     cap;
    int     count;
    uint64_t total_pkts;
    uint64_t total_bytes;
} IPMap;

static void map_init(IPMap *m, int cap) {
    m->cap   = cap;
    m->count = 0;
    m->total_pkts = m->total_bytes = 0;
    m->slots = calloc(cap, sizeof(IPStat));
}

static void map_add(IPMap *m, uint32_t ip, int bytes) {
    if (ip == 0) return;
    uint32_t h = (ip * 2654435761u) % m->cap;
    while (m->slots[h].ip && m->slots[h].ip != ip)
        h = (h + 1) % m->cap;
    if (m->slots[h].ip == 0) {
        m->slots[h].ip = ip;
        m->count++;
    }
    m->slots[h].pkts++;
    m->slots[h].bytes += bytes;
    m->total_pkts++;
    m->total_bytes += bytes;
}

// Build a flat sorted snapshot.  Caller owns the malloc'd array.
static IPStat *map_snapshot(const IPMap *m, int *out_n) {
    IPStat *arr = malloc(m->count * sizeof(IPStat));
    int k = 0;
    for (int i = 0; i < m->cap && k < m->count; i++)
        if (m->slots[i].ip) arr[k++] = m->slots[i];
    *out_n = k;
    return arr;
}

static int cmp_by_pkts_desc(const void *a, const void *b) {
    uint64_t pa = ((const IPStat *) a)->pkts;
    uint64_t pb = ((const IPStat *) b)->pkts;
    if (pa < pb) return  1;
    if (pa > pb) return -1;
    return 0;
}

// ── Globals ──────────────────────────────────────────────────────────────────
static IPMap udp_map, tcp_map, icmp_map;
static volatile sig_atomic_t running = 1;
static void on_sigint(int sig) { (void) sig; running = 0; }

// ── Report rendering ─────────────────────────────────────────────────────────

static void render_discover(FILE *f, const char *name, IPMap *m) {
    fprintf(f, "\n%s — %d unique source IPs (%lu packets total)\n", name,
            m->count, m->total_pkts);
    for (int i = 0; i < 60; i++) fputc('-', f);
    fputc('\n', f);
    int n;
    IPStat *arr = map_snapshot(m, &n);
    qsort(arr, n, sizeof(IPStat), cmp_by_pkts_desc);
    for (int i = 0; i < n; i++) {
        struct in_addr a = { .s_addr = arr[i].ip };
        fprintf(f, "  %-16s  %5lu pkt\n", inet_ntoa(a), arr[i].pkts);
    }
    free(arr);
}

static void render_throughput(FILE *f, const char *name, IPMap *m, int top) {
    char tbs[32]; fmt_bytes(m->total_bytes, tbs, sizeof(tbs));
    fprintf(f, "\n%s — %d unique sources  |  %lu packets  |  %s total\n",
            name, m->count, m->total_pkts, tbs);
    for (int i = 0; i < 70; i++) fputc('-', f);
    fputc('\n', f);
    fprintf(f, "  %-16s  %10s  %12s  %8s\n",
            "Source IP", "Packets", "Bytes", "Avg sz");

    int n;
    IPStat *arr = map_snapshot(m, &n);
    qsort(arr, n, sizeof(IPStat), cmp_by_pkts_desc);
    int shown = (top > 0 && top < n) ? top : n;
    for (int i = 0; i < shown; i++) {
        struct in_addr a = { .s_addr = arr[i].ip };
        char bs[32]; fmt_bytes(arr[i].bytes, bs, sizeof(bs));
        uint64_t avg = arr[i].pkts ? arr[i].bytes / arr[i].pkts : 0;
        fprintf(f, "  %-16s  %10lu  %12s  %6lu B\n",
                inet_ntoa(a), arr[i].pkts, bs, avg);
    }
    if (shown < n)
        fprintf(f, "  ... %d more sources omitted (use --top 0 to show all)\n",
                n - shown);
    free(arr);
}

static void save_report(const char *path, int mode_throughput, int top, int protos) {
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return; }
    fprintf(f, "tg-listen report\n");
    time_t now = time(NULL);
    fprintf(f, "generated at %s", ctime(&now));

    if (mode_throughput) {
        if (protos & PROTO_UDP)  render_throughput(f, "UDP",  &udp_map,  0);
        if (protos & PROTO_TCP)  render_throughput(f, "TCP",  &tcp_map,  0);
        if (protos & PROTO_ICMP) render_throughput(f, "ICMP", &icmp_map, 0);
    } else {
        if (protos & PROTO_UDP)  render_discover(f, "UDP",  &udp_map);
        if (protos & PROTO_TCP)  render_discover(f, "TCP",  &tcp_map);
        if (protos & PROTO_ICMP) render_discover(f, "ICMP", &icmp_map);
    }

    fclose(f);
    (void) top;
    printf("\n[*] report saved to %s\n", path);
}

// ── CLI parsing ──────────────────────────────────────────────────────────────

static void print_usage(void) {
    fprintf(stderr,
        "Usage:\n"
        "  tg-listen <command> [options]\n"
        "\n"
        "Commands:\n"
        "  discover     Report unique source IPs per protocol.\n"
        "  throughput   Report per-source packet & byte counters, sorted.\n"
        "\n"
        "Options:\n"
        "  -c, --config <file>     INI config (default: tg-listen.conf)\n"
        "  -p, --proto <list>      protocols to count: udp,tcp,icmp / all   (default: all)\n"
        "      --udp-port <p>      filter on this UDP dport               (default 54321)\n"
        "      --tcp-port <p>      filter on this TCP dport (SYN)         (default 54322)\n"
        "      --icmp-id <n>       filter on this ICMP echo id; 0=any     (default 0x1234)\n"
        "      --report <secs>     live-report interval                   (default 2.0)\n"
        "      --top <N>           rows in throughput live view; 0 = all  (default 10)\n"
        "      --rcvbuf <bytes>    SO_RCVBUF                              (default 16 MiB)\n"
        "  -o, --output <file>     final report path                      (default scan_report.txt)\n"
        "\n"
        "Example:\n"
        "  sudo ./tg-listen discover -p all\n"
        "  sudo ./tg-listen throughput -p udp --top 20\n"
    );
}

static int parse_cli(int argc, char **argv, ListenCfg *cfg) {
    static struct option opts[] = {
        { "config",   required_argument, 0, 'c' },
        { "proto",    required_argument, 0, 'p' },
        { "udp-port", required_argument, 0,  1  },
        { "tcp-port", required_argument, 0,  2  },
        { "icmp-id",  required_argument, 0,  3  },
        { "report",   required_argument, 0,  4  },
        { "top",      required_argument, 0,  5  },
        { "rcvbuf",   required_argument, 0,  6  },
        { "output",   required_argument, 0, 'o' },
        { "help",     no_argument,       0, 'h' },
        { 0, 0, 0, 0 },
    };

    const char *cfg_path = "tg-listen.conf";    // <- default file is now per-binary
    int explicit_cfg = 0;

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "c:p:o:h", opts, NULL)) != -1) {
        if (c == 'c')      { cfg_path = optarg; explicit_cfg = 1; }
        else if (c == 'h') { print_usage(); exit(0); }
    }
    load_listen_cfg(cfg_path, explicit_cfg, cfg);

    optind = 1;
    while ((c = getopt_long(argc, argv, "c:p:o:h", opts, NULL)) != -1) {
        switch (c) {
            case 'c': case 'h': break;
            case 'p': cfg->protos = parse_protos(optarg); break;
            case 'o': strncpy(cfg->output, optarg, sizeof(cfg->output) - 1); break;
            case  1 : cfg->udp_port = atoi(optarg); break;
            case  2 : cfg->tcp_port = atoi(optarg); break;
            case  3 : cfg->icmp_id  = (int) strtol(optarg, NULL, 0); break;
            case  4 : cfg->report   = atof(optarg); break;
            case  5 : cfg->top      = atoi(optarg); break;
            case  6 : cfg->rcvbuf   = atol(optarg); break;
            default:  return -1;
        }
    }
    return 0;
}

// ── Live report tickers ──────────────────────────────────────────────────────

static void live_discover(int protos) {
    int first = 1;
    printf("    [+]");
    if (protos & PROTO_UDP)  { printf("%s UDP=%d",  first?"":"  ", udp_map.count);  first = 0; }
    if (protos & PROTO_TCP)  { printf("%s TCP=%d",  first?"":"  ", tcp_map.count);  first = 0; }
    if (protos & PROTO_ICMP) { printf("%s ICMP=%d", first?"":"  ", icmp_map.count); first = 0; }
    printf("\n");
    fflush(stdout);
}

static void live_throughput(int protos, int top) {
    char ub[32], tb[32], ib[32];
    fmt_bytes(udp_map.total_bytes,  ub, sizeof(ub));
    fmt_bytes(tcp_map.total_bytes,  tb, sizeof(tb));
    fmt_bytes(icmp_map.total_bytes, ib, sizeof(ib));
    int first = 1;
    printf("    [+]");
    if (protos & PROTO_UDP) {
        printf("%sUDP %d srcs / %lu pkt / %s", first?" ":"   ",
            udp_map.count, udp_map.total_pkts, ub);
        first = 0;
    }
    if (protos & PROTO_TCP) {
        printf("%sTCP %d srcs / %lu pkt / %s", first?" ":"   ",
            tcp_map.count, tcp_map.total_pkts, tb);
        first = 0;
    }
    if (protos & PROTO_ICMP) {
        printf("%sICMP %d srcs / %lu pkt / %s", first?" ":"   ",
            icmp_map.count, icmp_map.total_pkts, ib);
        first = 0;
    }
    printf("\n");
    (void) top;
    fflush(stdout);
}

// ── Main capture loop ────────────────────────────────────────────────────────

static int run(int mode_throughput, const ListenCfg *cfg) {
    map_init(&udp_map,  MAP_CAP);
    map_init(&tcp_map,  MAP_CAP);
    map_init(&icmp_map, MAP_CAP);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket (need root/CAP_NET_RAW)"); return 1; }
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &cfg->rcvbuf, sizeof(cfg->rcvbuf));

    // Drop outgoing frames at the kernel (Linux ≥ 4.20). Ignored on older
    // kernels; we also re-filter in userspace below as a safety net.
    int one = 1;
    setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one));

    printf("\n[*] %s mode\n", mode_throughput ? "throughput" : "discover");
    printf("    protocols         %s%s%s\n",
        (cfg->protos & PROTO_UDP)  ? "UDP "  : "",
        (cfg->protos & PROTO_TCP)  ? "TCP "  : "",
        (cfg->protos & PROTO_ICMP) ? "ICMP " : "");
    if (cfg->protos & PROTO_UDP)
        printf("    filter UDP        :%d\n", cfg->udp_port);
    if (cfg->protos & PROTO_TCP)
        printf("    filter TCP-SYN    :%d\n", cfg->tcp_port);
    if (cfg->protos & PROTO_ICMP)
        printf("    filter ICMP-id    %s\n",
            cfg->icmp_id ? "matched" : "any");
    printf("    live report every %.1fs   (Ctrl+C to stop)\n\n", cfg->report);

    signal(SIGINT, on_sigint);

    uint8_t buf[65536];
    double t0 = mono_now();
    double last = t0;

    while (running) {
        struct sockaddr_ll sll;
        socklen_t slen = sizeof(sll);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *) &sll, &slen);
        if (n < 14 + 20) {
            // Periodic wakeups: still emit live report.
            double now = mono_now();
            if (now - last >= cfg->report) {
                if (mode_throughput) live_throughput(cfg->protos, cfg->top);
                else                 live_discover(cfg->protos);
                last = now;
            }
            continue;
        }

        // Userspace safety net for kernels lacking PACKET_IGNORE_OUTGOING:
        // skip frames we ourselves sent.
        if (sll.sll_pkttype == PACKET_OUTGOING) continue;
        uint8_t *ip = buf + 14;              // skip Ethernet header
        if ((ip[0] >> 4) != 4) continue;

        int      ihl   = (ip[0] & 0x0f) * 4;
        uint8_t  proto = ip[9];
        uint32_t src;
        memcpy(&src, ip + 12, 4);            // network order
        uint8_t *l4    = ip + ihl;
        ssize_t  l4len = n - 14 - ihl;
        if (l4len < 1) continue;

        // Only count payload bytes (L7), not headers — gives a clean
        // sense of how much "real" data made it through.
        // The cfg->protos bitmask gates which counters we update at all.
        if (proto == 17 && l4len >= 8 && (cfg->protos & PROTO_UDP)) {           // UDP
            uint16_t dport = ((uint16_t) l4[2] << 8) | l4[3];
            if (dport == cfg->udp_port)
                map_add(&udp_map, src, (int)(l4len - 8));
        } else if (proto == 6 && l4len >= 20 && (cfg->protos & PROTO_TCP)) {   // TCP
            uint16_t dport = ((uint16_t) l4[2] << 8) | l4[3];
            uint8_t flags  = l4[13];
            // Match SYN packets only (no payload meaning for TCP throughput).
            if (dport == cfg->tcp_port && (flags & 0x02))
                map_add(&tcp_map, src, (int) l4len);
        } else if (proto == 1 && l4len >= 8 && (cfg->protos & PROTO_ICMP)) {   // ICMP
            uint8_t  type = l4[0];
            uint16_t id   = ((uint16_t) l4[4] << 8) | l4[5];
            if (type == 8 && (cfg->icmp_id == 0 || id == cfg->icmp_id))
                map_add(&icmp_map, src, (int)(l4len - 8));
        }

        double now = mono_now();
        if (now - last >= cfg->report) {
            if (mode_throughput) live_throughput(cfg->protos, cfg->top);
            else                 live_discover(cfg->protos);
            last = now;
        }
    }

    double total_s = mono_now() - t0;
    printf("\n[*] stopped after %.1fs\n", total_s);

    // ── Final on-screen summary ──────────────────────────────────────────────
    if (mode_throughput) {
        if (cfg->protos & PROTO_UDP)  render_throughput(stdout, "UDP",  &udp_map,  cfg->top);
        if (cfg->protos & PROTO_TCP)  render_throughput(stdout, "TCP",  &tcp_map,  cfg->top);
        if (cfg->protos & PROTO_ICMP) render_throughput(stdout, "ICMP", &icmp_map, cfg->top);
    } else {
        if (cfg->protos & PROTO_UDP)  render_discover(stdout, "UDP",  &udp_map);
        if (cfg->protos & PROTO_TCP)  render_discover(stdout, "TCP",  &tcp_map);
        if (cfg->protos & PROTO_ICMP) render_discover(stdout, "ICMP", &icmp_map);
    }

    save_report(cfg->output, mode_throughput, cfg->top, cfg->protos);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { print_usage(); return 1; }

    const char *sub = argv[1];
    if (!strcmp(sub, "-h") || !strcmp(sub, "--help")) { print_usage(); return 0; }

    ListenCfg cfg;
    if (parse_cli(argc - 1, argv + 1, &cfg) < 0) return 1;

    if      (!strcmp(sub, "discover"))   return run(0, &cfg);
    else if (!strcmp(sub, "throughput")) return run(1, &cfg);

    fprintf(stderr, "[!] unknown command '%s'\n\n", sub);
    print_usage();
    return 1;
}
