# traceghost

> **trace** the path your **ghost** packets take.
>
> A pair of small Linux tools to probe which **spoofed source IPs** actually make it through your network's egress filter and the target's ingress filter — and to detect when DPI or stateful firewalls cut connections mid-stream.

🌐 **English** &nbsp;|&nbsp; [فارسی](README-fa.md)

---

## Overview

`traceghost` is two cooperating CLI tools:

| Binary      | Role                                                                                |
| ----------- | ----------------------------------------------------------------------------------- |
| `tg-scan`   | **Sender** — emits raw IPv4 probes with a spoofed source address to a chosen target |
| `tg-listen` | **Receiver** — captures and tallies arriving packets per `(protocol, source IP)`    |

Each tool has two subcommands that pair across the wire:

| Mode           | Sender behavior                                                  | Listener report                                                                  |
| -------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| **discover**   | One probe per source IP per protocol                             | List of source IPs that arrived, per protocol                                    |
| **throughput** | `N` packets of `S` bytes per source IP, one protocol, rate-limited | Per-IP packet & byte counts, sorted — shows who pushes data and who gets dropped |

The two-stage workflow:

1. **`discover`** finds which spoofed sources egress filtering lets out and ingress filtering lets in.
2. **`throughput`** runs sustained traffic from those survivors to see which the DPI / stateful firewall in the middle starts blocking after the first few packets.

## Why

- Identifying source addresses that work for spoofed-IP tunnel projects.
- Testing your own network's egress filtering (BCP 38 / uRPF) and your server's reverse-path filtering.
- Understanding **DPI behavior**: a source that survives `discover` (1 packet) but fails `throughput` (500 packets) tells you the network does stateful tracking.
- Anti-censorship research on **your own infrastructure**.

## Features

- 🚀 **Fast** — raw `AF_INET / IPPROTO_RAW` send path with stack-allocated packet buffers and a `setsockopt(IP_HDRINCL)` strategy that keeps the kernel out of the loop.
- 🎛 **Three protocols** — UDP datagrams, TCP-SYN probes, and ICMP Echo Requests.
- 📏 **Configurable packet size** for throughput mode (0–1400 B to stay below typical MTU).
- ⏱ **Rate limiter** with `nanosleep`-based no-drift scheduling (`--rate` packets/sec, `0` = unlimited).
- 🎯 **Protocol filter on the listener** — capture only the protocols you care about, ignore stray TCP/ICMP noise on the wire.
- 🔇 **Quiet defaults** — missing default config is silent; only an explicit `-c <file>` that's missing warns.
- 📊 **Per-IP counters** in the listener with sorted top-N report and a final file dump.
- 🧹 **Clean CLI** with subcommands, long & short flags, and INI config files for the values you don't want to repeat.
- 🛡 **Self-cleaning capture** — listener drops outgoing packets via `PACKET_IGNORE_OUTGOING` (kernel ≥ 4.20) plus a userspace fallback, so running both ends on the same box for tests gives the right counts.
- ✨ **Tiny** — ~1200 lines of dependency-free C, builds in seconds with `make`.

## Build

```bash
make
```

Produces two binaries in the working directory: `tg-scan` and `tg-listen`.

If you don't want to run with `sudo` every time, drop `CAP_NET_RAW` onto the binaries (Linux only):

```bash
make setcap     # uses sudo once to install the capability
./tg-listen discover    # then no sudo
```

## Quick start

### Stage 1 — discover

On the **target** host (the box that will receive probes):

```bash
sudo ./tg-listen discover
```

On the **sender** host:

```bash
sudo ./tg-scan discover \
     --target 1.2.3.4 \
     --range 5.0.0.0/24 \
     --range 8.8.8.0/24 \
     --rate 5000
```

After you `Ctrl+C` the listener, it writes a sorted report to `scan_report.txt`. Pull out the IPs that arrived and save them — one per line — into `open_ips.txt`.

### Stage 2 — throughput

```bash
# target
sudo ./tg-listen throughput --proto udp --top 20

# sender
sudo ./tg-scan throughput \
     --target 1.2.3.4 \
     --ips-file open_ips.txt \
     --proto udp \
     --size 1200 --count 500 --rate 3000
```

The final per-IP table tells you, for each previously-discovered source, how many of the 500 packets actually made it through. A source that scored ~100% in discover but <10% here is a strong DPI signature.

> ℹ️ Run both ends with the same `--proto` — otherwise the listener will also count stray TCP-SYNs / pings on the wire that have nothing to do with your scan.

## Configuration files

Each tool loads its own INI-style file from the working directory:

| Binary      | Default file     | Lives on        |
| ----------- | ---------------- | --------------- |
| `tg-scan`   | `tg-scan.conf`   | sender host     |
| `tg-listen` | `tg-listen.conf` | target host     |

Three keys appear in both files because they **must match across the wire**:

```ini
udp_port = 54321
tcp_port = 54322
icmp_id  = 0x1234     # on the listener, set 0 to mean "any ID"
```

Any unknown key in a file is silently ignored — you can keep a single combined config and pass it to both tools with `-c`. Any CLI flag overrides what's in the file.

Sample files are provided in the repo: see [`tg-scan.conf`](tg-scan.conf) and [`tg-listen.conf`](tg-listen.conf), both heavily commented.

## CLI reference

### `tg-scan`

```
Usage:
  tg-scan <discover|throughput> [options]

Common options:
  -c, --config <file>     INI config                              (default: tg-scan.conf)
  -t, --target <ip>       target IP (overrides config)
  -r, --range <cidr>      source CIDR (repeatable; overrides config)
  -p, --proto <list>      udp,tcp,icmp  or  udp / tcp / icmp / all
      --udp-port <p>      destination UDP port                    (default: 54321)
      --tcp-port <p>      destination TCP port                    (default: 54322)
      --icmp-id <n>       ICMP echo identifier                    (default: 0x1234)
      --rate <pps>        packets-per-second limit, 0 = unlimited
      --report <secs>     progress update interval                (default: 2.0)

Throughput-only:
      --size <bytes>      payload bytes per packet (0..1400)      (default: 1024)
      --count <N>         packets per source IP                   (default: 100)
      --ips-file <file>   one IP per line; replaces --range
```

### `tg-listen`

```
Usage:
  tg-listen <discover|throughput> [options]

Options:
  -c, --config <file>     INI config                              (default: tg-listen.conf)
  -p, --proto <list>      protocols to count: udp,tcp,icmp / all  (default: all)
      --udp-port <p>      filter on this UDP dport                (default: 54321)
      --tcp-port <p>      filter on this TCP dport (SYN only)     (default: 54322)
      --icmp-id <n>       filter on this ICMP echo id, 0 = any    (default: 0x1234)
      --report <secs>     live-report interval                    (default: 2.0)
      --top <N>           rows in throughput view, 0 = all        (default: 10)
      --rcvbuf <bytes>    SO_RCVBUF                               (default: 16 MiB)
  -o, --output <file>     final report path                       (default: scan_report.txt)
```

## How it works

**`tg-scan`** opens an `AF_INET / SOCK_RAW / IPPROTO_RAW` socket, enables `IP_HDRINCL`, and crafts each packet from scratch — full IPv4 header with the chosen source address, plus a UDP / TCP-SYN / ICMP segment with correct RFC-1071 checksums (pseudo-header included for TCP/UDP). The kernel only writes the IP checksum.

**`tg-listen`** opens an `AF_PACKET / SOCK_RAW` socket and parses every Ethernet frame the kernel hands it. Frames are filtered by:

- IPv4 + protocol = UDP / TCP / ICMP (gated by the `--proto` bitmask)
- TCP: SYN flag set, destination port matches `tcp_port`
- UDP: destination port matches `udp_port`
- ICMP: type 8 (Echo Request); identifier matches `icmp_id` (or any when `icmp_id == 0`)
- Direction: `PACKET_IGNORE_OUTGOING` socket option (kernel ≥ 4.20), with a userspace `sll_pkttype == PACKET_OUTGOING` check as a fallback

Surviving frames update an open-addressed per-IP hash map with linear probing (~26 MiB per protocol). At report time the listener snapshots the map and sorts by packet count.

## Network prerequisites

Spoofed packets only get anywhere when the network between sender and receiver doesn't filter them. The two usual blockers:

```bash
# Many distros default to rp_filter=1 — kills incoming spoofed packets.
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0
sudo sysctl -w net.ipv4.conf.<your-iface>.rp_filter=0

# The kernel may auto-reply to ICMP Echo Requests addressed to spoofed IPs.
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

If you're testing a UDP / TCP path and the receiver's kernel sends ICMP-unreachable or TCP-RST back to the spoofed source, you'll see weird drops at the sender's network too. Suppress with:

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
```

## Tips

- **Match `--proto` on both ends.** If `tg-scan` is sending UDP only, run `tg-listen ... -p udp` — otherwise the listener will mix in random TCP-SYN / ICMP traffic that happens to hit the box.
- **Pick `icmp_id` carefully** — `0x0001` is what `/bin/ping` uses, so it collides with regular pings on the same wire. Anything less common (`0x4321`, `0x7E5F`) is fine. The default `0x1234` is unique enough for most setups.
- **Always set `--rate`** for serious runs. Unlimited will saturate every queue between you and the target and cause artificial drops that look like DPI but aren't.
- **Keep `--size` under 1400 B** to avoid IP fragmentation on standard MTU-1500 paths — fragments are handled inconsistently by DPI.
- **TCP throughput is SYN-only**. You can't establish a real TCP connection from a spoofed source (the SYN-ACK comes back to someone else), so the TCP throughput count measures how many SYNs survive — useful for stateful-firewall behavior, less so for "throughput" in the literal sense.

## Disclaimer

This is a research and operations tool intended for use on **infrastructure you own or have explicit authorization to test**. Sending spoofed-source packets to systems you do not control is unwelcome at best and illegal in many jurisdictions. Don't do it.

## License

MIT.
