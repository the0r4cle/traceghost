# traceghost

A pair of Linux command-line utilities for probing which spoofed source IP addresses successfully traverse the egress filter of the sending network and the ingress filter of the receiving host, and for detecting when deep-packet-inspection or stateful firewalls terminate connections in mid-stream.

---

## Overview

`traceghost` consists of two cooperating command-line utilities:

| Binary      | Role                                                                                                  |
| ----------- | ----------------------------------------------------------------------------------------------------- |
| `tg-scan`   | **Sender.** Emits raw IPv4 probes with a spoofed source address toward a specified target.            |
| `tg-listen` | **Receiver.** Captures arriving packets and aggregates statistics keyed by `(protocol, source IP)`.   |

Each utility supports two subcommands, which are intended to be paired across the wire:

| Mode           | Sender behaviour                                                              | Listener report                                                                       |
| -------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| **discover**   | Emits a single probe per source IP for each requested protocol.               | Lists the source addresses that arrived, grouped by protocol.                         |
| **throughput** | Emits *N* packets of *S* bytes per source IP on a single protocol, rate-limited. | Reports per-source packet and byte counters, sorted; reveals which sources drop out.  |

The intended workflow is a two-stage procedure:

1. **`discover`** identifies which spoofed source addresses are permitted by the sender's egress filter and accepted by the receiver's ingress filter.
2. **`throughput`** subjects the surviving sources to sustained traffic, exposing those that are subsequently filtered by stateful inspection devices in the path.

## Use cases

- Identifying source addresses suitable for use with spoofed-IP tunnelling projects.
- Auditing the egress filtering policy (BCP 38 / uRPF) of a network under one's control.
- Verifying the reverse-path-filtering configuration of a server.
- Characterising **deep-packet-inspection behaviour**: a source that succeeds during `discover` (one packet) but fails during `throughput` (hundreds of packets) indicates the presence of stateful tracking in the path.
- Research on network-level censorship circumvention on infrastructure owned by the researcher.

## Features

- **Performance.** Raw `AF_INET / IPPROTO_RAW` send path with stack-allocated packet buffers and the `IP_HDRINCL` socket option, minimising kernel involvement on the hot path.
- **Three protocols supported.** UDP datagrams, TCP-SYN probes, and ICMP Echo Requests.
- **Configurable payload size** in throughput mode (0–1400 bytes, to remain below typical path MTUs).
- **Rate limiter** based on `clock_gettime(CLOCK_MONOTONIC)` and `nanosleep`, providing drift-free scheduling. Specify `--rate` in packets per second; `0` disables the limiter.
- **Per-protocol capture filter on the listener.** Only the protocols of interest are recorded; unrelated traffic on the same interface is ignored.
- **Quiet defaults.** A missing default configuration file produces no output; a configuration file explicitly requested with `-c` and not found produces a warning.
- **Per-source counters** maintained in the listener using an open-addressed hash table, with a sorted top-*N* live view and a final report written to disk.
- **Command-line interface** with subcommands, long and short flags, and INI-style configuration files for values that need not be repeated on every invocation.
- **Capture hygiene.** The listener discards outgoing packets via the `PACKET_IGNORE_OUTGOING` socket option (Linux ≥ 4.20), with a userspace fallback for older kernels. Both ends may therefore be run on the same host for testing without inflating the counts.
- **Minimal footprint.** Approximately 1,200 lines of dependency-free C; builds in seconds via `make`.

## Building

```bash
make
```

Two binaries are produced in the working directory: `tg-scan` and `tg-listen`.

To avoid invoking `sudo` on every execution, the `CAP_NET_RAW` capability may be granted to the binaries (Linux only):

```bash
make setcap
./tg-listen discover
```

## Quick start

### Stage 1 — discover

On the **target** host (the system that will receive probes):

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

Upon receiving `Ctrl+C`, the listener writes a sorted report to `scan_report.txt`. Extract the addresses that arrived and place them, one per line, in a file such as `open_ips.txt` for use in the next stage.

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

The resulting per-source table indicates, for each address discovered in Stage 1, how many of the 500 packets ultimately arrived. A source that achieved a near-perfect rate during `discover` but a low rate during `throughput` constitutes a strong indication of stateful deep-packet inspection on the path.

> **Note.** Both ends must be configured with the same `--proto` selection. Otherwise the listener will count unrelated TCP-SYN or ICMP traffic that happens to arrive at the host.

## Configuration files

Each utility loads its own INI-style configuration file from the working directory:

| Binary      | Default file       | Resides on    |
| ----------- | ------------------ | ------------- |
| `tg-scan`   | `tg-scan.conf`     | sender host   |
| `tg-listen` | `tg-listen.conf`   | target host   |

Three keys appear in both files because they **must match across the wire**:

```ini
udp_port = 54321
tcp_port = 54322
icmp_id  = 0x1234     # in the listener, 0 means "match any identifier"
```

Unrecognised keys in a configuration file are silently ignored; a single combined configuration file may therefore be shared between the two utilities. Command-line flags take precedence over values set in the configuration file.

Annotated sample files are provided: see [`tg-scan.conf`](tg-scan.conf) and [`tg-listen.conf`](tg-listen.conf).

## Command-line reference

### `tg-scan`

```
Usage:
  tg-scan <discover|throughput> [options]

Common options:
  -c, --config <file>     INI configuration file                   (default: tg-scan.conf)
  -t, --target <ip>       target IP address (overrides config)
  -r, --range <cidr>      source CIDR (repeatable; overrides config)
  -p, --proto <list>      udp,tcp,icmp  or  udp / tcp / icmp / all
      --udp-port <p>      destination UDP port                     (default: 54321)
      --tcp-port <p>      destination TCP port                     (default: 54322)
      --icmp-id <n>       ICMP echo identifier                     (default: 0x1234)
      --rate <pps>        packet-per-second limit; 0 = unlimited
      --report <secs>     progress reporting interval              (default: 2.0)

Throughput-only options:
      --size <bytes>      payload bytes per packet (0..1400)       (default: 1024)
      --count <N>         packets emitted per source IP            (default: 100)
      --ips-file <file>   one IP per line; overrides --range
```

### `tg-listen`

```
Usage:
  tg-listen <discover|throughput> [options]

Options:
  -c, --config <file>     INI configuration file                   (default: tg-listen.conf)
  -p, --proto <list>      protocols to record: udp,tcp,icmp / all  (default: all)
      --udp-port <p>      UDP destination port to record           (default: 54321)
      --tcp-port <p>      TCP destination port to record (SYN)     (default: 54322)
      --icmp-id <n>       ICMP echo identifier to record; 0 = any  (default: 0x1234)
      --report <secs>     live-report interval                     (default: 2.0)
      --top <N>           rows to display in throughput view; 0 = all  (default: 10)
      --rcvbuf <bytes>    SO_RCVBUF size                           (default: 16 MiB)
  -o, --output <file>     final report destination                 (default: scan_report.txt)
```

## Operation

**`tg-scan`** opens an `AF_INET / SOCK_RAW / IPPROTO_RAW` socket, enables `IP_HDRINCL`, and constructs each packet in full: a 20-byte IPv4 header carrying the selected source address, followed by a UDP, TCP-SYN, or ICMP Echo Request segment with checksums computed in accordance with RFC 1071 (including the pseudo-header for UDP and TCP). The kernel computes only the IPv4 header checksum.

**`tg-listen`** opens an `AF_PACKET / SOCK_RAW` socket and parses every Ethernet frame delivered by the kernel. Frames are filtered according to:

- IPv4 with protocol equal to UDP, TCP, or ICMP (gated by the `--proto` bitmask);
- TCP: SYN flag set and destination port equal to `tcp_port`;
- UDP: destination port equal to `udp_port`;
- ICMP: type 8 (Echo Request) and identifier equal to `icmp_id` (or any identifier when `icmp_id == 0`);
- Direction: outgoing frames are discarded via the `PACKET_IGNORE_OUTGOING` socket option (Linux ≥ 4.20), with a userspace check on `sll_pkttype == PACKET_OUTGOING` as a fallback.

Frames that pass these filters update a per-source-address open-addressed hash map with linear probing (approximately 26 MiB per protocol). At reporting time the listener takes a snapshot of the map and sorts it by packet count in descending order.

## Network prerequisites

Spoofed packets reach their destination only if neither network on the path filters them. The two configurations most commonly responsible for unexpected loss are:

```bash
# Many distributions enable rp_filter by default, which causes the kernel
# to discard packets whose source address does not reverse-route correctly.
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0
sudo sysctl -w net.ipv4.conf.<interface>.rp_filter=0

# The kernel may emit unsolicited Echo Reply messages when an Echo Request
# directed at a spoofed source address is received.
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

If, while testing a UDP or TCP path, the receiver's kernel emits ICMP-unreachable messages or TCP-RST segments to the spoofed source, additional spurious drops may be observed on the sender side. These responses may be suppressed at the firewall:

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
```

## Operational notes

- **Align `--proto` between the two ends.** When `tg-scan` is configured to emit UDP traffic only, the listener should be invoked with `-p udp`; otherwise unrelated TCP-SYN and ICMP traffic arriving at the host will be included in the report.
- **Select `icmp_id` deliberately.** The value `0x0001` is the default identifier used by `/bin/ping`; it collides with ordinary diagnostic traffic on shared interfaces. Less common values (for instance `0x4321` or `0x7E5F`) are preferable. The default of `0x1234` is suitable for most deployments.
- **Set `--rate` for non-trivial runs.** Unlimited transmission saturates intermediate queues and produces artificial loss that is easily mistaken for inspection-induced drops.
- **Keep `--size` below 1400 bytes.** This avoids IP-level fragmentation on MTU-1500 paths; fragments are handled inconsistently by inspection devices and complicate the interpretation of results.
- **TCP throughput is restricted to SYN segments.** A genuine TCP connection cannot be established from a spoofed source — the SYN-ACK is delivered to a third party — so the TCP throughput count measures the number of SYNs admitted, which characterises stateful firewall behaviour rather than data throughput proper.

## Disclaimer

`traceghost` is a research and operations tool intended for use on infrastructure that the operator owns or is explicitly authorised to test. Transmission of spoofed-source packets to systems outside the operator's authority is unwelcome at best and unlawful in many jurisdictions. The authors disclaim responsibility for any misuse.

## License

Released under the terms of the MIT License. See [`LICENSE`](LICENSE) for details.
