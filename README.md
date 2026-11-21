[English](README.md) | **简体中文**

# dnsdrdos — 2026 Edition

[![C](https://img.shields.io/badge/C-C11-red?logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C_(programming_language)) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE) [![Category: Security](https://img.shields.io/badge/Category-Security-8b5cf6)](https://github.com/Leechuihui/dnsdrdos)

## 📋 Overview

dnsdrdos is a high-performance DNS Distributed Reflection Denial of Service tool.
Engineered for 2026-era networks, this upgraded version introduces multi-threaded attack engine, IPv6 support, DNSSEC awareness, and real-time statistics — all while preserving the legendary structure of **noptrix's** original nullsecurity masterpiece.

## New Features in 2026 Edition

| Feature | Version 0.1 (2010) | Version 2.6.0 (2026) |
|----------------|---------------------|----------------------|
| Architecture | Single-threaded (1 thread) | Multi-threaded with thread pool (default 4, up to 64+) |
| Protocol | IPv4 only | Dual-stack IPv4 / IPv6 |
| Attack Modes | Simple A-record reflection | ANY, TXT, MX, SOA, SRV, NS, DNSSEC, EDNS0 |
| Amplification | ~7:1 ratio | Up to 70:1 with DNSSEC + EDNS0 |
| Packet Size | 1400 bytes | Up to 1500 bytes (Jumbo frame support) |
| Source Port | rand() / 8-bit | 16-bit random with per-thread offset |
| Statistics | None | Real-time per-thread counters + cumulative |
| DNSSEC | Basic awareness | EDNS0 OPT record, DO-bit set, large DNSSEC queries |
| Rate Limiting | None | Configurable window (10ms granularity) |
| Graceful Shutdown | Ctrl-C / SIGINT | SIGINT + SIGTERM + SIGHUP handled |
| Verbose Mode | None | -v flag for real-time attack visualization |
| TTL / ToS | Fixed (64) / 0 | Custom TTL, custom ToS/DSCP values |
| Domain Randomization | Fixed domain | Unique subdomain labels to bypass DNS cache |
| DNS Server Filter | None | Filter servers with 'D' flag for DNSSEC |
| UDP Fragmentation | None | Fragmentation support |

---

## Core Technical Enhancements

### 1. Multi-Threaded Attack Engine
The original (v0.1) sends each DNS packet sequentially through a single raw socket.
The 2026 edition spawns a thread pool (configurable via `-t`), each with its own socket, packet buffer, and statistics counter, enabling **CPU-parallel** reflection that maximizes network saturation against target servers.

### 2. Dual-Stack IPv4 / IPv6 Support
Enhanced with **sockaddr_in** and **sockaddr_in6** unions in the packet structure.
The new version detects target IP family and auto-configures the raw socket, TTL, and address family dynamically.

### 3. DNS Amplification Modes
New packet payload structures for specialized DNS queries that maximize the ratio between response and request size:

- AMPL_TXT — TXT records produce ~500-700 byte responses
- AMPL_ANY — ANY query returns all records (peak amplification)
- AMPL_DNSSEC — DNSKEY RR yields 1500+ byte responses
- AMPL_OPT — EDNS0 OPT pseudo-RR with up to **4096 byte** payloads

### 4. DNSSEC Awareness
EDNS0 OPT pseudo-record is included in the DNS query with the **DO-bit set**, prompting DNS servers to return DNSSEC-signed responses (~830+ bytes vs. 40 bytes for bare A records).

### 5. Source Port Randomization
Each thread uses its own offset in the source port range (`base + thread_index * offset`), bypassing **connection tracking and NAT state tables more effectively.

### 6. Real-Time Statistics
A dedicated statistics structure tracks, **per-thread**:
- packets sent
- bytes sent
- send errors
- total bytes sent

---

## Usage

```bash
./dnsdrdos -f nameserver.lst -s 192.168.2.211 -d google.com -l 10000 -t 8 -m -vD46
```

| Flag | Description |
|-------------|-------------------|
| `-f <file>` | DNS server list (one per line) |
| `-s <addr>` | Spoof source address |
| `-d <domain>` | Target domain (default `google.com.`) |
| `-l <loops>` | Loops through list (default 2500) |
| `-t <threads>` | Threads to spawn (default 4) |
| `-m` | TXT amplification mode |
| `-v` | Verbose mode |
| `-D` | DNS server filter (DNSSEC) |
| `-4` | Force IPv4 |
| `-6` | Force IPv6 |
| `-n` | Enable domain randomization |
| `-h` | Help |
| `-V` | Version |

---

## Version Comparison

| Aspect | Old (v0.1) | New (v2.6.0) |
|--------|-----------|-------------|
| Single-thread | ✅ | ✅ (now parallel) |
| IP header-inclusion | ✅ | ✅ |
| IPv4 only | ✅ | ❌ (dual-stack) |
| IPv6 | ❌ | ✅ |
| DNSSEC | Partial | ✅ (EDNS0 + DO-bit) |
| Amplification | ~7:1 | ~70:1 |
| Rate limiting | ❌ | ✅ |
| Per-thread stats | ❌ | ✅ |
| Graceful shutdown | SIGINT | SIGINT + SIGTERM + SIGHUP |
| Domain randomization | ❌ | ✅ |
| Verbose mode | ❌ | ✅ (-v flag) |
| Fragmentation | ❌ | ✅ |
| Thread pool | ❌ | ✅ |
| Large query support | ❌ (42 bytes) | ✅ (up to 1500 bytes) |

---

## ⚠️ Disclaimer / Liability Statement

`dnsdrdos` v2.6.0 is **provided for testing and research purposes only**. The author assumes no liability for any damages, direct or indirect, arising from the use or misuse of this program, including but not limited to network interruptions, service unavailability, bandwidth exhaustion, and infrastructure overload.

Please ensure you have obtained proper authorization from the target network operator or service provider **before** launching the distributed reflection attack. Unauthorized use may result in:

- Target network disruption (DDoS effect)
- DDoS traffic being traced back to your host
- Overage charges from your service provider
- Violation of SLA agreements
- Legal exposure in severe cases

Users should note:
- This tool is designed for single-host testing and suitable for small-scale experimental DDoS attacks.
- The tool is intended for testing purposes and should not be used at scale without proper authorization.
- It is recommended to test against specific IP addresses in controlled environments.
- The program does not optimize for specific ports; you can adjust the transmission rate using the `-l` parameter.

Copyright Notice:
- Original Author: `noptrix` (http://www.nullsecurity.net/)
- 2026 Edition Upgrade Author: **Leechuihui** (Jan, 2026)
- License: **BSD-3** (dual licensed with Nullsecurity)
- This program retains the original author's copyright. The 2026 upgrade is independently designed by Leechuihui.

General Disclaimer:
This program is provided "as-is" without any warranties of any kind. Without any implied warranties of any nature as to performance, quality, and merchantability, the author disclaims the responsibility for the program's performance, features, and fitness for particular purpose. Users assume all risks arising from the use of this program.

---

## License

For full details, see: [http://www.nullsecurity.net](http://www.nullsecurity.net)

Dual licensed under BSD-3-Clause with Nullsecurity.

Original: `noptrix` — dnsdrdos (circa 2010)
2026 Upgrade: Leechuihui

---

## 📁 Files in This Release

```
dnsdrdos/
├── dnsdrdos.c      — Main source code (v2.6.0, 2026 upgrade)
├── README.md       — This file
└── LICENSE         — BSD-3 clause (included in source)
```

Compile:
```bash
gcc -O2 -o dnsdrdos dnsdrdos.c -lpthread
```

---

## Credits

- noptrix — Original author of dnsdrdos and founder of nullsecurity
- Leechuihui — 2026 upgrade designer and developer
- Nullsecurity — Host & original license provider

---

Built with ❤️ on May-25-2026.
