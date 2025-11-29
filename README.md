# DNS-Sentinel

<p align="center">
  <img src="DNS-Sentinel Logo.png" alt="DNS-Sentinel Logo" width="200"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Clang-12+-blue?logo=clang" />
  <img src="https://img.shields.io/badge/libbpf-supported-brightgreen?logo=linux" />
  <img src="https://img.shields.io/badge/eBPF-programming-blue?logo=linux" />
  <img src="https://img.shields.io/badge/XDP-enabled-orange?logo=linux" />
  <img src="https://img.shields.io/badge/Linux-kernel%205.x-black?logo=linux" />
</p>

## Overview

DNS-Sentinel is a lightweight eBPF-powered DNS monitoring tool written
in C. It captures outgoing DNS queries from your system and displays the
domains your machine is resolving in real time with minimal overhead.

## Features

-   Capture DNS queries in real time\
-   Display visited domains directly in the terminal\
-   Kernel-space packet inspection using XDP\
-   Safe memory operations\
-   Minimal CPU overhead\
-   Pure libbpf implementation

## Architecture

                  ┌────────────────┐
                  │   User Space   │
                  │ dns_sentinel   │
                  └───────▲────────┘
                          │ BPF Maps
                          │ (Counters, Timestamps, Domains)
                  ┌───────┴────────┐
                  │    XDP/eBPF    │
                  │ dns-sentinel   │
                  └───────▲────────┘
                          │
                    Network Traffic
                          │
                     DNS Queries (UDP/53)


## Installation

Requirements: Linux kernel 5.8+, clang, libbpf-dev, llvm, bpftool, make.

### Build

    make

### Run

    sudo ./dns_sentinel_user

## What I Learned

-   eBPF Fundamentals\
-   Kernel-space C restrictions\
-   libbpf usage\
-   DNS packet parsing\
-   Linux terminal fluency\
-   Personal growth and persistence

## Domain Hashing

The eBPF program uses DJB2 hashing to index domains.  
User-space maintains a hash → string table to reconstruct domain names.

## Performance

XDP runs before iptables and before the networking stack, allowing  
line-rate packet processing with minimal overhead.


## Limitations

- Only supports **IPv4 DNS traffic**  
- Domain strings limited to **96 bytes**  
- Does not monitor DoH/DoT (encrypted DNS)  
- Single-interface monitoring by default 

## License

MIT License.
