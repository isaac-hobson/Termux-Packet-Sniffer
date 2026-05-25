# Termux Packet Sniffer
A lightweight, high-performance terminal network analyzer designed for Termux and Linux environments. Built on Python and Scapy, this utility provides real-time packet inspection, multi-protocol decoding, and basic anomaly detection inside a low-overhead Curses terminal user interface (TUI).
## Core Capabilities
 * **Live TUI Dashboard:** Monitor live network traffic without the resource overhead of a graphical interface.
 * **Protocol Decoding:** Deep packet inspection for Ethernet, IPv4, TCP (including HTTP), UDP (including DNS), ICMP, and ARP.
 * **Security Auditing:** Automatic tagging for suspicious patterns including SYN, NULL, and XMAS port scans.
 * **Data Portability:** Native session serialization alongside export support for standard .pcap, .json, and .csv formats.
## Installation
### 1. Environment Setup
Ensure your system package manager and Python environment are up to date.
```bash
pkg update && pkg upgrade
pkg install python

```
### 2. Install Dependencies
The application relies on Scapy for network interface interaction.
```bash
pip install scapy

```
## Quick Start Tutorial
### Running the Sniffer
Because packet capture requires raw socket access, you must execute the script with administrative privileges:
```bash
sudo python3 sniffer.py

```
### Interface Controls
| Key | Action |
|---|---|
| Up Arrow / Down Arrow | Navigate and scroll through the active packet list buffer. |
| Q | Gracefully terminate packet capture loops and close the application. |
### Data Fields Explained
The terminal dashboard organizes captured data into high-density columns:
 * **Time:** Precise system timestamp of packet arrival.
 * **Proto:** The highest-layer protocol detected (e.g., TCP, UDP, DNS, HTTP).
 * **Source -> Destination:** Resolved IP addresses and port numbers mapping the traffic direction.
 * **Size:** Total packet length in bytes.
 * **Info:** Summary of packet contents, flag structures, or triggered alerts ([!]).
## Technical Architecture
The utility uses a multi-threaded processing pipeline to prevent UI lag during high-throughput traffic:
```
[ Network Interface ] 
        │
        ▼ (Background Thread)
  Scapy Sniffer ──► Packet Parsing Engine (Layer Extraction)
                          │
                          ▼ (Thread Safe Lock)
                   Shared Deque Buffer ──► Traffic Statistics
                          │
                          ▼ (Main Thread)
                   Curses TUI Render

```