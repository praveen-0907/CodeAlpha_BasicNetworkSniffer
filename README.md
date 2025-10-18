# Sniffer CLI (Python / Scapy)

## Overview
`sniffer-cli.py` is a **Kali Linux-ready packet sniffer** written in Python using Scapy. It allows users to:

- Capture live network traffic on a specified interface
- Apply optional libpcap filters (BPF)
- Write captured packets incrementally to a `.pcap` file
- Gracefully stop capture with `Ctrl+C`
- Analyze captured packets for TCP payloads
- Optionally analyze existing pcap files without capturing

This project is ideal for **learning network traffic capture, analysis, and basic cybersecurity monitoring**.

---

## Features

1. **Interface Selection**
   - User can specify interface (`-i`) or choose interactively.
   - Compatible with Ethernet (`eth0`) or wireless monitor interfaces (`wlan0mon`).

2. **Capture Filters**
   - Optional BPF filter (`-f`) to capture specific traffic (e.g., `"tcp port 80"`).
   - Removing filters works reliably to capture all traffic.

3. **Packet Writing**
   - Incrementally writes to `.pcap` using `PcapWriter`.
   - `sync=True` ensures packets are immediately saved to disk.

4. **Graceful Shutdown**
   - Handles `Ctrl+C` or termination signals.
   - Ensures `.pcap` is safely closed.
   - Optional automatic analysis after capture (`--analyze-after-capture`).

5. **Packet Analysis**
   - Analyze captured `.pcap` files (`--analyze-file`) or post-capture.
   - Shows TCP payload lengths and first 200 bytes of payload.
   - Uses `PcapReader` for streaming large files safely.

6. **Stats**
   - Periodically prints protocol summary counts every 20 packets.
   - Quiet mode (`-q`) suppresses individual packet printing.

---

## Requirements

- Kali Linux or any Linux distribution
- Python 3.x
- Scapy
- libpcap development library (`libpcap-dev`)

### Install dependencies:

```bash
sudo apt update
sudo apt install -y libpcap-dev python3-pip
python3 -m pip install --upgrade pip
python3 -m pip install scapy
```
## Notes / Caveats

- Root privileges required for live capture.
- Filters must match existing traffic; otherwise, no packets will be written.
- Encrypted traffic (HTTPS/TLS) will show payload length but not plaintext.
- Large .pcap files are handled safely via PcapReader.
- Console output can be verbose; use -q to suppress summaries.

## Project Goals

- Learn packet capture and network protocol basics
- Understand TCP handshake vs payload (Len=0 for SYN/ACK, >0 for data)
- Implement graceful shutdown and incremental pcap writing
- Perform basic traffic analysis (payloads, protocols, counts)
