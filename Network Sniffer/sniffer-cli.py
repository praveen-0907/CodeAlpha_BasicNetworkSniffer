#!/usr/bin/env python3

import argparse
import signal
import sys
from collections import Counter

from scapy.all import (
    sniff,
    PcapWriter,
    get_if_list,
    conf,
    PcapReader,
    Raw,
)
from scapy.utils import hexdump

# -------------------------
# Argument parsing
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Simple Scapy sniffer (Kali-ready)")
    p.add_argument("-i", "--iface", required=False,
                   help="Interface to listen on (e.g., eth0, wlan0mon)")
    p.add_argument("-f", "--filter", default="",
                   help="libpcap BPF filter string (e.g., 'tcp and port 80')")
    p.add_argument("-o", "--outfile", default="capture.pcap",
                   help="Output pcap file (default: capture.pcap)")
    p.add_argument("-c", "--count", type=int, default=0,
                   help="Packet count (0 = unlimited)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Quiet mode: don't print each packet summary")
    # Analysis flags
    p.add_argument("--analyze-file", default=None,
                   help="Analyze an existing pcap file and exit")
    p.add_argument("--analyze-after-capture", action="store_true",
                   help="Analyze outfile automatically after capture ends")
    p.add_argument("--analyze-max", type=int, default=0,
                   help="When analyzing, limit to this many packets (0 = all)")
    return p.parse_args()


# -------------------------
# Pcap analysis function
# -------------------------
def analyze_pcap(path, max_packets=None):
    print(f"[ANALYZE] Opening pcap: {path!r}")
    try:
        reader = PcapReader(path)
    except FileNotFoundError:
        print(f"[ANALYZE] File not found: {path}")
        return
    except Exception as e:
        print(f"[ANALYZE] Error opening pcap: {e}")
        return

    count = 0
    try:
        for pkt in reader:
            count += 1
            if max_packets is not None and max_packets > 0 and count > max_packets:
                break

            # Show only TCP packets (you can expand to UDP/ICMP/etc.)
            if pkt.haslayer("TCP"):
                tcp_payload_len = len(pkt["TCP"].payload)
                summary = pkt.summary()
                print(f"[{count}] {summary}  TCP_payload_len={tcp_payload_len}")

                if tcp_payload_len > 0:
                    # Prefer Raw layer if present
                    if Raw in pkt:
                        data = pkt[Raw].load
                        print("  Payload (first 200 bytes):")
                        # Try UTF-8 display, fall back to hexdump
                        try:
                            text = data.decode("utf-8", errors="replace")
                            print(text[:200])
                        except Exception:
                            hexdump(data[:200])
                    else:
                        # Fallback: get raw bytes from transport payload
                        payload_bytes = bytes(pkt["TCP"].payload)
                        if payload_bytes:
                            print("  Has non-zero payload but Raw layer missing. Hexdump:")
                            hexdump(payload_bytes[:200])
                        else:
                            print("  tcp.len > 0 but no printable payload found.")
            # Progress hint for large files
            if count % 1000 == 0:
                print(f"[ANALYZE] Processed {count} packets...")

    finally:
        try:
            reader.close()
        except Exception:
            pass

    print(f"[ANALYZE] Done. Packets processed: {count}")


# -------------------------
# Main sniffer logic
# -------------------------
def main():
    args = parse_args()

    # If user requested only analysis of an existing file => run and exit
    if args.analyze_file:
        maxp = args.analyze_max if args.analyze_max > 0 else None
        analyze_pcap(args.analyze_file, max_packets=maxp)
        sys.exit(0)

    # Warn if libpcap/filter support isn't available
    if not conf.use_pcap:
        print("Warning: libpcap not available; BPF filters may not work as expected. "
              "Install libpcap-dev if needed (sudo apt install libpcap-dev).")

    # Interface selection (interactive fallback)
    iface = args.iface
    if not iface:
        print("Available interfaces:", get_if_list())
        iface = input("Choose interface (e.g., eth0, wlan0mon): ").strip()
        if not iface:
            print("No interface chosen. Exiting.")
            sys.exit(1)

    print(f"Interface: {iface}")
    if args.filter:
        print(f"Filter: {args.filter!r}")
    print(f"Output file: {args.outfile}")
    if args.count and args.count > 0:
        print(f"Capture packet count limit: {args.count}")
    if args.quiet:
        print("Quiet mode: printing of each packet summary disabled.")

    # Prepare pcap writer (incremental + sync)
    try:
        writer = PcapWriter(args.outfile, append=True, sync=True)
    except Exception as e:
        print("Error opening output pcap for writing:", e)
        sys.exit(1)

    # Stats counters (lightweight)
    proto_counter = Counter()
    total_seen = 0

    # Stop handler: close writer, optionally analyze
    def stop(sig, frame):
        print("\n[STOP] Signal received. Closing pcap and exiting...")
        try:
            writer.close()
        except Exception:
            pass

        # Analyze the output pcap if requested
        if args.analyze_after_capture:
            maxp = args.analyze_max if args.analyze_max > 0 else None
            analyze_pcap(args.outfile, max_packets=maxp)
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    # Packet callback
    def pkt_cb(pkt):
        nonlocal total_seen
        try:
            total_seen += 1

            # Basic protocol counting (every packet regardless of layer)
            # Use pkt.summary() prefix as rough classifier or inspect layers
            try:
                s = pkt.summary().split()[0]
                proto_counter[s] += 1
            except Exception:
                proto_counter["UNKNOWN"] += 1

            # Print summary unless quiet
            if not args.quiet:
                try:
                    print(pkt.summary())
                except Exception:
                    print(repr(pkt)[:200])

            # Write to pcap; keep running even if write fails
            try:
                writer.write(pkt)
            except Exception as e:
                print("[WRITE ERROR]", e)

            # Periodic small stats to console
            if total_seen % 20 == 0:
                top = proto_counter.most_common(5)
                print(f"[STATS] Packets seen: {total_seen}; Top proto summaries: {top}")

        except Exception as cb_e:
            # Ensure callback exceptions don't kill sniff loop
            print("[CALLBACK ERROR]", cb_e)

    # Run the sniff
    sniff_count = args.count if args.count > 0 else 0  # 0 => unlimited for Scapy
    try:
        sniff(iface=iface,
              filter=(args.filter if args.filter else None),
              prn=pkt_cb,
              store=False,
              count=sniff_count)
    except PermissionError:
        print("Permission error: run the script with elevated privileges (sudo).")
        try:
            writer.close()
        except Exception:
            pass
        sys.exit(1)
    except OSError as e:
        print("OSError from sniff():", e)
        print("Possible causes: invalid interface, BPF filter issue, or missing libpcap.")
        try:
            writer.close()
        except Exception:
            pass
        sys.exit(1)
    except KeyboardInterrupt:
        # Fallback; signal handler should handle normally
        stop(None, None)

    # If sniff returned because count was reached, optionally analyze
    if args.analyze_after_capture:
        maxp = args.analyze_max if args.analyze_max > 0 else None
        analyze_pcap(args.outfile, max_packets=maxp)

    # Close writer on normal exit
    try:
        writer.close()
    except Exception:
        pass

    print("[DONE] Capture finished. Exiting.")


if __name__ == "__main__":
    main()
