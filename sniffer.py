#!/usr/bin/env python3

import argparse
import datetime
import sys
from textwrap import shorten

try:
    from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, Raw, wrpcap
except Exception as e:
    print("Scapy import failed. Install it with: pip install scapy")
    raise

BANNER = r"""
===========================================================
   Educational Packet Sniffer  |  Use only with permission
===========================================================
This tool is for learning and lab use. Sniffing networks
you don't own/manage or lack consent for may be illegal.
"""

def confirm_ethics(flag_ok: bool) -> None:
    if flag_ok:
        return
    print(BANNER)
    resp = input("I confirm I will use this tool ethically and lawfully [yes/no]: ").strip().lower()
    if resp not in {"y", "yes"}:
        print("Aborting. Please use this tool only for authorized, educational purposes.")
        sys.exit(1)

def ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")

def proto_name(pkt) -> str:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IP):
        return f"IP-proto-{pkt[IP].proto}"
    return "OTHER"

def endpoint_info(pkt) -> tuple[str, str, str]:
    src = dst = "-"
    port_info = ""
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
    if pkt.haslayer(TCP):
        port_info = f"{pkt[TCP].sport}->{pkt[TCP].dport}"
    elif pkt.haslayer(UDP):
        port_info = f"{pkt[UDP].sport}->{pkt[UDP].dport}"
    return src, dst, port_info

def payload_preview(pkt, max_bytes: int = 32) -> str:
    if Raw in pkt:
        data = bytes(pkt[Raw].load)
        # Build a safe, mostly printable preview
        safe = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:max_bytes])
        return shorten(safe, width=max_bytes, placeholder="…")
    return ""

def summarize(pkt, show_mac: bool = False) -> str:
    p = proto_name(pkt)
    src, dst, ports = endpoint_info(pkt)

    mac_part = ""
    if show_mac and pkt.haslayer(Ether):
        mac_part = f"  MAC {pkt[Ether].src} -> {pkt[Ether].dst}"

    size = len(pkt)
    payload = payload_preview(pkt)
    port_part = f"  Ports {ports}" if ports else ""
    payload_part = f"  Payload '{payload}'" if payload else ""

    return f"[{ts()}] {p:4}  {src} -> {dst}  ({size} B){port_part}{mac_part}{payload_part}"

def main():
    parser = argparse.ArgumentParser(
        description="Educational packet sniffer (Scapy)",
        epilog="Examples:\n"
               "  sudo python3 sniffer.py -i eth0 -c 50\n"
               "  sudo python3 sniffer.py -i wlan0 -f 'tcp port 80'\n"
               "  sudo python3 sniffer.py -i en0 --pcap out.pcap\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--interface", help="Network interface to sniff (e.g., eth0, wlan0, en0)", required=True)
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp', 'udp', 'port 53', 'host 8.8.8.8')", default=None)
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("--show-mac", action="store_true", help="Also display Ethernet MAC addresses")
    parser.add_argument("--pcap", help="Save all captured packets to this PCAP file")
    parser.add_argument("--i-understand", action="store_true",
                        help="Skip ethics prompt (asserts you have authorization and consent)")

    args = parser.parse_args()
    confirm_ethics(args.i_understand)

    captured = []

    def _on_packet(pkt):
        line = summarize(pkt, show_mac=args.show_mac)
        print(line)
        if args.pcap:
            captured.append(pkt)

    print(f"Starting capture on {args.interface!r} "
          f"{'(filter: ' + args.filter + ')' if args.filter else ''} "
          f"{'(count: ' + str(args.count) + ')' if args.count else '(count: ∞)'}")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=_on_packet,
            store=False,           # don’t keep everything in RAM (we append selectively)
            count=args.count if args.count > 0 else 0
        )
    except PermissionError:
        print("Permission denied. Try running with sudo/Administrator privileges.")
        sys.exit(1)
    except OSError as e:
        print(f"OS/Interface error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        if args.pcap and captured:
            try:
                wrpcap(args.pcap, captured)
                print(f"\nSaved {len(captured)} packets to '{args.pcap}'.")
            except Exception as e:
                print(f"\nFailed to save PCAP: {e}")

    print("\nCapture finished. Remember to handle any data ethically and securely.")

if __name__ == "__main__":
    main()

