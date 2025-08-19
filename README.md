# PRODIGY_CS_05
Educational packet sniffer using Python and Scapy.

## Educational Packet Sniffer (Python + Scapy)

This project is a **simple packet sniffer** built in Python using the **Scapy** library.  
It captures and displays useful information about network traffic such as:
- Source & Destination IP addresses  
- Protocol (TCP, UDP, ICMP, etc.)  
- Ports (for TCP/UDP packets)  
- A safe preview of the payload data  

⚠️ **Ethical use only!** This tool is designed **for educational and learning purposes**.  
Do **not** use it on networks you don’t own or have explicit permission to monitor.

## Features
- Capture live network packets
- Display IPs, protocol, ports, and payload preview

## Requirements
- Python 3.8+
- [Scapy](https://scapy.net/) (`pip install scapy`)
- **Npcap** (Windows only) → [Download here](https://npcap.com/)
  
## Usage
Run with **Administrator**.

## Basic capture
python sniffer.py -i "Wi-Fi" -c 20

-i → Network interface name (e.g., Wi-Fi, Ethernet)
-c → Number of packets to capture (0 = infinite)

## Sample output
[14:03:01] TCP   192.168.1.5 -> 142.250.183.206  (74 B)  Ports 51674->443  Payload 'GET /...'
[14:03:01] UDP   192.168.1.5 -> 8.8.8.8          (62 B)  Ports 58023->53   Payload '...google.com...'
[14:03:02] ICMP  192.168.1.5 -> 1.1.1.1          (98 B)  Payload '................................'

## Disclaimer
This project is intended only for learning, testing, and lab environments.
Unauthorized packet sniffing may be illegal. Always get permission before monitoring any network traffic.

## Author
Developed by ANUSHKA KUDU
