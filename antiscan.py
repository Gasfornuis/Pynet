#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP
import argparse
import time

scan_tracker = {}
packet_trigger = 20
timewindow_trigger = 10

def detect_SYN_scan(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].flags == "S":
            source_ip = packet[IP].src
            destination_port = packet[TCP].dport
            flags = packet[TCP].flags
            if source_ip not in scan_tracker:
                scan_tracker[source_ip] = []

            scan_tracker[source_ip].append((destination_port, time.time()))
            scan_tracker[source_ip] = [
                (p, t) for (p, t) in scan_tracker[source_ip]
                if time.time() - t <= timewindow_trigger
            ]
            if not scan_tracker[source_ip]: 
                scan_tracker.pop(source_ip)
            if len(scan_tracker[source_ip]) >= packet_trigger:
                ports = [p for (p, t) in scan_tracker[source_ip]]
                print(f"[ALERT] {source_ip} scanning ports:{len(ports)}")

def detect_full_TCP_scan(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP) and not packet[TCP].flags == "S":
         

def main():
    parser = argparse.ArgumentParser(description="simple port scanning detection")
    parser.add_argument("-i", "--interface", help="network interface for packet sniffing", required=True)
    parser.add_argument("-p", "--packet-type", help="type of packet to detect (SYN, TCP, UDP)", default="SYN")
    args = parser.parse_args()
    
    print(f"starting {args.packet_type} scan detection on interface: {args.interface}")

    match args.packet_type:
        case "SYN":
            sniff(iface=args.interface, filter="tcp", prn=detect_SYN_scan, store=0)

        case "TCP":
            sniff(iface=args.interface, filter="tcp", prn=detect_full_TCP_scan, store=0)
    
if __name__ == "__main__":
    main()
