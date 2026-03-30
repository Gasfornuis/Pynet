#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP
import argparse
import time
import socket

syn_scan_tracker = {}
tcp_scan_tracker = {}
packet_trigger = 20
timewindow_trigger = 10

def get_host_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def detect_SYN_scan(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].flags == "S":
            source_ip = packet[IP].src
            destination_port = packet[TCP].dport
            flags = packet[TCP].flags
            if source_ip not in syn_scan_tracker:
                syn_scan_tracker[source_ip] = []

            syn_scan_tracker[source_ip].append((destination_port, time.time()))
            syn_scan_tracker[source_ip] = [
                (p, t) for (p, t) in syn_scan_tracker[source_ip]
                if time.time() - t <= timewindow_trigger
            ]
            if not syn_scan_tracker[source_ip]: 
                syn_scan_tracker.pop(source_ip)
            if len(syn_scan_tracker[source_ip]) >= packet_trigger:
                established = tcp_scan_tracker.get(source_ip, {}).get("established", [])
                if not established:
                    ports = [p for (p, t) in syn_scan_tracker[source_ip]]
                    print(f"[ALERT] half open scan from: {source_ip}"
                          f"{len(ports)} SYNs sent with no completed handshakes")

def detect_full_TCP_scan(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        flags = packet[TCP].flags
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        dest_port = packet[TCP].dport
        source_port = packet[TCP].sport

        match flags:
            case "S":
                if source_ip not in tcp_scan_tracker:
                    tcp_scan_tracker[source_ip] = {"syn": {}, "established": []}
                tcp_scan_tracker[source_ip]["syn"][dest_port] = time.time()
                
            case "SA":
                if dest_ip not in tcp_scan_tracker:
                    tcp_scan_tracker[dest_ip] = {"syn": {}, "established": []}
                if source_port in tcp_scan_tracker.get(dest_ip, {}).get("syn", {}):
                    tcp_scan_tracker[dest_ip]["syn"][source_port] = time.time()

            case "A":
                if source_ip in tcp_scan_tracker:
                    if dest_port in tcp_scan_tracker[source_ip].get("syn", {}):
                        tcp_scan_tracker[source_ip]["established"].append((dest_port, time.time()))
                        tcp_scan_tracker[source_ip]["established"] = [
                            (p, t) for (p, t) in tcp_scan_tracker[source_ip]["established"]
                            if time.time() - t <= timewindow_trigger
                        ]
                        if len(tcp_scan_tracker[source_ip]["established"]) >= packet_trigger:
                            ports = [p for (p, t) in tcp_scan_tracker[source_ip]["established"]]
                            print(f"[ALERT] Full TCP scan from {source_ip} — "
                                  f"{len(ports)} completed handshakes "
                                  f"in {timewindow_trigger}s window")
                            tcp_scan_tracker[source_ip]["established"] = []
                            tcp_scan_tracker[source_ip]["syn"] = {}                
                
def main():
    parser = argparse.ArgumentParser(description="simple port scanning detection")
    parser.add_argument("-i", "--interface", help="network interface for packet sniffing", required=True)
    parser.add_argument("-p", "--packet-type", help="type of packet to detect (SYN, TCP, UDP)", default="SYN")
    args = parser.parse_args()
    host_ip  = get_host_ip()
    
    print(f"starting {args.packet_type} scan detection on interface: {args.interface}")

    match args.packet_type:
        case "SYN":
            sniff(iface=args.interface, filter="tcp", prn=detect_SYN_scan, store=0)

        case "TCP":
            sniff(iface=args.interface, filter=f"tcp and dst host {host_ip}", prn=detect_full_TCP_scan, store=0)
    
if __name__ == "__main__":
    main()
