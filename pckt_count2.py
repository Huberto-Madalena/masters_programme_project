#!/usr/bin/env python3
from scapy.all import rdpcap, IP, IPv6, ARP, TCP, UDP, ICMP
import sys

if len(sys.argv) < 2:
    print("you need to input 2 arguments, ending with <file.pcap>")
    exit()

packets = rdpcap(sys.argv[1])
count = {"IPv4": 0, "IPv6": 0, "ARP": 0, "TCP": 0, "UDP": 0, "ICMP":0}

for p in packets:
    if p.haslayer(IP):   count["IPv4"] += 1
    if p.haslayer(IPv6): count["IPv6"] += 1
    if p.haslayer(ARP):  count["ARP"]  += 1
    if p.haslayer(TCP):  count["TCP"]  += 1
    if p.haslayer(UDP):  count["UDP"]  += 1
    if p.haslayer(ICMP): count["ICMP"] += 1

print("\n=== num of header pckts ===")
for k, v in sorted(count.items(), key=lambda x: x[1], reverse=True):
    print(f"{k:<6}: {v}")
print("==========================")
