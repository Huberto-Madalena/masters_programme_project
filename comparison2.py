import pyshark
import matplotlib.pyplot as plt
from collections import Counter


def proto_count(pcap_file):
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)
    protocol_counter = Counter()
    for pkt in capture:
        proto = pkt.highest_layer  
        protocol_counter[proto] += 1
    capture.close()
    return protocol_counter

pcap_file = "capture1.pcap"

protocol_counts = proto_count(pcap_file)

top_protocols = protocol_counts.most_common() 
protocols, counts = zip(*top_protocols)

# 
plt.figure(figsize=(12, 6))
plt.bar(protocols, counts, color='skyblue')
plt.xticks(rotation=10, ha='right')
plt.ylabel("packet count")
plt.title(f"protocol frequency in {pcap_file}")
plt.tight_layout()
plt.show()
