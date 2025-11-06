import pyshark
import matplotlib.pyplot as plt
from collections import Counter

def count_protocols(pcap_file):
    #print(f"Analysiere {pcap_file} ...")
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)
    protocol_counts = Counter()
    for pkt in capture:
        
        proto = pkt.highest_layer
        protocol_counts[proto] += 1
    capture.close()
    return protocol_counts

# 1st capture and 2nd capture
prot1 = count_protocols("capture1.pcap")


prot2 = count_protocols("capture2.pcap")

# gathering all protocols' information. note: review this
#set used as it doesn't allow for repetitions
all_protocols = sorted(set(prot1.keys()) | set(prot2.keys()))

# assembling teh diagram
counts1 = [prot1.get(p, 0) for p in all_protocols]
counts2 = [prot2.get(p, 0) for p in all_protocols]

x = range(len(all_protocols))
width = 0.35

plt.figure(figsize=(12, 6))
plt.bar([i - width/2 for i in x], counts1, width=width, label="capture1.pcap")
plt.bar([i + width/2 for i in x], counts2, width=width, label="capture2.pcap")

plt.xticks(x, all_protocols, rotation=12, ha='right')
plt.ylabel("number of packets")
plt.title("comparison: capture1.pcap und capture2.pcap")
plt.legend()
plt.tight_layout()
plt.show()
