import pyshark
import seaborn as sns
import matplotlib.pyplot as plt
from collections import Counter


file = 'all1_anon.pcap'


cap = pyshark.FileCapture(file, use_json=True)


protocol_counts = Counter()

for pkt in cap:
    for layer in pkt.layers:
        protocol_counts[layer.layer_name.lower()] += 1

cap.close()

#treat protocols as key-value pairs
protocols = list(protocol_counts.keys())
counts = list(protocol_counts.values())

# set style for display. look this up further later on
sns.set(style="whitegrid")

# bar chart
plt.figure(figsize=(10, 6))
sns.barplot(x=counts, y=protocols, palette="viridis")


#plt.title(f"protocol frequency in {file}")
plt.title(f"prtocol frequency")
plt.xlabel("pckt count")
plt.ylabel("proto")
plt.tight_layout()
plt.show()
