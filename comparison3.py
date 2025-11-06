import pyshark
import matplotlib.pyplot as plt
from collections import Counter

file = 'capture1.pcap'

network_protocols = {'eth', 'ip', 'ip6', 'tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'https'}
parser_layers = {'mdns', 'llmnr', 'data-text-lines', 'xml', 'json', 'html', 'ssl', 'tls'}
#check https://www.ecma-international.org/wp-content/uploads/s020269e.pdf and 
#https://stackoverflow.com/questions/36901995/list-for-wireshark-tshark-payload-protocols and
#https://wiki.wireshark.org/ProtocolReference

#print(f"Analysiere {file} ...")
cap = pyshark.FileCapture(file, use_json=True)

counts = Counter()

for pkt in cap:
    layers = {layer.layer_name.lower() for layer in pkt.layers}

    # check protocol presence in set network_protocols
    if any(proto in layers for proto in network_protocols):
        counts['network_protocol'] += 1

    # check for presence in parser_layer set
    if any(proto in layers for proto in parser_layers):
        counts['parser_layer'] += 1

    # if not in either, lump it into "other"
    if not any(proto in layers for proto in network_protocols.union(parser_layers)):
        counts['other'] += 1

cap.close()

# the diagram
#note: look up other options for diagrams
labels = ['network protocol', 'parser/payload', 'others']
values = [counts['network_protocol'], counts['parser_layer'], counts['other']]

plt.figure(figsize=(8, 5))
bars = plt.bar(labels, values, color=['dodgerblue', (0.1,0.2,0.6), 'gray'])
#check https://matplotlib.org/stable/gallery/color/named_colors.html for a complete list of possible colours and formats thereof

# bar values
for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, yval + 5, int(yval), ha='center', va='bottom')
    #check https://matplotlib.org/stable/plot_types/index.html for further options for charts and plots

plt.ylabel('number of packets')
plt.title(f'packet analysis of {file}: network protocol and parser/payload layer')
plt.tight_layout()
plt.show()
