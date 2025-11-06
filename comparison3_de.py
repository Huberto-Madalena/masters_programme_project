import pyshark
import matplotlib.pyplot as plt
from collections import Counter

# --- Nur eine Datei ---
file = 'capture1.pcap'

# --- Kategorien definieren ---
network_protocols = {'eth', 'ip', 'tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'https'}
parser_layers = {'mdns', 'llmnr', 'data-text-lines', 'xml', 'json', 'html', 'ssl', 'tls'}

# --- Capture laden (alle Layer anzeigen) ---
print(f"Analysiere {file} ...")
cap = pyshark.FileCapture(file, use_json=True)

counts = Counter()

for pkt in cap:
    layers = {layer.layer_name.lower() for layer in pkt.layers}

    # Prüfen, ob das Paket Netzwerkprotokolle enthält
    if any(proto in layers for proto in network_protocols):
        counts['network_protocol'] += 1

    # Prüfen, ob das Paket Parser-/Payload-Schichten enthält
    if any(proto in layers for proto in parser_layers):
        counts['parser_layer'] += 1

    # Wenn nichts erkannt wird
    if not any(proto in layers for proto in network_protocols.union(parser_layers)):
        counts['other'] += 1

cap.close()

# --- Diagramm ---
labels = ['Netzwerkprotokolle', 'Parser-/Payload-Schichten', 'Andere']
values = [counts['network_protocol'], counts['parser_layer'], counts['other']]

plt.figure(figsize=(8, 5))
bars = plt.bar(labels, values, color=['steelblue', 'salmon', 'gray'])

# Werte über den Balken anzeigen
for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, yval + 5, int(yval), ha='center', va='bottom')

plt.ylabel('Anzahl der Pakete')
plt.title(f'Analyse von {file}: Netzwerkprotokolle vs. Parser-/Payload-Schichten')
plt.tight_layout()
plt.show()
