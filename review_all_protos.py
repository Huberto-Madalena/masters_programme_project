import pyshark

# --- Datei angeben ---
file = 'review_all_protos.pcap'

# --- Capture öffnen ---
cap = pyshark.FileCapture(file, use_json=True)

# --- Menge für alle Protokolle ---
all_protocols = set()

for pkt in cap:
    for layer in pkt.layers:
        all_protocols.add(layer.layer_name.lower())

cap.close()

# --- Ausgabe sortieren ---
sorted_protocols = sorted(all_protocols)

print(f"Gefundene Protokolle in {file}:")
for proto in sorted_protocols:
    print(f"- {proto}")

print(f"\nGesamtanzahl: {len(sorted_protocols)}")
