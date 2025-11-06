import pyshark
import matplotlib.pyplot as plt

cap = pyshark.FileCapture('capture1.pcap')

protocol_payload = {}
protocol_headers = {}

for pkt in cap:
    try:
        layers = pkt.layers
        total_len = int(pkt.length)  # gesamte Paketgröße
        header_size = 0

        for layer in layers:
            # Wenn Layer einen Header hat, summieren
            if hasattr(layer, 'layer_length'):
                header_size += int(layer.layer_length)

        payload_size = max(total_len - header_size, 0)

        # Protokollnamen
        proto_name = layers[-1].layer_name  # oberste Schicht

        protocol_payload[proto_name] = protocol_payload.get(proto_name, 0) + payload_size
        protocol_headers[proto_name] = protocol_headers.get(proto_name, 0) + header_size

    except Exception:
        continue

cap.close()

# --- Diagramm ---
protocols = list(protocol_payload.keys())
payload_sizes = [protocol_payload[p] for p in protocols]
header_sizes = [protocol_headers.get(p, 0) for p in protocols]

x = range(len(protocols))

plt.figure(figsize=(12, 6))
plt.bar(x, header_sizes, label='Headers', color='orange')
plt.bar(x, payload_sizes, bottom=header_sizes, label='Payload', color='skyblue')
plt.xticks(x, protocols, rotation=45, ha='right')
plt.ylabel('Bytes')
plt.title('Header vs Payload pro oberstem Protokoll')
plt.legend()
plt.tight_layout()
plt.show()
