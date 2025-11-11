import pyshark


file = 'all1_anon.pcap'


cap = pyshark.FileCapture(file, use_json=True)


all_protocols = set()

for pkt in cap:
    for layer in pkt.layers:
        all_protocols.add(layer.layer_name.lower())

cap.close()


sorted_protocols = sorted(all_protocols)

print(f"protocols found in {file}:")
for proto in sorted_protocols:
    print(f"- {proto}")

print(f"\ntotal: {len(sorted_protocols)}")
