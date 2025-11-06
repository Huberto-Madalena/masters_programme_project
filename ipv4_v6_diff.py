from scapy.all import rdpcap, IP, IPv6
from collections import Counter


def pcap_total(fineName):
    try:
        pak = rdpcap(fileName)
    except FileNotFoundError:
        return None

    total_count = Counter()
    for p in pak:
        if pak.haslayer(any):
            total_counter = +1
    
    return total_counter

def pcap_analyse(fileName):

    try:
        pckt = rdpcap(fileName)
    except FileNotFoundError:
        return None
    
    proto_counter = Counter()
        
    for pak in pckt:
        if pak.haslayer(any):
            total_count += 1


    for p in pckt:
        # ip/ipv4
        if p.haslayer(IP):
            proto_counter['IPv4'] += 1
        # ipv6
        elif p.haslayer(IPv6):
            proto_counter['IPv6'] += 1
        # other protocols go here (ARP, ICMP)
        
        '''
        elif p.haslayer(ICMP):
            proto_counter['ICMP'] += 1
            
        elif p.haslayer(ARP):
            proto_counter['ARP'] += 1
            '''
    return proto_counter
    
    
this_file = "friday_capture.pcap"
results = pcap_analyse(this_file)

total_packets = rdpcap(this_file)
total_length = len(total_packets)

print (f"number of packets analysed in: {this_file} :", total_length)

if results:
    print(f"\n examining '{this_file}':")
    print("-" * 10)
    print(f"total IPv4-packets: {results.get('IPv4', 0)}")
    print(f"total IPv6-packets: {results.get('IPv6', 0)}")
    #print(f"total ICMP packets: {results.get('ICMP', 0)}")
    #print(f"total arp packets:{results.get('ARP', 0)}")
    print("-" * 10)

    # Füge hier weitere Analyse-Logik hinzu, z.B. um die häufigsten Ziel-Ports oder Quell-IPs zu finden.