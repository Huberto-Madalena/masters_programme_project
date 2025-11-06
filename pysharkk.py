import pyshark as ps

capture = ps.LiveCapture(interface="wi-fi", output_file='capture.pcap')
capture.sniff(timeout=30)
print ("pakete erfasst: ", len(capture))