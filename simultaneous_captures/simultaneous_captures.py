import subprocess

cmd1 = ["tshark", "-i", "5", "-a", "duration:300", "-s", "65335", "-w", "capture1.pcap"]
cmd2 = ["tshark", "-i", "5", "-a", "duration:300", "-w", "capture2.pcap"]

p1 = subprocess.Popen(cmd1)
p2 = subprocess.Popen(cmd2)

p1.wait()
p2.wait()