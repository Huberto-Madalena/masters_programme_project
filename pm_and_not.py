import subprocess

cmd1 = ["tshark", "-i", "5", "-a", "duration:220", "-p", "-w", "pm_on.pcap"]
cmd2 = ["tshark", "-i", "5", "-a", "duration:220", "-w", "no_pm.pcap"]

p1 = subprocess.Popen(cmd1)
p2 = subprocess.Popen(cmd2)

p1.wait()
p2.wait()