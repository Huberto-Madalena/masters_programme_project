from multiprocessing import Process, Manager
import json


def process_data(data):
	Ergebnis ={}
	for i in data:
		if i in Ergebnis:
			Ergebnis[i]+=1
		else:
			Ergebnis[i]=1
	return Ergebnis


a = process_data(["clod", "dolt", "grunion", "wren", "wren", "wrench","wench"])
print (a)
