from scapy.all import Ether, ARP, srp, send #The library we'll be using for ARP spoofing (py -m pip install scapy)
import argparse
import time
import os
import sys

try: 
	interface = raw_input ( "[*] Enter Desired Interface: ")
	victimIP = raw_input("[*] Enter victim IP: ")
	gateIP = raw_input ("[*] Enter Router IP : ")

def main():
	print("Python MITM has booted.")

#Runs the main function if this script is executed as the main program
if __name__ == "__main__":
	main()
