from scapy.all import Ether, ARP, srp, send #The library we'll be using for ARP spoofing (py -m pip install scapy)
import argparse
import time
import os
import sys

def main():
	print("Python MITM has booted.")

#Runs the main function if this script is executed as the main program
if __name__ == "__main__":
	main()