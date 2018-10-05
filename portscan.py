#!/usr/bin/env python

# Based on code found at https://www.pythonforbeginners.com/code-snippets-source-code/port-scanner-in-python
import socket
import subprocess
import sys
import ipaddress
import netaddr
import ping
from datetime import datetime
from scapy.all import *

####################################################################################################################

def singleTCPscan():
	# Ask for input
	remoteServer = raw_input("Enter a host to scan: ")
	# Get the port range
	startPort = raw_input("Enter the port range you would like to scan.\nStarting port: ")
	endPort = raw_input("Ending port(max 65535): ")
	remoteServerIP = socket.gethostbyname(remoteServer)
	# Print a nice banner with information on which host we are about to scan
	print "-" * 60
	print "Please wait, scanning remote host", remoteServerIP
	print "-" * 60
	# Check what time the scan started
	t1 = datetime.now()
	# Using the range function to specify ports
	# We also put in some error handling for catching errors
	try:
		sPort = int(startPort)
		nPort = int(endPort)
		nPort = nPort + 1
		for port in range(sPort, nPort):  
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(0.1)
			result = sock.connect_ex((remoteServerIP, port))
			if result == 0:
				print "Port {}:      Open".format(port)
			sock.close()
	except KeyboardInterrupt:
		print "You pressed Ctrl+C"
		sys.exit()
	except socket.gaierror:
		print 'Hostname could not be resolved. Exiting'
		sys.exit()
	except socket.error:
		print "Couldn't connect to server"
		sys.exit()
	except Exception:
		print "something happened!"
	# Checking the time again
	t2 = datetime.now()
	# Calculates the difference of time, to see how long it took to run the script
	total =  t2 - t1
	# Printing the information to screen
	print 'Scanning Completed in: ', total
	return

####################################################################################################################

def multiTCPscan():
	print "There are a few ways you can enter IP addresses...\n1.CIDR format\n2.Comma delimited list\n3.Start IP and end IP\n"
	form = raw_input("Which will you choose?: ")

	if form == '1':
		cidrRange = raw_input("Enter an IP address range in CIDR format (i.e. 192.168.0.0/24): ")
		ipRange = netaddr.IPNetwork(cidrRange)
		serverRange = [str(i) for i in ipRange]
		# Remove the broadcast address
		serverRange.pop(0)
		serverRange.pop()
		print serverRange
	elif form == '2':
		commaRange = raw_input("Enter a comma delimited list of IP addresses (192,168.1.1, 192.168.1.2, etc...): ")
		noSpaceRange = commaRange.replace(" ","")
		serverRange = noSpaceRange.split(",")
	elif form == '3':
		startIP = raw_input("Starting IP: ")
		endIP = raw_input("End IP: ")
		ipRange = netaddr.IPRange(startIP, endIP)
		serverRange = [str(i) for i in ipRange]
	else:
		print "Malformed input. Aborting."
		sys.exit()

	# Get the port range
	startPort = raw_input("Enter the port range you would like to scan.\nStarting port: ")
	endPort = raw_input("Ending port(max 65535): ")

	# Check what time the scans started
	t1 = datetime.now()
	# Using the range function to specify ports
	# We also put in some error handling for catching errors
	for i in serverRange:
		print "-" * 60
		print "Now scanning ", i
		print "-" * 60
		try:
			sPort = int(startPort)
			nPort = int(endPort)
			for port in range(sPort, nPort):  
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				result = sock.connect_ex((str(i), port))
				if result == 0:
					print "Port {}:      Open".format(port)
				sock.close()
		except KeyboardInterrupt:
			print "You pressed Ctrl+C"
			sys.exit()
		except socket.gaierror:
			print 'Hostname could not be resolved. Exiting'
			sys.exit()
		except socket.error:
			print "Couldn't connect to server"
			sys.exit()
	# Checking the time again
	t2 = datetime.now()
	# Calculates the difference of time, to see how long it took to run the script
	total =  t2 - t1
	# Printing the information to screen
	print 'Scanning Completed in: ', total
	return

####################################################################################################################

def pingSweep():
	print "\n**Please note that you have to run this script as sudo to properly ping sweep.**\n"
	print "There are a few ways you can enter IP addresses...\n1.CIDR format\n2.Comma delimited list\n3.Start IP and end IP\n"
	form = raw_input("Which will you choose?: ")
	
	if form == '1':
		cidrRange = raw_input("Enter an IP address range in CIDR format (i.e. 192.168.0.0/24): ")
		ipRange = netaddr.IPNetwork(cidrRange)
		serverRange = [str(i) for i in ipRange]
		# Remove the broadcast address
		serverRange.pop(0)
		serverRange.pop()
	elif form == '2':
		commaRange = raw_input("Enter a comma delimited list of IP addresses (192,168.1.1, 192.168.1.2, etc...): ")
		noSpaceRange = commaRange.replace(" ","")
		serverRange = noSpaceRange.split(",")
	elif form == '3':
		startIP = raw_input("Starting IP: ")
		endIP = raw_input("End IP: ")
		ipRange = netaddr.IPRange(startIP, endIP)
		serverRange = [str(i) for i in ipRange]
	else:
		print "Malformed input. Aborting."
		sys.exit()

	# Pings a range of addresses and only returns the addresses the could be pinged
	for i in serverRange:
		try:
			delay = ping.do_one(i, 2, 64)
		except socket.gaierror, e:
			print e
		if delay == None:
			None
			# print "Failed", i
		else:
			print "Success", i
	return

####################################################################################################################

def traceRoute():
	# Based on https://gist.github.com/amitsaha/8879445
	hostname = raw_input("Please input the host you would like to trace: ")
	# Time to live
	ttl = 4
	while 1:
		try:

		    p=sr1(IP(dst=hostname,ttl=ttl)/ICMP(id=os.getpid()), 
		          verbose=0, timeout=5)
		    # if time exceeded due to TTL exceeded
		    if p[ICMP].type == 11 and p[ICMP].code == 0:
		        print 'hop #', ttl, '->', p.src
		        ttl += 1
		    elif p[ICMP].type == 0:
		        print 'hop #', ttl, '->', p.src
		        break
		    else:
		    	print "Something went wrong..."
		except TypeError:
			# A type error here is equivalent to a timeout here because p will not have the necessary values
			print "Timed out"
			sys.exit()
	print "Finished!"
	return

####################################################################################################################

print "Welcome to Braden's port scanner!"
# Grab the name from a socket connection to get your own IP (for convenience)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
myip = s.getsockname()[0]
s.close()

print "Your current IP is", myip

print "\nYour options are...\n1. Single host TCP scan\n2. Multi host TCP scan\n3. Multi host ICMP sweep (Requires sudo)\n4. Traceroute (Requires sudo)"
selection = raw_input("Enter your selection: ")

if selection == "1":
	singleTCPscan()
elif selection == "2":
	multiTCPscan()
elif selection == "3":
	pingSweep()
elif selection == "4":
	traceRoute()
else:
	print "Malformed input. Aborting."
	sys.exit()
