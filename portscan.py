#!/usr/bin/env python
import socket
import subprocess
import sys
import ipaddress
import netaddr
import ping
from datetime import datetime

# Clear the screen
# subprocess.call('clear', shell=True)

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
        for port in range(sPort, nPort):  
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
    format = raw_input("Which will you choose?: ")

    if format == '1':
        cidrRange = raw_input("Enter an IP address range in CIDR format (i.e. 192.168.0.0/24): ")
        serverRange = netaddr.IPNetwork(cidrRange)
    elif format == '2':
        commaRange = raw_input("Enter a comma delimited list of IP addresses (192,168.1.1, 192.168.1.2, etc...): ")
        noSpaceRange = commaRange.replace(" ","")
        serverRange = noSpaceRange.split(",")
    elif format == '3':
        startIP = raw_input("Starting IP: ")
        endIP = raw_input("End IP: ")
        serverRange = netaddr.IPRange(startIP, endIP)
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

print "Welcome to Braden's port scanner!"
# Grab the name from a socket connection to get your own IP (for convenience)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
myip = s.getsockname()[0]
s.close()

print "Your current IP is ", myip

print "\nYour options are...\n1. Single host TCP scan\n2. Multi host TCP scan\n"
selection = raw_input("Enter your selection: ")

if selection == "1":
    singleTCPscan()
elif selection == "2":
    multiTCPscan()
else:
    print "Malformed input. Aborting."
    sys.exit()




