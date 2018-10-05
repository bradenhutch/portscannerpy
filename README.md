Braden's portscanner

To run this script you will need to have python installed along with these pip packages:

	netaddr --> pip install netaddr
	ipaddress --> pip install ipaddress
	ping --> pip install ping
	scapy --> pip install scapy

This script is designed to be self-explanatory. One thing to note is that ICMP sweep and traceroute require sudo privileges to run properly, so keep that in mind.

The script starts out by showing you your hostname for convenience if you want to scan your own computer or network. It then displays 4 options:
	
	1. Single host TCP scan
	2. Multi host TCP scan
	3. Multi host ICMP sweep
	4. Traceroute

1. Single host TCP scan

	This prompts you to enter a host followed by the ports you would like to scan. The socket will throw a gaia error if you provide a malformed host. Enter the starting and ending port to input a port range to scan. Put in the same port for both to only scan one port.

2. Multi host TCP scan

	This is the same as the single host, but you have several options for inputting multiple hosts. You can enter a CIDR formatted network, a comma delimited list of hosts, or the starting and ending IPs to scan. Enter the ports in the same way you would for single host.

3. Multi host ICMP sweep

	This requires sudo privileges and pings hosts that it is given. You can enter a range of hosts in the same 3 ways you can for the multi host TCP scan.

4. Traceroute

	This also requires sudo privileges and returns a list of gateways at each hop between your machine and the host. You can only do one host at a time.
