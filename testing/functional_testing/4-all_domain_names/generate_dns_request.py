from scapy.all import *
import sys

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print "Usage <script> <domain name> <request type (1 for A, 2 for something else)> <request class 1 for IN, 2 for something else>"
        sys.exit(1)

    packet = Ether(dst='13:11:11:11:11:11',src="24:22:22:22:22:22")/IP(src="192.168.5.2", dst="192.168.5.1")/UDP(sport=2,dport=53)/DNS(rd=1,qr=0)
    packet.show()
    sendp(packet, iface="eth2")
    #wrpcap('dns_request.pcap', packet)
