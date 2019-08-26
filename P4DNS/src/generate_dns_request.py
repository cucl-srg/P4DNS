from scapy.all import *
import sys

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage <script> <domain name>"
        sys.exit(1)

    packet = sendp(Ether(dst='11:11:11:11:11:11',src="22:22:22:22:22:22")/IP(src="192.168.5.2", dst="192.168.5.1")/UDP(sport=2,dport=53)/DNS(rd=1,qd=DNSQR(qname=sys.argv[1])), iface='eth2')
    #wrpcap('dns_request.pcap', packet)
