import sys
from scapy.all import *
char_to_use_in_domain="a"
max_label_length = 63


starting_size = 4 # packet size of 64
ending_size = 1458 # packet size of 560


def get_domain_name(required_length="5"):
        final_domain_name = char_to_use_in_domain
        current_label_length = 1
        while len(final_domain_name) < required_length:
                if current_label_length == max_label_length:
                        final_domain_name += '.a'
                        current_label_length = 2
                else:
                        final_domain_name += char_to_use_in_domain
                        current_label_length += 1
        return final_domain_name

if __name__ == "__main__":
        packet_number = 1
        for i in range(starting_size, ending_size):
                domain_name = get_domain_name(i)
                current_length = i
                packet = Ether(dst='11:11:11:11:11:11',src="22:22:22:22:22:22")/IP(src="192.168.5.2", dst="192.168.5.1")/UDP(sport=2,dport=53)/DNS(rd=0,qd=DNSQR(qname=domain_name))
                wrpcap('./'+str(i + 60)+'.cap', packet)
                # sendp(packet, iface="eth2")
