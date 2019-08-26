#!/usr/bin/python

import sys
import argparse
from scapy.all import wrpcap, Ether, IP, UDP, Raw

parser = argparse.ArgumentParser()
parser.add_argument('length', type=int, help='Length to generate')
parser.add_argument('--total', action='store_true', default=False, dest='use_total', help='Split the length up into a suitable number of packets')
args = parser.parse_args()

length = args.length

MAX_SIZE=1514

if args.use_total:
        packets = length / MAX_SIZE
        last_length = length % MAX_SIZE
else:
        packets = 1
        last_length = length

print MAX_SIZE * (packets - 1) + last_length

packet_list = []
for i in range(packets - 1):
        data="0" * (MAX_SIZE - 42)
        packet = Ether() / IP(dst="192.168.1.1") / UDP(sport=1,dport=123) / Raw(load=data)
        packet[UDP].length=MAX_SIZE - 42 + 8
        packet[IP].src="192.168.0.1"
        packet[IP].dest="192.168.0.2"
        packet_list.append(packet)

# Append the last length  packet to make the whole PCAP file the right length.
data="a" * (last_length - 42)
packet = Ether() / IP(dst="192.168.1.1") / UDP(sport=1,dport=123) / Raw(load=data)
packet[UDP].length=last_length - 42 + 8
packet[IP].src="192.168.0.1"
packet[IP].dest="192.168.0.2"
packet_list.append(packet)

wrpcap('variable_length.pcap', packet_list)
