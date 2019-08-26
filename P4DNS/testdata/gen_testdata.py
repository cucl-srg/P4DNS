#!/usr/bin/env python

#
# Copyright (c) 2017 Stephen Ibanez, 2019 Jackson Woodruff, Murali Ramanujam
# All rights reserved.
#
# This software was developed by Stanford University and the University of Cambridge Computer Laboratory 
# under National Science Foundation under Grant No. CNS-0855268,
# the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
# by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), 
# as part of the DARPA MRC research programme.
#
# @NETFPGA_LICENSE_HEADER_START@
#
# Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  NetFPGA licenses this
# file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.netfpga-cic.org
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @NETFPGA_LICENSE_HEADER_END@
#


from nf_sim_tools import *
import random
from collections import OrderedDict
import sss_sdnet_tuples
from sss_digest_header import Digest_data


########################
# pkt generation tools #
########################

pktsApplied = []
pktsExpected = []

# Pkt lists for SUME simulations
nf_applied = OrderedDict()
nf_applied[0] = []
nf_applied[1] = []
nf_applied[2] = []
nf_applied[3] = []
nf_expected = OrderedDict()
nf_expected[0] = []
nf_expected[1] = []
nf_expected[2] = []
nf_expected[3] = []

dma0_expected = []

nf_port_map = {"nf0":0b00000001, "nf1":0b00000100, "nf2":0b00010000, "nf3":0b01000000, "dma0":0b00000010}
nf_id_map = {"nf0":0, "nf1":1, "nf2":2, "nf3":3}

sss_sdnet_tuples.clear_tuple_files()

def applyPkt(pkt, ingress, time):
    pktsApplied.append(pkt)
    sss_sdnet_tuples.sume_tuple_in['src_port'] = nf_port_map[ingress]
    sss_sdnet_tuples.sume_tuple_expect['src_port'] = nf_port_map[ingress]
    pkt.time = time
    nf_applied[nf_id_map[ingress]].append(pkt)

def mac_to_int(mac):
    return int(mac.replace(':',''),16) 

def expPkt(pkt, egress, eth_src_addr, src_port):
    pktsExpected.append(pkt)
    sss_sdnet_tuples.sume_tuple_expect['send_dig_to_cpu'] = 1
    sss_sdnet_tuples.sume_tuple_expect['dst_port'] = 0b01010101  # broadcast

    sss_sdnet_tuples.dig_tuple_expect['eth_src_addr'] = mac_to_int(eth_src_addr)
    sss_sdnet_tuples.dig_tuple_expect['src_port'] = nf_port_map[src_port]
    sss_sdnet_tuples.dig_tuple_expect['flags'] = 8

    sss_sdnet_tuples.write_tuples()

    if True: # if goes to plane
        digest_pkt = Digest_data(flags=8,eth_src_addr=mac_to_int(eth_src_addr), src_port=nf_port_map[src_port])
        dma0_expected.append(digest_pkt)

    if egress in ["nf0","nf1","nf2","nf3"]:
        nf_expected[nf_id_map[egress]].append(pkt)
    elif egress == 'bcast':
        nf_expected[0].append(pkt)
        nf_expected[1].append(pkt)
        nf_expected[2].append(pkt)
        nf_expected[3].append(pkt)

def do_dns():
    test_dns()

def print_summary(pkts):
    for pkt in pkts:
        print "summary = ", pkt.summary()

def write_pcap_files():
    wrpcap("src.pcap", pktsApplied)
    wrpcap("dst.pcap", pktsExpected)

    for i in nf_applied.keys():
        if (len(nf_applied[i]) > 0):
            wrpcap('nf{0}_applied.pcap'.format(i), nf_applied[i])

    for i in nf_expected.keys():
        if (len(nf_expected[i]) > 0):
            wrpcap('nf{0}_expected.pcap'.format(i), nf_expected[i])

    if (len(dma0_expected) > 0):
        print "dma0 expected written"
        wrpcap('dma0_expected.pcap', dma0_expected)

    for i in nf_applied.keys():
        print "nf{0}_applied times: ".format(i), [p.time for p in nf_applied[i]]


pktCnt = 0
# Test the ethernet
def test_ethernet(): 
    MAC1 = '11:11:11:11:11:11'
    MAC2 = '12:12:12:12:12:12'

    global pktCnt
    pkt = Ether(dst=MAC1, src=MAC2)
    pkt = pad_pkt(pkt, 64)
    applyPkt(pkt, 'nf0', pktCnt)
    expPkt(pkt, 'bcast', MAC2, 'nf0')
test_ethernet()


def test_dns():
    MAC1 = '11:11:11:11:11:11'
    MAC2 = '12:12:12:12:12:12'

    global pktCnt
    pkt = Ether(dst='11:11:11:11:11:11',src="22:22:22:22:22:22")/IP(src="192.168.5.2", dst="192.168.5.1")/UDP(sport=2,dport=53)/DNS(rd=0,qd=DNSQR(qname="a.com"))
    pkt = pad_pkt(pkt, 64)
    applyPkt(pkt, 'nf0', pktCnt)
    # We should get a response:
    pkt = Ether(src='11:11:11:11:11:11',dst="22:22:22:22:22:22")/IP(len=43,dst="192.168.5.2", src="192.168.5.1")/UDP(len=33,dport=2,sport=53)/DNS(rd=0,qd=DNSQR(qname="a.com"),an=DNSRR(rrname="a.com",rdata="216.58.198.238"))
    expPkt(pkt, 'bcast', MAC1, 'nf0')

test_ethernet()

write_pcap_files()
