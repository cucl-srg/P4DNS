#!/usr/bin/env python

#
# Copyright (c) 2019 Jackson Woodruff, Murali Ramanujam
# All rights reserved.
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


import argparse
import sys, os
from socket import socket, AF_PACKET, SOCK_RAW
sys.path.append(os.path.expandvars('$P4_PROJECT_DIR/testdata/'))
from sss_digest_header import *

sys.path.append(os.path.expandvars('$P4_PROJECT_DIR/sw/CLI/'))
from p4_tables_api import *
sys.path.append(os.path.expandvars('$P4_PROJECT_DIR/src/'))
import dns_match
import dns_response
import copy

import dns.resolver
import threading
import time
from threading import Timer
from threading import Thread


"""
This is the learning switch software that adds the appropriate
entries to the forwarding and smac tables 
"""

DMA_IFACE = 'nf0'
DIG_PKT_LEN = 32 # 32 bytes, 256 bits
TABLE_ENTRY_SIZE_BYTES = 56 / 8
MAX_DOMAIN_NAME_BYTES = TABLE_ENTRY_SIZE_BYTES  # a.com
MIN_DOMAIN_NAME_BYTES = MAX_DOMAIN_NAME_BYTES - 1  # a.co
DNS_RESPONSE_SIZE = 128
MAX_DNS_TABLE_ENTRIES = 64

# These are offsets into the dig_pkt flags field
# for each flag value.
IS_DNS = 1
IS_DNS_RESPONSE = 2
RECURSION_REQUESTED = 4
FORWARDING_ENTRY = 8

forward_tbl = {}
smac_tbl = {}

dns_table_contents = []
dns_table_contents_lock = threading.Lock()
cached_domains = {}
cached_domains_lock = threading.Lock()
pending_requests = {}
pending_requests_lock = threading.Lock()
print_lock = threading.Lock()
forwarding_table_lock = threading.Lock()
dns_table_lock = threading.Lock()
myResolver = dns.resolver.Resolver()
CLOCK_TICK_FREQUENCY_SECONDS = 1



class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer     = None
        self.interval   = interval
        self.function   = function
        self.args       = args
        self.kwargs     = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


def resolve_domain_name_and_add_to_cache(domain_name, query_type='A', max_num_response=1):         
    failed = False
    try:
        # Conver the domain name to a string and strip off the first '.'
        myAnswers = myResolver.query(domain_name, query_type)
        response = str(myAnswers.rrset).split(' ')
        response_domain_name = response[0]
        ttl = int(response[1])
        if ttl <= 10:
            ttl += 10
        ipaddress = response[-1]
        cached_domains_lock.acquire()
        try:
            cached_domains[domain_name] = [False, response_domain_name, ipaddress, ttl]
        finally:
            cached_domains_lock.release()
    except dns.resolver.NXDOMAIN as e:
        if ENABLE_PRINT:
            print e
            print "unable to resolve domain name" + str(sys.exc_info()[0])
        failed = True
    except dns.resolver.NoNameservers as e:
        if ENABLE_PRINT:
            print e
            print "unable to resolve domain name" + str(sys.exc_info()[0])
        failed = True
    except dns.resolver.NoAnswer as e:
        if ENABLE_PRINT:
            print e
            print "unable to resolve domain name" + str(sys.exc_info()[0])
        failed = True
    except dns.resolver.Timeout as e:
        if ENABLE_PRINT:
            print e
            print "unable to resolve domain name" + str(sys.exc_info()[0])
        failed = True

    if failed:
        cached_domains_lock.acquire()
        try:
            cached_domains[domain_name] = [True, e, None, None]
        finally:
            cached_domains_lock.release()


def get_ip_and_ttl(domain_name):
    cached_domains_lock.acquire()
    try:
        keys = cached_domains.keys()[:]
    finally:
        cached_domains_lock.release()
    if domain_name in keys:  # cached in host already
        cached_domains_lock.acquire()
        try:
            resp = cached_domains[domain_name]
        finally:
            cached_domains_lock.release()
        return resp
    else:  # not in host
        resolve_domain_name_and_add_to_cache(domain_name)  # trigger recursive query
        try:
            cached_domains_lock.acquire()
            if domain_name in cached_domains.keys():
                resp = cached_domains[domain_name]
                return resp
            else:
                while True:
                    print "Serious bug: ", domain_name, "deleted"
        finally:
            cached_domains_lock.release()


packet_count = 0
def packet_trigger(pkt):
    global packet_count
    packet_count += 1
    thread = Thread(target = process_dma_msg, args = (pkt, ))
    thread.start()

def get_hex_pkt(pkt):
    return [hex(ord(x)) for x in str(pkt)]

def process_dma_msg(pkt):
    # Convert the packet to a scapy packet.
    if ENABLE_PRINT:
        print "Digest Received"
    dig_pkt = Digest_data(str(pkt)[0:32])
    has_dma = False

    if len(str(pkt)) > DIG_PKT_LEN:
        if ENABLE_PRINT:
            print "Received a DMA message..."
        has_dma = True
        pkt = Ether(_pkt=str(pkt)[32:])

    
    if ENABLE_PRINT:
        print_lock.acquire()
        print "Learn digest called!"
        print pkt.show()
        print_lock.release()
    if DISABLED:
        print "Control plane disabled"
        return
    if has_dma:
        if ENABLE_PRINT:
            print "Received DMA"
        if not pkt.haslayer(IP) \
                or not pkt.haslayer(UDP) \
                or not pkt.haslayer(DNS) \
                or not pkt.haslayer(DNSQR):
            raise Exception("Packet does not have all expected layers")

        domain_string = pkt[DNS][DNSQR].qname

        if pkt[DNS].qr == 1 and pkt[DNS].ancount == 1 and pkt[DNS].qdcount == 1:
            # we have confirmed it is a response, let us reparse the input
            # packet appropriately  
            too_long = len(domain_string) > TABLE_ENTRY_SIZE_BYTES
            resp_too_long = pkt[DNS][DNSRR].rdlen != 4
            # Check Qtype is A and qclass is IN
            is_dns_response = \
                    pkt[DNS][DNSQR].qtype == 1 and pkt[DNS][DNSQR].qclass == 1 and not too_long and not resp_too_long
            if too_long and ENABLE_PRINT:
                print "DNS Reponse name is wrong.  Name we got was ", domain_string
        else:
            is_dns_response = False

        if pkt[DNS].rd and pkt[DNS].qr == 0:
            dns_recursion(pkt)
        elif is_dns_response:
            if ENABLE_PRINT:
                print "this is a dns response"
            dns_name = pkt[DNS][DNSRR].rrname
            dns_answer = pkt[DNS][DNSRR].rdata
            ttl = pkt[DNS][DNSRR].ttl

            write_to_dns_table(dns_name, dns_answer, ttl)
            send_packet(pkt, interface="nf3")
        else:
            # Don't know what this is or how this got here.
            if ENABLE_PRINT:
                print "Unknown packet! Fix me!!!!"
            send_packet(pkt, interface="nf3")

    if dig_pkt.eth_src_addr != 0:
        learn_digest(dig_pkt)


def dns_recursion(pkt):
    if ENABLE_PRINT:
        print "this is a dns request, asked for recursion"
    start_time = time.time()
    dns_qname = pkt[DNS][DNSQR].qname

    if len('.' + dns_qname) > MAX_DOMAIN_NAME_BYTES:
        if ENABLE_PRINT:
            print "Name is too long, name we got was", \
                    dns_qname
        # Send the packet on its way
        send_packet(pkt, interface="nf3")
        return
    elif len('.' + dns_qname) < MIN_DOMAIN_NAME_BYTES:
        if ENABLE_PRINT:
            print "Name is too short, name we got was", \
                    dns_qname
        # Send the packet on its way
        send_packet(pkt, interface="nf3")
        return

    pending_requests_lock.acquire() # ACQUIRE
    try:
        if dns_qname in pending_requests:
            pending_requests[dns_qname].append(pkt)
        else:
            pending_requests[dns_qname] = [pkt]
        already_requested = len(pending_requests[dns_qname]) > 1
    finally:
        pending_requests_lock.release() # RELEASE

    if not already_requested:
        error, dns_name, dns_answer, ttl = get_ip_and_ttl(dns_qname)
        if not error:
            if ENABLE_PRINT:
                print dns_qname
            write_to_dns_table(dns_qname, dns_answer, ttl)
        end_time = time.time()

        # After we have written the update to the board, we know that no more DMA
        # packets can reach the host.  So everything in the pending requests should
        # sent a response.
        if ENABLE_PRINT:
            print("time taken is " + str(end_time - start_time))

        pending_requests_lock.acquire()
        all_requests = pending_requests[dns_qname][:]
        pending_requests[dns_qname] = []
        pending_requests_lock.release()

        for request in all_requests:
            new_dma_pkt = craft_response_packet(request, error, dns_answer=dns_answer, ttl=ttl)
            send_packet(new_dma_pkt, interface="nf3")



def learn_digest(dig_pkt):
    if ENABLE_PRINT:
        print "this is asking to update mac address table"

    add_to_forwarding_tables(dig_pkt)

def craft_response_packet(dma_pkt, error, dns_answer=None, ttl=None):
    new_dma_pkt = Ether()/IP()/UDP()/DNS(qd=DNSQR())

    # Ethernet
    new_dma_pkt[Ether].src = dma_pkt[Ether].dst
    new_dma_pkt[Ether].dst = dma_pkt[Ether].src
    new_dma_pkt[Ether].type = dma_pkt[Ether].type

    # IPv4
    new_dma_pkt[IP].version = dma_pkt[IP].version
    # Scapy will set IHL
    # Scapy will set TOS
    # Scapy will set len
    # Scapy will set ID
    # Scapy will clear flags
    # Scapy will set frag up
    # Scapy will set ttl
    # Scapy will set proto
    # Scapy will set checksum
    new_dma_pkt[IP].src = dma_pkt[IP].dst
    new_dma_pkt[IP].dst = dma_pkt[IP].src

    # UDP
    new_dma_pkt[UDP].sport = dma_pkt[UDP].dport
    new_dma_pkt[UDP].dport = dma_pkt[UDP].sport
    # Scapy will set UDP len
    # Scapy will set UDP checksum

    # DNS header.
    new_dma_pkt[DNS].id = dma_pkt[DNS].id
    new_dma_pkt[DNS].qr = 1
    new_dma_pkt[DNS].opcode = dma_pkt[DNS].opcode
    new_dma_pkt[DNS].aa = dma_pkt[DNS].aa
    new_dma_pkt[DNS].tc = dma_pkt[DNS].tc
    new_dma_pkt[DNS].rd = 0
    new_dma_pkt[DNS].ra = 0
    new_dma_pkt[DNS].z = 0
    new_dma_pkt[DNS].ad = 0
    new_dma_pkt[DNS].cd = 0
    # Set rcode depending on whether it's an error.
    new_dma_pkt[DNS].qdcount = 1
    # Set anscount depending on error.
    new_dma_pkt[DNS][DNSQR].qname = dma_pkt[DNS][DNSQR].qname
    new_dma_pkt[DNS][DNSQR].qtype = dma_pkt[DNS][DNSQR].qtype
    new_dma_pkt[DNS][DNSQR].qclass = dma_pkt[DNS][DNSQR].qclass

    if not error:
        if ENABLE_PRINT:
            print "Returning response!"
        qname = dma_pkt[DNS][DNSQR].qname
        rr = DNSRR(rrname=qname, type='A', rclass='IN', ttl=ttl,
                   rdlen=4, rdata=dns_answer)
        new_dma_pkt[DNS].an = rr

        new_dma_pkt[DNS].ancount = 1
        new_dma_pkt[DNS].rcode = 0
    else:
        new_dma_pkt[DNS].ancount = 0
        new_dma_pkt[DNS].rcode = 4
    if ENABLE_PRINT:
        print "sending back crafted response", new_dma_pkt
    return new_dma_pkt


def add_to_forwarding_tables(dig_pkt):
    if DISABLE_FORWARDING_TABLE_LEARING:
        return
    src_port = dig_pkt.src_port
    eth_src_addr = dig_pkt.eth_src_addr
    forwarding_table_lock.acquire()
    try:
        (found, val) = table_cam_read_entry('forward', [eth_src_addr])
        if (found == 'False'):
            if ENABLE_PRINT:
                print 'Adding entry: ({0}, set_output_port, {1}) to the forward table'.format(hex(eth_src_addr), bin(src_port))
                print 'Adding entry: ({0}, NoAction, []) to the smac table'.format(hex(eth_src_addr))
            table_cam_add_entry('forward', [eth_src_addr], 'set_output_port', [src_port])
            table_cam_add_entry('smac', [eth_src_addr], 'NoAction', [])
        elif ENABLE_PRINT:
            print "Entry: ({0}, set_output_port, {1}) is already in the tables".format(hex(eth_src_addr), bin(src_port))
    finally:
        forwarding_table_lock.release()


def convert_name_to_binary_key(keys):
    # This function does not manage the dns_table_contens_list
    def key_to_int(key):
        return int(key[2:], 2)

    for i in range(len(keys)):
        keys[i] = key_to_int(dns_match.dns_match(keys[i], TABLE_ENTRY_SIZE_BYTES))

    return keys

# takes in a list of keys to delete and deletes them
def delete_from_dns_table(keys_to_delete):
    dns_table_contents_lock.acquire()
    try:
        i = 0
        while i < len(dns_table_contents):
            key = dns_table_contents[i]
            if key in keys_to_delete:
                del dns_table_contents[i]
            else:
                i += 1
    finally:
        dns_table_contents_lock.release()

    __delete_from_dns_table(keys_to_delete)


def __delete_from_dns_table(keys):
    table_name = 'dns_1'
    keys = convert_name_to_binary_key(keys)

    dns_table_lock.acquire()
    try:
        table_cam_delete_entry(table_name, keys)
    finally:
        dns_table_lock.release()

def write_to_dns_table(dns_qname, ip_address, ttl):
    dns_table_contents_lock.acquire() # ACQUIRE
    try:
        assert len(dns_table_contents) <= MAX_DNS_TABLE_ENTRIES
        if len(dns_table_contents) == MAX_DNS_TABLE_ENTRIES:
            # Delete the least recently entered entry.
            delete_name = dns_table_contents[0]
            del dns_table_contents[0]
            __delete_from_dns_table([delete_name])
        dns_table_contents.append(dns_qname)
    finally:
        dns_table_contents_lock.release() # RELEASE

    key = dns_match.dns_match(dns_qname, TABLE_ENTRY_SIZE_BYTES)
    value = dns_response.dns_response(ip_address, ttl)

    dns_table_lock.acquire() # ACQUIRE
    try:
        table_cam_add_entry('dns_1', [int(key[2:], 2)], 'DNSMatch', [int(value[2:], 2)])
    finally:
        dns_table_lock.release() # RELEASE


def read_from_dns_table(key):  # key is domain name + length in binary.
    [key] = convert_name_to_binary_key([key])
    dns_table_lock.acquire()
    try:
        (found, val) = table_cam_read_entry('dns_1', [key])
    finally:
        dns_table_lock.release()
    if found:
        return val
    else:
        return False


def send_packet(dma_pkt, interface="nf3"):
    sendp(dma_pkt, iface=interface)


def clock_tick():
    global packet_count
    print "clock tick"
    print "Packet count is ", packet_count
    list_of_expired_domains = []
    # Decrement the stored TTLs
    cached_domains_lock.acquire()
    try:
        for domain_name in cached_domains.keys():
            error = cached_domains[domain_name][0]
            if not error:
                cached_domains[domain_name][3] = cached_domains[domain_name][3] - 1
                if cached_domains[domain_name][3] <= 0:
                    list_of_expired_domains.append(cached_domains[domain_name][1])
                    del cached_domains[domain_name]
                    delete_from_dns_table([domain_name])
    finally:
        cached_domains_lock.release()

    # Now, decrement the TTL of any names on the board.
    dns_table_contents_lock.acquire()
    try:
        all_contents = dns_table_contents[:]
    finally:
        dns_table_contents_lock.release()
    for key in all_contents:
        cached_domains_lock.acquire()
        try:
            if key in cached_domains:
                this_domain = cached_domains[key][:]
                error = this_domain[0]
                if not error:  # if it is not an error
                    domain_name = this_domain[1]
                    ip_address = this_domain[2]
                    new_ttl = this_domain[3]
                    delete_from_dns_table([domain_name])
                    write_to_dns_table(domain_name, ip_address, new_ttl)
        finally:
            cached_domains_lock.release()


def main():
    print "Starting!"
    if not DISABLE_TTL_UPDATE:
        rt = RepeatedTimer(CLOCK_TICK_FREQUENCY_SECONDS, clock_tick)
    sniff(iface=DMA_IFACE, prn=packet_trigger, count=0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--disable', dest='disable', action='store_true', default=False)
    parser.add_argument('--test', dest='test', action='store_true', default=False)
    parser.add_argument('--disable-learning', dest='disable_forwarding', action='store_true', default=False)
    parser.add_argument('--disable-ttl-update', dest='disable_ttl', action='store_true', default=False)
    parser.add_argument('--high-performance-mode', dest='high_perf', action='store_true', default=False)
    args = parser.parse_args()
    global DISABLED
    DISABLED = args.disable
    DISABLE_FORWARDING_TABLE_LEARING = args.disable_forwarding
    DISABLE_TTL_UPDATE = args.disable_ttl
    if args.high_perf:
        ENABLE_PRINT = False
    else:
        ENABLE_PRINT = True
    if args.test:
        print "Pass"
    else:
        main()
