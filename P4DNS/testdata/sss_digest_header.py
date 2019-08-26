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


from scapy.all import *
import sys, os

class Digest_data(Packet):
    name = "Digest_data"
    fields_desc = [
        # See the documentation here: https://scapy.readthedocs.io/en/latest/build_dissect.html?highlight=LELongField
        # for the types.
        # Unused bits:
        ByteField("src_port", 0),
        ByteField("flags", 0),
        LELongField("eth_src_addr", 0),
        BitFieldLenField("unused2", 0, 176),
    ]
    def mysummary(self):
        return "Sigest data"
#     struct Parsed_packet { 
#     ethernet_h ethernet;
#     ipv4_h ipv4;
#     udp_h udp; 
#     dns_query dns;
#     dns_response_h dns_response_fields;
# }

bind_layers(Digest_data, Raw)

