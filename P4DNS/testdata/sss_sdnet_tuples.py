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


"""
Used to create the Tuple_in.txt and Tuple_out.txt files for the
SDNet simulations 
"""

import argparse, collections, sys

# this defines the common sume_metadata
from sss_sume_metadata import *

tuple_in_file = "Tuple_in.txt"
tuple_expect_file = "Tuple_expect.txt"

# Diget Data MUST be 256 bits
""" Digest Data:
   unused         (256 bits)
"""

dig_field_len = collections.OrderedDict()
dig_field_len["unused2"] = 176
dig_field_len["eth_src_addr"] = 64
dig_field_len["flags"] = 8
dig_field_len["src_port"] = 8

#initialize tuple_expect
dig_tuple_expect = collections.OrderedDict()
dig_tuple_expect["unused2"] = 0
dig_tuple_expect["eth_src_addr"] =0
dig_tuple_expect["flags"] = 0
dig_tuple_expect["src_port"] = 0

"""
Clear the tuple files
"""
def clear_tuple_files():
    with open(tuple_in_file, "w") as f:
        f.write("")
    
    with open(tuple_expect_file, "w") as f:
        f.write("")


"""
Return a binary string with length = field_len_dic[field_name] 
"""
def get_bin_val(field_name, value, field_len_dic):
    format_string = "{0:0%db}" % field_len_dic[field_name] 
    print format_string, value
    bin_string = format_string.format(value)
    return bin_string

"""
Given a binary string, return the hex version
"""
def bin_to_hex(bin_string):
    hex_string = ''
    assert(len(bin_string) % 4 == 0)
    for i in range(0,len(bin_string),4):
        hex_string += "{0:1x}".format(int(bin_string[i:i+4], 2))
    return hex_string 

"""
Write the next line of the Tuple_in.txt and Tuple_expect.txt
"""
def write_tuples():
    with open("Tuple_in.txt", "a") as f:
        tup_bin_string = ''
        for field_name, value in sume_tuple_in.iteritems():
            bin_val = get_bin_val(field_name, value, sume_field_len)
            tup_bin_string += bin_val
        f.write(bin_to_hex(tup_bin_string) + '\n')

    with open("Tuple_expect.txt", "a") as f:
        tup_bin_string = ''
        for field_name, value in dig_tuple_expect.iteritems():
            bin_val = get_bin_val(field_name, value, dig_field_len)
            tup_bin_string += bin_val
        f.write(bin_to_hex(tup_bin_string) + ' ')

        tup_bin_string = ''
        for field_name, value in sume_tuple_expect.iteritems():
            bin_val = get_bin_val(field_name, value, sume_field_len)
            tup_bin_string += bin_val
        f.write(bin_to_hex(tup_bin_string) + '\n')


###############################
## Functions to parse tuples ##
###############################

def find_tup_len(field_len_dic):
    num_bits = 0
    for length in field_len_dic.values():
        num_bits += length
    return num_bits

"""
Given a hex string, convert it to a binary string
"""
def hex_to_bin(hex_string, length):
    fmat_string = '{0:0%db}' % length
    bin_string = fmat_string.format(int(hex_string, 16))
    return bin_string

def check_length(bin_string, field_len_dic):
    num_bits = find_tup_len(field_len_dic)
    try:
        assert(len(bin_string) == num_bits)
    except:
        print 'ERROR: unexpected input'
        print 'len(bin_string) = ', len(bin_string)
        print 'num_bits = ', num_bits
        sys.exit(1)

"""
Given hex string representation of a tuple, return the parsed version of it
"""
def parse_tup_string(tup_string, field_len_dic):
    tup_len = find_tup_len(field_len_dic)
    bin_string = hex_to_bin(tup_string, tup_len)
    check_length(bin_string, field_len_dic)
    tup = collections.OrderedDict()   
    i = 0
    for (field,length) in field_len_dic.iteritems():
        tup[field] = int(bin_string[i:i+length], 2)
        i += length
    return tup

def parse_line(line, tuple_type):
    if tuple_type == 'sume':
        field_len = sume_field_len
    elif tuple_type == 'digest':
        field_len = dig_field_len
    else:
        print >> sys.stderr, "ERROR: unsupported tuple_type, must one of: [sume, digest]"
        sys.exit(1)
    tup_string = line.strip()
    tup = parse_tup_string(tup_string, field_len)
    print "Parsed Tuple:\n", '-----------------------'
    for (key, val) in tup.items():
        if (key in ['src_port', 'dst_port']):
            print key, " = {0:08b}".format(val)
        else:
            print key, " = ", val

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--parse', type=str, help="A tuple line to parse")
    parser.add_argument('tuple_type', type=str, help="Which tuple type to parse: sume, digest")
    args = parser.parse_args()

    parse_line(args.parse, args.tuple_type)

