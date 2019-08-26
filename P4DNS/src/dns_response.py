#!/usr/bin/python
import sys

def pad_before(x, length):
    if len(x) < length:
        x = '0' * (length - len(x)) + x
    return x


def dns_response(ip, ttl):
	# This should be  a 14 bit number  pointing to the start of the name in the message.
	offset_bits = '00000000001100' 
	# Or maybe they can be fixed because we only ever respond to a single name.
	TTL_bits = pad_before(bin(int(ttl))[2:], 32)
	if len(TTL_bits) > 32:
	    print "TTL too large"
	    sys.exit(1)

	# Convert IP into bits.
	ip_bits = ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])
	pad_before(ip_bits, 14)

	return ('0b11' + offset_bits +
	    '0000000000000001' + # type is A
	    '0000000000000001' + # class is IN
	    TTL_bits + # should be 32 bits.
	    '0000000000000100' + # Length of the IP address. (needs fixing if we return more than one IP).
	    ip_bits)


if __name__ == "__main__":
	# This is a script that, given a domain name, and an IP address, creates
	# a response for it.
	if len(sys.argv) != 3:
	    print "Usage <script> <ip address> <TTL (decimal)>"
	    sys.exit(1)

	ip = sys.argv[1]
	ttl = sys.argv[2]

	print dns_response(ip, ttl)
