#! /usr/bin/env python

import socket
import sys
import signal, os
import time

def handler(signum, frame):
    print 'Signal handler called with signal', signum
    sys.exit(0)

# Set the signal handler and a 5-second alarm
signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGHUP, handler)
signal.signal(signal.SIGTERM, handler)

# Create a UDS socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = '/tmp/exact_cap'
print >>sys.stderr, 'connecting to %s' % server_address
try:
    sock.connect(server_address)
except socket.error, msg:
    print >>sys.stderr, msg
    sys.exit(1)


try:
    
    # Send data
    message = " ".join(sys.argv)
    print >>sys.stderr, 'sending "%s"' % message
    sock.sendall(message)

    amount_received = 0
    amount_expected = len(message)
    
    while True:
        time.sleep(1)

finally:
    print >>sys.stderr, 'closing socket'
    sock.close()



 
