#! /usr/bin/env python

import socket
import sys
import os
import select
import Queue
import signal, os
import time
import subprocess

###############################################################################
# EXACT CAPTURE CONFIGURATION
###############################################################################
cap_prepend     = "rm -rf /dev/shm/* && taskset -c 1,2,3,4,5,6,7,8,9,10,11 " 
cap_snaplen     = 2048 #Capture packets up to 2048B
cap_maxfile     = 0 #Set no limit on the per file output size
cap_ifaces      = ["exanic1:0", "exanic1:1", "exanic2:0", "exanic2:1"]
cap_tmp_outs    = ["/media/nvme0", "/media/nvme1", "/media/nvme2", "/media/nvme3"]
cap_tmp_file    = "exact_cap_tmp"

cap_tmp_paths   = [ "%s/%s" % (x,cap_tmp_file) for x in cap_tmp_outs ]
cap_all_ifaces  = " ".join([ "--interface=%s" % x for x in cap_ifaces])
cap_all_outs    = " ".join([ "--output=%s" % (tmp_path) for tmp_path in cap_tmp_paths ])
cap_bin         = "/root/exact-capture/bin/exact-capture"

capture_cmd = "%s %s %s %s --maxfile=%i --sanplen=%i " \
    % (cap_prepend, cap_bin, cap_all_ifaces, cap_all_outs, cap_maxfile, cap_snaplen)
#capture_cmd = "echo \"%s\"" % capture_cmd 

#print capture_cmd

###############################################################################
# EXACT EXTRACT CONFIGURATION
###############################################################################
extr_prepend     = "taskset -c 1,2,3,4,5,6,7,8,9,10,11 " 
extr_format      = "pcap" # options are pcap or expcap
extr_maxfile     = 1024 #Limit output files to 1GB ea
extr_nic_to_port = {"exanic1:0":"0", 
                    "exanic1:1":"1", 
                    "exanic2:0":"2", 
                    "exanic2:1":"3" }
extr_input_files = cap_tmp_paths
extr_bin         = "/root/exact-extract/bin/exact-extract"

extr_all_files = " ".join("--extract=%s-0.expcap" % tmp for tmp in extr_input_files)
extract_cmd_base = "%s %s %s --format=%s --maxfile=%s" % \
            (extr_prepend, extr_bin, extr_all_files, extr_format, extr_maxfile)

#print extract_cmd_base


server_address = '/tmp/exact_cap'

def handler(signum, frame):
    print 'Signal handler called with signal', signum
    sys.exit(0)

# Set the signal handler and a 5-second alarm
signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGHUP, handler)
signal.signal(signal.SIGTERM, handler)

# Make sure the socket does not already exist
try:
    os.unlink(server_address)
except OSError:
    if os.path.exists(server_address):
        raise

# Create a UDS socket
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

# Bind the socket to the port
print >>sys.stderr, "Starting ExaCT Capture Automation Server"
server.bind(server_address)

# Listen for incoming connections
server.listen(10)

# Sockets from which we expect to read
inputs = [ server ]

# Sockets to which we expect to write
outputs = [ ]

ifaces = {}

while inputs:

    # Wait for at least one of the sockets to be ready for processing
    if len(inputs) ==  1:
        print >>sys.stderr, "Waiting for clients to connect..."
    readable, writable, exceptional = select.select(inputs, [], [])

    # Handle inputs
    for s in readable:

        if s is server:
            # A "readable" server socket is ready to accept a connection
            connection, client_address = s.accept()
            connection.setblocking(0)
            inputs.append(connection)
        else:
            data = s.recv(1024)
            if data:
                # A readable client socket has data
                argv = data.split(" ")
                if len(argv) != 3:
                    print >>sys.stderr, "Incorrect number of parameters %i" % len(argv)
                    inputs.remove(s)
                    s.close()
                    continue

                (appname, iface, outfile) = argv
                print >>sys.stderr, "Capture request from %s to \"%s\"..." % (iface, outfile)
                ifaces[iface] = outfile
                if len(inputs) == 2:
                    print >>sys.stderr, "First client connected, starting capture..."
		    print >>sys.stderr, capture_cmd
                    capture_process = subprocess.Popen(capture_cmd, shell=True)
            else:
                # Interpret empty result as closed connection
                #print >>sys.stderr, "Client disconnected!" 
                # Stop listening for input on the connection
                inputs.remove(s)
                s.close()

                if len(inputs) == 1:
                    print >>sys.stderr, "All clients disconnected, ending capture..."

                    # Send SIGTER (on Linux)
                    capture_process.terminate()
                    # Wait for process to terminate
                    returncode = capture_process.wait()
                    print "Returncode of subprocess: %s" % returncode

                    for iface in ifaces:
                        outfile = ifaces[iface]
                        print >>sys.stderr, "Outputting from %s to file \"%s\"..." % (iface, outfile)
                        if iface not in extr_nic_to_port:
                            print >>sys.stderr, "Error: %s not a supported interface" % iface
                        else:
                            extract_cmd = "%s --port=%s --write=%s && mv %s_0.pcap %s" %  \
                                (extract_cmd_base, extr_nic_to_port[iface], outfile, outfile, outfile)			    
                            #extract_cmd = "echo \"%s \"" % (extract_cmd)
			    print >>sys.stderr, extract_cmd
                            subprocess.call(extract_cmd, shell=True)
                    ifaces = {} #reset now that we've output everything
		    print >>sys.stderr, "Removing temporary files\n"
		    os.system("rm -rf /tmp/nvme*/*")
                    print >>sys.stderr, "Capture complete!" 
