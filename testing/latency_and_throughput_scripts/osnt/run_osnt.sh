#!/bin/zsh

# This is a wrapper script around the OSNT script.  It passes every 
# argument it receives onto the OSNT CLI.

cd /root/jcw78/OSNT-SUME-live/projects/osnt/sw/host/app/cli
python osnt-tool-cmd.py "$@"
