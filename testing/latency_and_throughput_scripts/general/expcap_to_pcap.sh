#!/bin/bash

if [[ $# -ne 2 ]]; then
	echo "Usage $0 <input file .expcap> <output file .pcap>"
	exit 1
fi

infile="$1"
outfile="$2"

# Check if the file needs to be decompressed first.
if [[ "$1" == *bz2 ]]; then
	# Unzip it.
	echo "Extracting"
	bunzip2 -d "$1"
	infile=${infile/.bz2/}
	echo "Extracted to $infile"
fi

echo "Converting..."
/root/jcw78/scripts/hpt_setup/exanic-exact/exact-capture-1.0RC/bin/exact-pcap-extract -i "$infile" -w "$outfile" -a -f pcap --usecpcap 1
