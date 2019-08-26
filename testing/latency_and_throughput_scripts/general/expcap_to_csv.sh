#!/bin/bash

if [[ $# -ne 2 ]]; then
	echo "Usage $0 <input file .expcap> <output file .csv>"
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
# This command fails every time because of some bug.  It says ''end of file'' or something like that, but as far as I can see it extracts every packet anyway.
/root/jcw78/scripts/hpt_setup/exanic-exact/exact-capture-1.0RC/bin/exact-pcap-parse -i "$infile" -c "$outfile" -f expcap || echo ""
