#!/bin/bash

set -ue
# Copy all the local pcap files to the remote machine.
if [[ "$#" -ne 2 ]]; then
	echo "Usage: $0 <target machine> <max pcap size>"
fi

host=$1
max_size=$2

# Generate all sizes of PCAP file up to max size:
pushd ../pcap_files/
for i in $(seq 1 ${max_size}); do
	if [[ ! -f $i.cap ]]; then
		python ../general/generate_pcap.py $i
		mv variable_length.pcap $i.cap
	fi
done
popd

echo "PCAP file generated!  Copying them to ${host}..."

# Now, copy them all.
source ../general/remote_scp.sh
source ../general/remote_exists.sh

files=( ../pcap_files/*.cap )
export host=$1

ssh $host 'mkdir -p /root/jcw78/pcap_files'
existing_files=$(ssh $host 'cd /root/jcw78/pcap_files; find . -name "*"')
parallel -j 32 --retries 5 --progress 'source ../general/remote_scp.sh; remote_scp $host {} /root/jcw78/pcap_files/$(basename {})' ::: ${files[@]}

wait
