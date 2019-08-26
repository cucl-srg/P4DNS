#!/bin/bash

set -eu

if [[ $# -ne 4 ]] && [[ $# -ne 5 ]]; then
	echo "Usage: <port> <output capture file> <cpus list (see exanic documentation)> <command line output file>"
	echo "Usage: <port 1> <port 2> <output capture file> <cpus list (see exanic documentation)> <command line output file>"
	echo "The CPUs should be a colon-separated list of three CPUs. e.g. 44:45:46"
	exit 1
fi

cpus_check() {
	# This function makes a rough check that the CPUs list
	# is right.  I ran into a lot of head-scratching bugs
	# due to issues with this list I didn't relize.  This
	# isn't a full check!
	local cpus_arg=$1

	if [[ $(tr -dc ':' <<<"$cpus_arg" | awk '{ print length; }')  != 2 ]]; then
		echo "Error: require a format suitable to pass to the HPT --cpus flag.  Instead got: $cpus_arg"
		exit 1
	fi
}

# Make sure that the port is enabled first.
pushd /root/jcw78/scripts/hpt_setup/exanic-software/util
./exanic-config $1 up
popd

# The ExaNIC appears to react fine to having multiple               
# instances running.  There is a kill script, but
# we don't do that here.  This lets us start multiple
# experiments on the machine.
if [[ $# -eq 4 ]]; then
	port=$1
	out_file=$2
	cpus=$3
	cmd_out_file=$4

	cpus_check $cpus

	# Make sure that the appropriate folders exist:
	mkdir -p $(dirname $out_file)
	mkdir -p $(dirname $cmd_out_file)

	pushd /root/jcw78/scripts/hpt_setup/exanic-exact/exact-capture-1.0RC/bin
	nohup ./exact-capture -i $port -o $out_file --cpus $cpus --no-kernel &> $cmd_out_file &
fi

if [[ $# -eq 5 ]]; then
	port_1=$1
	port_2=$2
	out_file=$3
	cpus=$4
	cmd_out_file=$5

	cpus_check $cpus

	# Make sure that the appropriate folders exist:
	mkdir -p $(dirname $out_file)
	mkdir -p $(dirname $cmd_out_file)

	pushd /root/jcw78/scripts/hpt_setup/exanic-exact/exact-capture-1.0RC/bin
	nohup ./exact-capture -i $port_1 -i $port_2 -o $out_file --cpus $cpus --no-kernel &> $cmd_out_file &
fi

echo "Capture started!"
echo "Capturing into file $out_file, with command output into file $cmd_out_file"
