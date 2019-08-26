#!/bin/zsh

set -ue
set -x

zmodload zsh/mathfunc

source /root/jcw78/scripts/general/parse_config.sh
source /root/jcw78/scripts/general/remote_run.sh

typeset -a dry_run
zparseopts -D -E -dry-run=dry_run

# Get the number of packets to send.
num_to_send=$(get_config_value NumberToSend)
starting_size=$(get_config_value MinSize)
final_size=$(get_config_value MaxSize)
increase=$(get_config_value StepSize)

OSNTMachine=$(get_config_value MachineA ../config)
HPTMachine=$(get_config_value MachineB ../config)

exa_port0=$(get_config_value HPTInterface0 ../config)
exa_port1=$(get_config_value HPTInterface1 ../config)
cpus=$(get_config_value HPTCPUs0 ../config)
# Keep track of the total space used.
total_space=0.0
# Wire capacity in Mbps.
wire_capacity=10000
rate=$wire_capacity

# Before we start, make sure that all existing recording
# is killed:
if [[ ${#dry_run} -eq 0 ]]; then
	remote_run_script $HPTMachine hpt/stop_recording.sh
fi

# These represent how often to go and compress files.
last_compress=$starting_size
compress_step=40

for size in $(seq $starting_size $increase $final_size); do
	echo "Capturing at $rate Mbps"

	# Calculate the IPG from the rate here:
	# On a 10G channel, one bit is 0.1ns.
	# IPG = target_rate * (packet wire time / max wire rate) - packet wire time
	packet_time=$(( 1000.0 * $size * 8.0 / $wire_capacity ))
	ipg=$((int(rint($(echo "scale=30; 10000.0 * ($packet_time / $rate) - $packet_time" | bc)))))
	echo "==========================================="
	echo "Running tests for rate $rate"
	echo "This means using inter-arrival gap ${ipg}ns"
	expected_time=$(( (num_to_send * ($size * 8)) / ($rate * 1000000) ))
	expected_space=$(( num_to_send * size ))
	total_space=$(( total_space + expected_space / 1000000000.0 ))
	echo "Expected runtime is $expected_time"
	echo "Expected space is ${expected_space}B"
	echo "Total space used by this test is $total_space GB"

	if [[ ${#dry_run} -gt 0 ]]; then
		continue
	fi
	set -x
	# Start the exanic recording.
	remote_run_script $HPTMachine hpt/record_port.sh $exa_port1 /dev/null $cpus /root/p51/P4-NetFPGA-live/report/throughput/${size}_cmd_out
	remote_run_command $HPTMachine  "cat /root/p51/P4-NetFPGA-live/report/throughput/${size}_cmd_out"
	# Run OSNT at the desired rate.
	remote_run_script $OSNTMachine osnt/run_osnt.sh -ifp0 /root/p51/dns_packets/$size.cap -rpn0 $num_to_send -ipg0 $ipg -run
	sleep $(( int(expected_time) + 3 ))

	# End the exanic recording.
	remote_run_script $HPTMachine hpt/stop_recording.sh
done
