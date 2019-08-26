#!/bin/bash

set -eu

source /root/jcw78/scripts/general/parse_config.sh
source /root/jcw78/scripts/general/remote_run.sh
# First, setup the machines
./setup_size_machines.sh

# Now, get the number of runs:
runs=$(get_config_value "Runs")
HPTMachine=$(get_config_value "MachineB")
lts_loc=$(get_config_value "LTSLocations")

for run in $(seq 1 $runs); do
	echo "Starting run number $run"
	pushd size_scan/
	./run.sh
	popd

	# This script will have compressed each one individually,
	# meaning we only have to move the directory as a whole.
	remote_run_command $HPTMachine "mv /root/jcw78/nvme/size_scan $lts_loc/size_scan_$run"
done
