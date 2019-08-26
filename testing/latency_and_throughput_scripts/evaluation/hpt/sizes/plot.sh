#!/bin/bash

set -eu

source /root/jcw78/scripts/general/parse_config.sh
# Go to the LTS directory and go through all the cmd output folders.
lts_folder=$(get_config_value LTSLocations)
runs=$(get_config_value Runs)
min_size=$(get_config_value MinSize)
max_size=$(get_config_value MaxSize)
size_step=$(get_config_value StepSize)

if [[ ! -d $lts_folder ]]; then
	echo "Expecting folder $lts_folder to exist on this device"
fi

# Now, with the LTS folder in existence, go through every
# kown packet size and location for it.  The aim
# is to combine them into a temp file.
echo -n "" > combined_results
for size in $(seq $min_size $size_step $max_size); do
	step_sizes=""
	for run in $(seq 1 $runs); do
		# Get the cmd out from each run.
		cmd_out_file="$lts_folder/size_scan_${run}/${size}_cmd_out"

		if [[ ! -f $cmd_out_file ]]; then
			echo "Error: expected $cmd_out_file to be a file"
			exit 1
		fi

		# Otherwise, get the number of received packets:
		this_drops=$(awk -F' ' '/SW Wrote:/ {print $3}' $cmd_out_file)
		step_sizes="$step_sizes $this_drops"
	done
	echo $step_sizes >> combined_results
done

# Now put the results on the LTS.
mkdir -p $lts_folder/size_scan_aggregated
mv combined_results $lts_folder/size_scan_aggregated

# With that in place, call the plot function on those results.
python plot.py combined_results $min_size $size_step $max_size $num_packets_sent
