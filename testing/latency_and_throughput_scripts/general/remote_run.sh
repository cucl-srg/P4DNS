#!/bin/bash


# This runs a local script on a remote machine.
remote_run() {
	if [[ "$#" -lt 2 ]]; then
		echo "usage: runremote.sh remotehost localscript arg1 arg2 ..."
		exit 1
	fi

	host=$1
	realscript="$2"
	shift 2

	declare -a args

	count=1
	for arg in "$@"; do
	  args[$count]="$(printf '%q' "$arg")"
	  count=$((count+1))
	done

	echo "SSH'ing to $host"
	if [[ $# -gt 0 ]]; then
		ssh $host 'cat | bash /dev/stdin ' "${args[@]}" < "$realscript" | tee .ssh_output
	else
		ssh $host 'bash -s ' < $realscript | tee .ssh_output
	fi
	echo "Executing on $(hostname)"
}

# This runs a remote script on a remote machine.  The base for the script
# location is the folder /root/jcw78/scripts.
# Note that the execution is done in the local folder with that script in it.
remote_run_script() {
	if [[ "$#" -lt 2 ]]; then
		echo "usage remote_run_script remotehost scriptlocation arg1 arg2 ..."
		exit 1
	fi

	local host=$1
	local script=$2
	local scriptname=$(basename $script)
	local scriptdir=$(dirname $script)
	shift 2

	declare -a args
	count=1
	for arg in "$@"; do
		args[$count]="$(printf '%q' "$arg")"
		count=$((count+1))
	done

	echo "SSH'ing to $host"
	ssh $host "cd /root/jcw78/scripts/$scriptdir; bash $scriptname $args" | tee .ssh_output
	echo "Executing on $(hostname)"
}

remote_run_command() {
	if [[ "$#" -ne 2 ]]; then
		echo "usage remote_run_command remotehost command"
		exit 1
	fi
	local host=$1
	local cmd="$2"

	echo "SSH'ing to $host"
	ssh $host "$cmd" | tee .ssh_output
	echo "Executing on $(hostname)"
}
