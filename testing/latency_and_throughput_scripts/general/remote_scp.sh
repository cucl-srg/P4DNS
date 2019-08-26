#!/bin/echo "This should not be run, it needs to be sourced"

remote_scp() {
	if [[ "$#" -ne 3 ]]; then
		echo "Usage: $0 <host> <source file> <dest file>"
		exit 1
	fi

	local host=$1
	local src=$2
	local dst=$3
	echo "Copying onto $host"

	scp $src $host:$dst
}
