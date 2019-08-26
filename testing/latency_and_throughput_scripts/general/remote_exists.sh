#!/bin/echo "This should be sourced not evaluated"

remote_exists() {
	if [[ "$#" -ne 2 ]]; then
		echo "Usage: $0 <host> <file>"
		exit 1
	fi

	host=$1
	file=$2

	is_file=$(ssh $host "if [[ -f $file ]]; then; echo 1; else; echo 0; fi")

	if [[ $is_file == 1 ]]; then
		echo "Exists"
	else
		echo "NotExists"
	fi
}
