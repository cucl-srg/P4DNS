#!/bin/bash

if [[ $# -eq 0 ]]; then
	echo "Usage $0 <files to compress>"
	exit 1
fi

parallel pbzip2 {} ::: "$@"
