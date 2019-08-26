#!/bin/bash

set -eu
if [[ $# -ne 3 ]]; then
	echo "Usage: $0 <in1> <in2> <out>"
	exit 1
fi

paste $1 $2 > $3
