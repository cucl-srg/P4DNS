#!/bin/bash

set -eu

if [[ "$#" -ne 1 ]]; then
	echo "Usage: $0 <NVMe device name>"
	exit 1
fi

mkdir -p /root/jcw78/nvme
mount $1 /root/jcw78/nvme
