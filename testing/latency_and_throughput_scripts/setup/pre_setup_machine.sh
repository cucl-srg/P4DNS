#!/bin/bash
set -ue

# This script does a pre-setup to make sure that the setup scripts exist etc.

mkdir -p /root/jcw78
if [[ ! -d /root/jcw78/scripts ]]; then
	git clone https://github.com/j-c-w/BandwidthPerf /root/jcw78/scripts
fi

echo "Pre setup done!"
echo "Calling setup machine!"
cd /root/jcw78/scripts/setup/
./setup_machine.sh
