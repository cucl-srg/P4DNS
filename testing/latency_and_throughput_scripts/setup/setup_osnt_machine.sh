#!/bin/bash

set -ue

mkdir -p /root/jcw78/
pushd /root/jcw78

# Get the CLI.
if [[ ! -d /root/jcw78/OSNT-SUME-live/ ]]; then
	git clone https://github.com/NetFPGA/OSNT-SUME-live.git

fi

# Either way, go in and set the right version.
pushd OSNT-SUME-live
git checkout 341708ffab448efcf9b77e14aa5c85c8eb1fc4c3
popd

# Build the riffa module:
pushd /root/jcw78/OSNT-SUME-live/lib/sw/driver/osnt_sume_riffa_v1_00/
make
popd

# Also get the bitfile:
if [[ ! -f /root/jcw78/osnt_20170129.bit ]];  then
	wget https://www.cl.cam.ac.uk/research/srg/netos/projects/netfpga/bitfiles/OSNT-SUME-live/osnt_20170129.bit
fi

# Get the applications directory:
if [[ ! -d /root/jcw78/SUMMER2017/ ]]; then
	git clone https://github.com/cucl-srg/SUMMER2017
fi

# Either way, go in and check out the right  version:
pushd /root/jcw78/SUMMER2017
git checkout 17d29a6efcf2c9b3fb5644a741abe1d0d1ef0773
popd

echo "Setup Done! The bit file has not been loaded.  Use init_osnt.sh to do that"
