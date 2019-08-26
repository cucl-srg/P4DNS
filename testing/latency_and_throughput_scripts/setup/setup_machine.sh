#!/bin/bash

set -ue

# This script requires the directory to have been cloned
# already.  It should be called locally for the config
# sourcing to work OK.

if [[ ! -f ../general/parse_config.sh ]]; then
	echo "Error: could not load the config.  Is this script being run from the right directory?"
	exit 1
fi

if [[ ! -d /root/jcw78/scripts ]]; then
	echo "Error: could not find the scripts directory.  Have you run pre_setup_machine.sh?"
	exit 1
fi

source ../general/parse_config.sh 
VIVADO_LOC=$(get_config_value "VivadoLocation")
XMD_LOC=$(get_config_value "XMDLocation")

if [[ ! -f /root/.vimrc ]]; then
	echo "imap jk <Esc>
	imap JK <Esc>
	nmap <Space>w :w<CR>" > /root/.vimrc
else
	echo "VIMRC already exists, not overwriting"
fi

mkdir -p /root/jcw78
cd /root/jcw78

# Get the scripts directory:
if [[ ! -d scripts ]]; then
	git clone https://github.com/j-c-w/BandwidthPerf scripts
fi

if [[ ! -d NetFPGA-SUME-live ]]; then
	# Get SUME (and build the module)
	git clone https://github.com/NetFPGA/NetFPGA-SUME-live.git
fi

pushd NetFPGA-SUME-live/lib/sw/std/driver/sume_riffa_v1_0_0
make
popd

# Install things on the machine.
sudo apt install python-tk python-pip pbzip2 scapy nfs-common parallel cpufrequtils alien dkms
sleep 1
pip install --upgrade pip
# Attempt to avoid issues with 'main' not found.
sleep 2
python -m pip install  matplotlib --ignore-installed
pip install statistics
pip install numpy
pip install scipy

# Get the PCAP parsing scripts
if [[ ! -d process_pcap_traces ]]; then
	git clone https://github.com/j-c-w/process_pcap_traces
fi

# Get OSNT and the NRG-dev folder.
if [[ ! -d NRG-dev ]]; then
	git clone https://github.com/j-c-w/NRG-dev
fi

pushd /root/jcw78/NRG-dev/sw/api
# Build the NRG APIs.
./build_me.sh
popd

if [[ ! -d OSNT-SUME-live ]]; then
	git clone https://github.com/NetFPGA/OSNT-SUME-live.git
fi

# We need to build the OSNT software.
pushd /root/jcw78/OSNT-SUME-live/projects/osnt/sw/host/app
make
popd

# Finally, get the SUMMER2017 repo:
if [[ ! -d SUMMER2017 ]]; then
	git clone https://github.com/j-c-w/SUMMER2017
fi

# Copy the local bitfiles to the top level.
cp /root/jcw78/scripts/bitfiles/* /root/jcw78

# Generate the pcap files:
pushd /root/jcw78/scripts/pcap_files/
echo "Generating PCAP files..."
for i in $(seq 1 1518); do
	if [[ ! -f $i.cap ]]; then
		python ../general/generate_pcap.py $i 1> /dev/null
		mv variable_length.pcap $i.cap
	fi
done
popd
echo "Done generating PCAP files."

# Make and install the Exanic software.
pushd /root/jcw78/scripts/hpt_setup
# First make the generic repository:
pushd exanic-software
make clean
make
sudo make install
popd
# Then make the exanic-exact stuff:
pushd exanic-exact/exact-capture-1.0RC/
make clean
make
sudo make install

# Make sure vivado is installed:
if [[ ! -d $VIVADO_LOC ]]; then
	echo "Vivado should be installed in $VIVADO_LOC"
	echo "Edit the config file in $PWD/config"
	echo "Install failed: set Vivado location and run again"
	echo "If $(hostname) is a machine that needs to use a NetFPGA then you need to have Vivado installed.  Otherwise, this can be ignored."
	exit 0
fi
if [[ ! -d $XMD_LOC ]]; then
	echo "XMD should be installed in $XMD_LOC"
	echo "Edit the config file in $PWD/config"
	echo "Install failed: set XMD location and run again"
	echo "If $(hostname) is a machine that needs to use a NetFPGA, then you need to have XMD installed.  Otherwise, this can be ignored."
	exit 0
fi
echo "Install finished!"
