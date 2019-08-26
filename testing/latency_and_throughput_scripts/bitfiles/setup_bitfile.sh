#!/bin/bash

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <bitfile>"
	exit 1
fi

set -eu

source /root/jcw78/scripts/general/parse_config.sh

SDKLocation=$(get_config_value VivadoLocation ../setup/config)
XMDLocation=$(get_config_value XMDLocation ../setup/config)

export DRIVER_FOLDER=/root/jcw78/NetFPGA-SUME-live/lib/sw/std/driver/sume_riffa_v1_0_0
export SUME_FOLDER=/root/jcw78/NetFPGA-SUME-live
export PATH=$PATH:$XMDLocation:$SDKLocation

current_dir=$PWD
pushd /root/jcw78/NetFPGA-SUME-live/tools/scripts
chmod +x ./run_load_image.sh
./run_load_image.sh $current_dir/$1
popd
