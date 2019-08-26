#!/bin/bash

if [[ "$#" -eq 0 ]]; then
	source ../general/parse_config.sh
	typeset -r settings_loc="$(get_config_value 'VivadoSetting')"
else
	typeset -r settings_loc=/home/Vivado/2016.4/settings64.sh
fi

# Make the kernel module
pushd /root/jcw78/OSNT-SUME-live/lib/sw/driver/osnt_sume_riffa_v1_00
make
popd
pushd /root/jcw78/OSNT-SUME-live/projects/osnt/test
# The xilinx path is set by some mysterious config
# file I can't find.
export XILINX_PATH=""
source $settings_loc
bash run_load_image.sh /root/jcw78/osnt_20170129.bit
