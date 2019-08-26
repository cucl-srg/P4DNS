#!/bin/bash

set -e 
if [[ $(pwd) != /root/P4-NetFPGA/contrib-projects/sume-sdnet-switch/projects/switch_calc/src ]]; then
	echo "Needs to be executed in /root/P4-NetFPGA/contrib-projects/sume-sdnet-switch/projects/switch_calc/src"
	exit 1
fi

source ~/P4-NetFPGA/tools/settings.sh

make 
cd $P4_PROJECT_DIR
make
cd $P4_PROJECT_DIR/nf_sume_sdnet_ip/SimpleSumeSwitch
bash vivado_sim.bash
cd $P4_PROJECT_DIR
make config_writes
make uninstall_sdnet
make install_sdnet
cd $NF_DESIGN_DIR
make > ~/compile_out
