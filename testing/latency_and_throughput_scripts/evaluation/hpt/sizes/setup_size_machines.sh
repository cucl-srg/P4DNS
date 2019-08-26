#!/bin/zsh

set -ue
if [[ $# -ne 0 ]]; then
	echo "Usage: $0"
	exit 1
fi

# This is a script that sets up the machines defined in the config
# file so that they are ready to do the test.

source ../../../general/parse_config.sh
source ../../../general/remote_run.sh

echo "Libraries loaded.  Extracting config values"

machA=$(get_config_value "MachineA")
machB=$(get_config_value "MachineB")

nvme_dev_name=$(get_config_value "NVMeDeviceName")
echo "Config values extracted for setup.  Starting running on"
echo $machA
echo $machB

# Run the generic setup on both machines.
remote_run $machA ../../../setup/pre_setup_machine.sh
remote_run $machB ../../../setup/pre_setup_machine.sh

# Run the exanic setup on machine B.
remote_run_script $machB setup/setup_exanic_machine.sh

# Now, flash OSNT to the NetFPGA in machine A.
remote_run_script $machA bitfiles/setup_bitfile.sh osnt_20170129.bit

# Make sure the long term storage and the temporary NVMe are there on the capturing device.
remote_run_script $machB setup/setup_nvme.sh $nvme_dev_name
