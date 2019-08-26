#!/bin/bash
set -eu
# Now, get the firmware and install it.
if [[ ! -f exanic_hpt_20180221.fw.gz ]]; then
	wget https://exablaze.com/downloads/exanic/exanic_hpt_20180221.fw.gz
fi

if [[ ! -f exanic_hpt_20180221.fw ]]; then
	gzip -d exanic_hpt_20180221.fw.gz
fi

# Now, install that firmware.
firmware_loc="$PWD/exanic_hpt_20180221.fw"
pushd /root/jcw78/scripts/hpt_setup/exanic-software/util
./exanic-fwupdate -d exanic0 -r $firmware_loc || (echo "If that script failed requiring a reboot, reboot the system and run /root/jcw78/scripts/setup/update_exanic_firmware.sh before running setup_exanic_machine.sh"; exit 1)
# Note that the system needs a reboot now, so
# exit with an error, inform the user and then wait.
echo "$(hostname) NOW NEEDS TO BE REBOOTED.  Re-run this script after reboot."
# Exit with an error to make sure all scripts stop.
exit 1
