#!/bin/bash

set -ue

if [[ "$#" -ne 2 ]]; then
	echo "Usage: $0 <mount point> <size>"
	echo "Size can be any units provided they are specified, e.g. 64g"
	exit 1
fi

mount_point=$1
size=$2
fs_type=ramfs

# We really don't want to eat the ram by mounting gazillions
# of these each time setup is called.  There are plenty
# of good reasons for setup to be called without the HPT
# machine restarting.  So, check whether there is already
# a ramdisk mounted.  This is a complete hack, so accompany
# it with a big warning!
echo "Checking if already mounted..."
set -x
already_mounted="$(df | (grep -ce "${fs_type}.*$mount_point" || true))"
echo "Mount check complete (yielded $already_mounted)"

# If we have not mounted any ramfs disks at the location
# already, then mount away!
if [[ $already_mounted == 0 ]]; then
	if [[ -n "$(ls -A $mount_point)" ]]; then
		# If the mount-point isn't empty, then we can't use
		# the ramdisk here.  This is an error.
		echo "Error: $mount_point is neither a ramdisk nor empty."
		echo "Cannot setup ramdisk."
		exit 1
	fi
	echo "Disk not mounted, starting to mount"
	mkdir -p $mount_point
	mount -t tmpfs -o size=$size $fs_type $mount_point
	echo "Mounted at $mount_point!"
else
	echo "RAMDISK already mounted at $mount_point! Skipping!"
fi
