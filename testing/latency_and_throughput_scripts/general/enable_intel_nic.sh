#!/bin/bash

rmmod ixgbe
modprobe ixgbe allow_unsupported_sfp=1
