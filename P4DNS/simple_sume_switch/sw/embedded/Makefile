#
# Copyright (c) 2015 University of Cambridge
# Modified by Salvator Galea
# All rights reserved.
#
#  File:
#        Makefile
#
#  Project:
#        reference projects
#
#
#  Description:
#        This makefile is used to generate and compile SDK project for reference projects.
#
# This software was developed by Stanford University and the University of Cambridge Computer Laboratory 
# under National Science Foundation under Grant No. CNS-0855268,
# the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
# by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), 
# as part of the DARPA MRC research programme.
#
# @NETFPGA_LICENSE_HEADER_START@
#
# Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  NetFPGA licenses this
# file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.netfpga-cic.org
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @NETFPGA_LICENSE_HEADER_END@
#
# Vivado Launch Script
################################################################################


WS	= SDK_Workspace
PROJ	= ${NF_PROJECT_NAME}

.PHONY: distclean clean project compile download

all:
	@echo ""
	@echo "NetFPGA-SUME Reference Project SW Makefile"
	@echo ""
	@echo "make TARGETS"
	@echo "------------------------------------------------------"
	@echo "project:         Create software project"
	@echo "compile:         Compile specified project"
	@echo "download:        Download and run specified project via xmd"
	@echo ""
	@echo "clean:           Remove specified project"
	@echo "distclean:       Remove all generated projects"
	@echo ""

project:
	@if [ -d ./${WS} ]; then rm -rf ./${WS}; fi
	mkdir ./${WS}
	xsdk -batch -source ./tcl/${PROJ}_xsdk.tcl

# Compile Command needs to run twice to get sw compiled correctly in DEBUG mode
compile:
	@if [ -d ./${WS} ]; then \
		cp -a ./src/. ./${WS}/${PROJ}/app/src/; \
		xsdk -wait -eclipseargs -nosplash -application org.eclipse.cdt.managedbuilder.core.headlessbuild -build all -data ./${WS}/${PROJ} -vmargs -Dorg.eclipse.cdt.core.console=org.eclipse.cdt.core.systemConsole; \
		xsdk -wait -eclipseargs -nosplash -application org.eclipse.cdt.managedbuilder.core.headlessbuild -build all -data ./${WS}/${PROJ} -vmargs -Dorg.eclipse.cdt.core.console=org.eclipse.cdt.core.systemConsole; \
	else \
		echo "SDK_Workspace not found"; \
	fi

download:
	@if [ -d ./../bitfiles ]; then \
		xmd -tcl ./tcl/download.tcl `find ./../bitfiles -name "*.bit"`; \
	else \
		echo "Bitfile folder not found"; \
	fi


clean:
	rm -rf ./${WS}
	rm -rf *.log
	rm -rf *.jou

distclean:
	rm -rf `find . -name "${WS}"`
	rm -rf `find . -name "*.log"`
	rm -rf `find . -name "*.jou"`

