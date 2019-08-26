#
# Copyright (c) 2017 Stephen Ibanez
# All rights reserved.
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


# Makefile to build the SUME-SDNet module / wrapper IP for use in the SUME project 

SDNET_OUT_DIR=nf_sume_sdnet_ip

PX=sdnet
PX_FLAGS=-busType axi -busWidth 256 -singlecontrolport -workDir ${SDNET_OUT_DIR} -altVivadoScripts
TARGET=${SUME_FOLDER}/lib/hw/contrib/cores
P4_SWITCH=SimpleSumeSwitch
P4_SWITCH_BASE_ADDR=0x44020000
SWITCH_INFO=src/.sdnet_switch_info.dat

# Compile to HDL with P4-SDNet
# Running vivado_sim.bash or questa.bash compares the HDL simulation output to user provided expected output 
all: clean frontend compile_no_cpp_test run_scripts
	cp src/*.tbl ${SDNET_OUT_DIR}/${P4_SWITCH}/
	cp testdata/*.txt ${SDNET_OUT_DIR}/${P4_SWITCH}/
	cp testdata/*.axi ${SDNET_OUT_DIR}/${P4_SWITCH}/

# Compile to HDL with P4-SDNet
# Running vivado_sim.bash or questa.bash compares the HDL simulation output to the C++ simulation output
cpp_test: clean frontend compile_cpp_test run_scripts 
	cp src/*.tbl ${SDNET_OUT_DIR}/${P4_SWITCH}/
	cp testdata/src.pcap ${SDNET_OUT_DIR}/${P4_SWITCH}/Packet.user
	cp testdata/Tuple_in.txt ${SDNET_OUT_DIR}/${P4_SWITCH}/Tuple.user
	cp src/*.tbl ${SDNET_OUT_DIR}/${P4_SWITCH}/${P4_SWITCH}.TB/
	cp testdata/src.pcap ${SDNET_OUT_DIR}/${P4_SWITCH}/${P4_SWITCH}.TB/Packet.user
	cp testdata/Tuple_in.txt ${SDNET_OUT_DIR}/${P4_SWITCH}/${P4_SWITCH}.TB/Tuple.user

frontend:
	make -C src/
	make -C testdata/

compile_cpp_test:
	$(PX) ./src/${P4_PROJECT_NAME}.sdnet $(PX_FLAGS)

compile_no_cpp_test:
	$(PX) ./src/${P4_PROJECT_NAME}.sdnet -skipEval $(PX_FLAGS)

run_scripts:
	${SUME_SDNET}/bin/gen_P4_SWITCH_externs.py ${SWITCH_INFO} ${SDNET_OUT_DIR}/${P4_SWITCH}/ ${SUME_SDNET}/templates/ ./testdata/ ./sw/ --base_address ${P4_SWITCH_BASE_ADDR}
	${SUME_SDNET}/bin/gen_P4_SWITCH_API.py ${SWITCH_INFO} ${SDNET_OUT_DIR}/${P4_SWITCH}/ sw/ ${SUME_SDNET}/templates/ --base_address ${P4_SWITCH_BASE_ADDR}
	${SUME_SDNET}/bin/gen_P4_SWITCH_CLI.py ${SWITCH_INFO} ${SDNET_OUT_DIR}/${P4_SWITCH}/ sw/ ${SUME_SDNET}/templates/ --base_address ${P4_SWITCH_BASE_ADDR}
	# The following command only applies if running P4_SWITCH Questa Simulation with Ubuntu
	sed -i 's/vsim/vsim \-ldflags \"\-B\/usr\/lib\/x86\_64\-linux-gnu\"/g' ${SDNET_OUT_DIR}/${P4_SWITCH}/questa.bash
	# modify the P4_SWITCH_tb so that it writes the table configuration writes to a file
	${SUME_SDNET}/bin/modify_P4_SWITCH_tb.py ${SDNET_OUT_DIR}/${P4_SWITCH}/Testbench/${P4_SWITCH}_tb.sv
	# Fix introduced for SDNet 2017.4
	sed -i 's/xsim\.dir\/xsc\/dpi\.so/dpi\.so/g' ${SDNET_OUT_DIR}/${P4_SWITCH}/vivado_sim.bash
	sed -i 's/xsim\.dir\/xsc\/dpi\.so/dpi\.so/g' ${SDNET_OUT_DIR}/${P4_SWITCH}/vivado_sim_waveform.bash
	# Fix introduced for SDNet 2018.2
	sed -i 's/glbl_sim/glbl/g' ${SDNET_OUT_DIR}/${P4_SWITCH}/vivado_sim_waveform.bash
	sed -i 's/SimpleSumeSwitch_tb_sim#work.glbl/SimpleSumeSwitch_tb/g' ${SDNET_OUT_DIR}/${P4_SWITCH}/vivado_sim_waveform.bash

config_writes:
	${SUME_SDNET}/bin/gen_config_writes.py ${SDNET_OUT_DIR}/${P4_SWITCH}/config_writes.txt ${P4_SWITCH_BASE_ADDR} testdata

# install the SDNet core as a NetFPGA-SUME-SDNet library core 
install_sdnet: uninstall_sdnet
	cp -r ${SDNET_OUT_DIR} ${TARGET}/
	mkdir ${TARGET}/${SDNET_OUT_DIR}/wrapper
	cp ${SUME_SDNET}/templates/sss_wrapper/hdl/* ${TARGET}/${SDNET_OUT_DIR}/wrapper/
	cp ${SUME_SDNET}/templates/sss_wrapper/tcl/* ${TARGET}/${SDNET_OUT_DIR}/
	cp ${SUME_SDNET}/templates/sss_wrapper/Makefile ${TARGET}/${SDNET_OUT_DIR}/
	make -C ${TARGET}/${SDNET_OUT_DIR}/

uninstall_sdnet:
	rm -rf ${TARGET}/${SDNET_OUT_DIR}

clean:
	make -C src/ clean
	make -C testdata/ clean
	rm -rf ${SDNET_OUT_DIR}/
	rm -f $(shell find -name *.log -o -name *.jou)
	rm -f sw/config_tables.c

