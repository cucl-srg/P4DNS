#
# Copyright (c) 2015 Georgina Kalogeridou
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

# Set variables.
set design $::env(NF_PROJECT_NAME)
set top top_sim
set sim_top top_tb
set device  xc7vx690t-3-ffg1761
set proj_dir ./project
set public_repo_dir $::env(SUME_FOLDER)/lib/hw/
set xilinx_repo_dir $::env(XILINX_VIVADO)/data/ip/xilinx/
set repo_dir ./ip_repo
set bit_settings $::env(CONSTRAINTS)/generic_bit.xdc 
set project_constraints $::env(NF_DESIGN_DIR)/hw/constraints/nf_sume_general.xdc
set nf_10g_constraints $::env(NF_DESIGN_DIR)/hw/constraints/nf_sume_10g.xdc


set test_name [lindex $argv 0] 

#####################################
# Read IP Addresses and export registers
#####################################
source $::env(NF_DESIGN_DIR)/hw/tcl/$::env(NF_PROJECT_NAME)_defines.tcl

# Build project.
create_project -name ${design} -force -dir "$::env(NF_DESIGN_DIR)/hw/${proj_dir}" -part ${device}
set_property source_mgmt_mode DisplayOnly [current_project]  
set_property top ${top} [current_fileset]
puts "Creating User Datapath reference project"

create_fileset -constrset -quiet constraints
file copy ${public_repo_dir}/ ${repo_dir}
set_property ip_repo_paths ${repo_dir} [current_fileset]
add_files -fileset constraints -norecurse ${bit_settings}
add_files -fileset constraints -norecurse ${project_constraints}
add_files -fileset constraints -norecurse ${nf_10g_constraints}
set_property is_enabled true [get_files ${project_constraints}]
set_property is_enabled true [get_files ${bit_settings}]
set_property is_enabled true [get_files ${project_constraints}]

update_ip_catalog
#source ../hw/create_ip/nf_sume_sdnet.tcl  # only need this if have sdnet_to_sume fifo in wrapper
create_ip -name nf_sume_sdnet -vendor NetFPGA -library NetFPGA -module_name nf_sume_sdnet_ip
set_property generate_synth_checkpoint false [get_files nf_sume_sdnet_ip.xci]
reset_target all [get_ips nf_sume_sdnet_ip]
generate_target all [get_ips nf_sume_sdnet_ip]

create_ip -name input_arbiter -vendor NetFPGA -library NetFPGA -module_name input_arbiter_ip
set_property -dict [list CONFIG.C_BASEADDR $INPUT_ARBITER_BASEADDR] [get_ips input_arbiter_ip]
set_property generate_synth_checkpoint false [get_files input_arbiter_ip.xci]
reset_target all [get_ips input_arbiter_ip]
generate_target all [get_ips input_arbiter_ip]

create_ip -name sss_output_queues -vendor NetFPGA -library NetFPGA -module_name sss_output_queues_ip
set_property -dict [list CONFIG.C_BASEADDR $OUTPUT_QUEUES_BASEADDR] [get_ips sss_output_queues_ip]
set_property generate_synth_checkpoint false [get_files sss_output_queues_ip.xci]
reset_target all [get_ips sss_output_queues_ip]
generate_target all [get_ips sss_output_queues_ip]

#Add ID block
create_ip -name blk_mem_gen -vendor xilinx.com -library ip -version 8.4 -module_name identifier_ip
set_property -dict [list CONFIG.Interface_Type {AXI4} CONFIG.AXI_Type {AXI4_Lite} CONFIG.AXI_Slave_Type {Memory_Slave} CONFIG.Use_AXI_ID {false} CONFIG.Load_Init_File {true} CONFIG.Coe_File {/../../../../../../create_ip/id_rom16x32.coe} CONFIG.Fill_Remaining_Memory_Locations {true} CONFIG.Remaining_Memory_Locations {DEADDEAD} CONFIG.Memory_Type {Simple_Dual_Port_RAM} CONFIG.Use_Byte_Write_Enable {true} CONFIG.Byte_Size {8} CONFIG.Assume_Synchronous_Clk {true} CONFIG.Write_Width_A {32} CONFIG.Write_Depth_A {1024} CONFIG.Read_Width_A {32} CONFIG.Operating_Mode_A {READ_FIRST} CONFIG.Write_Width_B {32} CONFIG.Read_Width_B {32} CONFIG.Operating_Mode_B {READ_FIRST} CONFIG.Enable_B {Use_ENB_Pin} CONFIG.Register_PortA_Output_of_Memory_Primitives {false} CONFIG.Register_PortB_Output_of_Memory_Primitives {false} CONFIG.Use_RSTB_Pin {true} CONFIG.Reset_Type {ASYNC} CONFIG.Port_A_Write_Rate {50} CONFIG.Port_B_Clock {100} CONFIG.Port_B_Enable_Rate {100}] [get_ips identifier_ip]
set_property generate_synth_checkpoint false [get_files identifier_ip.xci]
reset_target all [get_ips identifier_ip]
generate_target all [get_ips identifier_ip]

create_ip -name clk_wiz -vendor xilinx.com -library ip -version 6.0 -module_name clk_wiz_ip
set_property -dict [list CONFIG.PRIM_IN_FREQ {200.00} CONFIG.CLKOUT1_REQUESTED_OUT_FREQ {200.000} CONFIG.USE_SAFE_CLOCK_STARTUP {true} CONFIG.RESET_TYPE {ACTIVE_LOW} CONFIG.CLKIN1_JITTER_PS {50.0} CONFIG.CLKOUT1_DRIVES {BUFGCE} CONFIG.CLKOUT2_DRIVES {BUFGCE} CONFIG.CLKOUT3_DRIVES {BUFGCE} CONFIG.CLKOUT4_DRIVES {BUFGCE} CONFIG.CLKOUT5_DRIVES {BUFGCE} CONFIG.CLKOUT6_DRIVES {BUFGCE} CONFIG.CLKOUT7_DRIVES {BUFGCE} CONFIG.MMCM_CLKFBOUT_MULT_F {5.000} CONFIG.MMCM_CLKIN1_PERIOD {5.0} CONFIG.MMCM_CLKOUT0_DIVIDE_F {5.000} CONFIG.RESET_PORT {resetn} CONFIG.CLKOUT1_JITTER {98.146} CONFIG.CLKOUT1_PHASE_ERROR {89.971}] [get_ips clk_wiz_ip]
set_property generate_synth_checkpoint false [get_files clk_wiz_ip.xci]
reset_target all [get_ips clk_wiz_ip]
generate_target all [get_ips clk_wiz_ip]


create_ip -name barrier -vendor NetFPGA -library NetFPGA -module_name barrier_ip
reset_target all [get_ips barrier_ip]
generate_target all [get_ips barrier_ip]

create_ip -name axis_sim_record -vendor NetFPGA -library NetFPGA -module_name axis_sim_record_ip0
set_property -dict [list CONFIG.OUTPUT_FILE $::env(NF_DESIGN_DIR)/test/nf_interface_0_log.axi] [get_ips axis_sim_record_ip0]
reset_target all [get_ips axis_sim_record_ip0]
generate_target all [get_ips axis_sim_record_ip0]

create_ip -name axis_sim_record -vendor NetFPGA -library NetFPGA -module_name axis_sim_record_ip1
set_property -dict [list CONFIG.OUTPUT_FILE $::env(NF_DESIGN_DIR)/test/nf_interface_1_log.axi] [get_ips axis_sim_record_ip1]
reset_target all [get_ips axis_sim_record_ip1]
generate_target all [get_ips axis_sim_record_ip1]

create_ip -name axis_sim_record -vendor NetFPGA -library NetFPGA -module_name axis_sim_record_ip2
set_property -dict [list CONFIG.OUTPUT_FILE $::env(NF_DESIGN_DIR)/test/nf_interface_2_log.axi] [get_ips axis_sim_record_ip2]
reset_target all [get_ips axis_sim_record_ip2]
generate_target all [get_ips axis_sim_record_ip2]

create_ip -name axis_sim_record -vendor NetFPGA -library NetFPGA -module_name axis_sim_record_ip3
set_property -dict [list CONFIG.OUTPUT_FILE $::env(NF_DESIGN_DIR)/test/nf_interface_3_log.axi] [get_ips axis_sim_record_ip3]
reset_target all [get_ips axis_sim_record_ip3]
generate_target all [get_ips axis_sim_record_ip3]

create_ip -name axis_sim_record -vendor NetFPGA -library NetFPGA -module_name axis_sim_record_ip4
set_property -dict [list CONFIG.OUTPUT_FILE $::env(NF_DESIGN_DIR)/test/dma_0_log.axi] [get_ips axis_sim_record_ip4]
reset_target all [get_ips axis_sim_record_ip4]
generate_target all [get_ips axis_sim_record_ip4]

create_ip -name axis_sim_stim -vendor NetFPGA -library NetFPGA -module_name axis_sim_stim_ip0
set_property -dict [list CONFIG.input_file $::env(NF_DESIGN_DIR)/test/nf_interface_0_stim.axi] [get_ips axis_sim_stim_ip0]
generate_target all [get_ips axis_sim_stim_ip0]

create_ip -name axis_sim_stim -vendor NetFPGA -library NetFPGA -module_name axis_sim_stim_ip1
set_property -dict [list CONFIG.input_file $::env(NF_DESIGN_DIR)/test/nf_interface_1_stim.axi] [get_ips axis_sim_stim_ip1]
generate_target all [get_ips axis_sim_stim_ip1]

create_ip -name axis_sim_stim -vendor NetFPGA -library NetFPGA -module_name axis_sim_stim_ip2
set_property -dict [list CONFIG.input_file $::env(NF_DESIGN_DIR)/test/nf_interface_2_stim.axi] [get_ips axis_sim_stim_ip2]
generate_target all [get_ips axis_sim_stim_ip2]

create_ip -name axis_sim_stim -vendor NetFPGA -library NetFPGA -module_name axis_sim_stim_ip3
set_property -dict [list CONFIG.input_file $::env(NF_DESIGN_DIR)/test/nf_interface_3_stim.axi] [get_ips axis_sim_stim_ip3]
generate_target all [get_ips axis_sim_stim_ip3]

create_ip -name axis_sim_stim -vendor NetFPGA -library NetFPGA -module_name axis_sim_stim_ip4
set_property -dict [list CONFIG.input_file $::env(NF_DESIGN_DIR)/test/dma_0_stim.axi] [get_ips axis_sim_stim_ip4]
generate_target all [get_ips axis_sim_stim_ip4]

create_ip -name axi_sim_transactor -vendor NetFPGA -library NetFPGA -module_name axi_sim_transactor_ip
set_property -dict [list CONFIG.STIM_FILE $::env(NF_DESIGN_DIR)/test/reg_stim.axi CONFIG.EXPECT_FILE $::env(NF_DESIGN_DIR)/test/reg_expect.axi CONFIG.LOG_FILE $::env(NF_DESIGN_DIR)/test/reg_stim.log] [get_ips axi_sim_transactor_ip]
reset_target all [get_ips axi_sim_transactor_ip]
generate_target all [get_ips axi_sim_transactor_ip]

update_ip_catalog

source $::env(NF_DESIGN_DIR)/hw/tcl/control_sub_sim.tcl

read_verilog "$::env(NF_DESIGN_DIR)/hw/hdl/axi_clocking.v"
read_verilog "$::env(NF_DESIGN_DIR)/hw/hdl/nf_datapath.v"
read_verilog "$::env(NF_DESIGN_DIR)/hw/hdl/top_sim.v"
read_verilog "$::env(NF_DESIGN_DIR)/hw/hdl/top_tb.v"

update_compile_order -fileset sources_1
update_compile_order -fileset sim_1

set_property top ${sim_top} [get_filesets sim_1]
set_property include_dirs ${proj_dir} [get_filesets sim_1]
set_property simulator_language Mixed [current_project]
set_property verilog_define { {SIMULATION=1} } [get_filesets sim_1]
set_property -name xsim.more_options -value {-testplusarg TESTNAME=basic_test} -objects [get_filesets sim_1]
set_property runtime {} [get_filesets sim_1]
set_property target_simulator xsim [current_project]
set_property compxlib.xsim_compiled_library_dir {} [current_project]
set_property top_lib xil_defaultlib [get_filesets sim_1]
update_compile_order -fileset sim_1

set output [exec python $::env(NF_DESIGN_DIR)/test/${test_name}/run.py]
puts $output

set_property xsim.view {} [get_filesets sim_1]
launch_simulation -simset sim_1 -mode behavioral

# Add top level datapath IO
set nf_datapath top_tb/top_sim/nf_datapath_0/
add_wave_divider {input arbiter input signals}
add_wave $nf_datapath/s_axis_0_tdata -color blue
add_wave $nf_datapath/s_axis_0_tkeep -color blue
add_wave $nf_datapath/s_axis_0_tuser -color blue
add_wave $nf_datapath/s_axis_0_tvalid -color blue
add_wave $nf_datapath/s_axis_0_tready -color blue
add_wave $nf_datapath/s_axis_0_tlast -color blue
add_wave $nf_datapath/s_axis_1_tdata -color gold
add_wave $nf_datapath/s_axis_1_tkeep -color gold
add_wave $nf_datapath/s_axis_1_tuser -color gold
add_wave $nf_datapath/s_axis_1_tvalid -color gold
add_wave $nf_datapath/s_axis_1_tready -color gold
add_wave $nf_datapath/s_axis_1_tlast -color gold
add_wave $nf_datapath/s_axis_2_tdata -color orange
add_wave $nf_datapath/s_axis_2_tkeep -color orange
add_wave $nf_datapath/s_axis_2_tuser -color orange
add_wave $nf_datapath/s_axis_2_tvalid -color orange
add_wave $nf_datapath/s_axis_2_tready -color orange
add_wave $nf_datapath/s_axis_2_tlast -color orange
add_wave $nf_datapath/s_axis_3_tdata -color purple
add_wave $nf_datapath/s_axis_3_tkeep -color purple
add_wave $nf_datapath/s_axis_3_tuser -color purple
add_wave $nf_datapath/s_axis_3_tvalid -color purple
add_wave $nf_datapath/s_axis_3_tready -color purple
add_wave $nf_datapath/s_axis_3_tlast -color purple
add_wave $nf_datapath/s_axis_4_tdata -color cyan
add_wave $nf_datapath/s_axis_4_tkeep -color cyan
add_wave $nf_datapath/s_axis_4_tuser -color cyan
add_wave $nf_datapath/s_axis_4_tvalid -color cyan
add_wave $nf_datapath/s_axis_4_tready -color cyan
add_wave $nf_datapath/s_axis_4_tlast -color cyan

add_wave_divider {output queues output signals}
add_wave $nf_datapath/m_axis_0_tdata -color blue
add_wave $nf_datapath/m_axis_0_tkeep -color blue
add_wave $nf_datapath/m_axis_0_tuser -color blue
add_wave $nf_datapath/m_axis_0_tvalid -color blue
add_wave $nf_datapath/m_axis_0_tready -color blue
add_wave $nf_datapath/m_axis_0_tlast -color blue
add_wave $nf_datapath/m_axis_1_tdata -color gold
add_wave $nf_datapath/m_axis_1_tkeep -color gold
add_wave $nf_datapath/m_axis_1_tuser -color gold
add_wave $nf_datapath/m_axis_1_tvalid -color gold
add_wave $nf_datapath/m_axis_1_tready -color gold
add_wave $nf_datapath/m_axis_1_tlast -color gold
add_wave $nf_datapath/m_axis_2_tdata -color orange
add_wave $nf_datapath/m_axis_2_tkeep -color orange
add_wave $nf_datapath/m_axis_2_tuser -color orange
add_wave $nf_datapath/m_axis_2_tvalid -color orange
add_wave $nf_datapath/m_axis_2_tready -color orange
add_wave $nf_datapath/m_axis_2_tlast -color orange
add_wave $nf_datapath/m_axis_3_tdata -color purple
add_wave $nf_datapath/m_axis_3_tkeep -color purple
add_wave $nf_datapath/m_axis_3_tuser -color purple
add_wave $nf_datapath/m_axis_3_tvalid -color purple
add_wave $nf_datapath/m_axis_3_tready -color purple
add_wave $nf_datapath/m_axis_3_tlast -color purple
add_wave $nf_datapath/m_axis_4_tdata -color cyan
add_wave $nf_datapath/m_axis_4_tkeep -color cyan
add_wave $nf_datapath/m_axis_4_tuser -color cyan
add_wave $nf_datapath/m_axis_4_tvalid -color cyan
add_wave $nf_datapath/m_axis_4_tready -color cyan
add_wave $nf_datapath/m_axis_4_tlast -color cyan

## Add top level AXI Lite control signals to P4_SWITCH
#add_wave_divider {Top-Level SDNet Control Signals}
#add_wave top_tb/top_sim/M02_AXI_araddr
#add_wave top_tb/top_sim/M02_AXI_arprot
#add_wave top_tb/top_sim/M02_AXI_arready
#add_wave top_tb/top_sim/M02_AXI_arvalid
#add_wave top_tb/top_sim/M02_AXI_awaddr
#add_wave top_tb/top_sim/M02_AXI_awprot
#add_wave top_tb/top_sim/M02_AXI_awready
#add_wave top_tb/top_sim/M02_AXI_awvalid
#add_wave top_tb/top_sim/M02_AXI_bready
#add_wave top_tb/top_sim/M02_AXI_bresp
#add_wave top_tb/top_sim/M02_AXI_bvalid
#add_wave top_tb/top_sim/M02_AXI_rdata
#add_wave top_tb/top_sim/M02_AXI_rready
#add_wave top_tb/top_sim/M02_AXI_rresp
#add_wave top_tb/top_sim/M02_AXI_rvalid
#add_wave top_tb/top_sim/M02_AXI_wdata
#add_wave top_tb/top_sim/M02_AXI_wready
#add_wave top_tb/top_sim/M02_AXI_wstrb
#add_wave top_tb/top_sim/M02_AXI_wvalid

# Add SDNet Interface Signals
set sdnet_ip top_tb/top_sim/nf_datapath_0/nf_sume_sdnet_wrapper_1/inst/SimpleSumeSwitch_inst/
add_wave_divider {SDNet Control Interface}
add_wave top_tb/top_sim/nf_datapath_0/nf_sume_sdnet_wrapper_1/inst/internal_rst_done -color yellow
add_wave $sdnet_ip/control_S_AXI_AWADDR
add_wave $sdnet_ip/control_S_AXI_AWVALID 
add_wave $sdnet_ip/control_S_AXI_AWREADY 
add_wave $sdnet_ip/control_S_AXI_WDATA   
add_wave $sdnet_ip/control_S_AXI_WSTRB   
add_wave $sdnet_ip/control_S_AXI_WVALID  
add_wave $sdnet_ip/control_S_AXI_WREADY  
add_wave $sdnet_ip/control_S_AXI_BRESP   
add_wave $sdnet_ip/control_S_AXI_BVALID  
add_wave $sdnet_ip/control_S_AXI_BREADY  
add_wave $sdnet_ip/control_S_AXI_ARADDR  
add_wave $sdnet_ip/control_S_AXI_ARVALID 
add_wave $sdnet_ip/control_S_AXI_ARREADY 
add_wave $sdnet_ip/control_S_AXI_RDATA   
add_wave $sdnet_ip/control_S_AXI_RRESP   
add_wave $sdnet_ip/control_S_AXI_RVALID  
add_wave $sdnet_ip/control_S_AXI_RREADY  

set nf_sume_sdnet_ip top_tb/top_sim/nf_datapath_0/nf_sume_sdnet_wrapper_1/inst/
add_wave_divider {nf_sume_sdnet input interface}
add_wave $sdnet_ip/clk_lookup_rst
add_wave $sdnet_ip/clk_lookup
add_wave $nf_sume_sdnet_ip/s_axis_tdata -radix hex
add_wave $nf_sume_sdnet_ip/s_axis_tkeep -radix hex
add_wave $nf_sume_sdnet_ip/s_axis_tvalid
add_wave $nf_sume_sdnet_ip/s_axis_tready
add_wave $nf_sume_sdnet_ip/s_axis_tlast

add_wave_divider {SDNet Tuple-In}
add_wave $nf_sume_sdnet_ip/sume_tuple_in_VALID
add_wave $nf_sume_sdnet_ip/s_axis_tuser -radix hex
add_wave $nf_sume_sdnet_ip/in_pkt_len
add_wave $nf_sume_sdnet_ip/in_src_port
add_wave $nf_sume_sdnet_ip/in_dst_port

add_wave_divider {nf_sume_sdnet output interface}
add_wave $sdnet_ip/clk_lookup_rst
add_wave $sdnet_ip/clk_lookup
add_wave $nf_sume_sdnet_ip/m_axis_tdata -radix hex
add_wave $nf_sume_sdnet_ip/m_axis_tkeep -radix hex
add_wave $nf_sume_sdnet_ip/m_axis_tvalid
add_wave $nf_sume_sdnet_ip/m_axis_tready
add_wave $nf_sume_sdnet_ip/m_axis_tlast

add_wave_divider {SDNet Tuple-Out}
add_wave $nf_sume_sdnet_ip/sume_tuple_out_VALID
add_wave $nf_sume_sdnet_ip/m_axis_tuser -radix hex
add_wave $nf_sume_sdnet_ip/out_pkt_len
add_wave $nf_sume_sdnet_ip/out_src_port
add_wave $nf_sume_sdnet_ip/out_dst_port

# set const_reg_ip /top_tb/top_sim/nf_datapath_0/nf_sume_sdnet_wrapper_1/inst/SimpleSumeSwitch_inst/const_reg_rw_0/
# add_wave_divider {const reg extern signals}
# add_wave $const_reg_ip 

# add_wave_divider {const cpu reg signals}
# add_wave $const_reg_ip/const_cpu_regs_inst


run 60us
