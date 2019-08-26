Here are some scripts we used to test latency and throughput.

They are highly scripted, just need a bit of installing :)

Step 0:
Put this in /root/jcw78

Step 1:

Go to setup and run ./setup_machine.sh

OK, that should be good.  For a latency test, you need three machines:

	1. Tcpreplay machine (put a PCAP file on there)
	2. NetFPGA machine (put the blister bitfile on there)
	3. HPT machine

Connect these machines as in the latency measurement setup in the documentation.

Then, run:

	1. (On the NetFPGA Machine): program the bitfile
	2. On HPT machine, start recording, run:
	cd hpt
	./record_port.sh
	filling in arguments as appropriate (You will need the two port recording version: the script will print a help when you run it)
	3. On the HPT machine, stop recording with:
	./stop_recording.sh


Throughput
===============

	1. Put this in /root/jcw78
	2. Move ../generate_scapy_packets_of_all_sizes.py to /root/p51/dns_packets
	3. go to evaluation/hpt/sizes/
	4. Edit the config there to match your machine.
	5. Go to evaluation/hpt/sizes/size_scan
	6. Edit the config there to match your machine.
	6. On your HPT machine, start a capture:
	7. On HPT machine, start recording, run:
	cd hpt
	./record_port.sh
	8. Run ./dns_run.sh
	9. On the HPT machine, stop recording with:
	./stop_recording.sh
