Functional tests
---
1-simple_a_request
- This folder contains a single pcap file. Replay this file to Blister, and the DNS response will be sent back. `tcpreplay -i eth1 request_a_com.cap`

2-request_and_reply
- This folder contains a single pcap file. This pcap file contains two packets - a DNS request and a DNS response. Replay this file to blister, and the first packet will trigger a DNS response, and the second packet will be forwarded back to the origin. `tcpreplay -i eth1 from_google_dns_req_and_resp.cap`

3-dns_packets_increasing_size
- This folder contains a list of DNS requests from smallest to largest size. Note that DNS requests over ~512 bytes are recommended to be done over TCP, but for the sake of this project, UDP versions have been generated. To recreate these files, run the generate.py file within this directory. In order to test these pcap files, use 
`tcpreplay -i eth1 file.pcap`.

4-all_domain_names
- This folder contains a pcap file generator, and a script to generate a list of DNS requests and send them out of the wire immediately. `bash run_test.sh` will send out all domain names in aa.uk, ab.uk, ..., zz.uk. Using wireshark, the output packet can be captured and observed - some domains will be resolved, and others will lead to 

5-tcp_traffic
- This folder contains a stream of TCP traffic. When replaying this file with tcpreplay, we observe that the packets are forwarded as a normal switch without any corruption. `tcpreplay -i eth1 normal_tcp_requests.cap`

