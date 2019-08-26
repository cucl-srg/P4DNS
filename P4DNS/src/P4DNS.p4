#include <core.p4>
#include <sume_switch.p4>

// How many bits fit in the query name.
#define QNAME_LENGTH 56
// How many bits we can return as a reponse.
#define DNS_RESPONSE_SIZE 128
// We can only send 256 bits to the CPU per packet.
// 64 are already taken with the Ethernet address for the learning
// switch.  I think we could take that down to 48 if this is a limit.
#define BITS_USED_FOR_DIGEST_FLAGS 8
#define BITS_USED_FOR_PORT_ID 8
#define IP_ADDR_LENGTH 32
#define DNS_TTL 32
#define UNUSED_DIGEST_BITS_COMPUTED 256 - 64 - BITS_USED_FOR_DIGEST_FLAGS - BITS_USED_FOR_PORT_ID
#if UNUSED_DIGEST_BITS_COMPUTED < 0
#error "Unused digest bits must be greater than or equal to 0"
#endif
// The preprocessor can't compute, so this actually needs to be done manually.
#define UNUSED_DIGEST_BITS 176
#if UNUSED_DIGEST_BITS != UNUSED_DIGEST_BITS_COMPUTED
#error "UNUSED_DIGEST_BITS must be updated whenever any lengths are updated"
#error "Also make sure to update sss_digest_header.py"
#endif

#define CPU_PORTS 8w0b10101010

#define IS_DNS 1
#define IS_DNS_RESPONSE 2
#define RECURSION_REQUESTED 4
#define FORWARDING_ENTRY 8

typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;
typedef bit<128> IPv6Address;

header ethernet_h {
    MacAddress dst;
    MacAddress src;
    bit<16> etherType; 
}
header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> tos;
    bit<16> len;
    bit<16> id;
    bit<3> flags;
    bit<13> frag;
    bit<8> ttl;
    bit<8> proto;
    bit<16> chksum;
    IPv4Address src;
    IPv4Address dst; 
}
header ipv6_h {
    bit<4> version;
    bit<8> tc;
    bit<20> fl;
    bit<16> plen;
    bit<8> nh;
    bit<8> hl;
    IPv6Address src;
    IPv6Address dst; 
}
header tcp_h {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq;
    bit<32> ack;
    bit<4> dataofs;
    bit<4> reserved;
    bit<8> flags;
    bit<16> window;
    bit<16> chksum;
    bit<16> urgptr; 
}
header udp_h {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> chksum; 
}

header dns_question_record_h {
    bit<QNAME_LENGTH> dns_qname;
    bit<16> qtype;
    bit<16> qclass;
}

header dns_question_record_h_48 {
	bit<48> dns_qname;
	bit<16> qtype;
	bit<16> qclass;
}

header dns_h {
    bit<16> id;
    bit<1> is_response;
    bit<4> opcode;
    bit<1> auth_answer;
    bit<1> trunc;
    bit<1> recur_desired;
    bit<1> recur_avail;
    bit<1> reserved;
    bit<1> authentic_data;
    bit<1> checking_disabled;
    bit<4> resp_code;
    bit<16> q_count;
    bit<16> answer_count;
    bit<16> auth_rec;
    bit<16> addn_rec;
}

struct dns_query {
    dns_h dns_header;
    dns_question_record_h question;
}

header dns_response_h {
    bit<DNS_RESPONSE_SIZE> answer;
}

// List of all recognized headers
struct Parsed_packet { 
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp; 
    dns_query dns;
    dns_response_h dns_response_fields;
	dns_question_record_h_48 question_48;
}
// digest data to send to cpu if desired.  Note that everything must be a
// multiple of 8 bits or scapy can't process it.
struct digest_data_t {
    #if UNUSED_DIGEST_BITS != 0
    bit<UNUSED_DIGEST_BITS> unused;
    #endif
    // These bits tell the control plane what
    // to do in addition to updating the ethernet tables.
    bit<64> eth_src_addr;  // 64 bits so we can use the LELongField type for scapy
    bit<8> flags;
    port_t src_port;
}

// user defined metadata: can be used to share information between
// TopParser, TopPipe, and TopDeparser 
struct user_metadata_t {
    bit<1> do_dns;
    bit<1> recur_desired;
    bit<1> response_set;
	bit<1> is_dns;
	bit<1> is_ip;
    bit<3>  unused;
}

@Xilinx_MaxLatency(3)
@Xilinx_ControlWidth(0)
extern void compute_ip_chksum(in bit<4> version, 
                         in bit<4> ihl,
                         in bit<8> tos,
                         in bit<16> totalLen,
                         in bit<16> identification,
                         in bit<3> flags,
                         in bit<13> fragOffset,
                         in bit<8> ttl,
                         in bit<8> protocol,
                         in bit<16> hdrChecksum,
                         in bit<32> srcAddr,
                         in bit<32> dstAddr,
                         out bit<16> result);

// parsers
@Xilinx_MaxPacketRegion(16384)
parser TopParser(packet_in pkt,
           out Parsed_packet p,
           out user_metadata_t user_metadata,
           out digest_data_t digest_data,
           inout sume_metadata_t sume_metadata) {
    state start {
        pkt.extract(p.ethernet);
        // These are set appropriately in the TopPipe.
        user_metadata.do_dns = 0;
        user_metadata.recur_desired = 0;
        user_metadata.response_set = 0;
		user_metadata.is_dns = 0;
		user_metadata.is_ip = 0;

        digest_data.flags = 0;
        digest_data.src_port = 0;
        digest_data.eth_src_addr = 0;

        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }

	state parse_ip {
        pkt.extract(p.ipv4);

		user_metadata.is_ip = 1;
		transition select(p.ipv4.proto) {
			17: parse_udp;
			default: accept;
		}
	}

	state parse_udp {
        pkt.extract(p.udp);

		transition select(p.udp.dport == 53 || p.udp.sport == 53) {
			true: parse_dns_header;
			false: accept;
		}
	}

	state parse_dns_header {
        pkt.extract(p.dns.dns_header);
		user_metadata.is_dns = 1;

		transition select(p.dns.dns_header.q_count) {
			1: select_dns_length;
			default: accept;
		}
	}

	state select_dns_length {
		transition select(p.ipv4.len) {
			51: parse_dns_question_56;
			50: parse_dns_question_48;
			default: accept;
		}
	}

	#if QNAME_LENGTH != 56
	#error "Qname means the states need to be updated maybe."
	#endif
	state parse_dns_question_56 {
        pkt.extract(p.dns.question);
		transition accept;
	}

	state parse_dns_question_48 {
		pkt.extract(p.question_48);
		transition accept;
	}
}

control TopPipe(inout Parsed_packet headers,
                inout user_metadata_t user_metadata, 
                inout digest_data_t digest_data, 
                inout sume_metadata_t sume_metadata) {

    action set_output_port(port_t port) {
        sume_metadata.dst_port = sume_metadata.dst_port | port;
    }

    table forward {
        key = { headers.ethernet.dst: exact; }

        actions = {
            set_output_port;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    action set_broadcast(port_t port) {
        sume_metadata.dst_port = sume_metadata.dst_port | port;
    }

    table broadcast {
        key = { sume_metadata.src_port: exact; }

        actions = {
            set_broadcast;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    table smac {
        key = { headers.ethernet.src: exact; }

        actions = {
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    action dma_send_to_control() {
        sume_metadata.dst_port = sume_metadata.dst_port | 8w0b00000010;
		sume_metadata.send_dig_to_cpu = 1;
    }

    action dns_dig_send_to_control() {
		// It would be better to send this as a digest.  However,
		// because we can't expand our parser and still close timing,
		// we can't process the DNS response header.
		// (Without going off the end of a DNS request packet).
		// So, we have to send the whole packet via DMA to be processed..
        sume_metadata.dst_port = sume_metadata.dst_port | 8w0b00000010;
		sume_metadata.send_dig_to_cpu = 1;
    }

    action mac_dig_send_to_control() {
        digest_data.flags = digest_data.flags | FORWARDING_ENTRY;
        digest_data.src_port = sume_metadata.src_port;
        digest_data.eth_src_addr = 16w0 ++ headers.ethernet.src;
        sume_metadata.send_dig_to_cpu = 1;
    }

    action NoDNSMatch() {
        user_metadata.response_set = 0;
    }

    action DNSMatch(bit<DNS_RESPONSE_SIZE> answer) {
        // Flip the sender and receiver addresses:
        bit<48> tmpEther = headers.ethernet.src;
        headers.ethernet.src = headers.ethernet.dst;
        headers.ethernet.dst = tmpEther;

        // Do the IPv4 swap:
        bit<32> tmpIpv4Addr = headers.ipv4.src;
        headers.ipv4.src = headers.ipv4.dst;
        headers.ipv4.dst = tmpIpv4Addr;
        headers.ipv4.len = headers.ipv4.len + DNS_RESPONSE_SIZE / 8;


        bit<16> tmpPort = headers.udp.sport;
        headers.udp.sport = headers.udp.dport;
        headers.udp.dport = tmpPort;
        // TODO -- Recalculate the UDP checksum.  For now, set it to zero.
        // Zero disables the UDP checksum.
        headers.udp.chksum = 0;
		headers.udp.len = headers.udp.len + DNS_RESPONSE_SIZE / 8;

        headers.dns.dns_header.is_response = 1;
        headers.dns.dns_header.opcode = 0;
        headers.dns.dns_header.answer_count = 1;
        headers.dns.dns_header.resp_code = 0;
        headers.dns_response_fields = {answer};

        user_metadata.response_set = 1;

        headers.dns_response_fields.setValid();
    }

    table dns {
        key = { headers.dns.question.dns_qname: exact; }
        
        actions = {
            DNSMatch;
            NoDNSMatch;
        }

        size = 64;

        default_action = NoDNSMatch;
    }

    apply {
		if ((headers.ipv4.isValid() && headers.ipv4.len == 50) ||
			headers.question_48.isValid()) {
			headers.dns.question.dns_qname = headers.question_48.dns_qname ++ 8w0;
			headers.dns.question.qtype = headers.question_48.qtype;
			headers.dns.question.qclass = headers.question_48.qclass;

			headers.dns.question.setValid();
		}

        bool to_control_only = false;
        bool came_from_control = (sume_metadata.src_port & CPU_PORTS) > 0;
        if (user_metadata.is_dns == 1) {
            user_metadata.do_dns = (bit) (user_metadata.is_dns == 1 && headers.dns.dns_header.is_response == 0 && headers.dns.dns_header.q_count == 1 && headers.dns.dns_header.answer_count == 0 && headers.dns.question.qtype == 1 && headers.dns.question.qclass == 1);

            // This will be set to true if we match the appropriate parts.
            user_metadata.response_set = (bit) (headers.dns.dns_header.is_response == 1);
            
            // Make sure that the response settings aren't triggered.
            // The are set in the dns table if required.

            // Try to perform DNS work.
            if (user_metadata.do_dns == 1) {
                user_metadata.recur_desired = (bit) (headers.dns.dns_header.recur_desired == 1);

                // If we miss the table and requested recursion, then pass on to the control
                // plane.
                if (!dns.apply().hit && user_metadata.recur_desired == 1 && !came_from_control) {
                    // This packet will be held in the control plane until recursion finishes.
                    // Do not send it out with the switch functionality
                    dma_send_to_control();
                    to_control_only = true;
                }
            } else if (user_metadata.response_set == 1 && !came_from_control) {
                // Send to control as before.  In this case, we will send the packet
                // anyway.
                dns_dig_send_to_control();
            }
        }
        
        if (!to_control_only) {
            // try to forward based on destination Ethernet address
            if (!forward.apply().hit) {
                // miss in forwarding table
                broadcast.apply();
            }

            /* // check if src Ethernet address is in the forwarding database */
            if (!smac.apply().hit && !came_from_control) {
                // unknown source MAC address
                mac_dig_send_to_control();
            }
	}

	if (user_metadata.is_ip == 1) {
            bit<16> result;
            headers.ipv4.chksum = 0;

            compute_ip_chksum(headers.ipv4.version, 
                                headers.ipv4.ihl,
                                headers.ipv4.tos,
                                headers.ipv4.len,
                                headers.ipv4.id,
                                headers.ipv4.flags,
                                headers.ipv4.frag,
                                headers.ipv4.ttl,
                                headers.ipv4.proto,
                                headers.ipv4.chksum,
                                headers.ipv4.src,
                                headers.ipv4.dst,
                                result);
            headers.ipv4.chksum = result;
	}

	if (headers.question_48.isValid()) {
		// If we parsed a 48 bit long DNS name, then we shouldn't emit
		// the 56 bit long DNS names.
		headers.dns.question.setInvalid();
	}
	}
}

// Deparser Implementation
@Xilinx_MaxPacketRegion(16384)
control TopDeparser(packet_out b,
                    in Parsed_packet p,
                    in user_metadata_t user_metadata,
                    inout digest_data_t digest_data,
                    inout sume_metadata_t sume_metadata) { 
    apply {
        b.emit(p.ethernet);
        b.emit(p.ipv4);
        b.emit(p.udp);
        b.emit(p.dns.dns_header);
		// Only one of these can ever be valid at once.  See the end of
		// the top pipe.
        b.emit(p.dns.question);
		b.emit(p.question_48);
        b.emit(p.dns_response_fields);
    }
}

// Instantiate the switch
SimpleSumeSwitch(TopParser(), TopPipe(), TopDeparser()) main;
