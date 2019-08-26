import matplotlib.pyplot as plt
import numpy as np
from extract_latency_from_csv import extract_latency


def draw_box_and_whisker(data, labels, title, xlab, ylab, filename):
    print data[0] == data[1]
    plt.clf()

    plt.boxplot(data, labels=labels, whis=[0,100])
    plt.title(title)
    plt.xlabel(xlab)
    plt.ylabel(ylab)
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig(filename)
    plt.show()


def draw_cdf(data, labels, title, xlab, ylab, filename):
    plt.clf()

    plt.hist(data, cumulative=True, normed=True, bins=1000, label=labels, histtype='step')
    plt.title(title)
    plt.xlabel(xlab)
    plt.ylabel(ylab)
    plt.ylim([0, 0.999])
    plt.xlim([0, 220])
    plt.legend()
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig(filename)
    plt.show()


def draw_bar(data, labels, title, xlab, ylab, filename):
    plt.bar(range(1, 4), data)
    plt.title(title)
    plt.legend()
    plt.xlabel(xlab)
    plt.ylabel(ylab)
    plt.xticks(range(1, 4), labels, rotation=90)
    plt.tight_layout()
    plt.savefig(filename)
    plt.show()


if __name__ == "__main__":
    # Get all the delays

    _, p4dns_hit_50 = extract_latency('./p4dns_hit_size_50.csv', threshold=1000)
    _, p4dns_hit_51 = extract_latency('./p4dns_hit_size_51.csv')

    _, learning_switch_50 = extract_latency('./learning_switch_latency_size_50.csv')
    _, learning_switch_51 = extract_latency('./learning_switch_latency_size_51.csv')

    _, nsd_latency_51 = extract_latency('./nsd_size_51_hit_dns.csv')
    print nsd_latency_51

    _, no_dns_51 = extract_latency('./p4dns_non_dns_size_51.csv')

    # Calculate some synthetic numbers representing the 'extra' latency our features add.
    p4dns_extra_latency = np.array(p4dns_hit_51) - np.array(learning_switch_51)

    # We don't have all the emu data.  So just draw this for what we have.  Fool pyplot into
    # picking the iqr and medians as desired.
    emu_data = [1.82, 1.82, 1.82, 1.82, 1.86, 1.86]
 
    draw_box_and_whisker([p4dns_hit_50, p4dns_hit_51], ["64 Byte DNS Request", "65 Byte DNS Request"], "Latency of DNS Cache Hits", "Packet Size (B)", "Latency (us)", "p4dns_cache_hit_latency.eps")
    draw_box_and_whisker([learning_switch_50, learning_switch_51], ["64 Byte Packet", "65 Byte Packet"], "Switch Latency", "Packet Size (B)", "Latency (us)", "ls_64_65_latency.eps")
    draw_box_and_whisker([p4dns_hit_51, no_dns_51, learning_switch_51, emu_data, p4dns_extra_latency], ["Blister: 65 Byte DNS Request", "Blister: Non-DNS Packet", "Learning Switch: 65 Byte Packet", "Emu", "Blister DNS Processing Time"], "Latency Under Different Conditions", "", "Latency (us)", "latency_comparison.eps")
    draw_box_and_whisker([p4dns_hit_50, nsd_latency_51], ["Blister: 65 Byte DNS Request", "NSD: 65 Byte DNS Request"], "Latency of DNS Cache Hits", "Packet Size (B)", "Latency (us)", "blister_vs_nsd.eps")
    draw_cdf([p4dns_hit_50, nsd_latency_51], ["Blister", "NSD"], "CDF of Latency", "Latency (us)", "CDF",  "blister_vs_nsd_cdf.eps")
    # The  NSD throughput and the EMU throughput are taken from the Emu poster.
    # The Blister throughput is taken from wireshark of the one million requests.pcap
    # file.
    draw_bar([877577 / (42.883531870 - 42.809814905),  226000, 1176000], ["Blister", "NSD", "Emu"], "Throughput of DNS Servers", "DNS Server", "Throughput (Queries per Second)", "blister_nds_emu_throughput.eps")
