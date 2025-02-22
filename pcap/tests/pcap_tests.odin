/* SPDX-License-Identifier: ISC */

package pcap_tests

import "core:testing"
import "core:fmt"
import pcap "../"

pcap_nlmon_big :: #load("nlmon-big.pcap")
pcap_dns :: #load("dns.pcap")

count_packets :: proc(handle: ^pcap.Handle) -> (n: int) {
	for _ in pcap.packet_iterator(handle) {
		n += 1
	}
	return
}

@(test)
big_endian :: proc(t: ^testing.T) {
	handle, err := pcap.open(pcap_nlmon_big)
	num_pkt : int
	testing.expect(t, err == nil, "can't open nlmon_big")
	testing.expect(t, handle.endian == .Big)
	testing.expect(t, handle.time_fmt == .Micro)
	num_pkt = count_packets(handle)
	testing.expectf(t, num_pkt == 13, "num_pkt is %d", num_pkt)
	pcap.close(handle)
}

@(test)
little_endian :: proc(t: ^testing.T) {
	handle, err := pcap.open(pcap_dns)
	num_pkt : int
	testing.expect(t, err == nil, "can't open dns")
	testing.expect(t, handle.endian == .Little)
	testing.expect(t, handle.time_fmt == .Micro)
	num_pkt = count_packets(handle)
	testing.expectf(t, num_pkt == 38, "num_pkt is %d", num_pkt)
	pcap.close(handle)
}

@(test)
all_records :: proc(t: ^testing.T) {
	all: []pcap.Packet_Record

	handle, err := pcap.open(pcap_dns)
	testing.expect(t, err == nil, "can't open pcap_dns")
	all, err = pcap.get_packets(handle)
	testing.expect(t, err == nil)
	testing.expectf(t, len(all) == 38, "num_pkt is %d", len(all))
	pcap.destroy_packets(all)
	pcap.close(handle)
}

@(test)
reset :: proc(t: ^testing.T) {
	all_a, all_b: []pcap.Packet_Record

	handle, err := pcap.open(pcap_dns)
	testing.expect(t, err == nil, "can't open nlmon_big")
	all_a, err = pcap.get_packets(handle)
	testing.expect(t, err == nil)
	testing.expectf(t, len(all_a) == 38, "num_pkt is %d", len(all_a))
	err = pcap.reset(handle)
	testing.expect(t, err == nil)
	all_b, err = pcap.get_packets(handle)
	testing.expect(t, len(all_a) == len(all_b))
	pcap.destroy_packets(all_b)
	pcap.destroy_packets(all_a)
	pcap.close(handle)
}
