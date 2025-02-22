/* SPDX-License-Identifier: ISC */

package dns_tests

import "core:bytes"
import "core:fmt"
import "core:io"
import "core:strings"
import "core:testing"

import dns "../dns"
import pcap "../pcap"

pcap_dns :: #load("dns.pcap")
pcap_zlip_1 :: #load("zlip-1.pcap")
pcap_zlip_2 :: #load("zlip-2.pcap")
pcap_zlip_3 :: #load("zlip-3.pcap")

expect :: testing.expect
expectf :: testing.expectf

@(test)
parsing :: proc(t: ^testing.T) {
	do_parsing(t, pcap_dns)
}

do_parsing :: proc(t: ^testing.T, buf: []byte) {
	pkt: dns.Packet
	pcap_pkt: pcap.Packet_Record

	pcap_pkts, pcap_err := pcap.get_packets(buf)
	expectf(t, pcap_err == nil, "%v", pcap_err)
	defer pcap.destroy_packets(pcap_pkts)
	expect(t, len(pcap_pkts) > 0)

	processed := 0
	for pcap_pkt, i in pcap_pkts {
		dns_err := dns.parse(pcap_pkt.data[42:], &pkt)
		expectf(t, dns_err == nil, "%v", dns_err)
		check_pkt_nr(t, &pkt, i + 1) /* i + 1 matches the "No." column in wireshark */
		dns.destroy_packet(&pkt)
		processed += 1
	}

	fmt.println("XXXXX", processed)
}

domain_equal :: proc {
	domain_equal_string,
	domain_equal_domain,
}

domain_equal_domain :: proc(da, db: dns.Domain_Name) -> bool {
	if len(da) != len(db) {
		return false
	}
	for d, i in da {
		if !bytes.equal(d, db[i]) {
			return false
		}
	}

	return true
}

domain_equal_string :: proc(d: dns.Domain_Name, s: string) -> bool {
	i: int
	s := s

	for l in strings.split_by_byte_iterator(&s, '.') {
		if i == len(d) {
			return false
		}
		if l != string(d[i]) {
			return false
		}
		i += 1
	}

	return len(d) == i
}

check_pkt_nr :: proc(t: ^testing.T, pkt: ^dns.Packet, nr: int) {
	/* q: dns.Question */

	expect(t, pkt.header.qd_count == 1)

	switch nr {
	case 1:
		expect(t, pkt.header.id == 0x1032)
		expect(t, pkt.header.set == dns.Packet_Header_Set{rd = true})
		q := pkt.qd[0]
		expect(t, q.class == .IN)
		expect(t, q.type == .TXT)
		expect(t, domain_equal(q.name, "google.com"))
	case 2:
		expect(t, pkt.header.id == 0x1032)
		expect(t, pkt.header.set == dns.Packet_Header_Set{qr = true, rd = true, ra = true})
		q := pkt.qd[0]
		expect(t, q.class == .IN)
		expect(t, q.type == .TXT)
		expect(t, domain_equal(q.name, "google.com"))
		an := pkt.an[0]
		expect(t, q.class == an.rr_set.class)
		expect(t, q.type == an.rr_set.type)
		expect(t, domain_equal(q.name, an.rr_set.name))
		expect(t, domain_equal(an.rr_set.name, "google.com"))
		txt, ok := an.variant.(^dns.RR_TXT)
		expect(t, ok, "not txt")
		expect(t, string(txt.data) == "v=spf1 ptr ?all")
	}
}

@(test)
zlip_1 :: proc(t: ^testing.T) {
	do_zlip(t, pcap_zlip_1)
}

@(test)
zlip_2 :: proc(t: ^testing.T) {
	do_zlip(t, pcap_zlip_2)
}

@(test)
zlip_3 :: proc(t: ^testing.T) {
	do_zlip(t, pcap_zlip_3)
}

do_zlip :: proc(t: ^testing.T, zlip: []byte) {
	pkt: dns.Packet
	pcap_pkt: pcap.Packet_Record

	handle, err := pcap.open(zlip)
	expect(t, err == nil)
	pcap_pkt, err = pcap.next_packet(handle)
	expect(t, err == nil)

	dns_err := dns.parse(pcap_pkt.data[42:], &pkt)
	expect(t, dns_err == .Bad_Label)
	pcap.close(handle)
}
