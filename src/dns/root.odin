/* SPDX-License-Identifier: ISC */

package dns

import "core:net"
import "core:fmt"
import "core:strings"

Root_Server :: struct {
	dname: string,
	addr4: net.IP4_Address,
	addr6: net.IP6_Address,
}

root_servers: [13]Root_Server

@(private)
parse_root :: proc(dname: string, s4: string, s6: string) -> Root_Server {
	addr4, ok4 := net.parse_ip4_address(s4)
	addr6, ok6 := net.parse_ip6_address(s6)
	ensure(ok4)
	ensure(ok6)

	return Root_Server{dname, addr4, addr6}
}

@(init, private)
build :: proc() {
	// Verisign, Inc.
	root_servers[0] = parse_root("a.root-servers.net", "198.41.0.4", "2001:503:ba3e::2:30")
	// University of Southern California,Information Sciences Institute
	root_servers[1] = parse_root("b.root-servers.net", "170.247.170.2", "2801:1b8:10::b")
	// Cogent Communications
	root_servers[2] = parse_root("c.root-servers.net", "192.33.4.12", "2001:500:2::c")
	// University of Maryland
	root_servers[3] = parse_root("d.root-servers.net", "199.7.91.13", "2001:500:2d::d")
	// NASA (Ames Research Center)
	root_servers[4] = parse_root("e.root-servers.net", "192.203.230.10", "2001:500:a8::e")
	// Internet Systems Consortium, Inc.
	root_servers[5] = parse_root("f.root-servers.net", "192.5.5.241", "2001:500:2f::f")
	// US Department of Defense (NIC)
	root_servers[6] = parse_root("g.root-servers.net", "192.112.36.4", "2001:500:12::d0d")
	// US Army (Research Lab)
	root_servers[7] = parse_root("h.root-servers.net", "198.97.190.53", "2001:500:1::53")
	// Netnod
	root_servers[8] = parse_root("i.root-servers.net", "192.36.148.17", "2001:7fe::53")
	// Verisign, Inc.
	root_servers[9] = parse_root("j.root-servers.net", "192.58.128.30", "2001:503:c27::2:30")
	// RIPE NCC
	root_servers[10] = parse_root("k.root-servers.net", "193.0.14.129", "2001:7fd::1")
	// ICANN
	root_servers[11] = parse_root("l.root-servers.net", "199.7.83.42", "2001:500:9f::42")
	// WIDE Project
	root_servers[12] = parse_root("m.root-servers.net", "202.12.27.33", "2001:dc3::35")
}
