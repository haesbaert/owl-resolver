/* SPDX-License-Identifier: ISC */

package main

import "core:fmt"
import "core:io"
import "core:net"
import "core:os"

import dns "../dns"

Error :: union #shared_nil {
	dns.Error,
	io.Error,
	os.Error,
	net.Network_Error,
}


fatal :: proc(err: Error, s: string, args: ..any) {
	fmt.fprintf(os.stderr, s, ..args)
	fmt.fprintf(os.stderr, ": %v\n", err)

	os.exit(1)
}

fatalx :: proc(s: string, args: ..any) {
	fmt.fprintf(os.stderr, s, ..args)
	fmt.fprint(os.stderr, '\n')

	os.exit(1)
}

main :: proc() {
	sock: net.UDP_Socket
	pkt: dns.Packet
	err: Error
	wbuf: []byte
	buf: [2048]byte
	ep: net.Endpoint
	n: int

	if len(os.args) != 3 {
		fatalx("usage: dig forward-addr name")
	}
	ep.port = 53
	ep.address = net.parse_address(os.args[1])
	if ep.address == nil {
		fatalx("invalid address %s", os.args[1])
	}

	err = dns.make_simple_query(os.args[2], &pkt)
	if err != nil {
		fatal(err, "make_simple_query")
	}
	fmt.printf("--> QUERY\n%#v\n", pkt)

	wbuf, err = dns.serialize_packet(&pkt)
	if err != nil {
		fatal(err, "serialize_packet")
	}
	dns.destroy_packet(&pkt)

	sock, err = net.make_unbound_udp_socket(.IP4)
	if err != nil {
		fatal(err, "make_unbound_udp_socket")
	}

	n, err = net.send_udp(sock, wbuf, ep)
	if err != nil {
		fatal(err, "send_udp")
	}
	if n != len(wbuf) {
		fatal(io.Error(.Short_Write), "send_udp")
	}
	delete(wbuf)

	n, ep, err = net.recv_udp(sock, buf[:])
	if err != nil {
		fatal(err, "recv_udp")
	}

	err = dns.from_bytes(buf[:], &pkt)
	if err != nil {
		fatal(err, "from_bytes")
	}
	fmt.printf("--> REPLY\n%#v\n", pkt)
	dns.destroy_packet(&pkt)

	net.close(sock)
	delete(os.args)
}
