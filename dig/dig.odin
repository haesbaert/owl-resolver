/* SPDX-License-Identifier: ISC */

package main

import "base:runtime"

import "core:fmt"
import "core:io"
import "core:net"
import "core:os"
import "core:sys/posix"

import dns "../dns"

Error :: union #shared_nil {
	dns.Error,
	io.Error,
	os.Error,
	net.Network_Error,
	net.Dial_Error,
	posix.Errno,
	runtime.Allocator_Error,
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

wait_reply :: proc(sock: net.UDP_Socket) -> (err: Error) {
	pollfd: posix.pollfd
	buffer: [2048]byte

	pollfd.fd = posix.FD(sock)
	pollfd.events = {.IN}

	if r := posix.poll(&pollfd, 1, 5000); r == -1 {
		return posix.errno()
	}
	if .IN not_in pollfd.revents {
		err = net.Dial_Error(.Timeout) /* XXX */
	}

	return
}


make_query :: proc(name: string, qtype: dns.RR_Type, pkt: ^dns.Packet) -> (err: Error) {
	defer if err != nil {
		dns.destroy_packet(pkt)
	}

	pkt.header.id = dns.gen_id()
	pkt.header.set.rd = true

	pkt.qd = make([]dns.Question, 1) or_return
	q := &pkt.qd[0]
	q.type = qtype
	q.class = .IN
	dns.domain_from_ascii(name, &q.name) or_return

	pkt.header.qd_count = u16be(len(pkt.qd))

	return
}

main :: proc() {
	sock: net.UDP_Socket
	pkt: dns.Packet
	err: Error
	wbuf: []byte
	buf: [2048]byte
	ep, ep2: net.Endpoint
	n: int

	if len(os.args) != 3 {
		fatalx("usage: dig forward-addr name")
	}
	ep.port = 53
	ep.address = net.parse_address(os.args[1])
	if ep.address == nil {
		fatalx("invalid address %s", os.args[1])
	}

	err = make_query(os.args[2], .A, &pkt)
	if err != nil {
		fatal(err, "make_simple_query")
	}
	/* fmt.printf("--> QUERY\n%#v\n", pkt) */

	wbuf, err = dns.serialize_packet(&pkt)
	if err != nil {
		fatal(err, "serialize_packet")
	}
	xid := pkt.header.id
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

	err = wait_reply(sock)
	if err != nil {
		fatal(err, "wait_reply")
	}

	n, ep, err = net.recv_udp(sock, buf[:])
	if err != nil {
		fatal(err, "recv_udp")
	}
	if ep != ep2 {
		fatalx("bad src address")
	}

	err = dns.from_bytes(buf[:], &pkt)
	if err != nil {
		fatal(err, "from_bytes")
	}
	/* fmt.printf("--> REPLY\n%#v\n", pkt) */

	if xid != pkt.header.id {
		fatalx("bad xid")
	}
	if len(pkt.an) == 0 {
		fatalx("no answer")
	}
	for an in pkt.an {
		#partial switch rr in an.variant {
		case ^dns.RR_A:
			/* XXX temp allocator */
			fmt.printf("%s\n", net.to_string(net.IP4_Address(rr.addr4)))
		}
	}

	dns.destroy_packet(&pkt)
	net.close(sock)
	delete(os.args)
}
