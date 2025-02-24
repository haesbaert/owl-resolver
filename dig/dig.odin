/* SPDX-License-Identifier: ISC */

package main

import "base:runtime"

import "core:fmt"
import "core:io"
import "core:mem"
import "core:net"
import "core:os"
import "core:sys/posix"

import dns "../dns"

Dig_Error :: enum u32 {
	None,
	Bad_Source_Address,
	Bad_Id,
}

Error :: union #shared_nil {
	Dig_Error,
	dns.Error,
	dns.Rcode,
	io.Error,
	os.Error,
	net.Network_Error,
	net.Dial_Error,
	posix.Errno,
	runtime.Allocator_Error,
}

Query :: struct {
	name:  string,
	type:  dns.RR_Type,
	query: dns.Packet,
	reply: dns.Packet,
	sock:  net.UDP_Socket,
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

send_query :: proc(
	name: string,
	qtype: dns.RR_Type,
	ep: net.Endpoint,
	sock: net.UDP_Socket,
) -> (
	err: Error,
) {
	query, reply: dns.Packet
	src: net.Endpoint
	recvbuf: [2048]byte

	defer {
		dns.destroy_packet(&query)
		dns.destroy_packet(&reply)
	}

	query.header.id = dns.gen_id()
	query.header.set.rd = true

	query.qd = make([]dns.Question, 1) or_return
	q := &query.qd[0]
	q.type = qtype
	q.class = .IN
	dns.domain_from_ascii(name, &q.name) or_return

	query.header.qd_count = u16be(len(query.qd))

	sendbuf := dns.serialize_packet(&query) or_return
	defer delete(sendbuf)
	n := net.send_udp(sock, sendbuf, ep) or_return
	if n != len(sendbuf) {
		err = io.Error(.Short_Write)
		return
	}

	wait_reply(sock) or_return
	n, src = net.recv_udp(sock, recvbuf[:]) or_return
	if src != ep {
		err = .Bad_Source_Address
		return
	}
	dns.parse(recvbuf[:], &reply) or_return
	if query.header.id != reply.header.id {
		err = .Bad_Id
		return
	}
	err = dns.Rcode(reply.header.set.rcode)
	if err != nil {
		return
	}
	for an in reply.an {
		#partial switch rr in an.variant {
		case ^dns.RR_A:
			fmt.printf("A\t%s\n", net.to_string(net.IP4_Address(rr.addr4)))
		case ^dns.RR_AAAA:
			fmt.printf("AAAA\t%s\n", net.to_string(transmute(net.IP6_Address)(rr.addr6)))
		case ^dns.RR_MX:
			fmt.printf("MX\t%s (%v)\n", rr.exchange, rr.preference)
		}
	}

	return
}

main_ :: proc(name: string, ep: net.Endpoint) -> (err: Error) {
	sock := net.make_unbound_udp_socket(.IP4) or_return
	defer net.close(sock)

	a_err := send_query(name, .A, ep, sock)
	aaaa_err := send_query(name, .AAAA, ep, sock)
	mx_err := send_query(name, .MX, ep, sock)

	if a_err != nil {
		fmt.fprintf(os.stderr, "A\t%v\n", a_err)
	}
	if aaaa_err != nil {
		fmt.fprintf(os.stderr, "AAAA\t%v\n", aaaa_err)
	}
	if mx_err != nil {
		fmt.fprintf(os.stderr, "MX\t%v\n", mx_err)
	}

	switch {
	case a_err != nil:
		return a_err
	case aaaa_err != nil:
		return aaaa_err
	case mx_err != nil:
		return mx_err
	}

	return
}

main :: proc() {
	ep: net.Endpoint

	when ODIN_DEBUG {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, context.allocator)
		context.allocator = mem.tracking_allocator(&track)

		defer {
			if len(track.allocation_map) > 0 {
				fmt.eprintf("=== %v allocations not freed: ===\n", len(track.allocation_map))
				for _, entry in track.allocation_map {
					fmt.eprintf("- %v bytes @ %v\n", entry.size, entry.location)
				}
			}
			if len(track.bad_free_array) > 0 {
				fmt.eprintf("=== %v incorrect frees: ===\n", len(track.bad_free_array))
				for entry in track.bad_free_array {
					fmt.eprintf("- %p @ %v\n", entry.memory, entry.location)
				}
			}
			mem.tracking_allocator_destroy(&track)
		}
	}

	if len(os.args) != 3 {
		fatalx("usage: dig forward-addr name")
	}
	ep.port = 53
	ep.address = net.parse_address(os.args[1])
	if ep.address == nil {
		fatalx("invalid address %s", os.args[1])
	}

	err := main_(os.args[2], ep)
	if err != nil {
		fatal(err, "%s", os.args[2])
	}

	free_all(context.temp_allocator)
	delete(os.args, runtime.default_allocator())
}
