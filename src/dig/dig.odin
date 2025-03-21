/* SPDX-License-Identifier: ISC */

package main

import "base:runtime"

import "core:bufio"
import "core:encoding/endian"
import "core:fmt"
import "core:io"
import "core:mem"
import "core:net"
import "core:os"
import "core:strings"
import "core:sys/posix"

import dns "../dns"

force_tcp: bool

Dig_Error :: enum u32 {
	None,
	Bad_Source_Address,
	Bad_Id,
	Bad_Resolv,
}

Error :: union #shared_nil {
	Dig_Error,
	dns.Dns_Error,		/* XXX fixme */
	dns.Error,
	dns.Rcode,
	io.Error,
	net.Dial_Error,
	net.Network_Error,
	os.Error,
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

usage :: proc() {
	fatalx("usage: dig [-T] [-r resolver] name")
}

wait_readable :: proc(sock: net.Any_Socket) -> (err: Error) {
	pollfd: posix.pollfd
	buffer: [2048]byte

	switch t in sock {
	case net.UDP_Socket:
		pollfd.fd = posix.FD(t)
	case net.TCP_Socket:
		pollfd.fd = posix.FD(t)
	}
	pollfd.events = {.IN}

	if r := posix.poll(&pollfd, 1, 5000); r == -1 {
		return posix.errno()
	}
	if .IN not_in pollfd.revents {
		err = net.Dial_Error(.Timeout) /* XXX */
	}

	return
}

Resolv_Conf :: struct {
	nameservers: []net.Address,
	search:      string,
	options:     []string,
}

parse_resolv_dot_conf :: proc(path := "/etc/resolv.conf") -> (rc: Resolv_Conf, err: Error) {
	r: bufio.Reader
	fd: os.Handle
	buffer: [1024]byte
	line: string
	nameservers: [dynamic]net.Address
	search: string
	options: [dynamic]string

	fd = os.open(path) or_return
	defer os.close(fd)
	bufio.reader_init_with_buf(&r, os.stream_from_handle(fd), buffer[:])
	defer bufio.reader_destroy(&r)

	defer if err != nil {
		delete(nameservers)
		delete(search)
		for opt in options {
			delete(opt)
		}
		delete(options)
	}

	for {
		line, err = bufio.reader_read_string(&r, '\n')
		if err == io.Error.EOF {
			err = nil
			break
		} else if err != nil {
			return
		}
		defer delete(line)
		line = strings.trim_right(line, "\n")

		switch {
		case strings.starts_with(line, "nameserver "):
			addr := net.parse_address(line[len("nameserver "):])
			if addr == nil {
				err = Dig_Error.Bad_Resolv
				return
			}
			_ = append(&nameservers, addr) or_return
		case strings.starts_with(line, "search "):
			search = line[len("search "):]
			if len(search) == 0 {
				err = Dig_Error.Bad_Resolv
				return
			}
			search = strings.clone(search) or_return
		case strings.starts_with(line, "options "):
			line2 := line[len("options "):]
			for opt in strings.split_iterator(&line2, " \t") {
				o := strings.clone(opt) or_return
				_ = append(&options, o) or_return
			}

		}
	}

	rc.nameservers = nameservers[:]
	rc.search = search
	rc.options = options[:]

	return
}

destroy_resolv_conf :: proc(rc: ^Resolv_Conf) {
	for opt in rc.options {
		delete(opt)
	}
	delete(rc.options)
	delete(rc.search)
	delete(rc.nameservers)
}

query_via_udp :: proc(ep: net.Endpoint, query, reply: ^dns.Packet) -> (err: Error) {
	sock: net.UDP_Socket
	recvbuf: [2048]byte = ---
	src: net.Endpoint

	if force_tcp {
		return dns.Dns_Error.Truncated
	}

	sendbuf := dns.serialize_packet(query) or_return
	defer delete(sendbuf)

	sock = net.make_unbound_udp_socket(.IP4) or_return
	defer net.close(sock)

	n := net.send_udp(sock, sendbuf, ep) or_return
	if n != len(sendbuf) {
		err = io.Error(.Short_Write)
		return
	}

	wait_readable(sock) or_return

	n, src = net.recv_udp(sock, recvbuf[:]) or_return
	if src != ep {
		err = .Bad_Source_Address
		return
	}
	dns.parse_packet(recvbuf[:n], reply) or_return

	return
}

query_via_tcp :: proc(ep: net.Endpoint, query, reply: ^dns.Packet) -> (err: Error) {
	sock: net.TCP_Socket
	recvbuf: [2048]byte = ---
	iov: [2]posix.iovec
	pkt_len: u16be

	sendbuf := dns.serialize_packet(query) or_return
	defer delete(sendbuf)

	sock = net.dial_tcp(ep) or_return
	defer net.close(sock)

	/* net doesn't expose iovecs, so we do it ourselves */
	pkt_len = u16be(len(sendbuf)) /* XXX deal with overflow */
	iov[0].iov_base = &pkt_len
	iov[0].iov_len = size_of(pkt_len)
	iov[1].iov_base = raw_data(sendbuf)
	iov[1].iov_len = len(sendbuf)

	n := posix.writev(posix.FD(sock), raw_data(iov[:]), 2)
	switch {
	case n == -1:
		return posix.errno()
	case n < 2:
		/* Bail if we couldn't write iov0, too much work to handle */
		return io.Error.Short_Write
	case n != len(sendbuf) + 2:
		written := n
		for written < len(sendbuf) + 2 {
			written += net.send(sock, sendbuf[written:]) or_return
		}
	}

	read := 0
	for read < 2 {
		wait_readable(sock) or_return
		n = net.recv_tcp(sock, recvbuf[read:]) or_return
		if n == 0 {
			return io.Error.Unexpected_EOF
		}
		read += n
	}

	to_read, ok := endian.get_u16(recvbuf[0:2], .Big)
	if !ok {
		return io.Error.Short_Buffer
	}
	for read < int(to_read) + 2 {
		wait_readable(sock) or_return
		n = net.recv_tcp(sock, recvbuf[read:]) or_return
		if n == 0 {
			return io.Error.Unexpected_EOF
		}
	}
	assert(read == int(to_read) + 2)
	dns.parse_packet(recvbuf[2:][:to_read], reply) or_return

	return
}

send_query :: proc(name: string, qtype: dns.RR_Type, ep: net.Endpoint) -> (err: Error) {
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

	err = query_via_udp(ep, &query, &reply)
	switch err {
	case nil:
		break
	case dns.Dns_Error.Truncated:
		dns.destroy_packet(&reply)
		reply = {}
		query_via_tcp(ep, &query, &reply) or_return
	case:
		return
	}

	if query.header.id != reply.header.id {
		err = .Bad_Id
		return
	}
	err = dns.Rcode(reply.header.set.rcode)
	if err != nil {
		return
	}
	for an in reply.an {
		if !dns.domain_equal(q.name, an.rr_set.name) {
			continue
		}

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

main_ :: proc(oname: string, rc: ^Resolv_Conf) -> (err: Error) {
	ep: net.Endpoint
	name: string

	if len(rc.nameservers) == 0 {
		return .Bad_Resolv
	}

	/* If there are no dots, append search */
	if dot := strings.index_byte(oname, '.'); dot == -1 && rc.search != "" {
		name = strings.concatenate([]string{oname, ".", rc.search}) or_return
	} else {
		name = oname
	}
	defer if name != oname {
		delete(name)
	}

	ep.address = rc.nameservers[0]
	ep.port = 53
	a_err := send_query(name, .A, ep)
	aaaa_err := send_query(name, .AAAA, ep)
	mx_err := send_query(name, .MX, ep)

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
	resolver: net.Address
	rc: Resolv_Conf
	err: Error

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

	arg_loop: for {
		c := posix.getopt(i32(len(runtime.args__)), raw_data(runtime.args__), "r:T")
		switch c {
		case 'r':
			resolver = net.parse_address(string(posix.optarg))
			if resolver == nil {
				usage()
			}
		case 'T':
			force_tcp = true
		case -1:
			break arg_loop
		case:
			usage()
		}
	}

	pos_args := runtime.args__[posix.optind:]

	if len(pos_args) != 1 {
		usage()
	}

	rc, err = parse_resolv_dot_conf()
	if err != nil {
		fatal(err, "")
	}
	defer destroy_resolv_conf(&rc)

	/* Overwrite nameserver with -r */
	if resolver != nil {
		delete(rc.nameservers)
		rc.nameservers, err = make([]net.Address, 1)
		if err != nil {
			fatal(err, "")
		}
		rc.nameservers[0] = resolver
	}

	err = main_(string(pos_args[0]), &rc)
	if err != nil {
		fatal(err, "%s", pos_args[0])
	}

	free_all(context.temp_allocator)
}
