/* SPDX-License-Identifier: ISC */

package dns

import "base:runtime"
import "core:bytes"
import "core:crypto"
import "core:encoding/endian"
import "core:fmt"
import "core:io"
import "core:mem"
import "core:strings"

parse :: proc {
	parse_packet,
	from_bytes,
}

parse_ptr_type :: proc(r: ^bytes.Reader, p: ^$T) -> io.Error {
	n, err := bytes.reader_read(r, mem.ptr_to_bytes(p))
	if err == .EOF {
		return .Unexpected_EOF
	}
	if (err == nil && n != size_of(p^)) {
		return .Short_Buffer
	}

	return err
}

parse_bytes :: proc(r: ^bytes.Reader, p: []byte) -> Error {
	n, err := bytes.reader_read(r, p)
	if err == .EOF {
		return .Unexpected_EOF
	}
	if (err == nil && n != len(p)) {
		return .Short_Buffer
	}

	return nil
}

parse_u16 :: proc(r: ^bytes.Reader, v: ^u16) -> Error {
	ok: bool
	v^, ok = endian.get_u16(r.s[r.i:], .Big)
	if !ok {
		return .Short_Buffer
	}
	if _, err := bytes.reader_seek(r, 2, .Current); err != nil {
		return err
	}

	return nil
}

/* TODO unify both */
parse_u32 :: proc(r: ^bytes.Reader, v: ^u32) -> Error {
	ok: bool
	v^, ok = endian.get_u32(r.s[r.i:], .Big)
	if !ok {
		return .Short_Buffer
	}
	if _, err := bytes.reader_seek(r, 4, .Current); err != nil {
		return err
	}

	return nil
}

parse_type :: proc(r: ^bytes.Reader, v: ^RR_Type) -> (err: Error) {
	vu: u16
	parse_u16(r, &vu) or_return

	v^ = RR_Type_Known(vu)

	switch v^ {
	case .A:
	case .PTR:
	case .MX:
	case .TXT:
	case .AAAA:
	case .SRV:
	case .Invalid:
		return .Bad_Resource_Record
	case:
		v^ = vu
	}
	return
}

parse_class :: proc(r: ^bytes.Reader, v: ^RR_Class) -> (err: Error) {
	vu: u16
	parse_u16(r, &vu) or_return
	v^ = RR_Class(vu)
	return
}

parse_rr_set :: proc(r: ^bytes.Reader, rr_set: ^RR_Set) -> (err: Error) {
	parse_domain_name(r, &rr_set.name) or_return
	defer if err != nil {
		destroy_domain_name(&rr_set.name)
	}
	parse_type(r, &rr_set.type) or_return
	parse_class(r, &rr_set.class) or_return

	return
}

parse_label :: proc(orig_r: ^bytes.Reader, domain: ^Domain_Name) -> Error {
	to_skip, cur, domain_len: int
	n: u8
	packet: []u8
	jumped: bool

	packet = orig_r.s /* Original packet */
	cur = int(orig_r.i) /* Where we're starting */

	for {
		if domain_len > MAX_DOMAIN_NAME_LEN {
			return .Bad_Label
		}
		if len(packet[cur:]) < 1 {
			return .Bad_Label
		}
		n = packet[cur]
		cur += 1
		if !jumped {
			to_skip += 1
		}

		switch {
		case n == 0:
			if _, err := bytes.reader_seek(orig_r, i64(to_skip), .Current); err != nil {
				return err
			}
			return nil
		case n & 0xC0 == 0xC0:
			ptr: u16
			if len(packet[cur:]) < 1 {
				return .Bad_Label
			}
			/* a PTR is 2 bytes, remember the lower half */
			ptr |= u16(packet[cur])
			cur += 1
			if !jumped {
				to_skip += 1
			}
			/* we're about to jump, no more skipping */
			jumped = true
			/* don't forget the upper half */
			ptr |= u16(n & ~u8(0xC0)) << 8
			/* can only point backwards, avoids infinity */
			if int(ptr) >= (cur - 2) || int(ptr) > len(packet) {
				return .Bad_Label
			}
			cur = int(ptr)
		case n > MAX_LABEL_LEN || len(packet[cur:]) < int(n):
			return .Bad_Label
		case:
			if !jumped {
				to_skip += int(n)
			}
			label, err := bytes.clone_safe(packet[cur:][:n])
			if err != nil {
				return nil
			}
			cur += int(n)
			if _, err := append(domain, label); err != nil {
				delete(label)
				return err
			}
			domain_len += len(label) + 1
		}
	}
	unreachable()
}

new_rr :: proc($T: typeid) -> (^T, runtime.Allocator_Error) {
	rr, err := new(T)
	if err != nil {
		return nil, err
	}
	rr.variant = rr

	return rr, nil
}

parse_rr :: proc(r: ^bytes.Reader) -> (rr: ^RR, err: Error) {
	rr_set: RR_Set

	parse_rr_set(r, &rr_set) or_return
	defer if err != nil {
		if rr != nil {
			rr_destroy(rr)
		} else {
			destroy_rr_set(&rr_set)
		}
	}

	switch rr_set.type {
	case .A:
		rr = new_rr(RR_A) or_return
	case .NS:
		rr = new_rr(RR_NS) or_return
	case .CNAME:
		rr = new_rr(RR_CNAME) or_return
	case .PTR:
		rr = new_rr(RR_PTR) or_return
	case .HINFO:
		rr = new_rr(RR_HINFO) or_return
	case .MX:
		rr = new_rr(RR_MX) or_return
	case .TXT:
		rr = new_rr(RR_TXT) or_return
	case .AAAA:
		rr = new_rr(RR_AAAA) or_return
	case .SRV:
		rr = new_rr(RR_SRV) or_return
	case .Invalid:
		return nil, .Bad_Resource_Record
	case:
		rr = new_rr(RR_OTHER) or_return
	}

	rr.rr_set = rr_set
	parse_u32(r, &rr.ttl) or_return
	parse_u16(r, &rr.rd_len) or_return

	switch rr in rr.variant {
	case ^RR_A:
		if rr.rd_len != 4 {
			return nil, .Bad_Resource_Data_Len
		}
		parse_bytes(r, rr.addr4[:]) or_return
	case ^RR_NS:
		parse_domain_name(r, &rr.domain) or_return
	case ^RR_CNAME:
		parse_domain_name(r, &rr.domain) or_return
	case ^RR_PTR:
		parse_domain_name(r, &rr.domain) or_return
	case ^RR_HINFO:
		parse_dns_string(r, &rr.cpu) or_return
		parse_dns_string(r, &rr.os) or_return
	case ^RR_MX:
		parse_u16(r, &rr.preference) or_return
		parse_domain_name(r, &rr.exchange) or_return
	case ^RR_TXT:
		parse_dns_string(r, &rr.data) or_return
	case ^RR_AAAA:
		if rr.rd_len != 16 {
			return nil, .Bad_Resource_Data_Len
		}
		parse_bytes(r, rr.addr6[:]) or_return
	case ^RR_SRV:
		parse_u16(r, &rr.priority) or_return
		parse_u16(r, &rr.weight) or_return
		parse_u16(r, &rr.port) or_return
		parse_domain_name(r, &rr.target) or_return
	case ^RR_OTHER:
		rr.data = make([]u8, rr.rd_len) or_return
		parse_bytes(r, rr.data) or_return
	}

	return
}

parse_dns_string :: proc(r: ^bytes.Reader, data: ^Dns_String) -> (err: Error) {
	n := bytes.reader_read_byte(r) or_return
	if n > MAX_DOMAIN_NAME_LEN {
		return .Bad_String_Len
	}
	if n == 0 {
		return nil
	}
	if bytes.reader_length(r) < int(n) {
		return .Short_Buffer
	}
	data^ = make([]byte, n) or_return
	copied := bytes.reader_read(r, data^[:]) or_return
	if copied != len(data^) {
		delete(data^)
		data^ = nil
		return .Short_Buffer
	}

	return
}

parse_question :: proc(r: ^bytes.Reader, qst: ^Question) -> (err: Error) {
	return parse_rr_set(r, qst)
}

parse_domain_name :: proc(r: ^bytes.Reader, domain: ^Domain_Name) -> (err: Error) {
	err = parse_label(r, domain)
	if err != nil {
		destroy_domain_name(domain)
	}
	return
}

parse_packet :: proc(r: ^bytes.Reader, pkt: ^Packet) -> (err: Error) {
	if bytes.reader_length(r) < size_of(Packet_Header) {
		return .Short_Buffer
	}
	defer if err != nil {
		destroy_packet(pkt)
	}

	parse_ptr_type(r, &pkt.header) or_return

	pkt.qd = make([]Question, pkt.header.qd_count) or_return
	for &qst in pkt.qd {
		parse_question(r, &qst) or_return
		//		fmt.printf("Q: %#w\n", qst)
	}

	pkt.an = make([]^RR, pkt.header.an_count)
	for &rr in pkt.an {
		rr = parse_rr(r) or_return
		//		fmt.printf("AN: %#w\n", rr.variant)
	}

	pkt.ns = make([]^RR, pkt.header.ns_count)
	for &rr in pkt.ns {
		rr = parse_rr(r) or_return
		//		fmt.printf("AUTH: %#w\n", rr.variant)
	}

	pkt.ar = make([]^RR, pkt.header.ar_count)
	for &rr in pkt.ar {
		rr = parse_rr(r) or_return
		//		fmt.printf("AR: %#w\n", rr.variant)
	}

	return
}

gen_id :: proc() -> (v: u16be) {
	crypto.rand_bytes(mem.ptr_to_bytes(&v))
	return
}

from_bytes :: proc(buf: []byte, pkt: ^Packet) -> Error {
	r: bytes.Reader

	bytes.reader_init(&r, buf)

	return parse_packet(&r, pkt)
}

/* XXX doesn't handle escaped dots */
domain_from_ascii :: proc(s: string, domain: ^Domain_Name) -> (err: Error) {
	s := s

	defer if err != nil {
		destroy_domain_name(domain)
	}

	for l in strings.split_by_byte_iterator(&s, '.') {
		lcopy := strings.clone(l) or_return

		_, err = append(domain, transmute([]byte)lcopy)
		if err != nil {
			delete(lcopy)
			return
		}
	}

	return
}

serialize_packet :: proc(pkt: ^Packet) -> (buf: []byte, err: Error) {
	b: bytes.Buffer
	n: int

	bytes.buffer_init(&b, mem.ptr_to_bytes(&pkt.header))
	defer if err != nil {
		bytes.buffer_destroy(&b)
	}
	for &q in pkt.qd {
		serialize_rr_set(&b, &q) or_return
	}
	for rr in pkt.an {
		serialize_rr(&b, rr)
	}
	for rr in pkt.ns {
		serialize_rr(&b, rr)
	}
	for rr in pkt.ar {
		serialize_rr(&b, rr)
	}

	buf = b.buf[:]

	return
}

serialize_rr :: proc(b: ^bytes.Buffer, rr: ^RR) -> (err: Error) {
	n: int

	serialize_rr_set(b, &rr.rr_set) or_return

	switch rr in rr.variant {
	case ^RR_A:
		n = bytes.buffer_write(b, rr.addr4[:]) or_return
		check_short_write(n == 4) or_return
	case ^RR_NS:
		serialize_domain_name(b, rr.domain) or_return
	case ^RR_CNAME:
		serialize_domain_name(b, rr.domain) or_return
	case ^RR_PTR:
		serialize_domain_name(b, rr.domain) or_return
	case ^RR_HINFO:
		serialize_dns_string(b, rr.cpu)
		serialize_dns_string(b, rr.os)
	case ^RR_MX:
		serialize_domain_name(b, rr.exchange) or_return
	case ^RR_TXT:
		serialize_dns_string(b, rr.data)
	case ^RR_AAAA:
		n = bytes.buffer_write(b, rr.addr6[:]) or_return
		check_short_write(n == 16) or_return
	case ^RR_SRV:
		serialize_domain_name(b, rr.target) or_return
	case ^RR_OTHER:
		err = .Bad_Resource_Record
	}
	return
}

serialize_rr_set :: proc(b: ^bytes.Buffer, rr_set: ^RR_Set) -> (err: Error) {
	n: int

	serialize_domain_name(b, rr_set.name) or_return

	vk, ok := rr_set.type.(RR_Type_Known)
	if !ok {
		err = .Bad_Packet
		return
	}
	v := u16be(vk)
	n = bytes.buffer_write_ptr(b, rawptr(&v), size_of(v)) or_return
	check_short_write(n == 2) or_return

	v = u16be(rr_set.class)
	n = bytes.buffer_write_ptr(b, rawptr(&v), size_of(v)) or_return
	check_short_write(n == 2) or_return

	return
}

serialize_domain_name :: proc(b: ^bytes.Buffer, domain: Domain_Name) -> (err: Error) {
	n: int

	if len(domain) == 0 {
		err = .Bad_Domain
		return
	}
	for l in domain {
		if len(l) > MAX_LABEL_LEN {
			err = .Bad_Label
			return
		}
		bytes.buffer_write_byte(b, byte(len(l))) or_return
		n = bytes.buffer_write(b, l) or_return
		check_short_write(n == len(l)) or_return
	}
	bytes.buffer_write_byte(b, 0) or_return

	return
}

serialize_dns_string :: proc(b: ^bytes.Buffer, s: Dns_String) -> (err: Error) {
	if len(s) > MAX_DOMAIN_NAME_LEN {
		err = .Bad_String_Len
		return
	}

	bytes.buffer_write_byte(b, byte(len(s))) or_return
	bytes.buffer_write(b, s) or_return

	return
}

destroy_packet :: proc(pkt: ^Packet) {
	for &q in pkt.qd {
		destroy_rr_set(&q)
	}
	delete(pkt.qd)
	pkt.qd = nil

	for &rr in pkt.an {
		rr_destroy(rr)
	}
	delete(pkt.an)
	pkt.an = nil

	for &rr in pkt.ns {
		rr_destroy(rr)
	}
	delete(pkt.ns)
	pkt.ns = nil

	for &rr in pkt.ar {
		rr_destroy(rr)
	}
	delete(pkt.ar)
	pkt.ar = nil
}

rr_destroy :: proc(rr: ^RR) {
	if rr == nil {
		return
	}
	destroy_rr_set(&rr.rr_set)
	switch rr in rr.variant {
	case ^RR_A: /* nada */
	case ^RR_NS:
		destroy_domain_name(&rr.domain)
	case ^RR_CNAME:
		destroy_domain_name(&rr.domain)
	case ^RR_PTR:
		destroy_domain_name(&rr.domain)
	case ^RR_HINFO:
		delete(rr.cpu)
		delete(rr.os)
	case ^RR_MX:
		destroy_domain_name(&rr.exchange)
	case ^RR_TXT:
		delete(rr.data)
	case ^RR_AAAA: /* nada */
	case ^RR_SRV:
		destroy_domain_name(&rr.target)
	case ^RR_OTHER:
		delete(rr.data)
	}
	free(rr)
}

destroy_rr_set :: proc(rr_set: ^RR_Set) {
	destroy_domain_name(&rr_set.name)
}

destroy_domain_name :: proc(domain: ^Domain_Name) {
	for l in domain^ {
		delete(l)
	}
	delete(domain^)
	domain^ = nil
}

check_short_write :: proc(good: bool) -> io.Error {
	return good ? nil : .Short_Write
}
