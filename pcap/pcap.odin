/* SPDX-License-Identifier: ISC */

package pcap

import "base:intrinsics"
import "base:runtime"
import "core:bytes"
import "core:io"
import "core:mem"
import "core:slice"

File_Header :: struct {
	magic_number:  [4]u8,
	major_version: u16,
	minor_version: u16,
	reserved1:     u32,
	reserved2:     u32,
	snap_len:      u32,
	link_type:     u32,
}

Packet_Record :: struct {
	ts_seconds: u32,
	ts_small:   u32,
	cap_len:    u32,
	orig_len:   u32,
	data:       []u8,
}

Handle :: struct {
	header:      File_Header,
	endian:      Pcap_Endian,
	time_fmt:    Pcap_Time,
	stream:      io.Stream,
	reader:      bytes.Reader,
	packet_data: [dynamic]u8,
}

Pcap_Error :: enum u32 {
	None,
	Invalid_Header,
	Invalid_Magic,
}

Error :: union #shared_nil {
	io.Error,
	Pcap_Error,
	runtime.Allocator_Error,
}

Pcap_Time :: enum u32 {
	Unknown,
	Micro,
	Nano,
}

Pcap_Endian :: runtime.Odin_Endian_Type

Magic_Big_Micro: [4]u8 : {0xA1, 0xB2, 0xC3, 0xD4}
Magic_Big_Nano: [4]u8 : {0xA1, 0xB2, 0x3C, 0x4D}

Magic_Little_Micro: [4]u8 : {0xD4, 0xC3, 0xB2, 0xA1}
Magic_Little_Nano: [4]u8 : {0x4D, 0x3C, 0xB2, 0xA1}

@(private)
read_ptr_exactly :: proc(stream: io.Stream, p: rawptr, #any_int len: int) -> io.Error {
	n, err := io.read_at_least(stream, mem.byte_slice(p, len), len)
	if err == nil {
		ensure(n == len)
	}
	return err
}

@(private)
stream_read_into :: proc(s: io.Stream, p: ^$T) -> io.Error {
	sl := mem.ptr_to_bytes(p)
	n, err := io.read_at_least(s, sl, len(sl))
	if err == .EOF || (err == nil && n != len(sl)) {
		err = .Unexpected_EOF
	}

	return err
}

@(private)
swap_hdr :: proc(hdr: ^File_Header) {
	using hdr
	using intrinsics
	slice.reverse(magic_number[:])
	major_version = byte_swap(major_version)
	minor_version = byte_swap(hdr.minor_version)
	reserved1 = byte_swap(reserved1)
	reserved2 = byte_swap(reserved2)
	snap_len = byte_swap(snap_len)
	link_type = byte_swap(link_type)
}

@(private)
swap_packet_record :: proc(pkt: ^Packet_Record) {
	using pkt
	using intrinsics
	ts_seconds = byte_swap(ts_seconds)
	ts_small = byte_swap(ts_small)
	cap_len = byte_swap(cap_len)
	orig_len = byte_swap(orig_len)
}

next_packet :: proc(handle: ^Handle) -> (pkt: Packet_Record, err: Error) {
	read_ptr_exactly(handle.stream, &pkt, 16) or_return
	if handle.endian != ODIN_ENDIAN {
		swap_packet_record(&pkt)
	}
	resize(&handle.packet_data, pkt.cap_len)
	n := io.read_at_least(handle.stream, handle.packet_data[:], int(pkt.cap_len)) or_return
	ensure(n == int(pkt.cap_len))
	pkt.data = handle.packet_data[:]

	return
}

packet_iterator :: proc(handle: ^Handle) -> (Packet_Record, bool) {
	pkt, err := next_packet(handle)

	return pkt, err == nil
}

reset :: proc(handle: ^Handle) -> Error {
	_, err := io.seek(handle.stream, size_of(File_Header), .Start)

	return err
}

get_packets :: proc {
	get_packets_from_handle,
	get_packets_from_bytes,
}

/* Prefer using next_packet_record when possible */
get_packets_from_handle :: proc(handle: ^Handle) -> ([]Packet_Record, Error) {
	sl: [dynamic]Packet_Record
	pkt: Packet_Record
	err: Error

	for {
		pkt, err = next_packet(handle)
		if err == .EOF {
			return sl[:], nil
		} else if err != nil {
			break
		}
		pkt.data, err = bytes.clone_safe(pkt.data)
		if err != nil {
			break
		}
		_, err = append(&sl, pkt)
		if err != nil {
			break
		}
	}

	delete(sl)

	return nil, err
}

get_packets_from_bytes :: proc(buf: []byte) -> ([]Packet_Record, Error) {
	handle, err := open(buf)
	if err != nil {
		return nil, err
	}
	defer close(handle)

	return get_packets_from_handle(handle)
}

destroy_packets :: proc(all_pkts: []Packet_Record) {
	for &pkt in all_pkts {
		delete(pkt.data)
		pkt.data = nil
	}
	delete(all_pkts)
}

@(private)
load :: proc(handle: ^Handle) -> (err: Error) {
	stream_read_into(handle.stream, &handle.header) or_return

	switch handle.header.magic_number {
	case Magic_Little_Micro:
		handle.endian = .Little
		handle.time_fmt = .Micro
	case Magic_Little_Nano:
		handle.endian = .Little
		handle.time_fmt = .Nano
	case Magic_Big_Micro:
		handle.endian = .Big
		handle.time_fmt = .Micro
	case Magic_Big_Nano:
		handle.endian = .Big
		handle.time_fmt = .Nano
	case:
		return Pcap_Error.Invalid_Magic
	}

	if handle.endian != ODIN_ENDIAN {
		swap_hdr(&handle.header)
	}

	reserve(&handle.packet_data, 2048)

	return
}

open :: proc {
	from_stream,
	from_bytes,
}

from_stream :: proc(stream: io.Stream) -> (handle: ^Handle, err: Error) {
	handle = new(Handle) or_return
	handle.stream = stream

	if err := load(handle); err != nil {
		return {}, err
	}

	return
}

from_bytes :: proc(buf: []byte) -> (handle: ^Handle, err: Error) {
	handle = new(Handle) or_return
	handle.stream = bytes.reader_init(&handle.reader, buf)

	if err := load(handle); err != nil {
		return nil, err
	}

	return
}

close :: proc(handle: ^Handle) {
	delete(handle.packet_data)
	free(handle)
}
