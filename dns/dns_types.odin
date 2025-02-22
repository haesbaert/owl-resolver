/* SPDX-License-Identifier: ISC */

package dns

import "base:runtime"
import "core:io"
import "core:math/bits"

Dns_Error :: enum u32 {
	None,
	Bad_Label,
	Bad_String_Len,
	Bad_Compression,
	Bad_Resource_Data_Len,
	Bad_Resource_Record,
}

Error :: union #shared_nil {
	runtime.Allocator_Error,
	Dns_Error,
	io.Error,
}

/*
 * Packet types
 */

Packet :: struct {
	header: Packet_Header,
	qd:     []Question,
	an:     []^RR,
	ns:     []^RR,
	ar:     []^RR,
}

Packet_Header :: struct {
	id:       u16be `fmt:"#X"`,
	set:      Packet_Header_Set,
	qd_count: u16be,
	an_count: u16be,
	ns_count: u16be,
	ar_count: u16be,
}

when ODIN_ENDIAN == .Little {
	Packet_Header_Set :: bit_field u16be {
		rd:     b8 | 1, /* last bit of the first byte */
		tc:     b8 | 1,
		aa:     b8 | 1,
		opcode: u8 | 4,
		qr:     b8 | 1,
		rcode:  u8 | 4,
		z:      u8 | 3,
		ra:     b8 | 1,
	}
}

when ODIN_ENDIAN == .Big {
	Packet_Header_Set :: bit_field u16be {
		qr:     b8 | 1,
		opcode: u8 | 4,
		aa:     b8 | 1,
		tc:     b8 | 1,
		rd:     b8 | 1, /* last bit of the first byte */
		ra:     b8 | 1,
		z:      u8 | 3,
		rcode:  u8 | 4,
	}
}

Question :: RR_Set

/*
 * Resource Record definitions
 */

RR_Variant :: union {
	^RR_A,
	^RR_NS,
	^RR_CNAME,
	^RR_PTR,
	^RR_HINFO,
	^RR_MX,
	^RR_TXT,
	^RR_AAAA,
	^RR_SRV,
	^RR_OTHER,
}

RR_Type_Known :: enum u16 {
	Invalid = 0,
	A       = 1,
	NS      = 2,
	CNAME   = 5,
	PTR     = 12,
	HINFO   = 13,
	MX      = 15,
	TXT     = 16,
	AAAA    = 28,
	SRV     = 33,
}

RR_Type :: union {
	RR_Type_Known,
	u16,
}

RR :: struct {
	rr_set:  RR_Set,
	ttl:     u32,
	rd_len:  u16,
	variant: RR_Variant,
}

RR_A :: struct {
	using rr: RR,
	addr4:    [4]byte,
}

RR_NS :: struct {
	using rr: RR,
	domain:   Domain_Name,
}

RR_CNAME :: distinct RR_NS

RR_PTR :: distinct RR_CNAME

RR_HINFO :: struct {
	using rr: RR,
	cpu:      Dns_String `fmt:"s"`,
	os:       Dns_String `fmt:"s"`,
}

RR_MX :: struct {
	using rr:   RR,
	preference: u16,
	exchange:   Domain_Name,
}

RR_TXT :: struct {
	using rr: RR,
	data:     Dns_String `fmt:"s"`,
}

RR_AAAA :: struct {
	using rr: RR,
	addr6:    [16]byte,
}

RR_SRV :: struct {
	using rr: RR,
	priority: u16,
	weight:   u16,
	port:     u16,
	target:   Domain_Name,
}

RR_OTHER :: struct {
	using rr: RR,
	data:     []byte `fmt:"#X"`,
}

RR_Set :: struct {
	name:  Domain_Name `fmt:"s"`,
	type:  RR_Type,
	class: RR_Class,
}

RR_Class :: enum u16 {
	Invalid,
	IN = 1,
	NONE = 254,
	ANY = 255,
}

Domain_Name :: [dynamic][]byte
Dns_String :: []byte

MAX_LABEL_LEN :: 63
MAX_DOMAIN_NAME_LEN :: 255
