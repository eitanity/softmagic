// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"encoding/binary"
	"math"
)

// Integers read from the input file have the types below. Outside this
// file and bits.go, internal/rules rejects + - * << ++ and -- on them
// and any conversion to a type that is not a wider input type, so a
// size, count or offset taken from the file is combined only by the
// helpers here, which report overflow, and wraps only where a helper
// says file 5.48 wraps. Comparisons, masks and right shifts need no
// helper.
type (
	in16 uint16
	in32 uint32
	in64 uint64
)

// The readers of input integers. The byte order is the file's.

func le16(b []byte) in16 { return in16(binary.LittleEndian.Uint16(b)) }
func le32(b []byte) in32 { return in32(binary.LittleEndian.Uint32(b)) }
func le64(b []byte) in64 { return in64(binary.LittleEndian.Uint64(b)) }
func be16(b []byte) in16 { return in16(binary.BigEndian.Uint16(b)) }
func be32(b []byte) in32 { return in32(binary.BigEndian.Uint32(b)) }
func be64(b []byte) in64 { return in64(binary.BigEndian.Uint64(b)) }

// me32 is the PDP-11 word order: bytes 1 0 3 2.
func me32(b []byte) in32 {
	return in32(uint32(b[1])<<24 | uint32(b[0])<<16 | uint32(b[3])<<8 | uint32(b[2]))
}

// The readers of integers in a rule's value or the compiled database,
// which are not input: the rules are trusted like code, and Load
// checks every record it accepts.

func dbLE16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func dbLE32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func dbLE64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

// value is an input integer as a matched value: libmagic compares,
// masks and prints these in 64-bit unsigned arithmetic, wrapping as C
// does, so the wrap is the specified behaviour and not an overflow.
func value[T in16 | in32 | in64](v T) uint64 { return uint64(v) }

// floatBits32 is a 32-bit input integer as the bit pattern of a float.
func floatBits32(v in32) uint32 { return uint32(v) }

// inInt is a 16- or 32-bit input integer as an int; above math.MaxInt,
// which only a 32-bit host has below 2^32, it is math.MaxInt.
func inInt[T in16 | in32](v T) int { return intFromU32(uint32(v)) }

// inInt64 is an input integer as an int64, saturated at math.MaxInt64.
func inInt64[T in16 | in32 | in64](v T) int64 {
	if uint64(v) > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(uint64(v) & math.MaxInt64)
}

// inSID is C's (int32_t) cast of a 32-bit input integer, as a CDF
// sector id is read: the bit pattern as two's complement.
func inSID(v in32) int32 { return wrapInt32(int64(v)) }

// inAdd is a + b, false when the sum overflows the type.
func inAdd[T in16 | in32 | in64](a, b T) (T, bool) {
	sum := a + b
	return sum, sum >= a
}

// inWrapAdd is a + b in C's unsigned arithmetic, wrapping past the
// type's range, for the places where file 5.48 computes the sum so and
// the answer depends on the wrapped value.
func inWrapAdd[T in16 | in32 | in64](a, b T) T { return a + b }

// inWrapSub is a - b in C's unsigned arithmetic, likewise.
func inWrapSub[T in16 | in32 | in64](a, b T) T { return a - b }

// offInt is the reference's off_t cast of a file offset or size: a value
// past the signed range cannot be read and is clamped, not wrapped.
func offInt(v in64) int64 { return inInt64(v) }

// clampInt narrows a size to int within a limit.
func clampInt(v in64, limit int) int {
	if v > in64(bitsOfInt64(int64(limit))) {
		return limit
	}
	return int(v & math.MaxInt32)
}
