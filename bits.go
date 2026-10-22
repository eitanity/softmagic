// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import "math"

// This file holds every narrowing or sign-changing integer conversion the
// package makes, written as masks and arithmetic whose ranges a static
// analyser can see, so gosec's conversion-overflow check passes with no
// suppressions. A C cast's wrap-around is
// reproduced explicitly, never by a bare Go conversion.

// low32 is the low 32 bits of a 64-bit value.
func low32(v uint64) uint32 { return uint32(v & 0xffffffff) }

// low16 is the low 16 bits.
func low16(v uint64) uint16 { return uint16(v & 0xffff) }

// low8 is the low 8 bits.
func low8(v uint64) uint8 { return uint8(v & 0xff) }

// wrapInt32 is C's (int32_t) cast of a 64-bit value: the low 32 bits
// reinterpreted as two's complement.
func wrapInt32(v int64) int32 {
	w := v & 0xffffffff // low32
	if w >= 1<<31 {
		w -= 1 << 32
	}
	if w < math.MinInt32 || w > math.MaxInt32 {
		return 0 // unreachable: w is within range by construction
	}
	return int32(w)
}

// bitsOfInt32 is C's (uint32_t) cast of an int32: the same bit pattern.
func bitsOfInt32(v int32) uint32 { return uint32(int64(v) & 0xffffffff) }

// signExtend8 sign-extends the low 8 bits of v to 64 bits.
func signExtend8(v uint64) uint64 { return (v&0xff ^ 0x80) - 0x80 }

// signExtend16 sign-extends the low 16 bits of v to 64 bits.
func signExtend16(v uint64) uint64 { return (v&0xffff ^ 0x8000) - 0x8000 }

// signExtend32 sign-extends the low 32 bits of v to 64 bits.
func signExtend32(v uint64) uint64 { return (v&0xffffffff ^ 0x80000000) - 0x80000000 }

// smallUint8 converts an int known to be in [0, 255]; out of range is an
// invariant violation and yields 0.
func smallUint8(n int) uint8 {
	if n < 0 || n > math.MaxUint8 {
		return 0
	}
	return uint8(n)
}

// smallInt32 converts an int known to be in [0, MaxInt32]; out of range
// yields 0.
func smallInt32(n int) int32 {
	if n < 0 || n > math.MaxInt32 {
		return 0
	}
	return int32(n)
}

// bitsOfInt64 is the two's complement bit pattern of v.
func bitsOfInt64(v int64) uint64 {
	if v >= 0 {
		return uint64(v & math.MaxInt64)
	}
	return ^uint64((-(v + 1)) & math.MaxInt64) // -(v+1) is non-negative for every negative v
}

// intFromU32 is a 32-bit count as an int on any host: above the signed
// range it is clamped, which every later comparison against a small
// limit treats the same as the exact value.
func intFromU32(v uint32) int {
	if uint64(v) > math.MaxInt32 {
		return math.MaxInt32
	}
	return int(v)
}

// widenFloat32 is a float32's bits as a float64, the same on every host. A
// value that is not a NaN widens exactly anywhere; a NaN keeps its sign and
// payload and is made quiet, as amd64 and arm64 do, where MIPS would
// substitute its own default NaN and lose the sign that printf shows.
func widenFloat32(b uint32) float64 {
	if b&0x7f800000 != 0x7f800000 || b&0x7fffff == 0 {
		return float64(math.Float32frombits(b))
	}
	sign := uint64(b>>31) << 63
	frac := uint64(b&0x7fffff|0x400000) << 29
	return math.Float64frombits(sign | 0x7ff<<52 | frac)
}

// narrowFloat64 is widenFloat32's inverse: a float64 as float32 bits, the
// same on every host, a NaN keeping its sign and the top of its payload.
func narrowFloat64(f float64) uint32 {
	if !math.IsNaN(f) {
		return math.Float32bits(float32(f))
	}
	b := math.Float64bits(f)
	sign := low32(b>>63) << 31
	return sign | 0x7fc00000 | low32(b>>29)&0x3fffff
}
