// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from mconvert, cvt_flip and the cvt_* helpers in softmagic.c,
// file 5.48, Copyright (c) Ian F. Darwin 1986-1995 (see COPYING).

package softmagic

import (
	"github.com/eitanity/softmagic/internal/invariant"

	"encoding/binary"
	"math"
)

// cvtFlip swaps a type's endianness when a "use ^name" asked for it.
func cvtFlip(t fileType, flip bool) fileType { // fileType
	if !flip {
		return t
	}
	switch t {
	case tBeShort:
		return tLeShort
	case tBeLong:
		return tLeLong
	case tBeDate:
		return tLeDate
	case tBeLDate:
		return tLeLDate
	case tBeQuad:
		return tLeQuad
	case tBeQDate:
		return tLeQDate
	case tBeQLDate:
		return tLeQLDate
	case tBeQWDate:
		return tLeQWDate
	case tLeShort:
		return tBeShort
	case tLeLong:
		return tBeLong
	case tLeDate:
		return tBeDate
	case tLeLDate:
		return tBeLDate
	case tLeQuad:
		return tBeQuad
	case tLeQDate:
		return tBeQDate
	case tLeQLDate:
		return tBeQLDate
	case tLeQWDate:
		return tBeQWDate
	default:
		return cvtFlipFloat(t)
	}
}

func cvtFlipFloat(t fileType) fileType { // fileType
	switch t {
	case tBeFloat:
		return tLeFloat
	case tLeFloat:
		return tBeFloat
	case tBeDouble:
		return tLeDouble
	case tLeDouble:
		return tBeDouble
	case tBeMSDOSDate:
		return tLeMSDOSDate
	case tLeMSDOSDate:
		return tBeMSDOSDate
	case tBeMSDOSTime:
		return tLeMSDOSTime
	case tLeMSDOSTime:
		return tBeMSDOSTime
	default:
		return t
	}
}

// mconvert converts the copied bytes in s.value to host order for the
// type, storing the integer image little-endian in value[0:8] as the
// reference stores it in its union, and applies the rule's mask operator.
// False is the reference's "zerodivide/overflow" refusal.
func (s *scan) mconvert(m *record, flip bool) bool { // magicLine
	invariant.Check(m.typ != tInvalid, "line has a type")
	v := s.value[:]                       // value
	switch t := cvtFlip(m.typ, flip); t { // fileType
	case tByte:
		return s.cvtInt(m, uint64(v[0]), 8)
	case tShort, tMSDOSDate, tMSDOSTime, tLeShort, tLeMSDOSDate, tLeMSDOSTime:
		return s.cvtInt(m, uint64(binary.LittleEndian.Uint16(v)), 16)
	case tLong, tDate, tLDate, tLeLong, tLeDate, tLeLDate:
		return s.cvtInt(m, uint64(binary.LittleEndian.Uint32(v)), 32)
	case tQuad, tQDate, tQLDate, tQWDate, tOffset, tLeQuad, tLeQDate, tLeQLDate, tLeQWDate:
		return s.cvtInt(m, binary.LittleEndian.Uint64(v), 64)
	case tString, tBeString16, tLeString16, tOctal:
		v[maxString-1] = 0
		return true
	case tPString:
		return s.cvtPString(m)
	case tBeShort, tBeMSDOSDate, tBeMSDOSTime:
		return s.cvtInt(m, uint64(binary.BigEndian.Uint16(v)), 16)
	case tBeLong, tBeDate, tBeLDate:
		return s.cvtInt(m, uint64(binary.BigEndian.Uint32(v)), 32)
	case tBeQuad, tBeQDate, tBeQLDate, tBeQWDate:
		return s.cvtInt(m, binary.BigEndian.Uint64(v), 64)
	case tMeLong, tMeDate, tMeLDate:
		return s.cvtInt(m, uint64(middleEndian32(v)), 32)
	default:
		return s.mconvertFloat(m, t)
	}
}

// mconvertFloat handles the float and double types and the types that
// need no conversion.
func (s *scan) mconvertFloat(m *record, t fileType) bool { // magicLine
	invariant.Check(t != tByte && !isWidth2(t) && !isWidth4(t) && !isWidth8(t) || isFloatType(t) || isDoubleType(t), "type without an integer conversion")
	v := s.value[:] // value
	switch t {
	case tFloat:
		return s.cvtFloat(m, binary.LittleEndian.Uint32(v))
	case tBeFloat:
		return s.cvtFloat(m, binary.BigEndian.Uint32(v))
	case tLeFloat:
		return s.cvtFloat(m, binary.LittleEndian.Uint32(v))
	case tDouble:
		return s.cvtDouble(m, binary.LittleEndian.Uint64(v))
	case tBeDouble:
		return s.cvtDouble(m, binary.BigEndian.Uint64(v))
	case tLeDouble:
		return s.cvtDouble(m, binary.LittleEndian.Uint64(v))
	case tRegex, tSearch, tDefault, tClear, tName, tUse, tDer, tGUID, tLeGUID, tBeGUID:
		return true
	default:
		return s.fail("mconvert on a type it does not handle")
	}
}

// widthMask is the all-ones mask of a width in bits.
func widthMask(bits int) uint64 {
	if bits >= 64 {
		return ^uint64(0)
	}
	return 1<<uint(bits) - 1
}

// cvtInt is the DO_CVT macro: apply the mask operator in the type's width
// and signedness, then store the result. The arithmetic is done on 64-bit
// values and truncated to the width, which is what the C casts do; the
// signed division and modulo cases use the sign-extended operands.
func (s *scan) cvtInt(m *record, val uint64, bits int) bool { // magicLine
	invariant.Check(bits == 8 || bits == 16 || bits == 32 || bits == 64, "integer width")
	mask := widthMask(bits)
	unsigned := m.flag&flagUnsigned != 0
	num := m.maskOrStr & mask
	val &= mask
	if m.maskOrStr != 0 {
		var ok bool
		val, ok = applyIntOp(m.maskOp&opsMask, val, num, bits, unsigned)
		if !ok {
			return false
		}
		val &= mask
	}
	if m.maskOp&opInverse != 0 {
		val = ^val & mask
	}
	binary.LittleEndian.PutUint64(s.value[0:8], val)
	return true
}

// applyIntOp is one DO_CVT1 case. Division and modulo refuse a zero
// divisor and the signed MIN/-1 overflow, as the reference does.
func applyIntOp(op uint8, val, num uint64, bits int, unsigned bool) (uint64, bool) { // operator
	invariant.Check(op <= opModulo, "operator in range")
	switch op {
	case opAnd:
		return val & num, true
	case opOr:
		return val | num, true
	case opXor:
		return val ^ num, true
	case opAdd:
		return val + num, true
	case opMinus:
		return val - num, true
	case opMultiply:
		return val * num, true
	case opDivide, opModulo:
		return divMod(op, val, num, bits, unsigned)
	default:
		return val, true
	}
}

func divMod(op uint8, val, num uint64, bits int, unsigned bool) (uint64, bool) { // operator
	invariant.Check(op == opDivide || op == opModulo, "division operator")
	if num == 0 {
		return 0, false
	}
	if unsigned {
		if op == opDivide {
			return val / num, true
		}
		return val % num, true
	}
	a, b := extend(val, bits, true), extend(num, bits, true) // dividend
	if b == -1 && (bits == 32 && a == math.MinInt32 || bits == 64 && a == math.MinInt64) {
		return 0, false
	}
	if op == opDivide {
		return bitsOfInt64(a / b), true
	}
	return bitsOfInt64(a % b), true
}

// cvtFloat is cvt_float over a 32-bit image.
func (s *scan) cvtFloat(m *record, bits uint32) bool {
	invariant.Check(m.maskOp&opsMask <= opModulo, "operator in range")
	f := float64(math.Float32frombits(bits)) // floatValue
	if m.maskOrStr != 0 {
		g, ok := applyFloatOp(m.maskOp&opsMask, f, float64(float32(m.maskOrStr)))
		if !ok {
			return false
		}
		f = g
	}
	binary.LittleEndian.PutUint32(s.value[0:4], math.Float32bits(float32(f)))
	return true
}

// cvtDouble is cvt_double over a 64-bit image.
func (s *scan) cvtDouble(m *record, bits uint64) bool {
	invariant.Check(m.maskOp&opsMask <= opModulo, "operator in range")
	f := math.Float64frombits(bits) // doubleValue
	if m.maskOrStr != 0 {
		g, ok := applyFloatOp(m.maskOp&opsMask, f, float64(m.maskOrStr))
		if !ok {
			return false
		}
		f = g
	}
	binary.LittleEndian.PutUint64(s.value[0:8], math.Float64bits(f))
	return true
}

// applyFloatOp is DO_CVT2: only + - * / apply to floating types.
func applyFloatOp(op uint8, f, num float64) (float64, bool) { // floatValue
	switch op {
	case opAdd:
		return f + num, true
	case opMinus:
		return f - num, true
	case opMultiply:
		return f * num, true
	case opDivide:
		if num == 0 {
			return 0, false
		}
		return f / num, true
	default:
		return f, true
	}
}

// cvtPString is mconvert's FILE_PSTRING case: shift the string over its
// length prefix and NUL-terminate it.
func (s *scan) cvtPString(m *record) bool {
	invariant.Check(m.typ == tPString, "pstring line")
	flags := m.strFlags()
	sz := pstringLengthSize(flags) // lengthSize
	if sz == 0 {
		return false
	}
	length := pstringLength(flags, s.value[:])
	limit := maxString - sz
	if length >= limit {
		length = limit
	}
	copy(s.value[0:length], s.value[sz:sz+length])
	s.value[length] = 0
	return true
}

// pstringLength is file_pstring_get_length: the length prefix as the
// flags describe it, minus its own size when the flag says so.
func pstringLength(flags uint32, b []byte) int { // lengthPrefix
	invariant.Check(len(b) >= 4, "length prefix readable")
	var n int // stringLength
	switch flags & pstringLen {
	case pstring1LE:
		n = int(b[0])
	case pstring2LE:
		n = int(binary.LittleEndian.Uint16(b))
	case pstring2BE:
		n = int(binary.BigEndian.Uint16(b))
	case pstring4LE:
		n = intFromU32(binary.LittleEndian.Uint32(b))
	case pstring4BE:
		n = intFromU32(binary.BigEndian.Uint32(b))
	default:
		return 0
	}
	if flags&pstringLengthIncludesItself != 0 {
		n -= pstringLengthSize(flags)
	}
	return n
}
