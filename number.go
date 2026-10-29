// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"math"

	"code.eitanity.com/softmagic/internal/invariant"
)

// This file reimplements the C library number parsers the reference relies
// on (strtol, strtoul, strtoull with base 0 or 10) over byte slices, so the
// grammar's edge cases are the reference's, not strconv's.

// cIsSpace is C isspace in the C locale.
func cIsSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

func cIsDigit(c byte) bool { return c >= '0' && c <= '9' }

func cIsAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func cIsAlnum(c byte) bool { return cIsDigit(c) || cIsAlpha(c) }

func cIsPrint(c byte) bool { return c >= 0x20 && c <= 0x7e }

// eatSpace is apprentice.c's EATAB: skip ASCII whitespace from i.
func eatSpace(s []byte, i int) int {
	if !invariant.Check(i >= 0, "cursor non-negative") ||
		!invariant.Check(i <= len(s), "cursor within the text") {
		return len(s)
	}
	for ; i < len(s) && cIsSpace(s[i]); i++ {
	}
	return i
}

// hexToInt is apprentice.c's hextoint: -1 when c is not a hex digit.
func hexToInt(c byte) int { // hexChar
	switch {
	case cIsDigit(c):
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// digitValue is the value of c in the given base and whether c is a digit.
func digitValue(c byte, base uint64) (uint64, bool) {
	if !invariant.Check(base >= 2 && base <= 16, "digit base") {
		return 0, false
	}
	v := hexToInt(c)
	if v < 0 || v > 15 || uint64(v) >= base {
		return 0, false
	}
	return uint64(v), true
}

// unsignedNumber is the digit-scanning core shared by strtoul and strtoull
// with base 0 or 10: it accepts leading whitespace and a sign, a 0x prefix
// (base 0 only), and returns the magnitude, whether a '-' was seen, the
// index after the last digit, whether any digit was consumed, and whether
// the magnitude overflowed. As in C, an overflowing magnitude is
// 2^64-1 and every digit is still consumed; over is C's ERANGE.
func unsignedNumber(s []byte, i int, base uint64) (mag uint64, neg bool, end int, ok, over bool) { // text
	if !invariant.Check(base == 0 || base == 8 || base == 10 || base == 16, "supported base") {
		return 0, false, i, false, false
	}
	i = eatSpace(s, i)
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	if base == 0 {
		base, i = detectBase(s, i)
	}
	start := i
	for ; i < len(s) && isDigitIn(s[i], base); i++ {
		d, _ := digitValue(s[i], base)
		if over || mag > (^uint64(0)-d)/base {
			mag, over = math.MaxUint64, true
			continue
		}
		mag = mag*base + d
	}
	if i == start {
		return 0, neg, start, false, false
	}
	return mag, neg, i, true, over
}

func isDigitIn(c byte, base uint64) bool {
	_, ok := digitValue(c, base)
	return ok
}

// detectBase is strtol's base-0 rule: 0x prefix is hex, a leading 0 is
// octal, else decimal. It returns the base and the index after any prefix.
func detectBase(s []byte, i int) (uint64, int) { // cursor
	if i < len(s)-1 && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') && hexToInt(at(s, i+2)) >= 0 {
		return 16, i + 2
	}
	if i < len(s) && s[i] == '0' {
		return 8, i
	}
	return 10, i
}

// at returns s[i] or 0 past the end: the C idiom of reading the terminator.
func at(s []byte, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// strtoull returns the two's-complement wrap of a negative magnitude, as C's
// strtoull does, and 2^64-1 for a magnitude past 64 bits of either sign.
func strtoull(s []byte, i int, base uint64) (v uint64, end int, ok bool) {
	v, end, ok, _ = strtoullRange(s, i, base)
	return v, end, ok
}

// strtoullRange is strtoull that also reports C's ERANGE.
func strtoullRange(s []byte, i int, base uint64) (v uint64, end int, ok, erange bool) {
	if !invariant.Check(i >= 0, "cursor non-negative") ||
		!invariant.Check(i <= len(s), "cursor within the text") {
		return 0, len(s), false, false
	}
	mag, neg, end, ok, over := unsignedNumber(s, i, base)
	switch {
	case !ok:
		return 0, end, false, false
	case over:
		return math.MaxUint64, end, true, true
	case neg:
		return -mag, end, true, false
	default:
		return mag, end, true, false
	}
}

// strtol returns the signed value clamped to the int64 range, as C's strtol
// does on a 64-bit long, a magnitude past 64 bits included.
func strtol(s []byte, i int, base uint64) (v int64, end int, ok bool) {
	if !invariant.Check(i >= 0, "cursor non-negative") ||
		!invariant.Check(i <= len(s), "cursor within the text") {
		return 0, len(s), false
	}
	mag, neg, end, ok, _ := unsignedNumber(s, i, base)
	if !ok {
		return 0, end, false
	}
	if mag > 1<<63-1 {
		if neg {
			return math.MinInt64, end, true
		}
		return math.MaxInt64, end, true
	}
	if neg {
		return -int64(mag), end, true
	}
	return int64(mag), end, true
}

// eatSize is apprentice.c's eatsize: skip a C integer suffix such as UL.
func eatSize(s []byte, i int) int { // cursor
	if !invariant.Check(i >= 0, "cursor non-negative") ||
		!invariant.Check(i <= len(s), "cursor within the text") {
		return len(s)
	}
	if lower(at(s, i)) == 'u' {
		i++
	}
	switch lower(at(s, i)) {
	case 'l', 's', 'h', 'b', 'c':
		return i + 1
	default:
		return i
	}
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
