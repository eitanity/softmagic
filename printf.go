// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"math"
	"strconv"

	"github.com/eitanity/softmagic/internal/invariant"
)

// This file is the printf subset the magic descriptions use, with C's
// semantics for flags, width, precision and integer promotion. A
// description holds at most one conversion (checked at compile time).

// convSpec is one parsed %-conversion.
type convSpec struct {
	width, prec                   int
	end                           int // index after the conversion
	minus, plus, space, alt, zero bool
	hasPrec                       bool
	verb                          byte
}

// parseConv parses the conversion starting at desc[i] == '%'.
func parseConv(desc string, i int) convSpec {
	invariant.Check(i >= 0, "index non-negative")
	invariant.Check(i < len(desc) && desc[i] == '%', "conversion starts at a percent")
	c := convSpec{prec: -1}
	j := i + 1
	for ; j < len(desc) && isFlagChar(desc[j]); j++ {
		switch desc[j] {
		case '-':
			c.minus = true
		case '+':
			c.plus = true
		case ' ':
			c.space = true
		case '#':
			c.alt = true
		case '0':
			c.zero = true
		}
	}
	for ; j < len(desc) && cIsDigit(desc[j]); j++ {
		c.width = saturate(c.width*10 + int(desc[j]-'0'))
	}
	if j < len(desc) && desc[j] == '.' {
		c.hasPrec, c.prec = true, 0
		j++
		for ; j < len(desc) && cIsDigit(desc[j]); j++ {
			c.prec = saturate(c.prec*10 + int(desc[j]-'0'))
		}
	}
	for ; j < len(desc) && isLengthChar(desc[j]); j++ {
	}
	c.verb = at([]byte(desc), j)
	c.end = j + 1
	return c
}

// saturate keeps a width or precision within a bound far above any the
// compile-time format check admits, so digit strings cannot overflow.
func saturate(n int) int {
	if n > 1<<20 {
		return 1 << 20
	}
	return n
}

func isFlagChar(c byte) bool { return c == '-' || c == '+' || c == ' ' || c == '#' || c == '0' }
func isLengthChar(c byte) bool {
	return c == 'l' || c == 'h' || c == 'q' || c == 'j' || c == 'z' || c == 'L'
}

// printfNum prints desc with its conversion applied to an integer of the
// given promoted width: v holds the sign-extended value; signed says the C
// argument type is signed, which decides how %d and %u reinterpret it.
func (s *scan) printfNum(desc string, v uint64, signed bool, bits int) {
	invariant.Check(s.outLen <= maxOutput, "output length within cap")
	invariant.Check(bits == 32 || bits == 64, "promoted width")
	i := indexFrom(desc, 0, '%')
	if i >= len(desc) {
		s.writeString(desc)
		return
	}
	c := parseConv(desc, i)
	s.writeString(desc[:i])
	s.writeString(formatInt(c, v&widthMask(bits), bits, signed))
	s.writeString(desc[c.end:])
}

// formatInt renders an integer image of `bits` width for the conversion.
func formatInt(c convSpec, v uint64, bits int, _ bool) string {
	invariant.Check(c.verb != 0, "conversion has a verb")
	invariant.Check(bits == 32 || bits == 64, "promoted width")
	var digits string
	neg := false
	switch c.verb {
	case 'd', 'i':
		n := extend(v, bits, true)
		if n < 0 {
			neg = true
			digits = strconv.FormatUint(bitsOfInt64(-(n+1))+1, 10)
		} else {
			digits = strconv.FormatInt(n, 10)
		}
	case 'u':
		digits = strconv.FormatUint(v, 10)
	case 'x':
		digits = strconv.FormatUint(v, 16)
	case 'X':
		digits = upper(strconv.FormatUint(v, 16))
	case 'o':
		digits = strconv.FormatUint(v, 8)
	case 'c':
		return padField(c, string(rune(low8(v))), false)
	default:
		return "%" + string(c.verb)
	}
	return finishNumber(c, digits, neg, v)
}

// finishNumber applies precision, sign, alternate prefix and width to the
// digit string as C's printf does.
func finishNumber(c convSpec, digits string, neg bool, v uint64) string {
	invariant.Check(c.verb != 's', "number conversion")
	if c.hasPrec {
		if c.prec == 0 && v == 0 {
			digits = ""
		}
		for n := len(digits); n < c.prec; n++ {
			digits = "0" + digits
		}
	}
	prefix, digits := numberPrefix(c, digits, neg, v)
	if c.zero && !c.minus && !c.hasPrec {
		for n := len(prefix) + len(digits); n < c.width; n++ {
			digits = "0" + digits
		}
	}
	return padField(c, prefix+digits, false)
}

// numberPrefix is the sign or alternate-form prefix of a number.
func numberPrefix(c convSpec, digits string, neg bool, v uint64) (string, string) {
	prefix := ""
	signed := c.verb == 'd' || c.verb == 'i'
	switch {
	case neg:
		prefix = "-"
	case c.plus && signed:
		prefix = "+"
	case c.space && signed:
		prefix = " "
	}
	if !c.alt || v == 0 {
		return prefix, digits
	}
	switch c.verb {
	case 'x':
		prefix = "0x"
	case 'X':
		prefix = "0X"
	case 'o':
		if digits == "" || digits[0] != '0' {
			digits = "0" + digits
		}
	}
	return prefix, digits
}

// padField pads to the width with spaces, on the right when '-' is set.
func padField(c convSpec, s string, _ bool) string {
	invariant.Check(c.width <= 1024, "width bounded by the compile-time format check")
	invariant.Check(c.width >= 0, "width non-negative")
	for n := len(s); n < c.width; n++ {
		if c.minus {
			s += " "
		} else {
			s = " " + s
		}
	}
	return s
}

func upper(s string) string {
	invariant.Check(len(s) <= 1<<20, "formatted number bounded")
	b := []byte(s)
	for i := range b {
		b[i] = cToUpper(b[i])
	}
	return string(b)
}

// printfStr prints desc with its %s conversion applied to str (precision
// truncates, width pads).
func (s *scan) printfStr(desc string, str []byte) {
	invariant.Check(s.outLen <= maxOutput, "output length within cap")
	i := indexFrom(desc, 0, '%')
	if i >= len(desc) {
		s.writeString(desc)
		return
	}
	c := parseConv(desc, i)
	if !invariant.Check(c.verb == 's', "string value printed with %s") {
		s.truncate(TruncInvariant)
	}
	if c.hasPrec && c.prec < len(str) {
		str = str[:c.prec]
	}
	s.writeString(desc[:i])
	pad := c.width - len(str)
	if !c.minus {
		s.spaces(pad)
	}
	s.write(str)
	if c.minus {
		s.spaces(pad)
	}
	s.writeString(desc[c.end:])
}

// spaces writes n spaces; anything past the output cap would be truncated,
// so the loop is bounded by the cap (a %s width is not bounded at compile
// time: the reference's check_format bounds only numeric widths).
func (s *scan) spaces(n int) {
	if n > maxOutput {
		n = maxOutput
		s.truncate(TruncOutput)
	}
	for k := 0; k < n; k++ {
		s.writeByte(' ')
	}
}

// formatCFloat is a floating conversion as C's printf spells it. Go writes
// "NaN", "+Inf" and "-Inf"; glibc writes "nan" or "-nan" by the NaN's sign
// bit, and "inf" or "-inf".
func formatCFloat(f float64, verb byte, prec int) string {
	switch {
	case math.IsNaN(f) && math.Signbit(f):
		return "-nan"
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	default:
		return strconv.FormatFloat(f, verb, prec, 64)
	}
}

// printfFloat prints desc with its floating conversion applied.
func (s *scan) printfFloat(desc string, f float64) {
	invariant.Check(s.outLen <= maxOutput, "output length within cap")
	i := indexFrom(desc, 0, '%')
	if i >= len(desc) {
		s.writeString(desc)
		return
	}
	c := parseConv(desc, i)
	prec := 6
	if c.hasPrec {
		prec = c.prec
	}
	var str string
	switch c.verb {
	case 'e', 'E', 'f', 'F', 'g', 'G':
		str = formatCFloat(f, lower(c.verb), prec)
		if c.verb == 'E' || c.verb == 'G' || c.verb == 'F' {
			str = upper(str)
		}
	default:
		str = "%" + string(c.verb)
	}
	if c.plus && !math.Signbit(f) {
		str = "+" + str
	}
	s.writeString(desc[:i])
	s.writeString(padField(c, str, false))
	s.writeString(desc[c.end:])
}
