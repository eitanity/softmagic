// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from getstr in apprentice.c, file 5.48, Copyright (c) Ian F.
// Darwin 1986-1995 (see COPYING).

package softmagic

import "github.com/eitanity/softmagic/internal/invariant"

// getStr decodes the C character escapes of the value at the cursor into
// rec.value, stopping at an unescaped space or tab, and sets rec.vallen.
// The reference's warnings (escaped dot, needless escape) are not errors and
// are not reproduced; its one error, a value longer than MAXstring-1, is.
func (p *lineParser) getStr() error {
	invariant.Check(p.i <= len(p.line), "cursor within the line")
	s, i, n := p.line, p.i, 0
	var next int
	for ; i < len(s) && !cIsSpace(s[i]); i = next {
		if !invariant.Check(n <= maxString, "value fits MAXstring") || n >= maxString-1 {
			return p.errorf("string too long: `" + string(s[p.i:]) + "'")
		}
		c := s[i]
		next = i + 1
		if c != '\\' {
			p.rec.value[n] = c
			n++
			continue
		}
		if next >= len(s) {
			next = len(s) // incomplete escape: the reference warns and stops at the end
			continue
		}
		b, after := decodeEscape(s, next)
		p.rec.value[n] = b
		n++
		next = after
	}
	p.i = i
	p.rec.value[n] = 0
	p.rec.vallen = smallUint8(n)
	if p.rec.typ == tPString {
		l := pstringLengthSize(p.rec.strFlags())
		if l == 0 || n+l > maxString {
			return p.errorf("bad pascal string length")
		}
		p.rec.vallen = smallUint8(n + l)
	}
	return nil
}

// decodeEscape decodes the escape whose first byte after the backslash is at
// s[i]; it returns the byte and the index after the escape.
func decodeEscape(s []byte, i int) (byte, int) {
	invariant.Check(i > 0 && i < len(s), "escape has a character")
	c := s[i]
	i++
	switch c {
	case 'a':
		return '\a', i
	case 'b':
		return '\b', i
	case 'f':
		return '\f', i
	case 'n':
		return '\n', i
	case 'r':
		return '\r', i
	case 't':
		return '\t', i
	case 'v':
		return '\v', i
	case '0', '1', '2', '3', '4', '5', '6', '7':
		return decodeOctal(s, i, int(c-'0'))
	case 'x':
		return decodeHex(s, i)
	default:
		// Relations, space, backslash and anything else stand for themselves.
		return c, i
	}
}

// decodeOctal reads up to two more octal digits after the first.
func decodeOctal(s []byte, i, val int) (byte, int) {
	invariant.Check(i > 0 && i <= len(s), "after the first digit")
	invariant.Check(val >= 0 && val <= 7, "first octal digit")
	for k := 0; k < 2; k++ {
		c := at(s, i)
		if c < '0' || c > '7' {
			break
		}
		val = val<<3 | int(c-'0')
		i++
	}
	return byte(val & 0xff), i
}

// decodeHex reads up to two hex digits; with none the result is a literal 'x'.
func decodeHex(s []byte, i int) (byte, int) {
	invariant.Check(i > 0, "after the escape character")
	invariant.Check(i <= len(s), "cursor within the value")
	val := int('x')
	for k := 0; k < 2; k++ {
		d := hexToInt(at(s, i))
		if d < 0 {
			break
		}
		if k == 0 {
			val = d
		} else {
			val = val<<4 + d
		}
		i++
	}
	return byte(val & 0xff), i
}

// pstringLengthSize is file_pstring_length_size; 0 is FILE_BADSIZE.
func pstringLengthSize(flags uint32) int {
	switch flags & pstringLen {
	case pstring1LE:
		return 1
	case pstring2LE, pstring2BE:
		return 2
	case pstring4LE, pstring4BE:
		return 4
	default:
		return 0
	}
}
