// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from check_format and check_format_type in apprentice.c, file
// 5.48, Copyright (c) Ian F. Darwin 1986-1995 (see COPYING).

package softmagic

import "github.com/eitanity/softmagic/internal/invariant"

// checkFormat verifies that the description's one printf conversion, if
// any, is valid for the record's type.
func (p *lineParser) checkFormat() error {
	invariant.Check(p.rec != nil, "record to check")
	r := p.rec
	d := r.desc[:]
	i := 0
	for ; i < len(d) && d[i] != 0 && d[i] != '%'; i++ {
	}
	if i >= len(d) || d[i] == 0 {
		return nil
	}
	if formatClass(r.typ) == fmtNone {
		return p.errorf("no format string for `" + r.descString() + "' with type `" + typeName(r.typ) + "'")
	}
	end, ok := checkFormatType(d, i+1, r.typ)
	if !ok {
		return p.errorf("printf format is not valid for type `" + typeName(r.typ) +
			"' in description `" + r.descString() + "'")
	}
	for j := end; j < len(d) && d[j] != 0; j++ {
		if d[j] == '%' {
			return p.errorf("too many format strings for `" + typeName(r.typ) +
				"' with description `" + r.descString() + "'")
		}
	}
	return nil
}

// checkFormatType validates the conversion starting at d[i] (after '%') and
// returns the index after it.
func checkFormatType(d []byte, i int, t fileType) (int, bool) {
	invariant.Check(i > 0, "conversion follows a percent")
	if at(d, i) == 0 {
		return i, false
	}
	switch formatClass(t) {
	case fmtQuad:
		return checkNumFormat(d, i, true, 0)
	case fmtNum:
		return checkNumFormat(d, i, false, numFormatH(t))
	case fmtFloat, fmtDouble:
		return checkFloatFormat(d, i)
	case fmtStr:
		return checkStrFormat(d, i)
	default:
		return i, false
	}
}

// numFormatH is the `h` budget of check_format_type: how many 'h' modifiers
// the type could take. Without STRICT_FORMAT it only decides whether %c is
// allowed (bytes only).
func numFormatH(t fileType) int {
	switch t {
	case tByte:
		return 2
	case tShort, tBeShort, tLeShort:
		return 1
	default:
		return 0
	}
}

// checkLen is the CHECKLEN macro: at most five digits, value at most 1024.
func checkLen(d []byte, i int) (int, bool) {
	invariant.Check(i >= 0, "cursor non-negative")
	invariant.Check(i <= len(d), "cursor within the description")
	n, cnt := 0, 0
	for ; i < len(d) && cIsDigit(d[i]); i++ {
		n = n*10 + int(d[i]-'0')
		cnt++
	}
	return i, cnt <= 5 && n <= 1024
}

func checkNumFormat(d []byte, i int, quad bool, h int) (int, bool) {
	invariant.Check(i >= 0, "cursor non-negative")
	invariant.Check(i <= len(d), "cursor within the description")
	for ; i < len(d) && isNumFlag(d[i]); i++ {
	}
	i, ok := checkLen(d, i)
	if !ok {
		return i, false
	}
	if at(d, i) == '.' {
		i++
	}
	i, ok = checkLen(d, i)
	if !ok {
		return i, false
	}
	if quad {
		if at(d, i) != 'l' || at(d, i+1) != 'l' {
			return i, false
		}
		i += 2
	}
	switch at(d, i) {
	case 'c':
		return i + 1, h == 2
	case 'i', 'd', 'u', 'o', 'x', 'X':
		return i + 1, true
	default:
		return i, false
	}
}

func checkFloatFormat(d []byte, i int) (int, bool) {
	invariant.Check(i >= 0, "cursor non-negative")
	invariant.Check(i <= len(d), "cursor within the description")
	if at(d, i) == '-' {
		i++
	}
	if at(d, i) == '.' {
		i++
	}
	i, ok := checkLen(d, i)
	if !ok {
		return i, false
	}
	if at(d, i) == '.' {
		i++
	}
	i, ok = checkLen(d, i)
	if !ok {
		return i, false
	}
	switch at(d, i) {
	case 'e', 'E', 'f', 'F', 'g', 'G':
		return i + 1, true
	default:
		return i, false
	}
}

func isNumFlag(c byte) bool { return c == '+' || c == '-' || c == '.' || c == '#' }

func checkStrFormat(d []byte, i int) (int, bool) {
	invariant.Check(i >= 0, "cursor non-negative")
	invariant.Check(i <= len(d), "cursor within the description")
	if at(d, i) == '-' {
		i++
	}
	for ; i < len(d) && cIsDigit(d[i]); i++ {
	}
	if at(d, i) == '.' {
		i++
		for ; i < len(d) && cIsDigit(d[i]); i++ {
		}
	}
	if at(d, i) == 's' {
		return i + 1, true
	}
	return i, false
}
