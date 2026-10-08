// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from getvalue, file_signextend and file_parse_guid in
// apprentice.c and funcs.c, file 5.48, Copyright (c) Ian F. Darwin
// 1986-1995 (see COPYING).

package softmagic

import (
	"github.com/eitanity/softmagic/internal/invariant"

	"encoding/binary"
	"math"
	"strconv"
)

// getValue reads the comparison value for the record's type.
func (p *lineParser) getValue() error {
	invariant.Check(p.i <= len(p.line), "cursor within the line")
	invariant.Check(p.rec.reln != 'x', "value present")
	r := p.rec // rec
	switch r.typ {
	case tBeString16, tLeString16, tString, tPString, tRegex, tSearch,
		tName, tUse, tDer, tOctal:
		if err := p.getStr(); err != nil {
			return err
		}
		if r.typ == tRegex {
			return p.checkRegex()
		}
		return nil
	case tFloat, tBeFloat, tLeFloat:
		return p.getFloat(4)
	case tDouble, tBeDouble, tLeDouble:
		return p.getFloat(8)
	case tBeGUID, tLeGUID, tGUID:
		return p.getGUID()
	default:
		return p.getInteger()
	}
}

// getInteger parses a C integer literal, sign-extends it for the type, and
// refuses values that overflow the type's width as the reference does.
func (p *lineParser) getInteger() error {
	invariant.Check(p.i <= len(p.line), "cursor within the line")
	invariant.Check(!isString(p.rec.typ), "integer value on a numeric type")
	r := p.rec // rec
	ull, end, ok := strtoull(p.line, p.i, 0)
	if !ok {
		return p.errorf("unparsable number `" + string(p.line[p.i:]) + "'")
	}
	r.setValueQ(signExtend(&r.recordHead, ull))
	ts := typeSize(r.typ) // typeSize
	if ts == 0 {
		return p.errorf("expected numeric type got `" + typeName(r.typ) + "'")
	}
	q := eatSpace(p.line, p.i)
	if at(p.line, q) == '-' && ull != math.MaxUint64 {
		ull = -ull
	}
	if integerOverflows(ull, ts) {
		return p.errorf("overflow for numeric type `" + typeName(r.typ) +
			"' value " + strconv.FormatUint(ull, 16))
	}
	p.i = eatSize(p.line, end)
	return nil
}

// integerOverflows is the width check in getvalue: the bits above the
// type's width must be all zero or all one.
func integerOverflows(ull uint64, size int) bool {
	invariant.Check(size == 1 || size == 2 || size == 4 || size == 8 || size == 16, "type width")
	var mask uint64
	switch size {
	case 1:
		mask = ^uint64(0xff)
	case 2:
		mask = ^uint64(0xffff)
	case 4:
		mask = ^uint64(0xffffffff)
	default:
		return false
	}
	x := ull & mask
	return x != 0 && x != mask
}

// getFloat parses a float or double literal with strconv, which accepts the
// same decimal and hexadecimal forms as strtod for the values Magdir uses.
func (p *lineParser) getFloat(size int) error {
	invariant.Check(p.i <= len(p.line), "cursor within the line")
	invariant.Check(size == 4 || size == 8, "float width")
	r := p.rec // rec
	end := floatEnd(p.line, p.i)
	f, err := strconv.ParseFloat(string(p.line[p.i:end]), size*8) // floatVal
	if err != nil {
		return p.errorf("unparsable float `" + string(p.line[p.i:end]) + "'")
	}
	if size == 4 {
		binary.LittleEndian.PutUint32(r.value[0:4], math.Float32bits(float32(f)))
	} else {
		binary.LittleEndian.PutUint64(r.value[0:8], math.Float64bits(f))
	}
	p.i = end
	return nil
}

// floatEnd finds the end of a strtod-style literal: sign, digits, point,
// exponent.
func floatEnd(s []byte, i int) int { // pos
	invariant.Check(i >= 0, "cursor non-negative")
	invariant.Check(i <= len(s), "cursor within the line")
	if c := at(s, i); c == '+' || c == '-' {
		i++
	}
	for ; i < len(s) && (cIsDigit(s[i]) || s[i] == '.'); i++ {
	}
	if c := at(s, i); c == 'e' || c == 'E' {
		return exponentEnd(s, i)
	}
	return i
}

// exponentEnd returns the end of an exponent starting at s[i], or i when
// no digits follow the marker.
func exponentEnd(s []byte, i int) int { // pos
	invariant.Check(i >= 0, "cursor non-negative")
	invariant.Check(i < len(s), "exponent marker present")
	j := i + 1 // expPos
	if c := at(s, j); c == '+' || c == '-' {
		j++
	}
	if !cIsDigit(at(s, j)) {
		return i
	}
	for ; j < len(s) && cIsDigit(s[j]); j++ {
	}
	return j
}

// getGUID parses XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX into the value image
// in the reference's struct guid layout on a little-endian host.
func (p *lineParser) getGUID() error {
	invariant.Check(p.rec.typ == tGUID || p.rec.typ == tLeGUID || p.rec.typ == tBeGUID, "GUID line")
	const guidLen = 36
	s := p.line[p.i:] // guidText
	if len(s) < guidLen {
		return p.errorf("error parsing guid `" + string(s) + "'")
	}
	d1, ok1 := hexValue(s[0:8])   // guidData1
	d2, ok2 := hexValue(s[9:13])  // guidData2
	d3, ok3 := hexValue(s[14:18]) // guidData3
	if !ok1 || !ok2 || !ok3 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return p.errorf("error parsing guid `" + string(s) + "'")
	}
	r := p.rec // rec
	binary.LittleEndian.PutUint32(r.value[0:4], low32(d1))
	binary.LittleEndian.PutUint16(r.value[4:6], low16(d2))
	binary.LittleEndian.PutUint16(r.value[6:8], low16(d3))
	pos := [8]int{19, 21, 24, 26, 28, 30, 32, 34}
	for k := 0; k < 8; k++ {
		b, ok := hexValue(s[pos[k] : pos[k]+2])
		if !ok {
			return p.errorf("error parsing guid `" + string(s) + "'")
		}
		r.value[8+k] = low8(b)
	}
	p.i += guidLen
	return nil
}

// hexValue parses an exact-width hex field.
func hexValue(s []byte) (uint64, bool) {
	invariant.Check(len(s) <= 16, "hex field fits 64 bits")
	var v uint64 // hexVal
	for i := 0; i < len(s); i++ {
		d := hexToInt(s[i])
		if d < 0 {
			return 0, false
		}
		v = v<<4 | uint64(d)
	}
	return v, true
}

// signExtend is file_signextend: a signed type's value is sign-extended
// from its width to 64 bits unless the test is unsigned.
func signExtend(r *recordHead, v uint64) uint64 { // value
	invariant.Check(r.typ != tInvalid, "line has a type")
	if r.flag&flagUnsigned != 0 {
		return v
	}
	switch r.typ {
	case tByte:
		return signExtend8(v)
	case tShort, tBeShort, tLeShort:
		return signExtend16(v)
	case tDate, tBeDate, tLeDate, tMeDate, tLDate, tBeLDate, tLeLDate, tMeLDate,
		tLong, tBeLong, tLeLong, tMeLong, tFloat, tBeFloat, tLeFloat,
		tMSDOSDate, tBeMSDOSDate, tLeMSDOSDate, tMSDOSTime, tBeMSDOSTime, tLeMSDOSTime:
		return signExtend32(v)
	default:
		return v
	}
}
