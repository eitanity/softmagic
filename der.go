// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from der.c, file 5.48, Copyright (c) Ian F. Darwin 1986-1995
// (see COPYING): the "der" test type, which walks ASN.1 DER tag-length-
// value elements. The reference's reading of a tag's long form, which
// leaves the final byte unconsumed, is reproduced as written.

package softmagic

import (
	"strconv"

	"github.com/eitanity/softmagic/internal/invariant"
)

const derBad = 0xffffffff

// derTagNames is der__tag: the names the rules use for universal tags.
func derTagName(tag uint32) string {
	names := [...]string{
		"eoc", "bool", "int", "bit_str", "octet_str",
		"null", "obj_id", "obj_desc", "ext", "real",
		"enum", "embed", "utf8_str", "rel_oid", "time",
		"res2", "seq", "set", "num_str", "prt_str",
		"t61_str", "vid_str", "ia5_str", "utc_time", "gen_time",
		"gr_str", "vis_str", "gen_str", "univ_str", "char_str",
		"bmp_str", "date", "tod", "datetime", "duration",
		"oid-iri", "rel-oid-iri",
	}
	if tag < uint32(len(names)) {
		return names[tag]
	}
	return "0x" + strconv.FormatUint(uint64(tag), 16)
}

// derTag is gettag: the tag number at c[p], advancing p.
func derTag(c []byte, p *int) uint32 { // content
	invariant.Check(*p >= 0, "cursor non-negative")
	if *p >= len(c) {
		return derBad
	}
	tag := uint32(c[*p] & 0x1f)
	*p++
	if tag != 0x1f {
		return tag
	}
	if *p >= len(c) {
		return derBad
	}
	i := *p // cursor
	for ; i < len(c) && c[i] >= 0x80; i++ {
		tag = tag*128 + uint32(c[i]) - 0x80
		if i+1 >= len(c) {
			*p = i + 1
			return derBad
		}
	}
	*p = i
	return tag
}

// derLength is getlength: the element length at c[p], advancing p.
func derLength(c []byte, p *int) uint32 { // content
	invariant.Check(*p >= 0, "cursor non-negative")
	l := len(c) // contentLength
	if *p >= l {
		return derBad
	}
	oneByte := c[*p]&0x80 == 0
	digits := int(c[*p] & 0x7f)
	*p++
	if *p+digits >= l {
		return derBad
	}
	if oneByte {
		return uint32(digits)
	}
	n := uint64(0) // length
	for i := 0; i < digits; i++ {
		n = n<<8 | uint64(c[*p])
		*p++
	}
	if n > 0xffffffff-bitsOfInt64(int64(*p)) || bitsOfInt64(int64(*p))+n > bitsOfInt64(int64(l)) {
		return derBad
	}
	return low32(n)
}

// derData is der_data: the element's value as the rule compares it, into
// buf (128 bytes as the reference's).
func derData(buf []byte, tag uint32, d []byte) []byte { // elementValue
	invariant.Check(len(buf) == maxString, "der buffer is MAXstring")
	switch tag {
	case 0x13, 0x0c, 0x16: // printable, utf8, ia5 strings: %.*s
		n := 0
		for ; n < len(d) && n < len(buf)-1 && d[n] != 0; n++ {
		}
		return append(buf[:0], d[:n]...)
	case 0x17: // utc_time
		if len(d) >= 12 {
			return append(buf[:0], "20"+string(d[0:2])+"-"+string(d[2:4])+"-"+string(d[4:6])+
				" "+string(d[6:8])+":"+string(d[8:10])+":"+string(d[10:12])+" GMT"...)
		}
	default:
	}
	out := buf[:0]
	for i := 0; i < len(d) && 2*i < len(buf)-2; i++ {
		out = append(out, hexDigits[d[i]>>4], hexDigits[d[i]&0xf])
	}
	return out
}

// derOffs is der_offs: the offset of the element's value, with the parent
// level's continuation offset moved past the element so siblings follow.
func (s *scan) derOffs(m *record, f *frame) (int32, bool) { // frame
	invariant.Check(s.search.valid, "der region set")
	b := s.buf[s.search.start : s.search.start+s.search.length] // searchRegion
	if s.search.length == 0 {
		b = s.buf[s.search.start:]
	}
	p := 0 // cursor
	if derTag(b, &p) == derBad {
		return 0, false
	}
	tlen := derLength(b, &p)
	if tlen == derBad {
		return 0, false
	}
	offs := int64(p) + int64(s.offset) + int64(m.offset)
	if m.contLevel != 0 {
		if offs+int64(tlen) > int64(f.n) {
			return 0, false
		}
		s.levels[m.contLevel-1].off = wrapInt32(offs + int64(tlen))
	}
	return wrapInt32(offs), true
}

// derCmp is der_cmp: match the element against the rule's "tag[len][=data]".
func (s *scan) derCmp(m *record) bool { // rule
	invariant.Check(m.typ == tDer, "der line")
	if !s.search.valid {
		return false
	}
	b := s.buf[s.search.start : s.search.start+s.search.length] // searchRegion
	p := 0                                                      // cursor
	tag := derTag(b, &p)
	if tag == derBad {
		return false
	}
	tlen := derLength(b, &p)
	if tlen == derBad {
		return false
	}
	name := derTagName(tag)
	spec := m.valueString()
	if len(spec) < len(name) || spec[:len(name)] != name {
		return false
	}
	rest := spec[len(name):]
	if len(rest) > 0 && cIsDigit(rest[0]) {
		want, end, _ := strtoull([]byte(rest), 0, 10)
		if want != uint64(tlen) {
			return false
		}
		rest = rest[end:]
	}
	if rest == "" {
		return true
	}
	if rest[0] != '=' {
		return false
	}
	want := rest[1:]
	data := derData(s.rxScratch(maxString), tag, b[p:p+int(tlen)])
	if string(data) != want && want != "x" {
		return false
	}
	for i := range s.value {
		s.value[i] = 0
	}
	copy(s.value[:maxString-1], data)
	return true
}
