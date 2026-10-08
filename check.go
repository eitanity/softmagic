// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from magiccheck and file_strncmp in softmagic.c, file 5.48,
// Copyright (c) Ian F. Darwin 1986-1995 (see COPYING).

package softmagic

import (
	"github.com/eitanity/softmagic/internal/invariant"

	"bytes"
	"encoding/binary"
	"math"
)

// magicCheck compares the converted value in s.value with the rule's.
func (s *scan) magicCheck(m *record, f *frame) bool { // rule
	invariant.Check(f.idx >= 0 && f.idx < f.count, "checking a line within the frame")
	invariant.Check(m.reln != 0, "line has a relation")
	l := binary.LittleEndian.Uint64(m.value[0:8]) // lineValue
	var v uint64                                  // fileValue
	switch {
	case m.typ == tByte:
		v = uint64(s.value[0])
	case isWidth2(m.typ):
		v = uint64(binary.LittleEndian.Uint16(s.value[:]))
	case isWidth4(m.typ) && !isFloatType(m.typ):
		v = uint64(binary.LittleEndian.Uint32(s.value[:]))
	case isWidth8(m.typ) && !isDoubleType(m.typ), m.typ == tOffset:
		v = binary.LittleEndian.Uint64(s.value[:])
	case isFloatType(m.typ):
		return compareFloat(m.reln, float64(math.Float32frombits(binary.LittleEndian.Uint32(m.value[0:4]))),
			float64(math.Float32frombits(binary.LittleEndian.Uint32(s.value[:]))))
	case isDoubleType(m.typ):
		return compareFloat(m.reln, math.Float64frombits(binary.LittleEndian.Uint64(m.value[0:8])),
			math.Float64frombits(binary.LittleEndian.Uint64(s.value[:])))
	case m.typ == tDefault || m.typ == tClear:
		l, v = 0, 0
	case m.typ == tString || m.typ == tPString || m.typ == tOctal:
		l, v = 0, strncmp(m.valueBytes(), s.value[:], int(m.vallen), maxString, m.strFlags())
	case m.typ == tBeString16 || m.typ == tLeString16:
		l, v = 0, strncmp(m.valueBytes(), s.value[:], int(m.vallen), maxString, 0)
	case m.typ == tSearch:
		l, v = 0, s.searchCheck(m, f.first+f.idx)
	case m.typ == tRegex:
		l, v = 0, s.regexCheck(f)
	case m.typ == tUse:
		return binary.LittleEndian.Uint64(s.value[0:8]) != 0
	case m.typ == tName || m.typ == tIndirect:
		return true
	case m.typ == tDer:
		return s.derCmp(m)
	case m.typ == tBeGUID || m.typ == tLeGUID || m.typ == tGUID:
		l, v = 0, memcmpBits(m.value[0:16], s.value[0:16])
	default:
		return s.fail("magiccheck on a type it does not handle")
	}
	return compareInt(m, signExtend(&m.recordHead, v), l)
}

func isFloatType(t fileType) bool  { return t == tFloat || t == tBeFloat || t == tLeFloat }
func isDoubleType(t fileType) bool { return t == tDouble || t == tBeDouble || t == tLeDouble }

// memcmpBits is memcmp's result as the reference stores it: 0 equal,
// otherwise non-zero.
func memcmpBits(a, b []byte) uint64 {
	c := bytes.Compare(a, b)
	if c == 0 {
		return 0
	}
	return bitsOfInt64(int64(c))
}

// compareInt applies the relation to the file value v and rule value l.
func compareInt(m *record, v, l uint64) bool { // rule
	invariant.Check(m.reln != 0, "line has a relation")
	switch m.reln {
	case 'x':
		return true
	case '!':
		return v != l
	case '=':
		return v == l
	case '>':
		if m.flag&flagUnsigned != 0 {
			return v > l
		}
		return int64FromBits(v) > int64FromBits(l)
	case '<':
		if m.flag&flagUnsigned != 0 {
			return v < l
		}
		return int64FromBits(v) < int64FromBits(l)
	case '&':
		return v&l == l
	case '^':
		return v&l != l
	default:
		return false
	}
}

// compareFloat is the float/double branch of magiccheck: unordered values
// (NaN) match only '!' and 'x'.
func compareFloat(reln uint8, l, v float64) bool { // lineValue
	invariant.Check(reln != 0, "relation given")
	unordered := math.IsNaN(l) || math.IsNaN(v)
	switch reln {
	case 'x':
		return true
	case '!':
		return unordered || v != l
	case '=':
		return !unordered && v == l
	case '>':
		return !unordered && v > l
	case '<':
		return !unordered && v < l
	default:
		return false
	}
}

func cIsLower(c byte) bool { return c >= 'a' && c <= 'z' }
func cIsUpper(c byte) bool { return c >= 'A' && c <= 'Z' }

func cToLower(c byte) byte {
	if cIsUpper(c) {
		return c + ('a' - 'A')
	}
	return c
}

func cToUpper(c byte) byte {
	if cIsLower(c) {
		return c - ('a' - 'A')
	}
	return c
}

// strncmp is file_strncmp: compare the rule string a against the file
// bytes b for n bytes with the string modifier flags; 0 means equal, and
// otherwise the (wrapped) difference of the first differing bytes.
func strncmp(a, b []byte, n, maxlen int, flags uint32) uint64 { // compareLength
	invariant.Check(n >= 0 && maxlen >= 0, "lengths non-negative")
	if flags == 0 {
		return strncmpPlain(a, b, n)
	}
	if flags&(strCompactWhitespace|strCompactOptionalWhitespace) == 0 {
		return strncmpCase(a, b, n, flags)
	}
	ws := flags&(strCompactWhitespace|strCompactOptionalWhitespace) != 0
	eb := n // compareEnd
	if ws {
		eb = maxlen
	}
	if eb > len(b) {
		eb = len(b)
	}
	c := strCursor{a: a, b: b, eb: eb, flags: flags} // cursor
	for k := 0; k < n; k++ {
		if c.bi >= eb {
			return 1
		}
		if v := c.step(); v != 0 {
			return v
		}
	}
	if flags&strFullWord != 0 && c.bi < len(b) && b[c.bi] != 0 && !cIsSpace(b[c.bi]) {
		return 1
	}
	return 0
}

// strCursor is the state of a flagged string comparison.
type strCursor struct {
	a, b   []byte
	ai, bi int
	eb     int
	flags  uint32
}

// step compares one rule character under the flags and returns the
// difference, 0 when equal so far.
func (c *strCursor) step() uint64 {
	invariant.Check(c.bi < c.eb, "file cursor within the compared range")
	ca := at(c.a, c.ai) // lineChar
	switch {
	case c.flags&strIgnoreLowercase != 0 && cIsLower(ca):
		c.ai, c.bi = c.ai+1, c.bi+1
		return diff(cToLower(c.b[c.bi-1]), ca)
	case c.flags&strIgnoreUppercase != 0 && cIsUpper(ca):
		c.ai, c.bi = c.ai+1, c.bi+1
		return diff(cToUpper(c.b[c.bi-1]), ca)
	case c.flags&strCompactWhitespace != 0 && cIsSpace(ca):
		c.ai++
		if !cIsSpace(c.b[c.bi]) {
			return 1
		}
		c.bi++
		if !cIsSpace(at(c.a, c.ai)) {
			c.bi = skipSpaces(c.b, c.bi, c.eb)
		}
		return 0
	case c.flags&strCompactOptionalWhitespace != 0 && cIsSpace(ca):
		c.ai++
		c.bi = skipSpaces(c.b, c.bi, c.eb)
		return 0
	default:
		c.ai, c.bi = c.ai+1, c.bi+1
		return diff(c.b[c.bi-1], ca)
	}
}

// strncmpCase is strncmp for modifiers that do not compact whitespace:
// each byte compares directly, folded under /c and /C, and /f requires a
// word boundary after the string. It is the general loop specialised, and
// returns what it would.
func strncmpCase(a, b []byte, n int, flags uint32) uint64 { // fileBytes
	invariant.Check(flags&(strCompactWhitespace|strCompactOptionalWhitespace) == 0, "no whitespace compaction")
	lower, upper := flags&strIgnoreLowercase != 0, flags&strIgnoreUppercase != 0
	for k := 0; k < n; k++ {
		ca, cb := at(a, k), at(b, k) // lineChar
		switch {
		case lower && cIsLower(ca):
			cb = cToLower(cb)
		case upper && cIsUpper(ca):
			cb = cToUpper(cb)
		}
		if cb != ca {
			return diff(cb, ca)
		}
	}
	if flags&strFullWord != 0 && n < len(b) && b[n] != 0 && !cIsSpace(b[n]) {
		return 1
	}
	return 0
}

// strncmpPlain is the fast path: n bytes, NULs included.
func strncmpPlain(a, b []byte, n int) uint64 {
	invariant.Check(n >= 0, "length non-negative")
	for k := 0; k < n; k++ {
		if v := diff(at(b, k), at(a, k)); v != 0 {
			return v
		}
	}
	return 0
}

// diff is the C expression `*b - *a` on unsigned chars, as a uint64.
func diff(b, a byte) uint64 {
	return bitsOfInt64(int64(b) - int64(a))
}

func skipSpaces(b []byte, i, end int) int {
	for ; i < end && cIsSpace(b[i]); i++ {
	}
	return i
}

// searchCheck scans the search region for the rule string within the
// rule's range; 0 means found.
func (s *scan) searchCheck(m *record, rec int32) uint64 { // searchRule
	invariant.Check(m.typ == tSearch, "search line")
	invariant.Check(!s.search.valid || s.search.start+s.search.length <= len(s.buf), "search region within the buffer")
	if !s.search.valid {
		return 1
	}
	region := s.buf[s.search.start : s.search.start+s.search.length]
	slen := int(m.vallen)
	if slen > maxString {
		slen = maxString
	}
	rng := int(m.strRange())
	limit := len(region)
	if rng != 0 && rng+slen < limit {
		limit = rng + slen
	}
	s.noteRead(s.search.start + limit)
	key := s.regionKey(memoSearch, rec)
	found, _, hit := s.memoGet(key)
	if !hit {
		found = -1
		if idx := searchRun(m, region, slen, rng, limit); idx >= 0 {
			found = smallInt32(idx)
		}
		s.memoPut(key, found, 0)
	}
	if found < 0 {
		return 1
	}
	s.search.offset += int(found)
	s.search.rmLen = len(region) - int(found)
	return 0
}

// searchRun finds the value in the region: the offset or -1.
func searchRun(m *record, region []byte, slen, rng, limit int) int { // searchRule
	invariant.Check(limit <= len(region), "limit within the region")
	invariant.Check(slen >= 0 && slen <= maxString, "search string within MAXstring")
	if slen > 0 && m.strFlags() == 0 {
		return bytes.Index(region[:limit], m.valueBytes())
	}
	return searchFlagged(m, region, slen, rng)
}

// searchFlagged is the position-by-position search for a string with
// modifier flags; -1 when not found within the range.
func searchFlagged(m *record, region []byte, slen, rng int) int { // searchRule
	invariant.Check(slen >= 0 && slen <= maxString, "search string within MAXstring")
	invariant.Check(rng >= 0, "range non-negative")
	tries := rng
	if tries == 0 || tries > len(region) {
		tries = len(region)
	}
	flags := m.strFlags()
	value := m.valueBytes()
	if slen > 0 && !cIsSpace(value[0]) {
		return searchByCandidate(m, region, slen, tries)
	}
	for idx := 0; idx <= tries; idx++ {
		if slen+idx > len(region) {
			return -1
		}
		if strncmp(value, region[idx:], slen, len(region)-idx, flags) == 0 {
			return idx
		}
	}
	return -1
}

// searchByCandidate is searchFlagged for a value that does not start
// with whitespace: whatever the flags, strncmp's first step then
// compares that byte directly under the case rules, so only the
// positions holding it (in either case the flags allow) are tried.
func searchByCandidate(m *record, region []byte, slen, tries int) int {
	invariant.Check(slen > 0 && slen <= maxString, "search string within MAXstring")
	invariant.Check(!cIsSpace(m.valueBytes()[0]), "value starts with a non-space byte")
	invariant.Check(tries >= 0 && tries <= len(region), "tries within the region")
	flags := m.strFlags()
	value := m.valueBytes()
	c1 := value[0] // firstChar
	c2 := c1       // otherCaseChar
	switch {
	case flags&strIgnoreLowercase != 0 && cIsLower(c1):
		c2 = cToUpper(c1)
	case flags&strIgnoreUppercase != 0 && cIsUpper(c1):
		c2 = cToLower(c1)
	}
	last := tries
	if len(region)-slen < last {
		last = len(region) - slen
	}
	for idx := 0; idx <= last; idx++ {
		j := nextCandidate(region[idx:last+1], c1, c2)
		if j < 0 {
			return -1
		}
		idx += j
		invariant.Check(firstByteMatches(c1, region[idx], flags), "candidate passes the first-byte rule")
		if strncmp(value, region[idx:], slen, len(region)-idx, flags) == 0 {
			return idx
		}
	}
	return -1
}

// firstByteMatches is strncmp's comparison of the first byte under /c
// and /C.
func firstByteMatches(ca, cb byte, flags uint32) bool { // fileChar
	switch {
	case flags&strIgnoreLowercase != 0 && cIsLower(ca):
		return cToLower(cb) == ca
	case flags&strIgnoreUppercase != 0 && cIsUpper(ca):
		return cToUpper(cb) == ca
	default:
		return cb == ca
	}
}

// regexCheck runs the compiled RE2 over the region, which the reference
// treats as a C string: it stops at the first NUL and drops its last byte.
// The region is transcoded byte-to-rune so that RE2 sees byte 0xNN as rune
// U+00NN, and the match indices are mapped back.
func (s *scan) regexCheck(f *frame) uint64 {
	invariant.Check(!s.search.valid || s.search.start+s.search.length <= len(s.buf), "regex region within the buffer")
	if !s.search.valid {
		return 1
	}
	rec := f.first + f.idx
	key := s.regionKey(memoRegex, rec)
	so, eo, hit := s.memoGet(key) // startOffset
	if !hit {
		var ok bool
		if so, eo, ok = s.regexRun(rec); !ok {
			return s.boolFail("regex line has a compiled pattern")
		}
		s.memoPut(key, so, eo)
	}
	if so < 0 {
		return 1
	}
	s.search.start += int(so)
	s.search.offset += int(so)
	s.search.rmLen = int(eo - so)
	return 0
}

// regexRun evaluates a regex line over the current region: the match's
// start and end as region offsets, start -1 when there is none. ok is
// false when the line has no compiled pattern.
func (s *scan) regexRun(rec int32) (int32, int32, bool) {
	invariant.Check(s.search.valid, "region set")
	slot := s.db.regexSlot(rec)
	re := s.db.regex(rec) // regex
	if slot == nil || re == nil {
		return -1, -1, false
	}
	region := s.buf[s.search.start : s.search.start+s.search.length]
	if len(region) > 0 {
		region = region[:len(region)-1]
	}
	if nul := bytes.IndexByte(region, 0); nul >= 0 {
		region = region[:nul]
	}
	if len(slot.lits) != 0 && !slot.possible(region) {
		return -1, -1, true
	}
	buf := s.rxScratch(2 * len(region))
	n := transcodeLatin1(buf, region) // transcodedLength
	loc := re.FindIndex(buf[:n])
	if loc == nil {
		return -1, -1, true
	}
	invariant.Check(loc[0] <= loc[1] && loc[1] <= n, "match within the transcoded region")
	so := originalOffset(buf[:n], loc[0])
	eo := originalOffset(buf[:n], loc[1])
	return smallInt32(so), smallInt32(eo), true
}

// boolFail is fail for callers that return a mismatch value.
func (s *scan) boolFail(what string) uint64 {
	s.fail(what)
	return 1
}

// transcodeLatin1 writes each byte of src as the UTF-8 encoding of the
// rune with the same value into dst and returns the length written.
func transcodeLatin1(dst, src []byte) int {
	invariant.Check(len(dst) >= 2*len(src) || len(src) > regexMax, "transcoding fits")
	n := 0 // writtenCount
	for i := 0; i < len(src) && n+1 < len(dst); i++ {
		c := src[i] // sourceByte
		if c < 0x80 {
			dst[n] = c
			n++
			continue
		}
		dst[n] = 0xc0 | c>>6
		dst[n+1] = 0x80 | c&0x3f
		n += 2
	}
	return n
}

// originalOffset maps an index into the transcoded buffer back to the
// index in the source bytes: every lead byte 0xC2/0xC3 before it stood for
// one source byte together with its continuation.
func originalOffset(transcoded []byte, idx int) int {
	invariant.Check(idx >= 0, "index non-negative")
	o := 0 // sourceOffset
	for i := 0; i < idx && i < len(transcoded); i++ {
		if transcoded[i]&0xc0 != 0x80 {
			o++
		}
	}
	return o
}
