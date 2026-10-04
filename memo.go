// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"github.com/eitanity/softmagic/internal/invariant"

	"bytes"
)

// A call computes the description and then the MIME, extension and Apple
// answers in separate passes over the same windows, as the reference does
// in separate processes. A regex or search line evaluated on the same
// window region gives the same answer every pass, so each pass after the
// first takes it from here. The table is fixed-size and direct-mapped: a
// collision costs one recomputation, never a wrong answer, because the
// whole key is compared.
const (
	memoSize   = 256 // a power of two
	memoRegex  = 1
	memoSearch = 2
	windowBin  = 1 // the input itself
	windowText = 2 // the text phase's UTF-8 re-encoding of it
)

// memoKey identifies one evaluation: the line, the window it ran on and
// the region within it.
type memoKey struct {
	rec    int32
	start  int32
	length int32
	window uint8
	kind   uint8
}

// memoEntry is a key with its answer, valid when gen is the current call.
type memoEntry struct {
	key  memoKey
	a, b int32
	gen  uint32
}

// slot is the entry a key hashes to.
func (k memoKey) slot() int {
	h := bitsOfInt32(k.rec)*0x9e3779b1 ^ bitsOfInt32(k.start)*0x85ebca6b ^ bitsOfInt32(k.length)*0xc2b2ae35
	h ^= uint32(k.window)<<8 | uint32(k.kind)
	return int(h & (memoSize - 1))
}

// memoGet returns the remembered answer for k in this call.
func (s *scan) memoGet(k memoKey) (int32, int32, bool) {
	invariant.Check(s.gen != 0, "call generation set")
	invariant.Check(k.kind == memoRegex || k.kind == memoSearch, "memo kind")
	e := &s.memo[k.slot()]
	if e.gen != s.gen || e.key != k {
		return 0, 0, false
	}
	return e.a, e.b, true
}

// memoPut remembers an answer for k in this call.
func (s *scan) memoPut(k memoKey, a, b int32) {
	invariant.Check(s.gen != 0, "call generation set")
	invariant.Check(k.window == windowBin || k.window == windowText, "memo window")
	s.memo[k.slot()] = memoEntry{key: k, a: a, b: b, gen: s.gen}
}

// regionKey is the key for the line at rec over the current search region.
func (s *scan) regionKey(kind uint8, rec int32) memoKey {
	invariant.Check(s.search.valid, "region set")
	invariant.Check(s.winID != 0, "window set")
	return memoKey{rec: rec, start: smallInt32(s.search.start), length: smallInt32(s.search.length),
		window: s.winID, kind: kind}
}

// nextCandidate is the first index in b holding c1 or c2 (c2 may equal
// c1), or -1.
func nextCandidate(b []byte, c1, c2 byte) int {
	i := bytes.IndexByte(b, c1)
	if c2 == c1 {
		return i
	}
	j := bytes.IndexByte(b, c2)
	if i < 0 || (j >= 0 && j < i) {
		return j
	}
	return i
}

// containsFoldASCII reports whether region contains lit, an ASCII literal
// whose letters are lower case, matching letters in either case. Exact
// for RE2's (?i) over the transcoded region, whose runes never exceed
// U+00FF: the only non-ASCII case equivalents of ASCII letters (U+212A,
// U+017F) cannot occur there.
func containsFoldASCII(region []byte, lit []byte) bool {
	invariant.Check(len(lit) != 0, "literal given")
	invariant.Check(!cIsUpper(lit[0]), "literal is lower case")
	c1 := lit[0]
	c2 := cToUpper(c1)
	last := len(region) - len(lit)
	for idx := 0; idx <= last; idx++ {
		j := nextCandidate(region[idx:last+1], c1, c2)
		if j < 0 {
			return false
		}
		idx += j
		if foldEqual(region[idx:idx+len(lit)], lit) {
			return true
		}
	}
	return false
}

// foldEqual compares b with a lower-case ASCII literal, folding b's
// letters.
func foldEqual(b []byte, lit []byte) bool {
	invariant.Check(len(b) == len(lit), "same length")
	for i := 0; i < len(lit); i++ {
		if cToLower(b[i]) != lit[i] {
			return false
		}
	}
	return true
}

// possible is the regex prefilter: false when no match is possible
// because none of the pattern's mandatory literals is present, in the
// region or, for an anchored pattern, at the start of any line.
func (r *regexSlot) possible(region []byte) bool {
	invariant.Check(len(r.lits) != 0, "literals given")
	if r.lineStart {
		return r.atLineStart(region)
	}
	for _, lit := range r.lits {
		invariant.Check(len(lit) != 0, "literal non-empty")
		if r.fold && containsFoldASCII(region, lit) {
			return true
		}
		if !r.fold && bytes.Contains(region, lit) {
			return true
		}
	}
	return false
}

// atLineStart reports whether some line of the region begins with one of
// the literals. (?m)^ matches at the start and after each '\n', which the
// Latin-1 transcoding leaves in place.
func (r *regexSlot) atLineStart(region []byte) bool {
	invariant.Check(r.lineStart, "anchored pattern")
	pos := 0
	for lines := 0; lines <= len(region); lines++ { // a line takes at least one byte
		if r.prefixOf(region[pos:]) {
			return true
		}
		nl := bytes.IndexByte(region[pos:], '\n')
		if nl < 0 {
			return false
		}
		pos += nl + 1
	}
	return false
}

// prefixOf reports whether b begins with one of the literals.
func (r *regexSlot) prefixOf(b []byte) bool {
	invariant.Check(len(r.lits) != 0, "literals given")
	for _, lit := range r.lits {
		if len(lit) > len(b) {
			continue
		}
		if r.fold && foldEqual(b[:len(lit)], lit) {
			return true
		}
		if !r.fold && bytes.Equal(b[:len(lit)], lit) {
			return true
		}
	}
	return false
}
