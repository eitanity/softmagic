// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"bytes"
	"regexp"
	"testing"
)

// testRand is a small xorshift generator: the tests need repeatable
// variety, not randomness.
type testRand struct{ x uint64 }

func (r *testRand) next() uint64 {
	r.x ^= r.x << 13
	r.x ^= r.x >> 7
	r.x ^= r.x << 17
	return r.x
}

func (r *testRand) intn(n int) int { return int(low32(r.next() % bitsOfInt64(int64(n)))) }

func sameStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRegexLiterals pins the literal sets derived from pattern shapes
// that occur in Magdir.
func TestRegexLiterals(t *testing.T) {
	cases := []struct {
		src       string
		lits      []string
		fold      bool
		lineStart bool
	}{
		{"(?m)^%?[ \t]*SiSU[ \t]+insert", []string{"insert"}, false, false},
		{"(?m)^(import|export).* from ", []string{"import", "export"}, false, true},
		{"(?m)^(:|;)", []string{":", ";"}, false, true},
		{"(?m)^\\.(BEGIN|endif|include)", []string{".BEGIN", ".endif", ".include"}, false, true},
		{"(?m)^[[:space:]]*(class|module)[[:space:]][A-Z]", []string{"class", "module"}, false, false},
		{"(?m)^[[:space:]]*#(set|show|let)", []string{"s", "let"}, false, false},
		{"(?m)^package[ \t]+req", []string{"package"}, false, true},
		{"(?mi)^<!doctype html", []string{"<!doctype html"}, true, true},
		{"(?mi)content-type", []string{"content-type"}, true, false},
		{"(?m)[0-9]+", nil, false, false},
		{"(?m)^[^:]{1,32}", nil, false, false},
		{"(?m)^[!-?A-~]{1,255}(\t[^\t]+){11}", []string{"\t"}, false, false},
		{"(?m)^(a|[bc])x", []string{"a", "b", "c"}, false, true},
		{"(?m)^[A-Za-z]:", []string{":"}, false, false}, // class too large: contained literal instead
		{"(?mi)^(k|s)x", []string{"x"}, true, false},    // folded class includes U+212A and U+017F
		{"(?mi)^(ab|cd)x", []string{"ab", "cd"}, true, true},
		{"(?m)^\xc3\xa9t\xc3\xa9", nil, false, false},
	}
	for _, c := range cases {
		lits, fold, lineStart := regexLiterals(c.src)
		if !sameStringSlices(lits, c.lits) || fold != c.fold || lineStart != c.lineStart {
			t.Errorf("%q: got %q fold=%v line=%v, want %q fold=%v line=%v",
				c.src, lits, fold, lineStart, c.lits, c.fold, c.lineStart)
		}
	}
}

// TestPrefilterSound checks on random inputs that the prefilter never
// rejects a region the regex matches, for every regex in the embedded
// database.
func TestPrefilterSound(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	rng := &testRand{x: 7}
	alphabet := []byte("abcdeKkSs:;.#<>!-_ \t\n\r\xc3\xa9\x00")
	region := make([]byte, 0, 512)
	for i := range db.regexes {
		slot := &db.regexes[i]
		if len(slot.lits) == 0 {
			continue
		}
		re := regexp.MustCompile(slot.pattern)
		for trial := 0; trial < 200; trial++ {
			region = region[:0]
			n := rng.intn(64)
			for k := 0; k < n; k++ {
				region = append(region, alphabet[rng.intn(len(alphabet))])
			}
			// Plant a literal in half the trials so matches do occur.
			if trial%2 == 0 {
				lit := slot.lits[rng.intn(len(slot.lits))]
				region = append(region, '\n')
				region = append(region, lit...)
				region = append(region, " x;\n"...)
			}
			if nul := bytes.IndexByte(region, 0); nul >= 0 {
				region = region[:nul]
			}
			buf := make([]byte, 2*len(region))
			m := transcodeLatin1(buf, region)
			if re.Match(buf[:m]) && !slot.possible(region) {
				t.Fatalf("%q rejected %q which matches", slot.pattern, region)
			}
		}
	}
}

func TestContainsFoldASCII(t *testing.T) {
	cases := []struct {
		region, lit string
		want        bool
	}{
		{"<!DOCTYPE SVG", "<!doctype svg", true},
		{"x <!doctype svg", "<!doctype svg", true},
		{"<!doctype sv", "<!doctype svg", false},
		{"kk KK kK", "kk", true},
		{"K", "k", true},
		{"", "k", false},
		{"abc", "c", true},
		{"ABC", "d", false},
	}
	for _, c := range cases {
		if got := containsFoldASCII([]byte(c.region), []byte(c.lit)); got != c.want {
			t.Errorf("containsFoldASCII(%q, %q) = %v", c.region, c.lit, got)
		}
	}
	if nextCandidate([]byte("xxBxxb"), 'b', 'B') != 2 || nextCandidate([]byte("xxx"), 'b', 'B') != -1 ||
		nextCandidate([]byte("xb"), 'b', 'b') != 1 {
		t.Error("nextCandidate")
	}
}

// naiveSearch is the position-by-position loop searchFlagged replaced.
func naiveSearch(m *record, region []byte, slen, rng int) int {
	tries := rng
	if tries == 0 || tries > len(region) {
		tries = len(region)
	}
	for idx := 0; idx <= tries; idx++ {
		if slen+idx > len(region) {
			return -1
		}
		if strncmp(m.valueBytes(), region[idx:], slen, len(region)-idx, m.strFlags()) == 0 {
			return idx
		}
	}
	return -1
}

// TestSearchCandidates checks the candidate-skipping search against the
// naive loop on random values, regions, ranges and flag combinations.
func TestSearchCandidates(t *testing.T) {
	rng := &testRand{x: 11}
	alphabet := []byte("aAbB \t<>x")
	flagSets := []uint32{strIgnoreLowercase, strIgnoreUppercase, strIgnoreLowercase | strIgnoreUppercase,
		strCompactWhitespace, strCompactOptionalWhitespace, strIgnoreLowercase | strCompactWhitespace,
		strIgnoreUppercase | strCompactOptionalWhitespace | strFullWord, strFullWord}
	for trial := 0; trial < 20000; trial++ {
		var m record
		m.value = make([]byte, valueMin)
		m.typ = tSearch
		n := 1 + rng.intn(4)
		for k := 0; k < n; k++ {
			m.value[k] = alphabet[rng.intn(len(alphabet))]
		}
		m.vallen = smallUint8(n)
		m.setStrFlags(flagSets[rng.intn(len(flagSets))])
		region := make([]byte, rng.intn(24))
		for k := range region {
			region[k] = alphabet[rng.intn(len(alphabet))]
		}
		r := rng.intn(30)
		if got, want := searchFlagged(&m, region, n, r), naiveSearch(&m, region, n, r); got != want {
			t.Fatalf("value %q flags %#x region %q range %d: got %d, want %d",
				m.valueBytes(), m.strFlags(), region, r, got, want)
		}
	}
}

// TestMemoRepeat checks that a call reuses its own regex and search
// answers: the second output pass finds every region in the memo.
func TestMemoRepeat(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	in := []byte("#!/bin/sh\n<html><title>x</title>\nimport os from 'x';\n")
	a := db.Identify(in)
	b := db.Identify(in)
	if a.Description != b.Description || a.MIME != b.MIME || len(a.Rules) != len(b.Rules) {
		t.Fatalf("results differ between calls: %+v %+v", a, b)
	}
	k := memoKey{rec: 3, start: 1, length: 2, window: windowBin, kind: memoSearch}
	s := scan{gen: 5}
	if _, _, hit := s.memoGet(k); hit {
		t.Fatal("hit in an empty table")
	}
	s.memoPut(k, 7, 9)
	if x, y, hit := s.memoGet(k); !hit || x != 7 || y != 9 {
		t.Fatal("stored answer not returned")
	}
	s.gen++
	if _, _, hit := s.memoGet(k); hit {
		t.Fatal("answer survived into the next call")
	}
}
