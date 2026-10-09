// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"math"
	"testing"
	"unicode/utf8"
)

// TestFormatCFloat: special values as glibc's printf spells them, not Go's.
// A NaN's sign is printed, as in a measure rule whose float reads
// 0xffc00000 ("spot sensor temperature -nan").
func TestFormatCFloat(t *testing.T) {
	negNaN := math.Float64frombits(0xfff8000000000000)
	for _, c := range []struct { // testCase
		want string
		f    float64
		verb byte
	}{
		{"nan", math.NaN(), 'f'},
		{"-nan", negNaN, 'f'},
		{"-nan", float64(math.Float32frombits(0xffc00000)), 'g'},
		{"inf", math.Inf(1), 'e'},
		{"-inf", math.Inf(-1), 'g'},
		{"1.500000", 1.5, 'f'},
	} {
		if got := formatCFloat(c.f, c.verb, 6); got != c.want {
			t.Errorf("formatCFloat(%v, %c) = %q, want %q", c.f, c.verb, got, c.want)
		}
	}
}

// TestTrimSpaceCString: file_strtrim trims the C string, which ends at its
// first NUL, so spaces before the NUL go even when NULs follow ("#!/bin/sh   "
// in a 128-byte value).
func TestTrimSpaceCString(t *testing.T) {
	for in, want := range map[string]string{ // input
		"/bin/sh   \x00\x00\x00": "/bin/sh",
		"  a b  ":                "a b",
		"\x00tail":               "",
		"   ":                    "",
	} {
		if got := string(trimSpace([]byte(in))); got != want {
			t.Errorf("trimSpace(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPrintfChar: %c prints the byte itself, as C's printf does, so a
// byte above 0x7f is one byte and not the UTF-8 of a code point; and a %c
// of zero ends the C string, dropping the rest of the piece.
func TestPrintfChar(t *testing.T) {
	for _, c := range []struct { // testCase
		desc, want string
		v          uint64
	}{
		{"%c-type", "E-type", 'E'},
		{"%c-type", "\xff-type", 0xff},
		{"%c-type", "\xe9-type", 0x1e9}, // only the low byte
		{"x %3c|", "x   \x1b|", 0x1b},
		{"x %-3c|", "x \x80  |", 0x80},
		{"at %c-type", "at ", 0},
		{"at %3c-type", "at   ", 0},
		{"at %-3c-type", "at ", 0},
	} {
		var s scan
		s.printfNum(c.desc, c.v, false, 32)
		if got := string(s.out[:s.outLen]); got != c.want {
			t.Errorf("printfNum(%q, %#x) = %q, want %q", c.desc, c.v, got, c.want)
		}
	}
}

// TestEscapeText: file_getbuffer's two passes. Valid UTF-8 keeps what
// glibc's iswprint accepts and escapes the bytes of the rest; anything
// else is escaped byte by byte outside printable ASCII. A list is one
// buffer: one invalid element puts every element through the byte pass.
func TestEscapeText(t *testing.T) {
	for _, c := range []struct { // testCase
		in, want string
	}{
		{"plain", "plain"},
		{"tab\there", "tab\\011here"},
		{"esc \x1b[31m", "esc \\033[31m"},
		{"café", "café"},
		{"a\u202eb", "a\u202eb"},               // a bidi override is printable to glibc
		{"a\u2028b", "a\\342\\200\\250b"},      // a line separator is not
		{"\xff and é", "\\377 and \\303\\251"}, // invalid UTF-8: the byte pass for all
	} {
		if got := escapeText(c.in, utf8.ValidString(c.in)); got != c.want {
			t.Errorf("escapeText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	list := escapeList([]string{"é", "\xff"})
	if list[0] != "\\303\\251" || list[1] != "\\377" {
		t.Errorf("escapeList with an invalid element = %q", list)
	}
	clean := []string{"a", "b"}
	if got := escapeList(clean); &got[0] != &clean[0] {
		t.Error("an unchanged list was copied")
	}
	if !iswprint(' ') || iswprint(0x7f) || !iswprint(0xe000) || iswprint(0x10ffff) {
		t.Error("iswprint edges")
	}
}
