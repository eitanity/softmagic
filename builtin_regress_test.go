// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"encoding/binary"
	"testing"
	"time"
)

// simhRecord is a SIMH tape record: its length, the bytes padded to an
// even count, and the length again.
func simhRecord(p []byte) []byte {
	n := binary.LittleEndian.AppendUint32(nil, low32(bitsOfInt64(int64(len(p)))))
	b := append(append([]byte(nil), n...), p...)
	if len(p)%2 != 0 {
		b = append(b, 0)
	}
	return append(b, n...)
}

// TestSIMHLayouts: tape layouts, including an end-of-medium word before
// any record, which on a 32-bit host used to read as a record of length
// -1. The answers are file 5.48's.
func TestSIMHLayouts(t *testing.T) {
	db := compileMagdir(t) // database
	rep := func(s string, n int) []byte {
		b := make([]byte, 0, len(s)*n)
		for range n {
			b = append(b, s...)
		}
		return b
	}
	cat := func(parts ...[]byte) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	eom := []byte{0xff, 0xff, 0xff, 0xff}
	for _, c := range []struct { // tapeCase
		name, want string
		input      []byte
	}{
		{"valid", "SIMH tape data", cat(simhRecord(rep("HDR1", 20)), simhRecord(rep("data", 30)), make([]byte, 4), eom)},
		{"eom-first", "ISO-8859 text, with no line terminators", eom},
		{"eom-first-long", "data", cat(eom, simhRecord(rep("abcd", 10)))},
		{"truncated", "SIMH tape data", cat(simhRecord(rep("abcd", 10)), binary.LittleEndian.AppendUint32(nil, 1000), []byte("xx"))},
		{"odd", "SIMH tape data", cat(simhRecord([]byte("abc")), make([]byte, 4))},
		{"tapemarks-only", "data", make([]byte, 16)},
		{"mismatch", "data", cat(binary.LittleEndian.AppendUint32(nil, 8), []byte("12345678"), binary.LittleEndian.AppendUint32(nil, 9))},
	} {
		if got := db.Identify(c.input).Description; got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// TestFILETIMEBoundaries: FILETIME values around the reference's
// calendar arithmetic, including negative ones that give a year before
// 1601. The answers are file 5.48's under TZ=UTC; the test reads the
// fields as UTC for its duration.
func TestFILETIMEBoundaries(t *testing.T) {
	local := time.Local
	time.Local = time.UTC
	defer func() { time.Local = local }()
	db := compileRules(t, "0\tstring\tQWD\tqw\n>4\tleqwdate\tx\t\\b %s\n")
	for _, c := range []struct { // filetimeCase
		want string
		v    int64
	}{
		{"qw Mon Jan  1 00:00:00 1601", -1},
		{"qw Mon Jan  1 00:00:00 1601", 0},
		{"qw Mon Jan  1 00:00:00 1601", 1},
		{"qw Thu Jan  1 00:00:00 1970", 116444736000000000},
		{"qw Wed Aug 21 19:53:57 1230", -0x00cfcfcfcfcfcfd0},
		{"qw Wed Apr 17 18:40:00 2019", 132000000000000000},
	} {
		in := binary.LittleEndian.AppendUint64([]byte("QWD\x00"), bitsOfInt64(c.v))
		if got := db.Identify(in).Description; got != c.want {
			t.Errorf("FILETIME %d: %q, want %q", c.v, got, c.want)
		}
	}
}

// TestID3LineTypes: beid3 and leid3 parse as line types but have no
// conversion. At the top level the reference refuses the line with no
// error in the answer, and so does this; the answers are file 5.48's. As
// a continuation, and under "!", the reference reports an error this does
// not reproduce; those lines must still not fail an internal check.
func TestID3LineTypes(t *testing.T) {
	for _, typ := range []string{"beid3", "leid3"} {
		db := compileRules(t, "0\t"+typ+"\tx\tid3 %d\n>0\tbyte\tx\tchild\n0\tbyte\tx\tB\n")
		r := db.Identify([]byte("\x00\x00\x01\x00rest"))
		if r.Description != "B" || r.Examined.Truncated != "" {
			t.Errorf("%s: %q (truncated %q), want %q", typ, r.Description, r.Examined.Truncated, "B")
		}
		for _, rules := range []string{"0\tbyte\tx\tB\n>0\t" + typ + "\tx\tid3\n", "0\tbyte\tx\tB\n>0\t" + typ + "\t!0\tid3 %d\n"} {
			r := compileRules(t, rules).Identify([]byte("\x00\x00\x01\x00rest"))
			if r.Examined.Truncated == TruncInvariant {
				t.Errorf("%s continuation: an internal check failed (%q)", typ, r.Description)
			}
		}
	}
}
