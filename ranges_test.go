// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"math"
	"testing"
	"testing/fstest"
)

// TestRangesPastInt32: string, regex and search ranges and search and der
// offsets of 2^31 and more are the reference's uint32 values on every
// host. On a 32-bit host they used to become negative ints and panic or
// miss. The answers are file 5.48's.
func TestRangesPastInt32(t *testing.T) {
	for _, c := range []struct{ name, rules, input, want string }{ // rangeCase
		{"05_string_range_2p31", "0\x09string/2147483648\x09abcdefgh\x09STR %s\x0a", "abcdefgh hello world\x0a", "STR abcdefgh"},
		{"05_string_range_u32max", "0\x09string/4294967295\x09abc\x09STR\x0a0\x09string/4294967295\x09abcdefgh\x09STR2 %s\x0a", "abcdefgh hello world\x0a", "STR2 abcdefgh"},
		{"06_regex_lines_wrap", "0\x09regex/30000000l\x09hel+o\x09RX\x0a", "abcdefgh hello world\x0a", "RX, ASCII text"},
		{"06_regex_range_2p31", "0\x09regex/2147483648\x09hel+o\x09RX\x0a", "abcdefgh hello world\x0a", "RX, ASCII text"},
		{"06_regex_range_u32max", "0\x09regex/4294967295\x09hel+o\x09RX\x0a", "abcdefgh hello world\x0a", "RX, ASCII text"},
		{"07_search_range_2p31-1", "0\x09search/2147483647\x09world\x09FOUND\x0a", "abcdefgh hello world\x0a", "FOUND, ASCII text"},
		{"07_search_range_u32max", "0\x09search/4294967295\x09world\x09FOUND\x0a", "abcdefgh hello world\x0a", "FOUND, ASCII text"},
		{"07_search_range_u32max-1", "0\x09search/4294967294\x09h\x09FOUND\x0a", "abcdefgh hello world\x0a", "FOUND, ASCII text"},
		{"08_der_abs_high", "0\x09byte\x09x\x09B\x0a>0xfffffff0\x09der\x09seq\x09DER\x0a", "0\x03\x02\x01\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "B"},
		{"08_der_indirect_file", "(0.L)\x09der\x09seq\x09DER\x0a0\x09byte\x09x\x09B\x0a", "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "B"},
		{"08_der_rel_neg", "0\x09byte\x09x\x09B\x0a>&-8\x09der\x09seq\x09DER\x0a", "0\x03\x02\x01\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "B"},
		{"08_search_indirect_file", "(0.L)\x09search/10\x09hello\x09FOUND\x0a0\x09byte\x09x\x09B\x0a", "\x80\x00\x00\x00hello\x00\x00\x00\x00\x00\x00\x00", "B"},
	} {
		db, err := compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte(c.rules)}}, CompileOptions{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := db.Identify([]byte(c.input)).Description; got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// TestLoadEntryTableWrap: an entry table whose first+count passes
// MaxInt32 is refused, not followed to a negative record index.
func TestLoadEntryTableWrap(t *testing.T) {
	db, err := compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte("0\x09string\x09A\x09a\x0a0\x09string\x09B\x09b\x0a")}}, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m := &db.maps[0]
	m.sets[0] = []entry{{first: 0, count: 1}, {first: 1, count: math.MaxInt32}}
	m.count = math.MinInt32
	m.sets[1] = []entry{{first: math.MinInt32, count: 1}}
	blob, err := db.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(blob); err == nil {
		t.Error("Load accepted an entry table whose sum wraps")
	}
}

// TestLoadRefusesUnparsableRecords: Load refuses a record the rule
// parser could not have produced, rather than leaving the matcher to
// meet it. A width of 262144 took 3.6 s to print before it was checked.
func TestLoadRefusesUnparsableRecords(t *testing.T) {
	for _, c := range []struct { // recordCase
		damage func(r *record)
		name   string
	}{
		{func(r *record) { r.desc = []byte("%.262144d") }, "printf width past 1024"},
		{func(r *record) { r.desc = []byte("%d %d") }, "two conversions"},
		{func(r *record) { r.desc = []byte("%s") }, "conversion for the wrong type"},
		{func(r *record) { r.typ = tInvalid }, "no type"},
		{func(r *record) { r.reln = 'Z' }, "unknown relation"},
		{func(r *record) { r.factorOp = '%' }, "unknown strength operator"},
		{func(r *record) { r.factorOp, r.factor = '/', 0 }, "strength divides by zero"},
	} {
		db, err := compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte("0\x09byte\x09x\x09b %d\x0a")}}, CompileOptions{})
		if err != nil {
			t.Fatal(err)
		}
		c.damage(&db.recs[0])
		blob, err := db.Marshal()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if _, err := Load(blob); err == nil {
			t.Errorf("%s: Load accepted the record", c.name)
		}
	}
}

// TestLoadRefusesBadRegex: Load refuses a regex RE2 rejects, as Compile
// does, instead of the matcher meeting a line with no pattern.
func TestLoadRefusesBadRegex(t *testing.T) {
	db, err := compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte("0\x09regex\x09abcd\x09R\x0a0\x09byte\x09x\x09B\x0a")}}, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range db.recs {
		if db.recs[i].typ == tRegex {
			copy(db.recs[i].value, "a(b")
		}
	}
	blob, err := db.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(blob); err == nil {
		t.Error("Load accepted a regex RE2 rejects")
	}
}

// TestMarshalRefusesLongFields: a field longer than its 16-bit length
// prefix is refused by Marshal, rather than written as a database Load
// then refuses.
func TestMarshalRefusesLongFields(t *testing.T) {
	db, err := CompileSources("h", []Source{{Name: "x", Data: []byte("0 string A a\n")}},
		CompileOptions{SourceDir: string(make([]byte, 1<<16+10))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Marshal(); err == nil {
		t.Error("Marshal accepted a 65546-byte SourceDir")
	}
}

// TestNumeralsPast64Bits: a numeral past 64 bits saturates as strtoull
// does, where it used to fail to compile. As an offset, range or mask it
// is then the saturated value; as a test value the reference's ERANGE
// leaves it in the description. The answers are file 5.48's.
func TestNumeralsPast64Bits(t *testing.T) {
	for _, c := range []struct{ name, rules, input, want string }{ // numeralCase
		{"offset", "99999999999999999999\x09byte\x09x\x09OFF\x0a", "\xff\x01abc", "data"},
		{"range", "0\x09string/99999999999999999999\x09\\x05\x09R\x0a", "\x05\x01abc", "R"},
		{"mask", "0\x09byte&0x1ffffffffffffffff\x09=0xff\x09MASK\x0a", "\xff\x01abc", "MASK"},
		{"value", "0\x09byte\x0999999999999999999999\x09VALUE\x0a", "\xff\x01abc", "99999999999999999999\\011VALUE"},
		{"value_eq", "0\x09byte\x09=99999999999999999999\x09VALUE\x0a", "\xff\x01abc", "99999999999999999999\\011VALUE"},
		{"value_hex", "0\x09byte\x090x1ffffffffffffffff\x09V\x0a", "\xff\x01abc", "0x1ffffffffffffffff\\011V"},
		{"value_negative", "0\x09byte\x09-99999999999999999999\x09V\x0a", "\xff\x01abc", "-99999999999999999999\\011V"},
		{"value_no_match", "0\x09byte\x0999999999999999999999\x09VALUE\x0a", "\x05\x01abc", "data"},
	} {
		db, err := compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte(c.rules)}}, CompileOptions{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := db.Identify([]byte(c.input)).Description; got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
