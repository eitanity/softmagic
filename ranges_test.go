// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"encoding/binary"
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

// TestDERNegativeRuleOffset: a der line's offset is added to the current
// one in uint32, so a sum below 0 wraps past the input and the line fails,
// while a negative offset that stays at or above 0 steps back. The answers
// are file 5.48's.
func TestDERNegativeRuleOffset(t *testing.T) {
	const kids = ">>&0\tbyte\tx\tD%d\n>&0\tbyte\tx\tC%d\n"
	for _, c := range []struct{ name, rules, input, want string }{ // derOffsetCase
		{"sum below 0", "0\tstring\t\\x30\\x03\tA\n>&0xfffffffe\tder\tseq\tB\n" + kids, "0\x03\x02\x01\x05\x00\x00\x00", "A B C2"},
		{"sum below 0, &--2", "0\tstring\t\\x30\\x03\tA\n>&--2\tder\tseq\tB\n" + kids, "0\x03\x02\x01\x05\x00\x00\x00", "A C2"},
		{"sum of 1", "0\tstring\t\\x30\\x03\tA\n>&-1\tder\tseq\tB\n" + kids, "0\x030\x01\x05\x00\x00\x00", "A C48"},
		{"sum of -1, no children", "0\tstring\tXX\tA\n>&--3\tder\tseq\tB\n", "XX0\x01\x05\x00\x00\x00", "A"},
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

// TestDERUnreadNegated: a "!" der line whose indirect offset is past the
// input matches without reading, so no line may have set a region. With
// one from an earlier der line or none, the answers are file 5.48's: the
// line prints, and with no region its offset fails.
func TestDERUnreadNegated(t *testing.T) {
	for _, c := range []struct{ name, rules, want string }{ // derUnreadCase
		{"no region", "0\tstring\tXX\tA\n>(100.l)\tder\t!seq\tB\n>>&0\tbyte\tx\tC%d\n", "A B"},
		{"no region, top level", "(100.l)\tder\t!seq\tB\n>&0\tbyte\tx\tC%d\n", "B"},
		{"earlier region", "0\tstring\tXX\tA\n>2\tder\tseq\tS\n>(100.l)\tder\t!seq\tB\n>>&0\tbyte\tx\tC%d\n", "A S B"},
	} {
		db, err := compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte(c.rules)}}, CompileOptions{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		r := db.Identify([]byte("XX0\x01\x05\x00\x00\x00"))
		if r.Description != c.want || r.Examined.Truncated != "" {
			t.Errorf("%s: %q, truncated %q, want %q", c.name, r.Description, r.Examined.Truncated, c.want)
		}
	}
}

// TestUnreadNegatedRegion: a "!" regex or search line whose indirect
// offset is past the input matches without reading and uses whatever
// region an earlier line left, in this window or in the binary pass
// before the text pass. The answers are file 5.48's, with and without -k;
// with no region at all, a regex line prints nothing after its separator.
func TestUnreadNegatedRegion(t *testing.T) {
	const kid = ">>&0\tbyte\tx\tC%d\n"
	const textTail = ", Unicode text, UTF-16, little-endian text"
	utf16 := []byte{0xff, 0xfe}
	for _, c := range []byte("hello 0 world, this is a long enough utf-16 text line\n") {
		utf16 = append(utf16, c, 0)
	}
	ascii := []byte("hello world, this is a long enough ascii text line\n")
	for _, c := range []struct { // unreadRegionCase
		name, rules, want string
		input             []byte
		cont              bool
	}{
		{"no region, regex", "0\tstring/t\th\tT\n>(200.l)\tregex\t!x\tRX[%s]\n", "T " + textTail, utf16, false},
		{"binary region, regex", "20\tsearch/1\tQ\tnever\n0\tstring/t\th\tT\n>(200.l)\tregex\t!x\tRX[%s]\n" + kid, "T RX[] C105" + textTail, utf16, false},
		{"binary region, regex, -k", "20\tsearch/1\tQ\tnever\n0\tstring/t\th\tT\n>(200.l)\tregex\t!x\tRX[%s]\n" + kid, "T RX[] C105" + textTail, utf16, true},
		{"binary region, search", "20\tsearch/1\tQ\tnever\n0\tstring/t\th\tT\n>(200.l)\tsearch/4\t!x\tSX[%s]\n" + kid, "T SX[] C115" + textTail, utf16, false},
		{"binary region, search, -k", "20\tsearch/1\tQ\tnever\n0\tstring/t\th\tT\n>(200.l)\tsearch/4\t!x\tSX[%s]\n" + kid, "T SX[] C115" + textTail, utf16, true},
		{"binary region, der", "20\tsearch/1\tQ\tnever\n0\tstring/t\th\tT\n>(200.l)\tder\t!seq\tD\n" + kid, "T D" + textTail, utf16, false},
		{"same window, regex", "0\tstring/t\th\tT\n>0\tregex\tw..ld\tW[%s]\n>(200.l)\tregex\t!x\tRX[%s]\n" + kid, "T W[world] RX[world] C44, ASCII text", ascii, false},
	} {
		db, err := compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte(c.rules)}}, CompileOptions{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		r := db.IdentifyWith(t.Context(), c.input, Options{Continue: c.cont})
		if r.Description != c.want || r.Examined.Truncated != "" {
			t.Errorf("%s: %q, truncated %q, want %q", c.name, r.Description, r.Examined.Truncated, c.want)
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

// TestRegionInIndirectFrame: a search, regex or der line run again by
// indirect four bytes in reads the frame's bytes, where its region used
// to start four bytes early and miss the frame's last bytes. The answers
// are file 5.48's.
func TestRegionInIndirectFrame(t *testing.T) {
	const marker = "0\tstring\tIND:\tIND:\n!:strength +255\n>4\tindirect\tx\n"
	keyPair := "\x30\x82\x00\x50\x02\x01\x00\x02\x41\x00" + string(make([]byte, 64)) +
		"\x02\x03\x01\x00\x01\x02\x03\x01\x02\x03"
	for _, c := range []struct{ name, rules, input, want string }{ // frameCase
		{"search", "0\tsearch/b/100\tworld\tW\n", "IND:\x05hello world", "IND:W"},
		{"search_then_string", "0\tsearch/b/100\thello\tH\n>&1\tstring\twor\t\\b, then wor\n",
			"IND:\x05hello world", "IND:H, then wor"},
		{"search_printed", "0\tsearch/b/100\tworld\tW %s\n", "IND:\x05hello world\n", "IND:W \\005hello"},
		{"regex", "0\tregex/b\twor\tRX\n", "IND:\x05hello world", "IND:RX"},
		{"der", "0\tder\tseq\tSEQ\n>&0\tder\tint1=00\t\\b, version 0\n>&0\tder\tint65=x\t\\b, modulus\n" +
			">&0\tder\tint3=010001\t\\b, exponent 65537\n", "IND:" + keyPair, "IND:SEQ, version 0, modulus, exponent 65537"},
	} {
		db, err := compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte(marker + c.rules)}}, CompileOptions{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := db.Identify([]byte(c.input)).Description; got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// TestValueNotCarriedOver: a der line's %s prints the value buffer, which
// it does not fill itself. Each call starts with that buffer zeroed, as a
// new magic_set does, where a pooled scan used to print the bytes the
// call before it copied. The answer is file 5.48's.
func TestValueNotCarriedOver(t *testing.T) {
	db, err := compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte(
		"0x10\tder\tint\t0 %s\n>&0\tubyte\tx\t\\b, then %u\n")}}, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("0000000000000000B\x0100000000000000000")
	for i := range 3 {
		if got := db.Identify(input).Description; got != "0 , then 48" {
			t.Errorf("call %d: %q, want %q", i, got, "0 , then 48")
		}
	}
}

// TestDateYearRange: a date prints as file 5.48 prints it on amd64 and
// 386, from glibc's asctime_r: years -999 to 9999, unpadded under 1000,
// and "*Invalid datetime*" outside them, where the year had been padded
// to four digits and printed past the range, wrapped inside time for the
// most negative counts.
func TestDateYearRange(t *testing.T) {
	for _, c := range []struct { // dateCase
		want string
		secs int64
	}{
		{"*Invalid datetime*", -93692592001},
		{"Thu Jan  1 00:00:00 -999", -93692592000},
		{"Fri Dec 31 23:59:59 -1", -62167219201},
		{"Sat Jan  1 00:00:00 0", -62167219200},
		{"Tue Jan  1 00:00:00 999", -30641760000},
		{"Fri Dec 31 23:59:59 9999", 253402300799},
		{"*Invalid datetime*", 253402300800},
		{"*Invalid datetime*", math.MinInt64},
		{"*Invalid datetime*", -dateSecsBound - 1},
	} {
		v := binary.LittleEndian.AppendUint64(nil, bitsOfInt64(c.secs))
		if got := fmtDateTime(tLeQDate, v); got != c.want {
			t.Errorf("%d seconds: %q, want %q", c.secs, got, c.want)
		}
	}
}
