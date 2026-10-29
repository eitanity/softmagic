// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"bytes"
	"math"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

// ruleFields are one rule line's parts as typed values, which FuzzRule
// assembles into rule text. flags selects the relation, the rendering of
// numbers, the type's modifiers and the lines around the generated one:
//
//	bits 0-2  relation: none = ! < > & ^ x
//	bit 3     numbers in hex
//	bits 4-6  numeric operator (none & | ^ + - * /) with rangeVal, or
//	bits 4-9  string and search flags W w c C t b, or regex flags c s l T t b
//	bit 10    a /rangeVal range or count on a string, search, regex or pstring
//	bit 11    a child line at &0 after it
//	bit 12    a conversion in the description
//	bit 13    under a parent line, so relative offsets have a base
//	bit 14    the unsigned form of a numeric type
//	bit 15    a relative indirect offset, (&...)
type ruleFields struct {
	desc         string
	offset       int64
	value        uint64
	rangeVal     uint32
	flags        uint16
	typ          uint8
	offsetKind   uint8
	indirectType uint8
}

// ruleTypes are the types a generated line may have: every type but
// invalid, name and use, which need a named block.
func ruleTypes() []typeEntry {
	tables := newTypeTables()
	var types []typeEntry
	for _, t := range tables.types {
		if t.typ != tInvalid && t.typ != tName && t.typ != tUse {
			types = append(types, t)
		}
	}
	return append(types, tables.special[0], tables.special[3]) // der, octal
}

// The relations and operators flags selects, the type letters of an
// indirect offset, and the der tests a der line takes.
const (
	ruleRelations  = "\x00=!<>&^x"
	ruleOperators  = "\x00&|^+-*/"
	ruleStrFlags   = "WwcCtb"
	ruleRegexFlags = "cslTtb"
	ruleIndirect   = "bcBChsHSlLmqQeEfFgGiI"
	ruleIndirectOp = "\x00+-*/%&|^"
)

// ruleSpelling is how ruleText writes 2^64-1: as itself, as a longer
// numeral that saturates to it, or as the reference reads the longer
// numeral, which differs only for a test value: on ERANGE the value is
// 2^64-1 and the numeral starts the description.
type ruleSpelling int

const (
	spellPlain ruleSpelling = iota
	spellOver
	spellRead
)

// ruleNumber is v as rule text. With over, 2^64-1 in decimal is written
// as a longer numeral that strtoull saturates to the same value, and in
// hex with a leading 1 past 64 bits.
func ruleNumber(v uint64, hex, over bool) string {
	switch {
	case hex && over && v == math.MaxUint64:
		return "0x1ffffffffffffffff"
	case hex:
		return "0x" + strconv.FormatUint(v, 16)
	case over && v == math.MaxUint64:
		return "99999999999999999999"
	default:
		return strconv.FormatUint(v, 10)
	}
}

// ruleOperand is rangeVal as a range, count or operand: 2^32-1 stands
// for 2^64-1, which the reference truncates per field.
func (r *ruleFields) ruleOperand(over bool) string {
	v := uint64(r.rangeVal)
	if r.rangeVal == math.MaxUint32 {
		v = math.MaxUint64
	}
	return ruleNumber(v, r.flags&8 != 0, over)
}

// ruleOffset is the offset field.
func (r *ruleFields) ruleOffset(over bool) string {
	hex := r.flags&8 != 0
	abs := strconv.FormatInt(r.offset, 10) // signed, but unsigned for kind 1 and in hex
	if r.offsetKind%6 == 1 || hex {
		abs = ruleNumber(bitsOfInt64(r.offset), hex, over)
	}
	t := ruleIndirect[int(r.indirectType)%len(ruleIndirect)]
	in := abs + "." + string(t)
	if op := ruleIndirectOp[int(r.indirectType>>5)%len(ruleIndirectOp)]; op != 0 {
		in += string(op) + r.ruleOperand(over)
	}
	if r.flags&0x8000 != 0 {
		in = "&" + in
	}
	switch r.offsetKind % 6 {
	case 2:
		return "(" + in + ")"
	case 3:
		return "&" + abs
	case 4:
		return "&(" + in + ")"
	default:
		return abs
	}
}

// ruleTest is the type with its modifiers, the test value, and the text
// that starts the description.
func (r *ruleFields) ruleTest(t typeEntry, sp ruleSpelling) (string, string, string) {
	name, f, over := t.name, r.flags, sp != spellPlain
	if t.typ == tDer {
		return name, r.derTest(), ""
	}
	rel := ruleRelations[int(f)%len(ruleRelations)]
	if rel == 'x' {
		return name, "x", ""
	}
	prefix := ""
	if rel != 0 {
		prefix = string(rel)
	}
	var b strings.Builder // valueText
	switch t.typ {
	case tString, tPString, tSearch, tRegex, tBeString16, tLeString16:
		var mods []byte
		if t.typ == tPString {
			mods = append(mods, "BHhLlJ"[int(f>>4)%6])
		}
		letters := ruleStrFlags
		if t.typ == tRegex {
			letters = ruleRegexFlags
		}
		for i := range len(letters) {
			if t.typ != tPString && f>>(4+i)&1 != 0 {
				mods = append(mods, letters[i])
			}
		}
		if f&0x400 != 0 {
			name += "/" + r.ruleOperand(over)
		}
		if len(mods) > 0 {
			name += "/" + string(mods)
		}
		for v := r.value; v != 0 || b.Len() == 0; v >>= 8 { // value's bytes up to its last non-zero one
			b.WriteString("\\x" + strconv.FormatUint(v&0xff, 16))
		}
		return name, prefix + b.String(), ""
	case tGUID, tLeGUID, tBeGUID, tIndirect, tDefault, tClear:
		return name, "x", ""
	default:
	}
	if f&0x4000 != 0 {
		name = "u" + name
	}
	if op := ruleOperators[int(f>>4)%len(ruleOperators)]; op != 0 {
		name += string(op) + r.ruleOperand(over)
	}
	hex, lead := f&8 != 0, ""
	if t.fmt == fmtFloat || t.fmt == fmtDouble || isString(t.typ) { // strtod or the string parser reads these
		return name, prefix + ruleNumber(r.value, hex, false), lead
	}
	if sp == spellRead && r.value == math.MaxUint64 {
		lead = ruleNumber(r.value, hex, true) + "\t"
	}
	return name, prefix + ruleNumber(r.value, hex, sp == spellOver), lead
}

// derTest is a der line's test: a tag, with a length from rangeVal and
// a value test chosen by value.
func (r *ruleFields) derTest() string {
	tests := [...]string{"seq", "set", "int", "obj_id", "prt_str", "utf8_str", "bit_str", "octet_str"}
	test := tests[int(r.value%uint64(len(tests)))]
	if r.value&8 != 0 {
		test += strconv.FormatUint(uint64(r.rangeVal%2048), 10)
	}
	if r.value&16 != 0 {
		test += "=x"
	}
	return test
}

// ruleDesc is the description: desc's printable bytes other than % and
// \, and with bit 12 a conversion for the type's class.
func (r *ruleFields) ruleDesc(t typeEntry) string {
	var b strings.Builder // description
	for i := 0; i < len(r.desc) && b.Len() < 40; i++ {
		if c := r.desc[i]; c >= 0x20 && c < 0x7f && c != '%' && c != '\\' {
			b.WriteByte(c)
		}
	}
	if r.flags&0x1000 != 0 {
		switch t.fmt {
		case fmtQuad:
			b.WriteString(" %lld")
		case fmtNum:
			b.WriteString(" %d")
		case fmtFloat, fmtDouble:
			b.WriteString(" %g")
		case fmtStr:
			b.WriteString(" %s")
		default:
		}
	}
	return b.String()
}

// ruleText assembles the rule set.
func (r *ruleFields) ruleText(sp ruleSpelling) string {
	types := ruleTypes()
	t := types[int(r.typ)%len(types)]
	over := sp != spellPlain
	name, test, lead := r.ruleTest(t, sp)
	level, text := "", ""
	if k := r.offsetKind % 6; r.flags&0x2000 != 0 || k == 3 || k == 4 || r.flags&0x8000 != 0 && k == 2 {
		level, text = ">", "0\tbyte\tx\tP\n"
	}
	text += level + r.ruleOffset(over) + "\t" + name + "\t" + test + "\t" + lead + r.ruleDesc(t) + "\n"
	if r.flags&0x800 != 0 {
		text += level + ">&0\tubyte\tx\t\\b, then %u\n"
	}
	return text
}

// framed is whether the answer must survive an indirect frame: a der
// line's conversion prints the value the line before it copied, which
// in the frame is the indirect line's.
func (r *ruleFields) framed() bool {
	types := ruleTypes()
	return types[int(r.typ)%len(types)].typ != tDer || r.flags&0x1000 == 0
}

// ruleMarker runs the whole database again four bytes in, through
// indirect, ahead of every other line.
const ruleMarker = "0\tstring\tIND:\tIND:\n!:strength +255\n>4\tindirect\tx\n"

// ruleCompile compiles rules, nil when they do not compile.
func ruleCompile(t *testing.T, rules string) *Database {
	t.Helper()
	var db *Database // database
	var err error
	fuzzBounded(t, "Compile", func() {
		db, err = compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte(rules)}}, CompileOptions{})
	})
	if err != nil {
		return nil
	}
	return db
}

// ruleType is the index of the type called name in ruleTypes.
func ruleType(name string) uint8 {
	for i, t := range ruleTypes() {
		if t.name == name {
			return smallUint8(i)
		}
	}
	return 0
}

// ruleSeeds are the shapes of the defects the rule paths have had: a
// string, regex or search range of 2^31 and 2^32-1 (SOF-4), a der line
// at a negative relative offset (SOF-12), a search in an indirect frame
// (SOF-13), numerals past 64 bits as an offset, a range, a mask and a
// value (SOF-16), and a 64-bit date before year -999, which the binary
// input's first eight bytes are (SOF-8).
func ruleSeeds() []ruleFields {
	const (
		relEq, relAny = 1, 7
		hex           = 8
		strRange      = 0x400
		conv          = 0x1000
		parent        = 0x2000
	)
	return []ruleFields{
		{typ: ruleType("string"), offset: 4, value: 0x6c6568, rangeVal: 1 << 31, flags: relEq | strRange | conv, desc: "STR"},
		{typ: ruleType("regex"), offset: 4, value: 0x6c6568, rangeVal: 1 << 31, flags: relEq | strRange, desc: "RX"},
		{typ: ruleType("search"), value: 0x646c726f77, rangeVal: math.MaxUint32, flags: relEq | strRange, desc: "FOUND"},
		{typ: ruleType("search"), value: 0x0a646c726f77, rangeVal: 100, flags: relEq | strRange | 0x200, desc: "S"}, // search/b
		{typ: ruleType("search"), offsetKind: 2, indirectType: 9, value: 0x6f6c6c656800, rangeVal: 10,
			flags: relEq | strRange, desc: "S"},
		{typ: ruleType("search"), value: 0x646c726f77, rangeVal: 1<<31 - 1, flags: relEq | strRange, desc: "FOUND"},
		{typ: ruleType("search"), value: 0x68, rangeVal: 1<<32 - 2, flags: relEq | strRange, desc: "FOUND"},
		{typ: ruleType("regex"), value: 0x6c6568, rangeVal: 30000000, flags: relEq | strRange | 0x40, desc: "RX"}, // regex/l
		{typ: ruleType("der"), offsetKind: 3, offset: -8, flags: relAny | parent, desc: "DER"},
		{typ: ruleType("der"), offsetKind: 2, flags: relAny, desc: "DER"},
		{typ: ruleType("byte"), offsetKind: 1, offset: -1, flags: relAny, desc: "OFF"},
		{typ: ruleType("string"), offset: 4, rangeVal: math.MaxUint32, flags: relEq | strRange, value: 0x68, desc: "RANGE"},
		{typ: ruleType("byte"), rangeVal: math.MaxUint32, flags: relEq | hex | 0x10, value: 1, desc: "MASK"},
		{typ: ruleType("byte"), value: math.MaxUint64, flags: relEq, desc: "VALUE"},
		{typ: ruleType("der"), offsetKind: 3, offset: 16, flags: relAny | parent, desc: "D"},
		{typ: ruleType("long"), value: 0x10, flags: 4 | 0x4000 | conv | 0x800, desc: "L"},
		{typ: ruleType("beqdate"), flags: relAny | conv, desc: "D"},
	}
}

// FuzzRule assembles a rule set from typed fields, compiles it, and
// identifies the input with it, through a slice, a reader, SafeText and
// continue mode. Two answers that must agree are also compared:
//
//   - the rules written with 2^64-1 as a longer numeral compile and
//     answer as the rules spelled the way file reads that numeral: the
//     saturated value, and for a test value the numeral moved to the
//     start of the description;
//   - "IND:" followed by the input, under a line that runs the database
//     again through indirect four bytes in, answers "IND:" and then what
//     the input alone answers, as file reads every offset in an indirect
//     frame from the frame's start.
func FuzzRule(f *testing.F) {
	fuzzSeeds(f, ruleSeedArgs())
	f.Fuzz(func(t *testing.T, typ, offsetKind uint8, offset int64, indirectType uint8, rangeVal uint32,
		flags uint16, value uint64, desc string, input []byte) {
		r, _ := ruleFromArgs([]any{typ, offsetKind, offset, indirectType, rangeVal, flags, value, desc})
		text := r.ruleText(spellPlain)
		if over := r.ruleText(spellOver); over != text {
			fuzzSaturated(t, over, r.ruleText(spellRead), input)
		}
		db := ruleCompile(t, text) // database
		if db == nil {
			return
		}
		fuzzStructured(t, db, input, int64(len(input)))
		if r.framed() {
			fuzzIndirectFrame(t, text, input)
		}
	})
}

// ruleSeedArgs are FuzzRule's seed arguments: each of ruleSeeds with a
// binary input and with a text one, since a rule whose test value is
// printable runs only on text, as in the reference.
func ruleSeedArgs() [][]any {
	inputs := []string{"\x80\x00\x00\x00hello world\x00\x02\x01\x050\x03\x02\x01\x05abcdefgh hello world\n",
		"hello world, abcdefgh hello world\n"}
	var seeds [][]any
	for _, r := range ruleSeeds() {
		for _, in := range inputs {
			seeds = append(seeds, []any{r.typ, r.offsetKind, r.offset, r.indirectType, r.rangeVal, r.flags,
				r.value, r.desc, []byte(in)})
		}
	}
	return seeds
}

// ruleFromArgs is the rule FuzzRule's first eight arguments describe,
// false when they are not its arguments.
func ruleFromArgs(args []any) (ruleFields, bool) {
	a := &argReader{args: args, ok: true}
	r := ruleFields{typ: arg[uint8](a), offsetKind: arg[uint8](a), offset: arg[int64](a),
		indirectType: arg[uint8](a), rangeVal: arg[uint32](a), flags: arg[uint16](a), value: arg[uint64](a),
		desc: arg[string](a)}
	return r, a.done()
}

// fuzzSaturated compares the rules with a numeral past 64 bits with the
// same rules spelled as the reference reads them.
func fuzzSaturated(t *testing.T, over, read string, input []byte) {
	t.Helper()
	odb, rdb := ruleCompile(t, over), ruleCompile(t, read) // overDatabase, readDatabase
	if (odb == nil) != (rdb == nil) {
		t.Fatalf("a numeral past 64 bits changes whether the rules compile:\n%s\n%s", over, read)
	}
	if odb == nil {
		return
	}
	if a, b := odb.Identify(input), rdb.Identify(input); a.Description != b.Description {
		t.Fatalf("a numeral past 64 bits changes the answer: %q vs %q\n%s\n%s", a.Description, b.Description, over, read)
	}
}

// fuzzIndirectFrame compares the rules' answer for input with their
// answer inside an indirect frame that starts where input does.
func fuzzIndirectFrame(t *testing.T, rules string, input []byte) {
	t.Helper()
	if bytes.HasPrefix(input, []byte("IND:")) {
		return
	}
	db, framed := ruleCompile(t, rules), ruleCompile(t, ruleMarker+rules) // database, framedDatabase
	if db == nil || framed == nil {
		t.Fatalf("the rules compile alone or under indirect but not both:\n%s", rules)
	}
	var a, b Result // alone, inFrame
	fuzzBounded(t, "Identify", func() { a = db.Identify(input) })
	fuzzBounded(t, "Identify in an indirect frame", func() { b = framed.Identify(append([]byte("IND:"), input...)) })
	// Only an answer the rules wrote is compared: a line that matches
	// and prints nothing leaves the input alone with "data".
	if a.Examined.Truncated != "" || b.Examined.Truncated != "" || a.Phase != b.Phase || a.Charset != b.Charset ||
		len(a.Rules) == 0 || a.Description == "data" || a.Failures.Description.Failed() || b.Failures.Description.Failed() {
		return
	}
	if b.Description != "IND:"+a.Description {
		t.Fatalf("an indirect frame changes the answer: %q alone, %q in the frame\n%s",
			a.Description, b.Description, rules)
	}
}
