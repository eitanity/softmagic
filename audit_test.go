// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"testing/fstest"
)

// auditCase is one input the 2026-10-22 audit built, with file 5.48's
// answer to it. The input is a FuzzIdentify corpus entry, read with the
// stock rules, or input itself, read with rules. A case whose ticket is
// still open is expected to differ from file and fails once it does not,
// so that whoever fixes the ticket makes the case a plain check.
type auditCase struct {
	ticket string
	entry  string // under testdata/fuzz/FuzzIdentify
	rules  string
	input  string
	want   string
	open   bool
}

// auditCases are the audit's inputs not already checked elsewhere: the
// ranges, der and search offsets and numerals are in ranges_test.go, the
// CDF chains in cdf_test.go and the JPEG comments in the FuzzIdentify
// corpus.
func auditCases() []auditCase {
	const elf = "ELF 64-bit LSB "
	const exec = elf + "executable, x86-64, version 1 (SYSV), "
	const date = "0\tleqdate\tx\tdate %s\n"
	return []auditCase{
		{ticket: "SOF-11", open: true, entry: "elf-note-offset-negative",
			want: exec + "no program header, can't read elf note at -16"},
		{ticket: "SOF-11", open: true, entry: "elf-shoff-negative",
			want: exec + "no program header, too large section header offset 4198400"},
		{ticket: "SOF-11", open: true, entry: "elf-core-note-negative",
			want: elf + "core file, x86-64, version 1 (SYSV) can't read note section at -256"},
		{ticket: "SOF-11", open: true, entry: "elf-section-offset-negative",
			want: exec + "can't read section at -256, no section header"},
		{ticket: "SOF-11", open: true, entry: "elf-core-auxv-wrap",
			want: elf + "core file, x86-64, version 1 (SYSV), SVR4-style, execfn: '/bin/evil'"},
		{ticket: "SOF-11", open: true, entry: "elf-phoff-negative",
			want: exec + "can't read elf program headers at -256, no section header"},
		{ticket: "SOF-14", open: true, entry: "elf-note-past-end", want: exec + "no program header, stripped"},
		{ticket: "SOF-15", open: true, entry: "elf-debug-info-last",
			want: elf + "relocatable, x86-64, version 1 (SYSV), stripped"},
		{ticket: "SOF-12", open: true, input: "0\x03\x02\x01\x05\x00\x00\x00", want: "A B C2",
			rules: "0\tstring\t\\x30\\x03\tA\n>&0xfffffffe\tder\tseq\tB\n>>&0\tbyte\tx\tD%d\n>&0\tbyte\tx\tC%d\n"},
		{ticket: "SOF-8", open: true, rules: date, input: "\x00\x00\x00\x00\x00\x00\x00\x80", want: "date *Invalid datetime*"},
		{ticket: "SOF-8", open: true, rules: date, input: "\x00\x00\x00\x00\x00\x00\x00\xff", want: "date *Invalid datetime*"},
		{ticket: "SOF-8", open: true, rules: date, input: "\x00\x77\x0b\x2f\xea\xff\xff\xff", want: "date *Invalid datetime*"},
		{ticket: "SOF-8", open: true, rules: date, input: "\x00\xd9\x9b\xdd\xf8\xff\xff\xff", want: "date Tue Jan  1 00:00:00 999"},
		{ticket: "SOF-8", rules: date, input: "\x00\xf1\x53\x65\x00\x00\x00\x00", want: "date Tue Nov 14 22:13:20 2023"},
		{ticket: "SOF-10", rules: "0\tpstring/J\tx\tPS[%s]\n", input: "abcdefgh hello world\nline2\n",
			want: "PS[bcdefgh hello world]"},
		{ticket: "SOF-10", rules: "0\tpstring/LJ\tx\tPS[%s]\n", input: "\x00\x00\x00\x03abcdefgh hello world\nline2\n",
			want: "data"},
		{ticket: "SOF-4", rules: "0\tlong\tx\n>(0.L*0x7fffffff)\tbyte\tx\tIND\n",
			input: "\xff\xff\xff\xfe\x01\x02\x03\x04\x05\x06", want: "data"},
	}
}

// TestAuditReproductions checks each of auditCases within the fuzz
// budgets.
func TestAuditReproductions(t *testing.T) {
	stock := compileMagdir(t) // database
	for _, c := range auditCases() {
		name, db, data := c.ticket+" "+c.entry, stock, []byte(c.input) // database
		if c.entry != "" {
			data = auditEntry(t, c.entry)
		} else {
			var err error
			if db, err = compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte(c.rules)}}, CompileOptions{}); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			name += strconv.Quote(c.rules)
		}
		var got string
		fuzzBounded(t, name, func() { got = db.Identify(data).Description })
		switch {
		case !c.open && got != c.want:
			t.Errorf("%s: %q, want %q", name, got, c.want)
		case c.open && got == c.want:
			t.Errorf("%s: matches file 5.48 (%q); if %s is fixed, the case is no longer open", name, got, c.ticket)
		case c.open:
			t.Logf("%s: open: %q, file 5.48 %q", name, got, c.want)
		}
	}
}

// auditEntry is the input of the FuzzIdentify corpus entry name.
func auditEntry(t *testing.T, name string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Join("testdata", "fuzz", "FuzzIdentify"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := root.ReadFile(name)
	if cerr := root.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	args, err := decodeFuzzEntry(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	data, ok := args[0].([]byte)
	if len(args) != 1 || !ok {
		t.Fatalf("%s: not a FuzzIdentify entry", name)
	}
	return data
}
