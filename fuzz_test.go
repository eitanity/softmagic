// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"context"
	"os"
	"path/filepath"
	"runtime/metrics"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	"unicode/utf8"
)

// FuzzIdentify checks that no input may panic, hang or produce a blank
// answer. Seeded from the corpus.
func FuzzIdentify(f *testing.F) {
	db, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{}) // database
	if err != nil {
		f.Fatal(err)
	}
	fuzzSeeds(f, identifySeeds())
	f.Fuzz(func(t *testing.T, data []byte) {
		var r Result // result
		fuzzBounded(t, "Identify", func() { r = db.Identify(data) })
		if r.Description == "" || r.MIME == "" || r.Charset == "" {
			t.Fatalf("blank answer for %d bytes: %+v", len(data), r)
		}
		if len(r.Description) > maxOutput {
			t.Fatalf("description over the cap: %d", len(r.Description))
		}
		fuzzEscaped(t, r)
		// Continue mode, raw on alternate inputs: every list present and
		// within the output cap, and the first-match answer unchanged.
		var c Result // continued
		fuzzBounded(t, "Identify in continue mode", func() {
			c = db.IdentifyWith(context.Background(), data, Options{Continue: true, Raw: len(data)%2 == 1})
		})
		for _, list := range [][]string{c.Continued.Descriptions, c.Continued.MIMEs, c.Continued.Encodings,
			c.Continued.Extensions, c.Continued.Apple} {
			if len(list) == 0 || len(strings.Join(list, "\n- ")) > maxOutput+len(c.Charset) {
				t.Fatalf("continue list missing or over the cap: %q", list)
			}
		}
		if len(data)%2 == 0 {
			fuzzEscaped(t, c)
		}
		// SafeText: the same classification, every string printable ASCII.
		var st Result // safeText
		fuzzBounded(t, "Identify with SafeText", func() {
			st = db.IdentifyWith(context.Background(), data, Options{SafeText: true, Continue: true})
		})
		if st.MIME != r.MIME || st.Phase != r.Phase {
			t.Fatalf("SafeText changed the classification: %q %q vs %q %q", st.MIME, st.Phase, r.MIME, r.Phase)
		}
		fuzzSafeASCII(t, st)
		if len(data)%2 == 0 && c.Description != r.Description {
			t.Fatalf("continue changed the description: %q vs %q", c.Description, r.Description)
		}
		// Exclusions and small limits chosen by the input itself, which
		// drives the hard-limit errors and the per-mode runs they fall
		// back to: still never a blank, and a failure always has a message.
		if len(data) > 3 {
			o := Options{Exclude: Checks(data[0]) | Checks(data[1]&0x0f)<<8, Continue: data[2]&1 != 0,
				Limits: Limits{Indirect: int(data[2]>>1&3) - 1, Name: int(data[2]>>3&3) - 1,
					Regex: int(data[3]&0x3f) - 1, Encoding: int(data[3]>>6) * 16, ELFShsize: int(data[3]&7) - 1}}
			var x Result
			fuzzBounded(t, "Identify with exclusions and limits", func() { x = db.IdentifyWith(context.Background(), data, o) })
			if x.Description == "" || x.MIME == "" || x.Charset == "" {
				t.Fatalf("blank answer with %+v: %+v", o, x)
			}
			for _, f := range []Failure{x.Failures.Description, x.Failures.MIME, x.Failures.Encoding,
				x.Failures.Extension, x.Failures.Apple} {
				if f.Buffer != "" && f.Message == "" {
					t.Fatalf("a failure buffer without a message: %+v", f)
				}
			}
		}
	})
}

// identifySeeds are FuzzIdentify's seed arguments: the corpus files
// under 64 KiB, an empty file and an ELF magic number alone.
func identifySeeds() [][]any {
	var seeds [][]any
	names, err := filepath.Glob("testdata/corpus/*.testfile")
	if err != nil {
		return nil
	}
	for _, n := range names {
		if data, err := os.ReadFile(filepath.Clean(n)); err == nil && len(data) < 64*1024 {
			seeds = append(seeds, []any{data})
		}
	}
	return append(seeds, []any{[]byte{}}, []any{[]byte("\x7fELF")})
}

// compileSeeds are FuzzCompile's seed arguments.
func compileSeeds() [][]any {
	return [][]any{
		{"0 string ABC hello\n>3 byte x %d\n!:mime text/x-abc\n"},
		{"0 regex/100l ^[a-z]+ word\n"},
		{"0 name x\n>0 use x\n"},
		{"0 search/10 abc\n0 lelong&0xff =1 one\n>(4.l+2) ubelong x %u\n"},
		{"0 string XY extra\n>2 use base\n"},
	}
}

// FuzzCompile: no rule text may panic the compiler.
func FuzzCompile(f *testing.F) {
	fuzzSeeds(f, compileSeeds())
	base, err := compileFS(fstest.MapFS{"b": &fstest.MapFile{Data: []byte(
		"0 name base\n>0 byte x \\b, base %d\n0 string AB base rules\n>0 use base\n")}}, CompileOptions{})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, rules string) {
		// file -c's dump of the same text: no panic, one line per rule.
		// A dump cut short by an error is still whole lines up to it.
		dump, dumpErr := DumpSources([]Source{{Name: "f", Data: []byte(rules)}}, CompileOptions{})
		if dump != "" && !strings.HasSuffix(dump, "]\n") {
			t.Fatalf("a dump line not ended as file -c ends it (error %v): %q", dumpErr, dump)
		}
		var db *Database // database
		var err error
		fuzzBounded(t, "Compile", func() {
			db, err = compileFS(fstest.MapFS{"f": &fstest.MapFile{Data: []byte(rules)}}, CompileOptions{})
		})
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var r Result
		fuzzBounded(t, "Identify with fuzzed rules", func() { r = db.IdentifyWith(ctx, []byte(rules), Options{}) })
		if r.Description == "" || r.MIME == "" {
			t.Fatalf("blank answer: %+v", r)
		}
		fuzzJoin(t, base, []byte(rules))
	})
}

// fuzzJoin compiles rules as an extra directory over base, as -m a:b does,
// joins them, marshals and loads the result, and identifies the rules'
// own text with it: the join, the cross-database name lookup and the
// serialised form of a joined database, under hostile rules.
func fuzzJoin(t *testing.T, base *Database, rules []byte) {
	t.Helper()
	extra, err := compileFS(fstest.MapFS{"g": &fstest.MapFile{Data: rules}}, CompileOptions{Base: base, SourceDir: "x"})
	if err != nil {
		return
	}
	joined, err := base.Join(extra, "joined")
	if err != nil {
		t.Fatalf("join of two compiled databases: %v", err)
	}
	data, err := joined.Marshal()
	if err != nil {
		t.Fatalf("marshal of a joined database: %v", err)
	}
	var loaded *Database
	fuzzBounded(t, "Load", func() { loaded, err = Load(data) })
	if err != nil {
		t.Fatalf("load of a marshalled joined database: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var a, b Result
	fuzzBounded(t, "Identify with joined rules", func() { a = joined.IdentifyWith(ctx, rules, Options{Continue: true}) })
	fuzzBounded(t, "Identify with loaded rules", func() { b = loaded.IdentifyWith(ctx, rules, Options{Continue: true}) })
	if a.Description == "" || a.Description != b.Description || a.MIME != b.MIME {
		t.Fatalf("joined %q / %q, loaded %q / %q", a.Description, a.MIME, b.Description, b.MIME)
	}
}

// fuzzEscaped fails when an answer made without Raw holds anything the
// reference's output escaping would have escaped: invalid UTF-8, or a
// character glibc's iswprint rejects, such as a control byte a %c rule
// copied from the input.
func fuzzEscaped(t *testing.T, r Result) {
	t.Helper()
	all := []string{r.Description, r.MIME, r.Charset, r.Apple}
	for _, list := range [][]string{r.Extensions, r.Continued.Descriptions, r.Continued.MIMEs,
		r.Continued.Encodings, r.Continued.Extensions, r.Continued.Apple} {
		all = append(all, list...)
	}
	for _, text := range all {
		if needsEscape(text, utf8.ValidString(text)) || !utf8.ValidString(text) {
			t.Fatalf("an answer without Raw is not escaped: %q", text)
		}
	}
}

// fuzzSafeASCII fails when a SafeText answer or failure buffer holds a byte
// outside printable ASCII.
func fuzzSafeASCII(t *testing.T, r Result) {
	t.Helper()
	all := []string{r.Description, r.MIME, r.Charset, r.Apple, r.Failures.Description.Buffer,
		r.Failures.MIME.Buffer, r.Continued.Failures.Description.Buffer}
	for _, list := range [][]string{r.Extensions, r.Continued.Descriptions, r.Continued.MIMEs,
		r.Continued.Encodings, r.Continued.Extensions, r.Continued.Apple} {
		all = append(all, list...)
	}
	for _, text := range all {
		for i := 0; i < len(text); i++ {
			if !cIsPrint(text[i]) {
				t.Fatalf("byte %#x in a SafeText answer: %q", text[i], text)
			}
		}
	}
}

// fuzzAllocBudget is the most one call may allocate: the largest buffer
// the library reads into (a CDF chain at cdfChainLimit) with room for the
// rest of a scan. fuzzTimeBudget is the most one call may take.
const (
	fuzzAllocBudget = 64 << 20
	fuzzTimeBudget  = 2 * time.Second
)

// heapAllocated is the bytes the process has allocated so far. Small
// allocations are counted when a cache refills, so the figure lags by a
// few KiB, which is far below the budget.
func heapAllocated() uint64 {
	sample := []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}
	metrics.Read(sample)
	return sample[0].Value.Uint64()
}

// fuzzBounded runs one call and fails when it allocates more than
// fuzzAllocBudget or takes longer than fuzzTimeBudget, so a call that
// returns the right answer at an unbounded cost is still a failure.
func fuzzBounded(t *testing.T, what string, call func()) {
	t.Helper()
	before, start := heapAllocated(), time.Now()
	call()
	elapsed, alloc := time.Since(start), heapAllocated()-before
	if alloc > fuzzAllocBudget {
		t.Fatalf("%s allocated %d MiB, over the %d MiB budget", what, alloc>>20, fuzzAllocBudget>>20)
	}
	if elapsed > fuzzTimeBudget {
		t.Fatalf("%s took %v, over the %v budget", what, elapsed, fuzzTimeBudget)
	}
}
