// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// FuzzIdentify checks that no input may panic, hang or produce a blank
// answer. Seeded from the corpus.
func FuzzIdentify(f *testing.F) {
	db, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{}) // database
	if err != nil {
		f.Fatal(err)
	}
	names, err := filepath.Glob("testdata/corpus/*.testfile")
	if err != nil {
		f.Fatal(err)
	}
	for _, n := range names {
		if data, err := os.ReadFile(filepath.Clean(n)); err == nil && len(data) < 64*1024 {
			f.Add(data)
		}
	}
	f.Add([]byte{})
	f.Add([]byte("\x7fELF"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := db.Identify(data) // result
		if r.Description == "" || r.MIME == "" || r.Charset == "" {
			t.Fatalf("blank answer for %d bytes: %+v", len(data), r)
		}
		if len(r.Description) > maxOutput {
			t.Fatalf("description over the cap: %d", len(r.Description))
		}
		// Continue mode, raw on alternate inputs: every list present and
		// within the output cap, and the first-match answer unchanged.
		c := db.IdentifyWith(context.Background(), data, Options{Continue: true, Raw: len(data)%2 == 1}) // continued
		for _, list := range [][]string{c.Continued.Descriptions, c.Continued.MIMEs, c.Continued.Encodings,
			c.Continued.Extensions, c.Continued.Apple} {
			if len(list) == 0 || len(strings.Join(list, "\n- ")) > maxOutput+len(c.Charset) {
				t.Fatalf("continue list missing or over the cap: %q", list)
			}
		}
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
			x := db.IdentifyWith(context.Background(), data, o)
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

// FuzzCompile: no rule text may panic the compiler.
func FuzzCompile(f *testing.F) {
	f.Add("0 string ABC hello\n>3 byte x %d\n!:mime text/x-abc\n")
	f.Add("0 regex/100l ^[a-z]+ word\n")
	f.Add("0 name x\n>0 use x\n")
	f.Add("0 search/10 abc\n0 lelong&0xff =1 one\n>(4.l+2) ubelong x %u\n")
	f.Add("0 string XY extra\n>2 use base\n")
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
		db, err := compileFS(fstest.MapFS{"f": &fstest.MapFile{Data: []byte(rules)}}, CompileOptions{}) // database
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		r := db.IdentifyWith(ctx, []byte(rules), Options{})
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
	loaded, err := Load(data)
	if err != nil {
		t.Fatalf("load of a marshalled joined database: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	a := joined.IdentifyWith(ctx, rules, Options{Continue: true})
	b := loaded.IdentifyWith(ctx, rules, Options{Continue: true})
	if a.Description == "" || a.Description != b.Description || a.MIME != b.MIME {
		t.Fatalf("joined %q / %q, loaded %q / %q", a.Description, a.MIME, b.Description, b.MIME)
	}
}
