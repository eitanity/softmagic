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
	db, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{})
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
		r := db.Identify(data)
		if r.Description == "" || r.MIME == "" || r.Charset == "" {
			t.Fatalf("blank answer for %d bytes: %+v", len(data), r)
		}
		if len(r.Description) > maxOutput {
			t.Fatalf("description over the cap: %d", len(r.Description))
		}
		// Continue mode, raw on alternate inputs: every list present and
		// within the output cap, and the first-match answer unchanged.
		c := db.IdentifyWith(context.Background(), data, Options{Continue: true, Raw: len(data)%2 == 1})
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
	f.Fuzz(func(t *testing.T, rules string) {
		// file -c's dump of the same text: no panic, one line per rule.
		if dump, _ := DumpSources([]Source{{Name: "f", Data: []byte(rules)}}, CompileOptions{}); dump != "" &&
			!strings.HasSuffix(dump, "]\n") {
			t.Fatalf("a dump line not ended as file_mdump ends it: %q", dump)
		}
		db, err := compileFS(fstest.MapFS{"f": &fstest.MapFile{Data: []byte(rules)}}, CompileOptions{})
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		r := db.IdentifyWith(ctx, []byte(rules), Options{})
		if r.Description == "" || r.MIME == "" {
			t.Fatalf("blank answer: %+v", r)
		}
	})
}
