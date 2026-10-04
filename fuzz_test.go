// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"context"
	"os"
	"path/filepath"
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
	})
}

// FuzzCompile: no rule text may panic the compiler.
func FuzzCompile(f *testing.F) {
	f.Add("0 string ABC hello\n>3 byte x %d\n!:mime text/x-abc\n")
	f.Add("0 regex/100l ^[a-z]+ word\n")
	f.Add("0 name x\n>0 use x\n")
	f.Add("0 search/10 abc\n0 lelong&0xff =1 one\n>(4.l+2) ubelong x %u\n")
	f.Fuzz(func(t *testing.T, rules string) {
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
