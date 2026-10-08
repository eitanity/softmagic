// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// compileRules compiles a single in-memory rule file.
func compileRules(t *testing.T, rules string) *Database {
	t.Helper()
	db, err := compileFS(fstest.MapFS{"test": &fstest.MapFile{Data: []byte(rules)}}, CompileOptions{SourceDir: "t"})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return db
}

// TestBoundsOutput reaches Truncated "output": a rule tree that
// emits more than the cap.
func TestBoundsOutput(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("0 string ABC head\n")
	for i := 0; i < 200; i++ {
		sb.WriteString(">0 string ABC " + strings.Repeat("x", 60) + "\n")
	}
	db := compileRules(t, sb.String())
	r := db.Identify([]byte("ABC"))
	if r.Examined.Truncated != TruncOutput {
		t.Errorf("Truncated = %q, want %q", r.Examined.Truncated, TruncOutput)
	}
	if len(r.Description) > maxOutput {
		t.Errorf("description longer than the cap: %d", len(r.Description))
	}
}

// TestBoundsRecursion reaches Truncated "recursion": a name that
// uses itself.
func TestBoundsRecursion(t *testing.T) {
	db := compileRules(t, "0 name loop\n>0 byte x looped\n>0 use loop\n\n0 string X start\n>0 use loop\n")
	r := db.Identify([]byte("XYZ"))
	if r.Examined.Truncated != TruncRecursion {
		t.Errorf("Truncated = %q, want %q (desc %q)", r.Examined.Truncated, TruncRecursion, r.Description)
	}
	if !strings.HasPrefix(r.Description, "start") {
		t.Errorf("description %q lost what was established", r.Description)
	}
}

// TestBoundsTime reaches Truncated "time": a cancelled context.
func TestBoundsTime(t *testing.T) {
	db := compileMagdir(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := db.IdentifyWith(ctx, bytes.Repeat([]byte("a"), 1000), Options{})
	if r.Examined.Truncated != TruncTime {
		t.Errorf("Truncated = %q, want %q", r.Examined.Truncated, TruncTime)
	}
	if r.Description == "" || r.MIME == "" {
		t.Errorf("a blank is never an answer: %+v", r)
	}
}

// TestBoundsDeadline: an expired deadline is reported the same way.
func TestBoundsDeadline(t *testing.T) {
	db := compileMagdir(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	r := db.IdentifyWith(ctx, bytes.Repeat([]byte("a"), 1000), Options{})
	if r.Examined.Truncated != TruncTime {
		t.Errorf("Truncated = %q, want %q", r.Examined.Truncated, TruncTime)
	}
}

// TestBoundsInvariant exercises the release-mode recovery path through a
// test hook only when assertions are off; under the tag the same hook
// panics, so it is skipped.
func TestBoundsInvariant(t *testing.T) {
	if invariantEnabled() {
		t.Skip("assertions panic in this build")
	}
	s := &scan{}
	if s.fail("forced") {
		t.Error("fail reported success")
	}
	if s.truncated != TruncInvariant {
		t.Errorf("Truncated = %q, want %q", s.truncated, TruncInvariant)
	}
}

// TestMaxBytes: the window is capped and reported.
func TestMaxBytes(t *testing.T) {
	db := compileMagdir(t)
	data := append([]byte("hello "), bytes.Repeat([]byte("x"), 5000)...)
	r := db.IdentifyWith(context.Background(), data, Options{MaxBytes: 100})
	if r.Examined.Bytes > 100 {
		t.Errorf("Examined.Bytes = %d, want <= 100", r.Examined.Bytes)
	}
}

// TestIdentifyPrefix: a complete signature at offset 0 is final; a prefix
// that cuts a test short says NeedMore.
func TestIdentifyPrefix(t *testing.T) {
	db := compileMagdir(t) // database
	pdf := []byte("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	r := db.IdentifyPrefix(context.Background(), pdf, Options{})
	if r.Examined.Complete {
		t.Error("prefix reported complete")
	}
	if r.Description != "PDF document, version 1.7" {
		t.Errorf("description %q", r.Description)
	}
	r2 := db.IdentifyPrefix(context.Background(), []byte("%P"), Options{})
	if !r2.Examined.NeedMore {
		t.Error("two bytes of a signature should need more")
	}
	full := db.Identify(pdf)
	if full.Examined.NeedMore || !full.Examined.Complete {
		t.Errorf("complete input: %+v", full.Examined)
	}
}

// TestResultContract checks the Result contract: no blank answers, the database hash and
// release on every result.
func TestResultContract(t *testing.T) {
	db := compileMagdir(t)                                                        // database
	for _, in := range [][]byte{nil, []byte("x"), []byte("hello\n"), {0, 1, 2}} { // input
		r := db.Identify(in)
		if r.Description == "" || r.MIME == "" || r.Charset == "" {
			t.Errorf("blank field for %q: %+v", in, r)
		}
		if r.Examined.DatabaseHash != db.Hash() || r.Examined.ImplementsFile != ImplementsFile {
			t.Errorf("examined identity for %q: %+v", in, r.Examined)
		}
	}
}

// TestCompileErrors: refused constructs name the file and line.
func TestCompileErrors(t *testing.T) {
	cases := []string{
		"0 bogus 1 x\n",
		"0 string\n",
		">0 byte 1 no parent\n",
		"0 regex ** bad\n",
		"0 byte 1 ok\n!:mime\n",
		"0 use nothere\n",
		"0 long 1 %s wrong format\n",
	}
	for _, c := range cases { // ruleText
		_, err := compileFS(fstest.MapFS{"f": &fstest.MapFile{Data: []byte(c)}}, CompileOptions{})
		var ce *CompileError
		if !errors.As(err, &ce) {
			t.Errorf("%q: error %v, want *CompileError", c, err)
			continue
		}
		if ce.File == "" || ce.Line == 0 {
			t.Errorf("%q: error without file and line: %v", c, err)
		}
	}
}

// TestAllocations checks that the identify core allocates only
// what the Result carries.
func TestAllocations(t *testing.T) {
	db := compileMagdir(t) // database
	data, err := os.ReadFile("testdata/corpus/zstd-v0.2-FF.testfile")
	if err != nil {
		t.Skip(err)
	}
	db.Identify(data) // warm the pool
	allocs := testing.AllocsPerRun(50, func() { db.Identify(data) })
	t.Logf("allocs per Identify: %.1f", allocs)
	if allocs > 6 {
		t.Errorf("allocs per Identify = %.1f, want at most 6 (the Result's own)", allocs)
	}
}
