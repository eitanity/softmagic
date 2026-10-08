// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The expectations in this file are file 5.48's answers for the same input
// and flags (file -b with -P or -e), built from its release tarball.

func identifyCorpus(t *testing.T, db *Database, name string, o Options) Result { // database
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join("testdata/corpus", name)))
	if err != nil {
		t.Fatal(err)
	}
	return db.IdentifyWith(context.Background(), data, o)
}

// TestHardLimitFailure: a name limit stops the description run in the
// middle of an OpenPGP key, and the MIME run, which has no annotation
// before that point, as well. libmagic's text is the buffer, a blank and
// the message: "OpenPGP Public Key name use count (1) exceeded".
func TestHardLimitFailure(t *testing.T) {
	db := compileMagdir(t)
	r := identifyCorpus(t, db, "pgp-binary-key-v4-dsa.testfile", Options{Limits: Limits{Name: 1}}) // result
	want := Failure{Message: "name use count (1) exceeded", Buffer: "OpenPGP Public Key"}
	if r.Failures.Description != want || r.Description != "OpenPGP Public Key" {
		t.Errorf("description: %+v %q", r.Failures.Description, r.Description)
	}
	if got := r.Failures.Description.Text(""); got != "OpenPGP Public Key name use count (1) exceeded" {
		t.Errorf("text %q", got)
	}
	if got := r.Failures.Description.Text("setuid "); got != "setuid OpenPGP Public Key name use count (1) exceeded" {
		t.Errorf("text with a stat-layer prefix %q", got)
	}
	if !r.Failures.MIME.Failed() || r.Failures.MIME.Text("") != "name use count (1) exceeded" {
		t.Errorf("MIME: %+v", r.Failures.MIME)
	}
	if r.Examined.Truncated != TruncName {
		t.Errorf("truncated %q", r.Examined.Truncated)
	}
}

// TestHardLimitPerMode: the same limit leaves an mp3 alone in both modes,
// and an indirect limit of one stops its description inside the ID3
// indirect match, whose own buffer is empty.
func TestHardLimitPerMode(t *testing.T) {
	db := compileMagdir(t)                                                                // database
	r := identifyCorpus(t, db, "JW07022A.mp3.testfile", Options{Limits: Limits{Name: 1}}) // result
	if r.Failures != (Failures{}) || r.MIME != "audio/mpeg" ||
		r.Description != "Audio file with ID3 version 2.2.0, contains: MPEG ADTS, layer III, v1, 96 kbps, 44.1 kHz, Monaural" {
		t.Errorf("name=1: %q %q %+v", r.Description, r.MIME, r.Failures)
	}
	r = identifyCorpus(t, db, "JW07022A.mp3.testfile", Options{Limits: Limits{Indirect: 1}})
	if f := r.Failures.Description; f.Text("") != "indirect count (1) exceeded" || !f.Pushed {
		t.Errorf("indir=1: %+v", f)
	}
}

// TestLimitsChangeAnswers: regex 0 leaves a .docx as plain Zip; a negative
// MaxBytes reads nothing, as bytes=0 does.
func TestLimitsChangeAnswers(t *testing.T) {
	db := compileMagdir(t)
	r := identifyCorpus(t, db, "issue311docx.testfile", Options{Limits: Limits{Regex: -1}})
	if r.Description != "Zip archive data, made by v2.0, extract using at least v2.0, last modified Sep 16 2013 14:48:14, uncompressed size 573, method=deflate" {
		t.Errorf("regex=0: %q", r.Description)
	}
	if r := identifyCorpus(t, db, "json1.testfile", Options{MaxBytes: -1}); r.Description != "empty" {
		t.Errorf("bytes=0: %q", r.Description)
	}
}

// TestExclude: each exclusion is file -e's.
func TestExclude(t *testing.T) {
	db := compileMagdir(t)       // database
	for _, c := range []struct { // testCase
		desc, mime, cs string
		ex             Checks
	}{
		{"ASCII text", "text/plain", "us-ascii", CheckJSON},
		{"JSON text data", "application/json", "binary", CheckEncoding},
		{"data", "application/octet-stream", "us-ascii", CheckSoft | CheckText | CheckJSON},
	} {
		r := identifyCorpus(t, db, "json1.testfile", Options{Exclude: c.ex})
		if r.Description != c.desc || r.MIME != c.mime || r.Charset != c.cs {
			t.Errorf("exclude %b: %q %q %q, want %q %q %q", c.ex, r.Description, r.MIME, r.Charset, c.desc, c.mime, c.cs)
		}
	}
}

// TestTailPastWindow: a line counted from the end reads the file's own
// last bytes, as buffer_fill does, not the window's, when MaxBytes leaves
// the window short of the file; and the lines after it read there too.
// The gzip trailer holds the original size, here 10000.
func TestTailPastWindow(t *testing.T) {
	db := compileMagdir(t) // database
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(bytes.Repeat([]byte("softmagic "), 1000)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	for _, max := range []int{0, 64} {
		r := db.IdentifyAt(context.Background(), bytes.NewReader(data), int64(len(data)), Options{MaxBytes: max})
		if !strings.HasSuffix(r.Description, "original size modulo 2^32 10000") {
			t.Errorf("MaxBytes %d: %q", max, r.Description)
		}
	}
}

// TestQWDate: the qwdate types are 8-byte values in magiccheck and
// moffset, as in the reference. They were missing from that group, so a
// qwdate line never matched (and stopped as an invariant). The expected
// text is file 5.48's for the same rule and bytes, under TZ=UTC.
func TestQWDate(t *testing.T) {
	db := compileRules(t, "0\tstring\tQWD\tqwdate test\n>4\tqwdate\tx\t\\b, at %s\n"+
		">4\tleqwdate\tx\t\\b, le %s\n>12\tbyte\tx\t\\b, then %d\n")
	r := db.Identify([]byte("QWD\x00\x00\x80\x3e\xd5\xde\xb1\x9d\x01\x2a"))
	want := "qwdate test, at Thu Jan  1 00:00:00 1970, le Thu Jan  1 00:00:00 1970, then 42"
	if r.Description != want || r.Examined.Truncated != "" {
		t.Errorf("%q (truncated %q), want %q", r.Description, r.Examined.Truncated, want)
	}
}

// TestDump: file -c's parsed form, for a rule file that uses every field
// and value format file_mdump prints. testdata/dump/rules.dump is file
// 5.48's output for `file -m m/rules -c` under TZ=UTC, past its warning
// and header lines, with rules in a directory named m.
func TestDump(t *testing.T) {
	data, err := os.ReadFile("testdata/dump/rules")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/dump/rules.dump")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DumpSources([]Source{{Name: "rules", Data: data}}, CompileOptions{SourceDir: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("dump differs:\n got %q\nwant %q", got, want)
	}
}
