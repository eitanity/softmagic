// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParityCorpus checks every corpus file against the
// reference's `file -b`, `-b -i`, `-b --extension` and `-b --apple`
// outputs. Any difference fails; the figure is logged.
func TestParityCorpus(t *testing.T) {
	db := compileMagdir(t) // database
	files, err := filepath.Glob("testdata/corpus/*.testfile")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skip("no corpus")
	}
	var okDesc, okMime, okExt, okApple, total int
	for _, f := range files { // fileName
		data, err := os.ReadFile(filepath.Clean(f))
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(strings.TrimSuffix(f, ".testfile") + ".expect")
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimRight(string(want), "\n"), "\n")
		if len(lines) < 3 {
			continue
		}
		total++
		r := db.Identify(data) // result
		name := filepath.Base(f)
		if r.Description == lines[0] {
			okDesc++
		} else {
			t.Errorf("%s: desc\n got %q\nwant %q", name, r.Description, lines[0])
		}
		gotMime := r.MIME + "; charset=" + r.Charset
		if gotMime == lines[1] {
			okMime++
		} else {
			t.Errorf("%s: mime got %q want %q", name, gotMime, lines[1])
		}
		gotExt := strings.Join(r.Extensions, "/")
		if gotExt == "" {
			gotExt = "???"
		}
		if gotExt == lines[2] {
			okExt++
		} else {
			t.Errorf("%s: ext got %q want %q", name, gotExt, lines[2])
		}
		gotApple := r.Apple
		if gotApple == "" {
			gotApple = "UNKNUNKN" // what `file --apple` prints for none
		}
		if len(lines) >= 4 && gotApple == lines[3] {
			okApple++
		} else if len(lines) >= 4 {
			t.Errorf("%s: apple got %q want %q", name, gotApple, lines[3])
		}
		if r.Examined.Truncated != "" {
			t.Logf("%s: truncated %q", name, r.Examined.Truncated)
		}
	}
	t.Logf("parity: description %d/%d, mime %d/%d, extension %d/%d, apple %d/%d", okDesc, total, okMime, total, okExt, total, okApple, total)
}

func TestIdentifyBasics(t *testing.T) {
	db := compileMagdir(t) // database
	cases := []struct {
		in   string
		want string
	}{
		{"", "empty"},
		{"x", "very short file (no magic)"},
		{"hello world\n", "ASCII text"},
		{"hello world\r\n", "ASCII text, with CRLF line terminators"},
		{"\x00\x01\x02\x03\x04\x05", "data"},
		{"#!/bin/sh\necho hi\n", "POSIX shell script, ASCII text executable"},
		{"%PDF-1.4\n", "PDF document, version 1.4"},
	}
	for _, c := range cases {
		r := db.Identify([]byte(c.in))
		if r.Description != c.want {
			t.Errorf("Identify(%q) = %q, want %q (rules %v)", c.in, r.Description, c.want, r.Rules)
		}
	}
}
