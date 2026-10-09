// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"testing/fstest"
)

// TestSafeText: text from the input is escaped as \xHH, markup and quote
// characters and backslashes included; the rules' own text is kept; Raw
// does not undo it.
func TestSafeText(t *testing.T) {
	db := compileMagdir(t)
	for _, c := range []struct { // testCase
		in, want string
	}{
		{"#!/usr/bin/env <img src=x onerror=alert(1)>\n", "a \\x3cimg src=x onerror=alert(1)\\x3e script, ASCII text executable"},
		{"#!/usr/bin/env py\\012thon\n", "a py\\x5c012thon script, ASCII text executable"},
		{"#!/usr/bin/env caf\xc3\xa9\n", "a caf\\xc3\\xa9 script, Unicode text, UTF-8 text executable"},
		{"#!/usr/bin/env a\"b'c`d&e\n", "a a\\x22b\\x27c\\x60d\\x26e script, ASCII text executable"},
	} {
		for _, raw := range []bool{false, true} {
			r := db.IdentifyWith(context.Background(), []byte(c.in), Options{SafeText: true, Raw: raw})
			if r.Description != c.want {
				t.Errorf("SafeText(%q, raw %v) = %q, want %q", c.in, raw, r.Description, c.want)
			}
		}
	}
	data, err := os.ReadFile(filepath.Join("testdata", "corpus", "sample-os2-msg-control.testfile"))
	if err != nil {
		t.Fatal(err)
	}
	r := db.IdentifyWith(context.Background(), data, Options{SafeText: true, Continue: true})
	want := "OS/2 help message 'DOS', 1 messages, version 0, at 0x30 \\x1b-type hello, " +
		"at 0 \\xff-type MKMSGF, at 0 \\xff-type MKMSGF"
	if r.Description != want || len(r.Continued.Descriptions) != 2 || r.Continued.Descriptions[0] != want {
		t.Errorf("OS/2 %%c bytes under SafeText:\n got %q %q\nwant %q", r.Description, r.Continued.Descriptions, want)
	}
}

// FuzzSafeText: over rules that copy the input into the answer (%c, %s of
// a string and of a regex match), the SafeText answer is printable ASCII
// with none of SafeText's escaped characters left as they are, and
// decoding its \xHH escapes gives back exactly the Raw answer.
func FuzzSafeText(f *testing.F) {
	db, err := compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte(
		"0\tubyte\tx\t%c\n>1\tstring\tx\t\\b, %s\n>0\tregex\t[^\\n]+\t\\b, %s\n")}}, CompileOptions{})
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"<a href='x'>", "\x1b[31m\\x", "\xff\xfe\x00z", "caf\xc3\xa9 \"q\" `b` &amp;"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		safe := db.IdentifyWith(context.Background(), data, Options{SafeText: true})
		raw := db.IdentifyWith(context.Background(), data, Options{Raw: true})
		for i := 0; i < len(safe.Description); i++ {
			if c := safe.Description[i]; !cIsPrint(c) || (c != '\\' && !safeTextByte(c) && c != ',') {
				t.Fatalf("byte %#x left in a SafeText answer: %q", c, safe.Description)
			}
		}
		if safe.Examined.Truncated != "" || raw.Examined.Truncated != "" {
			return // the escapes are longer, so the output cap cuts at another place
		}
		if got, ok := unescapeSafeText(safe.Description); !ok || got != raw.Description {
			t.Fatalf("decoded SafeText %q (%v) is not the Raw answer %q", got, ok, raw.Description)
		}
	})
}

// unescapeSafeText reverses SafeText's escaping: each backslash starts \xHH.
func unescapeSafeText(s string) (string, bool) {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b = append(b, s[i])
			continue
		}
		if i+3 >= len(s) || s[i+1] != 'x' {
			return "", false
		}
		v, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
		if err != nil {
			return "", false
		}
		b = append(b, byte(v))
		i += 3
	}
	return string(b), true
}
