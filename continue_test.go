// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestContinueCorpus checks continue mode against the reference's own output
// for every corpus file, in each of the five output modes. testdata/
// continue.json was made by file 5.48 built from its release tarball (the
// build softmagic-cli's scripts/reference.sh makes), run as
// `file -r -b -k [--mime-type|--mime-encoding|--extension|--apple] <file>`
// with TZ=UTC; raw output keeps the separators as newlines, so the joined
// lists are compared byte for byte. Each byte of that output is stored as
// the code point of the same value.
func TestContinueCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/continue.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string][5]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) == 0 {
		t.Fatal("no expectations")
	}
	db := compileMagdir(t)
	for name, w := range want {
		got := continueAnswers(t, db, filepath.Join("testdata/corpus", name))
		for i, mode := range []string{"description", "MIME", "encoding", "extension", "Apple"} {
			if exp := latin1Bytes(w[i]); got[i] != exp {
				t.Errorf("%s %s:\n got %q\nwant %q", name, mode, got[i], exp)
			}
		}
	}
}

// continueAnswers identifies a file as the CLI does, with continue and raw
// output, and returns each mode's list joined as file -k prints it.
func continueAnswers(t *testing.T, db *Database, path string) [5]string { // database
	t.Helper()
	f, err := os.Open(filepath.Clean(path)) // corpusFile
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Error(cerr)
		}
	}()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	r := db.IdentifyAt(context.Background(), f, info.Size(), Options{Continue: true, Raw: true})
	c := r.Continued
	join := func(a []string) string { return strings.Join(a, "\n- ") }
	return [5]string{join(c.Descriptions), join(c.MIMEs), join(c.Encodings), join(c.Extensions), join(c.Apple)}
}

// latin1Bytes turns the stored code points back into the bytes they stand for.
func latin1Bytes(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		b = append(b, smallUint8(int(r))) // every stored code point is below 256
	}
	return string(b)
}

// TestContinueLeavesFirstMatch: asking for continue mode changes nothing
// but Continued.
func TestContinueLeavesFirstMatch(t *testing.T) {
	db := compileMagdir(t) // database
	files, err := filepath.Glob("testdata/corpus/*.testfile")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		plain := db.Identify(data)
		cont := db.IdentifyWith(context.Background(), data, Options{Continue: true})
		if len(cont.Continued.Descriptions) == 0 || len(cont.Continued.Encodings) == 0 {
			t.Fatalf("%s: continue mode returned no lists", name)
		}
		cont.Continued = Continued{}
		if pj, cj := mustJSON(t, plain), mustJSON(t, cont); pj != cj {
			t.Errorf("%s: first-match fields changed\n plain %s\n  cont %s", name, pj, cj)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestIndependentRunsAgree: without a hard limit, one file_buffer run per
// output mode gives exactly the first-match answers, which derive the MIME,
// extension and Apple answers from the description run. The runs are what
// a hard limit falls back to, so they must be right where nothing fails.
func TestIndependentRunsAgree(t *testing.T) {
	db := compileMagdir(t) // database
	files, err := filepath.Glob("testdata/corpus/*.testfile")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		want := db.Identify(data)
		got := db.identifyIndependent(data)
		if want.Description != got.Description || want.MIME != got.MIME ||
			strings.Join(want.Extensions, "/") != strings.Join(got.Extensions, "/") || want.Apple != got.Apple {
			t.Errorf("%s:\n first match %q | %q | %q | %q\n independent %q | %q | %q | %q", filepath.Base(name),
				want.Description, want.MIME, want.Extensions, want.Apple,
				got.Description, got.MIME, got.Extensions, got.Apple)
		}
	}
}

// TestContinueEscaped: without Raw, each list is escaped as the reference
// escapes the one buffer it prints, so joined with the separator as that
// escaping prints it ("\012- ") a list is file -b -k's output. The
// expectations are file 5.48's, for files whose %c rules print ESC, NUL
// and 0xff.
func TestContinueEscaped(t *testing.T) {
	db := compileMagdir(t)
	for name, want := range map[string]string{
		"sample-os2-msg-control.testfile": "OS/2 help message 'DOS', 1 messages, version 0, at 0x30 \\033-type hello, " +
			"at 0 \\377-type MKMSGF, at 0 \\377-type MKMSGF\\012- data",
		"sample-os2-msg-nul.testfile": "OS/2 help message 'DOS', 1 messages, version 0, at 0x30  hello, " +
			"at 0 \\377-type MKMSGF, at 0 \\377-type MKMSGF\\012- data",
	} {
		data, err := os.ReadFile(filepath.Clean(filepath.Join("testdata/corpus", name)))
		if err != nil {
			t.Fatal(err)
		}
		r := db.IdentifyWith(context.Background(), data, Options{Continue: true})
		if got := strings.Join(r.Continued.Descriptions, "\\012- "); got != want {
			t.Errorf("%s:\n got %q\nwant %q", name, got, want)
		}
	}
}
