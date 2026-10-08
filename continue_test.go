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
func continueAnswers(t *testing.T, db *Database, path string) [5]string {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
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
	db := compileMagdir(t)
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
