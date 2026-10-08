// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"os"
	"strings"
	"testing"
)

func compileMagdir(t *testing.T) *Database {
	t.Helper()
	db, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return db
}

func TestCompileMagdir(t *testing.T) {
	db := compileMagdir(t)
	t.Logf("entries=%d lines=%d set0=%d set1=%d hash=%s",
		db.Entries(), db.Lines(), len(db.maps[0].sets[0]), len(db.maps[0].sets[1]), db.Hash())
}

// TestListOracle compares List() against the reference's file -l,
// byte-identical, in full.
func TestListOracle(t *testing.T) {
	want, err := os.ReadFile("testdata/file-5.48-list.txt")
	if err != nil {
		t.Fatal(err)
	}
	got := compileMagdir(t).List()
	if got == string(want) {
		return
	}
	gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n") // wantLines
	shown := 0
	for i := 0; i < len(gl) && i < len(wl) && shown < 20; i++ {
		if gl[i] != wl[i] {
			t.Errorf("line %d:\n got %q\nwant %q", i+1, gl[i], wl[i])
			shown++
		}
	}
	t.Errorf("listing differs: got %d lines, want %d", len(gl), len(wl))
}
