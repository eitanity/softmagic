// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"strings"
	"testing"
	"testing/fstest"
)

// TestAppend covers a caller's own rules searched after the embedded
// database, each sorted on its own, with names visible across both.
func TestAppend(t *testing.T) {
	base := compileMagdir(t)
	rules := "0 string SOFTMAGICX softmagic test format\n!:mime application/x-softmagic\n!:ext smx\n" +
		"0 string ZZTOP uses a base name\n>0 use elf-le\n" +
		"0 name local-name\n>0 byte x local name used\n" +
		"0 string %PDF-\n>0 use local-name\n"
	extra, err := compileFS(fstest.MapFS{"local": &fstest.MapFile{Data: []byte(rules)}}, CompileOptions{SourceDir: "local", Base: base})
	if err != nil {
		t.Fatal(err)
	}
	db, err := joinForTest(base, extra) // database
	if err != nil {
		t.Fatal(err)
	}
	r := db.Identify([]byte("SOFTMAGICX\x00"))
	if r.Description != "softmagic test format" || r.MIME != "application/x-softmagic" || strings.Join(r.Extensions, "/") != "smx" {
		t.Errorf("extra rule: %+v", r)
	}
	if r := db.Identify([]byte("%PDF-1.4\n")); r.Description != "PDF document, version 1.4" {
		t.Errorf("the base map answers first: %q", r.Description)
	}
	if r := db.Identify([]byte("hello world\n")); r.Description != "ASCII text" {
		t.Errorf("text still works: %q", r.Description)
	}
	if db.Hash() == base.Hash() || db.Hash() == extra.Hash() {
		t.Error("the joined hash should cover both")
	}
	listing := db.List()
	if !strings.Contains(listing, "softmagic test format") || !strings.Contains(listing, "WonderWitch") {
		t.Error("listing should show both maps")
	}
	if db.Entries() != base.Entries()+extra.Entries() {
		t.Errorf("entries %d, want %d", db.Entries(), base.Entries()+extra.Entries())
	}
	// Round trip through the compiled form keeps both maps.
	data, err := db.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	db2, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	if r := db2.Identify([]byte("SOFTMAGICX\x00")); r.Description != "softmagic test format" {
		t.Errorf("after round trip: %q", r.Description)
	}
	files := corpusFiles(t)
	for i, f := range files {
		a, b := base.Identify(f), db.Identify(f)
		if a.Description != b.Description || a.MIME != b.MIME {
			t.Errorf("corpus file %d differs with the extra map: %q vs %q", i, a.Description, b.Description)
		}
	}
}
