// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package compile_test

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/eitanity/softmagic"
	"github.com/eitanity/softmagic/compile"
)

// TestMatchesEmbedded checks that compiling the vendored Magdir through
// this package gives the embedded database: same hash, same listing.
func TestMatchesEmbedded(t *testing.T) {
	db, err := compile.Compile(os.DirFS("../magic/Magdir"), softmagic.CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	def, err := softmagic.Default()
	if err != nil {
		t.Fatal(err)
	}
	if db.Hash() != def.Hash() {
		t.Fatalf("hash %s, embedded %s", db.Hash(), def.Hash())
	}
	if db.List() != def.List() {
		t.Fatal("listing differs from the embedded database")
	}
	want, err := os.ReadFile("../testdata/file-5.48-list.txt")
	if err != nil {
		t.Fatal(err)
	}
	if db.List() != string(want) {
		t.Fatal("listing differs from file -l")
	}
}

func TestAppend(t *testing.T) {
	base, err := softmagic.Default()
	if err != nil {
		t.Fatal(err)
	}
	extra, err := compile.Compile(fstest.MapFS{
		"mine":    &fstest.MapFile{Data: []byte("0\tstring\tMYMAGIC\tmy own format\n")},
		".hidden": &fstest.MapFile{Data: []byte("garbage that must be skipped\n")},
	}, softmagic.CompileOptions{SourceDir: "extra", Base: base})
	if err != nil {
		t.Fatal(err)
	}
	db, err := compile.Append(base, extra)
	if err != nil {
		t.Fatal(err)
	}
	if r := db.Identify([]byte("MYMAGIC here")); r.Description != "my own format" {
		t.Fatalf("extra rule not used: %q", r.Description)
	}
	if r := db.Identify([]byte("#!/bin/sh\n")); r.MIME != "text/x-shellscript" {
		t.Fatalf("base rules lost: %q", r.MIME)
	}
	if db.Hash() == base.Hash() || db.Hash() == extra.Hash() || len(db.Hash()) != 64 {
		t.Fatalf("joined hash %q", db.Hash())
	}
	if _, err := compile.Append(nil, extra); err == nil {
		t.Fatal("nil base accepted")
	}
	if _, err := compile.Compile(nil, softmagic.CompileOptions{}); err == nil {
		t.Fatal("nil fs accepted")
	}
}
