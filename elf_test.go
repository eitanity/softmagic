// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"bytes"
	"context"
	"math"
	"os"
	"testing"
)

// TestIdentifyAtBeyondWindow: with a window smaller than the file, the
// ELF built-in reads section headers through the io.ReaderAt and the
// answer equals the whole-file answer; the bytes-only call cannot.
func TestIdentifyAtBeyondWindow(t *testing.T) {
	db := compileMagdir(t) // database
	data, err := os.ReadFile("testdata/corpus/sample-elf-static.testfile")
	if err != nil {
		t.Fatal(err)
	}
	full := db.Identify(data)
	small := Options{MaxBytes: 4096}
	at := db.IdentifyAt(context.Background(), bytes.NewReader(data), int64(len(data)), small)
	if at.Description != full.Description {
		t.Errorf("IdentifyAt with a 4 KiB window:\n got %q\nwant %q", at.Description, full.Description)
	}
	if at.Examined.Bytes > 4096 {
		t.Errorf("Examined.Bytes = %d, want the window", at.Examined.Bytes)
	}
	only := db.IdentifyWith(context.Background(), data, small)
	if only.Description == full.Description {
		t.Errorf("bytes-only call with a 4 KiB window should not see the section headers: %q", only.Description)
	}
}

// TestExecutableOption: the caller's executable bit reaches ${x?a:b}.
func TestExecutableOption(t *testing.T) {
	db := compileRules(t, "0 string XY ${x?exec:plain} file\n")
	if r := db.IdentifyWith(context.Background(), []byte("XY"), Options{Executable: true}); r.Description != "exec file" {
		t.Errorf("executable: %q", r.Description)
	}
	if r := db.Identify([]byte("XY")); r.Description != "plain file" {
		t.Errorf("plain: %q", r.Description)
	}
}

// TestAppleAnnotation: the first !:apple on the path is reported.
func TestAppleAnnotation(t *testing.T) {
	db := compileRules(t, "0 string XY an XY file\n!:apple TESTABCD\n")
	if r := db.Identify([]byte("XY")); r.Apple != "TESTABCD" {
		t.Errorf("Apple = %q", r.Apple)
	}
	if r := db.Identify([]byte("ZZ")); r.Apple != "" {
		t.Errorf("Apple for no match = %q", r.Apple)
	}
}

// TestIdentifyAtCDFBeyondWindow: the CDF built-in reads sectors past a
// small window through the reader, so the answer equals the whole-file one.
func TestIdentifyAtCDFBeyondWindow(t *testing.T) {
	db := compileMagdir(t) // database
	data, err := os.ReadFile("testdata/corpus/sample-word97-doc.testfile")
	if err != nil {
		t.Fatal(err)
	}
	full := db.Identify(data)
	at := db.IdentifyAt(context.Background(), bytes.NewReader(data), int64(len(data)), Options{MaxBytes: 1024})
	if at.Description != full.Description || at.MIME != full.MIME {
		t.Errorf("IdentifyAt with a 1 KiB window:\n got %q %q\nwant %q %q", at.Description, at.MIME, full.Description, full.MIME)
	}
}

// TestELFReadPastEnd: a segment or section name that starts past the end
// of the file reads as nothing, as pread returns 0 bytes there, and only
// an offset whose sum with the length passes MaxInt64 fails, as Linux's
// pread refuses it. The answers are file 5.48's for the first ELF seed
// with one field changed.
func TestELFReadPastEnd(t *testing.T) {
	db := compileMagdir(t) // database
	const exec = "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), "
	for _, c := range []struct { // pastEndCase
		name string
		mod  func(*elfFields)
		want string
	}{
		{"interpreter past the end", func(e *elfFields) { e.phOffB = math.MaxInt32 + 1 },
			exec + "for GNU/Linux 3.2.0, statically linked, interpreter *empty*, no section header"},
		{"note past the end", func(e *elfFields) { e.phOffA = math.MaxUint32 },
			exec + "statically linked, interpreter *empty*, no section header"},
		{"interpreter end past MaxInt64", func(e *elfFields) { e.phOffB = math.MaxInt64 },
			exec + "for GNU/Linux 3.2.0, can't read section at 9223372036854775807, no section header"},
		{"section name past the end", func(e *elfFields) { e.shnum = 1 },
			exec + "statically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped"},
	} {
		e := elfSeeds()[0]
		c.mod(&e)
		if got := db.Identify(elfImage(&e)).Description; got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}
