// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"testing"
)

// TestMain pins the timezone: the reference corpus was produced under
// TZ=UTC, and local-time date types print through it.
func TestMain(m *testing.M) {
	if err := os.Setenv("TZ", "UTC"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// compileFS is the compile package's Compile for tests inside this
// package, which cannot import it: the same listing, reading and hashing.
func compileFS(fsys fs.FS, o CompileOptions) (*Database, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, d := range entries {
		if d.Name()[0] == '.' || !d.Type().IsRegular() {
			continue
		}
		names = append(names, d.Name())
	}
	sort.Strings(names)
	srcs := make([]Source, 0, len(names))
	h := sha256.New()
	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		h.Write([]byte(name))
		h.Write([]byte{'\n'})
		h.Write(data)
		srcs = append(srcs, Source{Name: name, Data: data})
	}
	return CompileSources(hex.EncodeToString(h.Sum(nil)), srcs, o)
}

// joinForTest is the compile package's Append for tests in this package.
func joinForTest(base, extra *Database) (*Database, error) {
	sum := sha256.Sum256([]byte(base.Hash() + "\n" + extra.Hash()))
	return base.Join(extra, hex.EncodeToString(sum[:]))
}
