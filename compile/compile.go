// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

// Package compile builds a softmagic database from rule source on a file
// system, as file(1) reads a magic directory, and identifies the result
// by a SHA-256 of what it read. It is a separate package so that a
// program which only loads a compiled database, the common case, links
// neither the hashing nor its package initialiser.
package compile

import (
	"github.com/eitanity/softmagic"
	"github.com/eitanity/softmagic/internal/invariant"

	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"sort"
)

// Compile reads every regular file at the root of fsys, in byte order of
// name as the reference does, and builds the sorted database. Files whose
// names begin with a dot are skipped, as are directories and anything
// else that is not a regular file.
func Compile(fsys fs.FS, o softmagic.CompileOptions) (*softmagic.Database, error) {
	if fsys == nil {
		return nil, &softmagic.CompileError{File: "", Line: 0, Msg: "nil fs.FS"}
	}
	names, err := listRuleFiles(fsys)
	if err != nil {
		return nil, err
	}
	srcs := make([]softmagic.Source, 0, len(names))
	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, &softmagic.CompileError{File: name, Line: 0, Msg: err.Error()}
		}
		srcs = append(srcs, softmagic.Source{Name: name, Data: data})
	}
	return softmagic.CompileSources(Hash(srcs), srcs, o)
}

// Dump is file -c over a rule directory: each rule line, in the order
// read, in libmagic's parsed form (see softmagic.DumpSources). It reads
// fsys as Compile does.
func Dump(fsys fs.FS, o softmagic.CompileOptions) (string, error) {
	if fsys == nil {
		return "", &softmagic.CompileError{File: "", Line: 0, Msg: "nil fs.FS"}
	}
	names, err := listRuleFiles(fsys)
	if err != nil {
		return "", err
	}
	srcs := make([]softmagic.Source, 0, len(names))
	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return "", &softmagic.CompileError{File: name, Line: 0, Msg: err.Error()}
		}
		srcs = append(srcs, softmagic.Source{Name: name, Data: data})
	}
	return softmagic.DumpSources(srcs, o)
}

// Append returns a database that searches base first and then extra, as
// file(1) searches the directories of `-m a:b`; see Database.Join. Its
// hash is the SHA-256 of both inputs' hashes.
func Append(base, extra *softmagic.Database) (*softmagic.Database, error) {
	if base == nil || extra == nil {
		return nil, &softmagic.LoadError{Msg: "Append of a nil database"}
	}
	return base.Join(extra, joinHash(base.Hash(), extra.Hash()))
}

// Hash is the identity of a rule set: the hex SHA-256 over each source's
// name, a newline and its text, in order.
func Hash(srcs []softmagic.Source) string {
	h := sha256.New()
	invariant.Check(h.Size() == sha256.Size, "SHA-256 digest")
	for _, src := range srcs {
		h.Write([]byte(src.Name))
		h.Write([]byte{'\n'})
		h.Write(src.Data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// joinHash is the identity of two databases searched in order.
func joinHash(a, b string) string {
	invariant.Check(a != "" && b != "", "both hashes given")
	sum := sha256.Sum256([]byte(a + "\n" + b))
	return hex.EncodeToString(sum[:])
}

// listRuleFiles returns the regular, non-dot files at the root, sorted by
// name in byte order.
func listRuleFiles(fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, &softmagic.CompileError{File: ".", Line: 0, Msg: err.Error()}
	}
	names := make([]string, 0, len(entries))
	for _, d := range entries {
		if d.Name()[0] == '.' || !d.Type().IsRegular() {
			continue
		}
		names = append(names, d.Name())
	}
	sort.Strings(names)
	invariant.Check(sort.StringsAreSorted(names), "names sorted")
	return names, nil
}
