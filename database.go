// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"github.com/eitanity/softmagic/internal/invariant"

	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Database is a compiled, immutable rule set. It is safe for concurrent use:
// nothing writes to it after Compile returns, and all per-call state lives
// in the pooled scan.
type Database struct {
	// pool hands out per-call scans.
	pool *scanPool
	// names maps a "name" entry's name to its lines (file_magicfind).
	names map[string]entry
	// hash is the SHA-256 of the source files, hex, reported as Examined.DatabaseHash.
	hash string
	// sourceDir is the directory name tucked into empty descriptions.
	sourceDir string
	// recs holds every rule line, entries contiguous, sets in order.
	recs []record
	// meta holds the per-line Go-side data that is not part of the
	// reference's struct magic: compiled regexes and interned strings.
	meta []lineMeta
	// files holds the source file names, indexed by lineMeta.file.
	files []string
	// regexes holds the regex lines' patterns, compiled on first use.
	regexes []regexSlot
	// maps holds each loaded source in search order: the reference's
	// struct magic_map per directory (file -m a:b), each sorted on its own.
	maps []dbMap
	// pre is the prefilter of every line (active only on binary-set first
	// lines), parallel to recs.
	pre []prefilter
	// entryEnd is, for every line, the index of the first line after its
	// entry, so skipping an entry is one step rather than a walk.
	entryEnd []int32
	// eager is set when every regex slot was compiled before the database
	// was published, so the matcher never touches a slot's sync.Once.
	eager bool
}

// dbMap is one loaded source. sets[0] is its regular entries and sets[1]
// its "name" entries, each in the reference's matching order; its binary set's
// lines are db.recs[first:first+count], contiguous.
type dbMap struct {
	sets  [2][]entry
	first int32
	count int32
}

// lineMeta is the Go-side data of one rule line.
type lineMeta struct {
	file int32 // index into Database.files
	rx   int32 // index into Database.regexes for regex lines, else -1
}

// mimeOf is a line's !:mime annotation as a string.
func (db *Database) mimeOf(rec int32) string { return db.recs[rec].mimeString() }

// extOf is a line's !:ext annotation as a string.
func (db *Database) extOf(rec int32) string { return cString(db.recs[rec].ext) }

// regexSlot compiles a regex line's pattern on first use,
// behind a sync.Once per rule, so that loading the compiled database stays
// under a millisecond. Slots are addressed in place and never copied.
type regexSlot struct {
	re        *regexp.Regexp
	pattern   string
	lits      [][]byte // literals of which every match contains one; nil when none is known
	fold      bool     // the literals' letters match either case
	lineStart bool     // the literal is at the start of a line
	once      sync.Once
}

// regexSlot is the slot of a regex line, nil when it has none.
func (db *Database) regexSlot(rec int32) *regexSlot {
	invariant.Check(len(db.meta) == len(db.recs), "meta parallel to records")
	if rec < 0 || int(rec) >= len(db.meta) || db.meta[rec].rx < 0 {
		return nil
	}
	return &db.regexes[db.meta[rec].rx]
}

// regex returns the compiled pattern of a line, nil when it has none or
// the pattern does not compile (which Compile refuses up front; a loaded
// database is trusted to have been produced by Compile).
func (db *Database) regex(rec int32) *regexp.Regexp {
	if rec < 0 || int(rec) >= len(db.meta) || db.meta[rec].rx < 0 {
		return nil
	}
	slot := &db.regexes[db.meta[rec].rx]
	if db.eager {
		return slot.re
	}
	slot.once.Do(func() {
		slot.re = compilePattern(slot.pattern)
	})
	return slot.re
}

// compilePattern compiles a validated pattern with the reference's
// leftmost-longest semantics; nil only for a pattern Compile never saw.
func compilePattern(pattern string) *regexp.Regexp {
	invariant.Check(pattern != "", "pattern given")
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	re.Longest()
	return re
}

// precompile compiles every regex now and marks the database eager: no
// lazy work remains, no allocation follows initialisation, and a call's latency no longer depends on which rules it reaches.
func (db *Database) precompile() *Database {
	invariant.Check(db != nil, "database given")
	for i := range db.regexes {
		slot := &db.regexes[i]
		if slot.re == nil {
			slot.re = compilePattern(slot.pattern)
		}
	}
	db.eager = true
	return db
}

// addRegex appends a pattern slot and returns its index. The slot is
// grown in place so no sync.Once is ever copied.
func (db *Database) addRegex(pattern string, lits []string, fold, lineStart bool, re *regexp.Regexp) int32 {
	invariant.Check(pattern != "", "pattern given")
	invariant.Check(len(lits) > 0 || (!fold && !lineStart), "flags only with literals")
	db.regexes = append(db.regexes, regexSlot{})
	slot := &db.regexes[len(db.regexes)-1]
	slot.pattern, slot.fold, slot.lineStart, slot.re = pattern, fold, lineStart, re
	for _, lit := range lits {
		slot.lits = append(slot.lits, []byte(lit))
	}
	return smallInt32(len(db.regexes) - 1)
}

// litStrings is a slot's literal set as strings.
func (r *regexSlot) litStrings() []string {
	invariant.Check(r != nil, "slot given")
	out := make([]string, 0, len(r.lits))
	for _, lit := range r.lits {
		out = append(out, string(lit))
	}
	return out
}

// Entries is the number of top-level entries in all sets of all maps.
func (db *Database) Entries() int {
	invariant.Check(len(db.maps) > 0, "a database has a map")
	n := 0
	for i := range db.maps {
		n += len(db.maps[i].sets[0]) + len(db.maps[i].sets[1])
	}
	return n
}

// ruleID names a rule line.
func (db *Database) ruleID(rec int32) RuleID {
	if rec < 0 || int(rec) >= len(db.recs) {
		return RuleID{}
	}
	return RuleID{File: db.files[db.meta[rec].file], Line: int(db.recs[rec].lineno)}
}

// Hash is the SHA-256 of the Magdir source the database was compiled from,
// as hex: Examined.DatabaseHash in every Result.
func (db *Database) Hash() string { return db.hash }

// Lines is the number of rule lines.
func (db *Database) Lines() int { return len(db.recs) }

// List prints every entry in matching order in the format of file -l:
//
//	Set 0:
//	Binary patterns:
//	Strength = 670@1446: WonderWitch transfer file []
//	...
//	Text patterns:
//	...
//	Set 1:
//	...
//
// The output is byte-identical to the reference's `file -m <dir> -l` for
// the same Magdir; the tests compare the two in full, which is what proves
// the matching order.
func (db *Database) List() string {
	invariant.Check(len(db.recs) == len(db.meta), "meta parallel to records")
	var b strings.Builder    // builder
	for s := 0; s < 2; s++ { // setIndex
		b.WriteString("Set " + strconv.Itoa(s) + ":\nBinary patterns:\n")
		for i := range db.maps {
			db.listSet(&b, &db.maps[i], s, flagBinTest)
		}
		b.WriteString("Text patterns:\n")
		for i := range db.maps {
			db.listSet(&b, &db.maps[i], s, flagTextTest)
		}
	}
	return b.String()
}

// listSet is apprentice_list for one set and one mode flag.
func (db *Database) listSet(b *strings.Builder, m *dbMap, s int, mode uint16) { // builder
	invariant.Check(mode == flagBinTest || mode == flagTextTest, "mode is one class")
	for _, e := range m.sets[s] {
		lines := db.recs[e.first : e.first+e.count]
		first := &lines[0]
		if first.flag&mode != mode {
			continue
		}
		desc, mime := first, first
		for i := 1; i < len(lines); i++ {
			if !desc.hasDesc() && lines[i].hasDesc() {
				desc = &lines[i]
			}
			if !mime.hasMime() && lines[i].hasMime() {
				mime = &lines[i]
			}
		}
		b.WriteString("Strength = ")
		b.WriteString(pad3(entryStrength(first)))
		b.WriteString("@" + strconv.FormatUint(uint64(first.lineno), 10) + ": ")
		b.WriteString(desc.descString())
		b.WriteString(" [" + mime.mimeString() + "]\n")
	}
}

// pad3 is printf("%3d").
func pad3(n int) string {
	invariant.Check(n >= 0, "strength non-negative")
	s := strconv.Itoa(n)
	for n := len(s); n < 3; n++ {
		s = " " + s
	}
	return s
}

// Join returns a new database that searches db first and then extra, as
// file(1) searches the directories of `-m a:b` in order: each keeps its
// own sort, a "use" may name an entry of either, and the first map to
// match answers. hash identifies the combination; the compile package's
// Append derives one from both inputs' hashes. Neither input is modified.
func (db *Database) Join(extra *Database, hash string) (*Database, error) {
	if db == nil || extra == nil {
		return nil, &LoadError{Msg: "Join of a nil database"}
	}
	shift := len(db.recs)
	out := &Database{
		hash: hash, sourceDir: db.sourceDir,
		names: map[string]entry{}, pool: newScanPool(),
		recs: make([]record, 0, len(db.recs)+len(extra.recs)),
		meta: make([]lineMeta, 0, len(db.meta)+len(extra.meta)),
	}
	out.recs = append(append(out.recs, db.recs...), extra.recs...)
	out.files = append(append([]string(nil), db.files...), extra.files...)
	out.meta = append(out.meta, db.meta...)
	for i := range extra.meta {
		m := extra.meta[i]
		m.file += smallInt32(len(db.files))
		if m.rx >= 0 {
			m.rx += smallInt32(len(db.regexes))
		}
		out.meta = append(out.meta, m)
	}
	for i := range db.regexes {
		r := &db.regexes[i]
		out.addRegex(r.pattern, r.litStrings(), r.fold, r.lineStart, r.re)
	}
	for i := range extra.regexes {
		r := &extra.regexes[i]
		out.addRegex(r.pattern, r.litStrings(), r.fold, r.lineStart, r.re)
	}
	out.maps = append(append([]dbMap(nil), db.maps...), shiftMaps(extra.maps, smallInt32(shift))...)
	for name, e := range db.names {
		out.names[name] = e
	}
	for name, e := range extra.names {
		if _, dup := out.names[name]; !dup {
			e.first += smallInt32(shift)
			out.names[name] = e
		}
	}
	if err := checkSets(out); err != nil {
		return nil, err
	}
	out.buildPrefilters()
	if db.eager && extra.eager {
		return out.precompile(), nil
	}
	return out, nil
}

// shiftMaps copies maps with their line indexes moved by shift.
func shiftMaps(maps []dbMap, shift int32) []dbMap {
	invariant.Check(shift >= 0, "shift non-negative")
	out := make([]dbMap, len(maps))
	for i := range maps { // mapIndex
		out[i].first, out[i].count = maps[i].first+shift, maps[i].count
		for s := 0; s < 2; s++ {
			out[i].sets[s] = make([]entry, len(maps[i].sets[s]))
			for j, e := range maps[i].sets[s] {
				e.first += shift
				out[i].sets[s][j] = e
			}
		}
	}
	return out
}
