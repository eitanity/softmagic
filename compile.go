// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// The loading, set assignment and sorting here follow apprentice_load,
// load_1, addentry, set_test_type and coalesce_entries in apprentice.c,
// file 5.48, Copyright (c) Ian F. Darwin 1986-1995 (see COPYING).

package softmagic

import (
	"sort"
	"strconv"
	"strings"

	"github.com/eitanity/softmagic/internal/invariant"
)

// CompileOptions configures Compile. The zero value is the default.
type CompileOptions struct {
	// Base, when set, is the database this one will be appended to: a
	// "use" may name one of its "name" entries (a local rule
	// file extending the embedded database, as file -m a:b does).
	Base *Database
	// SourceDir is the directory name the reference was given on its command
	// line (file -m <dir>). The reference tucks "<dir>/<file>" into every
	// empty description, where it takes part in the ordering tie-break
	// so the port must know the same name to reproduce the same
	// order. Default: "magic/Magdir".
	SourceDir string
}

// entry is one top-level rule and its continuation lines: a window into
// Database.recs. Entries hold no pointers, which keeps the compiled form
// serialisable.
type entry struct {
	first    int32
	count    int32
	strength int32
}

// pending is an entry under construction during Compile: its lines while
// they are being parsed and annotated, then their records once flushed.
type pending struct {
	lines    []lineRec
	recs     []record
	file     int32
	strength int
	image    [recordSize]byte
}

// compiler is the per-Compile state.
type compiler struct {
	sourceDir string
	hash      string
	arena     arena // the records' byte fields
	sets      [2][]pending
	cur       *pending         // entry under construction, nil between entries
	dump      *strings.Builder // file -c: each line's parsed form, when DumpSources asks
	tables    typeTables
	base      *Database
	files     []string
	curSet    int
	fileIdx   int32
}

// Source is one rule file: its name, which error messages and the
// ordering tie-break use, and its text.
type Source struct {
	Name string
	Data []byte
}

// CompileSources builds the sorted database from rule sources in the
// order given (the reference reads a directory in byte order of name) and
// records hash as the database's identity, which Hash and
// Examined.DatabaseHash report. The compile package reads a directory and
// hashes it; call that unless the rules are already in memory.
func CompileSources(hash string, srcs []Source, o CompileOptions) (*Database, error) {
	if len(srcs) == 0 {
		return nil, &CompileError{File: "", Line: 0, Msg: "no rule sources"}
	}
	c := compiler{sourceDir: o.SourceDir, tables: newTypeTables(), base: o.Base, hash: hash}
	if c.sourceDir == "" {
		c.sourceDir = "magic/Magdir"
	}
	c.files = make([]string, 0, len(srcs))
	for fileIdx, src := range srcs {
		c.fileIdx = smallInt32(fileIdx)
		c.files = append(c.files, src.Name)
		if err := c.loadFile(src.Name, src.Data); err != nil {
			return nil, err
		}
	}
	return c.finish()
}

// loadFile is load_1: parse one rule file into entries.
func (c *compiler) loadFile(name string, data []byte) error {
	invariant.Check(c.cur == nil, "no entry carried over between files")
	invariant.Check(name != "", "rule file has a name")
	file := c.sourceDir + "/" + name
	lineno := uint32(0)
	end := 0
	for start := 0; start < len(data); start = end + 1 {
		end = start
		for ; end < len(data) && data[end] != '\n'; end++ {
		}
		line := data[start:end]
		if nul := indexByteFrom(line, 0, 0); nul >= 0 {
			line = line[:nul] // the reference parses a C string: a NUL ends the line
		}
		if end < len(data) {
			lineno++
		}
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if err := c.loadLine(file, lineno, line); err != nil {
			return err
		}
	}
	c.flush()
	return nil
}

// loadLine dispatches one non-comment line to the annotation or rule parser.
func (c *compiler) loadLine(file string, lineno uint32, line []byte) error {
	// A final line with no newline keeps the previous line number, as the
	// reference counts (a one-line file without a newline is line 0).
	invariant.Check(len(line) > 0 && line[0] != '#', "parsable line")
	p := lineParser{line: line, file: file, lineno: lineno, tables: &c.tables, dump: c.dump}
	if len(line) >= 2 && line[0] == '!' && line[1] == ':' {
		return c.annotate(&p)
	}
	level := p.parseContLevel()
	if level == 0 {
		c.flush()
		c.cur = &pending{lines: make([]lineRec, 1, 4), file: c.fileIdx}
		c.curSet = 0
	} else {
		if c.cur == nil {
			return p.errorf("no current entry for continuation")
		}
		c.cur.lines = append(c.cur.lines, lineRec{})
	}
	if level >= maxLevels {
		return p.errorf("continuation level " + strconv.Itoa(level) + " exceeds the supported " +
			strconv.Itoa(maxLevels-1))
	}
	p.rec = &c.cur.lines[len(c.cur.lines)-1]
	p.rec.contLevel = smallUint8(level)
	p.rec.lineno = lineno
	if err := p.parseLine(); err != nil {
		return err
	}
	if level == 0 && p.rec.typ == tName {
		c.curSet = 1
	}
	return nil
}

// flush is addentry: the entry under construction is complete (its
// annotations follow its lines), so its first line gets its test type,
// the sort image is taken, the lines become records and the entry joins
// its set.
func (c *compiler) flush() {
	if c.cur == nil {
		return
	}
	invariant.Check(len(c.cur.lines) > 0, "entry has a first line")
	invariant.Check(c.cur.recs == nil, "entry not yet flushed")
	setTestType(&c.cur.lines[0])
	c.cur.lines[0].image(&c.cur.image)
	c.cur.recs = make([]record, len(c.cur.lines))
	for i := range c.cur.lines {
		c.cur.recs[i] = c.cur.lines[i].intern(&c.arena)
	}
	c.cur.lines = nil
	c.cur.strength = entryStrength(&c.cur.recs[0])
	c.sets[c.curSet] = append(c.sets[c.curSet], *c.cur)
	c.cur = nil
}

// finish sets test types, sorts each set and coalesces into a Database.
func (c *compiler) finish() (*Database, error) {
	invariant.Check(c.cur == nil, "no entry under construction at finish")
	db := &Database{
		hash: c.hash, sourceDir: c.sourceDir,
		files: c.files, names: map[string]entry{}, pool: newScanPool(),
	}
	m := dbMap{}
	for s := 0; s < 2; s++ {
		ents := c.sets[s]
		sort.Stable(bySortOrder(ents))
		m.sets[s] = make([]entry, len(ents))
		for i := range ents {
			e := entry{first: smallInt32(len(db.recs)), count: smallInt32(len(ents[i].recs)),
				strength: smallInt32(ents[i].strength)}
			m.sets[s][i] = e
			if s == 1 {
				db.names[ents[i].recs[0].valueString()] = e
			}
			c.appendLines(db, &ents[i])
		}
		if s == 0 {
			m.count = smallInt32(len(db.recs))
		}
	}
	db.maps = []dbMap{m}
	if err := c.checkUses(db); err != nil {
		return nil, err
	}
	db.buildPrefilters()
	return db.precompile(), nil
}

// appendLines adds an entry's lines and their Go-side metadata.
func (c *compiler) appendLines(db *Database, p *pending) {
	invariant.Check(len(p.recs) > 0 && p.recs[0].contLevel == 0, "entry starts with a first line")
	for i := range p.recs {
		r := &p.recs[i]
		meta := lineMeta{file: p.file, rx: -1}
		if r.typ == tRegex {
			src := translateRegex(r.valueString(), r.strFlags())
			lits, fold, lineStart := regexLiterals(src)
			meta.rx = db.addRegex(src, lits, fold, lineStart, compilePattern(src))
		}
		db.recs = append(db.recs, *r)
		db.meta = append(db.meta, meta)
	}
}

// checkUses verifies every "use" names a compiled "name" entry, which the
// reference only discovers at match time.
func (c *compiler) checkUses(db *Database) error {
	invariant.Check(len(db.recs) == len(db.meta), "meta parallel to records")
	for i := range db.recs {
		r := &db.recs[i]
		if r.typ != tUse {
			continue
		}
		name := r.valueBytes()
		if len(name) > 0 && name[0] == '^' {
			name = name[1:]
		}
		if _, ok := db.names[string(name)]; ok {
			continue
		}
		if c.base != nil {
			if _, ok := c.base.names[string(name)]; ok {
				continue
			}
		}
		return &CompileError{File: c.sourceDir + "/" + c.files[db.meta[i].file],
			Line: int(r.lineno), Msg: "use of undefined name `" + string(name) + "'"}
	}
	return nil
}

// bySortOrder implements sort.Interface with apprentice_sort's order.
type bySortOrder []pending

func (b bySortOrder) Len() int      { return len(b) }
func (b bySortOrder) Swap(i, j int) { b[i], b[j] = b[j], b[i] }

// Less: higher strength first; on a tie the byte-wise greater image first.
func (b bySortOrder) Less(i, j int) bool {
	if b[i].strength != b[j].strength {
		return b[i].strength > b[j].strength
	}
	return imageGreater(&b[i].image, &b[j].image)
}

// imageGreater is memcmp(a, b) > 0.
func imageGreater(a, b *[recordSize]byte) bool {
	for k := 0; k < recordSize; k++ {
		if a[k] != b[k] {
			return a[k] > b[k]
		}
	}
	return false
}

// setTestType is set_test_type applied to an entry's first line, which is
// the only line the reference consults (its loop runs over entries whose
// first line always has cont_level 0).
func setTestType(r *lineRec) {
	invariant.Check(r.contLevel == 0, "test type set on a first line")
	switch {
	case isFixedWidth(r.typ) || r.typ == tDer || r.typ == tOctal:
		r.flag |= flagBinTest
	case r.typ == tString || r.typ == tPString || r.typ == tBeString16 ||
		r.typ == tLeString16 || r.typ == tRegex || r.typ == tSearch:
		if r.strFlags()&strBinTest != 0 {
			r.flag |= flagBinTest
		}
		if r.strFlags()&strTextTest != 0 {
			r.flag |= flagTextTest
		}
		if r.flag&(flagTextTest|flagBinTest) != 0 {
			return
		}
		if r.typ != tRegex && r.typ != tSearch {
			r.flag |= flagBinTest
			return
		}
		if looksUTF8(r.valueBytes()) <= 0 {
			r.flag |= flagBinTest
		} else {
			r.flag |= flagTextTest
		}
	default: // default, name, use, clear, indirect: no class
	}
}

// annotate handles a "!:" line: mime, apple, ext or strength.
func (c *compiler) annotate(p *lineParser) error {
	if c.cur == nil {
		return p.errorf("no current entry for " + string(p.line))
	}
	body := p.line[2:]
	switch {
	case hasPrefix(body, "mime") && len(body) > 4:
		p.i = 6
		return c.parseExtra(p, extraMime)
	case hasPrefix(body, "apple") && len(body) > 5:
		p.i = 7
		return c.parseExtra(p, extraApple)
	case hasPrefix(body, "ext") && len(body) > 3:
		p.i = 5
		return c.parseExtra(p, extraExt)
	case hasPrefix(body, "strength") && len(body) > 8:
		p.i = 10
		return c.parseStrength(p)
	default:
		return p.errorf("unknown !: entry `" + string(p.line) + "'")
	}
}

type extraKind uint8

const (
	extraMime extraKind = iota
	extraApple
	extraExt
)

// extraField returns the target array, its permitted extra characters and
// whether the reference NUL-terminates it (only MIME is).
func extraField(r *lineRec, k extraKind) (buf []byte, extra string, nulTerm bool) {
	switch k {
	case extraApple:
		return r.apple[:], "!+-./?", false
	case extraExt:
		return r.ext[:], ",!+-/@?_$&~.", false
	default:
		return r.mimetype[:], "+-/.$?:{};=", true
	}
}

func goodChar(c byte, extra string) bool {
	if cIsAlnum(c) {
		return true
	}
	for i := 0; i < len(extra); i++ {
		if extra[i] == c {
			return true
		}
	}
	return false
}

// parseExtra is parse_extra: copy the annotation's value into the last
// line's field, refusing a second annotation of the same kind and an
// annotation on a line with no description.
func (c *compiler) parseExtra(p *lineParser, k extraKind) error {
	invariant.Check(len(c.cur.lines) > 0, "annotated entry has lines")
	r := &c.cur.lines[len(c.cur.lines)-1]
	buf, extra, nulTerm := extraField(r, k)
	if buf[0] != 0 {
		return p.errorf("current entry already has this annotation: `" + cString(buf) + "'")
	}
	if r.desc[0] == 0 {
		return p.errorf("current entry does not yet have a description for adding an annotation")
	}
	p.i = eatSpace(p.line, p.i)
	n := 0
	for ; n < len(buf) && p.i < len(p.line) && goodChar(p.line[p.i], extra); n++ {
		buf[n] = p.line[p.i]
		p.i++
	}
	if n == len(buf) && p.i < len(p.line) && nulTerm {
		buf[len(buf)-1] = 0 // truncated, as the reference warns and does
	}
	if n == 0 {
		return p.errorf("bad magic entry `" + string(p.line) + "'")
	}
	return nil
}

// parseStrength is parse_strength: "!:strength OP VALUE" on the entry's
// first line.
func (c *compiler) parseStrength(p *lineParser) error {
	invariant.Check(len(c.cur.lines) > 0, "annotated entry has lines")
	r := &c.cur.lines[0]
	if r.factorOp != 0 {
		return p.errorf("current entry already has a strength type: " + string(r.factorOp) +
			" " + strconv.Itoa(int(r.factor)))
	}
	if r.typ == tName {
		return p.errorf("strength setting is not supported in \"name\" magic entries")
	}
	p.i = eatSpace(p.line, p.i)
	switch p.cur() {
	case 0:
	case '+', '-', '*', '/':
		r.factorOp = p.cur()
		p.i++
	default:
		return p.errorf("unknown factor op `" + string(p.cur()) + "'")
	}
	p.i = eatSpace(p.line, p.i)
	factor, end, ok := strtoull(p.line, p.i, 0)
	if !ok {
		factor, end = 0, p.i
	}
	if factor > 255 {
		return p.errorf("too large factor `" + strconv.FormatUint(factor, 10) + "'")
	}
	if end < len(p.line) && !cIsSpace(p.line[end]) {
		return p.errorf("bad factor `" + string(p.line[p.i:]) + "'")
	}
	r.factor = low8(factor)
	if r.factor == 0 && r.factorOp == '/' {
		return p.errorf("cannot have factor op `/' and factor 0")
	}
	return nil
}
