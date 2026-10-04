// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

//go:generate env SOFTMAGIC_GENERATE=1 go test -run TestGenerateDatabase .

import (
	_ "embed" // the compiled database
	"encoding/binary"
	"strconv"

	"github.com/eitanity/softmagic/internal/invariant"
)

// The compiled form: the library's own serialisation of a
// compiled Database, produced by Marshal from Compile's output, embedded by
// the embed directive, and read by Load. It is versioned by formatVersion and carries
// ImplementsFile and the source hash, both checked at load.
//
// Layout, all integers little-endian:
//
//	"SMDB" | u16 formatVersion | str ImplementsFile | str hash | str sourceDir
//	u32 nfiles | str file names...
//	u32 nmaps | per map: u32 first, u32 count (its binary set's lines),
//	  then for each of the two sets: u32 n | n × (u32 first, u32 count, i32 strength)
//	u32 nrecords | records...
//
// A record is struct magic's scalar fields in declaration order, the file
// index, then value, desc, mimetype, apple and ext as u8-length-prefixed
// byte strings trimmed of trailing NULs (the arrays are NUL-padded).
// A str is a u16-length-prefixed byte string.

const (
	formatMagic   = "SMDB"
	formatVersion = 3
	// maxCompiledRecords bounds what Load will allocate for.
	maxCompiledRecords = 1 << 20
)

//go:embed magic/softmagic.db
var embeddedDatabase []byte

// Default loads the database compiled into the library from the vendored
// Magdir of the release named by ImplementsFile. Load it once and keep it;
// it is safe for concurrent use. Its regexes compile on first use, which
// keeps the load near a millisecond; DefaultEager compiles them now.
func Default() (*Database, error) {
	return load(embeddedDatabase)
}

// DefaultEager is Default with every regex compiled before it returns:
// no lazy work and no allocation after this call, at about 1.5 ms more
// load time. A long-running process wants this; a one-file command does
// not.
func DefaultEager() (*Database, error) {
	db, err := load(embeddedDatabase)
	if err != nil {
		return nil, err
	}
	return db.precompile(), nil
}

// LoadEager is Load with every regex compiled before it returns; see
// DefaultEager.
func LoadEager(data []byte) (*Database, error) {
	db, err := Load(data)
	if err != nil {
		return nil, err
	}
	return db.precompile(), nil
}

// LoadError is a refused compiled database.
type LoadError struct {
	Msg string
}

func (e *LoadError) Error() string { return "softmagic: compiled database: " + e.Msg }

// enc appends the format's primitives to a byte slice.
type enc struct {
	b []byte
}

func (e *enc) u8(v uint8)   { e.b = append(e.b, v) }
func (e *enc) u16(v uint16) { e.b = binary.LittleEndian.AppendUint16(e.b, v) }
func (e *enc) u32(v uint32) { e.b = binary.LittleEndian.AppendUint32(e.b, v) }
func (e *enc) u64(v uint64) { e.b = binary.LittleEndian.AppendUint64(e.b, v) }

func (e *enc) str(s string) {
	invariant.Check(len(s) <= 0xffff, "string fits a u16 length")
	e.u16(low16(bitsOfInt64(int64(len(s)))))
	e.b = append(e.b, s...)
}

// trimmed appends a fixed array as a u8-length-prefixed string without its
// trailing NULs.
func (e *enc) trimmed(a []byte) {
	n := len(a)
	for ; n > 0 && a[n-1] == 0; n-- {
	}
	invariant.Check(n <= 0xff, "array fits a u8 length")
	e.u8(low8(bitsOfInt64(int64(n))))
	e.b = append(e.b, a[:n]...)
}

// Marshal serialises the database in the compiled form.
func (db *Database) Marshal() ([]byte, error) {
	if len(db.recs) > maxCompiledRecords {
		return nil, &LoadError{Msg: "too many records to serialise"}
	}
	e := &enc{b: make([]byte, 0, 64*len(db.recs)+1024)}
	e.b = append(e.b, formatMagic...)
	e.u16(formatVersion)
	e.str(ImplementsFile)
	e.str(db.hash)
	e.str(db.sourceDir)
	e.u32(low32(uint64(len(db.files))))
	for _, f := range db.files {
		e.str(f)
	}
	e.u32(low32(uint64(len(db.maps))))
	for i := range db.maps {
		m := &db.maps[i]
		e.u32(bitsOfInt32(m.first))
		e.u32(bitsOfInt32(m.count))
		for s := 0; s < 2; s++ {
			e.u32(low32(uint64(len(m.sets[s]))))
			for _, en := range m.sets[s] {
				e.u32(bitsOfInt32(en.first))
				e.u32(bitsOfInt32(en.count))
				e.u32(bitsOfInt32(en.strength))
			}
		}
	}
	e.u32(low32(uint64(len(db.recs))))
	for i := range db.recs {
		e.record(&db.recs[i], db.meta[i].file)
	}
	e.u32(low32(uint64(len(db.regexes))))
	for i := range db.regexes {
		slot := &db.regexes[i]
		e.u8(smallUint8(len(slot.lits)))
		for _, lit := range slot.lits {
			e.str(string(lit))
		}
		e.u8(boolByte(slot.fold)<<1 | boolByte(slot.lineStart))
	}
	return e.b, nil
}

func boolByte(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// record appends one rule line.
func (e *enc) record(r *record, file int32) {
	invariant.Check(file >= 0 && file <= 0xffff, "file index fits a u16")
	invariant.Check(r.vallen <= maxString, "value length within MAXstring")
	e.u16(r.flag)
	e.u8(r.contLevel)
	e.u8(r.factor)
	e.u8(r.reln)
	e.u8(r.vallen)
	e.u8(uint8(r.typ))
	e.u8(uint8(r.inType))
	e.u8(r.inOp)
	e.u8(r.maskOp)
	e.u8(r.dummy)
	e.u8(r.factorOp)
	e.u32(bitsOfInt32(r.offset))
	e.u32(bitsOfInt32(r.inOffset))
	e.u32(r.lineno)
	e.u64(r.maskOrStr)
	e.u16(low16(bitsOfInt64(int64(file))))
	e.trimmed(r.value)
	e.trimmed(r.desc)
	e.trimmed(r.mimetype)
	e.trimmed(r.apple)
	e.trimmed(r.ext)
}

// dec reads the format's primitives with bounds checks; after the first
// short read every further read yields zero and err is set.
type dec struct {
	b     []byte
	arena arena // for values shorter than their slice must be
	i     int
	err   bool
}

// count reads a table length and refuses one above limit while it is
// still unsigned, so a 32-bit int never has to hold it.
func (d *dec) count(limit int) (int, bool) {
	invariant.Check(limit >= 0 && limit <= maxCompiledRecords, "limit within the record bound")
	v := d.u32()
	if uint64(v) > bitsOfInt64(int64(limit)) {
		return 0, false
	}
	return int(v), true
}

func (d *dec) need(n int) bool {
	if d.err || n < 0 || d.i+n > len(d.b) {
		d.err = true
		return false
	}
	return true
}

func (d *dec) u8() uint8 {
	if !d.need(1) {
		return 0
	}
	v := d.b[d.i]
	d.i++
	return v
}

func (d *dec) u16() uint16 {
	if !d.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(d.b[d.i:])
	d.i += 2
	return v
}

func (d *dec) u32() uint32 {
	if !d.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(d.b[d.i:])
	d.i += 4
	return v
}

func (d *dec) str() string {
	n := int(d.u16())
	if !d.need(n) {
		return ""
	}
	s := string(d.b[d.i : d.i+n])
	d.i += n
	return s
}

// trimmed reads a u8-length-prefixed string into a fixed array.
// field reads a length-prefixed byte field of at most max bytes as a
// slice of the data itself, so loading copies nothing; a value shorter
// than need is copied into the arena with zero padding instead.
func (d *dec) field(max, need int) []byte {
	invariant.Check(max > 0 && max <= maxString, "field bound is a struct magic array size")
	n := int(d.u8())
	if n > max || !d.need(n) {
		d.err = true
		return nil
	}
	b := d.b[d.i : d.i+n : d.i+n]
	d.i += n
	if n < need {
		return d.arena.copyIn(b, need)
	}
	return b
}

// Load reads a compiled database. It refuses a different format version
// or a database compiled for a different file(1) release, naming both.
func Load(data []byte) (*Database, error) {
	return load(append([]byte(nil), data...))
}

// load reads a compiled database whose bytes it may keep: the records'
// byte fields are slices of data.
func load(data []byte) (*Database, error) {
	d := &dec{b: data}
	if len(data) < len(formatMagic) || string(data[:len(formatMagic)]) != formatMagic {
		return nil, &LoadError{Msg: "not a softmagic compiled database"}
	}
	d.i = len(formatMagic)
	if v := d.u16(); v != formatVersion {
		return nil, &LoadError{Msg: "format version " + strconv.Itoa(int(v)) +
			", this library reads " + strconv.Itoa(formatVersion)}
	}
	impl := d.str()
	if impl != ImplementsFile {
		return nil, &LoadError{Msg: "compiled for file " + impl +
			", this library implements " + ImplementsFile}
	}
	db := &Database{hash: d.str(), sourceDir: d.str(), names: map[string]entry{}, pool: newScanPool()}
	nfiles, ok := d.count(maxCompiledRecords)
	if !ok || !d.need(nfiles) {
		return nil, &LoadError{Msg: "file count out of range"}
	}
	db.files = make([]string, nfiles)
	for i := range db.files {
		db.files[i] = d.str()
	}
	if err := d.loadMaps(db); err != nil {
		return nil, err
	}
	if err := d.loadRecords(db); err != nil {
		return nil, err
	}
	if err := d.loadLiterals(db); err != nil {
		return nil, err
	}
	if err := checkSets(db); err != nil {
		return nil, err
	}
	db.buildPrefilters()
	return db, nil
}

// loadMaps reads the map table.
func (d *dec) loadMaps(db *Database) error {
	nmaps, ok := d.count(maxCompiledRecords)
	if !ok || !d.need(nmaps*16) {
		return &LoadError{Msg: "map count out of range"}
	}
	db.maps = make([]dbMap, nmaps)
	for i := range db.maps {
		db.maps[i].first = wrapInt32(int64(d.u32()))
		db.maps[i].count = wrapInt32(int64(d.u32()))
		for s := 0; s < 2; s++ {
			if err := d.loadSet(&db.maps[i], s); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadSet reads one set's entry table of one map.
func (d *dec) loadSet(m *dbMap, s int) error {
	n, ok := d.count(maxCompiledRecords)
	if !ok || !d.need(n*12) {
		return &LoadError{Msg: "entry count out of range"}
	}
	m.sets[s] = make([]entry, n)
	for i := range m.sets[s] {
		m.sets[s][i] = entry{first: wrapInt32(int64(d.u32())), count: wrapInt32(int64(d.u32())),
			strength: wrapInt32(int64(d.u32()))}
	}
	return nil
}

// loadRecords reads the rule lines and rebuilds the per-line metadata.
func (d *dec) loadRecords(db *Database) error {
	n, ok := d.count(maxCompiledRecords)
	if !ok || !d.need(n*40) {
		return &LoadError{Msg: "record count out of range"}
	}
	db.recs = make([]record, n)
	db.meta = make([]lineMeta, n)
	for i := range db.recs {
		r := &db.recs[i]
		file := d.scalars(r)
		if d.err || file >= len(db.files) || int(r.typ) >= numTypes || int(r.inType) >= numTypes ||
			r.vallen > maxString || int(r.contLevel) >= maxLevels {
			return &LoadError{Msg: "record " + strconv.Itoa(i) + " malformed"}
		}
		need := valueNeed(&r.recordHead)
		if need < valueMin {
			need = valueMin
		}
		r.value = d.field(maxString, need)
		r.desc = d.field(maxDesc, 0)
		r.mimetype = d.field(maxMime, 0)
		r.apple = d.field(maxApple, 0)
		r.ext = d.field(maxExt, 0)
		if d.err {
			return &LoadError{Msg: "record " + strconv.Itoa(i) + " fields malformed"}
		}
		db.meta[i] = lineMeta{file: smallInt32(file), rx: -1}
		if r.typ == tRegex {
			db.meta[i].rx = db.addRegex(translateRegex(r.valueString(), r.strFlags()), nil, false, false, nil)
		}
	}
	return nil
}

// loadLiterals reads the regex prefilter table, one entry per regex line
// in record order. Only its shape is checked: the literals are trusted
// like the rules they belong to, and re-deriving them would link the
// regex parser into every program that merely loads a database.
func (d *dec) loadLiterals(db *Database) error {
	n, ok := d.count(len(db.regexes))
	if !ok || n != len(db.regexes) || !d.need(n) {
		return &LoadError{Msg: "regex literal table does not match the records"}
	}
	for i := range db.regexes {
		count := int(d.u8())
		lits := make([]string, 0, count)
		for k := 0; k < count && !d.err; k++ {
			lits = append(lits, d.str())
		}
		flags := d.u8()
		fold, lineStart := flags&2 != 0, flags&1 != 0
		if d.err || count > maxAlternateLiterals || flags > 3 || (count == 0 && flags != 0) {
			return &LoadError{Msg: "regex literal " + strconv.Itoa(i) + " malformed"}
		}
		for _, lit := range lits {
			if lit == "" {
				return &LoadError{Msg: "regex literal " + strconv.Itoa(i) + " empty"}
			}
			db.regexes[i].lits = append(db.regexes[i].lits, []byte(lit))
		}
		db.regexes[i].fold, db.regexes[i].lineStart = fold, lineStart
	}
	return nil
}

// recordScalarSize is the fixed part of a record: struct magic's scalar
// fields in declaration order plus the file index.
const recordScalarSize = 2 + 10 + 4 + 4 + 4 + 8 + 2

// scalars reads a record's fixed part with one bounds check and returns
// the file index.
func (d *dec) scalars(r *record) int {
	invariant.Check(r != nil, "record to fill")
	if !d.need(recordScalarSize) {
		return 0
	}
	b := d.b[d.i : d.i+recordScalarSize]
	d.i += recordScalarSize
	le := binary.LittleEndian
	r.flag = le.Uint16(b[0:2])
	r.contLevel, r.factor, r.reln, r.vallen = b[2], b[3], b[4], b[5]
	r.typ, r.inType = fileType(b[6]), fileType(b[7])
	r.inOp, r.maskOp, r.dummy, r.factorOp = b[8], b[9], b[10], b[11]
	r.offset = wrapInt32(int64(le.Uint32(b[12:16])))
	r.inOffset = wrapInt32(int64(le.Uint32(b[16:20])))
	r.lineno = le.Uint32(b[20:24])
	r.maskOrStr = le.Uint64(b[24:32])
	return int(le.Uint16(b[32:34]))
}

// checkSets verifies the entry tables index the records consistently,
// builds the name table and checks every "use" resolves.
func checkSets(db *Database) error {
	expect := int32(0)
	for i := range db.maps {
		m := &db.maps[i]
		if m.first != expect {
			return &LoadError{Msg: "map table inconsistent with records"}
		}
		next, err := checkMap(db, m, expect)
		if err != nil {
			return err
		}
		expect = next
	}
	if int(expect) != len(db.recs) {
		return &LoadError{Msg: "records not covered by the entry tables"}
	}
	return checkUseNames(db)
}

// registerName adds a "name" entry unless an earlier map defined it.
func registerName(db *Database, e entry) {
	invariant.Check(db.recs[e.first].typ == tName, "name entry")
	name := db.recs[e.first].valueString()
	if _, dup := db.names[name]; !dup {
		db.names[name] = e
	}
}

// checkMap verifies one map's entry tables from line index expect and
// registers its names (the first map to define a name wins).
func checkMap(db *Database, m *dbMap, expect int32) (int32, error) {
	invariant.Check(expect >= 0, "line index non-negative")
	for s := 0; s < 2; s++ {
		for _, e := range m.sets[s] {
			if e.first != expect || e.count <= 0 || int(e.first)+int(e.count) > len(db.recs) ||
				db.recs[e.first].contLevel != 0 {
				return 0, &LoadError{Msg: "entry table inconsistent with records"}
			}
			expect += e.count
			if s == 1 {
				registerName(db, e)
			}
		}
		if s == 0 && m.count != expect-m.first {
			return 0, &LoadError{Msg: "map binary-set range inconsistent"}
		}
	}
	return expect, nil
}

// checkUseNames verifies every "use" line names a compiled "name" entry.
func checkUseNames(db *Database) error {
	for i := range db.recs {
		if db.recs[i].typ != tUse {
			continue
		}
		name := db.recs[i].valueBytes()
		if len(name) > 0 && name[0] == '^' {
			name = name[1:]
		}
		if _, ok := db.names[string(name)]; !ok {
			return &LoadError{Msg: "use of undefined name `" + string(name) + "'"}
		}
	}
	return nil
}
