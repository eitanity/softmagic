// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"testing/fstest"
	"time"
)

// TestGenerateDatabase writes magic/softmagic.db from the vendored Magdir
// when SOFTMAGIC_GENERATE is set: the go:generate hook.
func TestGenerateDatabase(t *testing.T) {
	if os.Getenv("SOFTMAGIC_GENERATE") == "" {
		t.Skip("set SOFTMAGIC_GENERATE=1 to regenerate magic/softmagic.db")
	}
	db := compileMagdir(t) // database
	data, err := db.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("magic/softmagic.db", data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote magic/softmagic.db: %d bytes, hash %s", len(data), db.Hash())
}

// TestEmbeddedCurrent: the embedded database is exactly what Compile of the
// vendored Magdir marshals to, so the two can never disagree.
func TestEmbeddedCurrent(t *testing.T) {
	fresh, err := compileMagdir(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fresh, embeddedDatabase) {
		t.Fatalf("magic/softmagic.db is stale (%d vs %d bytes): run `make generate`", len(embeddedDatabase), len(fresh))
	}
}

// TestListOracleEmbedded runs the listing oracle (List against file -l) on
// the embedded database's load path.
func TestListOracleEmbedded(t *testing.T) {
	want, err := os.ReadFile("testdata/file-5.48-list.txt")
	if err != nil {
		t.Fatal(err)
	}
	db, err := Default() // database
	if err != nil {
		t.Fatal(err)
	}
	if db.List() != string(want) {
		t.Fatal("embedded database lists differently from the reference")
	}
	if db.Hash() != compileMagdir(t).Hash() {
		t.Fatal("embedded hash differs from a fresh compile")
	}
}

// TestLoadRoundTrip: Marshal then Load reproduces every record.
func TestLoadRoundTrip(t *testing.T) {
	db := compileMagdir(t) // database
	data, err := db.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	db2, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(db2.recs) != len(db.recs) || len(db2.regexes) != len(db.regexes) || len(db2.names) != len(db.names) {
		t.Fatalf("sizes differ: %d/%d recs, %d/%d regexes, %d/%d names",
			len(db2.recs), len(db.recs), len(db2.regexes), len(db.regexes), len(db2.names), len(db.names))
	}
	for i := range db.recs {
		if !sameRecord(&db.recs[i], &db2.recs[i]) {
			t.Fatalf("record %d differs after round trip", i)
		}
	}
	files := corpusFiles(t)
	for i, f := range files {
		a, b := db.Identify(f), db2.Identify(f)
		if a.Description != b.Description || a.MIME != b.MIME {
			t.Errorf("file %d: %q vs %q", i, a.Description, b.Description)
		}
	}
}

// TestLoadRefusals: a wrong magic, version or release is refused by name.
func TestLoadRefusals(t *testing.T) {
	good, err := compileMagdir(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), good...)
	bad[4] = 9 // format version
	for _, in := range [][]byte{nil, []byte("nope"), bad, good[:len(good)/2]} {
		_, err := Load(in)
		var le *LoadError
		if !errors.As(err, &le) {
			t.Errorf("Load(%d bytes): %v, want *LoadError", len(in), err)
		}
	}
	rel := append([]byte(nil), good...)
	copy(rel[8:], "9.99") // ImplementsFile is "5.48": same length
	if _, err := Load(rel); err == nil {
		t.Error("a database for another release loaded")
	}
}

// TestLoadTime checks that the embedded database loads in under a
// millisecond.
func TestLoadTime(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing")
	}
	best := time.Hour
	for i := 0; i < 10; i++ {
		start := time.Now()
		if _, err := Default(); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d < best {
			best = d
		}
	}
	t.Logf("Default() best of 10: %v (%d bytes embedded)", best, len(embeddedDatabase))
	if best > 5*time.Millisecond {
		t.Errorf("load took %v", best)
	}
}

func BenchmarkLoad(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Default(); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzLoad: no byte string may panic Load.
func FuzzLoad(f *testing.F) {
	db, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{})
	if err != nil {
		f.Fatal(err)
	}
	good, err := db.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good[:4096])
	f.Add([]byte("SMDB\x01\x00"))
	for _, src := range fuzzLoadSources() { // whole small databases, so mutation starts past the header
		small, err := compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte(src)}}, CompileOptions{})
		if err != nil {
			f.Fatal(err)
		}
		blob, err := small.Marshal()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(blob)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var db *Database
		var err error
		fuzzBounded(t, "Load", func() { db, err = Load(data) })
		if err == nil {
			fuzzBounded(t, "Identify with a loaded database", func() { db.Identify(data) })
		}
	})
}

// fuzzLoadSources are small rule sets covering the record kinds the
// matcher treats differently.
func fuzzLoadSources() []string {
	return []string{
		"0\tbyte\tx\tbyte %d\n>1\tbeshort\t>0\tshort %x\n>>3\tlelong&0xff\t=1\tlong %u\n",
		"0\tstring\tAB\tstring\n>2\tpstring/H\tx\tp %s\n>2\tsearch/64\tCD\tsearch\n",
		"0\tregex/20l\t^[a-z]+\tword %s\n0\tlequad\tx\tq %lld\n>8\tleqdate\tx\tdate %s\n",
		"0\tname\tsub\n>0\tbyte\tx\tsub %d\n0\tstring\tXY\tuse\n>2\tuse\tsub\n>(2.l+1)\tbyte\tx\tind %d\n",
		"0\tder\tseq\tder\n>&0\tder\tint\tint\n0\tlefloat\tx\tf %f\n0\tguid\tx\tg %s\n0\tindirect\tx\tindirect\n",
	}
}

// FuzzLoadFields: one scalar field of one record of a small compiled
// database set to any value, then marshalled and loaded. Load refuses it,
// or the database identifies within budget. Mutating a decoded database
// reaches every field with every value, which mutating bytes rarely does.
func FuzzLoadFields(f *testing.F) {
	f.Add(uint8(0), uint16(0), uint8(0), uint64(0))
	f.Add(uint8(2), uint16(0), uint8(6), uint64(0x80000000))
	f.Fuzz(func(t *testing.T, src uint8, rec uint16, field uint8, v uint64) {
		db, err := compileFS(fstest.MapFS{"r": &fstest.MapFile{Data: []byte(fuzzLoadSources()[int(src)%len(fuzzLoadSources())])}}, CompileOptions{})
		if err != nil {
			t.Fatal(err)
		}
		setScalarField(&db.recs[int(rec)%len(db.recs)], field, v)
		blob, err := db.Marshal()
		if err != nil {
			return
		}
		var loaded *Database
		fuzzBounded(t, "Load", func() { loaded, err = Load(blob) })
		if err != nil {
			return
		}
		for _, in := range [][]byte{blob, []byte("ABCDXY0123456789abcdef"), make([]byte, 64)} {
			fuzzBounded(t, "Identify with a mutated database", func() { loaded.Identify(in) })
		}
	})
}

// setScalarField sets field (modulo the number of fields) of r to the low
// bits of v. vallen stays within MAXstring, which Marshal asserts and
// Load's structural check already refuses past.
func setScalarField(r *record, field uint8, v uint64) {
	switch field % 13 {
	case 0:
		r.flag = low16(v)
	case 1:
		r.contLevel = low8(v)
	case 2:
		r.factor = low8(v)
	case 3:
		r.reln = low8(v)
	case 4:
		r.vallen = low8(v) % (maxString + 1)
	case 5:
		r.typ = fileType(low8(v))
	case 6:
		r.inType = fileType(low8(v))
	case 7:
		r.inOp = low8(v)
	case 8:
		r.maskOp = low8(v)
	case 9:
		r.factorOp = low8(v)
	case 10:
		r.offset = wrapInt32(int64(low32(v)))
	case 11:
		r.inOffset = wrapInt32(int64(low32(v)))
	default:
		r.maskOrStr = v
	}
}

// sameRecord compares two records field by field; the byte fields may
// live in different arenas and value may be padded differently.
func sameRecord(a, b *record) bool {
	return a.recordHead == b.recordHead &&
		bytes.Equal(trimNul(a.value), trimNul(b.value)) &&
		bytes.Equal(a.desc, b.desc) && bytes.Equal(a.mimetype, b.mimetype) &&
		bytes.Equal(a.apple, b.apple) && bytes.Equal(a.ext, b.ext)
}

// TestLoadRefusesHugeCounts checks that a table length above the record
// bound is refused while still unsigned, which matters on a 32-bit host
// where it would not fit an int.
func TestLoadRefusesHugeCounts(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// The file count follows the magic, version and three strings.
	i := len(formatMagic) + 2 // byteOffset
	for k := 0; k < 3; k++ {
		n := int(raw[i]) | int(raw[i+1])<<8
		i += 2 + n
	}
	bad := append([]byte(nil), raw...)
	bad[i], bad[i+1], bad[i+2], bad[i+3] = 0xff, 0xff, 0xff, 0xff
	if _, err := Load(bad); err == nil {
		t.Fatal("a file count of 0xffffffff was accepted")
	}
}

// TestEager checks the eager entry points: same answers as the lazy
// database, every slot compiled up front, and eagerness preserved only
// when both halves of a Join are eager.
func TestEager(t *testing.T) {
	lazy, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	eager, err := DefaultEager()
	if err != nil {
		t.Fatal(err)
	}
	if lazy.eager || !eager.eager {
		t.Fatal("eager flags")
	}
	for i := range eager.regexes {
		if eager.regexes[i].re == nil {
			t.Fatalf("slot %d not compiled", i)
		}
	}
	for i, data := range corpusFiles(t) {
		a, b := lazy.Identify(data), eager.Identify(data)
		if a.Description != b.Description || a.MIME != b.MIME {
			t.Fatalf("corpus file %d: lazy %q eager %q", i, a.Description, b.Description)
		}
	}
	raw, err := eager.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if db, err := LoadEager(raw); err != nil || !db.eager {
		t.Fatal("LoadEager")
	}
	compiled := compileMagdir(t)
	if !compiled.eager {
		t.Fatal("a compiled database is eager")
	}
	if db, err := joinForTest(eager, compiled); err != nil || !db.eager {
		t.Fatal("eager join")
	}
	if db, err := joinForTest(lazy, compiled); err != nil || db.eager {
		t.Fatal("a lazy half makes the join lazy")
	}
}
