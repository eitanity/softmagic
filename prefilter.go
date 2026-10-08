// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"encoding/binary"

	"github.com/eitanity/softmagic/internal/invariant"
)

// A prefilter is the literal bytes an entry's first line must
// find at an absolute offset. It is derived only where the comparison is
// provably the same as evaluating the line: the `=` relation, an absolute
// non-negative offset, and either a `string` with no modifiers or range, or
// an unmasked fixed-width integer whose byte order the type fixes. A
// failing prefilter skips the entry exactly as the failed line would.
type prefilter struct {
	lit  [prefilterMax]byte
	off  int32
	n    uint8 // 0: no prefilter
	skip uint8 // skipTop's verdict per (mode, text) combination, see skipBit
}

// skipBit is the bit of prefilter.skip for a mode and text flag.
func skipBit(mode uint16, text bool) uint8 {
	bit := uint8(1)
	if mode == flagTextTest {
		bit <<= 1
	}
	if text {
		bit <<= 2
	}
	return bit
}

const prefilterMax = 16

// prefilterOf derives the prefilter of a first line, or an inactive one.
func prefilterOf(r *record) prefilter { // magicLine
	invariant.Check(r.contLevel == 0, "prefilter of a first line")
	var pf prefilter // prefilter
	if r.reln != '=' || r.offset < 0 ||
		r.flag&(flagIndir|flagOffAdd|flagIndirOffAdd|flagOffNegative) != 0 {
		return pf
	}
	pf.off = r.offset
	switch {
	case r.typ == tString:
		if r.strFlags() != 0 || r.strRange() != 0 || r.vallen == 0 || int(r.vallen) > prefilterMax {
			return prefilter{}
		}
		pf.n = r.vallen
		copy(pf.lit[:], r.value[:r.vallen])
	case r.maskOp != 0 || r.maskOrStr != 0:
		return prefilter{}
	default:
		pf.n = integerLiteral(r, pf.lit[:])
	}
	return pf
}

// integerLiteral writes the bytes an integer test compares against and
// returns their count, 0 for a type the prefilter does not cover.
func integerLiteral(r *record, lit []byte) uint8 {
	invariant.Check(len(lit) >= 8, "literal buffer holds a quad")
	v := binary.LittleEndian.Uint64(r.value[0:8]) // value
	switch r.typ {
	case tByte:
		lit[0] = low8(v)
		return 1
	case tShort, tLeShort:
		binary.LittleEndian.PutUint16(lit, low16(v))
		return 2
	case tBeShort:
		binary.BigEndian.PutUint16(lit, low16(v))
		return 2
	case tLong, tLeLong, tDate, tLeDate, tLDate, tLeLDate:
		binary.LittleEndian.PutUint32(lit, low32(v))
		return 4
	case tBeLong, tBeDate, tBeLDate:
		binary.BigEndian.PutUint32(lit, low32(v))
		return 4
	case tQuad, tLeQuad:
		binary.LittleEndian.PutUint64(lit, v)
		return 8
	case tBeQuad:
		binary.BigEndian.PutUint64(lit, v)
		return 8
	default:
		return 0
	}
}

// buildPrefilters derives the prefilter table for every first line of a
// binary-set entry in each map.
func (db *Database) buildPrefilters() {
	db.pre = make([]prefilter, len(db.recs))
	db.entryEnd = make([]int32, len(db.recs))
	for i := range db.maps {
		for _, e := range db.maps[i].sets[0] {
			db.pre[e.first] = prefilterOf(&db.recs[e.first])
		}
		for s := 0; s < 2; s++ {
			for _, e := range db.maps[i].sets[s] {
				db.pre[e.first].skip = skipMask(&db.recs[e.first])
				for k := e.first; k < e.first+e.count; k++ {
					db.entryEnd[k] = e.first + e.count
				}
			}
		}
	}
}

// skipMask evaluates skipTop for every mode and text combination.
func skipMask(m *record) uint8 {
	invariant.Check(m.contLevel == 0, "skip mask of a first line")
	var mask uint8
	for _, mode := range [2]uint16{flagBinTest, flagTextTest} {
		for _, text := range [2]bool{false, true} {
			if skipTop(m, mode, text) {
				mask |= skipBit(mode, text)
			}
		}
	}
	return mask
}

// prefilterOK reports whether the line's literal is present; it keeps the
// same bookkeeping the full evaluation would have done on that line.
func (s *scan) prefilterOK(f *frame, pf *prefilter) bool { // frame
	invariant.Check(pf.n > 0 && int(pf.n) <= prefilterMax, "active prefilter")
	win := s.window(f)
	off := int64(pf.off)
	end := off + int64(pf.n)
	if end > int64(len(win)) {
		s.oobHit = true
		return false
	}
	read := off + maxString // mcopy reads up to MAXstring bytes at the offset
	if read > int64(len(win)) {
		read = int64(len(win))
	}
	s.noteRead(f.base + int(read))
	return string(win[off:end]) == string(pf.lit[:pf.n])
}
