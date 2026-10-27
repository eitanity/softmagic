// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from is_tar.c, is_csv.c and is_simh.c, file 5.48, Copyright
// (c) Ian F. Darwin 1986-1995 (see COPYING). These are the built-in
// detectors file_buffer runs before the rules.

package softmagic

import (
	"code.eitanity.com/softmagic/internal/invariant"
)

// builtinResult is what a detector established: nothing, or a description
// and MIME type.
type builtinResult struct {
	desc string
	mime string
	hit  bool
}

// builtins runs the detectors in the reference's order (tar, JSON, CSV,
// SIMH; CDF and ELF are not implemented yet) and returns the first hit.
func (s *scan) builtins(e encoding) builtinResult { // encoding
	if !invariant.Check(len(s.buf) >= 2, "detectors run on two or more bytes") {
		s.truncate(TruncInvariant)
		return builtinResult{}
	}
	if r := detectTar(s.buf); r.hit && !s.excluded(CheckTar) {
		return r
	}
	if r := s.detectJSON(s.buf); r.hit && !s.excluded(CheckJSON) {
		return r
	}
	if r := s.detectCSV(s.buf, e); r.hit && !s.excluded(CheckCSV) {
		return r
	}
	if r := detectSIMH(s.buf); r.hit && !s.excluded(CheckSIMH) {
		return r
	}
	if s.excluded(CheckCDF) {
		return builtinResult{}
	}
	return s.detectCDF()
}

// tar.h's header layout.
const (
	tarRecordSize = 512
	tarNameSize   = 100
	tarChksumOff  = 148
	tarChksumLen  = 8
	tarMagicOff   = 257
	tarMagicLen   = 8
)

// detectTar is file_is_tar: a 512-byte header whose checksum field holds
// the sum of the header with the checksum itself counted as spaces.
func detectTar(buf []byte) builtinResult {
	if len(buf) < tarRecordSize {
		return builtinResult{}
	}
	hdr := buf[:tarRecordSize]
	name := hdr[:tarNameSize]
	// A Gentoo GLEP 78 binary package is left to the rules.
	if nul := indexByteFrom(name, 0, 0); nul >= 7 && string(name[nul-7:nul]) == "/gpkg-1" {
		return builtinResult{}
	}
	recsum := tarOctal(hdr[tarChksumOff : tarChksumOff+tarChksumLen])
	sum := 0
	for i := 0; i < tarRecordSize; i++ {
		sum += int(hdr[i])
	}
	for i := tarChksumOff; i < tarChksumOff+tarChksumLen; i++ {
		sum -= int(hdr[i])
	}
	sum += ' ' * tarChksumLen
	if sum != recsum {
		return builtinResult{}
	}
	magic := hdr[tarMagicOff : tarMagicOff+tarMagicLen]
	switch {
	case cStringEquals(magic, "ustar  "):
		return builtinResult{desc: "POSIX tar archive (GNU)", mime: "application/x-tar", hit: true}
	case cStringEquals(magic, "ustar"):
		return builtinResult{desc: "POSIX tar archive", mime: "application/x-tar", hit: true}
	default:
		return builtinResult{desc: "tar archive", mime: "application/x-tar", hit: true}
	}
}

// cStringEquals is strncmp(field, s, len(field)) == 0: the field holds s
// followed by a NUL (or ends exactly).
func cStringEquals(field []byte, s string) bool {
	if len(s) > len(field) || string(field[:len(s)]) != s {
		return false
	}
	return len(s) == len(field) || field[len(s)] == 0
}

// tarOctal is from_oct: leading spaces, octal digits, then space or NUL;
// -1 for a blank or malformed field.
func tarOctal(f []byte) int { // tarField
	i := 0 // fieldIndex
	for ; i < len(f) && cIsSpace(f[i]); i++ {
	}
	if i == len(f) {
		return -1
	}
	v := 0 // octalValue
	for ; i < len(f) && f[i] >= '0' && f[i] <= '7'; i++ {
		v = v<<3 | int(f[i]-'0')
	}
	if i < len(f) && f[i] != 0 && !cIsSpace(f[i]) {
		return -1
	}
	return v
}

// csvLines is CSV_LINES: how many lines decide.
const csvLines = 10

// detectCSV is file_is_csv: text whose first lines have a consistent
// field count greater than one.
func (s *scan) detectCSV(buf []byte, e encoding) builtinResult {
	if !e.isText() || !s.csvParse(buf) || s.stopped {
		return builtinResult{}
	}
	return builtinResult{desc: "CSV " + e.code() + " text", mime: "text/csv", hit: true}
}

// csvParse is csv_parse. It charges the scan every workPerPoll bytes and
// gives up when the scan stops.
func (s *scan) csvParse(uc []byte) bool { // input
	if !invariant.Check(uc != nil || len(uc) == 0, "input slice") {
		return false
	}
	var c csvCounts                 // fieldCounts
	charged, next := 0, workPerPoll // the cursor when the scan was last and is next charged
	for i := 0; i < len(uc); i++ {
		if i >= next {
			if s.charge(i - charged) {
				return false
			}
			charged, next = i, i+workPerPoll
		}
		switch uc[i] {
		case '"':
			i = s.csvEatQuote(uc, i+1) - 1
		case ',':
			c.nf++
		case '\n':
			if ok, done := c.endLine(); done {
				return ok
			}
		default:
		}
	}
	return c.tf >= 1 && c.nl >= 2
}

// csvCounts are csv_parse's counts: fields on this line and on the
// first line, and lines ended.
type csvCounts struct {
	nf, tf, nl int
}

// endLine is csv_parse's newline case. done is true when the lines seen
// decide, and ok is then the answer.
func (c *csvCounts) endLine() (ok, done bool) {
	c.nl++
	if c.nl == csvLines {
		return c.tf > 1 && c.tf == c.nf, true
	}
	switch {
	case c.tf == 0 && c.nf == 0:
		return false, true
	case c.tf == 0:
		c.tf = c.nf
	case c.tf != c.nf:
		return false, true
	}
	c.nf = 0
	return false, false
}

// csvEatQuote is eatquote: skip to the end of a quoted field, where a
// doubled quote is an escape; it returns the index after the field, or
// the end of the input when the scan stops. A field is scanned
// workPerPoll bytes at a time, each piece after the first charged before
// it is scanned.
func (s *scan) csvEatQuote(uc []byte, i int) int { // cursor
	if !invariant.Check(i >= 0 && i <= len(uc), "cursor within the input") {
		return len(uc)
	}
	quote := false
	for k := 0; k <= len(uc)/workPerPoll && i < len(uc); k++ {
		piece := uc[:min(len(uc), i+workPerPoll)] // ends at the next charge
		if k > 0 && s.charge(len(piece)-i) {
			return len(uc)
		}
		var done bool
		if i, quote, done = csvQuotePiece(piece, i, quote); done {
			return i
		}
	}
	return len(uc)
}

// csvQuotePiece is eatquote's loop over piece from i: done is true when
// the field ends, at the returned index.
func csvQuotePiece(piece []byte, i int, quote bool) (int, bool, bool) { // cursor
	for ; i < len(piece); i++ {
		if piece[i] != '"' {
			if quote {
				return i, quote, true
			}
			continue
		}
		quote = !quote
	}
	return i, quote, false
}

// simhTapemarks is SIMH_TAPEMARKS.
const simhTapemarks = 10

// detectSIMH is file_is_simh: a SIMH tape image of length-framed records.
func detectSIMH(buf []byte) builtinResult {
	if !simhParse(buf) {
		return builtinResult{}
	}
	return builtinResult{desc: "SIMH tape data", mime: "application/SIMH-tape-data", hit: true}
}

// simhLen is getlen: a little-endian record length whose bits 24-27 must
// be clear; odd lengths round up; 0xffffffff is end of medium.
func simhLen(buf []byte, i int) (n in32, ok bool) {
	n = le32(buf[i:])
	if n == 0xffffffff {
		return n, true
	}
	if n&0x00ffffff != n&0x0fffffff {
		return 0, false
	}
	n &= 0x00ffffff
	if n&1 != 0 {
		return inAdd(n, 1) // below 2^24, so it cannot overflow
	}
	return n, true
}

// simhParse is simh_parse: records framed by equal leading and trailing
// lengths, tapemarks of zero length, ending at end of medium.
func simhParse(buf []byte) bool {
	if !invariant.Check(simhTapemarks > 0, "tapemark limit positive") {
		return false
	}
	st := simhState{} // tapeState
	for ; st.i <= len(buf)-4; st.i += 4 {
		nbytes, ok := simhLen(buf, st.i) // lengthOK
		if !ok {
			return false
		}
		if (st.nt > 0 || st.nr > 0) && nbytes == 0xffffffff {
			break
		}
		stop, ok := st.frame(buf, nbytes)
		if !ok {
			return false
		}
		if stop {
			break
		}
	}
	return (st.past || st.nt*4 != st.i) && st.nr != 0
}

// frame handles one length word: a tapemark, or a data record.
func (st *simhState) frame(buf []byte, nbytes in32) (stop, ok bool) {
	if !invariant.Check(st.i >= 0 && st.i <= len(buf), "cursor within the input") {
		return false, false
	}
	if nbytes != 0 {
		return st.record(buf, nbytes)
	}
	st.nt++
	if st.nt == simhTapemarks {
		st.i += 4
		return true, true
	}
	return false, true
}

// simhState is the parse position and the tapemark and record counts;
// past is set when a record runs beyond the input, where the reference's
// cursor ends up past everything its tapemarks account for.
type simhState struct {
	i, nt, nr int
	past      bool
}

// record consumes a data record of nbytes bytes and its trailing length;
// stop is true when the input ends inside it. The length is up to
// 0xffffffff (end of medium before any record), so it is compared in
// int64 and becomes an int only once it is known to lie within buf.
func (st *simhState) record(buf []byte, nbytes in32) (stop, ok bool) {
	if !invariant.Check(nbytes > 0 && st.i >= 0 && st.i <= len(buf)-4, "record length positive and cursor on a length word") {
		return false, false
	}
	if inInt64(nbytes)+4 > int64(len(buf)-st.i-4) {
		st.past = true
		return true, true
	}
	n := inInt(nbytes) // recordLength
	cbytes, ok := simhLen(buf, st.i+4+n)
	if !ok || cbytes != nbytes {
		return false, false
	}
	st.i += n + 4
	st.nr++
	return false, true
}
