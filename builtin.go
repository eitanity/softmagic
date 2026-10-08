// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from is_tar.c, is_csv.c and is_simh.c, file 5.48, Copyright
// (c) Ian F. Darwin 1986-1995 (see COPYING). These are the built-in
// detectors file_buffer runs before the rules.

package softmagic

import (
	"encoding/binary"

	"github.com/eitanity/softmagic/internal/invariant"
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
	invariant.Check(len(s.buf) >= 2, "detectors run on two or more bytes")
	if r := detectTar(s.buf); r.hit && !s.excluded(CheckTar) {
		return r
	}
	if r := detectJSON(s.buf); r.hit && !s.excluded(CheckJSON) {
		return r
	}
	if r := detectCSV(s.buf, e); r.hit && !s.excluded(CheckCSV) {
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
func detectCSV(buf []byte, e encoding) builtinResult {
	if !e.isText() || !csvParse(buf) {
		return builtinResult{}
	}
	return builtinResult{desc: "CSV " + e.code() + " text", mime: "text/csv", hit: true}
}

// csvParse is csv_parse.
func csvParse(uc []byte) bool { // input
	invariant.Check(uc != nil || len(uc) == 0, "input slice")
	nf, tf, nl := 0, 0, 0 // firstLineFields
	for i := 0; i < len(uc); i++ {
		switch uc[i] {
		case '"':
			i = csvEatQuote(uc, i+1) - 1
		case ',':
			nf++
		case '\n':
			nl++
			if nl == csvLines {
				return tf > 1 && tf == nf
			}
			switch {
			case tf == 0 && nf == 0:
				return false
			case tf == 0:
				tf = nf
			case tf != nf:
				return false
			}
			nf = 0
		default:
		}
	}
	return tf >= 1 && nl >= 2
}

// csvEatQuote is eatquote: skip to the end of a quoted field, where a
// doubled quote is an escape; it returns the index after the field.
func csvEatQuote(uc []byte, i int) int { // cursor
	invariant.Check(i >= 0 && i <= len(uc), "cursor within the input")
	quote := false
	for ; i < len(uc); i++ {
		if uc[i] != '"' {
			if quote {
				return i
			}
			continue
		}
		quote = !quote
	}
	return len(uc)
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
func simhLen(buf []byte, i int) (n uint32, ok bool) {
	n = binary.LittleEndian.Uint32(buf[i:])
	if n == 0xffffffff {
		return n, true
	}
	if n&0x00ffffff != n&0x0fffffff {
		return 0, false
	}
	n &= 0x00ffffff
	if n&1 != 0 {
		n++
	}
	return n, true
}

// simhParse is simh_parse: records framed by equal leading and trailing
// lengths, tapemarks of zero length, ending at end of medium.
func simhParse(buf []byte) bool {
	invariant.Check(simhTapemarks > 0, "tapemark limit positive")
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
	return st.nt*4 != st.i && st.nr != 0
}

// frame handles one length word: a tapemark, or a data record.
func (st *simhState) frame(buf []byte, nbytes uint32) (stop, ok bool) {
	invariant.Check(st.i >= 0 && st.i <= len(buf), "cursor within the input")
	if nbytes != 0 {
		return st.record(buf, int(nbytes))
	}
	st.nt++
	if st.nt == simhTapemarks {
		st.i += 4
		return true, true
	}
	return false, true
}

// simhState is the parse position and the tapemark and record counts.
type simhState struct {
	i, nt, nr int
}

// record consumes a data record of n bytes and its trailing length; stop
// is true when the input ends inside it.
func (st *simhState) record(buf []byte, n int) (stop, ok bool) { // recordLength
	invariant.Check(n > 0 && st.i >= 0, "record length positive and cursor non-negative")
	invariant.Check(n >= 0 && st.i >= 0, "record length and cursor non-negative")
	if n > len(buf) || len(buf)-st.i-4 < n+4 {
		st.i += 4 + n
		return true, true
	}
	cbytes, ok := simhLen(buf, st.i+4+n)
	if !ok || cbytes != low32(bitsOfInt64(int64(n))) {
		return false, false
	}
	st.i += n + 4
	st.nr++
	return false, true
}
