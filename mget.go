// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from mget, mcopy, do_ops, msetoffset and moffset in
// softmagic.c, file 5.48, Copyright (c) Ian F. Darwin 1986-1995 (see
// COPYING).

package softmagic

import (
	"encoding/binary"
	"math"
	"strconv"

	"github.com/eitanity/softmagic/internal/invariant"
)

// setOffset is msetoffset: establish ms->offset for the line. It returns
// false when the line cannot be evaluated (a from-end offset beyond the
// window), which the caller treats as `goto flush`.
func (s *scan) setOffset(m *record, f *frame, contLevel int32) bool {
	invariant.Check(contLevel >= 0 && int(contLevel) < maxLevels, "continuation level within bounds")
	invariant.Check(f.n >= 0, "window length non-negative")
	if m.flag&flagOffNegative != 0 {
		if contLevel > 0 && m.flag&(flagOffAdd|flagIndirOffAdd) != 0 {
			// msetoffset's goto normal: back on the window, as bb is reset.
			s.offset, s.eoffset, f.onTail = bitsOfInt32(-m.offset), 0, false
			return true
		}
		return s.setOffsetFromEnd(m, f)
	}
	if m.flag&flagOffPositive != 0 || contLevel == 0 {
		s.offset, s.eoffset = bitsOfInt32(m.offset), 0
		f.onTail = false // match()'s "normal" path resets bb to the window
		return true
	}
	s.offset = bitsOfInt32(s.eoffset) + bitsOfInt32(m.offset)
	return true
}

// setOffsetFromEnd is msetoffset for a line counted from the end: from the
// window's end, or, as the reference's buffer_fill does for a file it
// opened, from the end of the file's last bytes (as many as the window
// holds), which past MaxBytes are not the window's.
func (s *scan) setOffsetFromEnd(m *record, f *frame) bool {
	invariant.Check(m.flag&flagOffNegative != 0, "a line counted from the end")
	invariant.Check(f.n >= 0, "window length non-negative")
	if f.o != 0 {
		return false // the reference refuses a non-zero base here
	}
	n := int64(f.n)
	if s.tailApplies(m) {
		t, ok := s.fileTail(f.n)
		if !ok {
			return false
		}
		n, f.onTail = int64(len(t)), true
	}
	if int64(m.offset) > n {
		s.oobHit = true
		return false
	}
	s.eoffset = wrapInt32(n - int64(m.offset))
	s.offset = bitsOfInt32(s.eoffset)
	return true
}

// tailApplies reports whether a line counted from the end reads the file's
// tail rather than the window's: an IdentifyAt input longer than the
// window, in the binary phase, and a test that reads one value. A search,
// regex, der, use or indirect line still counts from the window's end.
func (s *scan) tailApplies(m *record) bool {
	invariant.Check(m.flag&flagOffNegative != 0, "a line counted from the end")
	if s.src == nil || s.winID != windowBin || s.srcSize <= int64(len(s.buf)) {
		return false
	}
	return readsOneValue(m)
}

// readsOneValue reports whether a line's test reads one value at its
// offset, which can come from the tail; a search, regex, der, use or
// indirect line works over regions or frames of the window.
func readsOneValue(m *record) bool {
	switch m.typ {
	case tSearch, tRegex, tDer, tUse, tIndirect, tName:
		return false
	default:
		return true
	}
}

// fileTail is the file's last min(size, n) bytes, read once per call.
func (s *scan) fileTail(n int) ([]byte, bool) {
	invariant.Check(n >= 0 && s.src != nil, "a tail of an IdentifyAt input")
	l := int64(n)
	if s.srcSize < l {
		l = s.srcSize
	}
	if len(s.tail) == int(l) && s.tailRead {
		return s.tail, true
	}
	b, ok := s.readAt(s.srcSize-l, int(l))
	if !ok {
		return nil, false
	}
	if cap(s.tailBuf) < len(b) {
		s.tailBuf = make([]byte, len(b))
	}
	s.tail = s.tailBuf[:copy(s.tailBuf[:len(b)], b)]
	s.tailRead = true
	return s.tail, true
}

// mgetLine is mget over the window the reference's bb holds: the frame's
// own, or the file's tail after a line counted from the end.
func (s *scan) mgetLine(m *record, f *frame) (int, bool) {
	invariant.Check(f.base+f.n <= len(s.buf), "frame window within the buffer")
	if !f.onTail || !readsOneValue(m) || !s.tailRead {
		return s.mget(m, f)
	}
	saved := s.buf
	tf := *f
	tf.base, tf.n = 0, len(s.tail)
	s.buf = s.tail
	r, pushed := s.mget(m, &tf)
	s.buf = saved
	invariant.Check(!pushed, "a tail line pushes no frame")
	return r, pushed
}

// mget reads the value the line tests into s.value, resolving indirect
// offsets, and converts it. It returns r (0 no data, 1 ready, -1 fatal)
// and whether a child frame was pushed for a "use" or "indirect" line, in
// which case finishUse/finishIndirect complete the call later.
func (s *scan) mget(m *record, f *frame) (r int, pushed bool) {
	invariant.Check(f.base+f.n <= len(s.buf), "frame window within the buffer")
	invariant.Check(m.typ != tInvalid, "line has a type")
	// The reference checks both counts before every line, not only before
	// the lines that raise them, and either one ends the identification.
	if s.indir >= s.lim.indirect {
		s.abortWith(TruncIndirect, "indirect count ("+strconv.Itoa(s.indir)+") exceeded")
		return -1, false
	}
	if s.names >= s.lim.name {
		s.abortWith(TruncName, "name use count ("+strconv.Itoa(s.names)+") exceeded")
		return -1, false
	}
	win, nbytes := s.window(f), f.n
	offset := s.offset
	s.mcopy(m, m.flag&flagIndir != 0, win, offset+f.o)
	if m.flag&flagIndir != 0 {
		ok := false
		offset, ok = s.indirectOffset(m, f, win, offset)
		if !ok {
			return 0, false
		}
		s.mcopy(m, false, win, offset)
		s.offset = offset
	}
	if !s.enoughData(m, nbytes, offset) {
		return 0, false
	}
	switch m.typ {
	case tIndirect:
		return s.pushIndirect(m, f, offset)
	case tUse:
		return s.pushUse(m, f, offset)
	case tName:
		if s.mode == modeDesc {
			s.writeString(m.descString())
		}
		return 1, false
	default:
		if !s.mconvert(m, f.flip) {
			return 0, false
		}
		return 1, false
	}
}

// enoughData is mget's "verify we have enough data" switch.
func (s *scan) enoughData(m *record, nbytes int, offset uint32) bool {
	invariant.Check(nbytes >= 0, "window length non-negative")
	o := int64(offset)
	switch m.typ {
	case tByte:
		return !s.oob(nbytes, o, 1)
	case tShort, tBeShort, tLeShort:
		return !s.oob(nbytes, o, 2)
	case tLong, tBeLong, tLeLong, tMeLong, tDate, tBeDate, tLeDate, tMeDate,
		tLDate, tBeLDate, tLeLDate, tMeLDate, tFloat, tBeFloat, tLeFloat:
		return !s.oob(nbytes, o, 4)
	case tDouble, tBeDouble, tLeDouble:
		return !s.oob(nbytes, o, 8)
	case tLeGUID, tBeGUID, tGUID:
		return !s.oob(nbytes, o, 16)
	case tString, tPString, tSearch, tOctal:
		return !s.oob(nbytes, o, int(m.vallen))
	case tRegex, tIndirect, tUse:
		if int64(nbytes) < o {
			s.oobHit = true
			return false
		}
		return true
	default:
		return true
	}
}

// mcopy copies the bytes the test reads into s.value, or for search,
// regex and der sets up the search region. The copy is the reference's:
// 128 bytes (or the string range) from offset, zero-padded.
func (s *scan) mcopy(m *record, indir bool, win []byte, offset uint32) {
	invariant.Check(len(win) <= len(s.buf), "copy source is the window")
	nbytes := len(win)
	size := maxString
	if !indir {
		switch m.typ {
		case tDer, tSearch:
			s.setSearchRegion(win, offset)
			return
		case tRegex:
			s.setRegexRegion(m, win, offset)
			return
		case tBeString16, tLeString16:
			s.copyString16(m, win, offset)
			return
		case tString, tPString:
			if r := m.strRange(); r != 0 && int(r) < maxString {
				size = int(r)
			}
		default:
		}
	}
	for i := range s.value {
		s.value[i] = 0
	}
	if m.typ == tOffset {
		binary.LittleEndian.PutUint64(s.value[0:8], uint64(offset)&0xffffffff)
		return
	}
	if int64(offset) >= int64(nbytes) {
		s.oobHit = true
		return
	}
	n := copy(s.value[:size], win[offset:])
	s.noteRead(int(offset) + n)
}

// setSearchRegion is mcopy's FILE_SEARCH/FILE_DER case.
func (s *scan) setSearchRegion(win []byte, offset uint32) {
	invariant.Check(len(win) <= len(s.buf), "region within the buffer")
	off := int(offset)
	if off > len(win) {
		off = len(win)
	}
	s.search = searchState{start: off, length: len(win) - off, offset: off, valid: true}
}

// setRegexRegion is mcopy's FILE_REGEX case: the region is bounded by the
// rule's byte or line count and by regexMax.
func (s *scan) setRegexRegion(m *record, win []byte, offset uint32) {
	invariant.Check(m.typ == tRegex, "regex line")
	invariant.Check(len(win) <= len(s.buf), "region within the buffer")
	nbytes := len(win)
	if int64(nbytes) < int64(offset) {
		s.search = searchState{}
		return
	}
	off := int(offset)
	linecnt, bytecnt := 0, int(m.strRange())
	if m.strFlags()&regexLineCount != 0 {
		linecnt, bytecnt = int(m.strRange()), int(m.strRange())*80
	}
	if bytecnt == 0 || bytecnt > nbytes-off {
		bytecnt = nbytes - off
	}
	if bytecnt > s.lim.regex {
		bytecnt = s.lim.regex // the reference's regex_max, applied silently as it does
	}
	region := win[off : off+bytecnt]
	last := regexLineLimit(region, linecnt)
	s.search = searchState{start: off, length: last, offset: off, valid: true}
	s.noteRead(off + last)
}

// regexLineLimit reproduces the line-counting loop of mcopy: it returns
// the length of the region that holds the first linecnt lines, or the
// whole region when fewer lines are present or no count was given.
func regexLineLimit(region []byte, linecnt int) int {
	invariant.Check(linecnt >= 0, "line count non-negative")
	end := len(region)
	last := 0
	b := 0
	for lines := linecnt; lines > 0 && b < end; lines-- {
		nl := indexByteFrom(region, b, '\n')
		if nl < 0 {
			nl = indexByteFrom(region, b, '\r')
			if nl < 0 {
				return end
			}
		}
		b = nl
		if b < end-1 && region[b] == '\r' && region[b+1] == '\n' {
			b++
		}
		if b < end-1 && region[b] == '\n' {
			b++
		}
		last = b
		b++
		if lines == 1 {
			return last
		}
	}
	return end
}

// indexByteFrom is bytes.IndexByte from position i.
func indexByteFrom(b []byte, i int, c byte) int {
	for ; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// copyString16 is mcopy's 16-bit string case: the low (or high) bytes of
// UTF-16 units, with an embedded NUL unit turned into a space.
func (s *scan) copyString16(m *record, win []byte, offset uint32) {
	invariant.Check(m.typ == tBeString16 || m.typ == tLeString16, "16-bit string line")
	for i := range s.value {
		s.value[i] = 0
	}
	if int64(offset) >= int64(len(win)) {
		s.oobHit = true
		return
	}
	src := int(offset)
	if m.typ == tBeString16 {
		src++
	}
	dst := 0
	for ; src < len(win) && dst < maxString-1; src += 2 {
		s.value[dst] = win[src]
		if s.value[dst] == 0 {
			other := src - 1
			if m.typ == tLeString16 {
				other = src + 1
			}
			if other >= 0 && other < len(win) && win[other] != 0 {
				s.value[dst] = ' '
			}
		}
		dst++
	}
	s.noteRead(src)
}

// indirectOffset resolves an "(off.t[op]adj)" offset: the value at the
// current offset, combined with the adjustment, becomes the new offset.
func (s *scan) indirectOffset(m *record, f *frame, win []byte, offset uint32) (uint32, bool) {
	invariant.Check(m.flag&flagIndir != 0, "indirect line")
	nbytes := len(win)
	off := int64(m.inOffset)
	sgn := m.inOp&opSigned != 0
	if m.inOp&opIndirect != 0 {
		v, ok := s.readIndirectAdjust(m, f, win, int64(offset)+off, sgn)
		if !ok {
			return 0, false
		}
		off = v
	}
	inType := cvtFlip(m.inType, f.flip)
	size := typeSize(inType)
	if inType == tOctal {
		size = int(m.vallen)
	}
	if size == 0 || s.oob(nbytes, int64(offset), size) {
		return 0, false
	}
	lhs, ok := s.indirectLHS(inType, sgn)
	if !ok {
		return 0, false
	}
	newOffset, ok := doOps(m, lhs, off)
	if !ok {
		return 0, false
	}
	if m.flag&flagIndirOffAdd != 0 {
		if f.contLevel == 0 {
			return 0, false
		}
		newOffset += bitsOfInt32(s.levels[f.contLevel-1].off)
		if newOffset == 0 {
			return 0, false
		}
	}
	return newOffset, true
}

// indirectLHS reads the indirect value from the copied bytes in s.value
// as the in_type says, sign- or zero-extended.
func (s *scan) indirectLHS(inType fileType, sgn bool) (int64, bool) {
	invariant.Check(typeSize(inType) <= maxString, "indirect value fits the copy")
	v := s.value[:]
	switch inType {
	case tByte:
		return extend(uint64(v[0]), 8, sgn), true
	case tShort, tLeShort:
		return extend(uint64(binary.LittleEndian.Uint16(v)), 16, sgn), true
	case tBeShort:
		return extend(uint64(binary.BigEndian.Uint16(v)), 16, sgn), true
	case tLong, tLeLong:
		return extend(uint64(binary.LittleEndian.Uint32(v)), 32, sgn), true
	case tLeID3:
		return extend(uint64(id3Length(binary.LittleEndian.Uint32(v))), 32, sgn), true
	case tBeLong:
		return extend(uint64(binary.BigEndian.Uint32(v)), 32, sgn), true
	case tBeID3:
		return extend(uint64(id3Length(binary.BigEndian.Uint32(v))), 32, sgn), true
	case tMeLong:
		return extend(uint64(middleEndian32(v)), 32, sgn), true
	case tLeQuad:
		return extend(binary.LittleEndian.Uint64(v), 64, sgn), true
	case tBeQuad:
		return extend(binary.BigEndian.Uint64(v), 64, sgn), true
	case tOctal:
		n, _, _ := strtoull(v, 0, 8)
		return extend(n, 64, sgn), true
	default:
		return 0, false
	}
}

// readIndirectAdjust reads the "((x))" inner value at window offset at.
func (s *scan) readIndirectAdjust(m *record, f *frame, win []byte, at int64, sgn bool) (int64, bool) {
	invariant.Check(m.inOp&opIndirect != 0, "double indirection requested")
	inType := cvtFlip(m.inType, f.flip)
	size := typeSize(inType)
	if inType == tOctal {
		size = int(m.vallen)
	}
	if size == 0 || s.oob(len(win), at, size) {
		return 0, false
	}
	b := win[at:]
	switch inType {
	case tByte:
		return extend(uint64(b[0]), 8, sgn), true
	case tShort, tLeShort:
		return extend(uint64(binary.LittleEndian.Uint16(b)), 16, sgn), true
	case tBeShort:
		return extend(uint64(binary.BigEndian.Uint16(b)), 16, sgn), true
	case tLong, tLeLong, tLeID3:
		return extend(uint64(binary.LittleEndian.Uint32(b)), 32, sgn), true
	case tBeLong, tBeID3:
		return extend(uint64(binary.BigEndian.Uint32(b)), 32, sgn), true
	case tMeLong:
		return extend(uint64(middleEndian32(b)), 32, sgn), true
	case tLeQuad:
		return extend(binary.LittleEndian.Uint64(b), 64, sgn), true
	case tBeQuad:
		return extend(binary.BigEndian.Uint64(b), 64, sgn), true
	case tOctal:
		n, _, _ := strtoull(s.value[:], 0, 8)
		return extend(n, 64, sgn), true
	default:
		return 0, false
	}
}

// extend is the reference's SEXT macro: sign- or zero-extend the low
// `bits` of v to 64 bits, as a signed value.
func extend(v uint64, bits int, sgn bool) int64 {
	invariant.Check(bits == 8 || bits == 16 || bits == 32 || bits == 64, "extension width")
	switch bits {
	case 8:
		v &= 0xff
		if sgn {
			v = signExtend8(v)
		}
	case 16:
		v &= 0xffff
		if sgn {
			v = signExtend16(v)
		}
	case 32:
		v &= 0xffffffff
		if sgn {
			v = signExtend32(v)
		}
	default:
	}
	return int64FromBits(v)
}

// int64FromBits reinterprets a 64-bit pattern as two's complement.
func int64FromBits(v uint64) int64 {
	if v > math.MaxInt64 {
		return -int64(^v&math.MaxInt64) - 1
	}
	return int64(v & math.MaxInt64)
}

// id3Length is cvt_id3: four 7-bit groups.
func id3Length(v uint32) uint32 {
	return (v & 0x7f) | ((v >> 8) & 0x7f << 7) | ((v >> 16) & 0x7f << 14) | ((v >> 24) & 0x7f << 21)
}

// middleEndian32 is the PDP-11 word order: bytes 1 0 3 2.
func middleEndian32(b []byte) uint32 {
	return uint32(b[1])<<24 | uint32(b[0])<<16 | uint32(b[3])<<8 | uint32(b[2])
}

// doOps combines the indirect value with the adjustment as do_ops does,
// in the reference's intmax_t arithmetic with its overflow refusals.
func doOps(m *record, lhs, off int64) (uint32, bool) {
	invariant.Check(m.inOp&opsMask <= opModulo, "indirect operator in range")
	if lhs >= math.MaxUint32 || lhs <= math.MinInt32 || off >= math.MaxUint32 || off <= math.MinInt32 {
		return 0, false
	}
	offset := lhs
	if off != 0 {
		switch m.inOp & opsMask {
		case opAnd:
			offset = lhs & off
		case opOr:
			offset = lhs | off
		case opXor:
			offset = lhs ^ off
		case opAdd:
			offset = lhs + off
		case opMinus:
			offset = lhs - off
		case opMultiply:
			offset = lhs * off
		case opDivide:
			offset = lhs / off
		case opModulo:
			offset = lhs % off
		default:
		}
	}
	if m.inOp&opInverse != 0 {
		offset = ^offset
	}
	if offset >= math.MaxUint32 {
		return 0, false
	}
	return low32(bitsOfInt64(offset)), true
}

// moffset computes the offset continuation lines are relative to after
// this line matched, into *op. False is the reference's -1 or 0.
func (s *scan) moffset(m *record, f *frame, op *int32) bool {
	invariant.Check(f.n >= 0, "window length non-negative")
	invariant.Check(op != nil, "offset result has a target")
	var o int64
	switch {
	case m.typ == tByte:
		o = int64(s.offset) + 1
	case isWidth2(m.typ):
		o = int64(s.offset) + 2
	case isWidth4(m.typ):
		o = int64(s.offset) + 4
	case isWidth8(m.typ):
		o = int64(s.offset) + 8
	case m.typ == tString || m.typ == tPString || m.typ == tBeString16 || m.typ == tLeString16 || m.typ == tOctal:
		o = s.stringEnd(m)
	case m.typ == tRegex || m.typ == tSearch:
		o = s.searchEnd(m, f)
	case m.typ == tClear || m.typ == tDefault || m.typ == tIndirect || m.typ == tOffset || m.typ == tUse:
		o = int64(s.offset)
	case m.typ == tDer:
		v, ok := s.derOffs(m, f)
		if !ok || int64(v) > int64(f.n) {
			*op = 0
			return false
		}
		o = int64(v)
	case m.typ == tBeGUID || m.typ == tLeGUID || m.typ == tGUID:
		o = int64(s.offset) + 16
	default:
		o = 0
	}
	o32 := wrapInt32(o)
	if o32 < 0 || int64(o32) > int64(f.n) {
		return false
	}
	*op = o32
	return true
}

// searchEnd is moffset's regex and search cases: the end of the match,
// or its start with the /s modifier.
func (s *scan) searchEnd(m *record, f *frame) int64 {
	invariant.Check(m.typ == tRegex || m.typ == tSearch, "search line")
	vlen := int(m.vallen)
	if m.typ == tRegex {
		vlen = s.search.rmLen
	}
	if m.strFlags()&regexOffsetStart != 0 {
		vlen = 0
	}
	return int64(s.search.offset) + int64(vlen) - int64(f.o)
}

// stringEnd is moffset's string case: the end of the matched string. For
// a relation other than = and !, the file's string is truncated at the
// first CR or LF when the rule's own string is empty, as the reference
// does in place.
func (s *scan) stringEnd(m *record) int64 {
	invariant.Check(isString(m.typ) || m.typ == tBeString16 || m.typ == tLeString16, "string line")
	if m.reln == '=' || m.reln == '!' {
		return int64(s.offset) + int64(m.vallen)
	}
	if m.value[0] == 0 {
		truncateAtNewline(s.value[:])
	}
	n := 0
	for ; n < maxString && s.value[n] != 0; n++ {
	}
	o := int64(s.offset) + int64(n)
	if m.typ == tPString {
		o += int64(pstringLengthSize(m.strFlags()))
	}
	return o
}

// truncateAtNewline is the reference's in-place strcspn(s, "\r\n") cut.
func truncateAtNewline(v []byte) {
	for i := 0; i < len(v) && v[i] != 0; i++ {
		if v[i] == '\r' || v[i] == '\n' {
			v[i] = 0
			return
		}
	}
}

func isWidth2(t fileType) bool {
	switch t {
	case tShort, tBeShort, tLeShort, tMSDOSDate, tLeMSDOSDate, tBeMSDOSDate,
		tMSDOSTime, tLeMSDOSTime, tBeMSDOSTime:
		return true
	default:
		return false
	}
}

func isWidth4(t fileType) bool {
	switch t {
	case tLong, tBeLong, tLeLong, tMeLong, tDate, tBeDate, tLeDate, tMeDate,
		tLDate, tBeLDate, tLeLDate, tMeLDate, tFloat, tBeFloat, tLeFloat:
		return true
	default:
		return false
	}
}

func isWidth8(t fileType) bool {
	switch t {
	case tQuad, tBeQuad, tLeQuad, tQDate, tBeQDate, tLeQDate, tQLDate, tBeQLDate,
		tLeQLDate, tQWDate, tBeQWDate, tLeQWDate, tDouble, tBeDouble, tLeDouble:
		return true
	default:
		return false
	}
}

// pushUse starts evaluating the named entry as a child frame (mget's
// FILE_USE case up to the recursive match call).
func (s *scan) pushUse(m *record, f *frame, offset uint32) (int, bool) {
	invariant.Check(m.typ == tUse, "use line")
	name := m.valueBytes()
	flip := f.flip
	if len(name) > 0 && name[0] == '^' {
		name = name[1:]
		flip = !flip
	}
	target, ok := s.db.names[string(name)]
	if !invariant.Check(ok, "use names a compiled name entry") {
		s.truncate(TruncInvariant)
		return 0, false
	}
	child := frame{
		first: target.first, count: target.count, kind: kindUse,
		base: f.base, n: f.n, o: offset + f.o, mode: f.mode, text: f.text, flip: flip,
		returnval: f.returnval, savedLevels: s.levels, savedNeedSep: s.needSeparator,
		savedOffset: offset, savedEoffset: s.eoffset,
	}
	if m.flag&flagNoSpace != 0 {
		s.needSeparator = false
	}
	if !s.pushFrame(&child) {
		s.needSeparator = child.savedNeedSep
		return 0, false
	}
	s.names++
	return 0, true
}

// finishUse completes the parent's mget after a "use" child returned rv.
func (s *scan) finishUse(parent, child *frame, rv bool) int {
	invariant.Check(child.kind == kindUse, "finishing a use frame")
	invariant.Check(s.names > 0, "name count positive")
	nfound := child.foundMatch
	for i := range s.value {
		s.value[i] = 0
	}
	if nfound {
		s.value[0] = 1
	}
	s.names--
	parent.foundMatch = parent.foundMatch || nfound
	parent.returnval = child.returnval
	s.levels = child.savedLevels
	if !rv {
		s.needSeparator = child.savedNeedSep
	}
	s.offset, s.eoffset = child.savedOffset, child.savedEoffset
	if rv || parent.foundMatch {
		return 1
	}
	return 0
}

// pushIndirect starts evaluating the whole binary set over the window
// from offset as a child frame (mget's FILE_INDIRECT case).
func (s *scan) pushIndirect(m *record, f *frame, offset uint32) (int, bool) {
	invariant.Check(m.typ == tIndirect, "indirect line")
	if m.strFlags()&indirectRelative != 0 {
		offset += f.o
	}
	if offset == 0 || int64(f.n) < int64(offset) {
		return 0, false
	}
	child := frame{
		first: s.db.maps[0].first, count: s.db.maps[0].count, kind: kindIndirect, mapIdx: 0,
		base: f.base + int(offset), n: f.n - int(offset), o: 0,
		mode: flagBinTest, text: f.text, flip: false,
		savedOutLen: s.outLen, savedNseps: s.nseps, childOffset: offset,
	}
	if !s.pushFrame(&child) {
		return 0, false
	}
	s.indir++
	return 0, true
}

// finishIndirect completes the parent's mget after an "indirect" child:
// its output is re-emitted after the line's own description.
func (s *scan) finishIndirect(parent, child *frame, rv bool) int {
	invariant.Check(child.kind == kindIndirect, "finishing an indirect frame")
	invariant.Check(child.savedOutLen <= s.outLen, "child output follows the saved length")
	childOut := s.out[child.savedOutLen:s.outLen]
	tmp := s.rxScratch(maxOutput) // free here: no regex runs between push and pop
	n := copy(tmp, childOut)
	childSeps := s.nseps
	s.outLen, s.nseps = child.savedOutLen, child.savedNseps
	if !rv {
		return 0
	}
	m := s.line(parent, parent.idx)
	if s.mode == modeDesc {
		s.printfNum(m.descString(), uint64(child.childOffset), false, 32)
	}
	s.moveSeps(child.savedNseps, childSeps, s.outLen-child.savedOutLen)
	s.write(tmp[:n])
	s.dropSepsPast()
	return 1
}

// moveSeps reinstates the separators an indirect child printed, now that
// its output is re-emitted delta bytes later.
func (s *scan) moveSeps(from, to, delta int) {
	invariant.Check(from >= 0 && from <= to && to <= maxSeps, "separator range within cap")
	invariant.Check(delta >= 0, "the parent's text only moves the child's output later")
	for i := from; i < to; i++ {
		s.seps[i] = smallInt32(int(s.seps[i]) + delta)
	}
	s.nseps = to
}

// dropSepsPast forgets separators that truncation cut off the output.
func (s *scan) dropSepsPast() {
	invariant.Check(s.nseps >= 0 && s.nseps <= maxSeps, "separator count within cap")
	for range s.nseps {
		if int(s.seps[s.nseps-1])+len(sepText) <= s.outLen {
			return
		}
		s.nseps--
	}
}
