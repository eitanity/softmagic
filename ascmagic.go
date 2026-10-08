// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from file_ascmagic and file_ascmagic_with_encoding in
// ascmagic.c, file 5.48, Copyright (c) Ian F. Darwin 1986-1995 (see
// COPYING).

package softmagic

import "github.com/eitanity/softmagic/internal/invariant"

// textStats is what the line scan of the text phase establishes.
type textStats struct {
	crlf, lf, cr, nel int
	longLine          int
	escapes           bool
	backspace         bool
}

// trimNuls is ascmagic.c's trim_nuls: drop trailing NULs, keeping one byte.
func trimNuls(buf []byte) int {
	n := len(buf)
	for ; n > 1 && buf[n-1] == 0; n-- {
	}
	invariant.Check(n <= len(buf) && (n >= 1 || len(buf) == 0), "trim keeps at least one byte")
	return n
}

// textPhase is file_ascmagic: classify the NUL-trimmed window, run the
// text rules over its UTF-8 re-encoding, and describe the text. It
// returns whether anything was printed. looksText is the classification
// of the untrimmed window, passed to the matcher as the reference does.
func (s *scan) textPhase(looksText bool, e encoding) bool {
	invariant.Check(s.savedBuf == nil, "text phase starts on the input window")
	invariant.Check(e.n <= len(s.buf), "classified length within the input")
	n := trimNuls(s.buf)
	if n&1 != 0 && len(s.buf)&1 == 0 {
		n++ // keep the last UTF-16 unit whole
	}
	if n <= 1 || s.excluded(CheckText) {
		return false
	}
	win := s.buf[:n]
	if n != len(s.buf) || s.excluded(CheckEncoding) {
		e = classify(win, s.lim.encoding) // file_ascmagic classifies for itself
	}
	if !e.isText() || trimNuls(win) <= 1 {
		return false // file_ascmagic_with_encoding trims again and gives up at one byte
	}
	utf8Len := s.encodeWindow(win, e)
	invariant.Check(utf8Len <= len(s.utf8), "re-encoding fits the scratch")
	softFound := false
	if utf8Len > 0 {
		softFound = s.softmagic(s.utf8[:utf8Len], flagTextTest, looksText)
		if softFound {
			s.needSeparator = true
		}
	}
	if s.mode != modeDesc {
		return softFound && s.outputOrAnnotated()
	}
	st := scanLines(win, e)
	s.describeText(e, st)
	return true
}

// outputOrAnnotated reports whether the annotation modes found their
// annotation.
func (s *scan) outputOrAnnotated() bool {
	switch s.mode {
	case modeMime:
		return s.mimeRec >= 0
	case modeApple:
		return s.appleRec >= 0
	default:
		return s.extRec >= 0
	}
}

// encodeWindow re-encodes the decoded characters as UTF-8 into the
// scratch buffer and returns the length, 0 when a character cannot be
// encoded (the reference then skips the text rules).
func (s *scan) encodeWindow(win []byte, e encoding) int {
	invariant.Check(e.n <= len(win), "classified length within the window")
	d := newTextDecoder(win, e)
	dst := s.utf8Scratch(6 * e.n)
	n := 0
	for chars := 0; chars < len(win); chars++ { // a character takes at least one byte
		c, ok := d.next()
		if !ok {
			break
		}
		k := encodeUTF8(dst[n:], c)
		if k == 0 {
			return 0
		}
		n += k
	}
	return n
}

// scanLines is the line-terminator and long-line scan over the decoded
// characters.
func scanLines(win []byte, e encoding) textStats {
	invariant.Check(e.n <= len(win), "classified length within the window")
	var st textStats
	d := newTextDecoder(win, e)
	seenCR := false
	lastLineEnd := int64(-1)
	for i := int64(0); i < int64(len(win)); i++ { // a character takes at least one byte
		c, ok := d.next()
		if !ok {
			break
		}
		seenCR = st.noteChar(c, i, seenCR, &lastLineEnd)
		if i > lastLineEnd+maxLineLen && int(i-lastLineEnd) > st.longLine {
			st.longLine = int(i - lastLineEnd)
		}
	}
	if seenCR && st.cr == 0 && st.crlf == 0 {
		st.cr++
	}
	return st
}

// noteChar counts one character's terminator and control-character
// contribution and returns whether it was a CR.
func (st *textStats) noteChar(c uint32, i int64, seenCR bool, lastLineEnd *int64) bool {
	invariant.Check(i >= 0, "character index non-negative")
	switch {
	case c == '\n':
		if seenCR {
			st.crlf++
		} else {
			st.lf++
		}
		*lastLineEnd = i
	case seenCR:
		st.cr++
	}
	switch c {
	case '\r':
		*lastLineEnd = i
	case 0x85:
		st.nel++
		*lastLineEnd = i
	case 0x1b:
		st.escapes = true
	case '\b':
		st.backspace = true
	}
	return c == '\r'
}

// describeText prints the encoding, the text type and the line details,
// after rewriting a rule description that ended in " text".
func (s *scan) describeText(e encoding, st textStats) {
	invariant.Check(s.outLen <= maxOutput, "output length within cap")
	invariant.Check(e.isText(), "describing text")
	executable := false
	if s.outLen > 0 {
		switch {
		case s.replaceSuffix(" text", ", "):
		case s.replaceSuffix(" text executable", ", "):
			executable = true
		default:
			s.writeString(", ")
		}
	}
	s.writeString(e.code())
	s.writeString(" text")
	if executable {
		s.writeString(" executable")
	}
	if st.longLine > 0 {
		s.writeString(", with very long lines (")
		s.printfNum("%u", uint64(st.longLine), false, 64)
		s.writeString(")")
	}
	s.describeTerminators(st)
	if st.escapes {
		s.writeString(", with escape sequences")
	}
	if st.backspace {
		s.writeString(", with overstriking")
	}
}

// replaceSuffix is file_replace for an end-anchored literal pattern.
func (s *scan) replaceSuffix(suffix, rep string) bool {
	invariant.Check(len(suffix) > 0, "suffix given")
	if s.outLen < len(suffix) || string(s.out[s.outLen-len(suffix):s.outLen]) != suffix {
		return false
	}
	s.outLen -= len(suffix)
	s.writeString(rep)
	return true
}

// describeTerminators reports line terminators other than LF, or none.
func (s *scan) describeTerminators(st textStats) {
	invariant.Check(st.crlf >= 0 && st.cr >= 0 && st.lf >= 0 && st.nel >= 0, "counts non-negative")
	none := st.crlf == 0 && st.cr == 0 && st.nel == 0 && st.lf == 0
	if !none && st.crlf == 0 && st.cr == 0 && st.nel == 0 {
		return
	}
	s.writeString(", with")
	if none {
		s.writeString(" no")
	} else {
		s.listTerminators(st)
	}
	s.writeString(" line terminators")
}

// listTerminators prints the kinds present, comma-separated as the
// reference does.
func (s *scan) listTerminators(st textStats) {
	invariant.Check(st.crlf+st.cr+st.lf+st.nel > 0, "a terminator kind is present")
	kinds := [4]int{st.crlf, st.cr, st.lf, st.nel}
	names := [4]string{" CRLF", " CR", " LF", " NEL"}
	for k := 0; k < 4; k++ {
		if kinds[k] == 0 {
			continue
		}
		s.writeString(names[k])
		for later := k + 1; later < 4; later++ {
			if kinds[later] != 0 {
				s.writeString(",")
				break
			}
		}
	}
}
