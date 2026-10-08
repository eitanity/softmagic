// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// The continue runs follow file_buffer in funcs.c and
// file_ascmagic_with_encoding in ascmagic.c, file 5.48, Copyright (c) Ian F.
// Darwin 1986-1995 (see COPYING), under MAGIC_CONTINUE (file -k): each check
// that answers is followed by a separator and the next check still runs.

package softmagic

import "github.com/eitanity/softmagic/internal/invariant"

// identifyContinue runs file_buffer under MAGIC_CONTINUE once per output
// mode, as the reference does: each mode is a run of its own, so each list
// is what file -b -k prints in that mode. charset ends the encoding run,
// as file_buffer appends it after trimming.
func (s *scan) identifyContinue(charset string) Continued {
	invariant.Check(s.wantCont, "continue requested")
	invariant.Check(s.savedBuf == nil && s.nframes == 0, "continue runs start on the input window")
	var e encoding
	if len(s.buf) > 1 {
		e = classify(s.buf)
	}
	c := Continued{
		Descriptions: s.continueRun(modeDesc, e),
		MIMEs:        s.continueRun(modeMime, e),
		Encodings:    s.continueRun(modeEnc, e),
		Extensions:   s.continueRun(modeExt, e),
		Apple:        s.continueRun(modeApple, e),
	}
	c.Encodings[len(c.Encodings)-1] += charset
	s.cont = false
	return c
}

// continueRun is one file_buffer under MAGIC_CONTINUE in one mode.
func (s *scan) continueRun(mode matchMode, e encoding) []string {
	invariant.Check(mode <= modeEnc, "a known mode")
	s.mode, s.cont = mode, true
	s.outLen, s.nseps = 0, 0
	s.printedSomething, s.needSeparator, s.firstline = false, false, true
	s.nframes = 0
	s.mimeRec, s.extRec, s.appleRec = -1, -1, -1
	// file_buffer goes to its default when the last check it ran, the text
	// phase, found nothing: so a binary answer is followed by "data".
	if len(s.buf) < 2 || !s.continuePhases(e) {
		s.continueDefault()
	}
	s.trimSep()
	return s.answers()
}

// continuePhases runs the checks after the empty and one-byte cases and
// reports whether the text phase, the last of them, answered.
func (s *scan) continuePhases(e encoding) bool {
	invariant.Check(len(s.buf) >= 2, "checks run on two or more bytes")
	invariant.Check(s.cont, "continue run")
	s.continueBuiltins(e)
	elfText := ""
	if s.mode == modeDesc {
		elfText = s.tryELF() // printed only after a rule answered, and only as a description
	}
	if s.softmagic(s.buf, flagBinTest, e.isText()) {
		s.writeString(elfText)
		s.writeSep() // checkdone
	}
	return s.continueText(e.isText(), e)
}

// continueBuiltins runs the detectors in file_buffer's order, each answer
// followed by a separator. They answer nothing in the extension and Apple
// modes, and print nothing (though they still answer) for the encoding.
func (s *scan) continueBuiltins(e encoding) {
	invariant.Check(len(s.buf) >= 2, "detectors run on two or more bytes")
	if s.mode == modeExt || s.mode == modeApple {
		return
	}
	s.continueBuiltin(detectTar(s.buf))
	s.continueBuiltin(detectJSON(s.buf))
	s.continueBuiltin(detectCSV(s.buf, e))
	s.continueBuiltin(detectSIMH(s.buf))
	s.continueBuiltin(s.detectCDF())
}

// continueBuiltin prints one detector's answer in the run's mode.
func (s *scan) continueBuiltin(r builtinResult) {
	invariant.Check(s.cont, "continue run")
	invariant.Check(!r.hit || (r.desc != "" && r.mime != ""), "an answer has a description and a MIME type")
	if !r.hit {
		return
	}
	switch s.mode {
	case modeDesc:
		s.writeString(r.desc)
	case modeMime:
		s.writeString(r.mime)
	default:
	}
	s.writeSep() // checkdone
}

// continueText is file_ascmagic under MAGIC_CONTINUE: the text rules over
// the re-encoded window, then "text/plain" or the text description. Unlike
// the first-match path it runs after earlier answers, and in the MIME mode
// it adds its own answer after them.
func (s *scan) continueText(looksText bool, e encoding) bool {
	invariant.Check(s.savedBuf == nil, "text phase starts on the input window")
	invariant.Check(e.n <= len(s.buf), "classified length within the input")
	win, te, ok := s.textWindow(e)
	if !ok {
		return false
	}
	utf8Len := s.encodeWindow(win, te)
	if utf8Len == 0 {
		return false // a character that cannot be encoded: the reference gives up
	}
	softFound := s.softmagic(s.utf8[:utf8Len], flagTextTest, looksText)
	switch s.mode {
	case modeExt, modeApple:
		return softFound
	case modeMime:
		if s.outLen > 0 && softFound {
			s.writeSep()
		}
		s.writeString("text/plain")
	case modeDesc:
		s.describeText(te, scanLines(win, te))
	default:
	}
	return true
}

// textWindow is file_ascmagic's preparation: the NUL-trimmed window and its
// classification, and whether it is text at all.
func (s *scan) textWindow(e encoding) ([]byte, encoding, bool) {
	invariant.Check(e.n <= len(s.buf), "classified length within the input")
	n := trimNuls(s.buf)
	if n&1 != 0 && len(s.buf)&1 == 0 {
		n++ // keep the last UTF-16 unit whole
	}
	if n <= 1 {
		return nil, e, false
	}
	win := s.buf[:n]
	if n != len(s.buf) {
		e = classify(win)
	}
	return win, e, e.isText()
}

// continueDefault is file_default, then file_buffer's default description.
func (s *scan) continueDefault() {
	invariant.Check(s.cont, "continue run")
	invariant.Check(s.outLen <= maxOutput, "output length within cap")
	switch s.mode {
	case modeMime:
		if len(s.buf) == 0 {
			s.writeString("application/x-empty")
		} else {
			s.writeString("application/octet-stream")
		}
	case modeEnc:
	case modeApple:
		s.writeString("UNKNUNKN")
	case modeExt:
		s.writeString("???")
	default:
		s.writeString(defaultDescription(len(s.buf)))
	}
}

// defaultDescription is file_buffer's def for an input of n bytes.
func defaultDescription(n int) string {
	switch n {
	case 0:
		return "empty"
	case 1:
		return "very short file (no magic)"
	default:
		return "data"
	}
}

// answers splits the run's output at the separators it printed.
func (s *scan) answers() []string {
	invariant.Check(s.nseps >= 0 && s.nseps <= maxSeps, "separator count within cap")
	invariant.Check(s.outLen <= maxOutput, "output length within cap")
	out := make([]string, 0, s.nseps+1)
	start := 0
	for i := range s.nseps {
		p := int(s.seps[i])
		out = append(out, string(s.out[start:p]))
		start = p + len(sepText)
	}
	return append(out, string(s.out[start:s.outLen]))
}
