// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// The runs here follow file_buffer in funcs.c and
// file_ascmagic_with_encoding in ascmagic.c, file 5.48, Copyright (c) Ian F.
// Darwin 1986-1995 (see COPYING): one call of the reference in one output
// mode. Under MAGIC_CONTINUE (file -k) each check that answers is followed
// by a separator and the next check still runs; without it the first check
// that answers ends the run. A hard limit (Options.Limits) ends it with the
// reference's error.

package softmagic

import (
	"strings"

	"github.com/eitanity/softmagic/internal/invariant"
)

// runResult is one file_buffer run: its answers, or, when a hard limit
// stopped it, libmagic's error text and what had been printed before it.
type runResult struct {
	partial string
	answers []string
	failure Failure
}

// identifyContinue runs file_buffer under MAGIC_CONTINUE once per output
// mode, as the reference does: each mode is a run of its own, so each list
// is what file -b -k prints in that mode. charset ends the encoding run,
// as file_buffer appends it after trimming.
func (s *scan) identifyContinue(charset string) Continued {
	invariant.Check(s.wantCont, "continue requested")
	invariant.Check(s.savedBuf == nil && s.nframes == 0, "continue runs start on the input window")
	e := s.runEncoding()
	desc := s.bufferRun(modeDesc, e, true)
	mime := s.bufferRun(modeMime, e, true)
	enc := s.bufferRun(modeEnc, e, true)
	ext := s.bufferRun(modeExt, e, true)
	apple := s.bufferRun(modeApple, e, true)
	c := Continued{ // continued
		Descriptions: desc.answers, MIMEs: mime.answers, Encodings: enc.answers,
		Extensions: ext.answers, Apple: apple.answers,
		Failures: Failures{Description: desc.failure, MIME: mime.failure, Encoding: enc.failure,
			Extension: ext.failure, Apple: apple.failure},
	}
	if n := len(c.Encodings); n > 0 {
		c.Encodings[n-1] += charset
	}
	return c
}

// independentResult replaces the first-match answers with one file_buffer
// run per output mode. The first-match path derives the MIME, extension and
// Apple answers from the description run, which is exact while every run
// goes to its end; once a hard limit stops one, each mode stops where the
// reference's own run in that mode would, so each is run.
func (s *scan) independentResult(r Result) Result { // result
	invariant.Check(s.savedBuf == nil, "runs start on the input window")
	invariant.Check(r.Charset != "", "charset already established")
	e := s.runEncoding()
	desc := s.bufferRun(modeDesc, e, false)
	mime := s.bufferRun(modeMime, e, false)
	enc := s.bufferRun(modeEnc, e, false)
	ext := s.bufferRun(modeExt, e, false)
	apple := s.bufferRun(modeApple, e, false)
	r.Failures = Failures{Description: desc.failure, MIME: mime.failure, Encoding: enc.failure,
		Extension: ext.failure, Apple: apple.failure}
	r.Description = firstAnswer(desc, "data")
	r.MIME = firstAnswer(mime, "application/octet-stream")
	r.Extensions = nil
	if x := firstAnswer(ext, "???"); x != "???" {
		r.Extensions = strings.Split(x, "/")
	}
	r.Apple = ""
	if a := firstAnswer(apple, "UNKNUNKN"); a != "UNKNUNKN" {
		r.Apple = a
	}
	return r
}

// firstAnswer is a run's answer, or what it had established before an
// error, or def when that is blank: a blank is never an answer.
func firstAnswer(r runResult, def string) string {
	switch {
	case r.failure.Failed() && r.partial != "":
		return r.partial
	case !r.failure.Failed() && len(r.answers) > 0 && r.answers[0] != "":
		return r.answers[0]
	default:
		return def
	}
}

// runEncoding is the classification the runs share.
func (s *scan) runEncoding() encoding {
	if len(s.buf) < 2 {
		return encoding{kind: encBinary}
	}
	return s.classifyMain()
}

// bufferRun is one file_buffer in one mode, with or without MAGIC_CONTINUE.
func (s *scan) bufferRun(mode matchMode, e encoding, cont bool) runResult { // encoding
	invariant.Check(mode <= modeEnc, "a known mode")
	invariant.Check(s.nframes == 0, "runs start with no frames")
	s.mode, s.cont, s.independent = mode, cont, true
	s.outLen, s.nseps = 0, 0
	s.printedSomething, s.needSeparator, s.firstline = false, false, true
	s.mimeRec, s.extRec, s.appleRec = -1, -1, -1
	s.abort, s.abortPartial = "", ""
	// file_buffer goes to its default when the last check it ran found
	// nothing; under MAGIC_CONTINUE that is usually the text phase, so a
	// binary answer is followed by "data".
	if (len(s.buf) < 2 || !s.bufferPhases(e)) && s.abort == "" {
		s.bufferDefault()
	}
	var r runResult // runResult
	if s.abort != "" {
		r = runResult{failure: Failure{Message: s.abort, Buffer: s.abortBuf, Pushed: s.abortPushed},
			partial: s.abortPartial}
	} else {
		s.trimSep()
		r = runResult{answers: s.answers()}
	}
	s.cont, s.independent, s.abort, s.abortPartial = false, false, "", ""
	s.nframes = 0
	return r
}

// bufferPhases runs the checks after the empty and one-byte cases. It
// reports whether to skip the default: a check answered and ended the run,
// or, under MAGIC_CONTINUE, the last check that ran answered (file_buffer's
// m, which each check sets and a check switched off by Options.Exclude
// leaves alone). An error ends the run at once.
func (s *scan) bufferPhases(e encoding) bool { // encoding
	invariant.Check(len(s.buf) >= 2, "checks run on two or more bytes")
	invariant.Check(s.independent, "a run of one mode")
	m, done := s.bufferBuiltins(e) // matched
	if done {
		return true
	}
	elfText := ""
	if s.mode == modeDesc {
		// In the other modes the reference's ELF reader returns before it
		// reads anything that could fail, and prints nothing.
		elfText = s.tryELF()
		if s.abort != "" {
			return true
		}
	}
	if !s.excluded(CheckSoft) {
		m = s.softmagic(s.buf, flagBinTest, e.isText())
		if s.abort != "" {
			return true
		}
		if m {
			s.writeString(elfText)
			if s.checkdone() {
				return true
			}
		}
	}
	if !s.excluded(CheckText) {
		m = s.bufferText(e.isText(), e)
	}
	return m
}

// checkdone is file_buffer's checkdone: without MAGIC_CONTINUE an answer
// ends the run; with it, a separator and on.
func (s *scan) checkdone() bool {
	invariant.Check(s.independent, "a run of one mode")
	if !s.cont {
		return true
	}
	s.writeSep()
	return false
}

// bufferBuiltins runs the detectors in file_buffer's order and returns
// whether the last one that ran answered, and whether an answer ended the
// run. They answer nothing in the extension and Apple modes, and print
// nothing (though they still answer) for the encoding.
func (s *scan) bufferBuiltins(e encoding) (m, done bool) { // encoding
	invariant.Check(len(s.buf) >= 2, "detectors run on two or more bytes")
	invariant.Check(s.independent, "a run of one mode")
	if s.mode == modeExt || s.mode == modeApple {
		return false, false
	}
	if !s.excluded(CheckTar) {
		if m, done = s.bufferBuiltin(detectTar(s.buf)); done {
			return m, done
		}
	}
	if !s.excluded(CheckJSON) {
		if m, done = s.bufferBuiltin(detectJSON(s.buf)); done {
			return m, done
		}
	}
	if !s.excluded(CheckCSV) {
		if m, done = s.bufferBuiltin(detectCSV(s.buf, e)); done {
			return m, done
		}
	}
	if !s.excluded(CheckSIMH) {
		if m, done = s.bufferBuiltin(detectSIMH(s.buf)); done {
			return m, done
		}
	}
	if !s.excluded(CheckCDF) {
		m, done = s.bufferBuiltin(s.detectCDF())
	}
	return m, done
}

// bufferBuiltin prints one detector's answer in the run's mode and reports
// whether it answered and whether that ended the run.
func (s *scan) bufferBuiltin(r builtinResult) (bool, bool) { // builtin
	invariant.Check(s.independent, "a run of one mode")
	invariant.Check(!r.hit || (r.desc != "" && r.mime != ""), "an answer has a description and a MIME type")
	if !r.hit {
		return false, false
	}
	switch s.mode {
	case modeDesc:
		s.writeString(r.desc)
	case modeMime:
		s.writeString(r.mime)
	default:
	}
	return true, s.checkdone()
}

// bufferText is file_ascmagic in a run of one mode: the text rules over
// the re-encoded window, then "text/plain" or the text description. Under
// MAGIC_CONTINUE it runs after earlier answers, and in the MIME mode it
// adds its own answer after them; without it, a MIME answer from the text
// rules is the answer.
func (s *scan) bufferText(looksText bool, e encoding) bool { // textEncoding
	invariant.Check(s.savedBuf == nil, "text phase starts on the input window")
	invariant.Check(e.n <= len(s.buf), "classified length within the input")
	if s.excluded(CheckText) {
		return false
	}
	win, te, ok := s.textWindow(e) // textEncoding
	if !ok {
		return false
	}
	utf8Len := s.encodeWindow(win, te)
	if utf8Len == 0 {
		return false // a character that cannot be encoded: the reference gives up
	}
	softFound := s.softmagic(s.utf8[:utf8Len], flagTextTest, looksText)
	switch {
	case s.abort != "":
		return true
	case s.mode == modeExt || s.mode == modeApple:
		return softFound
	case s.mode == modeMime:
		if s.outLen > 0 && !s.cont {
			return true
		}
		if s.outLen > 0 && softFound {
			s.writeSep()
		}
		s.writeString("text/plain")
	case s.mode == modeDesc:
		s.describeText(te, scanLines(win, te))
	default:
	}
	return true
}

// textWindow is file_ascmagic's preparation: the NUL-trimmed window and its
// classification, and whether it is text at all.
func (s *scan) textWindow(e encoding) ([]byte, encoding, bool) { // encoding
	invariant.Check(e.n <= len(s.buf), "classified length within the input")
	n := trimNuls(s.buf) // textLength
	if n&1 != 0 && len(s.buf)&1 == 0 {
		n++ // keep the last UTF-16 unit whole
	}
	if n <= 1 {
		return nil, e, false
	}
	win := s.buf[:n]
	if n != len(s.buf) || s.excluded(CheckEncoding) {
		e = classify(win, s.lim.encoding) // file_ascmagic classifies for itself
	}
	// file_ascmagic_with_encoding trims again and gives up at one byte.
	return win, e, e.isText() && trimNuls(win) > 1
}

// bufferDefault is file_default, then file_buffer's default description.
func (s *scan) bufferDefault() {
	invariant.Check(s.independent, "a run of one mode")
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
