// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// The phase order follows file_buffer in funcs.c, file 5.48, Copyright (c)
// Ian F. Darwin 1986-1995 (see COPYING). The built-in detectors the
// reference runs before the rules (tar, JSON, CSV, SIMH, CDF, ELF) run
// first, as there.

package softmagic

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/eitanity/softmagic/internal/invariant"
)

// Identify returns what file(1) would print for data, with the default
// options and no deadline. It is safe to call from any number of
// goroutines on one Database.
func (db *Database) Identify(data []byte) Result {
	return db.IdentifyWith(context.Background(), data, Options{})
}

// IdentifyWith is Identify with a context, whose deadline or cancellation
// stops the match with Truncated "time", and explicit options.
func (db *Database) IdentifyWith(ctx context.Context, data []byte, o Options) Result {
	return db.identify(ctx, data, o, true)
}

// IdentifyPrefix identifies from a prefix of the input: Examined.Complete
// is false, and NeedMore reports whether more bytes could change the
// answer.
func (db *Database) IdentifyPrefix(ctx context.Context, prefix []byte, o Options) Result {
	return db.identify(ctx, prefix, o, false)
}

// IdentifyAt identifies an input of the given size that r reads: the
// first MaxBytes are consulted as Identify would, and the ELF built-in may
// read headers beyond them, as file(1) does through its file descriptor.
// Examined.Bytes counts only the window.
func (db *Database) IdentifyAt(ctx context.Context, r io.ReaderAt, size int64, o Options) Result { // options
	if !invariant.Check(db != nil && db.pool != nil, "identify on a compiled database") || r == nil || size < 0 {
		return invariantResult(o)
	}
	maxBytes := o.maxBytes()
	n := size // readLength
	if n > int64(maxBytes) {
		n = int64(maxBytes)
	}
	s := db.pool.get(db, ctx, nil, o) // scanState
	if cap(s.inbuf) < int(n) {
		s.inbuf = make([]byte, n)
	}
	got, err := r.ReadAt(s.inbuf[:n], 0)
	switch {
	case err == nil || got >= int(n):
	case errors.Is(err, io.EOF):
		// The input is shorter than size said (a file cut short after its
		// stat): the reference's read returns the bytes there are, and it
		// identifies those.
		n = int64(got)
	default:
		db.pool.put(s)
		return invariantResult(o)
	}
	s.buf, s.src, s.srcSize = s.inbuf[:n], r, size
	res := s.identify()
	res.Examined.Complete = true
	db.pool.put(s)
	return res
}

// invariantResult is the answer when the call itself was malformed or the
// input could not be read: the default, in every list continue mode asked
// for, so that a blank is never an answer there either.
func invariantResult(o Options) Result {
	r := Result{Description: "data", MIME: "application/octet-stream", Charset: "binary", Phase: PhaseDefault, // fallback
		Examined: Examined{Truncated: TruncInvariant, ImplementsFile: ImplementsFile}}
	if o.Continue {
		r.Continued = Continued{Descriptions: []string{"data"}, MIMEs: []string{"application/octet-stream"},
			Encodings: []string{"binary"}, Extensions: []string{"???"}, Apple: []string{"UNKNUNKN"}}
	}
	return r
}

func (db *Database) identify(ctx context.Context, data []byte, o Options, complete bool) Result { // options
	if !invariant.Check(db != nil && db.pool != nil, "identify on a compiled database") {
		return invariantResult(o)
	}
	maxBytes := o.maxBytes()
	if len(data) > maxBytes {
		data = data[:maxBytes]
	}
	invariant.Check(maxBytes >= 0 && len(data) <= maxBytes, "window within MaxBytes")
	s := db.pool.get(db, ctx, data, o) // scanState
	r := s.identify()                  // result
	r.Examined.Complete = complete
	if !complete {
		r.Examined.NeedMore = s.oobHit || s.maxRead >= len(data)
	}
	db.pool.put(s)
	return r
}

// identifyIndependent is Identify with every answer from a run of its own
// output mode: the path a hard limit falls back to, for tests to compare
// with the first-match path.
func (db *Database) identifyIndependent(data []byte) Result {
	r := db.Identify(data)
	s := db.pool.get(db, context.Background(), data, Options{})
	r = s.independentResult(r)
	db.pool.put(s)
	return r
}

// identify is file_buffer: the phases in the reference's order, then the
// MIME and extension passes where the description pass did not settle
// them.
func (s *scan) identify() Result {
	invariant.Check(s.nframes == 0, "identify starts with no frames")
	invariant.Check(s.outLen == 0, "identify starts with no output")
	r := Result{Examined: Examined{DatabaseHash: s.db.hash, ImplementsFile: ImplementsFile}, Phase: PhaseDefault} // result
	switch len(s.buf) {
	case 0:
		return s.finishResult(r, "empty", "application/x-empty", "binary")
	case 1:
		return s.finishResult(r, "very short file (no magic)", "application/octet-stream", "binary")
	default:
	}
	e := s.classifyMain() // encoding
	s.noteRead(e.n)
	charset := e.charset()
	if bi := s.builtins(e); bi.hit {
		s.noteRead(len(s.buf))
		r.Extensions = s.extResultOf(s.annotPipeline(e, modeExt))
		r.Apple = s.appleResultOf(s.annotPipeline(e, modeApple))
		r.Phase = PhaseBuiltin
		return s.finishResult(r, bi.desc, bi.mime, charset)
	}
	elfText := s.tryELF()
	found := s.softmagic(s.buf, flagBinTest, e.isText())
	if found {
		s.writeString(elfText) // appended after the rules' text, as file_buffer does
	}
	textFound := false
	if !found {
		textFound = s.textPhase(e.isText(), e)
	}
	desc := "data"
	switch {
	case found:
		desc, r.Phase = string(s.output()), PhaseMagic
	case textFound:
		desc, r.Phase = string(s.output()), PhaseText
	}
	if desc == "" {
		// The reference reports a match with no text (an "indirect" line
		// whose sub-match printed nothing) as an empty line; this port
		// never returns a blank answer and makes that "data" instead. A deliberate divergence.
		desc = "data"
	}
	r.Strength = s.winnerStrength()
	r.Rules = s.ruleIDs()
	mime := s.mimeResult(found, textFound, e)
	r.Extensions = s.extResult(found, textFound, e)
	r.Apple = s.appleResult(found, textFound, e)
	return s.finishResult(r, desc, mime, charset)
}

// finishResult fills the fields every answer carries.
func (s *scan) finishResult(r Result, desc, mime, charset string) Result { // result
	invariant.Check(desc != "", "a blank is never an answer")
	invariant.Check(mime != "" && charset != "", "MIME and charset always set")
	r.Description, r.MIME, r.Charset = desc, mime, charset
	if s.abort != "" {
		r = s.independentResult(r) // a hard limit stopped the first-match run
	}
	if s.wantCont {
		r.Continued = s.identifyContinue(charset)
	}
	r.Examined.Bytes = s.maxRead
	r.Examined.Truncated = s.truncated
	return r
}

// softmagic is file_softmagic: run the set-0 entries of the given class
// over win and report whether anything was printed or annotated.
func (s *scan) softmagic(win []byte, mode uint16, text bool) bool {
	invariant.Check(mode == flagBinTest || mode == flagTextTest, "mode is one class")
	if s.excluded(CheckSoft) {
		return false // -e soft: neither the binary nor the text rules run
	}
	s.beginWindow(win)
	s.winID = windowBin
	if mode == flagTextTest {
		s.winID = windowText
	}
	rv := false // anyMatched
	if s.cont {
		// file_softmagic's locals, fresh for each call.
		s.printedSomething, s.needSeparator, s.firstline = false, false, true
	}
	s.indir, s.names = 0, 0    // file_softmagic's counters, also fresh for each call
	for i := range s.db.maps { // file_softmagic: one match() per map, in order
		s.nframes = 0
		s.levels = [maxLevels]levelInfo{}
		m := &s.db.maps[i]
		root := frame{first: m.first, count: m.count, kind: kindRoot, base: 0, n: len(win),
			mode: mode, text: text, mapIdx: i}
		ok := s.pushFrame(&root)
		invariant.Check(ok, "root frame fits")
		found := s.run()
		rv = rv || found
		if s.abort != "" || (found && !s.cont) {
			break // under MAGIC_CONTINUE every map answers; an error ends the call
		}
	}
	s.endWindow()
	return rv
}

// beginWindow makes win the buffer frames index into: the input itself for
// the binary phase, or the UTF-8 re-encoding for the text phase.
func (s *scan) beginWindow(win []byte) {
	invariant.Check(s.savedBuf == nil, "windows do not nest")
	s.savedBuf = s.buf
	s.buf = win
}

// endWindow restores the input buffer; bytes consulted are clamped to it.
func (s *scan) endWindow() {
	invariant.Check(s.savedBuf != nil, "window was begun")
	s.buf = s.savedBuf
	s.savedBuf = nil
	s.winID = 0
	if s.maxRead > len(s.buf) {
		s.maxRead = len(s.buf)
	}
}

// mimeResult reproduces `file -i`: the first MIME annotation on the
// winning path; else the text phase in MIME mode; else the default.
func (s *scan) mimeResult(found, textFound bool, e encoding) string { // encoding
	invariant.Check(int(s.mimeRec) < len(s.db.meta), "MIME record within the database")
	if s.mimeRec >= 0 {
		return varexpand(s.db.mimeOf(s.mimeRec), s.execBit)
	}
	if !found && !textFound {
		return "application/octet-stream"
	}
	// A binary match without a MIME annotation fails the MIME run of the
	// binary phase, so the reference falls through to the text phase.
	s.mode = modeMime
	s.resetOutput()
	if s.textPhase(e.isText(), e) && s.mimeRec >= 0 {
		return varexpand(s.db.mimeOf(s.mimeRec), s.execBit)
	}
	if s.textPhaseWouldRun(e) {
		return "text/plain"
	}
	return "application/octet-stream"
}

// textPhaseWouldRun says whether the text phase reaches its "text/plain"
// line: the trimmed window is text.
func (s *scan) textPhaseWouldRun(e encoding) bool { // encoding
	if s.excluded(CheckText) {
		return false
	}
	buf := s.buf
	n := trimNuls(buf) // textLength
	if n&1 != 0 && len(buf)&1 == 0 {
		n++
	}
	if n <= 1 {
		return false
	}
	if n != len(buf) || s.excluded(CheckEncoding) {
		e = classify(buf[:n], s.lim.encoding)
	}
	return e.isText() && trimNuls(buf[:n]) > 1 // the second trim, as in textPhase
}

// extResult reproduces `file --extension`: the first extension annotation
// on the winning path, else the text phase's, else none.
func (s *scan) extResult(found, textFound bool, e encoding) []string {
	invariant.Check(int(s.extRec) < len(s.db.meta), "extension record within the database")
	if s.extRec < 0 && (found || textFound) {
		s.mode = modeExt
		s.resetOutput()
		s.textPhase(e.isText(), e)
	}
	return s.extResultOf(s.extRec)
}

// annotPipeline is `file --extension` or `file --apple` when a built-in
// detector answered the description: the detectors do not run in those
// modes, so the rules do, binary phase then text phase, until an
// annotation is met. It returns the annotated record, -1 for none.
func (s *scan) annotPipeline(e encoding, mode matchMode) int32 { // encoding
	invariant.Check(mode == modeExt || mode == modeApple, "annotation mode")
	s.mode = mode
	s.resetOutput()
	s.softmagic(s.buf, flagBinTest, e.isText())
	if s.annotRec() < 0 {
		s.textPhase(e.isText(), e)
	}
	return s.annotRec()
}

// annotRec is the record the current annotation mode collects.
func (s *scan) annotRec() int32 {
	if s.mode == modeApple {
		return s.appleRec
	}
	return s.extRec
}

// extResultOf is Result.Extensions for an annotated record.
func (s *scan) extResultOf(rec int32) []string {
	if rec < 0 {
		return nil
	}
	return strings.Split(s.db.extOf(rec), "/")
}

// appleResultOf is Result.Apple for an annotated record.
func (s *scan) appleResultOf(rec int32) string {
	if rec < 0 {
		return ""
	}
	return cString(s.db.recs[rec].apple)
}

// appleResult reproduces `file --apple`: the first !:apple on the winning
// path, else the text phase's, else none.
func (s *scan) appleResult(found, textFound bool, e encoding) string {
	if s.appleRec < 0 && (found || textFound) {
		s.mode = modeApple
		s.resetOutput()
		s.textPhase(e.isText(), e)
	}
	return s.appleResultOf(s.appleRec)
}

// resetOutput clears the printed text before an annotation pass.
func (s *scan) resetOutput() {
	invariant.Check(s.mode != modeDesc, "output reset only for annotation passes")
	s.outLen = 0
	s.printedSomething, s.needSeparator = false, false
	s.nframes = 0
}

// winnerStrength is the strength of the entry whose text was printed
// first, 0 when none.
func (s *scan) winnerStrength() int {
	invariant.Check(s.nrules <= maxRules, "rule count within cap")
	if s.nrules == 0 {
		return 0
	}
	rec := s.rules[0]
	for i := range s.db.maps {
		for _, set := range s.db.maps[i].sets {
			for _, e := range set {
				if rec >= e.first && rec < e.first+e.count {
					return int(e.strength)
				}
			}
		}
	}
	return 0
}

// ruleIDs is Result.Rules.
func (s *scan) ruleIDs() []RuleID {
	invariant.Check(s.nrules <= maxRules, "rule count within cap")
	if s.nrules == 0 {
		return nil
	}
	out := make([]RuleID, s.nrules)
	for i := 0; i < s.nrules; i++ {
		out[i] = s.db.ruleID(s.rules[i])
	}
	return out
}
