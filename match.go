// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from match() in softmagic.c, file 5.48, Copyright (c) Ian F.
// Darwin 1986-1995 (see COPYING), with the reference's recursion through
// mget() for "use" and "indirect" replaced by an explicit frame stack of
// fixed capacity: the module has no recursion, so nesting depth is a
// counter with a constant bound.

package softmagic

import "github.com/eitanity/softmagic/internal/invariant"

type framePhase uint8

const (
	phaseTop  framePhase = iota // f.idx is a top-level line to evaluate
	phaseCont                   // f.idx is a continuation line to evaluate
)

type frameKind uint8

const (
	kindRoot     frameKind = iota
	kindUse                // pushed by a "use" line
	kindIndirect           // pushed by an "indirect" line
)

// frame is one activation of the reference's match(): a window of rule
// lines, a window of input bytes, and the loop state. Frames hold no
// pointers: rule lines and input are referenced by index.
type frame struct {
	first, count int32 // rule lines: db.recs[first:first+count]
	idx          int32 // the line under evaluation, relative to first
	contLevel    int32 // the reference's cont_level
	base, n      int   // input window: s.buf[base:base+n]
	mapIdx       int   // the map whose binary set a root or indirect frame walks
	o            uint32
	mode         uint16
	kind         frameKind
	phase        framePhase
	text, flip   bool
	returnval    bool
	foundMatch   bool
	// State saved at push and restored at pop.
	savedLevels  [maxLevels]levelInfo // use: the parent's levels
	savedNeedSep bool                 // use
	// ended is set when the frame completed early (the reference's return
	// from inside match), not by running out of lines.
	ended bool
	// onTail is the reference's bb pointing at the file's tail: set by a
	// line counted from the end, it stays for the lines after it until one
	// is placed absolutely, as match() keeps bb from line to line.
	onTail       bool
	savedOffset  uint32 // use: ms->offset
	savedEoffset int32  // use
	savedOutLen  int    // indirect: output length at push
	savedNseps   int    // indirect: separator count at push
	childOffset  uint32 // indirect: the offset printed with the description
}

// line returns the record at relative index i of the frame.
func (s *scan) line(f *frame, i int32) *record {
	invariant.Check(f.count >= 0 && i >= 0, "line index non-negative")
	k := int(f.first) + int(i)
	if !invariant.Check(k >= 0 && k < len(s.db.recs), "frame line within database") {
		s.truncate(TruncInvariant)
		k = 0
	}
	return &s.db.recs[k]
}

// window is the frame's input bytes.
func (s *scan) window(f *frame) []byte { return s.buf[f.base : f.base+f.n] }

// pushFrame starts a child match. It reports false when the depth cap is
// reached, which is recorded as Truncated "recursion".
func (s *scan) pushFrame(fr *frame) bool { // childFrame
	invariant.Check(fr.n >= 0 && fr.base >= 0 && fr.base+fr.n <= len(s.buf), "child window within the buffer")
	invariant.Check(fr.count >= 0 && int(fr.first)+int(fr.count) <= len(s.db.recs), "child lines within the database")
	if s.nframes >= s.maxDepth {
		s.truncate(TruncRecursion)
		return false
	}
	s.frames[s.nframes] = *fr
	s.nframes++
	s.levels[0].gotMatch = false // file_check_mem(ms, 0) at the start of match()
	return true
}

// run evaluates frames until the root completes and returns the root's
// returnval: whether anything was printed or annotated.
func (s *scan) run() bool {
	invariant.Check(s.maxDepth > 0 && s.maxDepth <= maxFrames, "depth cap in range")
	invariant.Check(s.nframes == 1, "run starts with the root frame")
	rootResult := false
	for steps := 0; steps < maxSteps && s.nframes > 0 && s.truncated != TruncTime && s.abort == ""; steps++ {
		f := &s.frames[s.nframes-1] // frame
		if f.idx >= f.count {
			if s.cont && f.phase == phaseCont && !f.ended {
				s.contEntryDone(f) // the last entry ran to the end of the lines
			}
			rootResult = s.popFrame()
			continue
		}
		if f.phase == phaseTop {
			s.stepTop(f)
		} else {
			s.stepCont(f)
		}
	}
	if s.nframes > 0 && s.truncated != TruncTime && s.abort == "" {
		s.truncate(TruncTime) // the step budget ran out
	}
	if s.abort != "" {
		s.nframes = 0 // the reference returns -1 through every level
	}
	return rootResult
}

// popFrame finishes the top frame and, for a child, completes the parent's
// mget with the child's result. It returns the frame's returnval.
func (s *scan) popFrame() bool {
	invariant.Check(s.nframes > 0, "pop with a frame")
	invariant.Check(s.frames[s.nframes-1].idx >= s.frames[s.nframes-1].count, "popped frame is complete")
	f := &s.frames[s.nframes-1] // frame
	rv := f.returnval           // returnVal
	s.nframes--
	if f.kind == kindRoot || s.nframes == 0 {
		return rv
	}
	parent := &s.frames[s.nframes-1]
	invariant.Check(parent.idx < parent.count, "parent is suspended on a line")
	if f.kind == kindIndirect && !rv && f.mapIdx+1 < len(s.db.maps) {
		s.pushNextMap(f) // mget's indirect loop: the next map, until one answers
		return rv
	}
	var r int // mgetResult
	if f.kind == kindUse {
		r = s.finishUse(parent, f, rv)
	} else {
		r = s.finishIndirect(parent, f, rv)
	}
	if parent.phase == phaseTop {
		s.finishTop(parent, r)
	} else {
		s.finishCont(parent, r)
	}
	return rv
}

// pushNextMap starts an indirect child over the next map's binary set.
func (s *scan) pushNextMap(done *frame) {
	invariant.Check(done.mapIdx+1 < len(s.db.maps), "a next map exists")
	next := *done
	next.mapIdx++
	m := &s.db.maps[next.mapIdx]
	next.first, next.count = m.first, m.count
	next.idx, next.contLevel, next.phase = 0, 0, phaseTop
	next.returnval, next.foundMatch, next.onTail = false, false, false // a new match() call starts on the window
	ok := s.pushFrame(&next)
	invariant.Check(ok, "the popped frame's slot is free")
}

// flush skips the rest of the current entry: the reference's `goto flush`.
func (s *scan) flush(f *frame) { // frame
	invariant.Check(f.idx < f.count, "flush from a line within the frame")
	end := s.db.entryEnd[f.first+f.idx] - f.first
	invariant.Check(end > f.idx && end <= f.count, "entry end within the frame")
	f.idx = end
	f.contLevel = 0
	f.phase = phaseTop
}

// skipTop is the reference's first test in match(): entries of the other
// class, and string tests marked for the other text/binary mode.
func skipTop(m *record, mode uint16, text bool) bool { // magicLine
	invariant.Check(mode == flagBinTest || mode == flagTextTest, "mode is one class")
	if m.typ == tName {
		return false
	}
	if isString(m.typ) {
		flt := m.strFlags() & (strBinTest | strTextTest)
		if (text && flt == strBinTest) || (!text && flt == strTextTest) {
			return true
		}
	}
	return m.flag&mode != mode
}

// stepTop evaluates the top-level line at f.idx up to its mget; a child
// push suspends the frame and finishTop completes it later.
func (s *scan) stepTop(f *frame) { // frame
	invariant.Check(f.phase == phaseTop, "top-level step in the top phase")
	invariant.Check(s.line(f, f.idx).contLevel == 0, "top-level line has level 0")
	m := s.line(f, f.idx) // magicLine
	pf := &s.db.pre[f.first+f.idx]
	if pf.skip&skipBit(f.mode, f.text) != 0 || s.timeUp() {
		s.flush(f)
		return
	}
	if pf.n != 0 && f.kind != kindUse && !s.prefilterOK(f, pf) {
		s.flush(f)
		return
	}
	if !s.setOffset(m, f, 0) {
		s.flush(f)
		return
	}
	r, pushed := s.mgetLine(m, f)
	if pushed {
		return
	}
	s.finishTop(f, r)
}

// finishTop is the rest of the top-level line's evaluation after mget
// returned r (0 no match, 1 match, -1 the reference's fatal error).
func (s *scan) finishTop(f *frame, r int) { // mgetResult
	invariant.Check(r >= -1 && r <= 1, "mget result in range")
	m := s.line(f, f.idx) // magicLine
	if r < 0 {
		s.flush(f)
		return
	}
	var flush bool
	if r == 0 {
		flush = m.reln != '!'
	} else {
		if m.typ == tIndirect {
			f.foundMatch, f.returnval = true, true
		}
		flush = !s.magicCheck(m, f)
	}
	if flush {
		s.flush(f)
		return
	}
	if s.annotate(m, f) {
		s.endFrame(f, true)
		return
	}
	if m.hasDesc() {
		f.foundMatch = true
		if s.mode == modeDesc {
			f.returnval, s.needSeparator, s.printedSomething = true, true, true
			if s.cont && !s.firstline {
				s.writeSep() // print_sep: another entry already answered
			}
			s.mprint(m, f)
		}
	}
	if !s.moffset(m, f, &s.levels[0].off) {
		s.flush(f)
		return
	}
	f.contLevel = 1
	s.levels[1].gotMatch = false // file_check_mem(ms, ++cont_level)
	f.phase = phaseCont
	f.idx++
}

// endFrame makes the frame complete with the given result.
func (s *scan) endFrame(f *frame, rv bool) { // frame
	invariant.Check(f.idx <= f.count, "frame index within bounds")
	f.foundMatch = true
	s.needSeparator, s.printedSomething = true, true
	if s.cont {
		s.firstline = false
	}
	f.returnval = rv
	f.idx = f.count
	f.ended = true
}

// stepCont evaluates the continuation line at f.idx up to its mget.
func (s *scan) stepCont(f *frame) { // frame
	invariant.Check(f.phase == phaseCont, "continuation step in the continuation phase")
	invariant.Check(f.contLevel >= 0 && int(f.contLevel) < maxLevels, "continuation level within bounds")
	m := s.line(f, f.idx) // magicLine
	if m.contLevel == 0 {
		s.entryEnd(f)
		return
	}
	if f.contLevel < int32(m.contLevel) {
		f.idx++
		return
	}
	if f.contLevel > int32(m.contLevel) {
		f.contLevel = int32(m.contLevel)
	}
	if !s.setOffset(m, f, f.contLevel) {
		s.flush(f)
		return
	}
	if m.flag&flagOffAdd != 0 {
		if f.contLevel == 0 {
			f.returnval = false
			f.idx = f.count
			f.ended = true
			return
		}
		s.offset += bitsOfInt32(s.levels[f.contLevel-1].off)
	}
	r, pushed := s.mgetLine(m, f)
	if pushed {
		return
	}
	s.finishCont(f, r)
}

// entryEnd is reached when the entry's continuation lines are exhausted:
// a found match ends the frame, otherwise the next entry is tried.
func (s *scan) entryEnd(f *frame) { // frame
	invariant.Check(f.idx <= f.count, "frame index within bounds")
	if s.cont {
		s.contEntryDone(f) // under MAGIC_CONTINUE the next entry is tried regardless
	} else if f.foundMatch {
		f.idx = f.count
		f.ended = true
		return
	}
	f.contLevel = 0
	f.phase = phaseTop
}

// contEntryDone is the end of the reference's entry loop under
// MAGIC_CONTINUE: an entry that printed makes later answers need a
// separator, and after a match the printing state starts again.
func (s *scan) contEntryDone(f *frame) { // frame
	invariant.Check(s.cont, "continue run")
	invariant.Check(f.idx <= f.count, "frame index within bounds")
	if s.printedSomething {
		s.firstline = false
	}
	if f.foundMatch {
		s.printedSomething, s.firstline = false, false
	}
}

// finishCont is the rest of a continuation line's evaluation after mget.
func (s *scan) finishCont(f *frame, r int) { // mgetResult
	invariant.Check(r >= -1 && r <= 1, "mget result in range")
	m := s.line(f, f.idx) // magicLine
	if r < 0 {
		f.idx++
		return
	}
	var matched bool
	switch {
	case r == 0 && m.reln != '!':
		f.idx++
		return
	case r == 0: // a '!' test whose data could not be read counts as matched
		matched = true
	default:
		if m.typ == tIndirect {
			f.foundMatch, f.returnval = true, true
		}
		matched = s.magicCheck(m, f)
	}
	if matched {
		s.contMatched(f, m)
	}
	f.idx++
}

// contMatched handles a matched continuation line: the default/clear
// bookkeeping, annotation, printing and the next level's offset.
func (s *scan) contMatched(f *frame, m *record) { // magicLine
	invariant.Check(m.contLevel != 0, "continuation line")
	cl := f.contLevel // contLevel
	if !invariant.Check(cl >= 0 && int(cl) < maxLevels, "continuation level within bounds") {
		s.truncate(TruncInvariant)
		return
	}
	switch {
	case m.typ == tClear:
		s.levels[cl].gotMatch = false
	case s.levels[cl].gotMatch:
		if m.typ == tDefault {
			return
		}
	default:
		s.levels[cl].gotMatch = true
	}
	if s.annotate(m, f) {
		s.endFrame(f, true)
		return
	}
	if m.hasDesc() {
		f.foundMatch = true
		if s.mode == modeDesc {
			s.printCont(f, m)
		}
	}
	if !s.moffset(m, f, &s.levels[cl].off) {
		f.contLevel--
	}
	f.contLevel++
	if int(f.contLevel) < maxLevels {
		s.levels[f.contLevel].gotMatch = false // file_check_mem(ms, ++cont_level)
	}
}

// printCont prints a matched continuation line's description: a blank
// before it when the previous item printed, and under MAGIC_CONTINUE a
// separator when it is the first text since an answer ended.
func (s *scan) printCont(f *frame, m *record) { // frame
	invariant.Check(s.mode == modeDesc, "continuations print in description mode")
	invariant.Check(m.contLevel != 0, "continuation line")
	f.returnval = true
	if s.cont && !s.printedSomething && !s.firstline {
		s.writeSep()
	}
	s.printedSomething = true
	if s.needSeparator && m.flag&flagNoSpace == 0 {
		s.writeByte(' ')
	}
	s.mprint(m, f)
	s.needSeparator = true
}

// annotate is handle_annotation for the MIME and extension modes: the
// first annotated line on the path ends the match. In description mode the
// annotations are only recorded.
func (s *scan) annotate(m *record, f *frame) bool { // magicLine
	invariant.Check(f.idx >= 0 && f.idx < f.count, "annotating a line within the frame")
	rec := f.first + f.idx
	if m.hasMime() && s.mimeRec < 0 {
		s.mimeRec = rec
	}
	if m.hasExt() && s.extRec < 0 {
		s.extRec = rec
	}
	if m.hasApple() && s.appleRec < 0 {
		s.appleRec = rec
	}
	hit := false
	switch s.mode {
	case modeMime:
		hit = m.hasMime()
	case modeExt:
		hit = m.hasExt()
	case modeApple:
		hit = m.hasApple()
	default:
	}
	if hit && s.independent {
		s.printAnnotation(rec)
	}
	return hit
}

// printAnnotation is handle_annotation's printing in a run of one mode:
// the first answer is printed; a later one only under MAGIC_CONTINUE, after
// a separator.
func (s *scan) printAnnotation(rec int32) {
	invariant.Check(s.independent, "annotations print only in runs of one mode")
	invariant.Check(rec >= 0 && int(rec) < len(s.db.recs), "annotated record within the database")
	if !s.firstline {
		if !s.cont {
			return
		}
		s.writeSep()
	}
	s.firstline = false
	switch s.mode {
	case modeMime:
		s.writeString(varexpand(s.db.mimeOf(rec), s.execBit))
	case modeExt:
		s.writeString(s.db.extOf(rec))
	case modeApple:
		s.writeString(cString(s.db.recs[rec].apple)) // %.8s of an 8-byte field
	default:
	}
}
