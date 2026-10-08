// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"context"
	"io"
	"sync"

	"github.com/eitanity/softmagic/internal/invariant"
)

// Limits. The reference's are named beside each. A limit that fires is
// reported in Examined.Truncated, never hidden.
const (
	// DefaultMaxBytes is how much of the input is consulted: the
	// reference's FILE_BYTES_MAX in file 5.48.
	DefaultMaxBytes = 7 * 1024 * 1024
	// maxLevels bounds continuation depth; Magdir 5.48 reaches 30.
	maxLevels = 64
	// maxFrames bounds use/indirect nesting; the reference's MAXR is 50.
	maxFrames = 32
	// indirMax is the reference's FILE_INDIR_MAX: indirect evaluations per
	// call, cumulative, as the reference counts them.
	indirMax = 50
	// maxOutput caps the description; a longer one is cut and reported
	// as Truncated "output".
	maxOutput = 4096
	// maxRules caps Result.Rules.
	maxRules = 64
	// encodingMax is the reference's FILE_ENCODING_MAX.
	encodingMax = 64 * 1024
	// regexMax is the reference's FILE_REGEX_MAX.
	regexMax = 8192
	// maxLineLen is ascmagic.c's MAXLINELEN.
	maxLineLen = 300
	// utf8ScratchSize bounds the UTF-8 re-encoding of a classified text
	// window: six bytes per character, encodingMax characters.
	utf8ScratchSize = 6 * encodingMax
	// regexScratchSize bounds the byte-to-rune transcoding of a regex
	// region: two bytes per input byte.
	regexScratchSize = 2 * regexMax
	// printableMax is the reference's buffer for a printed string.
	printableMax = 512
	// timeCheckEvery is how many top-level entries pass between polls of
	// the context.
	timeCheckEvery = 64
	// maxSteps bounds the matcher loop outright, so the loop has a fixed bound: one
	// step is one rule line evaluated in one frame. The legitimate maximum
	// is fifty indirect re-runs of the 25k-line set, under 1.3M; a rule
	// set whose "use" lines branch exponentially (the reference has no
	// bound on that either) is stopped here, reported as Truncated "time".
	maxSteps = 1 << 21
)

// Options configures one identification. The zero value means defaults.
type Options struct {
	// MaxBytes caps the input consulted; 0 means DefaultMaxBytes.
	MaxBytes int
	// MaxDepth caps use/indirect nesting; 0 means maxFrames, and larger
	// values are clamped to it.
	MaxDepth int
	// Executable is the input file's executable permission bit, which the
	// reference consults through ${x?a:b} in rule descriptions (file(1)
	// sets it from stat; an ELF dynamic section overrides it).
	Executable bool
	// Continue is libmagic's MAGIC_CONTINUE (file -k): Result.Continued
	// lists every match in each output mode. The other fields of the
	// Result are what they are without it.
	Continue bool
	// Raw is libmagic's MAGIC_RAW (file -r): strings from the input are
	// printed as they are, not with non-printable bytes as \ooo escapes.
	Raw bool
}

// matchMode selects what a match run collects: a description, or the
// first MIME or extension annotation (the reference's MAGIC_MIME_TYPE and
// MAGIC_EXTENSION modes, which return at the first annotation).
type matchMode uint8

const (
	modeDesc matchMode = iota
	modeMime
	modeExt
	modeApple
	// modeEnc is the reference's MAGIC_MIME_ENCODING alone: the rules
	// match but print nothing, and no annotation ends a match. Only the
	// continue runs use it; first-match answers derive the charset alone.
	modeEnc
)

// sepText is the reference's FILE_SEPARATOR, written between the answers
// of a continue run.
const sepText = "\n- "

// maxSeps bounds the separators one output can hold: each takes three of
// its bytes.
const maxSeps = maxOutput / len(sepText)

// levelInfo is the reference's struct level_info.
type levelInfo struct {
	off      int32
	gotMatch bool
}

// scan is the per-call state: nothing a call needs lives on the
// Database. It is pooled and reset between calls.
type scan struct {
	ctx              context.Context
	src              io.ReaderAt // the whole input when IdentifyAt was used, else nil
	db               *Database
	truncated        string
	buf              []byte // the input window, at most MaxBytes
	savedBuf         []byte // the input while the text phase matches over the UTF-8 scratch
	utf8             []byte
	rxbuf            []byte
	srcbuf           []byte    // reads beyond the window
	inbuf            []byte    // the window read from src, grown once
	cdfbuf           [4][]byte // the CDF built-in's tables and streams, grown once
	cdfdir           []cdfDir
	srcSize          int64
	frames           [maxFrames]frame
	memo             [memoSize]memoEntry
	search           searchState
	indir            int
	outLen           int
	nseps            int // separators recorded in seps
	timeCheck        int
	maxRead          int
	nframes          int
	maxDepth         int
	names            int
	nrules           int
	levels           [maxLevels]levelInfo
	rules            [maxRules]int32
	offset           uint32
	gen              uint32 // the call, for memo validity; never 0
	mimeRec          int32
	appleRec         int32
	extRec           int32
	eoffset          int32
	out              [maxOutput]byte
	seps             [maxSeps]int32 // where each separator starts in out, ascending
	value            [maxString]byte
	printedSomething bool
	needSeparator    bool
	mode             matchMode
	cont             bool // a continue run is in progress (MAGIC_CONTINUE)
	wantCont         bool // Options.Continue
	firstline        bool // the reference's firstline: nothing answered yet in this softmagic call
	oobHit           bool
	raw              bool  // Options.Raw
	execBit          bool  // ms->mode & 0111: the caller's executable bit, then the ELF verdict
	winID            uint8 // windowBin or windowText while a window is begun
}

// searchState is the reference's ms->search: the region a search, regex
// or der test runs over, as indices into scan.buf.
type searchState struct {
	start  int // ms->search.s
	length int // ms->search.s_len
	offset int // ms->search.offset
	rmLen  int // ms->search.rm_len
	valid  bool
}

// scanPool hands out scans; the one func literal in the package is the
// pool constructor; the module has no function values otherwise.
type scanPool struct {
	p sync.Pool
}

func newScanPool() *scanPool {
	return &scanPool{p: sync.Pool{New: func() any {
		return &scan{}
	}}}
}

func (sp *scanPool) get(db *Database, ctx context.Context, buf []byte, o Options) *scan {
	invariant.Check(db != nil, "scan for a database")
	s, ok := sp.p.Get().(*scan)
	if !invariant.Check(ok && s != nil, "pool holds scans") {
		s = &scan{}
	}
	s.reset(db, ctx, buf, o)
	return s
}

func (sp *scanPool) put(s *scan) {
	s.db, s.buf, s.savedBuf, s.ctx, s.src = nil, nil, nil, nil, nil
	sp.p.Put(s)
}

// reset zeroes the per-call fields; the scratch buffers are kept.
func (s *scan) reset(db *Database, ctx context.Context, buf []byte, o Options) {
	invariant.Check(db != nil, "reset with a database")
	invariant.Check(o.MaxBytes <= 0 || len(buf) <= o.MaxBytes, "window within MaxBytes")
	s.db, s.buf, s.ctx = db, buf, ctx
	s.nframes, s.offset, s.eoffset = 0, 0, 0
	s.search = searchState{}
	s.indir, s.names = 0, 0
	s.mode = modeDesc
	s.outLen, s.printedSomething, s.needSeparator = 0, false, false
	s.mimeRec, s.extRec, s.appleRec = -1, -1, -1
	s.nrules = 0
	s.truncated = ""
	s.maxRead, s.oobHit = 0, false
	s.timeCheck = 0
	s.maxDepth = o.MaxDepth
	if s.maxDepth <= 0 || s.maxDepth > maxFrames {
		s.maxDepth = maxFrames
	}
	s.execBit = o.Executable
	s.raw = o.Raw
	s.cont, s.wantCont, s.firstline, s.nseps = false, o.Continue, true, 0
	s.src, s.srcSize = nil, 0
	s.gen++
	if s.gen == 0 {
		s.gen = 1
	}
	s.winID = 0
	for i := range s.levels {
		s.levels[i] = levelInfo{}
	}
}

// utf8Scratch returns the UTF-8 re-encoding buffer with room for n bytes.
// A pooled scan grows its buffers once, to a cap, and keeps them:
// allocation happens at initialisation, not per call in steady state.
func (s *scan) utf8Scratch(n int) []byte {
	invariant.Check(n >= 0, "size non-negative")
	if n > utf8ScratchSize {
		n = utf8ScratchSize
	}
	if cap(s.utf8) < n {
		s.utf8 = make([]byte, n)
	}
	return s.utf8[:n]
}

// rxScratch returns the regex transcoding and printing buffer with room
// for n bytes.
func (s *scan) rxScratch(n int) []byte {
	invariant.Check(n >= 0, "size non-negative")
	if n > regexScratchSize {
		n = regexScratchSize
	}
	if cap(s.rxbuf) < n {
		s.rxbuf = make([]byte, n)
	}
	return s.rxbuf[:n]
}

// cdfScratch returns the i-th CDF buffer with room for n bytes, grown
// once per pooled scan, not per call.
func (s *scan) cdfScratch(i, n int) []byte {
	invariant.Check(i >= 0 && i < len(s.cdfbuf) && n >= 0, "scratch index and size")
	if cap(s.cdfbuf[i]) < n {
		s.cdfbuf[i] = make([]byte, n)
	}
	b := s.cdfbuf[i][:n]
	for k := range b {
		b[k] = 0
	}
	return b
}

// truncate records the first limit that fired (later ones do not replace it).
func (s *scan) truncate(why string) {
	invariant.Check(why != "", "truncation names a reason")
	if s.truncated == "" {
		s.truncated = why
	}
}

// fail records a violated invariant in release mode, as Truncated
// "invariant"; in
// assertion builds invariant.Check has already panicked.
func (s *scan) fail(what string) bool {
	if invariant.Check(false, what) {
		return true
	}
	s.truncate(TruncInvariant)
	return false
}

// noteRead records that bytes up to end were consulted.
func (s *scan) noteRead(end int) {
	invariant.Check(end >= 0, "read end non-negative")
	if end > len(s.buf) {
		end = len(s.buf)
	}
	if end > s.maxRead {
		s.maxRead = end
	}
}

// oob is the reference's offset_oob: whether i bytes at offset o lie
// outside a window of n bytes. A failure is remembered for NeedMore.
func (s *scan) oob(n int, o int64, i int) bool {
	invariant.Check(n >= 0, "window length non-negative")
	if o < 0 || o > int64(n) || int64(i) > int64(n)-o {
		s.oobHit = true
		return true
	}
	s.noteRead(int(o) + i)
	return false
}

// timeUp polls the context every timeCheckEvery calls.
func (s *scan) timeUp() bool {
	invariant.Check(s.timeCheck >= 0 && s.timeCheck < timeCheckEvery, "poll counter within period")
	s.timeCheck++
	if s.timeCheck < timeCheckEvery || s.ctx == nil {
		return false
	}
	s.timeCheck = 0
	if s.ctx.Err() != nil {
		s.truncate(TruncTime)
		return true
	}
	return false
}

// Output helpers: the reference's file_printf family over a fixed buffer.

// write appends b, truncating at the cap (reported as Truncated "output").
func (s *scan) write(b []byte) {
	invariant.Check(s.outLen <= maxOutput, "output length within cap")
	n := copy(s.out[s.outLen:], b)
	s.outLen += n
	if n < len(b) {
		s.truncate(TruncOutput)
	}
}

func (s *scan) writeString(str string) {
	invariant.Check(s.outLen <= maxOutput, "output length within cap")
	n := copy(s.out[s.outLen:], str)
	s.outLen += n
	if n < len(str) {
		s.truncate(TruncOutput)
	}
}

func (s *scan) writeByte(c byte) {
	if s.outLen >= maxOutput {
		s.truncate(TruncOutput)
		return
	}
	s.out[s.outLen] = c
	s.outLen++
}

// output is the text printed so far.
func (s *scan) output() []byte { return s.out[:s.outLen] }

// writeSep is file_separator: the separator between two answers of a
// continue run, with its position recorded so the answers can be told
// apart without searching the text for it.
func (s *scan) writeSep() {
	invariant.Check(s.cont, "separators only in continue runs")
	invariant.Check(s.nseps <= maxSeps, "separator count within cap")
	if s.nseps == maxSeps || s.outLen+len(sepText) > maxOutput {
		s.truncate(TruncOutput)
		return
	}
	s.seps[s.nseps] = smallInt32(s.outLen)
	s.nseps++
	s.writeString(sepText)
}

// trimSep is trim_separator: drop a separator that ends the output. The
// reference compares the length with sizeof(FILE_SEPARATOR), which counts
// the terminating NUL, so an output that is a separator and nothing else is
// left as it is.
func (s *scan) trimSep() {
	invariant.Check(s.nseps >= 0 && s.nseps <= maxSeps, "separator count within cap")
	if s.outLen < len(sepText)+1 {
		return
	}
	if s.nseps > 0 && int(s.seps[s.nseps-1])+len(sepText) == s.outLen {
		s.nseps--
		s.outLen = int(s.seps[s.nseps])
	}
}

// noteRule records a line that contributed text.
func (s *scan) noteRule(rec int32) {
	invariant.Check(rec >= 0, "rule index non-negative")
	if s.nrules < maxRules {
		s.rules[s.nrules] = rec
		s.nrules++
	}
}

// invariantEnabled reports the build mode to tests.
func invariantEnabled() bool { return invariant.Enabled }
