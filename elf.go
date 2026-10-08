// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from readelf.c and elfclass.h, file 5.48, Copyright (c)
// Christos Zoulas 2003 (see COPYING): the ELF built-in, which the
// reference runs only when it has a file descriptor, because program and
// section headers lie anywhere in the file. Here it reads through
// scan.readAt: the window first, then the io.ReaderAt an IdentifyAt caller
// supplied, and reports a read it cannot make as the reference reports a
// failed pread.

package softmagic

import (
	"encoding/binary"
	"math"
	"strconv"

	"github.com/eitanity/softmagic/internal/invariant"
)

// Limits: the reference's defaults from file.h, except the note section
// size, which bounds a per-call buffer here.
const (
	elfNotesMax  = 256
	elfPhnumMax  = 2048
	elfShnumMax  = 32768
	elfShsizeMax = 16 * 1024 * 1024
	elfNbufSize  = 2024 // NBUFSIZE
)

// ELF constants used.
const (
	elfClass32 = 1
	elfClass64 = 2
	etRel      = 1
	etExec     = 2
	etDyn      = 3
	etCore     = 4
	ptDynamic  = 2
	ptInterp   = 3
	ptNote     = 4
	shtSymtab  = 2
	shtNote    = 7
	shtSunwCap = 0x6ffffff5
	dtNeeded   = 1
	dtFlags1   = 0x6ffffffb
	df1PIE     = 0x08000000
	emSparc    = 2
	em386      = 3
	emSparcPlu = 18
	emSparcV9  = 43
	emIA64     = 50
	emAMD64    = 62
)

// elfFlags is the reference's *flags.
const (
	elfCoreStyle    = 0x0003
	elfDidCore      = 0x0004
	elfDidOSNote    = 0x0008
	elfDidBuildID   = 0x0010
	elfDidCoreStyle = 0x0020
	elfDidPax       = 0x0040
	elfDidMarch     = 0x0080
	elfDidCmodel    = 0x0100
	elfDidEmulation = 0x0200
	elfDidUnknown   = 0x0400
	elfDidMemtag    = 0x0800
	elfIsCore       = 0x1000
	elfDidAuxv      = 0x2000
)

// elfState is one run of file_tryelf.
type elfState struct {
	s         *scan
	fsize     int64
	phOff     int64 // the core's program headers, for auxv strings
	phNum     int
	flags     int
	notecount int
	machine   uint16
	class     uint8
	swap      bool
}

// offInt is the reference's off_t cast of a file offset or size: a value
// past the signed range cannot be read and is clamped, not wrapped.
func offInt(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v & math.MaxInt64)
}

// clampInt narrows a size to int within a limit.
func clampInt(v uint64, limit int) int {
	if v > bitsOfInt64(int64(limit)) {
		return limit
	}
	return int(v & math.MaxInt32)
}

// u16 reads a half-word in the file's byte order.
func (e *elfState) u16(b []byte) uint16 {
	if e.swap {
		return binary.BigEndian.Uint16(b)
	}
	return binary.LittleEndian.Uint16(b)
}

func (e *elfState) u32(b []byte) uint32 {
	if e.swap {
		return binary.BigEndian.Uint32(b)
	}
	return binary.LittleEndian.Uint32(b)
}

func (e *elfState) u64(b []byte) uint64 {
	if e.swap {
		return binary.BigEndian.Uint64(b)
	}
	return binary.LittleEndian.Uint64(b)
}

// word reads a class-sized address or offset.
func (e *elfState) word(b []byte) uint64 {
	if e.class == elfClass32 {
		return uint64(e.u32(b))
	}
	return e.u64(b)
}

func (e *elfState) printf(str string) { e.s.writeString(str) }

// tryELF is file_tryelf in description mode: it returns the text the
// reference appends after the rules' description, and sets the scan's
// executable bit from the dynamic section as the reference sets ms->mode.
func (s *scan) tryELF() string {
	buf := s.buf
	if len(buf) <= 52 || buf[0] != 0x7f || (buf[1] != 'E' && buf[1] != 'O') || buf[2] != 'L' || buf[3] != 'F' {
		return ""
	}
	e := elfState{s: s, class: buf[4], fsize: s.inputSize(), notecount: elfNotesMax}
	e.swap = buf[5] != 1 // the host is little-endian
	start := s.outLen
	switch e.class {
	case elfClass32, elfClass64:
		e.run(buf)
	default:
		e.printf(", unknown class " + strconv.Itoa(int(e.class)))
	}
	text := string(s.out[start:s.outLen])
	s.outLen = start
	return text
}

// hdrSize is sizeof(Elf32_Ehdr) or sizeof(Elf64_Ehdr).
func (e *elfState) hdrSize() int {
	if e.class == elfClass32 {
		return 52
	}
	return 64
}

// run is the body of elfclass.h for the file's class.
func (e *elfState) run(buf []byte) {
	if len(buf) <= e.hdrSize() {
		return
	}
	typ := e.u16(buf[16:])
	e.machine = e.u16(buf[18:])
	var phoff, shoff uint64
	var phentsize, phnum, shentsize, shnum, shstrndx uint16
	if e.class == elfClass32 {
		phoff, shoff = uint64(e.u32(buf[28:])), uint64(e.u32(buf[32:]))
		phentsize, phnum = e.u16(buf[42:]), e.u16(buf[44:])
		shentsize, shnum, shstrndx = e.u16(buf[46:]), e.u16(buf[48:]), e.u16(buf[50:])
	} else {
		phoff, shoff = e.u64(buf[32:]), e.u64(buf[40:])
		phentsize, phnum = e.u16(buf[54:]), e.u16(buf[56:])
		shentsize, shnum, shstrndx = e.u16(buf[58:]), e.u16(buf[60:]), e.u16(buf[62:])
	}
	switch typ {
	case etCore:
		if phnum > elfPhnumMax {
			e.tooMany("program headers", phnum)
			return
		}
		e.flags |= elfIsCore
		e.phOff, e.phNum = offInt(phoff), int(phnum)
		e.phdrCore(e.phOff, e.phNum, int(phentsize))
	case etExec, etDyn:
		if phnum > elfPhnumMax {
			e.tooMany("program", phnum)
			return
		}
		if shnum > elfShnumMax {
			e.tooMany("section", shnum)
			return
		}
		e.phdrExec(offInt(phoff), int(phnum), int(phentsize), shnum != 0)
		e.shdr(offInt(shoff), int(shnum), int(shentsize), int(shstrndx))
	case etRel:
		if shnum > elfShnumMax {
			e.tooMany("section headers", shnum)
			return
		}
		e.shdr(offInt(shoff), int(shnum), int(shentsize), int(shstrndx))
	default:
	}
	if e.notecount == 0 {
		e.tooMany("notes", elfNotesMax)
	}
}

func (e *elfState) tooMany(what string, n uint16) {
	e.printf(", too many " + what + " (" + strconv.Itoa(int(n)) + ")")
}

// phdrSize is xph_sizeof.
func (e *elfState) phdrSize() int {
	if e.class == elfClass32 {
		return 32
	}
	return 56
}

// phdr is one program header's used fields.
type elfPhdr struct {
	typ    uint32
	offset uint64
	vaddr  uint64
	filesz uint64
	align  uint64
}

func (e *elfState) parsePhdr(b []byte) elfPhdr {
	invariant.Check(len(b) >= e.phdrSize(), "program header complete")
	var p elfPhdr
	p.typ = e.u32(b[0:])
	if e.class == elfClass32 {
		p.offset, p.vaddr, p.filesz, p.align = uint64(e.u32(b[4:])), uint64(e.u32(b[8:])), uint64(e.u32(b[16:])), uint64(e.u32(b[28:]))
	} else {
		p.offset, p.vaddr, p.filesz, p.align = e.u64(b[8:]), e.u64(b[16:]), e.u64(b[32:]), e.u64(b[48:])
	}
	if p.align == 0 {
		p.align = 4
	}
	if p.vaddr == 0 {
		p.vaddr = 4
	}
	return p
}

// phdrState accumulates across the program headers.
type phdrState struct {
	interp       string
	need         int
	pie, dynamic bool
}

// phdrExec is dophn_exec: linking, interpreter and notes from the program
// headers.
func (e *elfState) phdrExec(off int64, num, size int, haveSections bool) {
	invariant.Check(off >= 0, "program header offset non-negative")
	if num == 0 {
		e.printf(", no program header")
		return
	}
	if size != e.phdrSize() {
		e.printf(", corrupted program header size")
		return
	}
	st := phdrState{}
	for ; num > 0; num-- {
		hb, ok := e.s.readAt(off, size)
		if !ok {
			e.printf(", can't read elf program headers at " + strconv.FormatInt(off, 10))
			return
		}
		ph := e.parsePhdr(hb)
		off += int64(size)
		if !e.phdrEntry(&st, &ph, haveSections) {
			return
		}
	}
	e.linking(st.dynamic, st.pie, st.need, st.interp)
}

// phdrEntry handles one program header; false ends the walk.
func (e *elfState) phdrEntry(st *phdrState, ph *elfPhdr, haveSections bool) bool {
	invariant.Check(ph.align >= 4 || ph.align&0x80000000 != 0 || ph.align < 4, "alignment read")
	switch ph.typ {
	case ptDynamic:
		data, ok := e.readSegment(ph)
		if !ok {
			return false
		}
		st.dynamic = true
		st.pie, st.need = e.dynamic(data, st.pie, st.need)
	case ptNote:
		if haveSections {
			return true
		}
		align := ph.align
		if align&0x80000000 != 0 || align < 4 {
			e.printf(", invalid note alignment 0x" + strconv.FormatUint(align, 16))
			align = 4
		}
		data, ok := e.readSegment(ph)
		if !ok {
			return false
		}
		e.notes(data, clampInt(align, 1<<30))
	case ptInterp:
		data, ok := e.readSegment(ph)
		if !ok {
			return false
		}
		st.need++
		st.interp = interpString(data)
	default:
	}
	return true
}

// readSegment reads up to NBUFSIZE bytes of a segment, short at the end
// of the input as pread would be.
func (e *elfState) readSegment(ph *elfPhdr) ([]byte, bool) {
	n := clampInt(ph.filesz, elfNbufSize)
	data, ok := e.s.readUpTo(offInt(ph.offset), n)
	if !ok {
		e.printf(", can't read section at " + strconv.FormatUint(ph.offset, 10))
		return nil, false
	}
	return data, true
}

// interpString is the PT_INTERP contents as the reference keeps them.
func interpString(data []byte) string {
	if len(data) == 0 || data[0] == 0 {
		return "*empty*"
	}
	n := 0
	for ; n < len(data)-1 && data[n] != 0; n++ {
	}
	return string(data[:n])
}

// linking prints the linking summary of dophn_exec.
func (e *elfState) linking(dynamic, pie bool, need int, interp string) {
	switch {
	case dynamic && pie && need == 0:
		e.printf(", static-pie linked")
	case dynamic:
		e.printf(", dynamically linked")
	default:
		e.printf(", statically linked")
	}
	if interp != "" {
		e.printf(", interpreter ")
		e.s.write(printable(e.s.rxScratch(elfNbufSize), []byte(interp), len(interp), e.s.raw))
	}
}

// dynamic is the dodynamic loop over a PT_DYNAMIC segment.
func (e *elfState) dynamic(data []byte, pie bool, need int) (bool, int) {
	invariant.Check(need >= 0, "needed count non-negative")
	e.s.execBit = false // let DF_1 decide
	size := 8
	if e.class == elfClass64 {
		size = 16
	}
	for off := 0; off <= len(data)-size; off += size {
		tag, val := e.word(data[off:]), e.word(data[off+size/2:])
		switch tag {
		case dtFlags1:
			pie = val&df1PIE != 0
			e.s.execBit = pie
		case dtNeeded:
			need++
		default:
		}
	}
	return pie, need
}

// phdrCore is dophn_core: notes from a core file's program headers.
func (e *elfState) phdrCore(off int64, num, size int) {
	if num == 0 {
		e.printf(", no program header")
		return
	}
	if size != e.phdrSize() {
		e.printf(", corrupted program header size")
		return
	}
	for ; num > 0; num-- {
		hb, ok := e.s.readAt(off, size)
		if !ok {
			e.printf(", can't read elf program headers at " + strconv.FormatInt(off, 10))
			return
		}
		ph := e.parsePhdr(hb)
		off += int64(size)
		if e.fsize >= 0 && offInt(ph.offset) > e.fsize {
			continue
		}
		if ph.typ != ptNote {
			continue
		}
		data, ok := e.readSegment(&ph)
		if !ok {
			return
		}
		e.notes(data, 4)
	}
}

// shdrSize is xsh_sizeof.
func (e *elfState) shdrSize() int {
	if e.class == elfClass32 {
		return 40
	}
	return 64
}

// elfShdr is one section header's used fields.
type elfShdr struct {
	name   uint32
	typ    uint32
	offset uint64
	size   uint64
}

func (e *elfState) parseShdr(b []byte) elfShdr {
	invariant.Check(len(b) >= e.shdrSize(), "section header complete")
	var sh elfShdr
	sh.name, sh.typ = e.u32(b[0:]), e.u32(b[4:])
	if e.class == elfClass32 {
		sh.offset, sh.size = uint64(e.u32(b[16:])), uint64(e.u32(b[20:]))
	} else {
		sh.offset, sh.size = e.u64(b[24:]), e.u64(b[32:])
	}
	return sh
}

// shdr is doshn: stripped-ness, debug info, notes and capabilities from
// the section headers.
func (e *elfState) shdr(off int64, num, size, strtab int) {
	if num == 0 {
		e.printf(", no section header")
		return
	}
	if size != e.shdrSize() {
		e.printf(", corrupted section header size")
		return
	}
	offs := off + int64(size)*int64(strtab)
	nb, ok := e.s.readAt(offs, size)
	if !ok {
		e.printf(", missing section headers at " + strconv.FormatInt(offs, 10))
		return
	}
	nameOff := offInt(e.parseShdr(nb).offset)
	if e.fsize >= 0 && e.fsize < nameOff {
		e.printf(", too large section header offset " + strconv.FormatInt(nameOff, 10))
		return
	}
	st := shdrState{stripped: true}
	for ; num > 0; num-- {
		if !e.oneSection(&st, off, size, nameOff) {
			return
		}
		off += int64(size)
	}
	e.sectionSummary(&st)
}

// shdrState accumulates across sections.
type shdrState struct {
	capHW1, capSF1 uint64
	nbadcap        int
	stripped       bool
	hasDebugInfo   bool
}

// oneSection handles one section header; false ends the walk.
func (e *elfState) oneSection(st *shdrState, off int64, size int, nameOff int64) bool {
	hb, ok := e.s.readAt(off, size)
	if !ok {
		e.printf(", can't read elf section at " + strconv.FormatInt(off, 10))
		return false
	}
	sh := e.parseShdr(hb)
	nameAt := nameOff + int64(sh.name)
	name, ok := e.s.readUpTo(nameAt, 49)
	if !ok {
		e.printf(", can't read name of elf section at " + strconv.FormatInt(nameAt, 10))
		return false
	}
	if cString(name) == ".debug_info" {
		st.hasDebugInfo, st.stripped = true, false
	}
	switch sh.typ {
	case shtSymtab:
		st.stripped = false
		return true
	case shtNote:
		return e.noteSection(&sh)
	case shtSunwCap:
		if e.fsize >= 0 && offInt(sh.offset) > e.fsize {
			return true
		}
		return e.capSection(st, &sh)
	default:
		return true
	}
}

// noteSection is doshn's SHT_NOTE case.
func (e *elfState) noteSection(sh *elfShdr) bool {
	if e.fsize >= 0 && sh.size+sh.offset > uint64(e.fsize) {
		e.printf(", note offset/size 0x" + strconv.FormatUint(sh.offset, 16) + "+0x" +
			strconv.FormatUint(sh.size, 16) + " exceeds file size 0x" + strconv.FormatInt(e.fsize, 16))
		return false
	}
	if sh.size > elfShsizeMax {
		e.s.truncate(TruncOutput)
		return false
	}
	data, ok := e.s.readAt(offInt(sh.offset), clampInt(sh.size, elfShsizeMax))
	if !ok {
		e.printf(", can't read elf note at " + strconv.FormatUint(sh.offset, 10))
		return false
	}
	e.notes(data, 4)
	return true
}

// sectionSummary prints what doshn concludes after the walk.
func (e *elfState) sectionSummary(st *shdrState) {
	invariant.Check(st.nbadcap >= 0, "bad capability count non-negative")
	if st.hasDebugInfo {
		e.printf(", with debug_info")
	}
	if st.stripped {
		e.printf(", stripped")
	} else {
		e.printf(", not stripped")
	}
	e.capabilities(st)
}

// inputSize is the reference's fsize: the whole input's length.
func (s *scan) inputSize() int64 {
	if s.src != nil {
		return s.srcSize
	}
	return int64(len(s.buf))
}

// readAt returns exactly n bytes at off from the input: the window, or
// the IdentifyAt reader beyond it.
func (s *scan) readAt(off int64, n int) ([]byte, bool) {
	invariant.Check(n >= 0, "length non-negative")
	if off < 0 || n > elfShsizeMax || off > s.inputSize() {
		s.oobHit = true
		return nil, false
	}
	if off+int64(n) <= int64(len(s.buf)) {
		s.noteRead(int(off) + n)
		return s.buf[off : off+int64(n)], true
	}
	if s.src == nil || off+int64(n) > s.srcSize {
		s.oobHit = true
		return nil, false
	}
	buf := s.srcScratch(n)
	if _, err := s.src.ReadAt(buf, off); err != nil {
		return nil, false
	}
	return buf, true
}

// readUpTo returns up to n bytes at off, short at the end of the input as
// pread is; false only when nothing can be read.
func (s *scan) readUpTo(off int64, n int) ([]byte, bool) {
	invariant.Check(n >= 0, "length non-negative")
	size := s.inputSize()
	if off < 0 || off >= size {
		if off == size {
			return nil, true
		}
		return nil, false
	}
	if off+int64(n) > size {
		n = int(size - off)
	}
	return s.readAt(off, n)
}

// srcScratch is the buffer for reads beyond the window, grown once.
func (s *scan) srcScratch(n int) []byte {
	if cap(s.srcbuf) < n {
		s.srcbuf = make([]byte, n)
	}
	return s.srcbuf[:n]
}
