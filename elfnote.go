// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from the note and capability handling in readelf.c, file
// 5.48, Copyright (c) Christos Zoulas 2003 (see COPYING).

package softmagic

import (
	"strconv"

	"github.com/eitanity/softmagic/internal/invariant"
)

// Note types.
const (
	ntGNUVersion       = 1
	ntGNUBuildID       = 3
	ntGoBuildID        = 4
	ntNetBSDVersion    = 1
	ntNetBSDPax        = 3
	ntNetBSDMarch      = 5
	ntNetBSDCmodel     = 6
	ntNetBSDEmulation  = 2
	ntNetBSDCoreProc   = 1
	ntFreeBSDVersion   = 1
	ntOpenBSDVersion   = 1
	ntDragonFlyVersion = 1
	ntAndroidVersion   = 1
	ntAndroidMemtag    = 4
	ntPrpsinfo         = 3
	ntAuxv             = 6
	osStyleSVR4        = 0
	osStyleFreeBSD     = 1
	osStyleNetBSD      = 2
)

// elfNote is one parsed note header with its name and descriptor.
type elfNote struct {
	name []byte // namesz bytes, NUL included when the writer included it
	desc []byte
	typ  uint32
}

// nameIs is NAMEEQUALS: the name is v followed by a NUL.
func (n *elfNote) nameIs(v string) bool {
	return len(n.name) == len(v)+1 && string(n.name[:len(v)]) == v && n.name[len(v)] == 0
}

// notes walks the notes in a buffer: the loop around donote.
func (e *elfState) notes(data []byte, align int) {
	invariant.Check(align >= 4, "note alignment")
	offset := 0
	for n := 0; n <= len(data) && offset < len(data); n++ {
		next := e.note(data, offset, align)
		if next == 0 || next <= offset {
			break
		}
		offset = next
	}
}

func alignUp(v, align int) int { return (v + align - 1) / align * align }

// note is donote: returns the offset of the next note, 0 to stop.
func (e *elfState) note(data []byte, offset, align int) int {
	if e.notecount == 0 {
		return 0
	}
	e.notecount--
	if offset+12 > len(data) {
		return offset + 12
	}
	namesz, descsz, typ := e.u32(data[offset:]), e.u32(data[offset+4:]), e.u32(data[offset+8:])
	offset += 12
	if namesz == 0 && descsz == 0 {
		if offset >= len(data) {
			return offset
		}
		return len(data)
	}
	if namesz&0x80000000 != 0 {
		e.printf(", bad note name size 0x" + strconv.FormatUint(uint64(namesz), 16))
		return 0
	}
	if descsz&0x80000000 != 0 {
		e.printf(", bad note description size 0x" + strconv.FormatUint(uint64(descsz), 16))
		return 0
	}
	// Sizes are below 2^31 here, but their sums with an offset are formed
	// in 64 bits so a 32-bit host cannot wrap them; a step past the end
	// is reported as the end.
	noff := offset
	if int64(offset)+int64(namesz) > int64(len(data)) {
		return len(data)
	}
	doff := alignUp(offset+int(namesz), align)
	if int64(doff)+int64(descsz) > int64(len(data)) {
		return len(data)
	}
	next := alignUp(doff+int(descsz), align)
	n := elfNote{typ: typ, name: data[noff : noff+int(namesz)], desc: data[doff : doff+int(descsz)]}
	e.handleNote(&n, data, doff)
	return next
}

// handleNote tries each note handler once, as donote does.
func (e *elfState) handleNote(n *elfNote, data []byte, doff int) { // note
	if e.flags&elfDidOSNote == 0 && e.osNote(n) {
		return
	}
	if e.flags&elfDidBuildID == 0 && e.bidNote(n) {
		return
	}
	if e.flags&elfDidPax == 0 && e.paxNote(n) {
		return
	}
	if e.flags&elfDidMemtag == 0 && e.memtagNote(n) {
		return
	}
	if e.flags&elfDidCore == 0 && e.coreNote(n, data, doff) {
		return
	}
	if e.flags&elfDidAuxv == 0 && e.auxvNote(n) {
		return
	}
	if n.nameIs("NetBSD") {
		e.netbsdNote(n)
	}
}

// bidNote is do_bid_note: GNU and Go build ids.
func (e *elfState) bidNote(n *elfNote) bool { // note
	if n.nameIs("GNU") && n.typ == ntGNUBuildID && len(n.desc) >= 4 && len(n.desc) <= 20 {
		e.flags |= elfDidBuildID
		btype := "unknown"
		switch len(n.desc) {
		case 8:
			btype = "xxHash"
		case 16:
			btype = "md5/uuid"
		case 20:
			btype = "sha1"
		}
		e.printf(", BuildID[" + btype + "]=")
		for _, b := range n.desc {
			e.s.writeByte(hexDigits[b>>4])
			e.s.writeByte(hexDigits[b&0xf])
		}
		return true
	}
	if len(n.name) == 4 && string(n.name[:3]) == "Go\x00" && n.typ == ntGoBuildID && len(n.desc) < 128 {
		e.printf(", Go BuildID=" + copyStr(n.desc, 255))
		return true
	}
	return false
}

// copyStr is file_copystr: at most width bytes, as a string.
func copyStr(b []byte, width int) string {
	if len(b) < width {
		width = len(b)
	}
	return string(b[:width])
}

// osNote is do_os_note.
func (e *elfState) osNote(n *elfNote) bool { // note
	invariant.Check(e.flags&elfDidOSNote == 0, "OS note not yet seen")
	d := n.desc // descriptor
	switch {
	case n.nameIs("SuSE") && n.typ == ntGNUVersion && len(d) == 2:
		e.flags |= elfDidOSNote
		e.printf(", for SuSE " + strconv.Itoa(int(d[0])) + "." + strconv.Itoa(int(d[1])))
	case n.nameIs("GNU") && n.typ == ntGNUVersion && len(d) == 16:
		e.flags |= elfDidOSNote
		e.printf(", for GNU/" + gnuOSName(e.u32(d)) + " " + strconv.FormatUint(uint64(e.u32(d[4:])), 10) +
			"." + strconv.FormatUint(uint64(e.u32(d[8:])), 10) + "." + strconv.FormatUint(uint64(e.u32(d[12:])), 10))
	case n.nameIs("NetBSD") && n.typ == ntNetBSDVersion && len(d) == 4:
		e.flags |= elfDidOSNote
		e.netbsdVersion(e.u32(d))
	case n.nameIs("FreeBSD") && n.typ == ntFreeBSDVersion && len(d) == 4:
		e.flags |= elfDidOSNote
		e.freebsdVersion(e.u32(d))
	case n.nameIs("OpenBSD") && n.typ == ntOpenBSDVersion && len(d) == 4:
		e.flags |= elfDidOSNote
		e.printf(", for OpenBSD")
	case n.nameIs("DragonFly") && n.typ == ntDragonFlyVersion && len(d) == 4:
		e.flags |= elfDidOSNote
		v := e.u32(d)
		e.printf(", for DragonFly " + strconv.FormatUint(uint64(v/100000), 10) + "." +
			strconv.FormatUint(uint64(v/10000%10), 10) + "." + strconv.FormatUint(uint64(v%10000), 10))
	case n.nameIs("Android") && n.typ == ntAndroidVersion && len(d) >= 4:
		e.flags |= elfDidOSNote
		e.printf(", for Android " + strconv.FormatUint(uint64(e.u32(d)), 10))
		if len(d) >= 4+64+64 {
			e.printf(", built by NDK " + cString(d[4:68]) + " (" + cString(d[68:132]) + ")")
		}
		return false // the reference falls through without returning 1
	default:
		return false
	}
	return true
}

func gnuOSName(v uint32) string {
	switch v {
	case 0:
		return "Linux"
	case 1:
		return "Hurd"
	case 2:
		return "Solaris"
	case 3:
		return "kFreeBSD"
	case 4:
		return "kNetBSD"
	default:
		return "<unknown>"
	}
}

// netbsdVersion is do_note_netbsd_version.
func (e *elfState) netbsdVersion(desc uint32) {
	e.printf(", for NetBSD")
	if desc <= 100000000 {
		return
	}
	patch := (desc / 100) % 100
	rel := (desc / 10000) % 100
	minor := (desc / 1000000) % 100
	major := desc / 100000000
	e.printf(" " + strconv.FormatUint(uint64(major), 10) + "." + strconv.FormatUint(uint64(minor), 10))
	if major >= 9 {
		patch += 100 * rel
		rel = 0
	}
	switch {
	case rel == 0 && patch != 0:
		e.printf("." + strconv.FormatUint(uint64(patch), 10))
	case rel != 0:
		for ; rel > 26; rel -= 26 {
			e.printf("Z")
		}
		e.s.writeByte('A' + low8(uint64(rel)) - 1)
	}
}

// freebsdVersion is do_note_freebsd_version.
func (e *elfState) freebsdVersion(desc uint32) {
	invariant.Check(e.flags&elfDidOSNote != 0, "OS note flagged by the caller")
	e.printf(", for FreeBSD")
	d := uint64(desc) // descValue
	switch {
	case desc == 460002:
		e.printf(" 4.6.2")
	case desc < 460100:
		e.printf(" " + u10(d/100000) + "." + u10(d/10000%10))
		if d/1000%10 > 0 {
			e.printf("." + u10(d/1000%10))
		}
		if d%1000 > 0 || d%100000 == 0 {
			e.printf(" (" + u10(d) + ")")
		}
	case desc < 500000:
		e.printf(" " + u10(d/100000) + "." + u10(d/10000%10+d/1000%10))
		if d/100%10 > 0 {
			e.printf(" (" + u10(d) + ")")
		} else if d/10%10 > 0 {
			e.printf("." + u10(d/10%10))
		}
	default:
		e.printf(" " + u10(d/100000) + "." + u10(d/1000%100))
		if d/100%10 > 0 || d%100000/100 == 0 {
			e.printf(" (" + u10(d) + ")")
		} else if d/10%10 > 0 {
			e.printf("." + u10(d/10%10))
		}
	}
}

// u10 is %u.
func u10(v uint64) string { return strconv.FormatUint(v, 10) }

// paxNote is do_pax_note.
func (e *elfState) paxNote(n *elfNote) bool {
	if !n.nameIs("PaX") || n.typ != ntNetBSDPax || len(n.desc) != 4 {
		return false
	}
	e.flags |= elfDidPax
	e.flagList(e.u32(n.desc), ", PaX: ", [6]string{"+mprotect", "-mprotect", "+segvguard", "-segvguard", "+ASLR", "-ASLR"})
	return true
}

// memtagNote is do_memtag_note.
func (e *elfState) memtagNote(n *elfNote) bool {
	if !n.nameIs("Android") || n.typ != ntAndroidMemtag || len(n.desc) != 4 {
		return false
	}
	e.flags |= elfDidMemtag
	e.flagList(e.u32(n.desc), ", Android Memtag: ", [6]string{"none", "async", "sync", "heap", "stack", ""})
	return true
}

// flagList prints the names of the set bits, comma separated, after the
// prefix; an empty name skips its bit.
func (e *elfState) flagList(desc uint32, prefix string, names [6]string) {
	invariant.Check(prefix != "", "list has a prefix")
	if desc == 0 {
		return
	}
	e.printf(prefix)
	did := 0
	for i := range names { // bitIndex
		if names[i] == "" || desc&(1<<uint(i)) == 0 {
			continue
		}
		if did > 0 {
			e.printf(",")
		}
		e.printf(names[i])
		did++
	}
}

// netbsdNote is the NetBSD-named tail of donote.
func (e *elfState) netbsdNote(n *elfNote) { // note
	d := n.desc // descriptor
	if len(d) > 100 {
		d = d[:100]
	}
	var flag int
	var tag string
	switch n.typ {
	case ntNetBSDVersion:
		return
	case ntNetBSDMarch:
		flag, tag = elfDidMarch, "compiled for"
	case ntNetBSDCmodel:
		flag, tag = elfDidCmodel, "compiler model"
	case ntNetBSDEmulation:
		flag, tag = elfDidEmulation, "emulation:"
	default:
		if e.flags&elfDidUnknown == 0 {
			e.flags |= elfDidUnknown
			e.printf(", note=" + strconv.FormatUint(uint64(n.typ), 10))
		}
		return
	}
	if e.flags&flag != 0 {
		return
	}
	e.flags |= flag
	e.printf(", " + tag + ": " + copyStr(d, 255))
}

// coreNote is do_core_note.
func (e *elfState) coreNote(n *elfNote, data []byte, doff int) bool { // note
	invariant.Check(doff >= 0 && doff <= len(data), "descriptor within the buffer")
	style := -1
	switch {
	case (len(n.name) == 4 && string(n.name) == "CORE") || n.nameIs("CORE"):
		style = osStyleSVR4
	case n.nameIs("FreeBSD"):
		style = osStyleFreeBSD
	case len(n.name) >= 11 && string(n.name[:11]) == "NetBSD-CORE":
		style = osStyleNetBSD
	}
	if style != -1 && e.flags&elfDidCoreStyle == 0 {
		e.printf(", " + [3]string{"SVR4", "FreeBSD", "NetBSD"}[style] + "-style")
		e.flags |= elfDidCoreStyle | style
	}
	switch style {
	case osStyleNetBSD:
		return e.netbsdCore(n)
	case osStyleFreeBSD:
		return e.freebsdCore(n, data, doff)
	default:
		return e.svr4Core(n, data, doff)
	}
}

// netbsdCore prints a NetBSD core's process info from struct
// NetBSD_elfcore_procinfo (name at 124, siglwp at 156).
func (e *elfState) netbsdCore(n *elfNote) bool { // note
	invariant.Check(n.nameIs("NetBSD-CORE") || len(n.name) >= 11, "NetBSD core note")
	if n.typ != ntNetBSDCoreProc {
		return false
	}
	var pi [160]byte // psinfo
	copy(pi[:], n.desc)
	name := printable(e.s.rxScratch(printableMax), pi[124:156], 31, e.s.raw)
	e.printf(", from '" + string(name) + "', pid=" + u10(uint64(e.u32(pi[80:84]))) +
		", uid=" + u10(uint64(e.u32(pi[100:104]))) + ", gid=" + u10(uint64(e.u32(pi[112:116]))) +
		", nlwps=" + u10(uint64(e.u32(pi[120:124]))) + ", lwp=" + u10(uint64(e.u32(pi[156:160]))) +
		" (signal " + u10(uint64(e.u32(pi[8:12]))) + "/code " + u10(uint64(e.u32(pi[12:16]))) + ")")
	e.flags |= elfDidCore
	return true
}

// freebsdCore prints a FreeBSD core's command and pid.
func (e *elfState) freebsdCore(n *elfNote, data []byte, doff int) bool {
	if n.typ != ntPrpsinfo || e.flags&elfIsCore == 0 {
		return false
	}
	argoff := 4 + 4 + 17
	if e.class == elfClass64 {
		argoff += 8
	}
	if doff+argoff+81 <= len(data) {
		e.printf(", from '" + cString(data[doff+argoff:doff+argoff+80]) + "'")
	}
	pidoff := argoff + 81 + 2
	if doff+pidoff+4 <= len(data) {
		e.printf(", pid=" + strconv.FormatUint(uint64(e.u32(data[doff+pidoff:])), 10))
	}
	e.flags |= elfDidCore
	return false
}

// prpsOffsets are the candidate offsets of the command name in a
// prpsinfo note, 32- and 64-bit.
func (e *elfState) prpsOffsets() []int {
	if e.class == elfClass32 {
		return []int{100, 84, 44, 28, 48, 32, 8}
	}
	return []int{136, 120, 56, 40, 16}
}

// svr4Core prints an SVR4-style core's command name, trying the known
// offsets as the reference does.
func (e *elfState) svr4Core(n *elfNote, data []byte, doff int) bool { // note
	if n.typ != ntPrpsinfo || e.flags&elfIsCore == 0 {
		return false
	}
	offs := e.prpsOffsets()
	for i := 0; i < len(offs); i++ { // offsetIndex
		j, ok := prpsNameLen(data, doff, offs[i], len(n.desc))
		if !ok {
			continue
		}
		i = adjustPrps(data, doff, offs, i, j)
		start := doff + offs[i]
		end := start
		for ; end < len(data) && data[end] != 0 && cIsPrint(data[end]); end++ {
		}
		for ; end > start && cIsSpace(data[end-1]); end-- {
		}
		e.printf(", from '" + copyStr(data[start:end], 255) + "'")
		e.flags |= elfDidCore
		return true
	}
	return false
}

// prpsNameLen checks the 16-byte name field at a candidate offset and
// returns how many bytes it held before a NUL.
func prpsNameLen(data []byte, doff, rel, descsz int) (int, bool) {
	invariant.Check(rel >= 0 && descsz >= 0, "offsets non-negative")
	j := 0 // nameIndex
	for ; j < 16; j++ {
		noff := doff + rel + j
		if noff >= len(data) || rel+j >= descsz {
			return 0, false
		}
		c := data[noff] // nameChar
		if c == 0 {
			if j == 0 {
				return 0, false
			}
			return j, true
		}
		if !cIsPrint(c) || c == '\'' || c == '"' || c == '`' {
			return 0, false
		}
	}
	return j, true
}

// adjustPrps moves to an earlier candidate when the bytes between it and
// the match are all printable (the match was mid-string).
func adjustPrps(data []byte, doff int, offs []int, i, j int) int { // offsetIndex
	for k := i + 1; k < len(offs); k++ { // otherIndex
		if offs[k] >= offs[i] || (offs[k] == offs[i]-16 && j == 16) {
			continue
		}
		adjust := true
		for no := doff + offs[k]; no < doff+offs[i]; no++ {
			adjust = adjust && no < len(data) && cIsPrint(data[no])
		}
		if adjust {
			i = k
		}
	}
	return i
}

// auxvNote is do_auxv_note for SVR4 cores.
func (e *elfState) auxvNote(n *elfNote) bool { // note
	if e.flags&(elfIsCore|elfDidCoreStyle) != elfIsCore|elfDidCoreStyle ||
		e.flags&elfCoreStyle != osStyleSVR4 || n.typ != ntAuxv {
		return false
	}
	e.flags |= elfDidAuxv
	elsize := 8
	if e.class == elfClass64 {
		elsize = 16
	}
	nval := 0
	for off := 0; off <= len(n.desc)-elsize; off += elsize {
		nval++
		if nval > 50 {
			return true
		}
		typ, val := e.word(n.desc[off:]), e.word(n.desc[off+elsize/2:])
		tag, isString := auxvTag(typ)
		if tag == "" {
			continue
		}
		if isString {
			if str, ok := e.stringAt(val); ok {
				e.printf(", " + tag + ": '" + str + "'")
			}
			continue
		}
		e.printf(", " + tag + ": " + strconv.FormatInt(extend(val, 32, true), 10))
	}
	return true
}

// stringAt is get_string_on_virtaddr: the printable NUL-terminated string
// at a virtual address, located through the core's program headers.
func (e *elfState) stringAt(virtaddr uint64) (string, bool) {
	invariant.Check(e.phNum >= 0, "program header count non-negative")
	off := e.phOff
	size := e.phdrSize()
	for n := e.phNum; n > 0; n-- {
		hb, ok := e.s.readAt(off, size)
		if !ok {
			e.printf(", can't read elf program header at " + strconv.FormatInt(off, 10))
			return "", false
		}
		ph := e.parsePhdr(hb) // programHeader
		off += int64(size)
		if e.fsize >= 0 && offInt(ph.offset) > e.fsize {
			continue
		}
		if virtaddr >= ph.vaddr && virtaddr < ph.vaddr+ph.filesz {
			return e.printableAt(offInt(ph.offset + (virtaddr - ph.vaddr)))
		}
	}
	return "", false
}

// printableAt reads up to 256 bytes and accepts them only when every byte
// before the NUL is printable.
func (e *elfState) printableAt(at int64) (string, bool) {
	buf, ok := e.s.readUpTo(at, 256)
	if !ok || len(buf) == 0 {
		e.printf(", can't read elf string at " + strconv.FormatInt(at, 10))
		return "", false
	}
	n := 0 // printableLength
	for ; n < len(buf)-1 && buf[n] != 0 && cIsPrint(buf[n]); n++ {
	}
	if n == len(buf)-1 || buf[n] != 0 {
		return "", false
	}
	return string(buf[:n]), n > 0
}

func auxvTag(typ uint64) (string, bool) {
	switch typ {
	case 31:
		return "execfn", true
	case 15:
		return "platform", true
	case 11:
		return "real uid", false
	case 13:
		return "real gid", false
	case 12:
		return "effective uid", false
	case 14:
		return "effective gid", false
	default:
		return "", false
	}
}

// capSection is doshn's SHT_SUNW_cap case.
func (e *elfState) capSection(st *shdrState, sh *elfShdr) bool { // sectionState
	switch e.machine {
	case emSparc, emSparcV9, emIA64, em386, emAMD64:
	default:
		return true
	}
	if st.nbadcap > 5 {
		return true
	}
	size := 8
	if e.class == elfClass64 {
		size = 16
	}
	limit := clampInt(sh.size, elfShsizeMax)
	for coff := size; coff <= limit; coff += size {
		cb, ok := e.s.readAt(offInt(sh.offset)+int64(coff-size), size) // capEntry
		if !ok {
			return false
		}
		if cb[0] == 'A' {
			break
		}
		tag, val := e.word(cb), e.word(cb[size/2:])
		switch tag {
		case 0:
		case 1:
			st.capHW1 |= val
		case 2:
			st.capSF1 |= val
		default:
			e.printf(", with unknown capability 0x" + strconv.FormatUint(tag, 16) + " = 0x" + strconv.FormatUint(val, 16))
			st.nbadcap++
			if st.nbadcap > 3 {
				return true
			}
		}
	}
	return true
}

// capabilities prints the SunOS hardware and software capabilities.
func (e *elfState) capabilities(st *shdrState) { // sectionState
	invariant.Check(st != nil, "section state present")
	if st.capHW1 != 0 {
		e.hardwareCaps(st.capHW1)
	}
	if st.capSF1 == 0 {
		return
	}
	if st.capSF1&0x02 != 0 {
		if st.capSF1&0x01 != 0 {
			e.printf(", uses frame pointer")
		} else {
			e.printf(", not known to use frame pointer")
		}
	}
	if rest := st.capSF1 &^ 0x03; rest != 0 {
		e.printf(", with unknown software capability 0x" + strconv.FormatUint(rest, 16))
	}
}

// hardwareCaps names the hardware capability bits for the machine.
func (e *elfState) hardwareCaps(hw uint64) { // hwCaps
	invariant.Check(hw != 0, "capabilities present")
	e.printf(", uses")
	names := capNames(e.machine)
	if names == nil {
		e.printf(" hardware capability 0x" + strconv.FormatUint(hw, 16))
		return
	}
	for i := range names {
		if hw&(1<<uint(i)) != 0 && names[i] != "" {
			e.printf(" " + names[i])
			hw &^= 1 << uint(i)
		}
	}
	if hw != 0 {
		e.printf(" unknown hardware capability 0x" + strconv.FormatUint(hw, 16))
	}
}

// capNames is cap_desc_sparc or cap_desc_386 by bit position; nil for
// other machines.
func capNames(machine uint16) []string {
	switch machine {
	case emSparc, emSparcPlu, emSparcV9:
		return []string{"MUL32", "DIV32", "FSMULD", "V8PLUS", "POPC", "VIS", "VIS2", "ASI_BLK_INIT",
			"FMAF", "", "", "", "", "", "FJFMAU", "IMA"}
	case em386, emIA64, emAMD64:
		return []string{"FPU", "TSC", "CX8", "SEP", "AMD_SYSC", "CMOV", "MMX", "AMD_MMX", "AMD_3DNow",
			"AMD_3DNowx", "FXSR", "SSE", "SSE2", "PAUSE", "SSE3", "MON", "CX16", "AHF", "TSCP",
			"AMD_SSE4A", "POPCNT", "AMD_LZCNT", "SSSE3", "SSE4.1", "SSE4.2"}
	default:
		return nil
	}
}
