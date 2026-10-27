// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"testing"
	"testing/fstest"
)

// Byte mutation alone rarely produces the coordinated multi-byte values
// a structured format needs: an ELF offset of 2^63, a CDF header with
// 1 MiB sectors whose chain is coherent, a JPEG comment whose length is
// below its own prefix. The targets below take the fields as typed
// arguments, which the fuzzer mutates as integers, and build a
// well-formed file around them.

// sparseFile is a file of size bytes whose first bytes are data and whose
// rest is zeros, so a field can point gigabytes into a file the fuzzer
// never has to write.
type sparseFile struct {
	data []byte
	size int64
}

func (f sparseFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= f.size {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > f.size-off {
		n = int(f.size - off)
	}
	clear(p[:n])
	if off < int64(len(f.data)) {
		copy(p[:n], f.data[off:])
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// fuzzStructured runs data through the identify paths and fails on a
// panic, an answer over the resource budget, a blank answer, an
// unescaped answer, or a slice and a reader over the same bytes that
// disagree. size is the length IdentifyAt is told the file has; past
// data it reads zeros.
func fuzzStructured(t *testing.T, db *Database, data []byte, size int64) { // database
	t.Helper()
	ctx := context.Background()
	var r, st, at Result // result, safeText, readerResult
	fuzzBounded(t, "Identify", func() { r = db.Identify(data) })
	if r.Description == "" || r.MIME == "" || r.Charset == "" {
		t.Fatalf("blank answer for %d bytes: %+v", len(data), r)
	}
	fuzzEscaped(t, r)
	fuzzBounded(t, "Identify with SafeText", func() {
		st = db.IdentifyWith(ctx, data, Options{SafeText: true, Continue: true})
	})
	fuzzSafeASCII(t, st)
	if size < int64(len(data)) {
		size = int64(len(data))
	}
	fuzzBounded(t, "IdentifyAt", func() { at = db.IdentifyAt(ctx, sparseFile{data, size}, size, Options{}) })
	if at.Description == "" || at.MIME == "" || at.Charset == "" {
		t.Fatalf("blank answer through a reader of %d bytes: %+v", size, at)
	}
	if size == int64(len(data)) && (at.Description != r.Description || at.MIME != r.MIME) {
		t.Fatalf("a slice and a reader over the same bytes differ:\n %q %q\n %q %q",
			r.Description, r.MIME, at.Description, at.MIME)
	}
}

// u32 is a test-built length or offset as a 32-bit field.
func u32(n int) uint32 { return low32(bitsOfInt64(int64(n))) }

// putAt writes b at off in img, cut at the end of img.
func putAt(img []byte, off uint64, b []byte) {
	if off < uint64(len(img)) {
		copy(img[off:], b)
	}
}

// imageLen is n bounded to [lo, hi].
func imageLen(n uint32, lo, hi int) int {
	return min(max(int(n), lo), hi)
}

// The ELF image is at most 256 KiB; a field may point anywhere.
const elfImageMax = 256 << 10

// elfFields are an ELF file's header, two program headers and two
// section headers: entry 0 of each table has the A fields, every later
// entry the B fields.
type elfFields struct {
	payload                   []byte
	phoff, shoff              uint64
	phOffA, phSizeA, phVaddrA uint64
	phOffB, phSizeB, phVaddrB uint64
	shOffA, shSizeA           uint64
	shOffB, shSizeB           uint64
	phTypeA, phTypeB          uint32
	shTypeA, shTypeB          uint32
	shNameA, shNameB          uint32
	fileSize                  uint32
	etype, machine            uint16
	phnum, shnum, shstrndx    uint16
	class64, big              bool
}

// elfImage builds the file: the payload at the A entries' offsets
// first, then the tables, then the header. The B entries may point into
// the payload.
func elfImage(f *elfFields) []byte {
	img := make([]byte, imageLen(f.fileSize, 64, elfImageMax))
	var bo binary.ByteOrder = binary.LittleEndian
	if f.big {
		bo = binary.BigEndian
	}
	for _, off := range []uint64{f.phOffA, f.shOffA} {
		putAt(img, off, f.payload)
	}
	word := func(b []byte, v uint64) { // put
		if f.class64 {
			bo.PutUint64(b, v)
		} else {
			bo.PutUint32(b, low32(v))
		}
	}
	phsize, shsize := 32, 40
	if f.class64 {
		phsize, shsize = 56, 64
	}
	ph := make([]byte, phsize)
	for i := range int(min(f.phnum, 64)) {
		typ, off, size, vaddr := f.phTypeA, f.phOffA, f.phSizeA, f.phVaddrA
		if i > 0 {
			typ, off, size, vaddr = f.phTypeB, f.phOffB, f.phSizeB, f.phVaddrB
		}
		bo.PutUint32(ph, typ)
		if f.class64 {
			bo.PutUint32(ph[4:], 5) // p_flags: read, execute
			word(ph[8:], off)
			word(ph[16:], vaddr)
			word(ph[32:], size)
			word(ph[40:], size)
		} else {
			word(ph[4:], off)
			word(ph[8:], vaddr)
			word(ph[16:], size)
			word(ph[20:], size)
			bo.PutUint32(ph[24:], 5)
		}
		putAt(img, f.phoff+uint64(i*phsize), ph)
	}
	sh := make([]byte, shsize)
	for i := range int(min(f.shnum, 64)) {
		typ, name, off, size := f.shTypeA, f.shNameA, f.shOffA, f.shSizeA
		if i > 0 {
			typ, name, off, size = f.shTypeB, f.shNameB, f.shOffB, f.shSizeB
		}
		bo.PutUint32(sh, name)
		bo.PutUint32(sh[4:], typ)
		if f.class64 {
			word(sh[24:], off)
			word(sh[32:], size)
		} else {
			word(sh[16:], off)
			word(sh[20:], size)
		}
		putAt(img, f.shoff+uint64(i*shsize), sh)
	}
	h := make([]byte, 64)
	copy(h, "\x7fELF")
	h[4], h[5], h[6] = 1, 1, 1 // ELFCLASS32, ELFDATA2LSB, EV_CURRENT
	if f.class64 {
		h[4] = 2
	}
	if f.big {
		h[5] = 2
	}
	bo.PutUint16(h[16:], f.etype)
	bo.PutUint16(h[18:], f.machine)
	bo.PutUint32(h[20:], 1)
	if f.class64 {
		word(h[32:], f.phoff)
		word(h[40:], f.shoff)
		bo.PutUint16(h[52:], 64)
		bo.PutUint16(h[54:], uint16(phsize))
		bo.PutUint16(h[56:], f.phnum)
		bo.PutUint16(h[58:], uint16(shsize))
		bo.PutUint16(h[60:], f.shnum)
		bo.PutUint16(h[62:], f.shstrndx)
	} else {
		word(h[28:], f.phoff)
		word(h[32:], f.shoff)
		bo.PutUint16(h[40:], 52)
		bo.PutUint16(h[42:], uint16(phsize))
		bo.PutUint16(h[44:], f.phnum)
		bo.PutUint16(h[46:], uint16(shsize))
		bo.PutUint16(h[48:], f.shnum)
		bo.PutUint16(h[50:], f.shstrndx)
		h = h[:52]
	}
	copy(img, h)
	return img
}

// Program header and section header types the seeds use beside elf.go's.
const (
	ptLoad      = 1
	shtProgbits = 1
	shtStrtab   = 3
)

// elfSeeds are the defects the ELF reader has had, as fields: an offset
// at or past 2^63 (SOF-11), a note section past the end of the file
// (SOF-14), the last section named .debug_info (SOF-15), and a core
// file and an executable with a note and an interpreter.
func elfSeeds() []elfFields {
	gnuNote := []byte("\x04\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00GNU\x00" +
		"\x00\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")
	strtab := []byte("\x00.shstrtab\x00.debug_info\x00")
	return []elfFields{
		{class64: true, etype: etExec, machine: 62, phnum: 2, phoff: 64,
			phTypeA: ptNote, phOffA: 0x200, phSizeA: uint64(len(gnuNote)),
			phTypeB: ptInterp, phOffB: 0x200 + uint64(len(gnuNote)), phSizeB: 28, fileSize: 0x400,
			payload: append(gnuNote, "/lib64/ld-linux-x86-64.so.2\x00"...)},
		{class64: true, etype: etExec, machine: 62, phnum: 1, phoff: 1 << 63,
			phTypeA: ptNote, phOffA: 0xfffffffffffffff0, phSizeA: 16, fileSize: 0x200},
		{class64: true, etype: etRel, machine: 62, shnum: 1, shoff: 0x8000000000000040,
			fileSize: 0x200},
		{class64: true, etype: etCore, machine: 62, phnum: 2, phoff: 64,
			phTypeA: ptNote, phOffA: 0xffffffffffffff00, phSizeA: 0x100,
			phTypeB: ptLoad, phOffB: 0x200, phSizeB: 0x100, phVaddrB: 0x400000, fileSize: 0x400},
		{class64: true, etype: etRel, machine: 62, shnum: 2, shoff: 0x100,
			shTypeA: shtProgbits, shTypeB: shtNote, shOffB: 0x10000, shSizeB: 16, fileSize: 0x200},
		{class64: true, etype: etRel, machine: 62, shnum: 2, shoff: 0x100, shstrndx: 0,
			shTypeA: shtStrtab, shNameA: 1, shOffA: 0x40, shSizeA: uint64(len(strtab)),
			shTypeB: shtProgbits, shNameB: 11, shOffB: 0x80, shSizeB: 4, fileSize: 0x200, payload: strtab},
		{etype: etDyn, machine: 3, big: true, phnum: 3, phoff: 52, shnum: 3, shoff: 0x200,
			phTypeA: ptNote, phOffA: 0x100, phSizeA: 32, phTypeB: ptLoad, phSizeB: 0x300,
			shTypeA: shtNote, shOffA: 0x100, shSizeA: 32, shTypeB: shtStrtab, shOffB: 0x120, shSizeB: 8,
			fileSize: 0x300, payload: gnuNote},
	}
}

// FuzzELF builds an ELF file from its header and table fields and checks
// it as FuzzIdentify and FuzzIdentifyAt do, the reader told the file is
// fileSize bytes long however much of it the image holds.
func FuzzELF(f *testing.F) {
	db, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{}) // database
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range elfSeeds() {
		f.Add(e.class64, e.big, e.etype, e.machine, e.phnum, e.shnum, e.shstrndx, e.phoff, e.shoff,
			e.phTypeA, e.phOffA, e.phSizeA, e.phVaddrA, e.phTypeB, e.phOffB, e.phSizeB, e.phVaddrB,
			e.shTypeA, e.shNameA, e.shOffA, e.shSizeA, e.shTypeB, e.shNameB, e.shOffB, e.shSizeB,
			e.fileSize, e.payload)
	}
	f.Fuzz(func(t *testing.T, class64, big bool, etype, machine, phnum, shnum, shstrndx uint16,
		phoff, shoff uint64, phTypeA uint32, phOffA, phSizeA, phVaddrA uint64,
		phTypeB uint32, phOffB, phSizeB, phVaddrB uint64, shTypeA, shNameA uint32, shOffA, shSizeA uint64,
		shTypeB, shNameB uint32, shOffB, shSizeB uint64, fileSize uint32, payload []byte) {
		e := elfFields{class64: class64, big: big, etype: etype, machine: machine, phnum: phnum,
			shnum: shnum, shstrndx: shstrndx, phoff: phoff, shoff: shoff,
			phTypeA: phTypeA, phOffA: phOffA, phSizeA: phSizeA, phVaddrA: phVaddrA,
			phTypeB: phTypeB, phOffB: phOffB, phSizeB: phSizeB, phVaddrB: phVaddrB,
			shTypeA: shTypeA, shNameA: shNameA, shOffA: shOffA, shSizeA: shSizeA,
			shTypeB: shTypeB, shNameB: shNameB, shOffB: shOffB, shSizeB: shSizeB,
			fileSize: fileSize, payload: payload}
		fuzzStructured(t, db, elfImage(&e), int64(fileSize))
	})
}

// The CDF image is at most 4 MiB, room for the header and three 1 MiB
// sectors.
const cdfImageMax = 4 << 20

// cdfFields are a Composite Document File's header and the four chains
// it is built from, each a run of consecutive sectors ending in an
// end-of-chain mark: the directory, the short-sector table, the root's
// short-stream container and the summary-information stream. Sector
// numbers, sizes and counts are written as given, so the header may
// describe a file the layout does not match.
type cdfFields struct {
	payload              []byte
	numSAT, numMSAT      uint32
	firstMSAT            uint32
	minStream            uint32
	dirStart, dirLen     uint32
	ssatStart, ssatLen   uint32
	rootStart, rootLen   uint32
	sumStart, sumSize    uint32
	propType, propCount  uint32
	fileSize             uint32
	secShift, shortShift uint16
	sumType              uint8
}

// CDF sector ids and the summary-information property set's identifier.
const (
	cdfFreeSect  = 0xffffffff
	cdfEndChain  = 0xfffffffe
	cdfSATSect   = 0xfffffffd
	summaryFMTID = "\xe0\x85\x9f\xf2\xf9\x4f\x68\x10\xab\x91\x08\x00\x2b\x27\xb3\xd9"
)

// cdfSummaryStream is a summary-information stream with count properties of
// type typ, each value the payload.
func cdfSummaryStream(typ, count uint32, payload []byte) []byte {
	le := binary.LittleEndian
	n := int(min(count, 16)) // properties written; count is the field as given
	b := make([]byte, 0x30+8+8*n)
	le.PutUint16(b, 0xfffe)
	le.PutUint16(b[4:], 0x0a00) // Windows 10
	le.PutUint16(b[6:], 2)
	le.PutUint32(b[0x18:], 1)
	copy(b[0x1c:], summaryFMTID)
	le.PutUint32(b[0x2c:], 0x30)
	value := le.AppendUint32(nil, typ)
	value = append(value, payload...)
	size := len(b) - 0x30 + n*len(value)
	le.PutUint32(b[0x30:], u32(size))
	le.PutUint32(b[0x34:], count)
	for i := range n {
		le.PutUint32(b[0x38+8*i:], uint32(2+i)) // title, subject, author, ...
		le.PutUint32(b[0x3c+8*i:], u32(8+8*n+i*len(value)))
	}
	for range n {
		b = append(b, value...)
	}
	return b
}

// cdfDirEntry is a 128-byte directory entry.
func cdfDirEntry(name string, typ uint8, start, size uint32) []byte {
	b := make([]byte, cdfDirectorySz)
	le := binary.LittleEndian
	for i := range len(name) {
		le.PutUint16(b[2*i:], uint16(name[i]))
	}
	le.PutUint16(b[64:], low16(uint64(u32(2*len(name)+2))))
	b[66] = typ
	le.PutUint32(b[68:], cdfFreeSect) // no siblings, no child
	le.PutUint32(b[72:], cdfFreeSect)
	le.PutUint32(b[76:], cdfFreeSect)
	le.PutUint32(b[116:], start)
	le.PutUint32(b[120:], size)
	return b
}

// cdfImage builds the file from the fields: the summary stream, the
// directory, the short-sector table, the SAT in sector 0 and the header,
// in that order, so a table the fields place over a stream is still the
// table. Sector k starts at (k+1) sectors; a sector or table entry past
// the image is left out.
func cdfImage(f *cdfFields) []byte {
	le := binary.LittleEndian
	shift := min(max(f.secShift, 7), 20)
	ss := uint64(1) << shift
	img := make([]byte, imageLen(f.fileSize, 2<<shift, cdfImageMax)) // the header and the SAT at least
	sss := uint64(1) << min(f.shortShift, 20)
	sector := func(k uint32) uint64 { return (uint64(k) + 1) * ss }
	table := func(k uint32) []byte { // the sector's bytes in the image
		off := min(sector(k), uint64(len(img)))
		return img[off:min(off+ss, uint64(len(img)))]
	}
	chain := func(tab []byte, start, n uint32) {
		for i := range min(n, 1<<18) {
			next := uint32(cdfEndChain)
			if i+1 < n {
				next = start + i + 1
			}
			if p := uint64(start+i) * 4; p+4 <= uint64(len(tab)) {
				le.PutUint32(tab[p:], next)
			}
		}
	}
	long := f.sumSize >= f.minStream
	sum := cdfSummaryStream(f.propType, f.propCount, f.payload)
	if long {
		putAt(img, sector(f.sumStart), sum)
	} else {
		putAt(img, sector(f.rootStart)+uint64(f.sumStart)*sss, sum)
	}
	dir := cdfDirEntry("Root Entry", cdfDirRootStorage, f.rootStart, f.rootLen<<shift)
	dir = append(dir, cdfDirEntry("\x05SummaryInformation", f.sumType, f.sumStart, f.sumSize)...)
	putAt(img, sector(f.dirStart), dir)
	if !long {
		chain(table(f.ssatStart), f.sumStart, low32((uint64(f.sumSize)+sss-1)/sss))
	}
	sat := table(0) // every sector free but the chains
	for i := 0; i+4 <= len(sat); i += 4 {
		le.PutUint32(sat[i:], cdfFreeSect)
	}
	chain(sat, f.dirStart, f.dirLen)
	chain(sat, f.ssatStart, f.ssatLen)
	chain(sat, f.rootStart, f.rootLen)
	if long {
		chain(sat, f.sumStart, low32((uint64(f.sumSize)+ss-1)/ss))
	}
	if len(sat) >= 4 {
		le.PutUint32(sat, cdfSATSect)
	}
	h := make([]byte, 512)
	le.PutUint64(h, cdfMagic)
	le.PutUint16(h[0x18:], 0x3e)
	le.PutUint16(h[0x1a:], 3)
	le.PutUint16(h[0x1c:], 0xfffe)
	le.PutUint16(h[0x1e:], f.secShift)
	le.PutUint16(h[0x20:], f.shortShift)
	le.PutUint32(h[0x2c:], f.numSAT)
	le.PutUint32(h[0x30:], f.dirStart)
	le.PutUint32(h[0x38:], f.minStream)
	le.PutUint32(h[0x3c:], f.ssatStart)
	le.PutUint32(h[0x40:], uint32(min(uint64(f.ssatLen), 1<<32-1)))
	le.PutUint32(h[0x44:], f.firstMSAT)
	le.PutUint32(h[0x48:], f.numMSAT)
	for i := range 109 {
		le.PutUint32(h[0x4c+4*i:], cdfFreeSect)
	}
	le.PutUint32(h[0x4c:], 0)
	copy(img, h)
	return img
}

// cdfSeeds: documents with a short and a long summary stream, with
// 512-byte, 4096-byte and 1 MiB sectors, and the 1 MiB-sector header
// whose short-sector table is a chain of 10000 sectors in a 2 MiB file
// (SOF-1).
func cdfSeeds() []cdfFields {
	title := append(binary.LittleEndian.AppendUint32(nil, 6), "Title\x00\x00\x00"...)
	return []cdfFields{
		{secShift: 9, shortShift: 6, numSAT: 1, firstMSAT: cdfEndChain, minStream: 4096,
			dirStart: 1, dirLen: 1, ssatStart: 2, ssatLen: 1, rootStart: 3, rootLen: 2,
			sumSize: 200, sumType: cdfDirUserStream, propType: cdfTypeString, propCount: 1,
			fileSize: 512 * 6, payload: title},
		{secShift: 9, shortShift: 6, numSAT: 1, firstMSAT: cdfEndChain, minStream: 0,
			dirStart: 1, dirLen: 1, ssatStart: cdfEndChain, rootStart: cdfEndChain, sumStart: 2, sumSize: 512,
			sumType: cdfDirUserStream, propType: cdfTypeFiletime, propCount: 2,
			fileSize: 512 * 4, payload: []byte("\x00\x80\x3e\xd5\xde\xb1\x9d\x01")},
		{secShift: 12, shortShift: 6, numSAT: 1, firstMSAT: cdfEndChain, minStream: 4096,
			dirStart: 1, dirLen: 1, ssatStart: 2, ssatLen: 1, rootStart: 3, rootLen: 1,
			sumSize: 300, sumType: cdfDirUserStream, propType: cdfTypeSigned32, propCount: 3,
			fileSize: 4096 * 5, payload: []byte{1, 2, 3, 4}},
		{secShift: 20, shortShift: 6, numSAT: 1, firstMSAT: cdfEndChain, minStream: 0,
			dirStart: 1, dirLen: 1, ssatStart: cdfEndChain, rootStart: cdfEndChain, sumStart: 2, sumSize: 512,
			sumType: cdfDirUserStream, propType: cdfTypeString, propCount: 1, fileSize: 4 << 20, payload: title},
		{secShift: 20, shortShift: 6, numSAT: 1, firstMSAT: cdfEndChain, minStream: 4096,
			dirStart: 2, dirLen: 1, ssatStart: 1, ssatLen: 10000, rootStart: cdfEndChain, fileSize: 2 << 20},
	}
}

// FuzzCDF builds a Composite Document File from its header and chain
// fields and checks it as FuzzELF does.
func FuzzCDF(f *testing.F) {
	db, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{}) // database
	if err != nil {
		f.Fatal(err)
	}
	for _, c := range cdfSeeds() {
		f.Add(c.secShift, c.shortShift, c.numSAT, c.numMSAT, c.firstMSAT, c.minStream,
			c.dirStart, c.dirLen, c.ssatStart, c.ssatLen, c.rootStart, c.rootLen,
			c.sumStart, c.sumSize, c.sumType, c.propType, c.propCount, c.fileSize, c.payload)
	}
	f.Fuzz(func(t *testing.T, secShift, shortShift uint16, numSAT, numMSAT, firstMSAT, minStream,
		dirStart, dirLen, ssatStart, ssatLen, rootStart, rootLen, sumStart, sumSize uint32,
		sumType uint8, propType, propCount, fileSize uint32, payload []byte) {
		c := cdfFields{secShift: secShift, shortShift: shortShift, numSAT: numSAT, numMSAT: numMSAT,
			firstMSAT: firstMSAT, minStream: minStream, dirStart: dirStart, dirLen: dirLen,
			ssatStart: ssatStart, ssatLen: ssatLen, rootStart: rootStart, rootLen: rootLen,
			sumStart: sumStart, sumSize: sumSize, sumType: sumType, propType: propType,
			propCount: propCount, fileSize: fileSize, payload: payload}
		fuzzStructured(t, db, cdfImage(&c), int64(fileSize))
	})
}

// derLengthBytes is an element length in one of the encodings form selects:
// 0 the shortest, 1 the long form with digits bytes (0 is the
// indefinite form, more than needed pads with leading zeros, fewer cuts
// the value), 2 the given lie instead of n in the shortest form.
func derLengthBytes(n uint64, form, digits uint8, lie uint64) []byte {
	switch form % 3 {
	case 1:
		k := int(digits % 9)
		b := []byte{0x80 | byte(k)}
		for i := k - 1; i >= 0; i-- {
			b = append(b, low8(n>>(8*min(i, 7))))
		}
		return b
	case 2:
		n = lie
	}
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var digitsOf []byte
	for v := n; v != 0; v >>= 8 {
		digitsOf = append([]byte{byte(v)}, digitsOf...)
	}
	return append([]byte{0x80 | smallUint8(len(digitsOf))}, digitsOf...)
}

// derFile wraps payload, the content of the innermost element, in
// nesting constructed elements. The outermost has tag; those inside
// alternate SEQUENCE and SET. Each length is encoded as form and digits
// choose; lie replaces the outermost length when form says so.
func derFile(tag, form, digits, nesting uint8, lie uint64, payload []byte) []byte {
	b := payload
	n := int(nesting % 16)
	for i := n - 1; i >= 0; i-- {
		t := byte(0x30) // SEQUENCE, or SET at odd depths
		if i%2 == 1 {
			t = 0x31
		}
		f := byte(0) // the inner elements' lengths are true
		if i == 0 {
			t, f = tag, form
		}
		head := append([]byte{t}, derLengthBytes(uint64(len(b)), f, digits, lie)...)
		b = append(head, b...)
	}
	return b
}

// FuzzDER builds nested ASN.1 DER elements around a payload, the length
// encodings chosen by fields, over the stock rules' der tests.
func FuzzDER(f *testing.F) {
	db, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{}) // database
	if err != nil {
		f.Fatal(err)
	}
	// A 512-bit key pair's version, modulus and exponent, and a fourth
	// element: the reference matches the key only when its length is in
	// the long form and an element follows the exponent.
	keyPair := []byte("\x02\x01\x00\x02\x41\x00" + string(make([]byte, 64)) + "\x02\x03\x01\x00\x01\x02\x01\x00")
	f.Add(uint8(0x30), uint8(1), uint8(2), uint8(1), uint64(0), keyPair)
	f.Add(uint8(0x30), uint8(0), uint8(0), uint8(1), uint64(0), keyPair)
	f.Add(uint8(0x30), uint8(1), uint8(8), uint8(1), uint64(0), keyPair)
	f.Add(uint8(0x30), uint8(1), uint8(0), uint8(3), uint64(0), keyPair)
	f.Add(uint8(0x30), uint8(2), uint8(0), uint8(2), uint64(1<<32-1), keyPair)
	f.Add(uint8(0x3f), uint8(1), uint8(8), uint8(4), uint64(0), []byte("\x1f\x81\x80\x80\x80\x00"))
	if cert, err := os.ReadFile("testdata/corpus/sample-x509-der.testfile"); err == nil {
		f.Add(uint8(0x30), uint8(0), uint8(0), uint8(0), uint64(0), cert)
	}
	f.Fuzz(func(t *testing.T, tag, form, digits, nesting uint8, lie uint64, payload []byte) {
		data := derFile(tag, form, digits, nesting, lie, payload)
		fuzzStructured(t, db, data, int64(len(data)))
	})
}

// pstringWidth is a pstring length width: the flag, and the bytes the
// length takes in which byte order.
type pstringWidth struct {
	flag  string
	bytes int
	big   bool
}

// pstringWidths are the five widths.
func pstringWidths() [5]pstringWidth {
	return [5]pstringWidth{{"B", 1, false}, {"H", 2, true}, {"h", 2, false}, {"L", 4, true}, {"l", 4, false}}
}

// pstringRules is one rule per width, with and without /J, each at the
// start of the file.
func pstringRules(f *testing.F) []*Database {
	var dbs []*Database
	for _, w := range pstringWidths() {
		for _, j := range []string{"", "J"} {
			db, err := compileFS(fstest.MapFS{"p": &fstest.MapFile{Data: []byte(
				"0 pstring/" + w.flag + j + " x pstring \"%s\"\n>0 pstring/" + w.flag + j + " =abc \\b, abc\n")}},
				CompileOptions{})
			if err != nil {
				f.Fatal(err)
			}
			dbs = append(dbs, db)
		}
	}
	return dbs
}

// jpegComment is a JFIF file whose first segment after APP0 is a comment
// with the given length field, which counts itself.
func jpegComment(length uint16, comment []byte) []byte {
	b := []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xfe")
	b = binary.BigEndian.AppendUint16(b, length)
	b = append(b, comment...)
	return append(b, 0xff, 0xd9)
}

// FuzzPString checks a length-prefixed string at every width, with /J
// (the length counts its own prefix) and without, and the stock JPEG
// comment rule (pstring/HJ), whose length below the prefix size once
// went negative (SOF-10).
func FuzzPString(f *testing.F) {
	stock, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{}) // database
	if err != nil {
		f.Fatal(err)
	}
	dbs := pstringRules(f)
	for _, c := range []struct {
		width uint8
		j     bool
		value uint32
	}{{0, false, 3}, {1, true, 5}, {2, true, 0}, {3, true, 1}, {4, false, 0xffffffff}, {0, true, 0}} {
		f.Add(c.width, c.j, c.value, false, []byte("abc"))
	}
	f.Add(uint8(1), true, uint32(0), true, []byte("AAAAAAAA"))
	f.Add(uint8(1), true, uint32(1), true, []byte("AAAAAAAA"))
	f.Add(uint8(1), true, uint32(10), true, []byte("AAAAAAAA"))
	f.Fuzz(func(t *testing.T, width uint8, j bool, value uint32, jpeg bool, payload []byte) {
		if jpeg {
			data := jpegComment(low16(uint64(value)), payload)
			fuzzStructured(t, stock, data, int64(len(data)))
			return
		}
		widths := pstringWidths()
		w := widths[int(width)%len(widths)]
		var data []byte
		switch {
		case w.bytes == 1:
			data = []byte{low8(uint64(value))}
		case w.bytes == 2 && w.big:
			data = binary.BigEndian.AppendUint16(nil, low16(uint64(value)))
		case w.bytes == 2:
			data = binary.LittleEndian.AppendUint16(nil, low16(uint64(value)))
		case w.big:
			data = binary.BigEndian.AppendUint32(nil, value)
		default:
			data = binary.LittleEndian.AppendUint32(nil, value)
		}
		data = append(data, payload...)
		db := dbs[2*(int(width)%len(widths))]
		if j {
			db = dbs[2*(int(width)%len(widths))+1]
		}
		fuzzStructured(t, db, data, int64(len(data)))
	})
}
