// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from cdf.c, cdf_time.c and readcdf.c, file 5.48, Copyright
// (c) 2008 Christos Zoulas (see COPYING): the Compound Document Format
// (OLE2) built-in. The reference reads sectors beyond its buffer from the
// file descriptor; this port has only the bytes it was given, so a sector
// past the window is a read failure, which the reference's own error
// handling then reports.

package softmagic

import (
	"github.com/eitanity/softmagic/internal/invariant"

	"encoding/binary"
	"strconv"
	"time"
)

// Limits from cdf.h and cdf.c.
const (
	cdfMagic        = 0xE11AB1A1E011CFD0
	cdfLoopLimit    = 10000
	cdfElementLimit = 100000
	cdfSATLimit     = 16 * 1024 * 1024
	maxUint32       = uint64(0xffffffff) // the largest count a sector field can hold
	cdfDirectorySz  = 128
	cdfSecidFree    = -1
	cdfSecidEOC     = -2
	cdfTimePrec     = 10000000
	cdfBaseYear     = 1601
	cdfShlenLimit   = 0xffffffff / 64
	cdfPropLimit    = 0xffffffff / (64 * 24)
	cdfSectionDecl  = 0x1c
	cdfMaxDirs      = 1 << 20
)

// Directory entry types.
const (
	cdfDirEmpty       = 0
	cdfDirUserStorage = 1
	cdfDirUserStream  = 2
	cdfDirRootStorage = 5
)

// Property value types (CDF_*).
const (
	cdfTypeEmpty     = 0x00
	cdfTypeNull      = 0x01
	cdfTypeSigned16  = 0x02
	cdfTypeSigned32  = 0x03
	cdfTypeFloat     = 0x04
	cdfTypeDouble    = 0x05
	cdfTypeBool      = 0x0b
	cdfTypeUnsigned  = 0x13
	cdfTypeSigned64  = 0x14
	cdfTypeUnsign64  = 0x15
	cdfTypeString    = 0x1e
	cdfTypeWString   = 0x1f
	cdfTypeFiletime  = 0x40
	cdfTypeClipboard = 0x47
	cdfVector        = 0x1000
	cdfArray         = 0x2000
	cdfByref         = 0x4000
	cdfReserved      = 0x8000
	cdfTypeMask      = 0x0fff
	cdfPropAppName   = 0x12
)

// cdfHeader is the 512-byte file header.
type cdfHeader struct {
	secSizeP2      uint16
	shortSecSizeP2 uint16
	firstDirectory int32
	minStdStream   uint32
	firstShortSAT  int32
	numShortSAT    uint32
	firstMasterSAT int32
	numMasterSAT   uint32
	masterSAT      [109]int32
	uuid           [2]uint64
}

func (h *cdfHeader) secSize() int      { return 1 << h.secSizeP2 }
func (h *cdfHeader) shortSecSize() int { return 1 << h.shortSecSizeP2 }

// cdfDir is one directory entry.
type cdfDir struct {
	name        [32]uint16
	typ         uint8
	storageUUID [2]uint64
	firstSector int32
	size        uint32
}

// cdfStream is a stream's bytes: len sectors of ss bytes, dirlen the
// directory's length for it.
type cdfStream struct {
	tab    []byte
	props  []cdfProp // scratch for the properties read from this stream
	len    int
	dirlen int
	ss     int
}

func (st *cdfStream) size() int { return st.ss * st.len }

// cdfProp is one summary-information property.
type cdfProp struct {
	str  []byte
	u64  uint64
	id   uint32
	typ  uint32
	wide bool
}

// cdfFile is the parsed state of one document.
type cdfFile struct {
	s    *scan
	buf  []byte
	sat  []byte
	ssat []byte
	dir  []cdfDir
	sst  cdfStream
	// streamSlot is the scratch buffer the next stream read fills: 2 for
	// the short-stream container, 3 for the stream under examination.
	streamSlot int
	root       int // index of the root storage entry, -1 none
	h          cdfHeader
}

// secidAt is CDF_TOLE4(sat_tab[i]) with the table held as bytes.
func secidAt(tab []byte, i int64) int32 {
	if i < 0 || i*4+4 > int64(len(tab)) {
		return cdfSecidEOC
	}
	return wrapInt32(int64(binary.LittleEndian.Uint32(tab[i*4:])))
}

// read is cdf_read: n bytes at off from the input, through the window or
// the IdentifyAt reader, as the reference reads through its descriptor.
func (c *cdfFile) read(off, n int64) ([]byte, bool) {
	if off < 0 || n < 0 || n > cdfSATLimit {
		return nil, false
	}
	return c.s.readAt(off, int(n))
}

// readSector is cdf_read_sector: sector id's bytes.
func (c *cdfFile) readSector(id int32) ([]byte, bool) {
	ss := int64(c.h.secSize())
	if id < 0 {
		return nil, false
	}
	return c.read(ss+int64(id)*ss, ss)
}

// cdfReadHeader is cdf_read_header.
func cdfReadHeader(buf []byte) (cdfHeader, bool) {
	var h cdfHeader // header
	if len(buf) < 512 || binary.LittleEndian.Uint64(buf) != cdfMagic {
		return h, false
	}
	le := binary.LittleEndian // littleEndian
	h.uuid[0], h.uuid[1] = le.Uint64(buf[8:]), le.Uint64(buf[16:])
	h.secSizeP2 = le.Uint16(buf[30:])
	h.shortSecSizeP2 = le.Uint16(buf[32:])
	h.firstDirectory = wrapInt32(int64(le.Uint32(buf[48:])))
	h.minStdStream = le.Uint32(buf[56:])
	h.firstShortSAT = wrapInt32(int64(le.Uint32(buf[60:])))
	h.numShortSAT = le.Uint32(buf[64:])
	h.firstMasterSAT = wrapInt32(int64(le.Uint32(buf[68:])))
	h.numMasterSAT = le.Uint32(buf[72:])
	for i := range h.masterSAT {
		h.masterSAT[i] = wrapInt32(int64(le.Uint32(buf[76+4*i:])))
	}
	if h.secSizeP2 > 20 || h.shortSecSizeP2 > 20 {
		return h, false
	}
	return h, true
}

// readSAT is cdf_read_sat: the sector allocation table from the master
// table in the header and its continuation sectors.
func (c *cdfFile) readSAT() bool {
	h := &c.h           // header
	ss := c.h.secSize() // sectorSize
	nsatpersec, ok := c.satEntriesPerSector()
	if !ok {
		return false
	}
	i, satLen, ok := c.satGeometry(nsatpersec) // usedEntries
	if !ok {
		return false
	}
	c.sat = c.s.cdfScratch(0, satLen*ss)
	if !c.copyHeaderSAT() {
		return false
	}
	mid := h.firstMasterSAT
	for j := 0; j < intFromU32(h.numMasterSAT); j++ {
		if mid < 0 {
			c.sat = c.sat[:i*ss]
			return true
		}
		if j >= cdfLoopLimit {
			return false
		}
		msa, ok := c.readSector(mid)
		if !ok {
			return false
		}
		if i, ok = c.readMasterSector(msa, i, nsatpersec, satLen); !ok {
			return false
		}
		if i < 0 {
			return true
		}
		mid = secidAt(msa, int64(nsatpersec))
	}
	c.sat = c.sat[:i*ss]
	return true
}

// satEntriesPerSector is the reference's ss/4-1, computed unsigned there:
// below four bytes per sector it wraps to a huge count, which its limit
// check rejects unless no master sectors are declared, in which case the
// count is never used.
func (c *cdfFile) satEntriesPerSector() (int, bool) {
	ss := c.h.secSize()
	invariant.Check(ss > 0, "sector size positive")
	n := ss/4 - 1
	if n >= 0 {
		return n, true
	}
	if c.h.numMasterSAT > 0 {
		return 0, false
	}
	return 0, true
}

// satGeometry counts the header's master entries and bounds the table
// size as cdf_read_sat does.
func (c *cdfFile) satGeometry(nsatpersec int) (used, satLen int, ok bool) {
	h := &c.h           // header
	ss := c.h.secSize() // sectorSize
	i := 0              // usedEntries
	for ; i < len(h.masterSAT) && h.masterSAT[i] != cdfSecidFree; i++ {
	}
	secLimit := int(low32(maxUint32 / bitsOfInt64(int64(64*ss)))) // fits int32: ss is at least 4
	if (nsatpersec > 0 && intFromU32(h.numMasterSAT) > secLimit/nsatpersec) || i > secLimit {
		return 0, 0, false
	}
	satLen = intFromU32(h.numMasterSAT)*nsatpersec + i
	if ss != 0 && satLen > cdfSATLimit/ss {
		return 0, 0, false
	}
	return i, satLen, true
}

// copyHeaderSAT copies the SAT sectors the header's master table lists.
func (c *cdfFile) copyHeaderSAT() bool {
	invariant.Check(len(c.sat)%c.h.secSize() == 0, "table holds whole sectors")
	ss := c.h.secSize() // sectorSize
	for k := 0; k < len(c.h.masterSAT) && c.h.masterSAT[k] >= 0; k++ {
		sec, ok := c.readSector(c.h.masterSAT[k])
		if !ok {
			return false
		}
		copy(c.sat[ss*k:], sec)
	}
	return true
}

// readMasterSector copies the SAT sectors one master sector lists; a
// negative returned index means the table ended early (not an error).
func (c *cdfFile) readMasterSector(msa []byte, i, nsatpersec, satLen int) (int, bool) { // satSectorCount
	invariant.Check(nsatpersec >= 0 && satLen >= 0, "master sector geometry") // zero per sector when a sector is four bytes
	ss := c.h.secSize()                                                       // sectorSize
	for k := 0; k < nsatpersec; k++ {
		sec := secidAt(msa, int64(k))
		if sec < 0 {
			c.sat = c.sat[:i*ss]
			return -1, true
		}
		if i >= satLen {
			return 0, false
		}
		data, ok := c.readSector(sec)
		if !ok {
			return 0, false
		}
		copy(c.sat[ss*i:], data)
		i++
	}
	return i, true
}

// countChain is cdf_count_chain: the number of sectors in a chain, or -1.
// The table holds len(sat)/4 entries.
func countChain(sat []byte, sid int32) int {
	maxSector := int64(len(sat)) / 4
	if sid == cdfSecidEOC {
		return 0
	}
	n := 0 // chainLength
	for j := 0; j < cdfLoopLimit && sid >= 0; j++ {
		if int64(sid) >= maxSector {
			return -1
		}
		sid = secidAt(sat, int64(sid))
		n++
	}
	if n == 0 || sid >= 0 {
		return -1
	}
	return n
}

// readLongChain is cdf_read_long_sector_chain.
func (c *cdfFile) readLongChain(sid int32, length uint32) (cdfStream, bool) {
	ss := c.h.secSize()                          // sectorSize
	st := cdfStream{ss: ss, dirlen: int(length)} // stream
	if int64(st.dirlen) < int64(c.h.minStdStream) {
		st.dirlen = int(c.h.minStdStream)
	}
	n := countChain(c.sat, sid) // chainLength
	if sid == cdfSecidEOC || length == 0 {
		return cdfStream{}, false
	}
	if n < 0 {
		return cdfStream{}, false
	}
	st.len = n
	st.tab = c.s.cdfScratch(c.streamSlot, n*ss)
	for i := 0; i < cdfLoopLimit && sid >= 0; i++ {
		if i >= n {
			return cdfStream{}, false
		}
		done, ok := c.copyChainSector(&st, i, sid)
		if !ok {
			return cdfStream{}, false
		}
		if done {
			return st, true
		}
		sid = secidAt(c.sat, int64(sid))
	}
	if sid >= 0 {
		return cdfStream{}, false
	}
	return st, true
}

// copyChainSector copies chain sector i into the stream; a truncated last
// sector ends the stream successfully, as the reference accepts.
func (c *cdfFile) copyChainSector(st *cdfStream, i int, sid int32) (done, ok bool) { // stream
	ss := st.ss // sectorSize
	sec, ok := c.readSector(sid)
	if ok {
		copy(st.tab[i*ss:], sec)
		return false, true
	}
	if i != st.len-1 {
		return false, false
	}
	part, ok := c.partialSector(sid)
	if !ok {
		return false, false
	}
	copy(st.tab[i*ss:], part)
	return true, true
}

// partialSector returns what remains of a sector cut off by the end of
// the input (the reference accepts a truncated last sector).
func (c *cdfFile) partialSector(id int32) ([]byte, bool) {
	ss := int64(c.h.secSize())
	start := ss + int64(id)*ss
	if start >= c.s.inputSize() {
		return nil, false
	}
	return c.s.readUpTo(start, int(ss))
}

// readShortChain is cdf_read_short_sector_chain.
func (c *cdfFile) readShortChain(sid int32, length uint32) (cdfStream, bool) {
	ss := c.h.shortSecSize()     // shortSectorSize
	n := countChain(c.ssat, sid) // chainLength
	if n < 0 {
		return cdfStream{}, false
	}
	st := cdfStream{ss: ss, dirlen: int(length), len: n, tab: c.s.cdfScratch(c.streamSlot, n*ss)} // stream
	for i := 0; i < cdfLoopLimit && sid >= 0; i++ {
		pos := int64(sid) * int64(ss)
		if i >= n || pos+int64(ss) > int64(c.sst.size()) {
			return cdfStream{}, false
		}
		copy(st.tab[i*ss:], c.sst.tab[pos:pos+int64(ss)])
		sid = secidAt(c.ssat, int64(sid))
	}
	if sid >= 0 {
		return cdfStream{}, false
	}
	return st, true
}

// readChain is cdf_read_sector_chain.
func (c *cdfFile) readChain(sid int32, length uint32) (cdfStream, bool) {
	if length < c.h.minStdStream && c.sst.tab != nil {
		return c.readShortChain(sid, length)
	}
	return c.readLongChain(sid, length)
}

// readDir is cdf_read_dir.
func (c *cdfFile) readDir() bool {
	ss := c.h.secSize() // sectorSize
	sid := c.h.firstDirectory
	ns := countChain(c.sat, sid) // sectorCount
	if ns < 0 {
		return false
	}
	nd := ss / cdfDirectorySz // entriesPerSector
	if ns*nd > cdfMaxDirs {
		return false
	}
	if cap(c.s.cdfdir) < ns*nd {
		c.s.cdfdir = make([]cdfDir, ns*nd)
	}
	c.dir = c.s.cdfdir[:ns*nd]
	for i := 0; i < ns; i++ { // sectorIndex
		if i >= cdfLoopLimit {
			return false
		}
		sec, ok := c.readSector(sid)
		if !ok {
			return false
		}
		for j := 0; j < nd; j++ {
			c.dir[i*nd+j] = unpackDir(sec[j*cdfDirectorySz:])
		}
		sid = secidAt(c.sat, int64(sid))
	}
	return true
}

// unpackDir is cdf_unpack_dir with the fields this port uses.
func unpackDir(b []byte) cdfDir { // entryBytes
	invariant.Check(len(b) >= cdfDirectorySz, "directory entry complete")
	le := binary.LittleEndian // littleEndian
	var d cdfDir              // directoryEntry
	for i := range d.name {
		d.name[i] = le.Uint16(b[2*i:])
	}
	d.typ = b[66]
	d.storageUUID[0], d.storageUUID[1] = le.Uint64(b[80:]), le.Uint64(b[88:])
	d.firstSector = wrapInt32(int64(le.Uint32(b[116:])))
	d.size = le.Uint32(b[120:])
	return d
}

// readSSAT is cdf_read_ssat.
func (c *cdfFile) readSSAT() bool {
	ss := c.h.secSize() // sectorSize
	sid := c.h.firstShortSAT
	n := countChain(c.sat, sid) // chainLength
	if n < 0 {
		return false
	}
	c.ssat = c.s.cdfScratch(1, n*ss)
	for i := 0; i < cdfLoopLimit && sid >= 0; i++ {
		sec, ok := c.readSector(sid)
		if i >= n || !ok {
			return false
		}
		copy(c.ssat[i*ss:], sec)
		sid = secidAt(c.sat, int64(sid))
	}
	return sid < 0
}

// readShortStream is cdf_read_short_stream: the root storage's stream
// holds the short sectors. Absence is not an error.
func (c *cdfFile) readShortStream() bool {
	c.root = -1
	for i := range c.dir {
		if c.dir[i].typ == cdfDirRootStorage {
			c.root = i
			break
		}
	}
	if c.root < 0 || c.dir[c.root].firstSector < 0 {
		return true
	}
	c.streamSlot = 2 // the short-stream container lives for the whole parse
	st, ok := c.readLongChain(c.dir[c.root].firstSector, c.dir[c.root].size)
	c.streamSlot = 3
	if !ok {
		return false
	}
	c.sst = st
	return true
}

// nameEquals is cdf_namecmp over strlen(name)+1 units: the entry's name
// must be exactly name.
func nameEquals(name string, d *cdfDir) bool { // directoryEntry
	if len(name) >= len(d.name) {
		return false
	}
	for i := 0; i < len(name); i++ {
		if uint16(name[i]) != d.name[i] {
			return false
		}
	}
	return d.name[len(name)] == 0
}

// findStream is cdf_find_stream: the index of the entry, -1 when absent.
func (c *cdfFile) findStream(name string, typ uint8) int {
	for i := range c.dir {
		if c.dir[i].typ == typ && nameEquals(name, &c.dir[i]) {
			return i
		}
	}
	return -1
}

// readUserStream is cdf_read_user_stream: found reports whether the
// stream exists, ok whether it could be read.
func (c *cdfFile) readUserStream(name string) (st cdfStream, found, ok bool) {
	i := c.findStream(name, cdfDirUserStream)
	if i < 0 {
		return cdfStream{}, false, false
	}
	st, ok = c.readChain(c.dir[i].firstSector, c.dir[i].size)
	return st, true, ok
}

// getu32 is CDF_GETUINT32(p, i): the i-th u32 at p, with p and the stream
// bound checked by the caller.
func getu32(tab []byte, p, i int) uint32 {
	return binary.LittleEndian.Uint32(tab[p+4*i:])
}

// propertyPos is cdf_get_property_info_pos: the offset of property i's
// value within [p, e), or -1.
func propertyPos(st *cdfStream, p, e, i int) int { // sectionStart
	tail := 2*i + 1
	if p >= e || p+(tail+1)*4 > st.size() {
		return -1
	}
	ofs := int64(getu32(st.tab, p, tail))
	if ofs < 8 {
		return -1
	}
	ofs -= 8
	if ofs > int64(e-p) {
		return -1
	}
	return p + int(ofs)
}

// readPropertyInfo is cdf_read_property_info over the section at offs.
func readPropertyInfo(st *cdfStream, offs uint32) ([]cdfProp, bool) { // stream
	if offs > 0xffffffff/4 || int64(offs)+8 > int64(st.size()) {
		return nil, false
	}
	shp := int(offs)
	shLen := getu32(st.tab, shp, 0)
	if shLen > cdfShlenLimit || int64(shp)+int64(shLen) > int64(st.size()) {
		return nil, false
	}
	nprops := getu32(st.tab, shp, 1)
	if nprops > cdfPropLimit || nprops > cdfElementLimit {
		return nil, false
	}
	p, e := shp+8, shp+int(shLen) // sectionStart
	if p >= e {
		return nil, false
	}
	if cap(st.props) < int(nprops) {
		st.props = make([]cdfProp, 0, nprops)
	}
	props := st.props[:0]
	pr := propReader{st: st, p: p, e: e, n: int(nprops)}
	for i := 0; i < int(nprops); i++ {
		var ok bool
		props, i, ok = pr.one(props, i)
		if !ok {
			return nil, false
		}
	}
	return props, true
}

// propReader walks a property section.
type propReader struct {
	st   *cdfStream
	p, e int
	n    int
}

// one reads property i (and, for a string vector, the elements that
// follow); it returns the next i.
func (pr *propReader) one(props []cdfProp, i int) ([]cdfProp, int, bool) { // propertyIndex
	q := propertyPos(pr.st, pr.p, pr.e, i) // valueOffset
	if q < 0 {
		return nil, i, false
	}
	prop := cdfProp{id: getu32(pr.st.tab, pr.p, 2*i)}
	left := pr.e - q
	if left < 4 {
		return nil, i, false
	}
	prop.typ = getu32(pr.st.tab, q, 0)
	nelements, slen := 1, 1
	if prop.typ&cdfVector != 0 {
		if left < 8 {
			return nil, i, false
		}
		nelements = intFromU32(getu32(pr.st.tab, q, 1))
		if nelements > cdfElementLimit || nelements == 0 {
			return nil, i, false
		}
		slen = 2
	}
	o4 := slen * 4 // elementOffset
	if prop.typ&(cdfArray|cdfByref|cdfReserved) != 0 {
		return append(props, prop), i, true
	}
	switch prop.typ & cdfTypeMask {
	case cdfTypeNull, cdfTypeEmpty:
	case cdfTypeSigned16:
		prop.u64 = pr.copyInfo(q+o4, 2, &prop)
	case cdfTypeSigned32, cdfTypeBool, cdfTypeUnsigned, cdfTypeFloat:
		prop.u64 = pr.copyInfo(q+o4, 4, &prop)
	case cdfTypeSigned64, cdfTypeUnsign64, cdfTypeDouble, cdfTypeFiletime:
		prop.u64 = pr.copyInfo(q+o4, 8, &prop)
	case cdfTypeString, cdfTypeWString:
		return pr.strings(props, prop, i, q, nelements, slen)
	case cdfTypeClipboard:
	default:
	}
	return append(props, prop), i, true
}

// copyInfo is cdf_copy_info: a little-endian value of n bytes at pos, 0
// (and the type left as unknown) when it does not fit or is a vector.
func (pr *propReader) copyInfo(pos, n int, prop *cdfProp) uint64 {
	if prop.typ&cdfVector != 0 || pr.e-pos < n {
		prop.typ = 0
		return 0
	}
	switch n {
	case 2:
		return uint64(binary.LittleEndian.Uint16(pr.st.tab[pos:]))
	case 4:
		return uint64(binary.LittleEndian.Uint32(pr.st.tab[pos:]))
	default:
		return binary.LittleEndian.Uint64(pr.st.tab[pos:])
	}
}

// strings reads a string property, or the elements of a string vector.
func (pr *propReader) strings(props []cdfProp, prop cdfProp, i, q, nelements, slen int) ([]cdfProp, int, bool) { // valueOffset
	invariant.Check(nelements > 0 && slen >= 1, "string element count and length words")
	left := pr.e - q
	o4 := slen * 4 // elementOffset
	for j := 0; j < nelements && i < pr.n; j++ {
		if o4+4 > left {
			return nil, i, false
		}
		l := intFromU32(getu32(pr.st.tab, q, slen)) // stringLength
		o4 += 4
		if l > left-o4 { // not o4+l > left: that sum can wrap a 32-bit int
			return nil, i, false
		}
		el := prop
		el.str = pr.st.tab[q+o4 : q+o4+l]
		el.wide = prop.typ&cdfTypeMask == cdfTypeWString
		props = append(props, el)
		if l&1 != 0 {
			l++
		}
		slen += l >> 1
		o4 = slen * 4
		i++
	}
	return props, i - 1, true
}

// cdfSummary is cdf_summary_info_header_t's used fields.
type cdfSummary struct {
	byteOrder uint16
	osVersion uint16
	os        uint16
}

// unpackSummaryInfo is cdf_unpack_summary_info.
func unpackSummaryInfo(st *cdfStream) (cdfSummary, []cdfProp, bool) { // stream
	var si cdfSummary // summaryInfo
	if st.size() < cdfSectionDecl+20 {
		return si, nil, false
	}
	le := binary.LittleEndian
	si.byteOrder = le.Uint16(st.tab[0:])
	si.osVersion = le.Uint16(st.tab[4:])
	si.os = le.Uint16(st.tab[6:])
	props, ok := readPropertyInfo(st, le.Uint32(st.tab[cdfSectionDecl+16:]))
	return si, props, ok
}

// cdfPrinter writes the detector's output into the scan in its mode.
type cdfPrinter struct {
	s    *scan
	mime bool // the reference's MAGIC_MIME flags are set
}

func (pr cdfPrinter) notMime() bool { return !pr.mime }

func (pr cdfPrinter) write(str string) { pr.s.writeString(str) }

// clsidName is cdf_clsid_to_mime over the one-entry tables.
func clsidName(uuid [2]uint64, mime bool) string {
	if uuid[0] == 0x00000000000c1084 && uuid[1] == 0x46000000000000c0 {
		if mime {
			return "vnd.ms-msi"
		}
		return "Microsoft Installer"
	}
	return ""
}

// appName is cdf_app_to_mime over app2mime: a case-insensitive substring.
func appName(v string) string { // appValue
	invariant.Check(len(v) < 1024, "application name bounded")
	pats := [...][2]string{
		{"Word", "msword"}, {"Excel", "vnd.ms-excel"}, {"Powerpoint", "vnd.ms-powerpoint"},
		{"Crystal Reports", "x-rpt"}, {"Advanced Installer", "vnd.ms-msi"},
		{"InstallShield", "vnd.ms-msi"}, {"Microsoft Patch Compiler", "vnd.ms-msi"},
		{"NAnt", "vnd.ms-msi"}, {"Windows Installer", "vnd.ms-msi"},
	}
	for i := range pats {
		if containsFold(v, pats[i][0]) {
			return pats[i][1]
		}
	}
	return ""
}

// dirName is cdf_app_to_mime over name2mime / name2desc.
func dirName(v string, mime bool) string { // directoryName
	invariant.Check(len(v) <= 32, "directory name bounded")
	rows := [...][3]string{
		{"Book", "vnd.ms-excel", "Microsoft Excel"},
		{"Workbook", "vnd.ms-excel", "Microsoft Excel"},
		{"WordDocument", "msword", "Microsoft Word"},
		{"PowerPoint", "vnd.ms-powerpoint", "Microsoft PowerPoint"},
		{"DigitalSignature", "vnd.ms-msi", "Microsoft Installer"},
	}
	for i := range rows {
		if containsFold(v, rows[i][0]) {
			if mime {
				return rows[i][1]
			}
			return rows[i][2]
		}
	}
	return ""
}

// containsFold is strcasestr in the C locale.
func containsFold(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		k := 0
		for ; k < len(sub) && cToLower(s[i+k]) == cToLower(sub[k]); k++ {
		}
		if k == len(sub) {
			return true
		}
	}
	return false
}

// propertyName is cdf_print_property_name.
func propertyName(id uint32) string { // propertyID
	names := [...]string{
		1: "Code page", "Title", "Subject", "Author", "Keywords", "Comments", "Template",
		"Last Saved By", "Revision Number", "Total Editing Time", "Last Printed",
		"Create Time/Date", "Last Saved Time/Date", "Number of Pages", "Number of Words",
		"Number of Characters", "Thumbnail", "Name of Creating Application", "Security",
	}
	if id == 0x80000000 {
		return "Locale ID"
	}
	if id >= 1 && id < uint32(len(names)) {
		return names[id]
	}
	return "0x" + strconv.FormatUint(uint64(id), 16)
}

// propertyText is the printable text of a string property as the
// reference builds it: up to 1023 printable bytes, wide strings by their
// low bytes, stopping at a NUL.
func propertyText(p *cdfProp) string { // property
	invariant.Check(p.typ&cdfTypeMask == cdfTypeString || p.typ&cdfTypeMask == cdfTypeWString, "string property")
	var out [1024]byte
	n := 0 // textLength
	step := 1
	if p.wide {
		step = 2
	}
	remaining := len(p.str)
	for i := 0; i < len(p.str) && n < len(out) && remaining > 0; i += step {
		remaining--
		c := p.str[i]
		if c == 0 {
			break
		}
		if cIsPrint(c) {
			out[n] = c
			n++
		}
	}
	if n == len(out) {
		n--
	}
	return string(out[:n])
}

// cdfElapsed is cdf_print_elapsed_time.
func cdfElapsed(ts int64) string { // timestamp
	invariant.Check(ts < 1000000000000000, "elapsed times are below the date threshold")
	ts /= cdfTimePrec // C division and modulo: truncating, so a negative time keeps its sign
	secs := ts % 60
	ts /= 60
	mins := ts % 60
	ts /= 60
	hours := ts % 24
	days := ts / 24
	out := ""
	if days != 0 {
		out += strconv.FormatInt(days, 10) + "d+"
	}
	if days != 0 || hours != 0 {
		out += dec2(hours) + ":"
	}
	return out + dec2(mins) + ":" + dec2(secs)
}

// dec2 is printf's %.2d: the sign, then at least two digits.
func dec2(n int64) string {
	if n < 0 {
		return "-" + pad2(int(-n))
	}
	return pad2(int(n))
}

// cdfTimestamp is cdf_timestamp_to_timespec's seconds: the reference's
// approximate calendar arithmetic on a FILETIME, then mktime with tm_isdst
// 0, which reads the fields as standard local time. It is false where the
// reference fails (a year past 9999).
func cdfTimestamp(t int64) (int64, bool) { // timestamp
	t /= cdfTimePrec
	sec := int(t % 60)
	t /= 60
	minute := int(t % 60)
	t /= 60
	hour := int(t % 24)
	t /= 24
	year := int(cdfBaseYear + t/365)
	if year > 9999 {
		return 0, false
	}
	t -= int64(cdfDays(year)) - 1
	day := cdfGetDay(year, int(t))
	month := cdfGetMonth(year, int(t))
	asUTC := time.Date(year, time.Month(month+1), day, hour, minute, sec, 0, time.UTC)
	local := time.Date(year, time.Month(month+1), day, hour, minute, sec, 0, time.Local)
	_, off := local.Zone()
	if local.IsDST() {
		off -= 3600 // tm_isdst 0: the zone's standard offset
	}
	return asUTC.Unix() - int64(off), true
}

// cdfTime is cdf_timestamp_to_timespec followed by cdf_ctime: the
// reference's own, approximate, calendar arithmetic, then mktime and
// ctime in local time (which cancel), so the fields are printed as
// computed; a year past 9999 or a time past MAX_CTIME is "*Bad*".
func cdfTime(t int64) string { // timestamp
	t /= cdfTimePrec
	sec := int(t % 60)
	t /= 60
	minute := int(t % 60)
	t /= 60
	hour := int(t % 24)
	t /= 24
	year := int(cdfBaseYear + t/365)
	if year > 9999 {
		return "*Bad*"
	}
	t -= int64(cdfDays(year)) - 1
	day := cdfGetDay(year, int(t))
	month := cdfGetMonth(year, int(t))
	tm := time.Date(year, time.Month(month+1), day, hour, minute, sec, 0, time.Local)
	if tm.Unix() > maxCTime {
		return "*Bad* 0x" + pad16(bitsOfInt64(tm.Unix()))
	}
	return tm.Format("Mon Jan _2 15:04:05 2006")
}

func pad16(v uint64) string {
	invariant.Check(v > maxCTime, "only bad timestamps are printed in hex")
	s := strconv.FormatUint(v, 16)
	for n := len(s); n < 16; n++ {
		s = "0" + s
	}
	return s
}

func isLeap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }

// cdfDays is cdf_getdays: days from 1601 to the start of year.
func cdfDays(year int) int {
	invariant.Check(year >= cdfBaseYear && year <= 9999, "year within the calendar")
	days := 0
	for y := cdfBaseYear; y < year; y++ {
		days += 365
		if isLeap(y) {
			days++
		}
	}
	return days
}

// monthDays is the length of month m (0-based) in a non-leap year.
func monthDays(m int) int {
	switch m {
	case 1:
		return 28
	case 3, 5, 8, 10:
		return 30
	default:
		return 31
	}
}

// cdfGetDay is cdf_getday.
func cdfGetDay(year, days int) int {
	for m := 0; m < 12; m++ {
		sub := monthDays(m)
		if m == 1 && isLeap(year) {
			sub++
		}
		if days < sub {
			return days
		}
		days -= sub
	}
	return days
}

// cdfGetMonth is cdf_getmonth.
func cdfGetMonth(year, days int) int {
	for m := 0; m < 12; m++ { // month
		days -= monthDays(m)
		if m == 1 && isLeap(year) {
			days--
		}
		if days <= 0 {
			return m
		}
	}
	return 12
}
