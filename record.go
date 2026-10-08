// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// record mirrors struct magic from file.h, file 5.48, Copyright (c) Ian F.
// Darwin 1986-1995 (see COPYING). Its field order and widths are the
// tie-break of the entry sort, which compares records as bytes, and are not
// to be rearranged.

package softmagic

import (
	"encoding/binary"

	"github.com/eitanity/softmagic/internal/invariant"
)

// Sizes from file.h.
const (
	maxDesc   = 64  // MAXDESC
	maxMime   = 80  // MAXMIME
	maxExt    = 120 // MAXEXT
	maxString = 128 // MAXstring
	maxApple  = 8
	// recordSize is FILE_MAGICSIZE: sizeof(struct magic) on the reference.
	recordSize = 432
)

// record.flag bits.
const (
	flagIndir       uint16 = 0x01
	flagOffAdd      uint16 = 0x02
	flagIndirOffAdd uint16 = 0x04
	flagUnsigned    uint16 = 0x08
	flagNoSpace     uint16 = 0x10
	flagBinTest     uint16 = 0x20
	flagTextTest    uint16 = 0x40
	flagOffNegative uint16 = 0x80
	flagOffPositive uint16 = 0x100
)

// String modifier bits (str_flags).
const (
	strCompactWhitespace         uint32 = 1 << 0
	strCompactOptionalWhitespace uint32 = 1 << 1
	strIgnoreLowercase           uint32 = 1 << 2
	strIgnoreUppercase           uint32 = 1 << 3
	regexOffsetStart             uint32 = 1 << 4
	strTextTest                  uint32 = 1 << 5
	strBinTest                   uint32 = 1 << 6
	pstring1LE                   uint32 = 1 << 7 // also PSTRING_1_BE
	pstring2BE                   uint32 = 1 << 8
	pstring2LE                   uint32 = 1 << 9
	pstring4BE                   uint32 = 1 << 10
	pstring4LE                   uint32 = 1 << 11 // also REGEX_LINE_COUNT
	regexLineCount               uint32 = 1 << 11
	pstringLen                          = pstring1LE | pstring2LE | pstring2BE | pstring4LE | pstring4BE
	pstringLengthIncludesItself  uint32 = 1 << 12
	strTrim                      uint32 = 1 << 13
	strFullWord                  uint32 = 1 << 14
	indirectRelative             uint32 = 1 << 0
	stringDefaultRange           uint32 = 100
)

// Mask / indirect operators (FILE_OP*).
const (
	opAnd      uint8 = 0
	opOr       uint8 = 1
	opXor      uint8 = 2
	opAdd      uint8 = 3
	opMinus    uint8 = 4
	opMultiply uint8 = 5
	opDivide   uint8 = 6
	opModulo   uint8 = 7
	opsMask    uint8 = 0x07
	opSigned   uint8 = 0x20
	opInverse  uint8 = 0x40
	opIndirect uint8 = 0x80
)

// recordHead is struct magic's words 1-3: the scalar fields every rule
// line carries, in the reference's order. The raw unions keep the
// reference's memory image so the tie-break can compare bytes rather than
// reinterpret them.
type recordHead struct {
	flag      uint16
	contLevel uint8
	factor    uint8
	reln      uint8
	vallen    uint8
	typ       fileType
	inType    fileType
	inOp      uint8
	maskOp    uint8
	dummy     uint8 // `cond` when ENABLE_CONDITIONALS; zero in the reference build
	factorOp  uint8
	offset    int32
	inOffset  int32
	lineno    uint32
	// maskOrStr is union _u: num_mask for numeric types, or on a
	// little-endian host str_range in the low and str_flags in the high word.
	maskOrStr uint64
}

// record is one rule line as the matcher reads it. Its byte fields are
// slices into storage the database owns and never writes after
// compilation: value holds at least valueMin bytes, zero padded, so a
// numeric value is always readable as 8 or 16 bytes; the others hold
// exactly their text, with no NUL padding.
type record struct {
	// value is union VALUETYPE as bytes: a little-endian integer in [0:8],
	// a float in [0:4], a double in [0:8], a GUID in [0:16], or a string of
	// vallen bytes.
	value    []byte
	desc     []byte
	mimetype []byte
	apple    []byte
	ext      []byte
	recordHead
}

// valueMin is the shortest value slice: room for a GUID.
const valueMin = 16

// lineRec is a rule line while the compiler builds it: struct magic with
// its fixed arrays, which the parser writes into and the sort compares
// as a memory image. It becomes a record when its entry is complete.
type lineRec struct {
	recordHead
	value    [maxString]byte
	desc     [maxDesc]byte
	mimetype [maxMime]byte
	apple    [maxApple]byte
	ext      [maxExt]byte
}

func (r *recordHead) strRange() uint32 { return low32(r.maskOrStr) }
func (r *recordHead) strFlags() uint32 { return low32(r.maskOrStr >> 32) }

func (r *recordHead) setStrRange(v uint32) {
	r.maskOrStr = r.maskOrStr&^0xffffffff | uint64(v)
}

func (r *recordHead) setStrFlags(v uint32) {
	r.maskOrStr = r.maskOrStr&0xffffffff | uint64(v)<<32
}

func (r *lineRec) setValueQ(v uint64) { binary.LittleEndian.PutUint64(r.value[0:8], v) }

// valueString is value.s up to the first NUL, which is how the C code reads
// it. For string types vallen is the authoritative length (it may include
// embedded NULs); see valueBytes.
func (r *record) valueString() string {
	invariant.Check(r.vallen <= maxString, "value length within MAXstring")
	invariant.Check(len(r.value) >= valueMin, "value holds its minimum")
	return cString(r.value)
}

func (r *lineRec) valueString() string {
	invariant.Check(r.vallen <= maxString, "value length within MAXstring")
	return cString(r.value[:])
}

// valueBytes is the vallen-long string value for string types.
func (r *record) valueBytes() []byte {
	invariant.Check(r.vallen <= maxString, "value length within MAXstring")
	invariant.Check(int(r.vallen) <= len(r.value), "value holds vallen bytes")
	return r.value[:r.vallen]
}

func (r *lineRec) valueBytes() []byte {
	invariant.Check(r.vallen <= maxString, "value length within MAXstring")
	return r.value[:r.vallen]
}

func (r *record) descString() string  { return cString(r.desc) }
func (r *record) mimeString() string  { return cString(r.mimetype) }
func (r *lineRec) descString() string { return cString(r.desc[:]) }

// hasDesc is the reference's `m->desc[0] != '\0'`: an empty description
// may still carry the rule file's name after its NUL for the tie-break.
func (r *record) hasDesc() bool  { return len(r.desc) > 0 && r.desc[0] != 0 }
func (r *record) hasMime() bool  { return len(r.mimetype) > 0 && r.mimetype[0] != 0 }
func (r *record) hasExt() bool   { return len(r.ext) > 0 && r.ext[0] != 0 }
func (r *record) hasApple() bool { return len(r.apple) > 0 && r.apple[0] != 0 }

// cString is the NUL-terminated prefix of a byte field, or all of it.
func cString(b []byte) string {
	n := 0
	for ; n < len(b) && b[n] != 0; n++ {
	}
	return string(b[:n])
}

// valueNeed is how many bytes a line's value slice must hold: a GUID, or
// the longer of a numeric value and the string's vallen.
func valueNeed(h *recordHead) int { // head
	invariant.Check(h.vallen <= maxString, "value length within MAXstring")
	if h.typ == tGUID || h.typ == tLeGUID || h.typ == tBeGUID {
		return valueMin
	}
	if int(h.vallen) > 8 {
		return int(h.vallen)
	}
	return 8
}

// trimNul is a fixed array's content: everything before the NUL padding.
func trimNul(a []byte) []byte {
	n := len(a)
	for ; n > 0 && a[n-1] == 0; n-- {
	}
	return a[:n]
}

// arena hands out byte slices from chunks that are never reallocated, so
// a slice stays valid for the life of the database that holds it (the
// slices themselves keep the chunks alive). Allocation happens at
// compile or load time only, never while identifying.
type arena struct {
	chunk []byte
}

// arenaChunk is the size of a fresh chunk.
const arenaChunk = 256 * 1024

// take returns a zeroed slice of n bytes.
func (a *arena) take(n int) []byte { // size
	invariant.Check(n >= 0, "size non-negative")
	if len(a.chunk) < n {
		size := arenaChunk
		if n > size {
			size = n
		}
		a.chunk = make([]byte, size)
	}
	out := a.chunk[:n:n]
	a.chunk = a.chunk[n:]
	return out
}

// copyIn returns a slice of at least need bytes holding b, zero padded.
func (a *arena) copyIn(b []byte, need int) []byte { // src
	invariant.Check(need >= 0, "need non-negative")
	if need < len(b) {
		need = len(b)
	}
	out := a.take(need)
	copy(out, b)
	return out
}

// intern converts a built line into a record whose byte fields live in
// the arena.
func (r *lineRec) intern(a *arena) record { // arena
	invariant.Check(r.vallen <= maxString, "value length within MAXstring")
	need := valueNeed(&r.recordHead)
	invariant.Check(need >= 8 && need <= maxString, "value need within the array")
	return record{
		recordHead: r.recordHead,
		value:      a.copyIn(r.value[:need], valueMin),
		desc:       a.copyIn(trimNul(r.desc[:]), 0),
		mimetype:   a.copyIn(trimNul(r.mimetype[:]), 0),
		apple:      a.copyIn(trimNul(r.apple[:]), 0),
		ext:        a.copyIn(trimNul(r.ext[:]), 0),
	}
}

// image writes the record as the reference's 432-byte little-endian memory
// image with lineno zeroed: exactly what apprentice_sort hands to memcmp.
func (r *lineRec) image(out *[recordSize]byte) {
	invariant.Check(r.vallen <= maxString, "value length within MAXstring")
	le := binary.LittleEndian // littleEndian
	le.PutUint16(out[0:2], r.flag)
	out[2] = r.contLevel
	out[3] = r.factor
	out[4] = r.reln
	out[5] = r.vallen
	out[6] = uint8(r.typ)
	out[7] = uint8(r.inType)
	out[8] = r.inOp
	out[9] = r.maskOp
	out[10] = r.dummy
	out[11] = r.factorOp
	le.PutUint32(out[12:16], bitsOfInt32(r.offset))
	le.PutUint32(out[16:20], bitsOfInt32(r.inOffset))
	le.PutUint32(out[20:24], 0) // lineno
	le.PutUint64(out[24:32], r.maskOrStr)
	copy(out[32:160], r.value[:])
	copy(out[160:224], r.desc[:])
	copy(out[224:304], r.mimetype[:])
	copy(out[304:312], r.apple[:])
	copy(out[312:432], r.ext[:])
}
