// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from file_mdump in print.c and file_showstr and
// file_varint2uintmax_t in apprentice.c, file 5.48, Copyright (c) Ian F.
// Darwin 1986-1995 (see COPYING): what file -c prints for each rule line
// as it is parsed.

package softmagic

import (
	"encoding/binary"
	"math"
	"strconv"
	"strings"

	"github.com/eitanity/softmagic/internal/invariant"
)

// DumpSources is file -c over rule sources: each rule line in the order
// read, in libmagic's parsed form, one per line as file_mdump prints it.
// The text is what was dumped before an error, if there was one; the
// reference prints a warning for a refused line and goes on, where this
// returns the CompileError.
func DumpSources(srcs []Source, o CompileOptions) (string, error) {
	var b strings.Builder
	c := compiler{sourceDir: o.SourceDir, tables: newTypeTables(), base: o.Base, dump: &b}
	if c.sourceDir == "" {
		c.sourceDir = "magic/Magdir"
	}
	c.files = make([]string, 0, len(srcs))
	for fileIdx, src := range srcs {
		c.fileIdx = smallInt32(fileIdx)
		c.files = append(c.files, src.Name)
		if err := c.loadFile(src.Name, src.Data); err != nil {
			return b.String(), err
		}
	}
	_, err := c.finish()
	return b.String(), err
}

// dumpOps is FILE_OPS: the operator characters, by FILE_OP* number.
const dumpOps = "&|^+-*/%"

// mdump is file_mdump for the line just parsed.
func (p *lineParser) mdump(b *strings.Builder) {
	invariant.Check(b != nil && p.rec != nil, "a dump of a parsed line")
	r := p.rec
	invariant.Check(r.desc[maxDesc-1] == 0, "description terminated")
	if r.desc[0] == 0 {
		b.WriteString(cString(r.desc[1:])) // the file name tucked in after the NUL
	} else {
		b.WriteString("*unknown*")
	}
	b.WriteString(", " + strconv.FormatUint(uint64(r.lineno), 10) + ": ")
	b.WriteString(">>>>>>>>"[:int(r.contLevel&7)+1])
	b.WriteString(" " + strconv.Itoa(int(r.offset)))
	if r.flag&flagIndir != 0 {
		b.WriteString("(" + p.typeName(r.inType) + ",")
		if r.inOp&opInverse != 0 {
			b.WriteByte('~')
		}
		b.WriteByte(dumpOps[r.inOp&opsMask])
		b.WriteString(strconv.Itoa(int(r.inOffset)) + "),")
	}
	b.WriteByte(' ')
	if r.flag&flagUnsigned != 0 {
		b.WriteByte('u')
	}
	b.WriteString(p.typeName(r.typ))
	if r.maskOp&opInverse != 0 {
		b.WriteByte('~')
	}
	dumpModifiers(b, &r.recordHead)
	b.WriteString("," + string(rune(r.reln)))
	if r.reln != 'x' {
		dumpValue(b, r)
	}
	b.WriteString(",\"" + r.descString() + "\"]\n")
}

// typeName is file_names[t]: type_tbl's name for the type.
func (p *lineParser) typeName(t fileType) string {
	invariant.Check(p.tables != nil, "type tables")
	for _, e := range p.tables.types {
		if e.typ == t && e.name != "" {
			return e.name
		}
	}
	return "*bad type"
}

// dumpModifiers is the string flags and range, or the mask operator and
// mask, after the type.
func dumpModifiers(b *strings.Builder, r *recordHead) {
	invariant.Check(b != nil, "dump buffer")
	if !isString(r.typ) {
		b.WriteByte(dumpOps[r.maskOp&opsMask])
		if r.maskOrStr != 0 {
			s := strconv.FormatUint(r.maskOrStr, 16)
			b.WriteString(strings.Repeat("0", max(0, 8-len(s))) + s) // %.8llx
		}
		return
	}
	if fl := r.strFlags(); fl != 0 {
		b.WriteByte('/')
		for _, f := range []struct {
			bit uint32
			c   byte
		}{
			{strCompactWhitespace, 'W'}, {strCompactOptionalWhitespace, 'w'},
			{strIgnoreLowercase, 'c'}, {strIgnoreUppercase, 'C'}, {regexOffsetStart, 's'},
			{strTextTest, 't'}, {strBinTest, 'b'}, {pstring1LE, 'B'}, {pstring2BE, 'H'},
			{pstring2LE, 'h'}, {pstring4BE, 'L'}, {pstring4LE, 'l'}, {pstringLengthIncludesItself, 'J'},
		} {
			if fl&f.bit != 0 {
				b.WriteByte(f.c)
			}
		}
	}
	if rg := r.strRange(); rg != 0 {
		b.WriteString("/" + strconv.FormatUint(uint64(rg), 10))
	}
}

// dumpValue is the value as file_mdump prints it for the line's type.
func dumpValue(b *strings.Builder, r *lineRec) {
	invariant.Check(b != nil && r != nil, "dump of a value")
	v := r.value[:]
	switch r.typ {
	case tByte, tShort, tLong, tLeShort, tLeLong, tMeLong, tBeShort, tBeLong, tIndirect:
		b.WriteString(strconv.FormatInt(int64(wrapInt32(int64(binary.LittleEndian.Uint32(v)))), 10)) // %d of int32
	case tBeQuad, tLeQuad, tQuad, tOffset:
		b.WriteString(strconv.FormatInt(int64FromBits(binary.LittleEndian.Uint64(v)), 10))
	case tPString, tString, tRegex, tBeString16, tLeString16, tSearch:
		showStr(b, v[:r.vallen])
	case tFloat, tBeFloat, tLeFloat:
		b.WriteString(upper(formatCFloat(float64(math.Float32frombits(binary.LittleEndian.Uint32(v))), 'g', 6)))
	case tDouble, tBeDouble, tLeDouble:
		b.WriteString(upper(formatCFloat(math.Float64frombits(binary.LittleEndian.Uint64(v)), 'g', 6)))
	case tLeVarint, tBeVarint:
		b.WriteString(strconv.FormatInt(int64FromBits(varint(v, r.typ == tLeVarint)), 10))
	case tMSDOSDate, tBeMSDOSDate, tLeMSDOSDate:
		b.WriteString(fmtMSDOSDate(binary.LittleEndian.Uint16(v)) + ",")
	case tMSDOSTime, tBeMSDOSTime, tLeMSDOSTime:
		b.WriteString(fmtMSDOSTime(binary.LittleEndian.Uint16(v)) + ",")
	case tOctal:
		b.WriteString(fmtNumber(v, 8))
	case tDefault:
	case tUse, tName, tDer:
		b.WriteString("'" + cString(v) + "'")
	case tLeGUID, tGUID:
		b.WriteString(guidString(v, false))
	case tBeGUID:
		b.WriteString(guidString(v, true))
	default:
		if isDateType(r.typ) {
			b.WriteString(fmtDateTime(r.typ, v) + ",")
			return
		}
		b.WriteString("*bad type " + strconv.Itoa(int(r.typ)) + "*")
	}
}

// showStr is file_showstr: printable ASCII as itself, the C escapes by
// letter, anything else as three octal digits.
func showStr(b *strings.Builder, s []byte) {
	invariant.Check(len(s) <= maxString, "string value within MAXstring")
	const letters = "\a\b\f\n\r\t\v"
	for _, c := range s {
		switch i := strings.IndexByte(letters, c); {
		case c >= 040 && c <= 0176:
			b.WriteByte(c)
		case i >= 0:
			b.WriteByte('\\')
			b.WriteByte("abfnrtv"[i])
		default:
			b.WriteString("\\" + string([]byte{'0' + c>>6, '0' + c>>3&7, '0' + c&7}))
		}
	}
}

// varint is file_varint2uintmax_t over a value's bytes, which end at a NUL.
// The little-endian form shifts once more after its last byte, as the
// reference's loop does.
func varint(v []byte, le bool) uint64 {
	invariant.Check(len(v) >= valueMin, "value holds its minimum")
	n := indexByteFrom(v, 0, 0)
	if n < 0 {
		n = len(v)
	}
	var x uint64
	if !le {
		for i := range n {
			x |= uint64(v[i] & 0x7f)
			if v[i]&0x80 == 0 {
				break
			}
			x <<= 7
		}
		return x
	}
	last := n
	for i := range n {
		if v[i]&0x80 == 0 {
			last = i
			break
		}
	}
	if last == len(v) {
		last--
	}
	for i := range last + 1 {
		x |= uint64(v[last-i] & 0x7f)
		x <<= 7
	}
	return x
}
