// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from mprint and varexpand in softmagic.c and file_printable,
// file_print_guid, file_fmtdatetime, file_fmtdate, file_fmttime and
// file_fmtnum in funcs.c and print.c, file 5.48, Copyright (c) Ian F.
// Darwin 1986-1995 (see COPYING). The printf engine is this module's own
// (fmt is not used where its semantics differ from C's printf).

package softmagic

import (
	"github.com/eitanity/softmagic/internal/invariant"

	"encoding/binary"
	"math"
	"strconv"
	"time"
)

// mprint prints the line's description with its value substituted.
func (s *scan) mprint(m *record, f *frame) { // rule
	invariant.Check(f.idx >= 0 && f.idx < f.count, "printing a line within the frame")
	invariant.Check(m.hasDesc(), "printing a line with a description")
	s.noteRule(f.first + f.idx)
	desc := varexpand(m.descString(), s.execBit)
	v := s.value[:] // valueImage
	switch {
	case m.typ == tByte:
		s.printInt(m, desc, uint64(v[0]), 8)
	case m.typ == tShort || m.typ == tBeShort || m.typ == tLeShort:
		s.printInt(m, desc, uint64(binary.LittleEndian.Uint16(v)), 16)
	case m.typ == tLong || m.typ == tBeLong || m.typ == tLeLong || m.typ == tMeLong:
		s.printInt(m, desc, uint64(binary.LittleEndian.Uint32(v)), 32)
	case m.typ == tQuad || m.typ == tBeQuad || m.typ == tLeQuad || m.typ == tOffset:
		s.printInt(m, desc, binary.LittleEndian.Uint64(v), 64)
	case m.typ == tString || m.typ == tPString || m.typ == tBeString16 || m.typ == tLeString16:
		s.printString(m, desc)
	case isDateType(m.typ):
		s.printfStr(desc, []byte(fmtDateTime(m.typ, v)))
	case isFloatType(m.typ):
		s.printFloat(desc, float64(math.Float32frombits(binary.LittleEndian.Uint32(v))))
	case isDoubleType(m.typ):
		s.printFloat(desc, math.Float64frombits(binary.LittleEndian.Uint64(v)))
	case m.typ == tSearch || m.typ == tRegex:
		s.printSearch(m, desc)
	case m.typ == tDefault || m.typ == tClear:
		s.writeString(m.descString())
	case m.typ == tIndirect || m.typ == tUse || m.typ == tName:
	default:
		s.mprintOther(m, desc)
	}
}

// mprintOther prints the DER, GUID, DOS date and time and octal types.
func (s *scan) mprintOther(m *record, desc string) { // rule
	invariant.Check(m.hasDesc(), "printing a line with a description")
	v := s.value[:] // valueImage
	switch m.typ {
	case tDer:
		s.printfStr(desc, printable(s.rxScratch(printableMax), v, maxString, s.raw || s.safe))
	case tGUID, tLeGUID:
		s.printfStr(desc, []byte(guidString(v, false)))
	case tBeGUID:
		s.printfStr(desc, []byte(guidString(v, true)))
	case tMSDOSDate, tBeMSDOSDate, tLeMSDOSDate:
		s.printfStr(desc, []byte(fmtMSDOSDate(binary.LittleEndian.Uint16(v))))
	case tMSDOSTime, tBeMSDOSTime, tLeMSDOSTime:
		s.printfStr(desc, []byte(fmtMSDOSTime(binary.LittleEndian.Uint16(v))))
	case tOctal:
		s.printfStr(desc, []byte(fmtNumber(m.valueBytes(), 8)))
	default:
		s.fail("mprint on a type it does not handle")
	}
}

func isDateType(t fileType) bool {
	switch t {
	case tDate, tBeDate, tLeDate, tMeDate, tLDate, tBeLDate, tLeLDate, tMeLDate,
		tQDate, tBeQDate, tLeQDate, tQLDate, tBeQLDate, tLeQLDate, tQWDate, tBeQWDate, tLeQWDate:
		return true
	default:
		return false
	}
}

// printInt is the PRINTER macro: the value sign-extended for the type,
// then printed with the description's conversion as a C integer of the
// type's promoted width, or as a string when the description uses %s.
func (s *scan) printInt(m *record, desc string, raw uint64, bits int) {
	invariant.Check(!isString(m.typ), "integer line")
	invariant.Check(bits == 8 || bits == 16 || bits == 32 || bits == 64, "integer width")
	v := signExtend(&m.recordHead, raw) // signedValue
	unsigned := m.flag&flagUnsigned != 0
	if hasStringConv(desc) {
		var num string
		if unsigned {
			num = strconv.FormatUint(v&widthMask(promoted(bits)), 10)
		} else {
			num = strconv.FormatInt(extend(v, promoted(bits), true), 10)
		}
		s.printfStr(desc, []byte(num))
		return
	}
	s.printfNum(desc, v, !unsigned, promoted(bits))
}

// promoted is the width of the C argument printf sees: int for narrower
// types, long long for quads.
func promoted(bits int) int {
	if bits < 32 {
		return 32
	}
	return bits
}

// hasStringConv is check_fmt: the description's conversion is a %s form.
func hasStringConv(desc string) bool {
	i := indexFrom(desc, 0, '%')
	if i >= len(desc) {
		return false
	}
	j := i + 1
	for ; j < len(desc) && (desc[j] == '-' || desc[j] == '.' || cIsDigit(desc[j])); j++ {
	}
	return at([]byte(desc), j) == 's'
}

// printString is mprint's string case: the rule's own string for = and
// !, otherwise the file's bytes, truncated at CR or LF when the rule
// string is empty and trimmed when /T says so.
func (s *scan) printString(m *record, desc string) { // rule
	invariant.Check(m.typ == tString || m.typ == tPString || m.typ == tBeString16 || m.typ == tLeString16, "string line")
	if m.reln == '=' || m.reln == '!' {
		s.printfStr(desc, printable(s.rxScratch(printableMax), m.value, maxString, s.raw || s.safe))
		return
	}
	str := s.value[:]
	if m.value[0] == 0 {
		truncateAtNewline(str)
	}
	if m.strFlags()&strTrim != 0 {
		str = trimSpace(str)
	}
	s.printfStr(desc, printable(s.rxScratch(printableMax), str, len(str), s.raw || s.safe))
}

// printSearch prints the bytes a search or regex matched.
func (s *scan) printSearch(m *record, desc string) { // rule
	invariant.Check(s.search.rmLen >= 0, "match length non-negative")
	invariant.Check(s.search.start <= len(s.buf), "search start within the buffer")
	if !s.search.valid {
		return
	}
	end := s.search.start + s.search.rmLen
	if end > len(s.buf) {
		end = len(s.buf)
	}
	str := s.buf[s.search.start:end]
	if nul := indexByteFrom(str, 0, 0); nul >= 0 {
		str = str[:nul] // strndup stops at a NUL
	}
	if m.strFlags()&strTrim != 0 {
		str = trimSpace(str)
	}
	s.printfStr(desc, printable(s.rxScratch(printableMax), str, len(str), s.raw || s.safe))
}

// trimSpace is file_strtrim: leading and trailing C whitespace removed
// from the C string in b, which ends at its first NUL.
func trimSpace(b []byte) []byte { // text
	if nul := indexByteFrom(b, 0, 0); nul >= 0 {
		b = b[:nul]
	}
	i := 0 // start
	for ; i < len(b) && cIsSpace(b[i]); i++ {
	}
	j := len(b)
	for ; j > i && cIsSpace(b[j-1]); j-- {
	}
	invariant.Check(i <= j && j <= len(b), "trim bounds ordered")
	return b[i:j]
}

// printable is file_printable: the string up to its NUL or n bytes, with
// non-printable bytes as \ooo escapes unless raw (MAGIC_RAW), in a buffer
// of bufsiz bytes.
func printable(buf, str []byte, n int, raw bool) []byte { // maxLength
	invariant.Check(len(buf) <= regexScratchSize, "printable buffer bounded")
	invariant.Check(len(buf) >= 4, "printable buffer holds an escape")
	invariant.Check(n >= 0, "length non-negative")
	out := 0
	limit := len(buf) - 1
	for i := 0; i < n && i < len(str) && str[i] != 0 && out < limit; i++ {
		c := str[i] // char
		if raw || cIsPrint(c) {
			buf[out] = c
			out++
			continue
		}
		if out >= limit-3 {
			break
		}
		buf[out] = '\\'
		buf[out+1] = '0' + (c>>6)&7
		buf[out+2] = '0' + (c>>3)&7
		buf[out+3] = '0' + c&7
		out += 4
	}
	return buf[:out]
}

// printFloat is mprint's float case: %g through the description's own
// conversion, or formatted and printed with %s.
func (s *scan) printFloat(desc string, f float64) {
	if hasStringConv(desc) {
		s.printfStr(desc, []byte(formatCFloat(f, 'g', 6)))
		return
	}
	s.printfFloat(desc, f)
}

// varexpand expands ${x?a:b} in a description or MIME type: a when the
// input is executable (the caller's permission bit, or the ELF built-in's
// verdict), else b.
func varexpand(str string, exec bool) string {
	invariant.Check(len(str) <= maxMime, "text fits the larger of MAXDESC and MAXMIME")
	out := ""
	rest := str
	for n := 0; n < maxDesc; n++ {
		i := indexSubstr(rest, "${") // placeholderStart
		if i < 0 {
			return out + rest
		}
		j := i + 2 // nameStart
		if j+1 >= len(rest) || rest[j] != 'x' || rest[j+1] != '?' {
			return out + rest
		}
		colon := indexFrom(rest, j+2, ':')
		if colon >= len(rest) {
			return out + rest
		}
		brace := indexFrom(rest, colon+1, '}')
		if brace >= len(rest) {
			return out + rest
		}
		if exec {
			out += rest[:i] + rest[j+2:colon]
		} else {
			out += rest[:i] + rest[colon+1:brace]
		}
		rest = rest[brace+1:]
	}
	return out + rest
}

// indexSubstr is strings.Index for a two-byte needle.
func indexSubstr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// guidString is file_print_guid: the GUID as %.8X-%.4X-%.4X-%.2X%.2X-...
// from the union image; a big-endian GUID has its first three fields
// byte-swapped first.
func guidString(v []byte, be bool) string { // guidImage
	invariant.Check(len(v) >= 16, "GUID image complete")
	d1 := binary.LittleEndian.Uint32(v[0:4]) // data1
	d2 := binary.LittleEndian.Uint16(v[4:6]) // data2
	d3 := binary.LittleEndian.Uint16(v[6:8]) // data3
	if be {
		d1 = binary.BigEndian.Uint32(v[0:4])
		d2 = binary.BigEndian.Uint16(v[4:6])
		d3 = binary.BigEndian.Uint16(v[6:8])
	}
	var b [36]byte // text
	hexUpper(b[0:8], uint64(d1))
	b[8] = '-'
	hexUpper(b[9:13], uint64(d2))
	b[13] = '-'
	hexUpper(b[14:18], uint64(d3))
	b[18] = '-'
	hexUpper(b[19:21], uint64(v[8]))
	hexUpper(b[21:23], uint64(v[9]))
	b[23] = '-'
	for k := 0; k < 6; k++ {
		hexUpper(b[24+2*k:26+2*k], uint64(v[10+k]))
	}
	return string(b[:])
}

// hexUpper writes v as upper-case hex into exactly len(dst) digits.
func hexUpper(dst []byte, v uint64) {
	const digits = "0123456789ABCDEF"
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = digits[v&0xf]
		v >>= 4
	}
}

// maxCTime is the reference's MAX_CTIME: the last second of year 9999.
const maxCTime = 0x3afff487cf

// fmtDateTime is file_fmtdatetime: asctime's format, in UTC or local time,
// from a 32- or 64-bit second count or a Windows FILETIME.
func fmtDateTime(t fileType, v []byte) string { // dateImage
	invariant.Check(isDateType(t), "date type")
	invariant.Check(len(v) >= 8, "date image complete")
	var secs int64
	local, windows := false, false
	switch t {
	case tDate, tBeDate, tLeDate, tMeDate:
		secs = int64(binary.LittleEndian.Uint32(v))
	case tLDate, tBeLDate, tLeLDate, tMeLDate:
		secs, local = int64(binary.LittleEndian.Uint32(v)), true
	case tQDate, tBeQDate, tLeQDate:
		secs = int64FromBits(binary.LittleEndian.Uint64(v))
	case tQLDate, tBeQLDate, tLeQLDate:
		secs, local = int64FromBits(binary.LittleEndian.Uint64(v)), true
	default: // the qwdate family
		secs, windows = int64FromBits(binary.LittleEndian.Uint64(v)), true
	}
	if windows {
		// file_fmtdatetime converts a FILETIME through
		// cdf_timestamp_to_timespec, local time and all, then prints it in UTC.
		s, ok := cdfTimestamp(secs)
		if !ok {
			return "*Invalid datetime*"
		}
		secs = s
	}
	if secs > maxCTime {
		return "*Invalid datetime*"
	}
	tm := time.Unix(secs, 0).UTC()
	if local {
		tm = tm.Local()
	}
	return tm.Format("Mon Jan _2 15:04:05 2006")
}

// fmtMSDOSDate is file_fmtdate: strftime "%b %d %Y" of a DOS date.
func fmtMSDOSDate(v uint16) string { // dosDate
	invariant.Check(v>>9 <= 127, "year field within seven bits")
	day := int(v & 0x1f)
	mon := int((v>>5)&0xf) - 1
	if mon < 0 || mon > 11 {
		mon = 0
	}
	year := int(v>>9) + 1980
	tm := time.Date(year, time.Month(mon+1), 1, 0, 0, 0, 0, time.UTC)
	return tm.Format("Jan") + " " + pad2(day) + " " + strconv.Itoa(year)
}

// fmtMSDOSTime is file_fmttime: strftime "%T" of a DOS time.
func fmtMSDOSTime(v uint16) string {
	invariant.Check(v>>11 <= 31, "hour field within five bits")
	sec := int(v&0x1f) * 2
	minute := int((v >> 5) & 0x3f)
	hour := int(v >> 11)
	return pad2(hour) + ":" + pad2(minute) + ":" + pad2(sec)
}

func pad2(n int) string {
	if n < 10 && n >= 0 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// fmtNumber is file_fmtnum: the string parsed in the base and printed in
// decimal, or "*Invalid number*".
func fmtNumber(b []byte, base uint64) string { // numberText
	invariant.Check(len(b) <= maxString, "number text within MAXstring")
	invariant.Check(base == 8 || base == 10 || base == 16, "supported base")
	n := 0
	for ; n < len(b) && b[n] != 0; n++ {
	}
	v, end, ok := strtoull(b[:n], 0, base)
	if !ok || end != n {
		return "*Invalid number*"
	}
	return strconv.FormatUint(v, 10)
}
