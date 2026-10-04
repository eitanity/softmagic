// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from readcdf.c, file 5.48, Copyright (c) 2008 Christos Zoulas
// (see COPYING): what the CDF built-in prints.

package softmagic

import (
	"encoding/binary"
	"math"
	"strconv"

	"github.com/eitanity/softmagic/internal/invariant"
)

// detectCDF is file_trycdf, run once for the description and once for the
// MIME type, as the reference is run twice by `file` and `file -i`.
func (s *scan) detectCDF() builtinResult {
	invariant.Check(len(s.buf) >= 2, "detectors run on two or more bytes")
	if _, ok := cdfReadHeader(s.buf); !ok {
		return builtinResult{}
	}
	desc, hit := s.cdfRun(false)
	if !hit {
		return builtinResult{}
	}
	mime, mimeHit := s.cdfRun(true)
	if !mimeHit || mime == "" {
		mime = "application/x-ole-storage"
	}
	return builtinResult{desc: desc, mime: mime, hit: true}
}

// cdfRun parses the document and prints in one mode; the printed text is
// returned and removed from the output.
func (s *scan) cdfRun(mime bool) (string, bool) {
	start := s.outLen
	pr := cdfPrinter{s: s, mime: mime}
	c := &cdfFile{s: s, buf: s.buf, root: -1, streamSlot: 3}
	var ok bool
	c.h, ok = cdfReadHeader(s.buf)
	invariant.Check(ok, "header checked by detectCDF")
	i, expn := pr.body(c)
	if i == -1 {
		// The reference's default handler.
		if pr.notMime() {
			pr.write("Composite Document File V2 Document")
			if expn != "" {
				pr.write(", " + expn)
			}
		} else {
			pr.write("application/x-ole-storage")
		}
		i = 1
	}
	text := string(s.out[start:s.outLen])
	s.outLen = start
	return text, i != 0
}

// body is the sequence of attempts in file_trycdf; it returns the
// reference's i and the explanation for the default handler.
func (pr cdfPrinter) body(c *cdfFile) (int, string) {
	switch {
	case !c.readSAT():
		return -1, "Can't read SAT"
	case !c.readSSAT():
		return -1, "Can't read SSAT"
	case !c.readDir():
		return -1, "Can't read directory"
	case !c.readShortStream():
		return -1, "Cannot read short stream"
	}
	if st, found, ok := c.readUserStream("FileHeader"); found && ok && isHWP5(&st) {
		if pr.notMime() {
			pr.write("Hancom HWP (Hangul Word Processor) file, version 5.0")
		} else {
			pr.write("application/x-hwp")
		}
		return 1, ""
	}
	i, expn := pr.trySummary(c, "\x05SummaryInformation")
	if i <= 0 {
		var e2 string
		i, e2 = pr.trySummary(c, "\x05DocumentSummaryInformation")
		if e2 != "" {
			expn = e2
		}
	}
	if i <= 0 {
		i = pr.dirInfo(c)
		if i < 0 {
			expn = "Cannot read section info"
		}
	}
	return i, expn
}

func isHWP5(st *cdfStream) bool {
	const sig = "HWP Document File"
	return st.size() >= len(sig) && string(st.tab[:len(sig)]) == sig
}

// trySummary reads a summary-information stream and reports on it.
func (pr cdfPrinter) trySummary(c *cdfFile, name string) (int, string) {
	st, found, ok := c.readUserStream(name)
	if !found {
		return -1, ""
	}
	if !ok {
		return -1, "Cannot read summary info"
	}
	return pr.checkSummaryInfo(c, &st)
}

// checkSummaryInfo is cdf_check_summary_info.
func (pr cdfPrinter) checkSummaryInfo(c *cdfFile, st *cdfStream) (int, string) {
	i := pr.fileSummaryInfo(c, st)
	if i < 0 {
		return i, "Can't expand summary_info"
	}
	if i == 1 {
		return 1, ""
	}
	str := ""
	for j := 0; j < len(c.dir) && str == ""; j++ {
		str = dirName(dirNameString(&c.dir[j]), pr.mime)
	}
	if pr.notMime() {
		if str != "" {
			pr.write(str)
			i = 1
		}
	} else {
		if str == "" {
			str = "vnd.ms-office"
		}
		pr.write("application/" + str)
		i = 1
	}
	if i <= 0 {
		i = pr.catalogInfo(c)
	}
	return i, ""
}

// dirNameString is the entry's name as the reference passes it to
// strcasestr: the low bytes of its units, up to a NUL or 32 characters.
func dirNameString(d *cdfDir) string {
	invariant.Check(d != nil, "entry present")
	var b [32]byte
	n := 0
	for ; n < len(d.name) && d.name[n] != 0; n++ {
		b[n] = low8(uint64(d.name[n]))
	}
	return string(b[:n])
}

// fileSummaryInfo is cdf_file_summary_info.
func (pr cdfPrinter) fileSummaryInfo(c *cdfFile, st *cdfStream) int {
	si, props, ok := unpackSummaryInfo(st)
	if !ok {
		return -1
	}
	if pr.notMime() {
		pr.write("Composite Document File V2 Document")
		if si.byteOrder == 0xfffe {
			pr.write(", Little Endian")
		} else {
			pr.write(", Big Endian")
		}
		lo, hi := strconv.Itoa(int(si.osVersion&0xff)), strconv.Itoa(int(si.osVersion>>8))
		switch si.os {
		case 2:
			pr.write(", Os: Windows, Version " + lo + "." + hi)
		case 1:
			pr.write(", Os: MacOS, Version " + hi + "." + lo)
		default:
			pr.write(", Os " + strconv.Itoa(int(si.os)) + ", Version: " + lo + "." + hi)
		}
		if c.root >= 0 {
			if str := clsidName(c.dir[c.root].storageUUID, false); str != "" {
				pr.write(", " + str)
			}
		}
	}
	m := pr.propertyInfo(c, props)
	if m == -1 {
		return -2
	}
	return m
}

// propertyInfo is cdf_file_property_info.
func (pr cdfPrinter) propertyInfo(c *cdfFile, props []cdfProp) int {
	invariant.Check(c.root < len(c.dir), "root index within the directory")
	str := ""
	if pr.mime && c.root >= 0 {
		str = clsidName(c.dir[c.root].storageUUID, true)
	}
	for i := range props {
		p := &props[i]
		name := propertyName(p.id)
		switch p.typ {
		case cdfTypeNull, cdfTypeClipboard:
		case cdfTypeSigned16:
			pr.field(name, strconv.FormatInt(extend(p.u64, 16, true), 10))
		case cdfTypeSigned32:
			pr.field(name, strconv.FormatInt(extend(p.u64, 32, true), 10))
		case cdfTypeUnsigned:
			pr.field(name, strconv.FormatUint(p.u64&0xffffffff, 10))
		case cdfTypeFloat:
			pr.field(name, strconv.FormatFloat(float64(math.Float32frombits(low32(p.u64))), 'g', 6, 64))
		case cdfTypeDouble:
			pr.field(name, strconv.FormatFloat(math.Float64frombits(p.u64), 'g', 6, 64))
		case cdfTypeString, cdfTypeWString:
			str = pr.stringProperty(p, name, str)
		case cdfTypeFiletime:
			pr.filetime(p, name)
		default:
			return -1
		}
	}
	if pr.mime {
		if str == "" {
			return 0
		}
		pr.write("application/" + str)
	}
	return 1
}

// field prints ", name: value" in description mode.
func (pr cdfPrinter) field(name, value string) {
	if pr.notMime() {
		pr.write(", " + name + ": " + value)
	}
}

// stringProperty prints a string property, or in MIME mode derives the
// type from the creating application's name.
func (pr cdfPrinter) stringProperty(p *cdfProp, name, str string) string {
	if len(p.str) <= 1 {
		return str
	}
	text := propertyText(p)
	if pr.notMime() {
		if text != "" {
			pr.write(", " + name + ": " + text)
		}
	} else if str == "" && p.id == cdfPropAppName {
		str = appName(text)
	}
	return str
}

// filetime prints a FILETIME property as elapsed time or a date.
func (pr cdfPrinter) filetime(p *cdfProp, name string) {
	tp := int64FromBits(p.u64)
	if tp == 0 {
		return
	}
	if tp < 1000000000000000 {
		pr.field(name, cdfElapsed(tp))
		return
	}
	pr.field(name, cdfTime(tp))
}

// dirInfo is cdf_file_dir_info: known stream and storage names.
func (pr cdfPrinter) dirInfo(c *cdfFile) int {
	invariant.Check(len(c.dir) <= cdfMaxDirs, "directory bounded")
	type section struct {
		name, mime string
		streams    [2]string
		types      [2]uint8
	}
	table := [...]section{
		{"Encrypted", "encrypted", [2]string{"EncryptedPackage", "EncryptedSummary"}, [2]uint8{cdfDirUserStream, cdfDirUserStream}},
		{"QuickBooks", "quickbooks", [2]string{"mfbu_header", ""}, [2]uint8{cdfDirUserStream, 0}},
		{"Microsoft Excel", "vnd.ms-excel", [2]string{"Book", "Workbook"}, [2]uint8{cdfDirUserStream, cdfDirUserStream}},
		{"Microsoft Word", "msword", [2]string{"WordDocument", ""}, [2]uint8{cdfDirUserStream, 0}},
		{"Microsoft PowerPoint", "vnd.ms-powerpoint", [2]string{"PowerPoint Document", ""}, [2]uint8{cdfDirUserStream, 0}},
		{"Microsoft Outlook Message", "vnd.ms-outlook", [2]string{"__properties_version1.0", "__recip_version1.0_#00000000"}, [2]uint8{cdfDirUserStream, cdfDirUserStorage}},
	}
	for i := range c.dir {
		for sd := range table {
			if !sectionMatches(&table[sd].streams, &table[sd].types, &c.dir[i]) {
				continue
			}
			if pr.notMime() {
				pr.write("CDFV2 " + table[sd].name)
			} else {
				pr.write("application/" + table[sd].mime)
			}
			return 1
		}
	}
	return -1
}

// sectionMatches reports whether the entry is one of a section's streams.
func sectionMatches(streams *[2]string, types *[2]uint8, d *cdfDir) bool {
	for j := 0; j < 2 && streams[j] != ""; j++ {
		if types[j] == d.typ && nameEquals(streams[j], d) {
			return true
		}
	}
	return false
}

// catalogInfo is cdf_file_catalog_info and cdf_file_catalog: a
// Thumbs.db catalog.
func (pr cdfPrinter) catalogInfo(c *cdfFile) int {
	st, found, ok := c.readUserStream("Catalog")
	if !found || !ok {
		return -1
	}
	if !pr.notMime() {
		pr.write("application/CDFV2")
		return 1
	}
	pr.write("Microsoft Thumbs.db [")
	names, ok := unpackCatalog(&st)
	if !ok {
		return -1
	}
	for i := 1; i < len(names); i++ {
		pr.write(names[i])
		if i == len(names)-1 {
			pr.write("]")
		} else {
			pr.write(", ")
		}
	}
	return 1
}

// unpackCatalog is cdf_unpack_catalog: the entry names of a catalog.
func unpackCatalog(st *cdfStream) ([]string, bool) {
	tab := st.tab[:st.size()]
	nr := catalogRecords(tab)
	if nr == 0 {
		return nil, false
	}
	nr--
	names := make([]string, 0, nr)
	b := 0
	for i := 0; i < nr && b <= len(tab)-16; i++ {
		reclen := int(binary.LittleEndian.Uint16(tab[b:]))
		if reclen < 14 {
			b += reclen
			continue
		}
		n := reclen - 14
		if n > 255 {
			n = 255
		}
		if b+16+2*n > len(tab) {
			break
		}
		names = append(names, catalogName(tab[b+16:], n))
		b += reclen
	}
	return names, true
}

// catalogRecords counts the length-prefixed records up to a zero length.
func catalogRecords(tab []byte) int {
	invariant.Check(len(tab) <= cdfSATLimit*4, "catalog bounded")
	nr, b := 0, 0
	for ; nr <= len(tab) && b <= len(tab)-2; nr++ {
		reclen := int(binary.LittleEndian.Uint16(tab[b:]))
		if reclen == 0 {
			break
		}
		b += reclen
		if b > len(tab) {
			break
		}
	}
	return nr
}

// catalogName is the entry's name from n UTF-16 units, low bytes.
func catalogName(b []byte, n int) string {
	invariant.Check(n >= 0 && n <= 255 && len(b) >= 2*n, "name units within the record")
	var name [255]byte
	k := 0
	for ; k < n; k++ {
		u := binary.LittleEndian.Uint16(b[2*k:])
		if u == 0 {
			break
		}
		name[k] = low8(uint64(u))
	}
	return string(name[:k])
}
