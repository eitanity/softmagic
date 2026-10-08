// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from file_encoding and the looks_* classifiers in
// encoding.c, file 5.48, Copyright (c) Ian F. Darwin 1986-1995 (see
// COPYING). The reference decodes into a Unicode buffer; this port decodes
// on demand through textDecoder, so no per-call buffer of the window's size
// is needed.

package softmagic

import "github.com/eitanity/softmagic/internal/invariant"

// encodingKind names how the text window decodes.
type encodingKind uint8

const (
	encBinary encodingKind = iota
	encASCII
	encUTF7
	encUTF8BOM
	encUTF8
	encUTF32LE
	encUTF32BE
	encUTF16LE
	encUTF16BE
	encLatin1
	encExtended
	encEBCDIC
	encEBCDICIntl
)

// encoding is the classification of a text window.
type encoding struct {
	kind encodingKind
	n    int // bytes classified (at most encodingMax)
}

// code is the reference's *code string for the description.
func (e encoding) code() string {
	switch e.kind {
	case encASCII:
		return "ASCII"
	case encUTF7:
		return "Unicode text, UTF-7"
	case encUTF8BOM:
		return "Unicode text, UTF-8 (with BOM)"
	case encUTF8:
		return "Unicode text, UTF-8"
	case encUTF32LE:
		return "Unicode text, UTF-32, little-endian"
	case encUTF32BE:
		return "Unicode text, UTF-32, big-endian"
	case encUTF16LE:
		return "Unicode text, UTF-16, little-endian"
	case encUTF16BE:
		return "Unicode text, UTF-16, big-endian"
	case encLatin1:
		return "ISO-8859"
	case encExtended:
		return "Non-ISO extended-ASCII"
	case encEBCDIC:
		return "EBCDIC"
	case encEBCDICIntl:
		return "International EBCDIC"
	default:
		return "unknown"
	}
}

// charset is the reference's *code_mime: the charset after "; charset=".
func (e encoding) charset() string {
	switch e.kind {
	case encASCII:
		return "us-ascii"
	case encUTF7:
		return "utf-7"
	case encUTF8BOM, encUTF8:
		return "utf-8"
	case encUTF32LE:
		return "utf-32le"
	case encUTF32BE:
		return "utf-32be"
	case encUTF16LE:
		return "utf-16le"
	case encUTF16BE:
		return "utf-16be"
	case encLatin1:
		return "iso-8859-1"
	case encExtended:
		return "unknown-8bit"
	case encEBCDIC, encEBCDICIntl:
		return "ebcdic"
	default:
		return "binary"
	}
}

func (e encoding) isText() bool { return e.kind != encBinary }

// classify is file_encoding over at most limit bytes of buf (the
// reference's encoding_max).
func classify(buf []byte, limit int) encoding {
	invariant.Check(limit >= 0 && limit <= encodingLimitMax, "encoding limit resolved")
	if len(buf) > limit {
		buf = buf[:limit]
	}
	invariant.Check(len(buf) <= encodingLimitMax, "classified window bounded")
	e := encoding{n: len(buf)}
	switch {
	case looksClass(buf, chT):
		e.kind = encASCII
		if looksUTF7(buf) {
			e.kind = encUTF7
		}
	case looksUTF8WithBOM(buf) > 0:
		e.kind = encUTF8BOM
	case looksUTF8(buf) > 1:
		e.kind = encUTF8
	case looksUCS32(buf) != 0:
		e.kind = unicodeKind(encUTF32LE, encUTF32BE, looksUCS32(buf))
	case looksUCS16(buf) != 0:
		e.kind = unicodeKind(encUTF16LE, encUTF16BE, looksUCS16(buf))
	case looksClass(buf, chI):
		e.kind = encLatin1
	case looksClass(buf, chX):
		e.kind = encExtended
	default:
		e.kind = looksEBCDIC(buf)
	}
	return e
}

// unicodeKind maps a looks_ucs* result (1 little-endian, 2 big-endian).
func unicodeKind(le, be encodingKind, r int) encodingKind {
	invariant.Check(r == 1 || r == 2, "endianness result")
	if r == 2 {
		return be
	}
	return le
}

// looksClass is the LOOKS macro: every byte's text class is at most max
// (T for ASCII, I for Latin-1, X for extended).
func looksClass(buf []byte, maxClass uint8) bool {
	invariant.Check(maxClass >= chT && maxClass <= chX, "class bound")
	for i := 0; i < len(buf); i++ {
		t := textChars[buf[i]]
		if t == chF || t > maxClass {
			return false
		}
	}
	return true
}

func looksUTF7(buf []byte) bool {
	if len(buf) > 4 && buf[0] == '+' && buf[1] == '/' && buf[2] == 'v' {
		switch buf[3] {
		case '8', '9', '+', '/':
			return true
		default:
			return false
		}
	}
	return false
}

func looksUTF8WithBOM(buf []byte) int {
	if len(buf) > 3 && buf[0] == 0xef && buf[1] == 0xbb && buf[2] == 0xbf {
		return looksUTF8(buf[3:])
	}
	return -1
}

// looksUCS16 is looks_ucs16: 0 no, 1 little-endian, 2 big-endian.
func looksUCS16(bf []byte) int {
	if len(bf) < 2 {
		return 0
	}
	bigend := 0
	switch {
	case bf[0] == 0xff && bf[1] == 0xfe:
		bigend = 0
	case bf[0] == 0xfe && bf[1] == 0xff:
		bigend = 1
	default:
		return 0
	}
	hi := uint32(0)
	for i := 2; i < len(bf)-1; i += 2 {
		uc := uint32(bf[i]) | uint32(bf[i+1])<<8
		if bigend == 1 {
			uc = uint32(bf[i+1]) | uint32(bf[i])<<8
		}
		ok := false
		_, hi, ok = ucs16Unit(uc, hi)
		if !ok {
			return 0
		}
	}
	return 1 + bigend
}

// ucs16Unit validates one UTF-16 unit given a pending high surrogate and
// returns the character, the new pending surrogate and whether it is text.
func ucs16Unit(uc, hi uint32) (uint32, uint32, bool) {
	invariant.Check(hi <= 0x400, "pending surrogate index in range")
	if uc == 0xfffe || uc == 0xffff || (uc >= 0xfdd0 && uc <= 0xfdef) {
		return 0, 0, false
	}
	if hi != 0 {
		if uc < 0xdc00 || uc > 0xdfff {
			return 0, 0, false
		}
		uc = 0x10000 + 0x400*(hi-1) + (uc - 0xdc00)
		hi = 0
	}
	if uc < 128 && textChars[uc] != chT {
		return 0, 0, false
	}
	if uc >= 0xd800 && uc <= 0xdbff {
		hi = uc - 0xd800 + 1
	}
	if uc >= 0xdc00 && uc <= 0xdfff {
		return 0, 0, false
	}
	return uc, hi, true
}

// looksUCS32 is looks_ucs32: 0 no, 1 little-endian, 2 big-endian.
func looksUCS32(bf []byte) int {
	if len(bf) < 4 {
		return 0
	}
	bigend := 0
	switch {
	case bf[0] == 0xff && bf[1] == 0xfe && bf[2] == 0 && bf[3] == 0:
		bigend = 0
	case bf[0] == 0 && bf[1] == 0 && bf[2] == 0xfe && bf[3] == 0xff:
		bigend = 1
	default:
		return 0
	}
	for i := 4; i < len(bf)-3; i += 4 {
		uc := ucs32At(bf, i, bigend == 1)
		if uc == 0xfffe {
			return 0
		}
		if uc < 128 && textChars[uc] != chT {
			return 0
		}
	}
	return 1 + bigend
}

func ucs32At(bf []byte, i int, be bool) uint32 {
	if be {
		return uint32(bf[i+3]) | uint32(bf[i+2])<<8 | uint32(bf[i+1])<<16 | uint32(bf[i])<<24
	}
	return uint32(bf[i]) | uint32(bf[i+1])<<8 | uint32(bf[i+2])<<16 | uint32(bf[i+3])<<24
}

// looksEBCDIC classifies through the EBCDIC-to-ASCII table.
func looksEBCDIC(buf []byte) encodingKind {
	invariant.Check(len(buf) <= encodingLimitMax, "classified window bounded")
	ascii, latin1 := true, true
	for i := 0; i < len(buf) && latin1; i++ {
		t := textChars[ebcdicToASCII[buf[i]]]
		if t != chT {
			ascii = false
		}
		if t != chT && t != chI {
			latin1 = false
		}
	}
	switch {
	case ascii:
		return encEBCDIC
	case latin1:
		return encEBCDICIntl
	default:
		return encBinary
	}
}

// ebcdicToASCII is encoding.c's ebcdic_to_ascii table, as a constant.
const ebcdicToASCII = "\x00\x01\x02\x03\x9c\x09\x86\x7f\x97\x8d\x8e\x0b\x0c\x0d\x0e\x0f" +
	"\x10\x11\x12\x13\x9d\x85\x08\x87\x18\x19\x92\x8f\x1c\x1d\x1e\x1f" +
	"\x80\x81\x82\x83\x84\x0a\x17\x1b\x88\x89\x8a\x8b\x8c\x05\x06\x07" +
	"\x90\x91\x16\x93\x94\x95\x96\x04\x98\x99\x9a\x9b\x14\x15\x9e\x1a" +
	"\x20\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xd5\x2e\x3c\x28\x2b\x7c" +
	"\x26\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\x21\x24\x2a\x29\x3b\x7e" +
	"\x2d\x2f\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xcb\x2c\x25\x5f\x3e\x3f" +
	"\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\x60\x3a\x23\x40\x27\x3d\x22" +
	"\xc3\x61\x62\x63\x64\x65\x66\x67\x68\x69\xc4\xc5\xc6\xc7\xc8\xc9" +
	"\xca\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x5e\xcc\xcd\xce\xcf\xd0" +
	"\xd1\xe5\x73\x74\x75\x76\x77\x78\x79\x7a\xd2\xd3\xd4\x5b\xd6\xd7" +
	"\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\x5d\xe6\xe7" +
	"\x7b\x41\x42\x43\x44\x45\x46\x47\x48\x49\xe8\xe9\xea\xeb\xec\xed" +
	"\x7d\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\xee\xef\xf0\xf1\xf2\xf3" +
	"\x5c\x9f\x53\x54\x55\x56\x57\x58\x59\x5a\xf4\xf5\xf6\xf7\xf8\xf9" +
	"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\xfa\xfb\xfc\xfd\xfe\xff"

// textDecoder yields the window's characters as the reference's ubuf
// would hold them, one at a time.
type textDecoder struct {
	buf  []byte
	i    int
	kind encodingKind
	hi   uint32 // pending UTF-16 high surrogate
}

func newTextDecoder(buf []byte, e encoding) textDecoder {
	invariant.Check(e.n <= len(buf), "classified length within the window")
	d := textDecoder{buf: buf[:e.n], kind: e.kind}
	switch e.kind {
	case encUTF8BOM:
		d.i = 3
	case encUTF16LE, encUTF16BE:
		d.i = 2
	case encUTF32LE, encUTF32BE:
		d.i = 4
	default:
	}
	return d
}

// next returns the next character and false at the end.
func (d *textDecoder) next() (uint32, bool) {
	invariant.Check(d.i >= 0 && d.i <= len(d.buf), "decoder cursor within the window")
	switch d.kind {
	case encASCII, encUTF7, encLatin1, encExtended:
		if d.i >= len(d.buf) {
			return 0, false
		}
		c := uint32(d.buf[d.i])
		d.i++
		return c, true
	case encEBCDIC, encEBCDICIntl:
		if d.i >= len(d.buf) {
			return 0, false
		}
		c := uint32(ebcdicToASCII[d.buf[d.i]])
		d.i++
		return c, true
	case encUTF8, encUTF8BOM:
		return d.nextUTF8()
	case encUTF16LE, encUTF16BE:
		return d.nextUTF16()
	case encUTF32LE, encUTF32BE:
		if d.i+3 >= len(d.buf) {
			return 0, false
		}
		c := ucs32At(d.buf, d.i, d.kind == encUTF32BE)
		d.i += 4
		return c, true
	default:
		return 0, false
	}
}

// nextUTF8 decodes as file_looks_utf8 does; the window was validated by
// classify, so a truncated final sequence is the only irregularity, and
// it yields no character.
func (d *textDecoder) nextUTF8() (uint32, bool) {
	invariant.Check(d.i >= 0 && d.i <= len(d.buf), "decoder cursor within the window")
	if d.i >= len(d.buf) {
		return 0, false
	}
	b := d.buf[d.i]
	d.i++
	if b&0x80 == 0 {
		return uint32(b), true
	}
	following, ok := utf8Following(b)
	if !ok {
		return 0, false
	}
	c := uint32(b) & (0x3f >> uint(following))
	for n := 0; n < following; n++ {
		if d.i >= len(d.buf) {
			return 0, false
		}
		c = c<<6 + uint32(d.buf[d.i]&0x3f)
		d.i++
	}
	return c, true
}

func (d *textDecoder) nextUTF16() (uint32, bool) {
	invariant.Check(d.i >= 0 && d.i <= len(d.buf), "decoder cursor within the window")
	if d.i >= len(d.buf)-1 {
		return 0, false
	}
	uc := uint32(d.buf[d.i]) | uint32(d.buf[d.i+1])<<8
	if d.kind == encUTF16BE {
		uc = uint32(d.buf[d.i+1]) | uint32(d.buf[d.i])<<8
	}
	d.i += 2
	if d.hi != 0 {
		uc = 0x10000 + 0x400*(d.hi-1) + (uc - 0xdc00)
		d.hi = 0
		return uc, true
	}
	if uc >= 0xd800 && uc <= 0xdbff {
		d.hi = uc - 0xd800 + 1 // the reference stores the surrogate itself as well
	}
	return uc, true
}

// encodeUTF8 is ascmagic.c's encode_utf8 for one character; it returns
// the bytes written, 0 when the character cannot be encoded.
func encodeUTF8(dst []byte, c uint32) int {
	switch {
	case c <= 0x7f:
		if len(dst) < 1 {
			return 0
		}
		dst[0] = low8(uint64(c))
		return 1
	case c <= 0x7ff:
		if len(dst) < 2 {
			return 0
		}
		dst[0] = low8(uint64(c>>6)) + 0xc0
		dst[1] = low8(uint64(c&0x3f)) + 0x80
		return 2
	case c <= 0xffff:
		if len(dst) < 3 {
			return 0
		}
		dst[0] = byte(c>>12) + 0xe0
		dst[1] = byte(c>>6&0x3f) + 0x80
		dst[2] = byte(c&0x3f) + 0x80
		return 3
	case c <= 0x1fffff:
		if len(dst) < 4 {
			return 0
		}
		dst[0] = byte(c>>18) + 0xf0
		dst[1] = byte(c>>12&0x3f) + 0x80
		dst[2] = byte(c>>6&0x3f) + 0x80
		dst[3] = byte(c&0x3f) + 0x80
		return 4
	default:
		return encodeUTF8Long(dst, c)
	}
}

// encodeUTF8Long is the historical 5- and 6-byte forms.
func encodeUTF8Long(dst []byte, c uint32) int {
	switch {
	case c <= 0x3ffffff:
		if len(dst) < 5 {
			return 0
		}
		dst[0] = byte(c>>24) + 0xf8
		dst[1] = byte(c>>18&0x3f) + 0x80
		dst[2] = byte(c>>12&0x3f) + 0x80
		dst[3] = byte(c>>6&0x3f) + 0x80
		dst[4] = byte(c&0x3f) + 0x80
		return 5
	case c <= 0x7fffffff:
		if len(dst) < 6 {
			return 0
		}
		dst[0] = byte(c>>30) + 0xfc
		dst[1] = byte(c>>24&0x3f) + 0x80
		dst[2] = byte(c>>18&0x3f) + 0x80
		dst[3] = byte(c>>12&0x3f) + 0x80
		dst[4] = byte(c>>6&0x3f) + 0x80
		dst[5] = byte(c&0x3f) + 0x80
		return 6
	default:
		return 0
	}
}
