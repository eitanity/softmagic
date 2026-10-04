// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from file_looks_utf8 and text_chars in encoding.c, file 5.48,
// Copyright (c) Ian F. Darwin 1986-1995 (see COPYING).

package softmagic

import "github.com/eitanity/softmagic/internal/invariant"

// Character classes of text_chars.
const (
	chF uint8 = 0 // never appears in text
	chT uint8 = 1 // plain ASCII text
	chI uint8 = 2 // ISO-8859 text
	chX uint8 = 3 // non-ISO extended ASCII
)

// textChars is encoding.c's text_chars as a 256-byte constant, indexed by
// byte value: 0 never in text, 1 plain ASCII, 2 ISO-8859, 3 non-ISO.
const textChars = "\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x00\x00" +
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00" +
	"\x03\x03\x03\x03\x03\x01\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03" +
	"\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03" +
	"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02" +
	"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02" +
	"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02" +
	"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02" +
	"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02" +
	"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"

// UTF-8 first-byte classes, from encoding.c (itself from Go's utf8 package).
const (
	u8XX uint8 = 0xF1
	u8AS uint8 = 0xF0
	u8S1 uint8 = 0x02
	u8S2 uint8 = 0x13
	u8S3 uint8 = 0x03
	u8S4 uint8 = 0x23
	u8S5 uint8 = 0x34
	u8S6 uint8 = 0x04
	u8S7 uint8 = 0x44
)

// utf8FirstClass is the class of a first byte >= 0xC0 (lower bytes are AS
// or XX by rule and are handled inline).
func utf8FirstClass(b byte) uint8 {
	switch {
	case b < 0x80:
		return u8AS
	case b < 0xC2:
		return u8XX
	case b < 0xE0:
		return u8S1
	case b == 0xE0:
		return u8S2
	case b == 0xED:
		return u8S4
	case b < 0xF0:
		return u8S3
	case b == 0xF0:
		return u8S5
	case b < 0xF4:
		return u8S6
	case b == 0xF4:
		return u8S7
	default:
		return u8XX
	}
}

// utf8AcceptRange is accept_ranges[class>>4]: the bounds on the second byte.
func utf8AcceptRange(class uint8) (lo, hi byte) {
	switch class >> 4 {
	case 1:
		return 0xA0, 0xBF
	case 2:
		return 0x80, 0x9F
	case 3:
		return 0x90, 0xBF
	case 4:
		return 0x80, 0x8F
	default:
		return 0x80, 0xBF
	}
}

// looksUTF8 is file_looks_utf8 without the decode buffer: -1 for invalid
// UTF-8, 0 for valid UTF-8 containing control characters, 1 for plain
// ASCII, 2 for valid multi-byte UTF-8.
func looksUTF8(buf []byte) int {
	invariant.Check(len(buf) <= encodingMax || len(buf) <= maxString, "classified window bounded")
	gotone, ctrl := false, false
	for i := 0; i < len(buf); i++ {
		b := buf[i]
		if b&0x80 == 0 {
			if textChars[b] != chT {
				ctrl = true
			}
			continue
		}
		if b&0x40 == 0 {
			return -1
		}
		following, ok := utf8Following(b)
		if !ok {
			return -1
		}
		end, valid := utf8Continuation(buf, i, following, utf8FirstClass(b))
		if !valid {
			return -1
		}
		if end >= len(buf) {
			return utf8Verdict(ctrl, gotone) // sequence cut off by the end: the reference stops here
		}
		i = end
		gotone = true
	}
	return utf8Verdict(ctrl, gotone)
}

// utf8Continuation validates the `following` bytes after the lead byte at
// buf[i]; it returns the index of the last byte consumed and whether every
// byte seen was a valid continuation. Running past the buffer is not an
// error: the index is then len(buf).
func utf8Continuation(buf []byte, i, following int, class uint8) (int, bool) {
	invariant.Check(following >= 1 && following <= 5, "continuation count")
	lo, hi := utf8AcceptRange(class)
	for n := 0; n < following; n++ {
		i++
		if i >= len(buf) {
			return len(buf), true
		}
		if n == 0 && (buf[i] < lo || buf[i] > hi) {
			return i, false
		}
		if buf[i]&0x80 == 0 || buf[i]&0x40 != 0 {
			return i, false
		}
	}
	return i, true
}

// utf8Following is the continuation-byte count the reference derives from
// the leading bits (it accepts the historical 5- and 6-byte forms).
func utf8Following(b byte) (int, bool) {
	switch {
	case utf8FirstClass(b) == u8XX:
		return 0, false
	case b&0x20 == 0:
		return 1, true
	case b&0x10 == 0:
		return 2, true
	case b&0x08 == 0:
		return 3, true
	case b&0x04 == 0:
		return 4, true
	case b&0x02 == 0:
		return 5, true
	default:
		return 0, false
	}
}

func utf8Verdict(ctrl, gotone bool) int {
	if ctrl {
		return 0
	}
	if gotone {
		return 2
	}
	return 1
}
