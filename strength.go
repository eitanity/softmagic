// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated line for line from nonmagic, apprentice_magic_strength_1,
// file_magic_strength and apprentice_sort in apprentice.c, file 5.48,
// Copyright (c) Ian F. Darwin 1986-1995 (see COPYING). Which entry answers
// an input is decided by this sort, so it is reproduced, not approximated.

package softmagic

import "github.com/eitanity/softmagic/internal/invariant"

const mult = 10 // MULT

// nonMagic counts the characters of a regex that are not magic: escaped
// characters and bracket expressions count 1, repetition and anchor
// characters 0, braced expressions 0, everything else 1; at least 1.
func nonMagic(s string) int {
	invariant.Check(len(s) < maxString, "pattern fits MAXstring")
	rv := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
			}
			rv++
		case '?', '*', '.', '+', '^', '$':
		case '[':
			i = indexFrom(s, i, ']') - 1 // the ']' is counted on the next pass, as the reference does
		case '{':
			i = indexFrom(s, i, '}')
			if i >= len(s) {
				i--
			}
		default:
			rv++
		}
	}
	if rv == 0 {
		return 1
	}
	return rv
}

// indexFrom is the index of the first c at or after i, or len(s).
func indexFrom(s string, i int, c byte) int {
	invariant.Check(i <= len(s), "start within the string")
	invariant.Check(i >= 0, "start non-negative")
	for ; i < len(s) && s[i] != c; i++ {
	}
	return i
}

func isFixedWidth(t fileType) bool {
	switch t {
	case tByte, tShort, tLeShort, tBeShort, tLong, tLeLong, tBeLong, tMeLong,
		tDate, tLeDate, tBeDate, tMeDate, tLDate, tLeLDate, tBeLDate, tMeLDate,
		tFloat, tBeFloat, tLeFloat, tQuad, tBeQuad, tLeQuad,
		tQDate, tLeQDate, tBeQDate, tQLDate, tLeQLDate, tBeQLDate,
		tQWDate, tLeQWDate, tBeQWDate, tDouble, tBeDouble, tLeDouble,
		tBeVarint, tLeVarint, tGUID, tLeGUID, tBeGUID, tBeID3, tLeID3, tOffset,
		tMSDOSDate, tBeMSDOSDate, tLeMSDOSDate, tMSDOSTime, tBeMSDOSTime, tLeMSDOSTime:
		return true
	default:
		return false
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// strength1 is apprentice_magic_strength_1: the per-line score before the
// entry's !:strength factor is applied.
func strength1(r *record) int {
	invariant.Check(r.contLevel == 0, "strength of a first line")
	val := 2 * mult
	switch {
	case r.typ == tDefault:
		return 0
	case isFixedWidth(r.typ):
		val += typeSize(r.typ) * mult
	case r.typ == tPString || r.typ == tString || r.typ == tOctal:
		val += int(r.vallen) * mult
	case r.typ == tBeString16 || r.typ == tLeString16:
		val += int(r.vallen) * mult / 2
	case r.typ == tSearch:
		if r.vallen != 0 {
			val += int(r.vallen) * maxInt(mult/int(r.vallen), 1)
		}
	case r.typ == tRegex:
		v := nonMagic(r.valueString())
		val += v * maxInt(mult/v, 1)
	case r.typ == tDer:
		val += mult
	default: // indirect, name, use, clear
	}
	switch r.reln {
	case 'x', '!':
		val = 0
	case '=':
		val += mult
	case '>', '<':
		val -= 2 * mult
	case '^', '&':
		val -= mult
	}
	return val
}

// entryStrength is file_magic_strength for the entry whose first line is r.
func entryStrength(r *record) int {
	invariant.Check(r.contLevel == 0, "strength of a first line")
	val := strength1(r)
	switch r.factorOp {
	case '+':
		val += int(r.factor)
	case '-':
		val -= int(r.factor)
	case '*':
		val *= int(r.factor)
	case '/':
		val /= int(r.factor)
	default:
	}
	if val <= 0 {
		val = 1
	}
	if !r.hasDesc() {
		val++
	}
	return val
}
