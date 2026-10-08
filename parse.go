// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from parse and its helpers in apprentice.c, file 5.48,
// Copyright (c) Ian F. Darwin 1986-1995 (see COPYING). The grammar accepted
// here is the reference's, including its asymmetries; where the reference
// only warns, this parser accepts silently, and where it rejects a line,
// this parser returns a CompileError naming the file and line.

package softmagic

import (
	"strings"

	"github.com/eitanity/softmagic/internal/invariant"
)

// lineParser holds the cursor over one rule line and the record being built.
type lineParser struct {
	rec    *lineRec
	tables *typeTables
	file   string
	dump   *strings.Builder // nil unless file -c's dump is wanted
	line   []byte
	i      int
	lineno uint32
}

func (p *lineParser) cur() byte { return at(p.line, p.i) }

// parseContLevel counts the leading '>' characters.
func (p *lineParser) parseContLevel() int {
	invariant.Check(p.i == 0, "continuation count starts the line")
	n := 0
	for ; p.i < len(p.line) && p.line[p.i] == '>'; p.i++ {
		n++
	}
	return n
}

// parseOffset reads [&][(][&][+-]offset[.t[~][op][(]in_offset)[)]] into rec.
func (p *lineParser) parseOffset() error {
	invariant.Check(p.i <= len(p.line), "cursor within the line")
	invariant.Check(p.rec != nil, "record to fill")
	r := p.rec // rec
	if p.cur() == '&' {
		p.i++
		r.flag |= flagOffAdd
	}
	if p.cur() == '(' {
		p.i++
		r.flag |= flagIndir
		if r.flag&flagOffAdd != 0 {
			r.flag = r.flag&^flagOffAdd | flagIndirOffAdd
		}
		if p.cur() == '&' {
			p.i++
			r.flag |= flagOffAdd
		}
	}
	if r.contLevel == 0 && r.flag&(flagOffAdd|flagIndirOffAdd) != 0 {
		return p.errorf("relative offset at level 0")
	}
	if c := p.cur(); c == '-' || c == '+' {
		p.i++
		if c == '-' {
			r.flag |= flagOffNegative
		} else {
			r.flag |= flagOffPositive
		}
	}
	v, end, ok := strtol(p.line, p.i, 0)
	if !ok {
		return p.errorf("offset `" + string(p.line[p.i:]) + "' invalid")
	}
	r.offset = wrapInt32(v)
	p.i = end
	if r.flag&flagIndir != 0 {
		return p.parseIndirect()
	}
	return nil
}

// parseIndirect reads the part of an indirect offset after the base offset:
// [.,t][~][op][(]in_offset)[)].
func (p *lineParser) parseIndirect() error {
	invariant.Check(p.i <= len(p.line), "cursor within the line")
	invariant.Check(p.rec.flag&flagIndir != 0, "indirect offset")
	r := p.rec // rec
	r.inType, r.inOffset, r.inOp = tLong, 0, 0
	if err := p.parseIndirectType(); err != nil {
		return err
	}
	if p.cur() == '~' {
		r.inOp |= opInverse
		p.i++
	}
	if op, ok := getOp(p.cur()); ok {
		r.inOp |= op
		p.i++
	}
	if p.cur() == '(' {
		r.inOp |= opIndirect
		p.i++
	}
	if c := p.cur(); cIsDigit(c) || c == '-' {
		v, end, ok := strtol(p.line, p.i, 0)
		if !ok {
			return p.errorf("in_offset `" + string(p.line[p.i:]) + "' invalid")
		}
		r.inOffset = wrapInt32(v)
		p.i = end
	}
	if !p.expect(')') || (r.inOp&opIndirect != 0 && !p.expect(')')) {
		return p.errorf("missing ')' in indirect offset")
	}
	return nil
}

// parseIndirectType reads the optional [.,]t size letter of an indirect
// offset; ',' marks the value as signed.
func (p *lineParser) parseIndirectType() error {
	c := p.cur()
	if c != '.' && c != ',' {
		return nil
	}
	if c == ',' {
		p.rec.inOp |= opSigned
	}
	p.i++
	t, ok := indirectType(p.cur())
	if !ok {
		return p.errorf("indirect offset type `" + string(p.cur()) + "' invalid")
	}
	p.rec.inType = t
	p.i++
	return nil
}

// expect consumes c at the cursor and reports whether it was there.
func (p *lineParser) expect(c byte) bool {
	if p.cur() != c {
		return false
	}
	p.i++
	return true
}

// indirectType maps the size letter of an indirect offset to its type.
func indirectType(c byte) (fileType, bool) {
	switch c {
	case 'l':
		return tLeLong, true
	case 'L':
		return tBeLong, true
	case 'm':
		return tMeLong, true
	case 'h', 's':
		return tLeShort, true
	case 'H', 'S':
		return tBeShort, true
	case 'c', 'b', 'C', 'B':
		return tByte, true
	case 'e', 'f', 'g':
		return tLeDouble, true
	case 'E', 'F', 'G':
		return tBeDouble, true
	case 'i':
		return tLeID3, true
	case 'I':
		return tBeID3, true
	case 'o':
		return tOctal, true
	case 'q':
		return tLeQuad, true
	case 'Q':
		return tBeQuad, true
	default:
		return tInvalid, false
	}
}

// getOp is apprentice.c's get_op.
func getOp(c byte) (uint8, bool) {
	switch c {
	case '&':
		return opAnd, true
	case '|':
		return opOr, true
	case '^':
		return opXor, true
	case '+':
		return opAdd, true
	case '-':
		return opMinus, true
	case '*':
		return opMultiply, true
	case '/':
		return opDivide, true
	case '%':
		return opModulo, true
	default:
		return 0, false
	}
}

// parseType reads the test type: a keyword, optionally prefixed by 'u', or
// one of the SUS forms d/u[1248CSILQ] and s, or a special keyword.
func (p *lineParser) parseType() error {
	invariant.Check(p.rec.typ == tInvalid, "type not yet set")
	invariant.Check(p.i <= len(p.line), "cursor within the line")
	r := p.rec // rec
	rest := p.line[p.i:]
	if p.cur() == 'u' {
		t, n := lookupType(p.tables.types[:], rest[1:]) // fileType
		if t == tInvalid {
			t, n = standardIntegerType(rest)
		} else {
			n++
		}
		if t != tInvalid {
			r.flag |= flagUnsigned
		}
		r.typ = t
		p.i += n
	} else {
		t, n := lookupType(p.tables.types[:], rest) // typeLen
		if t == tInvalid && p.cur() == 'd' {
			t, n = standardIntegerType(rest)
		} else if t == tInvalid && p.cur() == 's' && !cIsAlpha(at(rest, 1)) {
			t, n = tString, 1
		}
		r.typ = t
		p.i += n
	}
	if r.typ == tInvalid {
		t, n := lookupType(p.tables.special[:], p.line[p.i:])
		r.typ = t
		p.i += n
	}
	if r.typ == tInvalid {
		return p.errorf("type `" + string(rest) + "' invalid")
	}
	if r.typ == tName && r.contLevel != 0 {
		return p.errorf("`name' entries can only be declared at top level")
	}
	return nil
}

// standardIntegerType is get_standard_integer_type: "d" or "u" followed by
// C, S, I, L, Q, or 1, 2, 4, 8, or nothing. It returns the bytes consumed.
func standardIntegerType(s []byte) (fileType, int) { // typeText
	if len(s) < 2 || s[1] == 0 {
		return tInvalid, 0
	}
	c := s[1] // sizeChar
	switch {
	case cIsAlpha(c):
		switch c {
		case 'C':
			return tByte, 2
		case 'S':
			return tShort, 2
		case 'I', 'L':
			return tLong, 2
		case 'Q':
			return tQuad, 2
		default:
			return tInvalid, 0
		}
	case cIsDigit(c):
		if cIsDigit(at(s, 2)) {
			return tInvalid, 0
		}
		switch c {
		case '1':
			return tByte, 2
		case '2':
			return tShort, 2
		case '4':
			return tLong, 2
		case '8':
			return tQuad, 2
		default:
			return tInvalid, 0
		}
	default:
		return tLong, 1
	}
}

// parseMask reads the optional ~ and operator/modifier part after the type:
// a numeric mask (&0xff), a string modifier list (/bc), or an indirect
// modifier (/r).
func (p *lineParser) parseMask() error {
	invariant.Check(p.i <= len(p.line), "cursor within the line")
	invariant.Check(p.rec.typ != tInvalid, "type parsed before mask")
	r := p.rec // rec
	r.maskOp = 0
	if p.cur() == '~' {
		if !isString(r.typ) {
			r.maskOp |= opInverse
		}
		p.i++
	}
	r.setStrRange(0)
	if r.typ == tPString {
		r.setStrFlags(pstring1LE)
	} else {
		r.setStrFlags(0)
	}
	op, ok := getOp(p.cur()) // maskOp
	if !ok {
		return nil
	}
	if !isString(r.typ) {
		p.parseOpModifier(op)
		return nil
	}
	if op != opDivide {
		return p.errorf("invalid string/indirect op: `" + string(p.cur()) + "'")
	}
	if r.typ == tIndirect {
		return p.parseIndirectModifier()
	}
	return p.parseStringModifier()
}

// parseOpModifier is parse_op_modifier: op, number, optional size suffix.
func (p *lineParser) parseOpModifier(op uint8) {
	invariant.Check(op <= opModulo, "operator in range")
	invariant.Check(!isString(p.rec.typ), "numeric mask on a numeric type")
	r := p.rec // rec
	p.i++
	r.maskOp |= op
	v, end, ok := strtoull(p.line, p.i, 0)
	if ok {
		p.i = end
	}
	r.maskOrStr = signExtend(&r.recordHead, v)
	p.i = eatSize(p.line, p.i)
}

// parseIndirectModifier is parse_indirect_modifier: only /r is defined.
func (p *lineParser) parseIndirectModifier() error {
	invariant.Check(p.cur() == '/', "modifier list starts with a slash")
	invariant.Check(p.rec.typ == tIndirect, "indirect modifier on an indirect line")
	p.i++
	for ; p.i < len(p.line) && !cIsSpace(p.line[p.i]); p.i++ {
		if p.line[p.i] != 'r' {
			return p.errorf("indirect modifier `" + string(p.line[p.i]) + "' invalid")
		}
		p.rec.setStrFlags(p.rec.strFlags() | indirectRelative)
	}
	return nil
}

// parseStringModifier is parse_string_modifier: the characters after '/'
// up to whitespace, each a flag or a decimal range, with '/' permitted
// between them for readability.
func (p *lineParser) parseStringModifier() error {
	invariant.Check(p.cur() == '/', "modifier list starts with a slash")
	invariant.Check(isString(p.rec.typ), "string modifier on a string type")
	r := p.rec // rec
	haveRange := false
	p.i++
	var next int
	for ; p.i < len(p.line) && !cIsSpace(p.line[p.i]); p.i = next {
		c := p.line[p.i] // modChar
		next = p.i + 1
		if cIsDigit(c) {
			if haveRange {
				return p.errorf("multiple ranges")
			}
			haveRange = true
			v, end, ok := strtoull(p.line, p.i, 0)
			if !ok {
				return p.errorf("range `" + string(p.line[p.i:]) + "' invalid")
			}
			r.setStrRange(low32(v))
			next = end
		} else if !applyModifier(r, c) {
			return p.errorf("string modifier `" + string(c) + "' invalid")
		}
		// Allow "/b/32": a '/' between modifiers is skipped, as the reference does.
		if at(p.line, next) == '/' && next+1 < len(p.line) && !cIsSpace(p.line[next+1]) {
			next++
		}
	}
	if p.i >= len(p.line) {
		// The reference reads the terminating NUL as a modifier and rejects it.
		return p.errorf("string modifier `' invalid")
	}
	return p.stringModifierCheck()
}

// applyModifier sets the flag for modifier character c; a pascal-length
// letter replaces the previous length selection.
func applyModifier(r *lineRec, c byte) bool { // rec
	invariant.Check(c != 0, "modifier character given")
	f, ok := stringModifierBit(c, r.typ) // modBit
	if !ok {
		return false
	}
	if f&pstringLen != 0 {
		r.setStrFlags(r.strFlags()&^pstringLen | f)
	} else {
		r.setStrFlags(r.strFlags() | f)
	}
	return true
}

// stringModifierBit maps a modifier character to its str_flags bit, refusing
// the pascal-length letters on non-pstring types as the reference does.
func stringModifierBit(c byte, t fileType) (uint32, bool) { // fileType
	switch c {
	case 'W':
		return strCompactWhitespace, true
	case 'w':
		return strCompactOptionalWhitespace, true
	case 'c':
		return strIgnoreLowercase, true
	case 'C':
		return strIgnoreUppercase, true
	case 's':
		return regexOffsetStart, true
	case 'b':
		return strBinTest, true
	case 't':
		return strTextTest, true
	case 'T':
		return strTrim, true
	case 'f':
		return strFullWord, true
	case 'B':
		return pstring1LE, t == tPString
	case 'H':
		return pstring2BE, t == tPString
	case 'h':
		return pstring2LE, t == tPString
	case 'L':
		return pstring4BE, t == tPString
	case 'l':
		return pstring4LE, t == tPString || t == tRegex
	case 'J':
		return pstringLengthIncludesItself, t == tPString
	default:
		return 0, false
	}
}

// stringModifierCheck is string_modifier_check under MAGIC_CHECK: every
// branch that returns -1 there is an error here, including a search with
// no range.
func (p *lineParser) stringModifierCheck() error {
	invariant.Check(isString(p.rec.typ), "string modifier on a string type")
	r := p.rec // rec
	flags := r.strFlags()
	if (r.typ != tRegex || flags&regexLineCount == 0) &&
		(r.typ != tPString && flags&pstringLen != 0) {
		return p.errorf("'/BHhLl' modifiers are only allowed for pascal strings")
	}
	switch r.typ {
	case tBeString16, tLeString16:
		if flags != 0 {
			return p.errorf("no modifiers allowed for 16-bit strings")
		}
	case tString, tPString:
		if flags&regexOffsetStart != 0 {
			return p.errorf("'/s' only allowed on regex and search")
		}
	case tSearch:
		if r.strRange() == 0 {
			return p.errorf("missing range")
		}
	case tRegex:
		if flags&(strCompactWhitespace|strCompactOptionalWhitespace) != 0 {
			return p.errorf("'/W' and '/w' not allowed on regex")
		}
	default:
		return p.errorf("coding error: modifiers on type " + typeName(r.typ))
	}
	return nil
}

// parseRelation reads the comparison operator; '=' is the default and 'x'
// matches anything when it stands alone.
func (p *lineParser) parseRelation() error {
	invariant.Check(p.rec.reln == 0, "relation not yet set")
	invariant.Check(p.i <= len(p.line), "cursor within the line")
	r := p.rec               // rec
	switch c := p.cur(); c { // relnChar
	case '>', '<':
		r.reln = c
		p.i++
		if p.cur() == '=' {
			return p.errorf(string(c) + "= not supported")
		}
	case '&', '^', '=':
		r.reln = c
		p.i++
		if p.cur() == '=' {
			p.i++ // HP compat: &= and friends
		}
	case '!':
		r.reln = c
		p.i++
	default:
		r.reln = '='
		if c == 'x' && (p.i+1 >= len(p.line) || cIsSpace(p.line[p.i+1])) {
			r.reln = 'x'
			p.i++
		}
	}
	return nil
}

// parseDesc reads the description, honouring a leading \b (no space) and
// truncating to MAXDESC-1 bytes. An empty description gets the file name
// tucked in after the NUL, as the reference does; it takes part in the
// tie-break of the entry sort.
func (p *lineParser) parseDesc() {
	invariant.Check(p.rec.desc[0] == 0, "description not yet set")
	invariant.Check(p.i <= len(p.line), "cursor within the line")
	r := p.rec // rec
	p.i = eatSpace(p.line, p.i)
	if p.cur() == '\b' {
		p.i++
		r.flag |= flagNoSpace
	} else if p.cur() == '\\' && at(p.line, p.i+1) == 'b' {
		p.i += 2
		r.flag |= flagNoSpace
	}
	n := copy(r.desc[:maxDesc-1], p.line[p.i:])
	r.desc[n] = 0
	if n == 0 {
		copy(r.desc[1:maxDesc-1], p.file)
	}
	invariant.Check(r.desc[maxDesc-1] == 0, "description NUL-terminated")
}

// parseLine parses one rule line into rec, which the caller has zeroed and
// whose contLevel is set. It is the body of the reference's parse().
func (p *lineParser) parseLine() error {
	invariant.Check(p.rec != nil && p.tables != nil, "parser is set up")
	if err := p.parseOffset(); err != nil {
		return err
	}
	p.i = eatSpace(p.line, p.i)
	if err := p.parseType(); err != nil {
		return err
	}
	if err := p.parseMask(); err != nil {
		return err
	}
	p.i = eatSpace(p.line, p.i)
	if err := p.parseRelation(); err != nil {
		return err
	}
	if p.rec.reln != 'x' {
		if p.i >= len(p.line) {
			return p.errorf("incomplete magic `" + string(p.line) + "'")
		}
		if err := p.getValue(); err != nil {
			return err
		}
	}
	p.parseDesc()
	if err := p.checkFormat(); err != nil {
		return err
	}
	if p.dump != nil {
		p.mdump(p.dump) // where parse() calls file_mdump in check mode
	}
	p.rec.mimetype[0] = 0
	return nil
}
