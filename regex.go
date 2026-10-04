// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// check_regex is translated from funcs.c, file 5.48, Copyright (c) Ian F.
// Darwin 1986-1995 (see COPYING). The POSIX ERE to RE2 translation is this
// module's own.

package softmagic

import (
	"github.com/eitanity/softmagic/internal/invariant"

	"regexp"
	"regexp/syntax"
	"strings"
)

// checkRegex applies the reference's own pattern checks, then requires the
// pattern to compile under RE2 after translation. A pattern RE2 rejects is
// a compile error naming the rule, never a runtime skip.
func (p *lineParser) checkRegex() error {
	invariant.Check(p.rec.vallen <= maxString, "pattern length within MAXstring")
	invariant.Check(p.rec.typ == tRegex, "regex line")
	pat := p.rec.valueString()
	if msg := checkRegexSyntax(pat); msg != "" {
		return p.errorf(msg + " in regex `" + pat + "'")
	}
	src := translateRegex(pat, p.rec.strFlags())
	if _, err := regexp.Compile(src); err != nil {
		return p.errorf("regex `" + pat + "' rejected by RE2 as `" + src + "': " + err.Error())
	}
	return nil
}

func isWild(c byte) bool { return c == '?' || c == '*' || c == '+' || c == '{' }

// checkRegexSyntax is funcs.c's check_regex; it returns "" when the pattern
// passes and the reference's message otherwise.
func checkRegexSyntax(pat string) string {
	invariant.Check(len(pat) < maxString, "pattern fits MAXstring")
	var oc byte
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		if isWild(oc) && isWild(c) {
			return "repetition-operator operand `" + string(oc) + string(c) + "' invalid"
		}
		if c == '{' {
			if oc == '}' {
				return "cascading repetition operators"
			}
			if !boundsOK(pat, i+1) {
				return "bounds too large"
			}
		}
		oc = c
		if cIsPrint(c) || cIsSpace(c) || c == '\b' || c == 0x8a {
			continue
		}
		return "non-ascii characters"
	}
	return ""
}

// boundsOK checks that an interval's numbers are at most 1000.
func boundsOK(pat string, i int) bool {
	invariant.Check(i > 0, "after the brace")
	invariant.Check(i <= len(pat), "cursor within the pattern")
	s := []byte(pat)
	l, end, ok := strtoull(s, i, 10)
	if ok && l > 1000 {
		return false
	}
	if at(s, end) == ',' {
		l2, _, ok2 := strtoull(s, end+1, 10)
		if ok2 && l2 > 1000 {
			return false
		}
	}
	return true
}

// translateRegex rewrites a POSIX ERE as RE2 source. Differences handled:
//
//   - a quantifier with nothing to repeat (pattern start, after '(' or '|',
//     or after '^') is a literal in POSIX and an error in RE2: escape it;
//   - inside a bracket expression a backslash is a literal in POSIX and an
//     escape in RE2: double it;
//   - \< and \> word boundaries become \b;
//   - the /c modifier becomes the (?i) flag.
//
// Leftmost-longest semantics are selected at compile time with Longest().
func translateRegex(pat string, flags uint32) string {
	invariant.Check(len(pat) < maxString, "pattern fits MAXstring")
	var b strings.Builder
	// The reference compiles with REG_NEWLINE: ^ and $ match at line
	// boundaries and '.' does not match a newline, which is RE2's (?m)
	// without (?s).
	if flags&strIgnoreLowercase != 0 {
		b.WriteString("(?mi)")
	} else {
		b.WriteString("(?m)")
	}
	atStart := true
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		switch {
		case c == '\\' && i+1 < len(pat):
			i++
			writeEscape(&b, pat[i])
			atStart = false
		case c == '[':
			i = writeBracket(&b, pat, i)
			atStart = false
		case (c == '*' || c == '+' || c == '?') && atStart:
			b.WriteByte('\\')
			b.WriteByte(c)
			atStart = false
		case c == '{' && (atStart || !intervalFollows(pat, i)):
			b.WriteString(`\{`)
			atStart = false
		case c == '(' || c == '|' || c == '^':
			b.WriteByte(c)
			atStart = true
		default:
			writeLiteral(&b, c)
			atStart = false
		}
	}
	return b.String()
}

const hexDigits = "0123456789abcdef"

// writeEscape emits an escaped character, mapping GNU word boundaries to
// RE2's and keeping other escapes verbatim.
func writeEscape(b *strings.Builder, c byte) {
	invariant.Check(b != nil, "builder present")
	switch c {
	case '<', '>':
		b.WriteString(`\b`)
	default:
		b.WriteByte('\\')
		b.WriteByte(c)
	}
}

// writeBracket copies a bracket expression from pat[i] and returns the
// index of its closing ']'. A ']' first in the set (after an optional '^')
// is a member, as in POSIX, and a backslash is a member, not an escape.
func writeBracket(b *strings.Builder, pat string, i int) int {
	invariant.Check(i < len(pat) && pat[i] == '[', "bracket starts here")
	b.WriteByte('[')
	j := i + 1
	if at([]byte(pat), j) == '^' {
		b.WriteByte('^')
		j++
	}
	if at([]byte(pat), j) == ']' {
		b.WriteString(`\]`)
		j++
	}
	var next int
	for ; j < len(pat) && pat[j] != ']'; j = next {
		next = j + 1
		switch {
		case pat[j] == '[' && at([]byte(pat), j+1) == ':':
			k := strings.Index(pat[j+2:], ":]")
			if k >= 0 {
				b.WriteString(pat[j : j+2+k+2])
				next = j + 2 + k + 2
				continue
			}
			b.WriteString(`\[`)
		case pat[j] == '\\':
			b.WriteString(`\\`)
		case pat[j] == '[':
			b.WriteString(`\[`)
		default:
			writeLiteral(b, pat[j])
		}
	}
	b.WriteByte(']')
	return j
}

// writeLiteral writes c as itself, or as \xNN when it is not ASCII: the
// matcher runs RE2 over a byte-to-rune transcoding of the window, so byte
// 0xNN is rune U+00NN.
func writeLiteral(b *strings.Builder, c byte) {
	invariant.Check(b != nil, "builder present")
	if c < 0x80 {
		b.WriteByte(c)
		return
	}
	b.WriteString(`\x`)
	b.WriteByte(hexDigits[c>>4])
	b.WriteByte(hexDigits[c&0x0f])
}

// intervalFollows reports whether pat[i] == '{' begins a valid interval
// {n}, {n,} or {n,m}; otherwise the brace is a literal in POSIX.
func intervalFollows(pat string, i int) bool {
	invariant.Check(i < len(pat) && pat[i] == '{', "brace starts here")
	s := []byte(pat)
	j := i + 1
	if !cIsDigit(at(s, j)) {
		return false
	}
	for ; j < len(s) && cIsDigit(s[j]); j++ {
	}
	if at(s, j) == ',' {
		j++
		for ; j < len(s) && cIsDigit(s[j]); j++ {
		}
	}
	return at(s, j) == '}'
}

// regexLiterals derives from RE2 source a set of ASCII literals of which
// every match must contain at least one, whether their letters match
// either case (the literals are then lower case), and whether the
// literal must sit at the start of a line. Every part of the top-level
// concatenation is mandatory, so a literal part is mandatory, and an
// alternation part forces one of its branches' own mandatory literals.
// Capture groups, plus and non-optional repeats are looked through. A
// pattern anchored with ^ whose first part begins with a literal gets
// the line-start form, which is checked per line; otherwise a single
// literal of three bytes or more is preferred to a set. nil when
// nothing is known.
func regexLiterals(src string) ([]string, bool, bool) {
	invariant.Check(src != "", "pattern given")
	top, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return nil, false, false
	}
	top = unwrapMandatory(top)
	subs := []*syntax.Regexp{top}
	if top.Op == syntax.OpConcat {
		subs = top.Sub
	}
	if set, fold := lineStartSet(subs); set != nil {
		return set, fold, true
	}
	set, fold := containedSet(subs)
	return set, fold, false
}

// containedSet is the literal set that must appear anywhere in the
// region: the longest literal part, or one alternation part's branches.
func containedSet(subs []*syntax.Regexp) ([]string, bool) {
	invariant.Check(len(subs) > 0, "parts given")
	single, singleFold := "", false
	var set []string
	setFold := false
	for _, sub := range subs {
		sub = unwrapMandatory(sub)
		lit, f := partLiteral(sub)
		if len(lit) > len(single) {
			single, singleFold = lit, f
		}
		if sub.Op == syntax.OpAlternate && set == nil {
			set, setFold = alternateLiterals(sub.Sub)
		}
	}
	if len(single) >= 3 || set == nil {
		if single == "" {
			return nil, false
		}
		return []string{single}, singleFold
	}
	return set, setFold
}

// lineStartSet is the literal set a ^-anchored pattern's match must begin
// with: the prefixes of the part after the anchor, each extended by the
// prefixes of an alternation that follows a lone literal. nil when the
// pattern is not anchored or does not begin with literals.
func lineStartSet(subs []*syntax.Regexp) ([]string, bool) {
	invariant.Check(len(subs) > 0, "parts given")
	if len(subs) < 2 || subs[0].Op != syntax.OpBeginLine {
		return nil, false
	}
	first := unwrapMandatory(subs[1])
	set, fold := prefixSet(first)
	if set == nil {
		return nil, false
	}
	if first.Op != syntax.OpLiteral || len(subs) < 3 {
		return set, fold
	}
	next := unwrapMandatory(subs[2])
	more, moreFold := prefixSet(next)
	if next.Op != syntax.OpAlternate || more == nil || moreFold != fold {
		return set, fold
	}
	invariant.Check(len(set) == 1, "a literal has one prefix")
	joined := make([]string, 0, len(more))
	for _, m := range more {
		joined = append(joined, set[0]+m)
	}
	return joined, fold
}

// prefixSet is the literals a node's match must begin with: a literal
// itself, the members of a small character class (the parser turns an
// alternation of single characters into one), one such prefix per
// branch of an alternation, or the prefixes of a concatenation's first
// part.
func prefixSet(re *syntax.Regexp) ([]string, bool) {
	invariant.Check(re != nil, "node given")
	head := re
	if re.Op == syntax.OpConcat {
		invariant.Check(len(re.Sub) > 0, "concatenation has parts")
		head = unwrapMandatory(re.Sub[0])
	}
	switch head.Op {
	case syntax.OpLiteral:
		if lit, fold := asciiLiteral(head); lit != "" {
			return []string{lit}, fold
		}
	case syntax.OpCharClass:
		return classLiterals(head), false
	case syntax.OpAlternate:
		return branchPrefixes(head.Sub)
	default:
	}
	return nil, false
}

// classLiterals is a character class's members as one-byte literals when
// they are few and ASCII; the class already lists both cases of a letter
// when the pattern folds case, so no folding applies.
func classLiterals(re *syntax.Regexp) []string {
	invariant.Check(re.Op == syntax.OpCharClass, "character class")
	invariant.Check(len(re.Rune)%2 == 0, "ranges come in pairs")
	var set []string
	for i := 0; i < len(re.Rune)/2; i++ {
		lo, hi := re.Rune[2*i], re.Rune[2*i+1]
		if lo <= 0 || hi >= 0x80 || len(set)+int(hi-lo)+1 > maxAlternateLiterals {
			return nil
		}
		for r := lo; r <= hi; r++ {
			set = append(set, string(low8(uint64(r))))
		}
	}
	return set
}

// branchPrefixes is one prefix literal per branch, or nil when a branch
// has none, the branches disagree on case folding, or there are too many.
func branchPrefixes(branches []*syntax.Regexp) ([]string, bool) {
	invariant.Check(len(branches) >= 2, "an alternation has branches")
	if len(branches) > maxAlternateLiterals {
		return nil, false
	}
	set := make([]string, 0, len(branches))
	fold := false
	for i, br := range branches {
		br = unwrapMandatory(br)
		var lit string
		var f bool
		switch {
		case br.Op == syntax.OpLiteral:
			lit, f = asciiLiteral(br)
		case br.Op == syntax.OpConcat && len(br.Sub) > 0:
			lit, f = asciiLiteral(unwrapMandatory(br.Sub[0]))
		}
		if lit == "" || (i > 0 && f != fold) || len(set) >= maxAlternateLiterals {
			return nil, false
		}
		set = append(set, lit)
		fold = f
	}
	return set, fold
}

// partLiteral is the mandatory literal of one part: the part itself when
// it is a literal, or the longest literal among a concatenation's parts.
func partLiteral(re *syntax.Regexp) (string, bool) {
	invariant.Check(re != nil, "node given")
	if re.Op == syntax.OpConcat {
		return directLiteral(re.Sub)
	}
	return asciiLiteral(re)
}

// unwrapMandatory looks through nodes whose sub-expression must match:
// capture groups, plus, and repeats with a minimum of one or more.
func unwrapMandatory(re *syntax.Regexp) *syntax.Regexp {
	invariant.Check(re != nil, "node given")
	for depth := 0; depth < 8; depth++ {
		mandatory := re.Op == syntax.OpCapture || re.Op == syntax.OpPlus ||
			(re.Op == syntax.OpRepeat && re.Min >= 1)
		if !mandatory {
			return re
		}
		invariant.Check(len(re.Sub) == 1, "a wrapper has one sub")
		re = re.Sub[0]
	}
	return re
}

// directLiteral is the longest ASCII literal among the parts of a
// concatenation, each looked through for mandatory wrappers.
func directLiteral(subs []*syntax.Regexp) (string, bool) {
	invariant.Check(len(subs) > 0, "concatenation has parts")
	best, fold := "", false
	for _, sub := range subs {
		if lit, f := asciiLiteral(unwrapMandatory(sub)); len(lit) > len(best) {
			best, fold = lit, f
		}
	}
	return best, fold
}

// alternateLiterals is one mandatory literal per branch of an
// alternation, or nil when a branch has none, the branches disagree on
// case folding, or there are too many to be worth scanning for.
func alternateLiterals(branches []*syntax.Regexp) ([]string, bool) {
	invariant.Check(len(branches) >= 2, "an alternation has branches")
	if len(branches) > maxAlternateLiterals {
		return nil, false
	}
	set := make([]string, 0, len(branches))
	fold := false
	for i, br := range branches {
		lit, f := partLiteral(unwrapMandatory(br))
		if lit == "" || (i > 0 && f != fold) {
			return nil, false
		}
		set = append(set, lit)
		fold = f
	}
	return set, fold
}

// maxAlternateLiterals bounds a prefilter set.
const maxAlternateLiterals = 16

// asciiLiteral is a literal node's text when every rune is ASCII, lower
// cased when the node folds case (the parser stores folded letters as
// their smallest equivalent, the upper-case ASCII letter).
func asciiLiteral(re *syntax.Regexp) (string, bool) {
	invariant.Check(re != nil, "node given")
	if re.Op != syntax.OpLiteral || len(re.Rune) == 0 {
		return "", false
	}
	fold := re.Flags&syntax.FoldCase != 0
	var b strings.Builder
	for _, r := range re.Rune {
		if r >= 0x80 || r <= 0 {
			return "", false
		}
		c := low8(uint64(r))
		if fold {
			c = cToLower(c)
		}
		b.WriteByte(c)
	}
	return b.String(), fold
}
