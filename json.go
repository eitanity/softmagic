// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// Translated from is_json.c, file 5.48, Copyright (c) Ian F. Darwin
// 1986-1995 (see COPYING), with the reference's recursive descent replaced
// by an explicit container stack, since the module has no recursion. The grammar accepted,
// the depth limit of 500 and the counting are the reference's.

package softmagic

import "github.com/eitanity/softmagic/internal/invariant"

// jsonMaxDepth is the reference's level limit of 500 in container depth:
// its level counter advances twice per container.
const jsonMaxDepth = 250

// jsonFrame is one open array or object.
type jsonFrame struct {
	object bool
	// expectValue is true when the next token must be a value (after '['
	// or ',' in an array, after ':' in an object); otherwise a separator
	// or closer is expected.
	expectValue bool
}

// jsonParser holds the cursor, the container stack and the counts the
// reference keeps in st[].
type jsonParser struct {
	uc     []byte
	i      int
	stack  [jsonMaxDepth + 1]jsonFrame
	depth  int
	arrays int // st[JSON_ARRAYN]: completed arrays
	objs   int // st[JSON_OBJECT]: completed objects
}

func jsonIsSpace(c byte) bool { return c == ' ' || c == '\n' || c == '\r' || c == '\t' }

func (p *jsonParser) skipSpace() {
	for ; p.i < len(p.uc) && jsonIsSpace(p.uc[p.i]); p.i++ {
	}
}

// detectJSON is file_is_json: 1 for one JSON document, 2 for newline
// delimited JSON (a second document of the same kind follows), else none.
func detectJSON(buf []byte) builtinResult {
	invariant.Check(len(buf) >= 2, "detectors run on two or more bytes")
	p := jsonParser{uc: buf}
	jt := p.parseTop()
	switch jt {
	case 1:
		return builtinResult{desc: "JSON text data", mime: "application/json", hit: true}
	case 2:
		return builtinResult{desc: "New Line Delimited JSON text data", mime: "application/x-ndjson", hit: true}
	default:
		return builtinResult{}
	}
}

// parseTop is json_parse at level 0.
func (p *jsonParser) parseTop() int {
	p.skipSpace()
	if p.i >= len(p.uc) {
		return 0
	}
	first := p.uc[p.i]
	if !p.parseValue() {
		return 0
	}
	p.skipSpace()
	container := p.arrays > 0 || p.objs > 0
	if p.i >= len(p.uc) {
		if container {
			return 1
		}
		return 0
	}
	if p.uc[p.i] == first && p.parseValue() && (p.arrays > 0 || p.objs > 0) {
		return 2
	}
	return 0
}

// parseValue parses one value, descending into containers with the
// explicit stack. It returns whether the value was well formed, leaving
// the cursor after it (or where the reference leaves it on failure).
func (p *jsonParser) parseValue() bool {
	invariant.Check(p.depth == 0, "a top-level value starts with an empty stack")
	for steps := 0; steps <= len(p.uc)+jsonMaxDepth; steps++ {
		ok, done := p.step()
		if !ok {
			return false
		}
		if done {
			return true
		}
	}
	return false
}

// step advances by one token. done is true when the outermost value is
// complete.
func (p *jsonParser) step() (ok, done bool) {
	p.skipSpace()
	if p.depth == 0 {
		return p.scalarOrOpen()
	}
	f := &p.stack[p.depth-1] // frame
	if p.i >= len(p.uc) {
		return false, false
	}
	c := p.uc[p.i] // char
	switch {
	case f.expectValue && f.object:
		return p.objectMember(c)
	case f.expectValue: // in an array ']' is accepted after '[' and after ','
		if c == ']' {
			return p.closeArray()
		}
		f.expectValue = false
		return p.scalarOrOpen()
	case c == ',':
		p.i++
		f.expectValue = true
		return true, false
	case !f.object && c == ']':
		return p.closeArray()
	case f.object && c == '}':
		return p.closeObject()
	default:
		return false, false
	}
}

func (p *jsonParser) closeArray() (ok, done bool) {
	invariant.Check(p.depth > 0 && !p.stack[p.depth-1].object, "closing an open array")
	p.i++
	p.arrays++
	return p.closeFrame()
}

func (p *jsonParser) closeObject() (ok, done bool) {
	invariant.Check(p.depth > 0 && p.stack[p.depth-1].object, "closing an open object")
	p.i++
	p.objs++
	return p.closeFrame()
}

// closeFrame pops a container; the parent now expects a separator.
func (p *jsonParser) closeFrame() (ok, done bool) {
	p.depth--
	if p.depth == 0 {
		return true, true
	}
	p.stack[p.depth-1].expectValue = false
	return true, false
}

// objectMember parses `"key" :` and leaves the value to the next step.
func (p *jsonParser) objectMember(c byte) (ok, done bool) {
	f := &p.stack[p.depth-1] // frame
	if c == '}' {
		return p.closeObject()
	}
	if c != '"' {
		return false, false
	}
	p.i++
	if !p.parseString() {
		return false, false
	}
	p.skipSpace()
	if p.i >= len(p.uc) || p.uc[p.i] != ':' {
		return false, false
	}
	p.i++
	f.expectValue = false
	// The member's value is parsed on this same step, so a nested container
	// is pushed before the separator is expected.
	p.skipSpace()
	return p.scalarOrOpen()
}

// scalarOrOpen parses a scalar, or pushes a container frame.
func (p *jsonParser) scalarOrOpen() (ok, done bool) {
	if p.i >= len(p.uc) {
		return false, false
	}
	c := p.uc[p.i] // char
	switch c {
	case '[', '{':
		if p.depth >= jsonMaxDepth {
			return false, false
		}
		p.i++
		p.stack[p.depth] = jsonFrame{object: c == '{', expectValue: true}
		p.depth++
		return true, false
	case '"':
		p.i++
		ok = p.parseString()
	case 't':
		ok = p.parseConst("true")
	case 'f':
		ok = p.parseConst("false")
	case 'n':
		ok = p.parseConst("null")
	default:
		ok = p.parseNumber()
	}
	if !ok {
		return false, false
	}
	return true, p.depth == 0
}

// parseString is json_parse_string after the opening quote.
func (p *jsonParser) parseString() bool {
	for n := 0; n < len(p.uc); n++ { // each pass consumes at least one byte
		if p.i >= len(p.uc) {
			return false
		}
		c := p.uc[p.i]
		p.i++
		switch c {
		case 0:
			return false
		case '"':
			return true
		case '\\':
			if !p.parseEscape() {
				return false
			}
		default:
		}
	}
	return false
}

// parseEscape is the backslash case of json_parse_string.
func (p *jsonParser) parseEscape() bool {
	if p.i >= len(p.uc) {
		return false
	}
	c := p.uc[p.i]
	p.i++
	switch c {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		return true
	case 'u':
		if len(p.uc)-p.i < 4 {
			p.i = len(p.uc)
			return false
		}
		for k := 0; k < 4; k++ {
			if hexToInt(p.uc[p.i]) < 0 {
				p.i++
				return false
			}
			p.i++
		}
		return true
	default:
		return false
	}
}

// parseConst is json_parse_const: the keyword's remaining letters.
func (p *jsonParser) parseConst(word string) bool {
	invariant.Check(len(word) >= 4, "keyword")
	end := p.i + len(word)
	if end > len(p.uc) {
		end = len(p.uc)
	}
	for k := 1; k < end-p.i; k++ {
		if p.uc[p.i+k] != word[k] {
			p.i = end
			return false
		}
	}
	p.i = end
	return true
}

// parseNumber is json_parse_number.
func (p *jsonParser) parseNumber() bool {
	if p.i >= len(p.uc) {
		return false
	}
	if p.uc[p.i] == '-' {
		p.i++
	}
	got := p.digits()
	if p.i >= len(p.uc) {
		return got
	}
	if p.uc[p.i] == '.' {
		p.i++
	}
	got = p.digits() || got
	if p.i >= len(p.uc) {
		return got
	}
	if got && (p.uc[p.i] == 'e' || p.uc[p.i] == 'E') {
		p.i++
		if p.i >= len(p.uc) {
			return false
		}
		if p.uc[p.i] == '+' || p.uc[p.i] == '-' {
			p.i++
		}
		return p.digits()
	}
	return got
}

// digits consumes decimal digits and reports whether there was one.
func (p *jsonParser) digits() bool {
	invariant.Check(p.i >= 0 && p.i <= len(p.uc), "cursor within the input")
	start := p.i
	for ; p.i < len(p.uc) && cIsDigit(p.uc[p.i]); p.i++ {
	}
	return p.i > start
}
