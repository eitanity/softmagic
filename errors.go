// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import "strconv"

// CompileError is a refused rule file: the file and line are always named
// so a malformed rule fails here, at compile time; identifying has no
// error path.
type CompileError struct {
	File string
	Msg  string
	Line int
}

func (e *CompileError) Error() string {
	return e.File + ":" + strconv.Itoa(e.Line) + ": " + e.Msg
}

// errorf builds a CompileError for the parser's current position.
func (p *lineParser) errorf(msg string) error {
	return &CompileError{File: p.file, Line: int(p.lineno), Msg: msg}
}
