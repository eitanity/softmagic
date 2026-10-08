// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

// Result is what Identify returns. A blank is never an answer:
// an input that matches no rule has Description "data" and MIME
// "application/octet-stream", as file(1) prints.
type Result struct {
	// Description is exactly what `file -b` prints.
	Description string
	// MIME is exactly what `file -b -i` prints before "; charset=".
	MIME string
	// Charset is the charset `file -i` reports; "binary" for binary input.
	Charset string
	// Extensions is the !:ext list of the first annotated line on the
	// winning path, split on '/'; nil when there is none.
	Extensions []string
	// Apple is the !:apple creator/type of the first annotated line on the
	// winning path (what `file --apple` prints); "" when there is none.
	Apple string
	// Rules lists every rule line that contributed text, in emission order.
	Rules []RuleID
	// Phase names the pass that produced Description: PhaseBuiltin,
	// PhaseMagic, PhaseText or PhaseDefault. file(1)'s driver needs it:
	// the reference joins its stat-layer prefix to a text-phase
	// description differently from the others.
	Phase string
	// Continued is set with Options.Continue: what `file -b -k` prints in
	// each output mode, as lists.
	Continued Continued
	// Failures is set when a hard limit of Options.Limits stopped an output
	// mode, where the reference reports an error; the fields above are then
	// what was established before it.
	Failures Failures
	// Examined says what the call looked at and what stopped it.
	Examined Examined
	// Strength is the winning entry's computed strength (as file -l prints it), 0 when
	// no entry matched.
	Strength int
}

// Continued is a continue-mode answer (libmagic's MAGIC_CONTINUE, file -k).
// The reference computes each output mode in a run of its own, and an
// entry can answer in one mode and not another (a match with no MIME
// annotation is a description and no MIME type), so element i of one list
// is not about the same entry as element i of another. Each list is that
// mode's output split where a separator was printed; joined with "\n- " it
// is byte-identical to file -b -k in that mode. An element can be empty:
// the reference prints a separator after a match that printed nothing in
// that mode. All are nil without Options.Continue.
type Continued struct {
	// Descriptions is file -b -k.
	Descriptions []string
	// MIMEs is file -b -k --mime-type. file -b -k -i is MIMEs joined,
	// then "; charset=" and Result.Charset.
	MIMEs []string
	// Encodings is file -b -k --mime-encoding: separators from the matches,
	// which print nothing in that mode, then the charset in the last
	// element.
	Encodings []string
	// Extensions is file -b -k --extension, each element as printed
	// ("jpeg/jpg").
	Extensions []string
	// Apple is file -b -k --apple.
	Apple []string
	// Failures are the continue runs that a hard limit stopped; a mode
	// that failed has no list.
	Failures Failures
}

// Failures holds, per output mode, the error libmagic reports when a hard
// limit of Options.Limits stopped that mode's run. Each mode is a run of
// its own in the reference, and a run that returns at its first annotation
// can finish before the line that stops another, so one mode can fail
// while another answers.
type Failures struct {
	Description Failure
	MIME        Failure // also -i, which is the MIME run with the charset after it
	Encoding    Failure
	Extension   Failure
	Apple       Failure
}

// Failure is libmagic's error for one output mode; the zero value is none.
// libmagic appends Message to its current output buffer, after a blank when
// that is not empty, and magic_error returns the result: see Text.
type Failure struct {
	// Message is libmagic's own: "indirect count (50) exceeded".
	Message string
	// Buffer is what the output buffer held: what the mode had printed, or,
	// when Pushed, the output of the indirect match or ELF reader the error
	// came inside, which the reference reads into a buffer of its own.
	Buffer string
	Pushed bool
}

// Failed reports whether the mode stopped with an error.
func (f Failure) Failed() bool { return f.Message != "" }

// Text is magic_error's text, which file(1) prints after "ERROR: ".
// prefix is whatever the caller's buffer held before the identification
// began (file's stat-layer words, such as "setuid "); it is part of the
// buffer only when the error was not inside a pushed one.
func (f Failure) Text(prefix string) string {
	buf := f.Buffer
	if !f.Pushed {
		buf = prefix + buf
	}
	if buf != "" {
		buf += " "
	}
	return buf + f.Message
}

// Phases: which pass of file_buffer produced the description.
const (
	// PhaseBuiltin is a built-in detector (tar, JSON, CSV, SIMH, CDF).
	PhaseBuiltin = "builtin"
	// PhaseMagic is a binary rule match, with any ELF text appended.
	PhaseMagic = "magic"
	// PhaseText is the text phase: text rules and the encoding
	// description.
	PhaseText = "text"
	// PhaseDefault is "data", "empty" or "very short file (no magic)".
	PhaseDefault = "default"
)

// RuleID names a rule line by its source file and line number.
type RuleID struct {
	File string
	Line int
}

// Examined reports the scope and the limits of one identification.
type Examined struct {
	// Truncated is "" or the limit that stopped a match: "recursion",
	// "search", "regex", "time", "output" or "invariant" (an internal
	// consistency check failed and the entry under evaluation was skipped).
	Truncated string
	// DatabaseHash is the hash of the Magdir source the database was
	// compiled from.
	DatabaseHash string
	// ImplementsFile is the file(1) release whose grammar and ordering this
	// library reproduces.
	ImplementsFile string
	// Bytes is the number of input bytes actually consulted.
	Bytes int
	// Complete is true when the whole input was available; false for a
	// bounded prefix (IdentifyPrefix).
	Complete bool
	// NeedMore is true when a longer prefix could change Description or
	// MIME; always false when Complete.
	NeedMore bool
}

// Truncation reasons.
const (
	TruncRecursion = "recursion"
	TruncSearch    = "search"
	TruncRegex     = "regex"
	TruncTime      = "time"
	TruncOutput    = "output"
	TruncInvariant = "invariant"
	// TruncIndirect, TruncName and TruncELF are the hard limits of
	// Options.Limits: the reference stops with an error, and so does the
	// output mode that reached one (see Result.Failures).
	TruncIndirect = "indirect"
	TruncName     = "name"
	TruncELF      = "elf"
)
