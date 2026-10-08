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
)
