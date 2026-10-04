// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

// Package softmagic is a pure-Go port of file(1)'s rule-driven matcher.
//
// It compiles libmagic's Magdir source files unchanged and reproduces the
// reference's entry ordering exactly. The ordering,
// strength and tie-break code is a translation of apprentice.c from file
// 5.48, Copyright (c) Ian F. Darwin 1986-1995, maintained by Christos Zoulas;
// that notice is reproduced in COPYING.
//
// This module is a library only. The command-line tool lives in the separate
// module github.com/eitanity/softmagic-cli.
package softmagic

// ImplementsFile is the file(1) release whose grammar, strength function and
// sort this package reproduces. A compiled database made for another
// release is refused at load.
const ImplementsFile = "5.48"
