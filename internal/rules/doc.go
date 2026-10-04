// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

// Package rules holds the test that checks this module's own code against
// the parts of Holzmann's Power of Ten ("The Power of 10: Rules for
// Developing Safety-Critical Code", IEEE Computer 39(6), 2006) that no
// linter checks:
// recursion, loop forms, assertion density, pointer and func types,
// package-level state, build tags and suppression comments. It uses only
// go/ast, go/parser, go/types and go/importer from the standard library, so
// it adds nothing to go.mod. The checks bind this module's non-test
// code; the standard library is called, not audited.
package rules
