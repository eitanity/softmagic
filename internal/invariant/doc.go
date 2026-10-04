// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

// Package invariant is the module's one assertion primitive (Power of Ten
// rule 5: assertions stay in production and have a recovery action).
//
// Check has two behaviours selected by build tag:
//
//   - with the tag softmagic_assert (every test, fuzz and CI run) a failed
//     check panics with the message, so a violated invariant is a found bug;
//   - without it (release) Check returns the condition, and the caller takes
//     the recovery action: an error from Compile, or the entry
//     under evaluation abandoned with Truncated: "invariant".
//
// Conditions passed to Check must be side-effect free.
package invariant
