// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

//go:build softmagic_assert

package invariant

// Check panics when cond is false. It returns cond so call sites read the
// same in both build modes.
func Check(cond bool, what string) bool {
	if !cond {
		panic("softmagic invariant violated: " + what)
	}
	return cond
}

// Enabled reports whether a failed Check panics in this build.
const Enabled = true
