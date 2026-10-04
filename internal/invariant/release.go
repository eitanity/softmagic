// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

//go:build !softmagic_assert

package invariant

// Check returns cond. The caller recovers when it is false.
func Check(cond bool, _ string) bool {
	return cond
}

// Enabled reports whether a failed Check panics in this build.
const Enabled = false
