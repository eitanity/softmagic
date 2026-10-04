// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

//go:build !race

package softmagic

// raceEnabled says the race detector is on: timing assertions are skipped.
const raceEnabled = false
