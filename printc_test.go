// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"math"
	"testing"
)

// TestFormatCFloat: special values as glibc's printf spells them, not Go's.
// A NaN's sign is printed, as in a measure rule whose float reads
// 0xffc00000 ("spot sensor temperature -nan").
func TestFormatCFloat(t *testing.T) {
	negNaN := math.Float64frombits(0xfff8000000000000)
	for _, c := range []struct {
		want string
		f    float64
		verb byte
	}{
		{"nan", math.NaN(), 'f'},
		{"-nan", negNaN, 'f'},
		{"-nan", float64(math.Float32frombits(0xffc00000)), 'g'},
		{"inf", math.Inf(1), 'e'},
		{"-inf", math.Inf(-1), 'g'},
		{"1.500000", 1.5, 'f'},
	} {
		if got := formatCFloat(c.f, c.verb, 6); got != c.want {
			t.Errorf("formatCFloat(%v, %c) = %q, want %q", c.f, c.verb, got, c.want)
		}
	}
}

// TestTrimSpaceCString: file_strtrim trims the C string, which ends at its
// first NUL, so spaces before the NUL go even when NULs follow ("#!/bin/sh   "
// in a 128-byte value).
func TestTrimSpaceCString(t *testing.T) {
	for in, want := range map[string]string{
		"/bin/sh   \x00\x00\x00": "/bin/sh",
		"  a b  ":                "a b",
		"\x00tail":               "",
		"   ":                    "",
	} {
		if got := string(trimSpace([]byte(in))); got != want {
			t.Errorf("trimSpace(%q) = %q, want %q", in, got, want)
		}
	}
}
