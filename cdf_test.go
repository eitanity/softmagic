// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"context"
	"encoding/binary"
	"testing"
)

// cdfChainDoc is a CDF whose sectors are 1 MiB and whose short-sector
// table is a chain of n sectors starting at sector 1, described by a
// table in sector 0. The input holds the header and that table, plus
// extra zero sectors.
func cdfChainDoc(n, extra int) []byte {
	const ss = 1 << 20
	b := make([]byte, ss*(2+extra))
	le := binary.LittleEndian
	le.PutUint64(b, cdfMagic)
	le.PutUint16(b[0x18:], 0x3e)
	le.PutUint16(b[0x1a:], 3)
	le.PutUint16(b[0x1c:], 0xfffe)
	le.PutUint16(b[0x1e:], 20) // sector size 2^20
	le.PutUint16(b[0x20:], 6)
	le.PutUint32(b[0x2c:], 1) // one table sector
	le.PutUint32(b[0x30:], 0xfffffffe)
	le.PutUint32(b[0x38:], 4096)
	le.PutUint32(b[0x3c:], 1) // short-sector table starts at sector 1
	le.PutUint32(b[0x40:], 0xfffffffe)
	for i := range 109 {
		le.PutUint32(b[0x4c+4*i:], 0xffffffff)
	}
	le.PutUint32(b[0x4c:], 0) // the table is sector 0
	sat := b[ss : 2*ss]
	for i := range ss / 4 {
		le.PutUint32(sat[4*i:], 0xffffffff)
	}
	le.PutUint32(sat, 0xfffffffd)
	for i := 1; i < n; i++ {
		le.PutUint32(sat[4*i:], uint32(i+1))
	}
	le.PutUint32(sat[4*n:], 0xfffffffe)
	return b
}

// allocatedBy is the bytes f allocates.
func allocatedBy(f func()) uint64 {
	before := heapAllocated()
	f()
	return heapAllocated() - before
}

// TestCDFChainBeyondInput: a chain longer than the input can hold is
// refused before its buffer is allocated, with the answer the reference
// gives, on every architecture (on 32-bit hosts n*ss used to wrap).
func TestCDFChainBeyondInput(t *testing.T) {
	db := compileMagdir(t) // database
	const want = "Composite Document File V2 Document, Can't read SSAT"
	for _, c := range []struct{ n, extra int }{{2049, 0}, {4096, 1}, {10000, 0}} { // chainCase
		data := cdfChainDoc(c.n, c.extra)
		var r Result
		alloc := allocatedBy(func() { r = db.Identify(data) })
		if r.Description != want {
			t.Errorf("chain of %d: %q, want %q", c.n, r.Description, want)
		}
		if alloc > 64<<20 {
			t.Errorf("chain of %d: allocated %d MiB for a %d MiB input", c.n, alloc>>20, len(data)>>20)
		}
	}
}

// TestCDFChainLimit: a chain the input does hold but that exceeds
// cdfChainLimit is refused and reported as TruncCDF.
func TestCDFChainLimit(t *testing.T) {
	db := compileMagdir(t)     // database
	n := cdfChainLimit>>20 + 1 // chainLength
	data := cdfChainDoc(n, n)
	r := db.IdentifyWith(context.Background(), data, Options{MaxBytes: len(data)})
	if r.Examined.Truncated != TruncCDF {
		t.Errorf("chain of %d MiB sectors: Truncated %q, want %q (%q)", n, r.Examined.Truncated, TruncCDF, r.Description)
	}
}
