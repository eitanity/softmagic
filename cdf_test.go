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

// TestMemoryBudget: a stream the input does hold but that is larger than
// Options.MaxMemory is refused with Truncated "memory" and the answer the
// reference gives when that read fails; the default budget reads it.
func TestMemoryBudget(t *testing.T) {
	db := compileMagdir(t) // database
	data := cdfChainDoc(10, 10)
	small := db.IdentifyWith(context.Background(), data, Options{MaxBytes: len(data), MaxMemory: 4 << 20})
	if small.Examined.Truncated != TruncMemory {
		t.Errorf("4 MiB budget: Truncated %q, want %q (%q)", small.Examined.Truncated, TruncMemory, small.Description)
	}
	if want := "Composite Document File V2 Document, Can't read SSAT"; small.Description != want {
		t.Errorf("4 MiB budget: %q, want %q", small.Description, want)
	}
	full := db.IdentifyWith(context.Background(), data, Options{MaxBytes: len(data)})
	if full.Examined.Truncated == TruncMemory {
		t.Errorf("default budget refused a 10 MiB stream: %q", full.Description)
	}
}

// TestPoolDropsLargeBuffers: a scan holding more than poolKeepBytes goes
// back to the pool without its buffers.
func TestPoolDropsLargeBuffers(t *testing.T) {
	sp := newScanPool()
	s := &scan{srcbuf: make([]byte, 1<<20), inbuf: make([]byte, poolKeepBytes+1), held: poolKeepBytes + 1}
	s.cdfbuf[0] = make([]byte, 1<<20)
	sp.put(s)
	if s.srcbuf != nil || s.cdfbuf[0] != nil || s.inbuf != nil || s.held != 0 {
		t.Errorf("buffers kept: src %d, cdf %d, in %d, held %d", cap(s.srcbuf), cap(s.cdfbuf[0]), cap(s.inbuf), s.held)
	}
	k := &scan{srcbuf: make([]byte, 1<<20), held: 1 << 20}
	sp.put(k)
	if k.srcbuf == nil || k.held != 1<<20 {
		t.Error("a scan within poolKeepBytes lost its buffers")
	}
}

// TestCDFDirBytes: the budget's charge per directory entry is at least
// what an entry takes (92 bytes on 32-bit hosts, 96 on 64-bit ones), and
// not much more.
func TestCDFDirBytes(t *testing.T) {
	const n = 1 << 12
	var dirs []cdfDir
	got := allocatedBy(func() { dirs = make([]cdfDir, n) })
	if len(dirs) != n || got > n*cdfDirBytes+8192 || got < n*(cdfDirBytes-8) {
		t.Errorf("%d entries allocated %d bytes, charged %d", n, got, n*cdfDirBytes)
	}
}

// TestCatalogNamesBounded: a catalog of two-byte records, too short to
// hold a name, reserves room for the names that can fit, not one per
// record (which was 8 MiB of string headers for this 1 MiB catalog).
func TestCatalogNamesBounded(t *testing.T) {
	tab := make([]byte, 1<<20)
	for i := 0; i < len(tab); i += 2 {
		tab[i] = 2
	}
	st := cdfStream{tab: tab, ss: 512, len: len(tab) / 512}
	got := allocatedBy(func() { unpackCatalog(&st) })
	if got > 2<<20 {
		t.Errorf("a 1 MiB catalog of two-byte records allocated %d MiB", got>>20)
	}
}
