// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// Reader behaviours outside the io.ReaderAt contract.
const (
	readHonest    = iota // copy the bytes there are, io.EOF when short
	readCount            // copy honestly, then report count instead, with a nil error
	readCountEOF         // copy honestly, then report count instead, with io.EOF
	readClaimFull        // past the first read: write nothing, report len(p), nil
	readZeros            // past the first read: write zeros, report len(p), nil
	readShortNil         // past the first read: write half, report half, nil
	readFail             // past the first read: report 0 and an error
)

// hostileReader reads data as behaviour says. Only reads at offset 0 are
// honest under the "past the first read" behaviours, which keeps the
// window intact and puts every later read through the hostile path.
type hostileReader struct {
	data      []byte
	count     int
	behaviour int
}

// copyAt copies the bytes the data has at off into p.
func (h *hostileReader) copyAt(p []byte, off int64) int {
	if off >= int64(len(h.data)) {
		return 0
	}
	return copy(p, h.data[off:])
}

func (h *hostileReader) ReadAt(p []byte, off int64) (int, error) {
	switch {
	case h.behaviour == readHonest, off == 0 && h.behaviour > readCountEOF:
		if n := h.copyAt(p, off); n < len(p) {
			return n, io.EOF
		}
		return len(p), nil
	case h.behaviour == readCount:
		h.copyAt(p, off)
		return h.count, nil
	case h.behaviour == readCountEOF:
		h.copyAt(p, off)
		return h.count, io.EOF
	case h.behaviour == readClaimFull:
		return len(p), nil
	case h.behaviour == readZeros:
		clear(p)
		return len(p), nil
	case h.behaviour == readShortNil:
		return h.copyAt(p, off) / 2, nil
	default:
		return 0, errors.New("read failed")
	}
}

// TestIdentifyAtBadCount: a count below zero or above the buffer gives
// the defined failure answer, where a negative count used to panic.
func TestIdentifyAtBadCount(t *testing.T) {
	db := compileMagdir(t) // database
	data := []byte("hello world\n")
	for _, c := range []struct { // countCase
		name  string
		count int
	}{
		{"negative", -1},
		{"past the buffer", len(data) + 1},
		{"far past the buffer", 1 << 30},
	} {
		for _, behaviour := range []int{readCount, readCountEOF} {
			r := db.IdentifyAt(context.Background(), &hostileReader{data: data, count: c.count, behaviour: behaviour}, int64(len(data)), Options{})
			if r.Description != "data" || r.Examined.Truncated != TruncInvariant {
				t.Errorf("%s (behaviour %d): %q (truncated %q), want data with %q", c.name, behaviour, r.Description, r.Examined.Truncated, TruncInvariant)
			}
		}
	}
	short := db.IdentifyAt(context.Background(), &hostileReader{data: data, count: 5, behaviour: readCount}, int64(len(data)), Options{})
	if want := db.Identify(data[:5]).Description; short.Description != want {
		t.Errorf("short count: %q, want the answer for the bytes received, %q", short.Description, want)
	}
}

// TestELFReadsBeyondWindow: reads past the window use only what the
// reader supplied. A reader that claims a read it did not make gives the
// answer for zeros, not bytes left in the pooled buffer by an earlier
// read of this call or of an earlier call; a short count is a failed read
// whatever the error says.
func TestELFReadsBeyondWindow(t *testing.T) {
	db := compileMagdir(t) // database
	data, err := os.ReadFile("testdata/corpus/sample-elf-pie.testfile")
	if err != nil {
		t.Fatal(err)
	}
	o := Options{MaxBytes: 128}
	at := func(behaviour int) string {
		return db.IdentifyAt(context.Background(), &hostileReader{data: data, behaviour: behaviour}, int64(len(data)), o).Description
	}
	honest := at(readHonest)
	if !strings.Contains(honest, "interpreter /") {
		t.Fatalf("honest reader: %q has no interpreter", honest)
	}
	if got, want := at(readClaimFull), at(readZeros); got != want {
		t.Errorf("reader claiming unwritten bytes: %q, want the answer for zeros, %q", got, want)
	}
	at(readHonest) // leaves this file's bytes in the pooled buffers
	if got, want := at(readClaimFull), at(readZeros); got != want {
		t.Errorf("after an earlier call: %q, want the answer for zeros, %q", got, want)
	}
	if got, want := at(readShortNil), at(readFail); got != want {
		t.Errorf("short count with no error: %q, want the failed-read answer, %q", got, want)
	}
}
