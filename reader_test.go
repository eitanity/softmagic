// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"testing"
	"time"
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

// errReader fails every read with err.
type errReader struct{ err error }

func (e errReader) ReadAt([]byte, int64) (int, error) { return 0, e.err }

// TestIdentifyAtReadError: a window the reader fails to read is reported
// with its error and TruncRead, apart from a classification, so that a
// caller can say the input was unreadable as file does.
func TestIdentifyAtReadError(t *testing.T) {
	db := compileMagdir(t) // database
	eio := errors.New("input/output error")
	for _, o := range []Options{{}, {Continue: true}} {
		r := db.IdentifyAt(context.Background(), errReader{eio}, 4096, o)
		if !errors.Is(r.Examined.ReadError, eio) || r.Examined.Truncated != TruncRead || r.Description != "data" {
			t.Errorf("continue %v: error %v, truncated %q, %q; want %v, %q, data",
				o.Continue, r.Examined.ReadError, r.Examined.Truncated, r.Description, eio, TruncRead)
		}
	}
	r := db.IdentifyAt(context.Background(), errReader{io.EOF}, 4096, Options{})
	if r.Examined.ReadError != nil || r.Examined.Truncated != "" || r.Description != "empty" {
		t.Errorf("EOF at once: error %v, truncated %q, %q; want an empty input", r.Examined.ReadError, r.Examined.Truncated, r.Description)
	}
}

// The behaviours a scriptedReader read can have.
const (
	scriptHonest    = iota // the bytes there are, io.EOF when short
	scriptShort            // half of them, no error
	scriptShortErr         // half of them and an error
	scriptOverCount        // the bytes, a count one past the buffer
	scriptNegative         // a count of -1
	scriptMutate           // the bytes inverted: a file changing between reads
	scriptClaimFull        // nothing written, the whole buffer claimed
	scriptSlow             // the bytes, after a millisecond
	scriptFail             // nothing and an error
	scriptBehaviours
)

// scriptedReader reads file, each call behaving as the next byte of
// script says, in turn; seen counts the calls of each behaviour.
type scriptedReader struct {
	file   *blockFile
	seen   *[scriptBehaviours]int
	script []byte
	calls  int
}

func (r *scriptedReader) ReadAt(p []byte, off int64) (int, error) {
	b := scriptHonest
	if len(r.script) > 0 {
		b = int(r.script[r.calls%len(r.script)]) % scriptBehaviours
	}
	r.calls++
	r.seen[b]++
	switch b {
	case scriptShort, scriptShortErr:
		n, err := r.file.ReadAt(p[:len(p)/2], off)
		if b == scriptShortErr {
			return n, errors.Join(err, errors.New("read failed"))
		}
		return n, nil
	case scriptOverCount:
		_, err := r.file.ReadAt(p, off)
		return len(p) + 1, err // the count is the lie
	case scriptNegative:
		return -1, nil
	case scriptMutate:
		n, err := r.file.ReadAt(p, off)
		for i := range p[:n] {
			p[i] ^= 0xff
		}
		return n, err
	case scriptClaimFull:
		return len(p), nil
	case scriptSlow:
		time.Sleep(time.Millisecond)
	case scriptFail:
		return 0, errors.New("read failed")
	}
	return r.file.ReadAt(p, off)
}

// readerAtCase is a file a FuzzReaderAt input describes: data at the
// start and far at farPage pages of 4 KiB in, within size pages, and the
// size the call is told, as claim chooses.
func readerAtCase(data []byte, farPage uint32, far []byte, pages uint32, claim uint8) (*blockFile, int64) {
	f := newBlockFile(max(int64(len(data)), int64(pages%(1<<22))*fileBlock))
	f.put(0, data)
	f.put(uint64(farPage)*fileBlock, far)
	switch claim % 5 {
	case 1:
		return f, f.size / 2
	case 2:
		return f, -1
	case 3:
		return f, math.MaxInt64
	case 4:
		return f, f.size + 1<<30
	}
	return f, f.size
}

// FuzzReaderAt checks IdentifyAt through a reader that breaks the
// io.ReaderAt contract in the ways the script chooses, over a sparse file
// the fuzzer lays out, and told a size that may be wrong: no panic, a
// defined answer within the budgets, a read error only with TruncRead,
// and an answer later calls leave alone.
func FuzzReaderAt(f *testing.F) {
	db, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{}) // database
	if err != nil {
		f.Fatal(err)
	}
	fuzzSeeds(f, readerAtSeeds())
	f.Fuzz(func(t *testing.T, data []byte, farPage uint32, far []byte, pages uint32, claim uint8,
		script []byte, window uint16, flags uint8) {
		checkReaderAt(t, db, &[scriptBehaviours]int{}, []any{data, farPage, far, pages, claim, script, window, flags})
	})
}

// checkReaderAt is FuzzReaderAt's check of one input, counting the
// behaviours its reads had in seen.
func checkReaderAt(t *testing.T, db *Database, seen *[scriptBehaviours]int, args []any) { // database
	t.Helper()
	a := &argReader{args: args, ok: true}
	data, farPage, far, pages, claim := arg[[]byte](a), arg[uint32](a), arg[[]byte](a), arg[uint32](a), arg[uint8](a)
	script, window, flags := arg[[]byte](a), arg[uint16](a), arg[uint8](a)
	if !a.done() {
		t.Fatalf("not FuzzReaderAt's arguments: %v", args)
	}
	file, size := readerAtCase(data, farPage, far, pages, claim)
	o := fuzzAtOptions(window, claim, flags) // options
	var r Result
	fuzzBounded(t, "IdentifyAt with a scripted reader", func() {
		r = db.IdentifyAt(context.Background(), &scriptedReader{file: file, seen: seen, script: script}, size, o)
	})
	if r.Description == "" || r.MIME == "" || r.Charset == "" {
		t.Fatalf("blank answer: %+v", r)
	}
	if (r.Examined.ReadError != nil) != (r.Examined.Truncated == TruncRead) {
		t.Fatalf("read error %v with truncated %q", r.Examined.ReadError, r.Examined.Truncated)
	}
	fuzzHeld(t, db, data, r)
}

// readerAtSeeds are FuzzReaderAt's seed arguments: the ELF sample in a
// 128-byte window, so its headers are read through the reader, once with
// each behaviour after an honest first read and once with each size
// claim; and farELFSeed.
func readerAtSeeds() [][]any {
	elf, err := os.ReadFile("testdata/corpus/sample-elf-pie.testfile")
	if err != nil {
		return nil
	}
	var seeds [][]any
	for b := range byte(scriptBehaviours) {
		seeds = append(seeds, []any{elf, uint32(0), []byte{}, uint32(0), uint8(0), []byte{scriptHonest, b}, uint16(127), uint8(0)})
	}
	for claim := range uint8(5) {
		seeds = append(seeds, []any{elf, uint32(0), []byte{}, uint32(0), claim, []byte{}, uint16(127), uint8(0)})
	}
	return append(seeds, farELFSeed())
}

// farELFSeed is a FuzzReaderAt seed: a 32-bit shared object whose
// section table, holding a symbol table, is a far page 1 GiB in.
func farELFSeed() []any {
	e := elfSeeds()[6]
	e.shTypeB = 2 // SHT_SYMTAB: "not stripped" only when the table is read
	table := elfImage(&e).get(e.shoff, int(e.shnum)*40)
	e.shoff, e.fileSize = 1<<30, 1<<30+fileBlock
	return []any{elfImage(&e).get(0, fileBlock), uint32(1 << 18), table, uint32(1<<18 + 1), uint8(0),
		[]byte{}, uint16(63), uint8(0)}
}

// TestReaderAtBehaviours: FuzzReaderAt's seeds pass and reach every
// behaviour a scripted read can have, and the far page of farELFSeed is
// read.
func TestReaderAtBehaviours(t *testing.T) {
	db := compileMagdir(t) // database
	a := &argReader{args: farELFSeed(), ok: true}
	f, size := readerAtCase(arg[[]byte](a), arg[uint32](a), arg[[]byte](a), arg[uint32](a), arg[uint8](a))
	if r := db.IdentifyAt(context.Background(), f, size, Options{MaxBytes: 64}); !strings.HasSuffix(r.Description, ", not stripped") {
		t.Errorf("far section table not read: %q", r.Description)
	}
	var seen [scriptBehaviours]int
	for _, args := range readerAtSeeds() {
		checkReaderAt(t, db, &seen, args)
	}
	for b, n := range seen {
		if n == 0 {
			t.Errorf("behaviour %d never reached", b)
		}
	}
}
