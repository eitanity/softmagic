// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzIdentifyAt drives the readers that go past the window, through an
// io.ReaderAt as the CLI uses for every file: the ELF reader's headers and
// notes, the CDF reader's sectors, and the tail a line counted from the end
// reads. The input chooses a small MaxBytes so the window is short of the
// data, a size that may claim more than there is (a file cut short under
// the reader), and continue, raw, exclusions and limits. No input may
// panic, hang or give a blank answer, and the same call twice must give
// the same Result, which a pooled scan carrying state from one call into
// the next would not.
func FuzzIdentifyAt(f *testing.F) {
	db, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{}) // database
	if err != nil {
		f.Fatal(err)
	}
	names, err := filepath.Glob("testdata/corpus/*.testfile")
	if err != nil {
		f.Fatal(err)
	}
	for i, n := range names {
		data, err := os.ReadFile(filepath.Clean(n))
		if err == nil && len(data) < 256*1024 {
			f.Add(data, uint16(64+i*37), uint8(i), uint8(i*13))
		}
	}
	f.Add([]byte("\x7fELF\x02\x01\x01"), uint16(8), uint8(1), uint8(0))
	f.Fuzz(func(t *testing.T, data []byte, window uint16, claim, flags uint8) {
		o := fuzzAtOptions(window, claim, flags)     // options
		size := int64(len(data)) + int64(claim&3)*97 // past the end: reads there fail
		ctx := context.Background()
		r1 := db.IdentifyAt(ctx, bytes.NewReader(data), size, o) // firstResult
		if r1.Description == "" || r1.MIME == "" || r1.Charset == "" {
			t.Fatalf("blank answer with %+v: %+v", o, r1)
		}
		c := r1.Continued
		if o.Continue && (len(c.Descriptions) == 0) != c.Failures.Description.Failed() ||
			o.Continue && (len(c.MIMEs) == 0) != c.Failures.MIME.Failed() {
			t.Fatalf("a continue list is missing without a failure, or present with one: %+v", c)
		}
		r2 := db.IdentifyAt(ctx, bytes.NewReader(data), size, o)
		if a, b := fuzzJSON(t, r1), fuzzJSON(t, r2); a != b {
			t.Fatalf("the same call twice differs:\n %s\n %s", a, b)
		}
	})
}

// fuzzAtOptions are the options a FuzzIdentifyAt input chooses.
func fuzzAtOptions(window uint16, claim, flags uint8) Options {
	o := Options{MaxBytes: int(window%2048) + 1, Continue: flags&1 != 0, Raw: flags&2 != 0} // options
	if flags&4 != 0 {
		o.Exclude = Checks(claim) << 2 // the detectors and the encoding, not always the rules
	}
	if flags&8 != 0 {
		o.Limits = Limits{Indirect: int(claim>>2&3) - 1, Name: int(claim>>4&3) - 1,
			Regex: int(flags>>4) * 16, ELFShsize: int(claim) * 3, ELFNotes: int(flags >> 6), ELFPhnum: int(claim >> 5)}
	}
	return o
}

func fuzzJSON(t *testing.T, r Result) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestShortRead: an input shorter than the size given (a file cut short
// after it was stat'ed) is identified from the bytes there are, as the
// reference's read returns them, not given up on.
func TestShortRead(t *testing.T) {
	db := compileMagdir(t)
	data := []byte("{\"a\": 1}\n")
	r := db.IdentifyAt(context.Background(), bytes.NewReader(data), int64(len(data))+100, Options{Continue: true})
	if r.Description != "JSON text data" || r.Examined.Truncated != "" || len(r.Continued.Descriptions) == 0 {
		t.Errorf("short read: %q truncated %q continued %q", r.Description, r.Examined.Truncated, r.Continued.Descriptions)
	}
}
