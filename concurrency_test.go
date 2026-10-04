// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

func corpusFiles(t *testing.T) [][]byte {
	t.Helper()
	names, err := filepath.Glob("testdata/corpus/*.testfile")
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, n := range names {
		data, err := os.ReadFile(filepath.Clean(n))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, data)
	}
	return out
}

// TestRace identifies the corpus from 16 goroutines through
// one Database, under -race.
func TestRace(t *testing.T) {
	db := compileMagdir(t)
	files := corpusFiles(t)
	want := make([]Result, len(files))
	for i, f := range files {
		want[i] = db.Identify(f)
	}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range files {
				k := (i + g) % len(files)
				r := db.Identify(files[k])
				if r.Description != want[k].Description || r.MIME != want[k].MIME {
					t.Errorf("goroutine %d file %d: %q vs %q", g, k, r.Description, want[k].Description)
				}
			}
		}(g)
	}
	wg.Wait()
}

// BenchmarkIdentify runs over the corpus, database compiled once.
func BenchmarkIdentify(b *testing.B) {
	db, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{})
	if err != nil {
		b.Fatal(err)
	}
	names, err := filepath.Glob("testdata/corpus/*.testfile")
	if err != nil {
		b.Fatal(err)
	}
	var files [][]byte
	for _, n := range names {
		data, err := os.ReadFile(filepath.Clean(n))
		if err != nil {
			b.Fatal(err)
		}
		files = append(files, data)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.Identify(files[i%len(files)])
	}
}

func BenchmarkCompile(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := compileFS(os.DirFS("magic/Magdir"), CompileOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

// TestLatencyReport logs per-file latency percentiles over the corpus (targets:
// median <= 1 ms, p95 <= 5 ms, max <= 50 ms). It fails only
// on the max bound, which does not depend on the machine's speed as much.
func TestLatencyReport(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing")
	}
	db := compileMagdir(t)
	files := corpusFiles(t)
	const rounds = 20
	per := make([]time.Duration, 0, len(files))
	for _, f := range files {
		best := time.Duration(1 << 62)
		for r := 0; r < rounds; r++ {
			start := time.Now()
			db.Identify(f)
			if d := time.Since(start); d < best {
				best = d
			}
		}
		per = append(per, best)
	}
	sort.Slice(per, func(i, j int) bool { return per[i] < per[j] })
	median, p95, max := per[len(per)/2], per[len(per)*95/100], per[len(per)-1]
	t.Logf("latency over %d files (best of %d): median %v, p95 %v, max %v", len(per), rounds, median, p95, max)
	if max > 50*time.Millisecond {
		t.Errorf("max latency %v exceeds 50 ms", max)
	}
}
