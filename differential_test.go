// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package softmagic

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// softmagic-cli's differential harness gives every fuzz target's corpus
// to softmagic and to file 5.48 and compares what they print. This
// library runs no programs, so its part is TestExportCorpus, which
// writes each corpus entry out as the files the two programs are given.

// diffCase is one comparison: the file, data and then zeros up to size
// bytes; the rules it is identified with, unless stock, when it is the
// stock database; flags for both programs; and a suffix that tells the
// cases one entry gives apart.
type diffCase struct {
	suffix string
	rules  string
	data   []byte
	flags  []string
	size   int64
	stock  bool
}

// diffTarget is how a fuzz target's arguments become cases, false when
// they are not that target's arguments, and its seeds' arguments.
type diffTarget struct {
	seeds func() [][]any
	cases func(args []any) ([]diffCase, bool)
}

// diffTargets are the targets whose inputs both programs can be given.
// FuzzLoad and FuzzLoadFields fuzz softmagic's own database format,
// which file cannot read.
func diffTargets() map[string]diffTarget {
	return map[string]diffTarget{
		"FuzzIdentify":   {identifySeeds, diffIdentify},
		"FuzzIdentifyAt": {identifyAtSeeds, diffIdentifyAt},
		"FuzzCompile":    {compileSeeds, diffCompile},
		"FuzzSafeText":   {safeTextSeeds, diffSafeText},
		"FuzzELF":        {elfSeedArgs, diffELF},
		"FuzzCDF":        {cdfSeedArgs, diffCDF},
		"FuzzDER":        {derSeeds, diffDER},
		"FuzzPString":    {pstringSeeds, diffPString},
		"FuzzRule":       {ruleSeedArgs, diffRule},
	}
}

// fuzzSeeds adds each seed's arguments to f's corpus. The testing
// package checks them against the target's signature when it runs.
func fuzzSeeds(f *testing.F, seeds [][]any) {
	for _, s := range seeds {
		f.Add(s...)
	}
}

// argReader reads a fuzz input's arguments in order. ok turns false at
// the first that is missing or of another type.
type argReader struct {
	args []any
	i    int
	ok   bool
}

// arg is the next argument, the zero value once ok is false.
func arg[T any](a *argReader) T {
	var v T
	if !a.ok || a.i >= len(a.args) {
		a.ok = false
		return v
	}
	v, a.ok = a.args[a.i].(T)
	a.i++
	return v
}

// done is whether every argument was read and of its type.
func (a *argReader) done() bool { return a.ok && a.i == len(a.args) }

func diffIdentify(args []any) ([]diffCase, bool) {
	a := &argReader{args: args, ok: true}
	data := arg[[]byte](a)
	return []diffCase{{data: data, stock: true}}, a.done()
}

// diffIdentifyAt gives file the window as -P bytes. The over-claimed
// size, which a file on disk cannot have, and the other options are not
// compared.
func diffIdentifyAt(args []any) ([]diffCase, bool) {
	a := &argReader{args: args, ok: true}
	data, window, claim, flags := arg[[]byte](a), arg[uint16](a), arg[uint8](a), arg[uint8](a)
	o := fuzzAtOptions(window, claim, flags)
	return []diffCase{{data: data, stock: true, flags: []string{"-P", "bytes=" + strconv.Itoa(o.MaxBytes)}}}, a.done()
}

// diffCompile identifies the rule text with itself, as FuzzCompile does.
func diffCompile(args []any) ([]diffCase, bool) {
	a := &argReader{args: args, ok: true}
	rules := arg[string](a)
	return []diffCase{{rules: rules, data: []byte(rules)}}, a.done()
}

func diffSafeText(args []any) ([]diffCase, bool) {
	a := &argReader{args: args, ok: true}
	data := arg[[]byte](a)
	return []diffCase{{rules: safeTextRules, data: data}}, a.done()
}

func elfSeedArgs() [][]any {
	var seeds [][]any
	for _, e := range elfSeeds() {
		seeds = append(seeds, elfArgs(&e))
	}
	return seeds
}

func diffELF(args []any) ([]diffCase, bool) {
	e, ok := elfFromArgs(args)
	return []diffCase{{data: elfImage(&e), size: int64(e.fileSize), stock: true}}, ok
}

func cdfSeedArgs() [][]any {
	var seeds [][]any
	for _, c := range cdfSeeds() {
		seeds = append(seeds, cdfArgs(&c))
	}
	return seeds
}

func diffCDF(args []any) ([]diffCase, bool) {
	c, ok := cdfFromArgs(args)
	return []diffCase{{data: cdfImage(&c), size: int64(c.fileSize), stock: true}}, ok
}

func diffDER(args []any) ([]diffCase, bool) {
	a := &argReader{args: args, ok: true}
	tag, form, digits, nesting := arg[uint8](a), arg[uint8](a), arg[uint8](a), arg[uint8](a)
	lie, payload := arg[uint64](a), arg[[]byte](a)
	return []diffCase{{data: derFile(tag, form, digits, nesting, lie, payload), stock: true}}, a.done()
}

func diffPString(args []any) ([]diffCase, bool) {
	a := &argReader{args: args, ok: true}
	width, j, value, jpeg, payload := arg[uint8](a), arg[bool](a), arg[uint32](a), arg[bool](a), arg[[]byte](a)
	if !a.done() {
		return nil, false
	}
	rules, data := pstringCase(width, j, value, jpeg, payload)
	if rules < 0 {
		return []diffCase{{data: data, stock: true}}, true
	}
	return []diffCase{{rules: pstringRuleText()[rules], data: data}}, true
}

// diffRule gives the rules as FuzzRule writes them, and the two
// variants it compares them with when it does: in an indirect frame,
// and with 2^64-1 as a numeral past 64 bits, which file reads itself.
func diffRule(args []any) ([]diffCase, bool) {
	if len(args) != 9 {
		return nil, false
	}
	r, ok := ruleFromArgs(args[:8])
	input, isBytes := args[8].([]byte)
	if !ok || !isBytes {
		return nil, false
	}
	text := r.ruleText(spellPlain)
	cases := []diffCase{{rules: text, data: input}}
	if r.framed() && !bytes.HasPrefix(input, []byte("IND:")) {
		cases = append(cases, diffCase{suffix: "-frame", rules: ruleMarker + text, data: append([]byte("IND:"), input...)})
	}
	if over := r.ruleText(spellOver); over != text {
		cases = append(cases, diffCase{suffix: "-over", rules: over, data: input})
	}
	return cases, true
}

// TestExportCorpus writes every case of every target in diffTargets
// under $SOFTMAGIC_DIFF_OUT, an empty directory: from the
// seeds, testdata/fuzz, and each directory in the colon-separated
// $SOFTMAGIC_DIFF_CORPUS laid out as testdata/fuzz is (the fuzz cache's
// corpus, at $(go env GOCACHE)/fuzz/code.eitanity.com/softmagic). A
// case is the directory <target>/<entry><suffix>, holding input, the
// rules as magic/rules unless the case uses the stock database, and the
// flags one per line in flags. Without $SOFTMAGIC_DIFF_OUT it skips.
func TestExportCorpus(t *testing.T) {
	outDir := os.Getenv("SOFTMAGIC_DIFF_OUT")
	if outDir == "" {
		t.Skip("SOFTMAGIC_DIFF_OUT is not set")
	}
	out := openRoot(t, outDir)
	if entries, err := fs.ReadDir(out.FS(), "."); err != nil || len(entries) > 0 {
		t.Fatalf("%s is not empty (%v)", outDir, err)
	}
	roots := []*os.Root{openRoot(t, filepath.Join("testdata", "fuzz"))}
	for _, dir := range filepath.SplitList(os.Getenv("SOFTMAGIC_DIFF_CORPUS")) {
		if dir != "" {
			roots = append(roots, openRoot(t, dir))
		}
	}
	targets := diffTargets()
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		e := diffExport{out: out, target: targets[name], name: name}
		for i, args := range e.target.seeds() {
			e.export(t, "seed-"+strconv.Itoa(i), args)
		}
		for _, root := range roots {
			e.exportDir(t, root)
		}
		t.Logf("%s: %d cases, %d entries not of this target's arguments", name, e.written, e.skipped)
	}
}

// openRoot opens dir, closed when the test ends.
func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

// diffExport writes one target's cases into out and counts them.
type diffExport struct {
	out              *os.Root
	target           diffTarget
	name             string
	written, skipped int
}

// exportDir exports each entry in root's directory for the target, if
// it has one.
func (e *diffExport) exportDir(t *testing.T, root *os.Root) {
	t.Helper()
	files, err := fs.ReadDir(root.FS(), e.name)
	if err != nil {
		return
	}
	for _, f := range files {
		b, err := root.ReadFile(e.name + "/" + f.Name())
		if err != nil {
			t.Fatal(err)
		}
		args, err := decodeFuzzEntry(b)
		if err != nil {
			e.skipped++
			continue
		}
		e.export(t, f.Name(), args)
	}
}

// export writes the cases one entry gives, unless an entry of the same
// name, the same content in another directory, already wrote them.
func (e *diffExport) export(t *testing.T, entry string, args []any) {
	t.Helper()
	cases, ok := e.target.cases(args)
	if !ok {
		e.skipped++
		return
	}
	for _, c := range cases {
		dir := e.name + "/" + entry + c.suffix
		if _, err := e.out.Stat(dir); err == nil {
			continue
		}
		if err := writeDiffCase(e.out, dir, c); err != nil {
			t.Fatal(err)
		}
		e.written++
	}
}

// writeDiffCase writes c into dir under out.
func writeDiffCase(out *os.Root, dir string, c diffCase) error {
	if err := out.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if !c.stock {
		if err := out.Mkdir(dir+"/magic", 0o750); err != nil {
			return err
		}
		if err := out.WriteFile(dir+"/magic/rules", []byte(c.rules), 0o600); err != nil {
			return err
		}
	}
	if len(c.flags) > 0 {
		if err := out.WriteFile(dir+"/flags", []byte(strings.Join(c.flags, "\n")+"\n"), 0o600); err != nil {
			return err
		}
	}
	return writeSparse(out, dir+"/input", c.data, max(c.size, int64(len(c.data))))
}

// writeSparse writes data and extends the file to size bytes with a
// hole, skipping the blocks of data that are all zeros, so a header
// that claims gigabytes takes no space.
func writeSparse(out *os.Root, path string, data []byte, size int64) error {
	f, err := out.Create(path)
	if err != nil {
		return err
	}
	const block = 4096
	for off := 0; off < len(data) && err == nil; off += block {
		b := data[off:min(off+block, len(data))]
		if len(bytes.Trim(b, "\x00")) > 0 {
			_, err = f.WriteAt(b, int64(off))
		}
	}
	if err == nil {
		err = f.Truncate(size)
	}
	return errors.Join(err, f.Close())
}

// decodeFuzzEntry reads a corpus file in the go command's format: a
// version line, then one T(literal) per argument. It reads the types
// the fuzz targets take.
func decodeFuzzEntry(b []byte) ([]any, error) {
	lines := strings.Split(string(b), "\n")
	if lines[0] != "go test fuzz v1" {
		return nil, errors.New("not a go test fuzz v1 file")
	}
	var args []any
	for _, line := range lines[1:] {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		v, err := decodeFuzzValue(line)
		if err != nil {
			return nil, err
		}
		args = append(args, v)
	}
	return args, nil
}

// decodeFuzzValue is one argument line as a value.
func decodeFuzzValue(line string) (any, error) {
	e, err := parser.ParseExpr(line)
	if err != nil {
		return nil, err
	}
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil, errors.New("not a conversion: " + line)
	}
	typ := ""
	switch f := call.Fun.(type) {
	case *ast.Ident:
		typ = f.Name
	case *ast.ArrayType:
		if elt, isIdent := f.Elt.(*ast.Ident); isIdent && f.Len == nil && (elt.Name == "byte" || elt.Name == "uint8") {
			typ = "[]byte"
		}
	}
	if id, isIdent := call.Args[0].(*ast.Ident); isIdent && typ == "bool" {
		switch id.Name {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		return nil, errors.New("not a bool: " + line)
	}
	text, kind, err := fuzzLiteral(call.Args[0])
	if err != nil {
		return nil, err
	}
	switch {
	case typ == "[]byte" && kind == token.STRING:
		s, uerr := strconv.Unquote(text)
		return []byte(s), uerr
	case typ == "string" && kind == token.STRING:
		return strconv.Unquote(text)
	case (typ == "byte" || typ == "uint8") && kind == token.CHAR:
		r, _, tail, uerr := strconv.UnquoteChar(text[1:len(text)-1], '\'')
		if uerr != nil || tail != "" || r > 0xff {
			return nil, errors.New("not a byte: " + line)
		}
		return smallUint8(int(r)), nil
	case kind != token.INT:
		return nil, errors.New("unsupported argument: " + line)
	}
	sizes := map[string]int{"uint8": 8, "byte": 8, "uint16": 16, "uint32": 32, "uint64": 64, "int64": 64}
	bits, ok := sizes[typ]
	if !ok {
		return nil, errors.New("unsupported type: " + line)
	}
	if typ == "int64" {
		return strconv.ParseInt(text, 0, 64)
	}
	u, err := strconv.ParseUint(text, 0, bits)
	switch bits {
	case 8:
		return low8(u), err
	case 16:
		return low16(u), err
	case 32:
		return low32(u), err
	}
	return u, err
}

// fuzzLiteral is a literal argument's text, with a leading minus sign
// when it has one, and its kind.
func fuzzLiteral(e ast.Expr) (string, token.Token, error) {
	sign := ""
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.SUB {
		sign, e = "-", u.X
	}
	lit, ok := e.(*ast.BasicLit)
	if !ok {
		return "", token.ILLEGAL, errors.New("not a literal")
	}
	return sign + lit.Value, lit.Kind, nil
}

// TestFuzzEntriesDecode: every committed corpus entry of a target in
// diffTargets decodes to that target's arguments, and every seed is
// taken as them, so the export cannot fall out of step with a target's
// signature unnoticed.
func TestFuzzEntriesDecode(t *testing.T) {
	for name, target := range diffTargets() {
		for i, args := range target.seeds() {
			if _, ok := target.cases(args); !ok {
				t.Errorf("%s seed %d is not the target's arguments", name, i)
			}
		}
		files, err := filepath.Glob(filepath.Join("testdata", "fuzz", name, "*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			b, err := os.ReadFile(filepath.Clean(f)) // a path under testdata
			if err != nil {
				t.Fatal(err)
			}
			args, err := decodeFuzzEntry(b)
			if err != nil {
				t.Errorf("%s: %v", f, err)
				continue
			}
			if _, ok := target.cases(args); !ok {
				t.Errorf("%s is not %s's arguments", f, name)
			}
		}
	}
}

// TestDecodeFuzzEntry decodes each form the go command writes for the
// types the targets take.
func TestDecodeFuzzEntry(t *testing.T) {
	in := "go test fuzz v1\n[]byte(\"\\x00a\")\nstring(\"s\\n\")\nbool(true)\nbyte('\\x05')\nbyte('é')\n" +
		"uint8(7)\nuint16(65535)\nuint32(4294967295)\nuint64(18446744073709551615)\nint64(-9223372036854775808)\n"
	got, err := decodeFuzzEntry([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []any{[]byte("\x00a"), "s\n", true, byte(5), byte(0xe9), uint8(7), uint16(65535), uint32(1<<32 - 1),
		uint64(1<<64 - 1), int64(-1 << 63)}
	if len(got) != len(want) {
		t.Fatalf("%d values, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if g, w := fmt.Sprintf("%#v", got[i]), fmt.Sprintf("%#v", want[i]); g != w {
			t.Errorf("value %d: %s, want %s", i, g, w)
		}
	}
	for _, bad := range []string{"int(1)", "uint8(256)", "float64(1)", "bool(1)", "[]int(\"x\")", "x"} {
		if _, err := decodeFuzzEntry([]byte("go test fuzz v1\n" + bad + "\n")); err == nil {
			t.Errorf("%s decoded", bad)
		}
	}
}
