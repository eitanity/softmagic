// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package rules

import (
	"go/ast"
	"go/build"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const modulePath = "code.eitanity.com/softmagic"

// pkg is one parsed and type-checked package of the module.
type pkg struct {
	tpkg  *types.Package
	info  *types.Info
	path  string // import path
	dir   string
	files []*ast.File
	names []string // file names parallel to files
}

// loadModule parses and type-checks every non-test package of the module
// under the softmagic_assert build tag, in dependency order.
func loadModule(t *testing.T) (*token.FileSet, []*pkg) {
	t.Helper()
	root := moduleRoot(t)
	fset := token.NewFileSet()
	ctx := build.Default
	ctx.BuildTags = []string{"softmagic_assert"}
	var pkgs []*pkg
	dirs := packageDirs(t, root)
	for _, dir := range dirs {
		p := parseDir(t, fset, &ctx, root, dir)
		if p != nil {
			pkgs = append(pkgs, p)
		}
	}
	// Type-check with module-local imports resolved to already-checked
	// packages; dependencies come first because internal/ sorts before the
	// root's files are reached only through the root package, listed last.
	sort.SliceStable(pkgs, func(i, j int) bool { return len(pkgs[i].path) > len(pkgs[j].path) })
	done := map[string]*types.Package{}
	imp := &moduleImporter{done: done, src: importer.ForCompiler(fset, "source", nil)}
	for _, p := range pkgs { // pkg
		conf := types.Config{Importer: imp}
		p.info = &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}
		tp, err := conf.Check(p.path, fset, p.files, p.info)
		if err != nil {
			t.Fatalf("type-check %s: %v", p.path, err)
		}
		p.tpkg = tp
		done[p.path] = tp
	}
	return fset, pkgs
}

type moduleImporter struct {
	done map[string]*types.Package
	src  types.Importer
}

func (m *moduleImporter) Import(path string) (*types.Package, error) {
	if p, ok := m.done[path]; ok {
		return p, nil
	}
	return m.src.Import(path)
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			t.Fatal("go.mod not found above " + dir)
		}
	}
}

// packageDirs lists every directory under root holding .go files, except
// the vendored database and testdata.
func packageDirs(t *testing.T, root string) []string {
	t.Helper()
	seen := map[string]bool{}
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error { // dirEntry
		if walkErr != nil {
			return walkErr
		}
		name := d.Name()
		if d.IsDir() && path != root && (name[0] == '.' || name == "testdata" || name == "magic") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(name, ".go") && !seen[filepath.Dir(path)] {
			seen[filepath.Dir(path)] = true
			dirs = append(dirs, filepath.Dir(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

// parseDir parses the non-test files of one directory that match the build
// context; nil when the directory has none.
func parseDir(t *testing.T, fset *token.FileSet, ctx *build.Context, root, dir string) *pkg {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		t.Fatal(err)
	}
	p := &pkg{path: modulePath, dir: dir} // pkg
	if rel != "." {
		p.path = modulePath + "/" + filepath.ToSlash(rel)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		ok, err := ctx.MatchFile(dir, name)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		p.files = append(p.files, f)
		p.names = append(p.names, name)
	}
	if len(p.files) == 0 {
		return nil
	}
	return p
}

// funcKey names a function or method for the call graph.
func funcKey(obj *types.Func) string { return obj.FullName() }

// callGraph maps each module function to the module functions it calls.
func callGraph(pkgs []*pkg) map[string][]string {
	graph := map[string][]string{}
	for _, p := range pkgs { // pkg
		for _, f := range p.files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl) // funcDecl
				if !ok || fd.Body == nil {
					continue
				}
				obj, isFunc := p.info.Defs[fd.Name].(*types.Func)
				if !isFunc {
					continue
				}
				graph[funcKey(obj)] = calleesOf(p, fd.Body)
			}
		}
	}
	return graph
}

// calleesOf lists the module functions called in body.
func calleesOf(p *pkg, body *ast.BlockStmt) []string { // pkg
	var out []string
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr) // isCall
		if !ok {
			return true
		}
		var id *ast.Ident // calleeIdent
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			id = fn
		case *ast.SelectorExpr:
			id = fn.Sel
		default:
			return true
		}
		obj, ok := p.info.Uses[id].(*types.Func)
		if ok && obj.Pkg() != nil && strings.HasPrefix(obj.Pkg().Path(), modulePath) {
			out = append(out, funcKey(obj))
		}
		return true
	})
	return out
}

// TestRule1NoRecursion fails on any cycle in the module's call graph, found
// by Kahn's algorithm: whatever cannot be topologically removed is cyclic.
func TestRule1NoRecursion(t *testing.T) {
	_, pkgs := loadModule(t)
	graph := callGraph(pkgs)
	indeg := map[string]int{}
	for caller, callees := range graph {
		if _, ok := indeg[caller]; !ok {
			indeg[caller] = 0
		}
		for _, c := range callees {
			indeg[c]++
		}
	}
	var queue []string
	for fn, d := range indeg {
		if d == 0 {
			queue = append(queue, fn)
		}
	}
	for len(queue) > 0 {
		fn := queue[0] // fnName
		queue = queue[1:]
		for _, c := range graph[fn] {
			indeg[c]--
			if indeg[c] == 0 {
				queue = append(queue, c)
			}
		}
		delete(indeg, fn)
	}
	var cyclic []string
	for fn, d := range indeg {
		if d > 0 && reaches(graph, fn, fn) {
			cyclic = append(cyclic, fn)
		}
	}
	sort.Strings(cyclic)
	for _, fn := range cyclic {
		t.Errorf("rule 1: %s takes part in a recursive call cycle", fn)
	}
}

// reaches reports whether `to` is reachable from `from` in one or more
// steps, by iterative breadth-first search.
func reaches(graph map[string][]string, from, to string) bool { // target
	seen := map[string]bool{}
	queue := append([]string(nil), graph[from]...)
	for len(queue) > 0 {
		fn := queue[0] // fnName
		queue = queue[1:]
		if fn == to {
			return true
		}
		if seen[fn] {
			continue
		}
		seen[fn] = true
		queue = append(queue, graph[fn]...)
	}
	return false
}

// TestRule1NoGotoDeferRecover forbids goto, defer and recover in non-test
// code, and panic outside the assertion helper.
func TestRule1NoGotoDeferRecover(t *testing.T) {
	fset, pkgs := loadModule(t)
	for _, p := range pkgs { // pkg
		for i, f := range p.files { // fileIdx
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) { // node
				case *ast.BranchStmt:
					if x.Tok == token.GOTO {
						t.Errorf("rule 1: goto at %s", fset.Position(x.Pos()))
					}
				case *ast.DeferStmt:
					t.Errorf("rule 1: defer at %s", fset.Position(x.Pos()))
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok && (id.Name == "recover" || (id.Name == "panic" && p.names[i] != "assert.go")) {
						t.Errorf("rule 1/5: %s at %s", id.Name, fset.Position(x.Pos()))
					}
				}
				return true
			})
		}
	}
}

// TestRule2LoopForms accepts a loop only when a tool can see its bound:
// `for range` over a slice, array, string or map, or over an integer that
// is a fixed bound; or a three-clause loop whose post statement steps the
// counter by ++, --, += or -=, with a conjunct of its condition comparing
// the counter against a fixed bound (from below for a counter that
// rises, from above for one that falls from a fixed start). A fixed bound
// is a constant, a len or cap, or a local assigned once from those (also
// through +, -, *, /, >>, min and conversions). Every slice the module
// loops over is capped by a limit before the loop, so its length is.
func TestRule2LoopForms(t *testing.T) {
	fset, pkgs := loadModule(t)
	for _, p := range pkgs {
		for _, f := range p.files {
			b := newBounds(p.info, f)
			ast.Inspect(f, func(n ast.Node) bool {
				switch s := n.(type) { // loopStmt
				case *ast.ForStmt:
					if why := b.loopForm(s); why != "" {
						t.Errorf("rule 2: %s at %s", why, fset.Position(s.Pos()))
					}
				case *ast.RangeStmt:
					if b.isInteger(s.X) && !b.fixed(s.X, 0) {
						t.Errorf("rule 2: range over %s, which is not a fixed bound, at %s", types.ExprString(s.X), fset.Position(s.Pos()))
					}
				}
				return true
			})
		}
	}
}

// bounds knows which locals of one file are assigned once, and from what.
type bounds struct {
	info   *types.Info
	defs   map[types.Object]ast.Expr // the defining expression, nil when there is none
	writes map[types.Object]int      // assignments after the definition, and address-taking
}

// maxBoundDepth limits how far fixed follows definitions and operands.
const maxBoundDepth = 8

func newBounds(info *types.Info, f *ast.File) *bounds { // file
	b := &bounds{info: info, defs: map[types.Object]ast.Expr{}, writes: map[types.Object]int{}}
	ast.Inspect(f, func(n ast.Node) bool {
		switch s := n.(type) { // stmt
		case *ast.AssignStmt:
			b.noteAssign(s)
		case *ast.ValueSpec:
			for i, id := range s.Names {
				if obj := info.Defs[id]; obj != nil {
					b.defs[obj] = nil
					if i < len(s.Values) {
						b.defs[obj] = s.Values[i]
					}
				}
			}
		case *ast.IncDecStmt:
			b.noteWrite(s.X)
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				b.noteWrite(s.X)
			}
		}
		return true
	})
	return b
}

func (b *bounds) noteAssign(s *ast.AssignStmt) {
	for i, l := range s.Lhs {
		id, ok := l.(*ast.Ident) // lhs
		if ok && s.Tok == token.DEFINE {
			if obj := b.info.Defs[id]; obj != nil {
				b.defs[obj] = nil
				if len(s.Rhs) == len(s.Lhs) {
					b.defs[obj] = s.Rhs[i]
				}
				continue
			}
		}
		b.noteWrite(l)
	}
}

func (b *bounds) noteWrite(e ast.Expr) {
	if id, ok := e.(*ast.Ident); ok {
		if obj := b.info.Uses[id]; obj != nil {
			b.writes[obj]++
		}
	}
}

func (b *bounds) isInteger(e ast.Expr) bool {
	tv := b.info.Types[e] // typeAndValue
	if tv.Type == nil {
		return false
	}
	basic, ok := tv.Type.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsInteger != 0
}

// fixed reports whether e is a fixed bound.
func (b *bounds) fixed(e ast.Expr, depth int) bool { // expr
	if depth > maxBoundDepth {
		return false
	}
	if tv, ok := b.info.Types[e]; ok && tv.Value != nil {
		return true
	}
	switch x := e.(type) {
	case *ast.ParenExpr:
		return b.fixed(x.X, depth+1)
	case *ast.CallExpr:
		return b.fixedCall(x, depth)
	case *ast.BinaryExpr:
		switch x.Op {
		case token.ADD, token.SUB, token.MUL, token.QUO, token.SHR:
			return b.fixed(x.X, depth+1) && b.fixed(x.Y, depth+1)
		default:
			return false
		}
	case *ast.Ident:
		obj := b.info.Uses[x]
		d, defined := b.defs[obj]
		return obj != nil && defined && d != nil && b.writes[obj] == 0 && b.fixed(d, depth+1)
	}
	return false
}

// fixedCall accepts len, cap, a min with a fixed argument, and a
// conversion of a fixed bound.
func (b *bounds) fixedCall(x *ast.CallExpr, depth int) bool { // call
	if id, ok := x.Fun.(*ast.Ident); ok && b.info.Uses[id] != nil && b.info.Uses[id].Parent() == types.Universe {
		switch id.Name {
		case "len", "cap":
			return true
		case "min":
			for _, a := range x.Args {
				if b.fixed(a, depth+1) {
					return true
				}
			}
			return false
		}
	}
	tv := b.info.Types[x.Fun] // conversionType
	return tv.IsType() && len(x.Args) == 1 && b.fixed(x.Args[0], depth+1)
}

// loopForm returns "" when fs is an accepted three-clause loop.
func (b *bounds) loopForm(fs *ast.ForStmt) string { // forStmt
	if fs.Cond == nil || fs.Post == nil {
		return "loop without a condition and a post statement"
	}
	counter, rising, why := stepOf(fs.Post)
	if why != "" {
		return why
	}
	if !rising && !b.fixedStart(fs.Init, counter) {
		return "falling counter " + counter + " has no fixed start in the loop's init"
	}
	for _, c := range conjuncts(fs.Cond) {
		cmp, ok := c.(*ast.BinaryExpr) // comparison
		if !ok {
			continue
		}
		if rising && (cmp.Op == token.LSS || cmp.Op == token.LEQ) && types.ExprString(cmp.X) == counter && b.fixed(cmp.Y, 0) {
			return ""
		}
		if !rising && (cmp.Op == token.GTR || cmp.Op == token.GEQ) && types.ExprString(cmp.X) == counter {
			return ""
		}
	}
	return "no conjunct of " + types.ExprString(fs.Cond) + " bounds " + counter + " by a fixed bound"
}

// stepOf names the counter a post statement steps and its direction.
func stepOf(post ast.Stmt) (counter string, rising bool, why string) { // stmt
	switch s := post.(type) {
	case *ast.IncDecStmt:
		return types.ExprString(s.X), s.Tok == token.INC, ""
	case *ast.AssignStmt:
		if len(s.Lhs) == 1 && (s.Tok == token.ADD_ASSIGN || s.Tok == token.SUB_ASSIGN) {
			return types.ExprString(s.Lhs[0]), s.Tok == token.ADD_ASSIGN, ""
		}
	}
	return "", false, "loop post statement is not ++, --, += or -= on a counter"
}

// fixedStart reports whether init sets counter from a fixed bound.
func (b *bounds) fixedStart(init ast.Stmt, counter string) bool { // initStmt
	s, ok := init.(*ast.AssignStmt) // assign
	if !ok || len(s.Lhs) != 1 || len(s.Rhs) != 1 || types.ExprString(s.Lhs[0]) != counter {
		return false
	}
	return b.fixed(s.Rhs[0], 0)
}

func conjuncts(e ast.Expr) []ast.Expr {
	var out []ast.Expr
	stack := []ast.Expr{e}
	for steps := 0; steps < 64 && len(stack) > 0; steps++ {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if x, ok := top.(*ast.BinaryExpr); ok && x.Op == token.LAND {
			stack = append(stack, x.Y, x.X)
			continue
		}
		out = append(out, top)
	}
	return out
}

// TestRule5AssertionDensity requires an average of two checks per function
// over functions of three or more statements: invariant.Check calls plus
// guard clauses (a top-level if whose body ends in a return).
func TestRule5AssertionDensity(t *testing.T) {
	_, pkgs := loadModule(t)
	funcs, checks := 0, 0
	var thin []string
	for _, p := range pkgs {
		if strings.HasSuffix(p.path, "/internal/invariant") {
			continue
		}
		for _, f := range p.files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl) // funcDecl
				if !ok || fd.Body == nil || len(fd.Body.List) < 3 {
					continue
				}
				n := checksIn(fd.Body)
				funcs++
				checks += n
				if n == 0 {
					thin = append(thin, fd.Name.Name)
				}
			}
		}
	}
	density := float64(checks) / float64(funcs)
	t.Logf("rule 5: %d checks over %d functions, density %.2f; %d functions with none: %s",
		checks, funcs, density, len(thin), strings.Join(thin, " "))
	if density < 2.0 {
		t.Errorf("rule 5: assertion density %.2f is below 2.0", density)
	}
}

// checksIn counts invariant.Check calls anywhere in body and guard clauses
// at its top level.
func checksIn(body *ast.BlockStmt) int {
	n := 0 // checkCount
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Check" {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "invariant" {
				n++
			}
		}
		return true
	})
	for _, s := range body.List {
		if ifs, ok := s.(*ast.IfStmt); ok && endsInReturn(ifs.Body) {
			n++
		}
	}
	return n
}

func endsInReturn(b *ast.BlockStmt) bool {
	if len(b.List) == 0 {
		return false
	}
	_, ok := b.List[len(b.List)-1].(*ast.ReturnStmt)
	return ok
}

// TestRule5ChecksActedOn rejects an invariant.Check whose result is
// discarded. In a release build Check only returns its condition, so a
// check written as a statement bounds nothing: the caller must return,
// refuse or truncate when it is false.
func TestRule5ChecksActedOn(t *testing.T) {
	fset, pkgs := loadModule(t)
	for _, p := range pkgs {
		if strings.HasSuffix(p.path, "/internal/invariant") {
			continue
		}
		for _, f := range p.files {
			ast.Inspect(f, func(n ast.Node) bool {
				es, ok := n.(*ast.ExprStmt) // exprStmt
				if !ok {
					return true
				}
				call, isCall := es.X.(*ast.CallExpr)
				if !isCall {
					return true
				}
				if sel, isSel := call.Fun.(*ast.SelectorExpr); isSel && sel.Sel.Name == "Check" {
					if id, isID := sel.X.(*ast.Ident); isID && id.Name == "invariant" {
						t.Errorf("rule 5: invariant.Check result discarded at %s", fset.Position(es.Pos()))
					}
				}
				return true
			})
		}
	}
}

// TestRule6NoMutableGlobals forbids init functions and any assignment to a
// package-level variable outside its declaration.
func TestRule6NoMutableGlobals(t *testing.T) {
	fset, pkgs := loadModule(t)
	for _, p := range pkgs { // pkg
		globals := map[types.Object]bool{}
		for _, f := range p.files {
			for _, d := range f.Decls {
				switch x := d.(type) { // decl
				case *ast.FuncDecl:
					if x.Name.Name == "init" && x.Recv == nil {
						t.Errorf("rule 6: init at %s", fset.Position(x.Pos()))
					}
				case *ast.GenDecl:
					if x.Tok == token.VAR {
						for _, sp := range x.Specs {
							vs, isValue := sp.(*ast.ValueSpec)
							if !isValue {
								continue
							}
							for _, name := range vs.Names {
								globals[p.info.Defs[name]] = true
							}
						}
					}
				}
			}
		}
		for _, f := range p.files {
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) { // node
				case *ast.AssignStmt:
					for _, l := range x.Lhs {
						if refersToGlobal(p, l, globals) {
							t.Errorf("rule 6: assignment to package-level variable at %s", fset.Position(x.Pos()))
						}
					}
				case *ast.IncDecStmt:
					if refersToGlobal(p, x.X, globals) {
						t.Errorf("rule 6: increment of package-level variable at %s", fset.Position(x.Pos()))
					}
				case *ast.UnaryExpr:
					if x.Op == token.AND && refersToGlobal(p, x.X, globals) {
						t.Errorf("rule 6: address of package-level variable at %s", fset.Position(x.Pos()))
					}
				}
				return true
			})
		}
	}
}

// refersToGlobal reports whether e's root identifier is a package-level var.
func refersToGlobal(p *pkg, e ast.Expr, globals map[types.Object]bool) bool { // expr
	for {
		switch x := e.(type) { // node
		case *ast.Ident:
			return globals[p.info.Uses[x]]
		case *ast.IndexExpr:
			e = x.X
		case *ast.SelectorExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		default:
			return false
		}
	}
}

// TestRule7IntConversionsChecked rejects a conversion to int of a value
// whose type is wider than a 32-bit int (uint32, uint64, int64, uint,
// uintptr) outside bits.go. On a 32-bit host such a conversion turns a
// value of 2^31 or more from a file or a compiled database into a
// negative int, which then passes every upper-bound check; intFromU32 and
// intFromI64 clamp instead. A masked or remaindered value whose constant
// fits an int32 is allowed, as its range is visible at the conversion.
func TestRule7IntConversionsChecked(t *testing.T) {
	fset, pkgs := loadModule(t)
	for _, p := range pkgs {
		for i, f := range p.files { // file
			if p.path == modulePath && p.names[i] == "bits.go" {
				continue
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr) // callExpr
				if !ok || len(call.Args) != 1 || !narrowsToInt(p.info, call) {
					return true
				}
				t.Errorf("rule 7: unchecked conversion to int at %s; use intFromU32 or intFromI64", fset.Position(call.Pos()))
				return true
			})
		}
	}
}

// narrowsToInt reports whether call is int(x) for a non-constant x whose
// type may not fit a 32-bit int, other than x & C or x % C with a small C.
func narrowsToInt(info *types.Info, call *ast.CallExpr) bool { // callExpr
	fn, ok := info.Types[call.Fun] // conversionType
	if !ok || !fn.IsType() || !types.Identical(fn.Type, types.Typ[types.Int]) {
		return false
	}
	arg := info.Types[call.Args[0]] // argument
	if arg.Type == nil || arg.Value != nil {
		return false
	}
	b, isBasic := arg.Type.Underlying().(*types.Basic)
	if !isBasic {
		return false
	}
	switch b.Kind() {
	case types.Uint32, types.Uint64, types.Int64, types.Uint, types.Uintptr:
	default:
		return false
	}
	return !smallByOperator(info, call.Args[0])
}

// smallByOperator reports whether e is x & C or x % C for a constant C in
// [0, MaxInt32], whose result therefore fits any int.
func smallByOperator(info *types.Info, e ast.Expr) bool { // expr
	for paren, ok := e.(*ast.ParenExpr); ok; paren, ok = e.(*ast.ParenExpr) {
		e = paren.X
	}
	bin, ok := e.(*ast.BinaryExpr) // binaryExpr
	if !ok || (bin.Op != token.AND && bin.Op != token.REM) {
		return false
	}
	c := info.Types[bin.Y].Value // operand
	if c == nil {
		return false
	}
	v, exact := constant.Int64Val(constant.ToInt(c))
	return exact && v >= 0 && v <= math.MaxInt32
}

// TestRule7InputArithmetic keeps integers read from the input inside
// their defined types: outside input.go and bits.go, no code reads an
// integer with encoding/binary, applies + - * << ++ or -- to an input
// type, or converts one to any type but a wider input type. Combining
// and converting them is left to input.go's helpers, which report
// overflow or wrap where file 5.48 wraps.
func TestRule7InputArithmetic(t *testing.T) {
	fset, pkgs := loadModule(t)
	for _, p := range pkgs {
		if p.path != modulePath {
			continue
		}
		for i, f := range p.files { // file
			if n := p.names[i]; n == "bits.go" || n == "input.go" || strings.HasSuffix(n, "_test.go") {
				continue
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if msg := inputMisuse(p.info, n); msg != "" {
					t.Errorf("rule 7: %s at %s", msg, fset.Position(n.Pos()))
				}
				return true
			})
		}
	}
}

// inputMisuse is what TestRule7InputArithmetic rejects in n, or "".
func inputMisuse(info *types.Info, n ast.Node) string { // node
	switch e := n.(type) {
	case *ast.BinaryExpr:
		if growsOrWraps(e.Op) && (inputWidth(info, e.X) > 0 || inputWidth(info, e.Y) > 0) {
			return e.Op.String() + " on an input integer"
		}
	case *ast.AssignStmt:
		if growsOrWraps(e.Tok) && inputWidth(info, e.Lhs[0]) > 0 {
			return e.Tok.String() + " on an input integer"
		}
	case *ast.IncDecStmt:
		if inputWidth(info, e.X) > 0 {
			return e.Tok.String() + " on an input integer"
		}
	case *ast.CallExpr:
		return inputCallMisuse(info, e)
	default:
	}
	return ""
}

// inputCallMisuse rejects a binary.ByteOrder integer read and a
// conversion out of an input type.
func inputCallMisuse(info *types.Info, call *ast.CallExpr) string { // callExpr
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok { // selector
		if fn, isFunc := info.Uses[sel.Sel].(*types.Func); isFunc && fn.Pkg() != nil && fn.Pkg().Path() == "encoding/binary" &&
			(fn.Name() == "Uint16" || fn.Name() == "Uint32" || fn.Name() == "Uint64") {
			return "integer read with encoding/binary; use input.go's readers"
		}
	}
	fn, ok := info.Types[call.Fun] // conversionType
	if !ok || !fn.IsType() || len(call.Args) != 1 {
		return ""
	}
	from := inputWidth(info, call.Args[0])
	if from == 0 {
		return ""
	}
	if to := typeInputWidth(fn.Type); to >= from {
		return ""
	}
	return "conversion out of an input integer type; use input.go's helpers"
}

// growsOrWraps reports whether op can take an unsigned value past its
// range in either direction.
func growsOrWraps(op token.Token) bool {
	switch op {
	case token.ADD, token.SUB, token.MUL, token.SHL,
		token.ADD_ASSIGN, token.SUB_ASSIGN, token.MUL_ASSIGN, token.SHL_ASSIGN:
		return true
	default:
		return false
	}
}

// inputWidth is the width of e's input type, 0 when it has none or is
// a constant.
func inputWidth(info *types.Info, e ast.Expr) int { // expr
	tv := info.Types[e] // typeAndValue
	if tv.Type == nil || tv.Value != nil {
		return 0
	}
	return typeInputWidth(tv.Type)
}

// typeInputWidth is t's width when t is one of the defined types of
// integers read from the input file, which input.go declares with the
// helpers that read, combine and convert them; else 0.
func typeInputWidth(t types.Type) int { // typ
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != modulePath {
		return 0
	}
	switch named.Obj().Name() {
	case "in16":
		return 16
	case "in32":
		return 32
	case "in64":
		return 64
	default:
		return 0
	}
}

// TestRule8BuildTagsAndImports allows one build tag and forbids the
// packages that stand in for a preprocessor.
func TestRule8BuildTagsAndImports(t *testing.T) {
	fset, pkgs := loadModule(t)
	for _, p := range pkgs {
		for _, f := range p.files { // file
			for _, cg := range f.Comments {
				for _, c := range cg.List { // comment
					if strings.HasPrefix(c.Text, "//go:build") {
						tag := strings.TrimSpace(strings.TrimPrefix(c.Text, "//go:build"))
						if tag != "softmagic_assert" && tag != "!softmagic_assert" {
							t.Errorf("rule 8: build constraint %q at %s", tag, fset.Position(c.Pos()))
						}
					}
					if strings.HasPrefix(c.Text, "//go:linkname") {
						t.Errorf("rule 8: go:linkname at %s", fset.Position(c.Pos()))
					}
				}
			}
			for _, im := range f.Imports {
				switch strings.Trim(im.Path.Value, `"`) {
				case "unsafe", "reflect", "C", "os/exec", "net", "syscall":
					t.Errorf("rule 8: import %s at %s", im.Path.Value, fset.Position(im.Pos()))
				}
			}
		}
	}
}

// TestRule9PointersAndFuncs forbids double indirection, pointers to
// slices, maps and interfaces, func types in declarations, and interface
// declarations. A func literal is allowed only as the New field of a
// sync.Pool literal or the argument of a Do call.
func TestRule9PointersAndFuncs(t *testing.T) {
	fset, pkgs := loadModule(t)
	for _, p := range pkgs { // pkg
		for _, f := range p.files {
			allowed := allowedFuncLits(f)
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) { // node
				case *ast.StarExpr:
					switch y := x.X.(type) {
					case *ast.StarExpr, *ast.MapType, *ast.InterfaceType, *ast.FuncType:
						t.Errorf("rule 9: pointer to pointer, map, interface or func at %s", fset.Position(x.Pos()))
					case *ast.ArrayType:
						if y.Len == nil { // a pointer to a fixed array is one level; to a slice is two
							t.Errorf("rule 9: pointer to slice at %s", fset.Position(x.Pos()))
						}
					}
				case *ast.FuncType:
					if !allowed[x] {
						t.Errorf("rule 9: func type in a declaration at %s", fset.Position(x.Pos()))
					}
					return false // a permitted literal's own signature may say `any`
				case *ast.InterfaceType:
					t.Errorf("rule 9: interface type at %s", fset.Position(x.Pos()))
				case *ast.Ident:
					if x.Name == "any" && p.info.Uses[x] != nil && p.info.Uses[x].Pkg() == nil {
						t.Errorf("rule 9: any at %s", fset.Position(x.Pos()))
					}
				}
				return true
			})
		}
	}
}

// allowedFuncLits collects the FuncType nodes that are a FuncDecl's own
// signature or a permitted func literal.
func allowedFuncLits(f *ast.File) map[*ast.FuncType]bool {
	ok := map[*ast.FuncType]bool{} // allowed
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) { // node
		case *ast.FuncDecl:
			ok[x.Type] = true
		case *ast.KeyValueExpr:
			if k, isId := x.Key.(*ast.Ident); isId && k.Name == "New" {
				if fl, isLit := x.Value.(*ast.FuncLit); isLit {
					ok[fl.Type] = true
				}
			}
		case *ast.CallExpr:
			if sel, isSel := x.Fun.(*ast.SelectorExpr); isSel && sel.Sel.Name == "Do" && len(x.Args) == 1 {
				if fl, isLit := x.Args[0].(*ast.FuncLit); isLit {
					ok[fl.Type] = true
				}
			}
		}
		return true
	})
	return ok
}

// TestRule10NoSuppressions greps every Go file, tests included, for linter
// suppression comments.
func TestRule10NoSuppressions(t *testing.T) {
	root := moduleRoot(t)
	scoped, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := scoped.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error { // dirEntry
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() && path != root && (d.Name()[0] == '.' || d.Name() == "magic") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		data, readErr := scoped.ReadFile(rel)
		if readErr != nil {
			return readErr
		}
		// The markers are assembled so this file does not contain them itself.
		for _, marker := range []string{"//" + "nolint", "// " + "nolint", "//" + "lint:ignore", "#" + "nosec"} {
			if strings.Contains(string(data), marker) {
				t.Errorf("rule 10: %s contains %q", path, marker)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
