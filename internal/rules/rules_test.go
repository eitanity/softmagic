// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.

package rules

import (
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/eitanity/softmagic"

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
		p.info = &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
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

// TestRule2LoopForms accepts only `for range` and three-clause loops whose
// condition's first conjunct compares the counter against a bound and whose
// post statement steps the counter.
func TestRule2LoopForms(t *testing.T) {
	fset, pkgs := loadModule(t)
	for _, p := range pkgs {
		for _, f := range p.files {
			ast.Inspect(f, func(n ast.Node) bool {
				fs, ok := n.(*ast.ForStmt)
				if !ok {
					return true
				}
				if why := loopForm(fs); why != "" {
					t.Errorf("rule 2: %s at %s", why, fset.Position(fs.Pos()))
				}
				return true
			})
		}
	}
}

// loopForm returns "" when fs is an accepted three-clause loop.
func loopForm(fs *ast.ForStmt) string { // forStmt
	if fs.Cond == nil {
		return "loop without condition"
	}
	if fs.Post == nil {
		return "loop without post statement"
	}
	cond := fs.Cond
	for {
		b, ok := cond.(*ast.BinaryExpr)
		if ok && b.Op == token.LAND {
			cond = b.X
			continue
		}
		break
	}
	cmp, ok := cond.(*ast.BinaryExpr)
	if !ok || (cmp.Op != token.LSS && cmp.Op != token.LEQ && cmp.Op != token.GTR && cmp.Op != token.GEQ) {
		return "loop condition's first conjunct is not a counter comparison"
	}
	counter := types.ExprString(cmp.X)
	switch cmp.X.(type) {
	case *ast.Ident, *ast.SelectorExpr:
	default:
		return "loop counter is not an identifier or field"
	}
	if !stepsCounter(fs.Post, counter) {
		return "loop post statement does not step the counter " + counter
	}
	if mentions(cmp.Y, counter) {
		return "loop bound mentions the counter"
	}
	return ""
}

func stepsCounter(post ast.Stmt, counter string) bool {
	switch s := post.(type) { // stmt
	case *ast.IncDecStmt:
		return types.ExprString(s.X) == counter
	case *ast.AssignStmt:
		if len(s.Lhs) != 1 || (s.Tok != token.ADD_ASSIGN && s.Tok != token.SUB_ASSIGN && s.Tok != token.ASSIGN) {
			return false
		}
		return types.ExprString(s.Lhs[0]) == counter
	default:
		return false
	}
}

func mentions(e ast.Expr, counter string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if x, ok := n.(ast.Expr); ok && types.ExprString(x) == counter {
			found = true
		}
		return !found
	})
	return found
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
