package invariant

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ids_free_test.go is the "new ids are free" check (lane OPTMOD, the joint
// security-pillar and sandbox-module review): several plans and lanes
// allocate ids in parallel, and git merges two allocations of the same id
// without a conflict when they land in different files or rows. Each test
// below fails when two places allocate one id, so the second lane to merge
// has to pick the next free one:
//
//   - a guard rule id (`ID: "R-191"` table rows, or `ID: someRuleID` through
//     a constant, in any package: the core rule tables and a module's own
//     ExtraRules table alike);
//   - a security ledger id in docs/security.md (a ledger prefix starts at
//     -1, so two arcs that pick the same prefix collide on <PREFIX>-1 here);
//   - a migration number within one migration lineage (every directory of
//     NNN_*.sql files: agent, org server, PostgreSQL, archive, cloud);
//   - a node dashboard page id or route path (web/compgen's page table);
//   - a live-check register id in docs/sandboxed-terminals.md (LIN, WIN,
//     MAC and REM, the last the hosted rows' register from lane SBX-P7).

// allocations maps an id to the places that allocate it.
type allocations map[string][]string

func (a allocations) add(id, where string) { a[id] = append(a[id], where) }

// report fails t for every id with more than one distinct place.
func (a allocations) report(t *testing.T, what string) {
	t.Helper()
	ids := make([]string, 0, len(a))
	for id := range a {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		places := uniqueSorted(a[id])
		if len(places) > 1 {
			t.Errorf("%s %s is allocated in %d places: %s (pick the next free one)", what, id, len(places), strings.Join(places, "; "))
		}
	}
}

func uniqueSorted(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// guardRuleID is the shape of a guard rule id.
var guardRuleID = regexp.MustCompile(`^[A-Z]-[0-9]{3}$`)

// TestGuardRuleIDsAreAllocatedOnce: every rule id's rows live in one file. A
// multi-row id (one rule split by sub-shape) is fine inside its file; the
// same id in two files is two rules.
//
// A row is an `ID: <value>` field of a composite literal in non-test source,
// where the value is a rule-shaped string literal (`ID: "R-191"`), a
// package-level constant of the same package (`ID: injectionRuleID`, R-180),
// or a constant of another package in this module (`ID: policy.SomeRuleID`).
// RuleID fields (a verdict naming a rule) are not rows. Known gap: an id
// built at run time (fmt.Sprintf, a function call, a variable) is not seen;
// no rule table does that today.
func TestGuardRuleIDsAreAllocatedOnce(t *testing.T) {
	root := repoRoot(t)
	type goFile struct {
		rel  string // slash path from the repo root
		dir  string // slash path of its directory
		file *ast.File
	}
	var files []goFile
	consts := map[string]map[string]string{} // dir -> constant name -> rule id
	fset := token.NewFileSet()
	for _, dir := range []string{"internal", "cmd"} {
		walkGo(t, filepath.Join(root, dir), func(path string, src []byte) {
			if !bytes.Contains(src, []byte("ID")) {
				return
			}
			f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			gf := goFile{rel: rel, dir: filepath.ToSlash(filepath.Dir(rel)), file: f}
			files = append(files, gf)
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if i >= len(vs.Values) {
							continue
						}
						if id, ok := ruleIDLiteral(vs.Values[i]); ok {
							if consts[gf.dir] == nil {
								consts[gf.dir] = map[string]string{}
							}
							consts[gf.dir][name.Name] = id
						}
					}
				}
			}
		})
	}
	ids := allocations{}
	viaConst := 0
	for _, gf := range files {
		imports := map[string]string{} // local name -> slash dir in this module
		for _, imp := range gf.file.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if !strings.HasPrefix(p, modulePath) {
				continue
			}
			name := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			imports[name] = strings.TrimPrefix(p, modulePath)
		}
		ast.Inspect(gf.file, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "ID" {
				return true
			}
			switch v := kv.Value.(type) {
			case *ast.BasicLit:
				if id, ok := ruleIDLiteral(v); ok {
					ids.add(id, gf.rel)
				}
			case *ast.Ident:
				if id, ok := consts[gf.dir][v.Name]; ok {
					ids.add(id, gf.rel)
					viaConst++
				}
			case *ast.SelectorExpr:
				if pkg, ok := v.X.(*ast.Ident); ok {
					if id, ok := consts[imports[pkg.Name]][v.Sel.Name]; ok {
						ids.add(id, gf.rel)
						viaConst++
					}
				}
			}
			return true
		})
	}
	if len(ids) < 50 {
		t.Fatalf("found only %d guard rule ids; the scan is stale", len(ids))
	}
	if viaConst == 0 || len(ids["R-180"]) == 0 {
		t.Fatal("R-180's row (ID: injectionRuleID) was not resolved; the constant scan is stale")
	}
	ids.report(t, "guard rule id")
}

// ruleIDLiteral returns the rule id a string literal expression holds.
func ruleIDLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil || !guardRuleID.MatchString(s) {
		return "", false
	}
	return s, true
}

// ledgerRow is a docs/security.md table row whose first cell is a ledger id
// (PREFIX-N, a prefix of one or more dash-joined parts).
var ledgerRow = regexp.MustCompile(`(?m)^\| ([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-[0-9]+[a-z]?) \|`)

// TestSecurityLedgerIDsAreAllocatedOnce: each ledger id heads one row.
func TestSecurityLedgerIDsAreAllocatedOnce(t *testing.T) {
	skipInPublicTree(t, repoRoot(t), "docs/security.md")
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "security.md"))
	if err != nil {
		t.Fatal(err)
	}
	ids := allocations{}
	lines := strings.Split(string(b), "\n")
	for i, line := range lines {
		if m := ledgerRow.FindStringSubmatch(line); m != nil {
			ids.add(m[1], "docs/security.md:"+strconv.Itoa(i+1))
		}
	}
	if len(ids) < 100 {
		t.Fatalf("found only %d ledger ids; the scan is stale", len(ids))
	}
	ids.report(t, "ledger id")
}

// migrationFile is a migration's numbered file name.
var migrationFile = regexp.MustCompile(`^([0-9]{3,4})_.*\.sql$`)

// TestMigrationNumbersAreAllocatedOnce: within each migration lineage (a
// directory of NNN_*.sql files) a number names one file.
func TestMigrationNumbersAreAllocatedOnce(t *testing.T) {
	root := repoRoot(t)
	lineages := 0
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if d.Name() == "testdata" || d.Name() == "node_modules" {
			return filepath.SkipDir
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		ids := allocations{}
		for _, e := range entries {
			if m := migrationFile.FindStringSubmatch(e.Name()); m != nil && !e.IsDir() {
				n := strings.TrimLeft(m[1], "0")
				ids.add(n, e.Name())
			}
		}
		if len(ids) == 0 {
			return nil
		}
		lineages++
		rel, _ := filepath.Rel(root, path)
		ids.report(t, "migration "+filepath.ToSlash(rel)+" number")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if lineages < 3 {
		t.Fatalf("found only %d migration lineages; the scan is stale", lineages)
	}
}

// compgenPageRow is one row of web/compgen's page table:
// {NavID, Path, Module, Export, Component}.
var compgenPageRow = regexp.MustCompile(`\{"([^"]*)", "([^"]*)", "([^"]*)", "([^"]*)", "([^"]*)"\}`)

// TestNodePageIDsAreAllocatedOnce: a node dashboard page id (its nav id) and
// a route path each name one page, whichever component owns it (the
// security pillar's `code-security` page sits beside Guard's `security` page;
// a component id and a page id are different namespaces).
func TestNodePageIDsAreAllocatedOnce(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "web", "compgen", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	start := strings.Index(src, "var pages = []page{")
	if start < 0 {
		t.Fatal("web/compgen/main.go: page table not found; the scan is stale")
	}
	end := strings.Index(src[start:], "\n}\n")
	if end < 0 {
		t.Fatal("web/compgen/main.go: page table end not found")
	}
	navIDs, paths := allocations{}, allocations{}
	rows := compgenPageRow.FindAllStringSubmatch(src[start:start+end], -1)
	for _, m := range rows {
		where := m[3] + " (component " + m[5] + ")"
		if m[1] != "" {
			navIDs.add(m[1], where)
		}
		paths.add("/"+m[2], where)
	}
	if len(rows) < 20 {
		t.Fatalf("found only %d page rows; the scan is stale", len(rows))
	}
	navIDs.report(t, "node page id")
	paths.report(t, "node page path")
}

// liveCheckRegisterPrefixes are the prefixes of the sandbox module's
// live-check registers in docs/sandboxed-terminals.md: LIN (Linux), WIN
// (Windows, lane SBX-P6), MAC (macOS, lane SBX-P5) and REM (the hosted rows,
// lane SBX-P7). A new register adds its prefix here.
var liveCheckRegisterPrefixes = []string{"LIN", "WIN", "MAC", "REM"}

// registerRow is a docs/sandboxed-terminals.md table row whose first cell is
// a register id (PREFIX-N).
var registerRow = regexp.MustCompile(`(?m)^\| ([A-Z]+)-([0-9]+) \|`)

// TestLiveCheckRegisterIDsAreAllocatedOnce: each live-check register id heads
// one row of docs/sandboxed-terminals.md, every register prefix there is a
// known one, and no register prefix is also a security ledger prefix (a
// REM-1 in both files would be two things under one name).
func TestLiveCheckRegisterIDsAreAllocatedOnce(t *testing.T) {
	root := repoRoot(t)
	skipInPublicTree(t, root, "docs/sandboxed-terminals.md and docs/security.md")
	b, err := os.ReadFile(filepath.Join(root, "docs", "sandboxed-terminals.md"))
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, p := range liveCheckRegisterPrefixes {
		known[p] = true
	}
	ids := allocations{}
	seen := map[string]int{}
	for i, line := range strings.Split(string(b), "\n") {
		m := registerRow.FindStringSubmatch(line)
		if m == nil || !known[m[1]] {
			continue
		}
		seen[m[1]]++
		ids.add(m[1]+"-"+m[2], "docs/sandboxed-terminals.md:"+strconv.Itoa(i+1))
	}
	for _, p := range liveCheckRegisterPrefixes {
		if seen[p] == 0 {
			t.Errorf("register prefix %s has no row in docs/sandboxed-terminals.md; the scan is stale", p)
		}
	}
	ids.report(t, "live-check register id")
	sec, err := os.ReadFile(filepath.Join(root, "docs", "security.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ledgerRow.FindAllStringSubmatch(string(sec), -1) {
		id := m[1]
		prefix := id[:strings.LastIndex(id, "-")]
		if known[prefix] {
			t.Errorf("security ledger id %s uses the live-check register prefix %s", id, prefix)
		}
	}
}

func walkGo(t *testing.T, dir string, fn func(path string, src []byte)) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fn(path, b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
