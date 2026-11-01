package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// daemonLoopCalls returns every loop name started through a two-argument
// `.Go(name, fn)` call in this package's non-test source, whatever the file's
// build tags (an omit twin and a module's own file are parsed too), keyed by
// name with one position each. A call whose name is not a string literal is
// returned in nonLiteral: the classification test cannot see it, so it fails.
// The bodies of gatedGroup.Go and namedGroup.Go (the gate itself) are skipped.
func daemonLoopCalls(t *testing.T) (names map[string]string, nonLiteral []string) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	names = map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil || isGroupGoMethod(fd) {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 2 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Go" {
					return true
				}
				pos := fset.Position(call.Pos()).String()
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					nonLiteral = append(nonLiteral, pos)
					return true
				}
				name, err := strconv.Unquote(lit.Value)
				if err != nil {
					nonLiteral = append(nonLiteral, pos)
					return true
				}
				names[name] = pos
				return true
			})
		}
	}
	return names, nonLiteral
}

// isGroupGoMethod reports the Go method of gatedGroup or namedGroup, whose
// inner call forwards a variable name by design.
func isGroupGoMethod(fd *ast.FuncDecl) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 || fd.Name.Name != "Go" {
		return false
	}
	typ := fd.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	id, ok := typ.(*ast.Ident)
	return ok && (id.Name == "gatedGroup" || id.Name == "namedGroup")
}

// TestEveryDaemonLoopIsClassified fails when a daemon loop is started
// without a classification (lane OPTMOD): every `.Go("name", fn)` call in
// this package, in any file and under any build tag, names a loop exactly
// one table classifies (daemonLoopComponents for core rows, moduleGates for
// an optional module's rows); every row names a loop some call starts; and
// every component a row names is a node catalog row. The runtime fails
// closed on an unclassified name, so this test is what keeps a loop running
// at all.
func TestEveryDaemonLoopIsClassified(t *testing.T) {
	found, nonLiteral := daemonLoopCalls(t)
	for _, pos := range nonLiteral {
		t.Errorf("%s: a daemon loop name must be a string literal so it can be classified", pos)
	}
	if len(found) < 30 {
		t.Fatalf("found only %d daemon loops; the scan is stale", len(found))
	}
	for name, pos := range found {
		if _, _, ok := loopClass(name); !ok {
			t.Errorf("%s: loop %q is not classified (add a daemonLoopComponents row, or a moduleGates row for an optional module)", pos, name)
		}
	}
	owners := map[string][]string{}
	for name, ids := range daemonLoopComponents {
		owners[name] = append(owners[name], "daemonLoopComponents")
		if found[name] == "" {
			t.Errorf("daemonLoopComponents row %q names no started loop", name)
		}
		if bad := componentstate.UnknownNodeIDs(ids...); len(bad) > 0 {
			t.Errorf("loop %q names %v, not node components", name, bad)
		}
	}
	for _, row := range moduleGates {
		for _, name := range row.loops {
			owners[name] = append(owners[name], "moduleGates "+row.component)
			if found[name] == "" {
				t.Errorf("moduleGates row %s names loop %q, which nothing starts", row.component, name)
			}
		}
	}
	for name, by := range owners {
		if len(by) > 1 {
			sort.Strings(by)
			t.Errorf("loop %q is classified twice: %v", name, by)
		}
	}
	for _, row := range inertOverlay {
		if bad := componentstate.UnknownNodeIDs(row.component); len(bad) > 0 {
			t.Errorf("inertOverlay names unknown component %q", row.component)
		}
	}
}

// TestModuleGatesAreOptionalNodeComponents pins the module table: every row
// names a node catalog row that is not core (core cannot be inactive, so a
// module gate on it would be dead), once.
func TestModuleGatesAreOptionalNodeComponents(t *testing.T) {
	seen := map[string]bool{}
	for _, row := range moduleGates {
		if bad := componentstate.UnknownNodeIDs(row.component); len(bad) > 0 {
			t.Errorf("moduleGates row %q is not a node component", row.component)
			continue
		}
		if c, _ := components.Get(row.component); c.Class == components.ClassCore {
			t.Errorf("moduleGates row %q is core; module rows gate optional components", row.component)
		}
		if seen[row.component] {
			t.Errorf("moduleGates names %q twice", row.component)
		}
		seen[row.component] = true
		if len(row.loops) == 0 && row.inert == nil {
			t.Errorf("moduleGates row %q gates nothing", row.component)
		}
	}
	if !seen["terminals.sandbox"] {
		t.Error("moduleGates lacks the terminals.sandbox row")
	}
}

// TestUnclassifiedLoopFailsClosed: a loop no table names does not start, and
// says so as a defect, not as a component choice.
func TestUnclassifiedLoopFailsClosed(t *testing.T) {
	snap := componentstate.Resolve(config.ComponentsConfig{}, fullNodeIDs())
	if loopAllowed(snap, "no-such-loop") {
		t.Fatal("an unclassified loop must not start")
	}
	var out bytes.Buffer
	g := newGatedGroup(namedGroup{}, snap, &out)
	g.Go("no-such-loop", func() error {
		t.Error("an unclassified loop ran")
		return nil
	})
	if len(g.skipped) != 1 || !strings.Contains(out.String(), "not classified") {
		t.Fatalf("skipped=%v out=%q", g.skipped, out.String())
	}
}

// TestModuleLoopFailsInvisible: a module row's loop starts only while its
// component is active under ModuleActive, so a row whose id the catalog does
// not know never starts it (where a core row would fail open).
func TestModuleLoopFailsInvisible(t *testing.T) {
	// A distro-stamped build resolves its own distro's base, where
	// terminals.sandbox is never active by default.
	requireUnstampedBuild(t)
	saved := moduleGates
	t.Cleanup(func() { moduleGates = saved })
	moduleGates = append(append([]moduleGate(nil), saved...),
		moduleGate{component: "terminals.sandbox", loops: []string{"sandbox-test-loop"}},
		moduleGate{component: "no.such.module", loops: []string{"typo-test-loop"}},
	)
	all := componentstate.Resolve(config.ComponentsConfig{}, fullNodeIDs())
	if !loopAllowed(all, "sandbox-test-loop") {
		t.Error("a module loop must start while its component is active")
	}
	if loopAllowed(all, "typo-test-loop") {
		t.Error("a module loop whose component id is unknown must not start")
	}
	remove := []string{"terminals.sandbox"}
	for _, c := range components.ForBinary(components.BinaryNode) {
		if strings.HasPrefix(c.ID, "terminals.sandbox.") {
			remove = append(remove, c.ID)
		}
	}
	off := componentstate.Resolve(config.ComponentsConfig{Remove: remove}, fullNodeIDs())
	if loopAllowed(off, "sandbox-test-loop") {
		t.Error("a module loop must not start while its component is inactive")
	}
}

// TestSandboxInertOverlay: [terminal.sandbox] enabled = true does nothing at
// start while terminals.sandbox is inactive, compiled out, or inactive
// because terminals (which it requires) is; it stays on while active.
func TestSandboxInertOverlay(t *testing.T) {
	requireUnstampedBuild(t)
	cfg := config.Default()
	cfg.Terminal.Sandbox.Enabled = true
	var withoutSandbox []string
	for _, id := range fullNodeIDs() {
		if id != "terminals.sandbox" {
			withoutSandbox = append(withoutSandbox, id)
		}
	}
	cases := []struct {
		name string
		snap componentstate.Snapshot
		want bool
	}{
		{"active", componentstate.Resolve(config.ComponentsConfig{}, fullNodeIDs()), true},
		{"removed", componentstate.Resolve(config.ComponentsConfig{Remove: []string{"terminals.sandbox"}}, fullNodeIDs()), false},
		{"compiled out", componentstate.Resolve(config.ComponentsConfig{}, withoutSandbox), false},
		{"terminals removed", removalSnapshot(t, "terminals"), false},
		{"zero snapshot", componentstate.Snapshot{}, false},
	}
	for _, tc := range cases {
		if got := applyInertOverlay(cfg, tc.snap).Terminal.Sandbox.Enabled; got != tc.want {
			t.Errorf("%s: sandbox enabled = %v, want %v", tc.name, got, tc.want)
		}
	}
	if !cfg.Terminal.Sandbox.Enabled {
		t.Fatal("the overlay must not change its input")
	}
}
