package dashboard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// launch_routes_pin_test.go pins agentLaunchRoutes (lane cli-2 fixes-1,
// audit H1: POST /api/tools/launch started an agent with no ask and no hold
// because no table named it). The test reads this package's source: every
// route registered with reg whose handler can reach a launch sink (a call
// that starts an agent or a harness of agents) must be a row of the table,
// and every row must be such a route. A new launch route therefore fails
// here until it is held for a human and asked about by R-168.

// launchSinkSelectors are the method calls that start an agent: the launch
// manager's creates (on s.opts.LaunchManager) and the arena runner's start.
var launchSinkSelectors = map[string]func(recv string) bool{
	"Create":            func(r string) bool { return strings.HasSuffix(r, "LaunchManager") },
	"CreateFresh":       func(r string) bool { return strings.HasSuffix(r, "LaunchManager") },
	"CreateResume":      func(r string) bool { return strings.HasSuffix(r, "LaunchManager") },
	"CreateGUI":         func(r string) bool { return strings.HasSuffix(r, "LaunchManager") },
	"StartRun":          func(string) bool { return true },
	"StartRunWithForce": func(string) bool { return true },
}

// launchSinkFuncs are the package functions that start an agent: the Tools
// card's window spawn.
var launchSinkFuncs = map[string]bool{"launchSpawn": true}

// exprString renders a selector chain ("s.opts.LaunchManager").
func exprString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprString(x.X) + "." + x.Sel.Name
	}
	return ""
}

// benchmarkRunArgv reports a []string literal that starts with "benchmark",
// "run": the benchmark job's argv, which drives agent harnesses.
func benchmarkRunArgv(n ast.Node) bool {
	cl, ok := n.(*ast.CompositeLit)
	if !ok || len(cl.Elts) < 2 {
		return false
	}
	var words []string
	for _, e := range cl.Elts[:2] {
		bl, ok := e.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return false
		}
		w, _ := strconv.Unquote(bl.Value)
		words = append(words, w)
	}
	return words[0] == "benchmark" && words[1] == "run"
}

// pkgFuncs parses this package (every non-test file, any build tag) into
// function name to bodies.
func pkgFuncs(t *testing.T) (map[string][]*ast.BlockStmt, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string][]*ast.BlockStmt{}
	var files []*ast.File
	for _, m := range matches {
		if strings.HasSuffix(m, "_test.go") {
			continue
		}
		src, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, m, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", m, err)
		}
		files = append(files, f)
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				funcs[fd.Name.Name] = append(funcs[fd.Name.Name], fd.Body)
			}
		}
	}
	return funcs, files
}

// reachesSink reports whether node (a body) can reach a launch sink through
// this package's own functions, by name.
type sinkWalker struct {
	funcs map[string][]*ast.BlockStmt
	memo  map[string]bool
	busy  map[string]bool
}

func (w *sinkWalker) node(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if found {
			return false
		}
		if benchmarkRunArgv(x) {
			found = true
			return false
		}
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if launchSinkFuncs[fn.Name] || w.fn(fn.Name) {
				found = true
			}
		case *ast.SelectorExpr:
			if recv, ok := launchSinkSelectors[fn.Sel.Name]; ok && recv(exprString(fn.X)) {
				found = true
			} else if exprString(fn.X) == "s" && w.fn(fn.Sel.Name) {
				found = true
			}
		}
		return !found
	})
	return found
}

func (w *sinkWalker) fn(name string) bool {
	if v, ok := w.memo[name]; ok {
		return v
	}
	if w.busy[name] {
		return false
	}
	w.busy[name] = true
	got := false
	for _, b := range w.funcs[name] {
		if w.node(b) {
			got = true
			break
		}
	}
	delete(w.busy, name)
	w.memo[name] = got
	return got
}

// TestEveryLaunchRouteIsHeldAndAsked is the pin.
func TestEveryLaunchRouteIsHeldAndAsked(t *testing.T) {
	funcs, files := pkgFuncs(t)
	w := &sinkWalker{funcs: funcs, memo: map[string]bool{}, busy: map[string]bool{}}
	launching := map[string]bool{}
	registered := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 4 {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "reg" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				return true
			}
			pattern, _ := strconv.Unquote(lit.Value)
			registered[pattern] = true
			var reaches bool
			switch h := call.Args[3].(type) {
			case *ast.SelectorExpr:
				reaches = w.fn(h.Sel.Name)
			case *ast.FuncLit:
				reaches = w.node(h.Body)
			default:
				reaches = w.node(h)
			}
			if reaches {
				launching[pattern] = true
			}
			return true
		})
	}
	if len(registered) < 100 {
		t.Fatalf("only %d registered routes parsed; the pin would be vacuous", len(registered))
	}
	if len(launching) < 5 {
		t.Fatalf("only %d launch routes found (%v); the sink set no longer matches the code", len(launching), launching)
	}
	inTable := map[string]bool{}
	for _, r := range agentLaunchRoutes {
		inTable[r.pattern] = true
		if !launching[r.pattern] {
			t.Errorf("agentLaunchRoutes row %q is not a registered route that starts an agent", r.pattern)
		}
	}
	var missing []string
	for p := range launching {
		if !inTable[p] {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	for _, p := range missing {
		t.Errorf("route %q can start an agent but is not in agentLaunchRoutes: an agent's request there would run unasked (add a row, and an R-168 row in internal/policy/rules_agentlaunch.go)", p)
	}
}

// launchRouteSamples is one request per agentLaunchRoutes row that the row
// holds, for the R-168 agreement check.
var launchRouteSamples = map[string]struct{ path, body string }{
	"/api/terminal/launch":             {path: "/api/terminal/launch", body: `{"tool":"claude-code"}`},
	"/api/arena/runs":                  {path: "/api/arena/runs", body: `{}`},
	"/api/session/":                    {path: "/api/session/abc/launch", body: `{}`},
	"/api/tools/launch":                {path: "/api/tools/launch", body: `{"tool":"claude-code"}`},
	"/api/security/fix/launch":         {path: "/api/security/fix/launch", body: `{"tool":"claude-code","project_root_hash":"h"}`},
	"/api/security/assessments/launch": {path: "/api/security/assessments/launch", body: `{"tool":"claude-code","assessment":"threat_model","project_root_hash":"h"}`},
	"/api/security/assessments/fix":    {path: "/api/security/assessments/fix", body: `{"tool":"claude-code","run":"3fa9c2d17b0e4a56","item":"T-1"}`},
	"/api/benchmarks/run":              {path: "/api/benchmarks/run", body: `{"spec":"x","confirm_spend":true}`},
}

// TestLaunchRoutesAgreeWithR168: every request the dashboard holds is one
// R-168 asks about when an agent's shell sends it, so the hook and the
// daemon cover the same launches.
func TestLaunchRoutesAgreeWithR168(t *testing.T) {
	e, err := policy.New(policy.Config{Mode: policy.ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range agentLaunchRoutes {
		sample, ok := launchRouteSamples[r.pattern]
		if !ok {
			t.Errorf("row %q has no sample request in launchRouteSamples", r.pattern)
			continue
		}
		if !r.path(sample.path) || (r.body != nil && !r.body([]byte(sample.body))) {
			t.Errorf("row %q does not hold its own sample %+v", r.pattern, sample)
		}
		line := `curl -X POST http://127.0.0.1:8821` + sample.path + ` -d '` + sample.body + `'`
		v := e.Evaluate(policy.Event{Kind: policy.KindShellExec, Target: line, Cwd: "/home/u/p", ProjectRoot: "/home/u/p", SessionID: "s1"})
		if v.RuleID != "R-168" || v.Decision != policy.DecisionAsk {
			t.Errorf("R-168 does not ask about %s (got %q %s)", line, v.RuleID, v.Decision)
		}
	}
}
