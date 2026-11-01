package defaults

import (
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// TestAdaptersCanonicalOrder pins the full build's adapter list to the
// pre-P5 fan-in order (lane MP-ADP moved most adapters to self-registering
// files; the watcher's dispatch and every consumer must see exactly the same
// list in exactly the same order).
func TestAdaptersCanonicalOrder(t *testing.T) {
	want := []string{
		"claude-code", "codex", "cline", "cline-cli", "copilot", "copilot-cli", "cowork", "cursor",
		"deepseek", "openclaw", "opencode", "pi", "gemini-cli", "antigravity", "antigravity-cli",
		"hermes", "kilo-code", "kilo-code-cli", "qwen-code", "kiro-cli", "crush", "kimi-code", "grok",
		"devin", "qoder", "aider", "goose", "droid", "open-interpreter", "command-code", "muse",
		"prime-agent", "junie", "zcode", "mistral-code", "freebuff", "grokbot", "kiro-crew",
		"poolside", "zed", "chatgpt-web", "claude-web", "perplexity-web", "gemini-web", "copilot-web",
		"autohand", "ibm-bob", "cortex-code", "codebuddy", "deepagents-code", "dimcode", "dirac", "kimchi", "stakpak", "vtcode",
	}
	// In a build with adapter omit tags the expected list is the canonical
	// one minus what the binary reports compiled out (consistency within
	// the compiled set); the plain build checks the whole list.
	omitted := map[string]bool{}
	for _, id := range components.Omitted() {
		omitted[strings.TrimPrefix(id, "adapter.")] = true
	}
	var keep []string
	for _, n := range want {
		if !omitted[n] {
			keep = append(keep, n)
		}
	}
	want = keep
	var got []string
	for _, a := range Adapters() {
		got = append(got, a.Name())
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("adapter order changed:\n got %v\nwant %v", got, want)
	}
	seen := map[int]bool{}
	for _, s := range registered {
		if seen[s.order] {
			t.Errorf("two adapters share canonical slot %d", s.order)
		}
		seen[s.order] = true
	}
}

// TestByTool returns a fresh adapter by registry tool id and refuses an
// unknown one.
func TestByTool(t *testing.T) {
	all := Adapters()
	if len(all) == 0 {
		t.Skip("this build compiles every adapter out")
	}
	name := all[0].Name()
	a, ok := ByTool(name)
	if !ok || a.Name() != name {
		t.Fatalf("ByTool(%s) = %v, %v", name, a, ok)
	}
	if _, ok := ByTool("no-such-tool"); ok {
		t.Fatal("ByTool accepted an unknown tool")
	}
}

// TestRegistrationPairsMatchTheCatalog is the stub-parity check for the
// adapter wiring pairs (plan 5.1, risk R1): every adapter_<pkg>.go is built
// exactly when its adapter_<pkg>_omit.go is not (one constraint is the
// negation of the other), the omit file marks exactly the catalog rows the
// package serves, every one of those rows claims L1, its own omit tag is in
// the constraint, and every adapter row that claims L1 has such a pair.
func TestRegistrationPairsMatchTheCatalog(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "adapter_") || strings.HasSuffix(name, "_test.go") || strings.HasSuffix(name, "_omit.go") {
			continue
		}
		stem := strings.TrimSuffix(name, ".go")
		onExpr, onImports, _ := readGoFile(t, name)
		offExpr, _, marks := readGoFile(t, stem+"_omit.go")
		onTags, offTags := tagsOf(onExpr), tagsOf(offExpr)
		if strings.Join(onTags, ",") != strings.Join(offTags, ",") {
			t.Errorf("%s and its omit file name different tags: %v vs %v", name, onTags, offTags)
		}
		for _, tags := range [][]string{nil, onTags} {
			set := map[string]bool{}
			for _, tg := range tags {
				set[tg] = true
			}
			ok := func(tag string) bool { return set[tag] }
			if onExpr.Eval(ok) == offExpr.Eval(ok) {
				t.Errorf("%s and its omit file are not exact complements (tags %v)", name, tags)
			}
		}
		pkg := ""
		for _, imp := range onImports {
			if rel := strings.TrimPrefix(imp, "github.com/marmutapp/superbased-observer/"); strings.HasPrefix(rel, "internal/adapter/") && rel != "internal/adapter" {
				pkg = rel
			}
		}
		if pkg == "" {
			t.Errorf("%s imports no adapter package", name)
			continue
		}
		var served []string
		for _, c := range components.All() {
			if c.Class != components.ClassAdapter {
				continue
			}
			if contains(c.Packages, pkg) || contains(c.HostedIn, pkg) {
				served = append(served, c.ID)
				covered[c.ID] = true
				if !c.Levels.Has(components.L1) {
					t.Errorf("%s is registered from a tagged file but does not claim L1", c.ID)
				}
				if !contains(onTags, c.BuildTag()) {
					t.Errorf("%s: its omit tag %s is not in %s's constraint", c.ID, c.BuildTag(), name)
				}
			}
		}
		sort.Strings(served)
		sort.Strings(marks)
		if strings.Join(served, ",") != strings.Join(marks, ",") {
			t.Errorf("%s_omit.go marks %v, the catalog rows of %s are %v", stem, marks, pkg, served)
		}
	}
	for _, c := range components.All() {
		if c.Class == components.ClassAdapter && c.Levels.Has(components.L1) && !covered[c.ID] {
			t.Errorf("%s claims L1 but no adapter_<pkg>.go pair registers it", c.ID)
		}
	}
}

// readGoFile returns a file's build constraint, its imports and the string
// arguments of its components.MarkOmitted calls.
func readGoFile(t *testing.T, name string) (constraint.Expr, []string, []string) {
	t.Helper()
	src, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var expr constraint.Expr
	for _, line := range strings.Split(string(src), "\n") {
		if constraint.IsGoBuild(line) {
			if expr, err = constraint.Parse(line); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			break
		}
	}
	if expr == nil {
		t.Fatalf("%s has no //go:build line", name)
	}
	f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var imports []string
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		imports = append(imports, p)
	}
	var marks []string
	const call = `components.MarkOmitted("`
	for _, line := range strings.Split(string(src), "\n") {
		if i := strings.Index(line, call); i >= 0 {
			rest := line[i+len(call):]
			if j := strings.Index(rest, `"`); j >= 0 {
				marks = append(marks, rest[:j])
			}
		}
	}
	return expr, imports, marks
}

// tagsOf returns the sorted tag names an expression mentions.
func tagsOf(e constraint.Expr) []string {
	set := map[string]bool{}
	e.Eval(func(tag string) bool { set[tag] = true; return false })
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
