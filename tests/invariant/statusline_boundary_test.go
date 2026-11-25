package invariant

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 1. internal/statusline purity (belt-and-braces with its own imports_test.go)
// ---------------------------------------------------------------------------

// statuslineForbiddenImports mirrors internal/statusline/imports_test.go's
// own forbidden list exactly. Kept as a literal duplicate rather than a
// shared helper on purpose — same rationale as oneshotForbiddenImports in
// tests/invariant/oneshot_boundary_test.go: the whole point of
// "belt-and-braces" is that this suite does not depend on that package's
// test file continuing to exist.
var statuslineForbiddenImports = []string{
	"database/sql",
	"net/http",
	"os/exec",
	"github.com/fsnotify/fsnotify",
	"github.com/marmutapp/superbased-observer/internal/store",
	"github.com/marmutapp/superbased-observer/internal/db",
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost",
}

// TestStatuslinePurePackageImports enforces plan §7: internal/statusline
// imports none of the forbidden set. Uses the house assertNoImport helper
// (tests/invariant/aggregate_test.go), same package.
func TestStatuslinePurePackageImports(t *testing.T) {
	t.Parallel()
	dir := filepath.Join("..", "..", "internal", "statusline")
	for _, forbidden := range statuslineForbiddenImports {
		assertNoImport(t, dir, forbidden)
	}
}

// ---------------------------------------------------------------------------
// 2. cmd/observer/statusline.go — single-file forbidden-import AST scan
// ---------------------------------------------------------------------------

// statuslineCmdForbiddenImports is the plan §7 boundary for the command
// file: registration (internal/hook) is init's job, not the statusline
// command's, and a direct DB read (database/sql, internal/store) would
// duplicate WP2's cost-engine-priced query inside a command this plan
// requires stay side-effect-free and non-blocking.
var statuslineCmdForbiddenImports = []string{
	"database/sql",
	"github.com/marmutapp/superbased-observer/internal/store",
	"github.com/marmutapp/superbased-observer/internal/hook",
}

// scanFileImports parses src as a SINGLE Go file (filename is used only
// for parser diagnostics — src need not exist on disk, which is what lets
// the fixture tests below exercise the checker without ever touching the
// real cmd/observer/statusline.go) and returns the forbidden import paths
// it finds.
//
// This is deliberately single-file rather than whole-package like the
// house assertNoImport helper: cmd/observer is a large package whose
// OTHER files legitimately import database/sql, internal/store, and
// internal/hook (e.g. usage.go's own loadConfigAndDB, or start.go's
// autoRegisterHooks) — globbing the whole directory the way assertNoImport
// does would false-positive on those unrelated files. Scoping to exactly
// one *ast.File's Imports is the fix.
func scanFileImports(t *testing.T, filename string, src []byte, forbidden []string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	forbiddenSet := make(map[string]bool, len(forbidden))
	for _, f := range forbidden {
		forbiddenSet[f] = true
	}
	var hits []string
	for _, imp := range file.Imports {
		// Unquote, not a trim of double quotes: a raw-string (`...`)
		// import literal must not slip past the check.
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Errorf("%s: unparseable import literal %s: %v", filename, imp.Path.Value, err)
			continue
		}
		if forbiddenSet[p] {
			hits = append(hits, p)
		}
	}
	return hits
}

// TestStatuslineCmdNeverImportsForbiddenPackages is the real assertion
// (plan §7): cmd/observer/statusline.go imports none of
// statuslineCmdForbiddenImports.
func TestStatuslineCmdNeverImportsForbiddenPackages(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "cmd", "observer", "statusline.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if hits := scanFileImports(t, path, src, statuslineCmdForbiddenImports); len(hits) > 0 {
		t.Errorf("cmd/observer/statusline.go imports forbidden package(s) (plan §7 — registration is init's job, not the statusline command's; a direct DB read would pull database/sql/internal/store into a command that must stay non-blocking): %v", hits)
	}
}

// TestStatuslineScanFileImportsCatchesDeliberateViolations feeds
// scanFileImports small in-memory fixture sources — never the real
// cmd/observer/statusline.go — each importing exactly one forbidden
// package, and asserts the checker flags it. This is what proves
// TestStatuslineCmdNeverImportsForbiddenPackages is a live tripwire and
// not a vacuously-passing assertion.
func TestStatuslineScanFileImportsCatchesDeliberateViolations(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "database/sql",
			src: `package fixture

import "database/sql"

func demo() {
	var _ *sql.DB
}
`,
			want: "database/sql",
		},
		{
			name: "internal/store",
			src: `package fixture

import "github.com/marmutapp/superbased-observer/internal/store"

func demo() {
	_ = store.New
}
`,
			want: "github.com/marmutapp/superbased-observer/internal/store",
		},
		{
			name: "internal/hook",
			src: `package fixture

import "github.com/marmutapp/superbased-observer/internal/hook"

func demo() {
	_ = hook.NewRegistry
}
`,
			want: "github.com/marmutapp/superbased-observer/internal/hook",
		},
		{
			// A raw-string import literal is still an import.
			name: "database/sql (raw-string literal)",
			src:  "package fixture\n\nimport `database/sql`\n\nfunc demo() {\n\tvar _ *sql.DB\n}\n",
			want: "database/sql",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hits := scanFileImports(t, "fixture.go", []byte(tc.src), statuslineCmdForbiddenImports)
			if len(hits) == 0 {
				t.Fatalf("checker did NOT fire on a deliberate import of %q — the tripwire is dead", tc.want)
			}
			var found bool
			for _, h := range hits {
				if h == tc.want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("hits = %v, want an entry %q", hits, tc.want)
			}
		})
	}
}

// TestStatuslineScanFileImportsNoFalsePositiveOnCleanSource is the
// companion sanity check: legitimate imports (net/http, time), plus a
// comment that MENTIONS every forbidden import path, must NOT be
// flagged — comment text never becomes an *ast.ImportSpec.
func TestStatuslineScanFileImportsNoFalsePositiveOnCleanSource(t *testing.T) {
	t.Parallel()
	src := []byte(`package fixture

// This comment mentions database/sql, github.com/marmutapp/superbased-observer/internal/store,
// and github.com/marmutapp/superbased-observer/internal/hook — on purpose,
// to prove comment text is never mistaken for an import.
import (
	"net/http"
	"time"
)

func demo() {
	_ = http.MethodGet
	_ = time.Now
}
`)
	if hits := scanFileImports(t, "fixture.go", src, statuslineCmdForbiddenImports); len(hits) != 0 {
		t.Errorf("false positive(s) on clean source (comment-only mentions + legitimate net/http/time imports): %v", hits)
	}
}

// ---------------------------------------------------------------------------
// 3. cmd/observer/statusline.go — forbidden-identifier AST scan
// ---------------------------------------------------------------------------

// statuslineCmdForbiddenSymbols is the plan §7 zero-side-effect list for
// the command file, reusing the house forbiddenSymbol/scanForbiddenSymbols
// machinery from tests/invariant/oneshot_boundary_test.go (same package).
var statuslineCmdForbiddenSymbols = []forbiddenSymbol{
	{Qualifier: "os", Name: "Setenv"},
	{Qualifier: "config", Name: "Write", Prefix: true},
}

// TestStatuslineCmdNeverReferencesForbiddenSymbols is the real assertion
// (plan §7): cmd/observer/statusline.go references none of
// statuslineCmdForbiddenSymbols anywhere in its AST.
func TestStatuslineCmdNeverReferencesForbiddenSymbols(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "cmd", "observer", "statusline.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if hits := scanForbiddenSymbols(t, path, src, statuslineCmdForbiddenSymbols); len(hits) > 0 {
		t.Errorf("cmd/observer/statusline.go references forbidden symbol(s) (plan §7 zero-side-effect list):\n%s",
			strings.Join(hits, "\n"))
	}
}

// TestStatuslineScanForbiddenSymbolsCatchesDeliberateViolations proves the
// statuslineCmdForbiddenSymbols checker is a live tripwire against small
// in-memory fixture sources, never the real statusline.go.
func TestStatuslineScanForbiddenSymbolsCatchesDeliberateViolations(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "os.Setenv (qualified, exact)",
			src: `package fixture

func demo() {
	os.Setenv("OBSERVER_STATUSLINE_SESSION_COST", "1.23")
}
`,
			want: "os.Setenv",
		},
		{
			name: "config.Write* (qualified, prefix family)",
			src: `package fixture

func demo() {
	config.WriteGlobal(cfg)
}
`,
			want: "config.WriteGlobal",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hits := scanForbiddenSymbols(t, "fixture.go", []byte(tc.src), statuslineCmdForbiddenSymbols)
			if len(hits) == 0 {
				t.Fatalf("checker did NOT fire on a deliberate violation containing %q — the tripwire is dead", tc.want)
			}
			var found bool
			for _, h := range hits {
				if strings.Contains(h, tc.want) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("hits = %v, want one containing %q", hits, tc.want)
			}
		})
	}
}

// TestStatuslineScanForbiddenSymbolsNoFalsePositiveOnCleanSource is the
// companion sanity check: legitimate os.Getenv/config.Load, plus a
// comment mentioning the forbidden names, must NOT be flagged.
func TestStatuslineScanForbiddenSymbolsNoFalsePositiveOnCleanSource(t *testing.T) {
	t.Parallel()
	src := []byte(`package fixture

// This comment mentions os.Setenv and config.Write — on purpose, to
// prove comment text is never mistaken for code.
func demo() {
	_ = os.Getenv("HOME")
	cfg, _ := config.Load(config.LoadOptions{})
	_ = cfg
}
`)
	if hits := scanForbiddenSymbols(t, "fixture.go", src, statuslineCmdForbiddenSymbols); len(hits) != 0 {
		t.Errorf("false positive(s) on clean source (comment-only mentions + legitimate os.Getenv/config.Load): %v", hits)
	}
}

// ---------------------------------------------------------------------------
// 4. internal/hook/register.go — claudeCodeEvents pinned-contents assertion
// ---------------------------------------------------------------------------

// pinnedClaudeCodeEvents is the exact, ordered contents of
// internal/hook/register.go's claudeCodeEvents var as of the statusline
// arc (docs/plans/observer-statusline-plan-2026-07-30.md §7): "the
// claudeCodeEvents list unchanged by this arc — find the events list
// variable and pin its current contents so a statusline change that
// folds into hooks fails loudly." Statusline registration is a SEPARATE
// top-level settings.json key ("statusLine"), added/removed via its own
// registerClaudeCodeStatusline/unregisterClaudeCodeStatusline path — it
// must never grow, shrink, or reorder this list.
var pinnedClaudeCodeEvents = []string{
	"SessionStart",
	"SessionEnd",
	"Setup",
	"UserPromptSubmit",
	"UserPromptExpansion",
	"PreToolUse",
	"PostToolUse",
	"PostToolUseFailure",
	"PostToolBatch",
	"PermissionRequest",
	"PermissionDenied",
	"Stop",
	"StopFailure",
	"PreCompact",
	"PostCompact",
	"SubagentStart",
	"SubagentStop",
	"Notification",
	"CwdChanged",
	"InstructionsLoaded",
	"ConfigChange",
	"WorktreeRemove",
	// T-322 (fix/live-ground-2026-10-04-bef, 42c0f9cf1): the task hooks,
	// live-grounded; a deliberate hook-list change unrelated to the
	// statusline arc (Integration 6).
	"TaskCreated",
	"TaskCompleted",
}

// extractStringSliceVar parses src (a full parse, not ImportsOnly — a
// top-level var decl is a *ast.GenDecl, not an import) and returns the
// ordered string-literal contents of the composite-literal slice
// assigned to the top-level var named varName (e.g. `var claudeCodeEvents
// = []string{"A", "B", ...}`), plus whether such a var/shape was found at
// all.
//
// Comment-immune by construction: go/parser never turns a comment into
// an *ast.BasicLit, so a trailing "// ..." note on any element (several
// of register.go's claudeCodeEvents entries carry one) can never leak
// into, or otherwise affect, the extracted contents.
func extractStringSliceVar(t *testing.T, filename string, src []byte, varName string) ([]string, bool) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	var result []string
	found := false
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if name.Name != varName || i >= len(vs.Values) {
					continue
				}
				cl, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					continue
				}
				found = true
				for _, elt := range cl.Elts {
					lit, ok := elt.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					unquoted, uerr := strconv.Unquote(lit.Value)
					if uerr != nil {
						continue
					}
					result = append(result, unquoted)
				}
			}
		}
	}
	return result, found
}

// TestClaudeCodeEventsListUnchangedByStatuslineArc is the real assertion:
// internal/hook/register_claude.go's claudeCodeEvents var still contains exactly
// pinnedClaudeCodeEvents, in the same order. A deliberate hard failure —
// see the comment in the Errorf message — is the point: this arc adds a
// NEW top-level key ("statusLine"), never folds anything into the
// existing hook-events list.
func TestClaudeCodeEventsListUnchangedByStatuslineArc(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "internal", "hook", "register_claude.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	got, found := extractStringSliceVar(t, path, src, "claudeCodeEvents")
	if !found {
		t.Fatalf("could not find var claudeCodeEvents in %s — has it been renamed or removed?", path)
	}
	if !slices.Equal(got, pinnedClaudeCodeEvents) {
		t.Errorf("claudeCodeEvents drifted from the pinned plan §7 snapshot:\n got:  %#v\nwant: %#v\n\n"+
			"This is intentionally a hard failure: the statusline arc "+
			"(docs/plans/observer-statusline-plan-2026-07-30.md) adds an "+
			"entirely separate top-level settings.json key (\"statusLine\", "+
			"via registerClaudeCodeStatusline/unregisterClaudeCodeStatusline) "+
			"and must never fold into, reorder, or otherwise touch this list. "+
			"If this failed for a reason UNRELATED to the statusline arc, "+
			"update pinnedClaudeCodeEvents deliberately.", got, pinnedClaudeCodeEvents)
	}
}

// TestExtractStringSliceVarCatchesDrift proves extractStringSliceVar (and
// therefore TestClaudeCodeEventsListUnchangedByStatuslineArc) is a live
// tripwire: a fixture var with an extra element must NOT compare equal to
// pinnedClaudeCodeEvents.
func TestExtractStringSliceVarCatchesDrift(t *testing.T) {
	t.Parallel()
	src := []byte(`package fixture

var claudeCodeEvents = []string{
	"SessionStart",
	"SessionEnd",
	"SomeNewStatuslineEvent", // a hypothetical fold-in this arc must never make
}
`)
	got, found := extractStringSliceVar(t, "fixture.go", src, "claudeCodeEvents")
	if !found {
		t.Fatalf("checker did not find the fixture's claudeCodeEvents var — the tripwire is dead")
	}
	if slices.Equal(got, pinnedClaudeCodeEvents) {
		t.Fatalf("checker failed to detect a deliberately mutated (extra-element) claudeCodeEvents list")
	}
}

// TestExtractStringSliceVarNoFalsePositiveOnMatchingFixture is the
// companion sanity check: a fixture var built FROM pinnedClaudeCodeEvents
// itself (so this test stays correct even if a future, deliberate edit to
// pinnedClaudeCodeEvents lands), each element carrying a trailing comment,
// must extract back out byte-for-byte equal — proving comment text never
// leaks into or otherwise perturbs the extracted contents.
func TestExtractStringSliceVarNoFalsePositiveOnMatchingFixture(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("package fixture\n\nvar claudeCodeEvents = []string{\n")
	for _, e := range pinnedClaudeCodeEvents {
		fmt.Fprintf(&b, "\t%q, // trailing per-element comment must never affect extraction\n", e)
	}
	b.WriteString("}\n")

	got, found := extractStringSliceVar(t, "fixture.go", []byte(b.String()), "claudeCodeEvents")
	if !found {
		t.Fatalf("checker did not find the fixture's claudeCodeEvents var")
	}
	if !slices.Equal(got, pinnedClaudeCodeEvents) {
		t.Errorf("comment-immune extraction failed: got %#v, want %#v", got, pinnedClaudeCodeEvents)
	}
}
