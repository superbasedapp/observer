package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/genout"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// committedDir is where the generated migration lives, relative to this
// package dir. The file NAME comes from the generator itself
// (migrationName), so the gate cannot end up diffing the wrong file.
const committedDir = "../migrations"

// repoRoot is this package's path back to the module root, used by the
// conformance tests that read adapter sources.
const repoRoot = "../../.."

func generateOrFail(t *testing.T) []byte {
	t.Helper()
	data, err := generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return data
}

// statements splits the generated body into executable statements,
// dropping comment-only lines so a test that forbids a token (LIKE, a
// bare SET) cannot be fooled by prose in the header.
func statements(t *testing.T, body []byte) []string {
	t.Helper()
	var code []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		code = append(code, line)
	}
	var out []string
	for _, s := range strings.Split(strings.Join(code, "\n"), ";") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		t.Fatal("no statements in generated migration")
	}
	return out
}

// TestGenerateIsDeterministic is the precondition for the drift gate: if
// generate() were order-unstable (a ranged map, a clock, an environment
// read) the gate would fail at random.
func TestGenerateIsDeterministic(t *testing.T) {
	first := generateOrFail(t)
	for run := 2; run <= 5; run++ {
		if next := generateOrFail(t); !bytes.Equal(next, first) {
			t.Fatalf("run %d differs from run 1 (%d vs %d bytes)", run, len(next), len(first))
		}
	}
}

// TestGeneratedMatchesCommitted is the in-test half of the drift gate:
// it fails the Go suite (not just `make verify-assistant-migration`)
// when somebody hand-edits the committed migration, or changes the site
// table without regenerating it.
func TestGeneratedMatchesCommitted(t *testing.T) {
	path := filepath.Join(committedDir, migrationName)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed %s: %v", path, err)
	}
	if got := generateOrFail(t); !bytes.Equal(got, want) {
		t.Errorf("%s drifted from a fresh generator run (%d committed bytes vs %d generated); "+
			"run `make assistant-migration-build` and commit", path, len(want), len(got))
	}
}

// TestEveryStatementIsAnExactPairRewrite pins guard predicate 1, the
// property that replaces 077's unknown-only guard: the old type is named
// in the WHERE and the new type in the SET, so a statement can only ever
// convert task_complete -> assistant_message and a second execution
// matches nothing.
func TestEveryStatementIsAnExactPairRewrite(t *testing.T) {
	for i, s := range statements(t, generateOrFail(t)) {
		if !strings.Contains(s, "SET action_type = '"+newType+"'") {
			t.Errorf("statement %d does not SET %q:\n%s", i, newType, s)
		}
		if !strings.Contains(s, "AND action_type = '"+oldType+"'") {
			t.Errorf("statement %d has no `AND action_type = '%s'` guard — a bare SET would rewrite rows "+
				"an adapter deliberately typed something else:\n%s", i, oldType, s)
		}
		if strings.Contains(s, "DELETE") || strings.Contains(s, "DROP") || strings.Contains(s, "INSERT") {
			t.Errorf("statement %d is not a plain UPDATE:\n%s", i, s)
		}
	}
}

// TestEveryStatementIsToolScoped pins guard predicate 3. An unscoped
// rewrite would flatten a raw name that means different things in
// different harnesses.
func TestEveryStatementIsToolScoped(t *testing.T) {
	for i, s := range statements(t, generateOrFail(t)) {
		if !strings.Contains(s, "WHERE tool = '") {
			t.Errorf("statement %d is not tool-scoped:\n%s", i, s)
		}
	}
}

// TestNoStatementUsesLIKE pins guard predicate 2. SQLite's LIKE is ASCII
// case-INSENSITIVE and `_` is a wildcard (these names are full of
// underscores), and a LIKE pattern would additionally capture FUTURE
// `.assistant_text` names added after this migration shipped.
func TestNoStatementUsesLIKE(t *testing.T) {
	for i, s := range statements(t, generateOrFail(t)) {
		if strings.Contains(strings.ToUpper(s), " LIKE ") {
			t.Errorf("statement %d matches with LIKE; use exact literals:\n%s", i, s)
		}
		if !strings.Contains(s, "raw_tool_name = '") && !strings.Contains(s, "raw_tool_name IN (") {
			t.Errorf("statement %d does not scope raw_tool_name by exact literal:\n%s", i, s)
		}
	}
}

// TestClaudeCodeStopHookIsCarvedOut pins guard predicate 4 — the one a
// mechanical rewrite would get wrong. It also pins the NULL-safe
// spelling: actions.source_file is NULLable, so a bare `<>` would be
// NULL (hence FALSE) for a NULL source file and silently skip those
// walker rows.
func TestClaudeCodeStopHookIsCarvedOut(t *testing.T) {
	var found bool
	for _, s := range statements(t, generateOrFail(t)) {
		if !strings.Contains(s, "WHERE tool = '"+models.ToolClaudeCode+"'") {
			continue
		}
		found = true
		want := "AND COALESCE(source_file, '') <> '" + claudeCodeHookSourceFile + "'"
		if !strings.Contains(s, want) {
			t.Errorf("the claude-code statement is missing the Stop-hook carve-out %q:\n%s", want, s)
		}
	}
	if !found {
		t.Fatal("no claude-code statement in the generated migration")
	}

	// And no OTHER tool carries a carve-out it never needed.
	for _, s := range statements(t, generateOrFail(t)) {
		if strings.Contains(s, "COALESCE(source_file") &&
			!strings.Contains(s, "WHERE tool = '"+models.ToolClaudeCode+"'") {
			t.Errorf("a non-claude-code statement carries a source_file carve-out:\n%s", s)
		}
	}
}

// TestHookSourceFileSentinelMatchesHookWriter pins claudeCodeHookSourceFile
// against the hook writer's own source. cmd/observer is package main and
// cannot be imported, so the literal is verified by reading the file —
// the alternative (trusting a transcribed string) is exactly how a
// carve-out silently stops carving.
func TestHookSourceFileSentinelMatchesHookWriter(t *testing.T) {
	path := filepath.Join(repoRoot, "cmd", "observer", "hook.go")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(body), `SourceFile:    "`+claudeCodeHookSourceFile+`"`) {
		t.Errorf("%s no longer sets SourceFile to %q — the migration's Stop-hook carve-out is stale",
			path, claudeCodeHookSourceFile)
	}
	// The Stop event must still be the one that keeps task_complete.
	if !strings.Contains(string(body), "models.ActionTaskComplete, \"stop\"") {
		t.Errorf("%s: buildClaudeStopEvent no longer emits models.ActionTaskComplete for the stop event — "+
			"the B2b exemplar contract changed and this migration's carve-out must be revisited", path)
	}
}

// TestSiteTableIsWellFormed pins the table's own invariants: no
// duplicate raw names, no empty tool lists, every raw name in the
// `.assistant_text` family, and at least one swept site (the table is
// not allowed to quietly become empty).
func TestSiteTableIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	var swept int
	for _, s := range sites {
		if seen[s.raw] {
			t.Errorf("duplicate site raw name %q", s.raw)
		}
		seen[s.raw] = true
		if !strings.HasSuffix(s.raw, ".assistant_text") {
			t.Errorf("site %q is outside the .assistant_text family", s.raw)
		}
		if len(s.tools) == 0 {
			t.Errorf("site %q has no tools", s.raw)
		}
		if s.emitSite == "" {
			t.Errorf("site %q has no emit-site provenance", s.raw)
		}
		if s.swept {
			swept++
		}
	}
	if swept != 7 {
		t.Errorf("swept sites = %d, want the 7 emit sites WP-T6/B2a re-typed", swept)
	}
}

// TestSiteRawNamesAppearInAdapterSources proves the table describes real
// emit sites rather than invented names: every non-dynamic raw name must
// appear as a string literal somewhere under internal/adapter. The
// dynamic ones (cline/roo-code build `toolID + ".assistant_text"` at
// runtime) are exempt by construction and flagged as such in the table.
func TestSiteRawNamesAppearInAdapterSources(t *testing.T) {
	corpus := adapterSources(t)
	for _, s := range sites {
		if s.dynamicName {
			continue
		}
		if !strings.Contains(corpus, `"`+s.raw+`"`) {
			t.Errorf("site raw name %q appears in no adapter source — the table has drifted from the emit sites", s.raw)
		}
	}
}

// TestNoAdapterTypesAssistantTextAsTaskComplete is the B2a invariant,
// pinned structurally instead of by grep: walk every non-test adapter
// source with go/ast, find each models.ToolEvent composite literal whose
// RawToolName is a string literal in the `.assistant_text` family, and
// require its ActionType to be models.ActionAssistantMessage.
//
// Scope note: this catches composite-literal emit sites, which is every
// adapter. The claude-code Stop hook (cmd/observer/hook.go) builds its
// event by field ASSIGNMENT after baseToolEvent, so it is outside this
// scan by construction — which is correct, because it is the one
// producer that must keep task_complete. Its contract is pinned instead
// by TestHookSourceFileSentinelMatchesHookWriter.
func TestNoAdapterTypesAssistantTextAsTaskComplete(t *testing.T) {
	root := filepath.Join(repoRoot, "internal", "adapter")
	fset := token.NewFileSet()

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			raw, hasRaw := litFieldString(lit, "RawToolName")
			if !hasRaw || !strings.HasSuffix(raw, ".assistant_text") {
				return true
			}
			action, hasAction := litFieldSelector(lit, "ActionType")
			if !hasAction {
				// A computed ActionType (openclaw branches on part type)
				// is legitimate; the per-adapter tests pin those.
				return true
			}
			if action != "models."+actionConstName(models.ActionAssistantMessage) {
				t.Errorf("%s:%d: RawToolName %q is typed %s; the assistant-text family must be "+
					"models.ActionAssistantMessage (WP-T6/B2a)",
					path, fset.Position(lit.Pos()).Line, raw, action)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// litFieldString returns a composite literal's field value when it is a
// plain string literal.
func litFieldString(lit *ast.CompositeLit, field string) (string, bool) {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != field {
			continue
		}
		bl, ok := kv.Value.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return "", false
		}
		return strings.Trim(bl.Value, "`\""), true
	}
	return "", false
}

// litFieldSelector returns a composite literal's field value when it is
// a qualified identifier such as models.ActionAssistantMessage.
func litFieldSelector(lit *ast.CompositeLit, field string) (string, bool) {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != field {
			continue
		}
		sel, ok := kv.Value.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		return pkg.Name + "." + sel.Sel.Name, true
	}
	return "", false
}

// actionConstName is the identifier the AST scan expects to see for the
// assistant-message action type. Spelled from the VALUE so a rename of
// the constant is caught by the compiler, not by a stale string.
func actionConstName(value string) string {
	if value == models.ActionAssistantMessage {
		return "ActionAssistantMessage"
	}
	return value
}

// adapterSources concatenates every non-test adapter source once.
func adapterSources(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	root := filepath.Join(repoRoot, "internal", "adapter")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		sb.Write(body)
		sb.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return sb.String()
}

// TestBuildClausesRejectsAnUnscopedSite proves the generator refuses to
// emit a statement that could reach every tool.
func TestBuildClausesRejectsAnUnscopedSite(t *testing.T) {
	orig := sites
	t.Cleanup(func() { sites = orig })

	sites = []site{{raw: "x.assistant_text", tools: []string{""}, emitSite: "test"}}
	if _, err := buildClauses(); err == nil {
		t.Error("buildClauses accepted an empty tool")
	}
	sites = []site{{raw: "x.assistant_text", emitSite: "test"}}
	if _, err := buildClauses(); err == nil {
		t.Error("buildClauses accepted a site with no tools")
	}
	sites = []site{{raw: "x.reasoning", tools: []string{"t"}, emitSite: "test"}}
	if _, err := buildClauses(); err == nil {
		t.Error("buildClauses accepted a raw name outside the .assistant_text family")
	}
}

// TestBuildClausesRejectsMixedCarveOutsForOneTool pins the grouping
// invariant: a tool's raw names share ONE statement, which is only sound
// if they share the carve-out set — otherwise the carve-out would leak
// onto a raw name that never needed it.
func TestBuildClausesRejectsMixedCarveOutsForOneTool(t *testing.T) {
	orig := sites
	t.Cleanup(func() { sites = orig })

	sites = []site{
		{raw: "a.assistant_text", tools: []string{"t"}, emitSite: "test"},
		{raw: "b.assistant_text", tools: []string{"t"}, keepSourceFiles: []string{"x:hook"}, emitSite: "test"},
	}
	if _, err := buildClauses(); err == nil {
		t.Error("buildClauses grouped raw names with different carve-out sets into one statement")
	}
}

// TestQuoteEscapesSingleQuotes guards the literal renderer.
func TestQuoteEscapesSingleQuotes(t *testing.T) {
	if got, want := quote("it's"), "'it''s'"; got != want {
		t.Errorf("quote = %q, want %q", got, want)
	}
}

// TestCheckSQLSafeRejectsControlCharacters guards the table against junk.
func TestCheckSQLSafeRejectsControlCharacters(t *testing.T) {
	if err := checkSQLSafe("ok.assistant_text"); err != nil {
		t.Errorf("checkSQLSafe rejected a clean name: %v", err)
	}
	if err := checkSQLSafe("bad\nname"); err == nil {
		t.Error("checkSQLSafe accepted a newline")
	}
}

// TestHeaderIsPresentAndSelfDescribing keeps the migration explaining
// itself: the regenerate command, the DO-NOT-EDIT marker, the carve-out
// and the idempotency claim must all survive an edit to the header.
func TestHeaderIsPresentAndSelfDescribing(t *testing.T) {
	body := string(generateOrFail(t))
	for _, want := range []string{
		"GENERATED by internal/db/asstbackfillgen",
		"DO NOT EDIT BY HAND",
		"make assistant-migration-build",
		"make verify-assistant-migration",
		claudeCodeHookSourceFile,
		"IDEMPOTENT BY CONSTRUCTION",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("header lost %q", want)
		}
	}
}

// TestWriteCreatesParentDir lets the drift gate point the generator at a
// scratch directory that does not exist yet.
func TestWriteCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", migrationName)
	if err := genout.WriteFile(path, []byte("-- x\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat: %v", err)
	}
}
