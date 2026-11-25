package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/genout"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// committedDir is where the generated migration lives, relative to this
// package dir. The file NAME comes from the generator itself
// (migrationName), so the gate cannot end up diffing the wrong file.
const committedDir = "../migrations"

func generateOrFail(t *testing.T) []byte {
	t.Helper()
	data, err := generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return data
}

// TestGenerateIsDeterministic is the precondition for the drift gate: if
// generate() were order-unstable (a ranged map, a clock, an environment
// read) the gate would fail at random.
func TestGenerateIsDeterministic(t *testing.T) {
	first := generateOrFail(t)
	for run := 2; run <= 5; run++ {
		next := generateOrFail(t)
		if !bytes.Equal(next, first) {
			t.Fatalf("run %d differs from run 1 (%d vs %d bytes)", run, len(next), len(first))
		}
	}
}

// TestGeneratedMatchesCommitted is the in-test half of the drift gate:
// it fails the Go suite (not just `make verify-taxonomy-migration`) when
// somebody hand-edits the committed migration, or changes tooltax
// without regenerating it.
func TestGeneratedMatchesCommitted(t *testing.T) {
	path := filepath.Join(committedDir, migrationName)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed %s: %v", path, err)
	}
	got := generateOrFail(t)
	if !bytes.Equal(got, want) {
		t.Errorf("%s is stale or hand-edited — run `make taxonomy-migration-build` and commit.\n"+
			"committed %d bytes, regenerated %d bytes", path, len(want), len(got))
	}
}

// TestKnownActionTypesCoverTooltax pins the models mirror in BOTH
// directions. tooltax may not import internal/models, so this package is
// where a new canonical action type must acquire a models.Action*
// constant — the WP-T4 half of the taxonomy contract. A tooltax type
// with no constant would otherwise be emitted into SQL as a bare string
// no Go code can name.
func TestKnownActionTypesCoverTooltax(t *testing.T) {
	for _, at := range tooltax.ActionTypes() {
		if !knownActionTypes[at] {
			t.Errorf("tooltax action type %q has no models.Action* constant in knownActionTypes", at)
		}
	}
	for at := range knownActionTypes {
		if _, ok := tooltax.MetaForActionType(at); !ok {
			t.Errorf("knownActionTypes has %q, which tooltax does not register", at)
		}
	}
}

// TestEveryTaxonomyRowIsCovered proves the emitted SQL is the WHOLE
// table, not a hand-picked subset: every non-unknown tooltax row must be
// reachable by some clause with the row's own action type.
func TestEveryTaxonomyRowIsCovered(t *testing.T) {
	clauses, err := buildClauses()
	if err != nil {
		t.Fatalf("buildClauses: %v", err)
	}
	// covered[tool][native] = action type of the FIRST clause that
	// claims it, mirroring the 'unknown' guard's first-wins semantics.
	covered := map[string]map[string]string{}
	claim := func(tool, native, at string) {
		if covered[tool] == nil {
			covered[tool] = map[string]string{}
		}
		if _, dup := covered[tool][native]; !dup {
			covered[tool][native] = at
		}
	}
	for _, c := range clauses {
		for _, n := range c.literals {
			claim(c.tool, n, c.actionType)
		}
	}

	for _, e := range tooltax.Table() {
		if e.ActionType == tooltax.ActionUnknown {
			continue
		}
		if e.IsGlob() {
			if !hasPrefixClause(clauses, e.Tool, strings.TrimSuffix(e.Native, "*"), e.ActionType) {
				t.Errorf("glob row (%q, %q) -> %q has no prefix clause", e.Tool, e.Native, e.ActionType)
			}
			continue
		}
		// Precedence: the tool's own clause wins; a tool-less row is
		// served by the any-tool clause.
		got, ok := covered[e.Tool][e.Native]
		if !ok {
			t.Errorf("row (%q, %q) -> %q is not covered by any clause", e.Tool, e.Native, e.ActionType)
			continue
		}
		if got != e.ActionType {
			// A duplicate row later in the table legitimately loses to
			// the earlier one; buildClauses errors on a real conflict,
			// so a mismatch here means the emission dropped the winner.
			t.Errorf("row (%q, %q): clause writes %q, table says %q", e.Tool, e.Native, got, e.ActionType)
		}
	}
}

func hasPrefixClause(clauses []clause, tool, prefix, actionType string) bool {
	for _, c := range clauses {
		if c.tool == tool && c.prefix == prefix && c.actionType == actionType {
			return true
		}
	}
	return false
}

// TestNoClauseWritesUnknown proves the migration can never write the
// value it is supposed to be clearing. The three tooltax rows that
// resolve to ActionUnknown on purpose (a native name that was seen and
// deliberately not bucketed) must be skipped, not emitted as no-ops.
func TestNoClauseWritesUnknown(t *testing.T) {
	clauses, err := buildClauses()
	if err != nil {
		t.Fatalf("buildClauses: %v", err)
	}
	for _, c := range clauses {
		if c.actionType == tooltax.ActionUnknown {
			t.Errorf("clause for tool %q writes %q", c.tool, tooltax.ActionUnknown)
		}
	}
}

// TestEveryStatementGuardsOnUnknown is the safety invariant of the whole
// migration: a statement without the guard could re-classify rows an
// adapter already classified (the post_tool_batch shadow rows, cowork's
// semantic remaps), and would not be idempotent.
func TestEveryStatementGuardsOnUnknown(t *testing.T) {
	body := statementBody(t, string(generateOrFail(t)))
	stmts := splitStatements(body)
	if len(stmts) < 100 {
		t.Fatalf("expected the full taxonomy, got %d statements", len(stmts))
	}
	for i, st := range stmts {
		if !strings.Contains(st, "action_type = 'unknown'") {
			t.Errorf("statement %d has no unknown-guard:\n%s", i, st)
		}
		if !strings.HasPrefix(st, "UPDATE actions\n   SET action_type = ") {
			t.Errorf("statement %d is not a plain action_type UPDATE:\n%s", i, st)
		}
		if strings.Contains(st, "DELETE") || strings.Contains(st, "DROP") {
			t.Errorf("statement %d is destructive:\n%s", i, st)
		}
	}
}

// statementBody returns everything from the first UPDATE onwards, i.e.
// the emitted file minus its header comment.
func statementBody(t *testing.T, sql string) string {
	t.Helper()
	i := strings.Index(sql, "UPDATE actions")
	if i < 0 {
		t.Fatal("the generated migration contains no UPDATE statements")
	}
	return sql[i:]
}

// splitStatements chops the emitted body on the statement terminator.
func splitStatements(body string) []string {
	var out []string
	for _, raw := range strings.Split(body, ";\n") {
		s := strings.TrimSpace(raw)
		if strings.HasPrefix(s, "UPDATE") {
			out = append(out, s)
		}
	}
	return out
}

// TestPrefixClausesUseCaseSensitiveMatching pins the substr-equality
// choice. SQLite's LIKE is ASCII case-INSENSITIVE by default, so a LIKE
// prefix would match names tooltax's strings.HasPrefix never would; and
// '_' is a LIKE wildcard, which every MCP prefix is full of. The emitted
// length must equal the prefix length or the comparison silently never
// matches.
func TestPrefixClausesUseCaseSensitiveMatching(t *testing.T) {
	body := statementBody(t, string(generateOrFail(t)))
	if strings.Contains(body, " LIKE ") {
		t.Error("the emitted statements use LIKE, which is case-insensitive in SQLite")
	}
	re := regexp.MustCompile(`substr\(raw_tool_name, 1, (\d+)\) = '([^']*)'`)
	ms := re.FindAllStringSubmatch(body, -1)
	if len(ms) == 0 {
		t.Fatal("no prefix clauses emitted — tooltax has glob rows")
	}
	for _, m := range ms {
		if got, want := m[1], strconv.Itoa(len(m[2])); got != want {
			t.Errorf("prefix %q: substr length %s, want %s", m[2], got, want)
		}
	}
}

// TestMCPPrefixComesFromTooltax proves the mcp_call clause is DERIVED
// from tooltax.MCPPrefix rather than re-declaring "mcp__" — the exact
// drift the taxonomy package exists to remove — and that it is the LAST
// statement, matching the table's glob-sorts-last precedence.
func TestMCPPrefixComesFromTooltax(t *testing.T) {
	sql := string(generateOrFail(t))
	want := "   AND substr(raw_tool_name, 1, " + strconv.Itoa(len(tooltax.MCPPrefix)) + ") = '" + tooltax.MCPPrefix + "';\n"
	if !strings.HasSuffix(sql, want) {
		t.Errorf("the migration does not END with the %q clause; want suffix:\n%s", tooltax.MCPPrefix, want)
	}
	stmts := splitStatements(statementBody(t, sql))
	last := stmts[len(stmts)-1]
	if !strings.Contains(last, "SET action_type = 'mcp_call'") || strings.Contains(last, "WHERE tool =") {
		t.Errorf("the last statement should be the tool-less mcp_call sweep, got:\n%s", last)
	}
}

// TestToolSpecificClausesPrecedeToolLessOnes pins the precedence the
// 'unknown' guard turns into behaviour: a tool-specific mapping must be
// applied before the any-tool fallback that would otherwise claim the
// same name.
func TestToolSpecificClausesPrecedeToolLessOnes(t *testing.T) {
	clauses, err := buildClauses()
	if err != nil {
		t.Fatalf("buildClauses: %v", err)
	}
	seenToolLess := false
	for _, c := range clauses {
		if c.tool == "" {
			seenToolLess = true
			continue
		}
		if seenToolLess {
			t.Fatalf("tool-scoped clause for %q emitted after a tool-less one", c.tool)
		}
	}
	if !seenToolLess {
		t.Fatal("no tool-less clauses emitted — tooltax has fallback rows")
	}
}

// TestToolLiteralsPrecedeToolPrefixes pins the second half of the
// precedence walk: within one tool, a literal name must beat a prefix
// rule (tooltax sorts glob rows after every literal).
func TestToolLiteralsPrecedeToolPrefixes(t *testing.T) {
	clauses, err := buildClauses()
	if err != nil {
		t.Fatalf("buildClauses: %v", err)
	}
	prefixSeenFor := map[string]bool{}
	for _, c := range clauses {
		if c.prefix != "" {
			prefixSeenFor[c.tool] = true
			continue
		}
		if prefixSeenFor[c.tool] {
			t.Errorf("tool %q: literal clause (%s) emitted after its prefix clause", c.tool, c.actionType)
		}
	}
}

// TestClausesAreSorted pins the deterministic output order the drift
// gate depends on: tools ascending, action types ascending within a
// tool, names ascending within a clause.
func TestClausesAreSorted(t *testing.T) {
	clauses, err := buildClauses()
	if err != nil {
		t.Fatalf("buildClauses: %v", err)
	}
	var lastTool, lastType string
	for _, c := range clauses {
		if c.tool != lastTool {
			if c.tool != "" && c.tool < lastTool {
				t.Errorf("tool %q emitted after %q", c.tool, lastTool)
			}
			lastTool, lastType = c.tool, ""
		}
		if c.prefix == "" {
			if c.actionType < lastType {
				t.Errorf("tool %q: action type %q emitted after %q", c.tool, c.actionType, lastType)
			}
			lastType = c.actionType
		}
		for i := 1; i < len(c.literals); i++ {
			if c.literals[i] <= c.literals[i-1] {
				t.Errorf("tool %q/%s: names out of order or duplicated: %q then %q",
					c.tool, c.actionType, c.literals[i-1], c.literals[i])
			}
		}
	}
}

// TestQuoteEscapesSingleQuotes covers the one string-safety rule the
// generator has to get right; no tooltax name contains a quote today,
// which is exactly why the escaping needs its own test.
func TestQuoteEscapesSingleQuotes(t *testing.T) {
	if got, want := quote("it's"), "'it''s'"; got != want {
		t.Errorf("quote(%q) = %s, want %s", "it's", got, want)
	}
	if got, want := quote("plain"), "'plain'"; got != want {
		t.Errorf("quote(%q) = %s, want %s", "plain", got, want)
	}
}

// TestCheckSQLSafeRejectsControlCharacters pins the junk-in-the-table
// guard.
func TestCheckSQLSafeRejectsControlCharacters(t *testing.T) {
	if err := checkSQLSafe("Read"); err != nil {
		t.Errorf("checkSQLSafe(%q) = %v, want nil", "Read", err)
	}
	for _, bad := range []string{"a\nb", "a\tb", "a\x7fb"} {
		if err := checkSQLSafe(bad); err == nil {
			t.Errorf("checkSQLSafe(%q) = nil, want an error", bad)
		}
	}
}

// TestHeaderIsPresentAndSelfDescribing keeps the generated file honest
// about being generated — the first thing a reader (or a future agent
// about to hand-edit it) sees.
func TestHeaderIsPresentAndSelfDescribing(t *testing.T) {
	sql := string(generateOrFail(t))
	for _, want := range []string{
		migrationName,
		"GENERATED by internal/db/taxbackfillgen",
		"DO NOT EDIT BY HAND",
		"make taxonomy-migration-build",
		"make verify-taxonomy-migration",
		"IDEMPOTENT",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("header is missing %q", want)
		}
	}
}

// TestWriteCreatesParentDir covers the scratch-dir path the drift gate
// script uses.
func TestWriteCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", migrationName)
	if err := genout.WriteFile(path, []byte("-- x\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat: %v", err)
	}
}
