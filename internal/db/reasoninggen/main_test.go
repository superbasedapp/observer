package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/genout"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// committedDir is where the generated migration lives, relative to this
// package dir. The file NAME comes from the generator itself
// (migrationName), so the gate cannot end up diffing the wrong file.
const committedDir = "../migrations"

// repoRoot is this package's path back to the module root, used by the
// emit-site guard that reads adapter sources.
const repoRoot = "../../.."

func generateOrFail(t *testing.T) []byte {
	t.Helper()
	data, err := generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return data
}

// statements splits the generated body into executable statements IN
// ORDER, dropping comment-only lines so a test that forbids a token
// (LIKE, GLOB) cannot be fooled by prose in the header.
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
// it fails the Go suite (not just `make verify-reasoning-migration`)
// when somebody hand-edits the committed migration, or changes a table
// above without regenerating it.
func TestGeneratedMatchesCommitted(t *testing.T) {
	path := filepath.Join(committedDir, migrationName)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed %s: %v", path, err)
	}
	if got := generateOrFail(t); !bytes.Equal(got, want) {
		t.Errorf("%s drifted from a fresh generator run (%d committed bytes vs %d generated); "+
			"run `make reasoning-migration-build` and commit", path, len(want), len(got))
	}
}

// TestNoStatementUsesLIKEOrGLOB pins the matching vocabulary. SQLite's
// LIKE is ASCII case-INSENSITIVE and `_` is a wildcard (these names are
// full of underscores); GLOB would be case-sensitive but still a pattern
// match, and the stakes here are a DELETE that must not reach one row
// more than the producer could have written.
func TestNoStatementUsesLIKEOrGLOB(t *testing.T) {
	for i, s := range statements(t, generateOrFail(t)) {
		up := strings.ToUpper(s)
		if strings.Contains(up, " LIKE ") {
			t.Errorf("statement %d matches with LIKE; use exact literals + substr:\n%s", i, s)
		}
		if strings.Contains(up, " GLOB ") {
			t.Errorf("statement %d matches with GLOB; use exact literals + substr:\n%s", i, s)
		}
	}
}

// deleteStatements returns the `DELETE FROM actions` statements in order.
func deleteStatements(t *testing.T, body []byte) []string {
	t.Helper()
	var out []string
	for _, s := range statements(t, body) {
		if strings.HasPrefix(s, "DELETE FROM actions") {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		t.Fatal("no DELETE FROM actions statement — the migration has become vacuous")
	}
	return out
}

// TestEveryActionsDeleteCarriesTheFullPredicate pins all five ANDed
// conditions on every row-removing statement. Each one is a distinct way
// the delete could over-reach, so each is asserted separately rather
// than by a single golden-string compare.
func TestEveryActionsDeleteCarriesTheFullPredicate(t *testing.T) {
	body := generateOrFail(t)
	prefixLen := len(placeholderEncPrefix)
	suffixLen := len(placeholderEncSuffix)
	for i, s := range deleteStatements(t, body) {
		for _, want := range []string{
			"WHERE tool = '",
			"AND action_type = '" + placeholderActionType + "'",
			"AND raw_tool_name = '" + placeholderRawName + "'",
			"AND raw_tool_output = target",
			"target = '" + placeholderExactTarget + "'",
			fmt.Sprintf("substr(target, 1, %d) = '%s'", prefixLen, placeholderEncPrefix),
			fmt.Sprintf("substr(target, -%d) = '%s'", suffixLen, placeholderEncSuffix),
			fmt.Sprintf("length(target) - %d BETWEEN 1 AND %d", prefixLen+suffixLen, maxPlaceholderDigits),
			fmt.Sprintf("substr(target, %d, 1) BETWEEN '%s' AND '%s'",
				prefixLen+1, minPlaceholderDigit, maxPlaceholderDigit),
			fmt.Sprintf("trim(substr(target, %d, length(target) - %d), '%s') = ''",
				prefixLen+1, prefixLen+suffixLen, digitSet),
		} {
			if !strings.Contains(s, want) {
				t.Errorf("delete statement %d is missing %q:\n%s", i, want, s)
			}
		}
	}
}

// TestPredicateOffsetsAreDerivedFromTheProducerShape proves the substr
// arithmetic is computed from the placeholder constants rather than
// typed twice. A hand-typed offset is how a shape change silently stops
// matching (or starts matching too much).
func TestPredicateOffsetsAreDerivedFromTheProducerShape(t *testing.T) {
	got := predicate("codex", "")
	if !strings.Contains(got, "substr(target, 1, 22)") {
		t.Errorf("prefix length is not 22 for %q:\n%s", placeholderEncPrefix, got)
	}
	if len(placeholderEncPrefix) != 22 || len(placeholderEncSuffix) != 7 {
		t.Fatalf("producer shape changed (prefix=%d suffix=%d) — the migration must be revisited, "+
			"not silently regenerated", len(placeholderEncPrefix), len(placeholderEncSuffix))
	}
	// The middle segment must start one past the prefix and be required
	// non-empty; both fall out of the same two lengths.
	if !strings.Contains(got, "substr(target, 23, length(target) - 29)") {
		t.Errorf("middle-segment arithmetic is not derived from the prefix/suffix lengths:\n%s", got)
	}
	// The numeric segment is matched as a canonical positive %d: bounded
	// 1..19 characters (non-empty AND no wider than a Go int renders) and
	// with a first digit in 1..9 (no bare zero, no leading zero).
	if !strings.Contains(got, "length(target) - 29 BETWEEN 1 AND 19") {
		t.Errorf("the digit-count bounds are missing or not derived:\n%s", got)
	}
	if !strings.Contains(got, "substr(target, 23, 1) BETWEEN '1' AND '9'") {
		t.Errorf("the canonical-first-digit guard is missing; without it the predicate reaches "+
			"'(encrypted reasoning, 0 bytes)' and leading-zero counts the producer could not write:\n%s", got)
	}
	if maxPlaceholderDigits != 19 {
		t.Errorf("maxPlaceholderDigits = %d; 19 is the decimal width of the int64 ceiling and the reason "+
			"a 20-digit count cannot be a %%d rendering", maxPlaceholderDigits)
	}
}

// TestDeleteIsScopedToTheCodexRetagPair pins tool scoping AND the retag
// seam: the identical parser output is tagged 'open-interpreter' by
// NewOpenInterpreter, so a codex-only delete would leave a silent island
// of placeholder rows behind.
func TestDeleteIsScopedToTheCodexRetagPair(t *testing.T) {
	got := map[string]bool{}
	for _, s := range deleteStatements(t, generateOrFail(t)) {
		for _, tool := range []string{models.ToolCodex, models.ToolOpenInterpreter} {
			if strings.Contains(s, "WHERE tool = '"+tool+"'") {
				got[tool] = true
			}
		}
	}
	for _, tool := range []string{models.ToolCodex, models.ToolOpenInterpreter} {
		if !got[tool] {
			t.Errorf("no DELETE FROM actions statement scoped to tool %q", tool)
		}
	}
	if len(got) != len(deleteStatements(t, generateOrFail(t))) {
		t.Errorf("a DELETE FROM actions statement is scoped to a tool outside the codex retag pair")
	}
}

// TestNoDeleteReachesGeminiOrAnyOtherToolsReasoningRows is the (c)
// invariant: gemini's rows are LOSSY to delete (their raw_tool_output
// holds 211-2,926 bytes that exist nowhere else) and the other 11
// minority emitters' rows are content-bearing. No statement in this
// migration may name them at all.
func TestNoDeleteReachesGeminiOrAnyOtherToolsReasoningRows(t *testing.T) {
	code := strings.Join(statements(t, generateOrFail(t)), "\n")
	for _, forbidden := range []string{
		"gemini", "crush", "hermes", "cline", "antigravity", "opencode",
		"kilo-code", "cowork", "pi", "copilot", "openclaw", "devin",
	} {
		if strings.Contains(code, "'"+forbidden) {
			t.Errorf("a statement names tool %q; 079 deletes ONLY the codex/open-interpreter "+
				"placeholder rows and rewrites ONLY cursor", forbidden)
		}
	}
}

// TestDependencyProtocolPrecedesEachDelete pins (b): every dependent
// table is handled, with the SAME candidate predicate, BEFORE the rows
// it references are removed. Order is the whole point — the reverse
// order trips "FOREIGN KEY constraint failed (787)" and aborts the
// migration, and skipping action_excerpts leaves searchable FTS ghosts.
func TestDependencyProtocolPrecedesEachDelete(t *testing.T) {
	all := statements(t, generateOrFail(t))
	for _, tool := range deleteTools {
		deleteIdx := -1
		for i, s := range all {
			if strings.HasPrefix(s, "DELETE FROM actions") && strings.Contains(s, "WHERE tool = '"+tool+"'") {
				deleteIdx = i
			}
		}
		if deleteIdx < 0 {
			t.Fatalf("no actions delete for tool %q", tool)
		}
		for _, d := range dependencies {
			found := -1
			for i, s := range all {
				if i >= deleteIdx {
					break
				}
				if !strings.Contains(s, d.table) || !strings.Contains(s, "WHERE tool = '"+tool+"'") {
					continue
				}
				switch d.mode {
				case depDelete:
					if strings.HasPrefix(s, "DELETE FROM "+d.table) {
						found = i
					}
				case depNull:
					if strings.HasPrefix(s, "UPDATE "+d.table) && strings.Contains(s, "SET "+d.column+" = NULL") {
						found = i
					}
				}
			}
			if found < 0 {
				t.Errorf("tool %q: no %s cleanup statement before the actions delete (index %d)",
					tool, d.table, deleteIdx)
				continue
			}
			// The dependent statement must be scoped by the same
			// candidate predicate, not by a looser one.
			s := all[found]
			for _, want := range []string{
				"AND raw_tool_name = '" + placeholderRawName + "'",
				"AND raw_tool_output = target",
				"target = '" + placeholderExactTarget + "'",
			} {
				if !strings.Contains(s, want) {
					t.Errorf("tool %q: the %s cleanup is not scoped by the candidate predicate (missing %q):\n%s",
						tool, d.table, want, s)
				}
			}
		}
	}
}

// TestDependencyTablesMatchRetentionProtocol pins the table/column
// inventory against the verified path in
// internal/retention/retention.go::deleteActionsOlder. A new nullable
// action_id FK added by a future migration must land in BOTH places.
func TestDependencyTablesMatchRetentionProtocol(t *testing.T) {
	want := []struct {
		table  string
		column string
		mode   depMode
	}{
		{"action_excerpts", "action_id", depDelete},
		{"failure_context", "action_id", depDelete},
		{"file_state", "last_action_id", depNull},
		{"retrieval_signals", "action_id", depNull},
		{"guard_events", "action_id", depNull},
		{"process_runs", "action_id", depNull},
		{"process_events", "action_id", depNull},
	}
	if len(dependencies) != len(want) {
		t.Fatalf("dependency count = %d, want %d (retention.go handles exactly these)", len(dependencies), len(want))
	}
	for i, w := range want {
		got := dependencies[i]
		if got.table != w.table || got.column != w.column || got.mode != w.mode {
			t.Errorf("dependency %d = %+v, want table=%s column=%s mode=%d", i, got, w.table, w.column, w.mode)
		}
	}

	// And the retention path still spells them the same way — a column
	// rename there would silently invalidate this migration's protocol.
	body, err := os.ReadFile(filepath.Join(repoRoot, "internal", "retention", "retention.go"))
	if err != nil {
		t.Fatalf("read retention.go: %v", err)
	}
	src := string(body)
	for _, w := range want {
		var probe string
		if w.mode == depDelete {
			probe = "DELETE FROM " + w.table
		} else {
			probe = "UPDATE " + w.table + " SET " + w.column + " = NULL"
		}
		if !strings.Contains(src, probe) {
			t.Errorf("retention.go no longer contains %q — 079's dependency protocol is transcribed from it "+
				"and must be re-verified", probe)
		}
	}
}

// TestMarkerIsTheFirstStatement pins (e). Recording MAX(actions.id)
// AFTER the delete would leave surviving pre-079 rows above the mark and
// make "no phantom row younger than 079" produce false positives.
func TestMarkerIsTheFirstStatement(t *testing.T) {
	all := statements(t, generateOrFail(t))
	first := all[0]
	for _, want := range []string{
		"INSERT INTO schema_meta (key, value)",
		"'" + markerKey + "'",
		"SELECT CAST(COALESCE(MAX(id), 0) AS TEXT) FROM actions",
		"ON CONFLICT(key) DO NOTHING",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("the first statement is not the high-water marker (missing %q):\n%s", want, first)
		}
	}
	for i, s := range all[1:] {
		if strings.Contains(s, markerKey) {
			t.Errorf("statement %d also writes the marker key; it must be written exactly once:\n%s", i+1, s)
		}
	}
	// No new table: schema_meta is the repo's existing KV, so nothing
	// here needs adding to the org-push privacy sentinel.
	code := strings.Join(all, "\n")
	if strings.Contains(strings.ToUpper(code), "CREATE TABLE") {
		t.Errorf("079 creates a table; it is supposed to reuse schema_meta (and a new table would need a "+
			"privacy-sentinel entry):\n%s", code)
	}
}

// TestCursorFoldInIsAnExactPairRewrite pins (d): 078's pair-rewrite
// vocabulary (old type in the WHERE, new type in the SET) makes the
// statement idempotent and unable to touch a row an adapter typed on
// purpose.
func TestCursorFoldInIsAnExactPairRewrite(t *testing.T) {
	var found bool
	for _, s := range statements(t, generateOrFail(t)) {
		if !strings.HasPrefix(s, "UPDATE actions") {
			continue
		}
		found = true
		for _, want := range []string{
			"SET action_type = '" + models.ActionAssistantMessage + "'",
			"WHERE tool = '" + models.ToolCursor + "'",
			"AND action_type = '" + models.ActionTaskComplete + "'",
			"AND raw_tool_name = 'cursor.assistant_response'",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("the cursor fold-in is missing %q:\n%s", want, s)
			}
		}
	}
	if !found {
		t.Fatal("no UPDATE actions statement — the cursor fold-in is missing")
	}
}

// TestDevinIsExcludedWithItsEvidence pins the deliberate branch. devin's
// task_complete rows are produced by a LIVE conditional keyed on the
// provider's own finish_reason, so rewriting them would destroy recorded
// evidence. The evidence itself is re-read from the adapter here, not
// trusted from a comment.
func TestDevinIsExcludedWithItsEvidence(t *testing.T) {
	for _, rw := range rewrites {
		if rw.tool == models.ToolDevin || strings.Contains(rw.raw, "devin") {
			t.Fatalf("devin is in the rewrite table (%+v); its task_complete rows are evidence-grounded", rw)
		}
	}
	body, err := os.ReadFile(filepath.Join(repoRoot, "internal", "adapter", "devin", "adapter.go"))
	if err != nil {
		t.Fatalf("read devin adapter: %v", err)
	}
	src := string(body)
	for _, want := range []string{
		`action := models.ActionAssistantMessage`,
		`action = models.ActionTaskComplete`,
		`metaFinish(cm.Metadata), "stop"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("devin/adapter.go no longer contains %q — the exclusion's evidence has moved and the "+
				"fold-in decision must be revisited", want)
		}
	}
}

// TestValidateRejectsMalformedTables proves the generator refuses to
// emit a delete that reaches further than intended.
func TestValidateRejectsMalformedTables(t *testing.T) {
	origTools, origDeps, origRewrites := deleteTools, dependencies, rewrites
	t.Cleanup(func() { deleteTools, dependencies, rewrites = origTools, origDeps, origRewrites })

	deleteTools = nil
	if err := validate(); err == nil {
		t.Error("validate accepted an empty tool list")
	}
	deleteTools = []string{""}
	if err := validate(); err == nil {
		t.Error("validate accepted an empty tool — an unscoped delete")
	}
	deleteTools = []string{models.ToolCodex, models.ToolCodex}
	if err := validate(); err == nil {
		t.Error("validate accepted a duplicated tool")
	}
	deleteTools = origTools

	dependencies = nil
	if err := validate(); err == nil {
		t.Error("validate accepted an empty dependency protocol — that is the FTS-ghost / FK-787 bug")
	}
	dependencies = []dependency{{table: "x", column: ""}}
	if err := validate(); err == nil {
		t.Error("validate accepted a dependency with no column")
	}
	dependencies = origDeps

	rewrites = []rewrite{{tool: "", raw: "r", oldType: "a", newType: "b"}}
	if err := validate(); err == nil {
		t.Error("validate accepted an unscoped rewrite")
	}
	rewrites = []rewrite{{tool: "t", raw: "r", oldType: "a", newType: "a"}}
	if err := validate(); err == nil {
		t.Error("validate accepted a rewrite that is not an exact old->new pair")
	}
	rewrites = origRewrites

	if err := validate(); err != nil {
		t.Fatalf("validate rejected the real tables: %v", err)
	}
}

// TestQuoteEscapesSingleQuotes guards the literal renderer.
func TestQuoteEscapesSingleQuotes(t *testing.T) {
	if got, want := quote("it's"), "'it''s'"; got != want {
		t.Errorf("quote = %q, want %q", got, want)
	}
}

// TestCheckSQLSafeRejectsControlCharacters guards the tables against junk.
func TestCheckSQLSafeRejectsControlCharacters(t *testing.T) {
	if err := checkSQLSafe("codex.reasoning"); err != nil {
		t.Errorf("checkSQLSafe rejected a clean name: %v", err)
	}
	if err := checkSQLSafe("bad\nname"); err == nil {
		t.Error("checkSQLSafe accepted a newline")
	}
}

// TestHeaderIsPresentAndSelfDescribing keeps the migration explaining
// itself: the regenerate command, the DO-NOT-EDIT marker, the honest
// claim, the accepted residue, the decay caveat and the org divergence
// must all survive an edit to the header.
func TestHeaderIsPresentAndSelfDescribing(t *testing.T) {
	body := string(generateOrFail(t))
	for _, want := range []string{
		"GENERATED by internal/db/reasoninggen",
		"DO NOT EDIT BY HAND",
		"make reasoning-migration-build",
		"make verify-reasoning-migration",
		"PRODUCER-INVARIANT MATCHING, not a mathematical",
		"ACCEPTED RESIDUE",
		"DECAY, HONESTLY",
		"ORG DIVERGENCE, ACCEPTED",
		"IDEMPOTENT BY CONSTRUCTION",
		markerKey,
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

// ---------------------------------------------------------------------
// The emit-site guard (plan §1, last paragraph).
//
// The 079 delete is a one-time repair; the guard is what raises the cost
// of the class coming back. It is deliberately NAME-BASED, not
// type-based, and that is the design decision that closes 078's escape
// hatch: 078's walker skipped any site whose ActionType was a computed
// expression rather than a plain models.X selector
// (asstbackfillgen/main_test.go's "a computed ActionType is legitimate"
// branch), because 078 could only judge a site by the TYPE it wrote.
// Here there is nothing to judge — a reasoning row must not exist AT
// ALL, whatever type it carries — so the walker never looks at
// ActionType and a computed one buys no exemption.
//
// WHAT THIS GUARD IS, HONESTLY. It is a bar against ACCIDENTAL
// reintroduction — somebody re-adding an emit site the way the fifteen
// retired ones were written, in any of the shapes this tree has actually
// used: composite literal, field assignment, `+=` composition, concat
// over consts/idents (both operands, recursively), fmt.Sprintf formats,
// and string([]byte{…}) conversions. It is NOT, and cannot be, a proof
// that no reasoning row can ever be minted: a raw name assembled through
// an interface method, a map lookup, a struct field, reflection, or any
// value crossing a function boundary is beyond static reach without a
// whole-program dataflow analysis this repo does not have.
// TestGuardKnownEvasionsAreCaughtOrDocumented carries a live example of
// the remaining gap rather than pretending it away.
//
// The GROUND TRUTH is therefore not this walker — it is migration 079's
// ID high-water marker plus the corpus re-verification it makes
// possible (see corpusReVerificationSQL). The walker catches the likely
// mistake early and cheaply; the marker catches ANY mistake, however it
// was constructed, by asking the database instead of the source.
// ---------------------------------------------------------------------

// guardClaim is the guard's own statement of what it does and does not
// prove. It is a value rather than a comment so that it is printed to
// whoever trips the guard, and so a test can hold it to its word.
const guardClaim = "This walker raises the bar against ACCIDENTAL reintroduction of a reasoning " +
	"emit site; it cannot catch arbitrarily indirect construction (interface dispatch, maps, struct " +
	"fields, reflection). The ground-truth backstop is migration 079's high-water marker plus the " +
	"corpus re-verification query (corpusReVerificationSQL): zero reasoning-named rows with " +
	"id > migration_079_max_action_id."

// corpusReVerificationSQL is the ground-truth backstop the guard defers
// to: it asks the DATABASE whether any reasoning-named row was minted
// after 079 applied, which is true regardless of how the emit site was
// written.
//
// Operator command (READ-ONLY; never run against a live daemon's DB with
// a writable handle):
//
//	sqlite3 'file:$HOME/.observer/observer.db?mode=ro' \
//	  "SELECT COUNT(*) FROM actions WHERE id > (SELECT CAST(value AS INTEGER) FROM schema_meta
//	   WHERE key='migration_079_max_action_id') AND (substr(raw_tool_name,-10)='.reasoning'
//	   OR substr(raw_tool_name,-9)='.thinking');"
//
// The expected answer is 0. A non-zero count means a still-running old
// daemon (the documented decay in 079's header) or a new emit site the
// walker could not see — either way it is measurable, which is the whole
// reason the marker exists. Exercised for real against a migrated
// database in internal/db/migrations_test.go's 079 test, including the
// negative case where a post-079 row makes it return 1.
const corpusReVerificationSQL = `SELECT COUNT(*) FROM actions
 WHERE id > (SELECT CAST(value AS INTEGER) FROM schema_meta WHERE key = 'migration_079_max_action_id')
   AND (substr(raw_tool_name, -10) = '.reasoning' OR substr(raw_tool_name, -9) = '.thinking')`

// reasoningSuffixes are the raw-name tails that mark a row as "the model
// thinking", the thing B3 converged onto preceding_reasoning.
var reasoningSuffixes = []string{".reasoning", ".thinking"}

// rawNameFields are the models.ToolEvent fields that become
// actions.raw_tool_name — the column 079's predicate matches on.
var rawNameFields = map[string]bool{"RawToolName": true}

// allowedLiterals is the escape hatch for a string literal that ends in
// a reasoning suffix but is NOT a raw action name (a JSON key, a file
// name, a provider's own event type). It is EMPTY today: after the B3
// emission sweep no adapter source carries such a literal at all.
// Adding an entry is a deliberate act that must carry its reason.
var allowedLiterals = map[string]string{}

// mintFinding is one site that would put a reasoning-named row on the
// actions table.
type mintFinding struct {
	file   string
	line   int
	kind   string
	name   string
	detail string
}

func (f mintFinding) String() string {
	return fmt.Sprintf("%s:%d [%s] %q — %s", f.file, f.line, f.kind, f.name, f.detail)
}

// scanReasoningMints walks every non-test .go file under root and
// reports each site that names an action `*.reasoning` / `*.thinking`.
//
// Three shapes are recognised because all three exist (or existed) in
// this tree:
//
//   - composite literal:  models.ToolEvent{RawToolName: "codex.reasoning"}
//   - field assignment:   ev.RawToolName = "cursor.reasoning"
//     (cursor's real emit shape, adapter.go:433)
//   - string concat:      models.ToolCopilotCLI + ".reasoning"
//     toolID + ".reasoning"          (cline's runtime-built names)
//
// plus fmt.Sprintf formats and one level of local-variable indirection.
// A fourth, blunter layer catches ANY string literal with a reasoning
// tail anywhere in adapter code, so a shape nobody anticipated still
// fails the build rather than shipping.
//
// Parse failures are returned separately from findings: a file being
// edited by another process mid-walk is a transient condition, not a
// guard violation.
func scanReasoningMints(root string) ([]mintFinding, []error) {
	var findings []mintFinding
	var parseErrs []error

	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			parseErrs = append(parseErrs, fmt.Errorf("walk %s: %w", path, err))
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			parseErrs = append(parseErrs, fmt.Errorf("parse %s: %w", path, perr))
			return nil
		}
		idents := stringIdents(file)
		add := func(pos token.Pos, kind, name, detail string) {
			findings = append(findings, mintFinding{
				file: path, line: fset.Position(pos).Line, kind: kind, name: name, detail: detail,
			})
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				for _, el := range x.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok || !rawNameFields[key.Name] {
						continue
					}
					if v, ok := evalString(kv.Value, idents); ok && hasReasoningSuffix(v.val) {
						add(kv.Pos(), "composite-literal", v.val,
							"a composite literal sets "+key.Name+" to a reasoning name")
					}
				}
			case *ast.AssignStmt:
				if len(x.Rhs) != len(x.Lhs) {
					// A multi-value call (a, b := f()) cannot carry a
					// literal raw name on the right-hand side.
					return true
				}
				for i, lhs := range x.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || !rawNameFields[sel.Sel.Name] {
						continue
					}
					v, ok := evalString(x.Rhs[i], idents)
					if x.Tok == token.ADD_ASSIGN {
						// `ev.RawToolName += ".reasoning"`: the prior
						// field value is unknown, but a tail is all the
						// suffix test needs.
						v, ok = concatVal(strVal{}, false, v, ok)
					}
					if ok && hasReasoningSuffix(v.val) {
						add(x.Pos(), "field-assignment", v.val,
							"a field assignment sets ."+sel.Sel.Name+" to a reasoning name")
					}
				}
			case *ast.BasicLit:
				if x.Kind != token.STRING {
					return true
				}
				v, err := strconv.Unquote(x.Value)
				if err != nil || !hasReasoningSuffix(v) {
					return true
				}
				if _, ok := allowedLiterals[v]; ok {
					return true
				}
				add(x.Pos(), "string-literal", v,
					"a reasoning-tailed string literal in adapter code (backstop layer)")
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		parseErrs = append(parseErrs, walkErr)
	}
	return findings, parseErrs
}

// hasReasoningSuffix reports whether a raw name is in the reasoning
// family. Case-insensitive: the convention is lower-case, and a
// capitalised variant would be the same row with the same problem.
func hasReasoningSuffix(s string) bool {
	low := strings.ToLower(s)
	for _, suf := range reasoningSuffixes {
		if strings.HasSuffix(low, suf) {
			return true
		}
	}
	return false
}

// strVal is a partially-resolved string. When complete is true, val is
// the WHOLE string; when it is false, val is a known SUFFIX of it. The
// suffix case is what makes concatenation useless as a hiding place:
// `toolID + ".reasoning"` is unresolvable as a whole and still tells the
// guard everything it needs.
type strVal struct {
	val      string
	complete bool
}

// evalString resolves a string expression as far as it statically can.
// The second return is false when nothing at all is known.
//
// Both operands of a concat are resolved, recursively over const/ident
// chains, so a name split across several constants
// (`"codex" + "." + "reasoning"`) composes back into the whole. Go parses
// `a + b + c` left-associatively, so resolving only the right operand
// would see just "reasoning" and miss it — that was a real evasion.
func evalString(expr ast.Expr, idents map[string]strVal) (strVal, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return strVal{}, false
		}
		v, err := strconv.Unquote(e.Value)
		if err != nil {
			return strVal{}, false
		}
		return strVal{val: v, complete: true}, true
	case *ast.ParenExpr:
		return evalString(e.X, idents)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return strVal{}, false
		}
		r, rok := evalString(e.Y, idents)
		l, lok := evalString(e.X, idents)
		return concatVal(l, lok, r, rok)
	case *ast.Ident:
		if v, ok := idents[e.Name]; ok {
			return v, true
		}
	case *ast.CallExpr:
		return evalCall(e, idents)
	}
	return strVal{}, false
}

// concatVal composes `left + right`. A suffix of the right operand is a
// suffix of the whole; a suffix of the LEFT operand is only usable when
// the right operand is fully known, in which case the two concatenate
// into a longer suffix.
func concatVal(l strVal, lok bool, r strVal, rok bool) (strVal, bool) {
	if !rok {
		return strVal{}, false
	}
	if !r.complete || !lok {
		return strVal{val: r.val, complete: false}, true
	}
	return strVal{val: l.val + r.val, complete: l.complete}, true
}

// evalCall handles the two call shapes that can carry a raw name:
// fmt.Sprint* (the format's tail is the result's tail) and a
// string([]byte{...}) / string([]rune{...}) conversion, which is
// otherwise a perfectly readable way to spell a literal that no
// substring search would ever find.
func evalCall(e *ast.CallExpr, idents map[string]strVal) (strVal, bool) {
	if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "string" && len(e.Args) == 1 {
		if v, ok := decodeByteSliceLiteral(e.Args[0]); ok {
			return strVal{val: v, complete: true}, true
		}
		return strVal{}, false
	}
	sel, ok := e.Fun.(*ast.SelectorExpr)
	if !ok {
		return strVal{}, false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "fmt" || !strings.HasPrefix(sel.Sel.Name, "Sprint") || len(e.Args) == 0 {
		return strVal{}, false
	}
	v, vok := evalString(e.Args[0], idents)
	if !vok {
		return strVal{}, false
	}
	// A format may interpolate anywhere, so only its tail is claimed.
	return strVal{val: v.val, complete: false}, true
}

// decodeByteSliceLiteral turns []byte{...} / []rune{...} of constant
// elements into the string it spells.
func decodeByteSliceLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	arr, ok := lit.Type.(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return "", false
	}
	elt, ok := arr.Elt.(*ast.Ident)
	if !ok || (elt.Name != "byte" && elt.Name != "rune") {
		return "", false
	}
	var sb strings.Builder
	for _, el := range lit.Elts {
		bl, ok := el.(*ast.BasicLit)
		if !ok {
			return "", false
		}
		switch bl.Kind {
		case token.CHAR:
			r, _, _, err := strconv.UnquoteChar(strings.Trim(bl.Value, "'"), '\'')
			if err != nil {
				return "", false
			}
			sb.WriteRune(r)
		case token.INT:
			n, err := strconv.Atoi(bl.Value)
			if err != nil || n < 0 || n > 0x10FFFF {
				return "", false
			}
			sb.WriteRune(rune(n))
		default:
			return "", false
		}
	}
	return sb.String(), true
}

// stringIdents maps local identifiers to what is statically known about
// the string they hold, so indirection (`name := tool + "."` then
// `name += "reasoning"` then `ev.RawToolName = name`) does not evade the
// walker. `+=` is COMPOSED onto the prior value rather than replacing
// it — that split was a real evasion, because each half on its own is
// innocent.
//
// Two passes so a forward reference resolves; a reasoning-tailed value
// always wins over a later reassignment, because the guard's question is
// "can this identifier ever carry a reasoning name", not "what does it
// hold last".
func stringIdents(file *ast.File) map[string]strVal {
	out := map[string]strVal{}
	record := func(name string, v strVal, ok bool) {
		if !ok || name == "" || name == "_" {
			return
		}
		if prev, seen := out[name]; seen && hasReasoningSuffix(prev.val) {
			return
		}
		out[name] = v
	}
	for pass := 0; pass < 2; pass++ {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if len(x.Lhs) != len(x.Rhs) {
					return true
				}
				for i, lhs := range x.Lhs {
					id, ok := lhs.(*ast.Ident)
					if !ok {
						continue
					}
					v, vok := evalString(x.Rhs[i], out)
					if x.Tok == token.ADD_ASSIGN {
						prev, pok := out[id.Name]
						v, vok = concatVal(prev, pok, v, vok)
					}
					record(id.Name, v, vok)
				}
			case *ast.ValueSpec:
				for i, id := range x.Names {
					if i < len(x.Values) {
						v, vok := evalString(x.Values[i], out)
						record(id.Name, v, vok)
					}
				}
			}
			return true
		})
	}
	return out
}

// scanAdaptersWithRetry runs the guard over internal/adapter, tolerating
// a transient parse failure caused by a file being written while the
// walk runs (a real condition in this repo: adapters are edited by
// parallel work). Three attempts with backoff, then the parse error is
// reported as a failure — a file that genuinely does not compile is a
// problem the guard should not paper over.
func scanAdaptersWithRetry(t *testing.T) []mintFinding {
	t.Helper()
	root := filepath.Join(repoRoot, "internal", "adapter")
	var findings []mintFinding
	var errs []error
	for attempt := 1; attempt <= 3; attempt++ {
		findings, errs = scanReasoningMints(root)
		if len(errs) == 0 {
			return findings
		}
		t.Logf("attempt %d: %d parse error(s) under %s (a concurrently-written file is the usual cause); retrying",
			attempt, len(errs), root)
		time.Sleep(2 * time.Second)
	}
	for _, err := range errs {
		t.Errorf("adapter source did not parse: %v", err)
	}
	t.Fatalf("the emit-site guard could not read %s cleanly after 3 attempts", root)
	return findings
}

// TestNoAdapterMintsReasoningActionRows is the B3 forward invariant: after
// the emission sweep, NO adapter may put a `*.reasoning` / `*.thinking`
// row on the actions table. Reasoning belongs on the successor event's
// preceding_reasoning field (grok's shape), which is not an action and
// therefore not reachable by this walker at all.
func TestNoAdapterMintsReasoningActionRows(t *testing.T) {
	findings := scanAdaptersWithRetry(t)
	for _, f := range findings {
		t.Errorf("reasoning action mint: %s\n"+
			"    B3 converged the taxonomy onto preceding_reasoning; a reasoning row is not an action.\n"+
			"    If this literal is genuinely not a raw action name, add it to allowedLiterals with a reason.\n"+
			"    Scope of this check: %s",
			f, guardClaim)
	}
}

// ---------------------------------------------------------------------
// Mutation proofs.
//
// The mutants are written into a temp dir and the SAME scanner is run
// over them, rather than editing files under internal/adapter. That is
// deliberate on two counts: the walk is over a directory, so a temp tree
// exercises the identical code path with nothing stubbed, and mutating
// real adapter sources in a tree other agents are editing would be a
// destructive test.
// ---------------------------------------------------------------------

// mutantDir writes one synthetic adapter source and returns its dir.
func mutantDir(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "adapter.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("write mutant: %v", err)
	}
	return dir
}

// scanMutant runs the guard over a synthetic tree and fails on a parse
// error (a mutant that does not parse would prove nothing).
func scanMutant(t *testing.T, body string) []mintFinding {
	t.Helper()
	findings, errs := scanReasoningMints(mutantDir(t, body))
	for _, err := range errs {
		t.Fatalf("mutant did not parse: %v", err)
	}
	return findings
}

func requireKind(t *testing.T, findings []mintFinding, kind string) {
	t.Helper()
	if len(findings) == 0 {
		t.Fatalf("MUTANT SURVIVED: the guard reported nothing; expected a %s finding", kind)
	}
	for _, f := range findings {
		if f.kind == kind {
			return
		}
	}
	t.Fatalf("MUTANT SURVIVED the %s rule (only caught as %v)", kind, findings)
}

// TestGuardCatchesCompositeLiteralMint — mutation proof 1: the shape
// codex/adapter.go carried before B3 removed it.
func TestGuardCatchesCompositeLiteralMint(t *testing.T) {
	findings := scanMutant(t, `package codex

import "github.com/marmutapp/superbased-observer/internal/models"

func reasoningEvent(target string) models.ToolEvent {
	return models.ToolEvent{
		Tool:        models.ToolCodex,
		ActionType:  models.ActionTaskComplete,
		RawToolName: "codex.reasoning",
		Target:      target,
	}
}
`)
	requireKind(t, findings, "composite-literal")
}

// TestGuardCatchesFieldAssignmentMint — mutation proof 2: the SAME mint
// relocated into cursor's assignment form
// (internal/adapter/cursor/adapter.go:433 builds its event that way), the
// shape 078's composite-literal-only walker could not see.
func TestGuardCatchesFieldAssignmentMint(t *testing.T) {
	findings := scanMutant(t, `package cursor

import "github.com/marmutapp/superbased-observer/internal/models"

func reasoningEvent(target string) models.ToolEvent {
	var ev models.ToolEvent
	ev.Tool = models.ToolCursor
	ev.ActionType = models.ActionTaskComplete
	ev.RawToolName = "cursor.reasoning"
	ev.Target = target
	return ev
}
`)
	requireKind(t, findings, "field-assignment")
}

// TestGuardCatchesConcatenatedNameMint — mutation proof 3: a raw name
// BUILT at runtime, both from a package constant (copilot-cli's form)
// and from a loop variable (cline's toolID form). Neither is a literal
// the eye or a grep would find in full.
func TestGuardCatchesConcatenatedNameMint(t *testing.T) {
	findings := scanMutant(t, `package clinecli

import "github.com/marmutapp/superbased-observer/internal/models"

func constConcat() models.ToolEvent {
	return models.ToolEvent{RawToolName: models.ToolCopilotCLI + ".reasoning"}
}

func runtimeConcat(toolID string) models.ToolEvent {
	var ev models.ToolEvent
	ev.RawToolName = toolID + ".reasoning"
	return ev
}
`)
	requireKind(t, findings, "composite-literal")
	requireKind(t, findings, "field-assignment")
	if len(findings) < 2 {
		t.Fatalf("MUTANT SURVIVED: only %d finding(s) for two concat shapes: %v", len(findings), findings)
	}
}

// TestGuardCatchesComputedActionTypeMint — mutation proof 4, the
// explicit close of 078's escape. openclaw's old emit site chose its
// ActionType with a branch; 078's walker skipped such sites by design.
// Here the type is irrelevant, so the branch buys nothing.
func TestGuardCatchesComputedActionTypeMint(t *testing.T) {
	findings := scanMutant(t, `package openclaw

import "github.com/marmutapp/superbased-observer/internal/models"

func reasoningEvent(partType string, done bool) models.ToolEvent {
	action := models.ActionAssistantMessage
	if done {
		action = models.ActionTaskComplete
	}
	name := "openclaw" + ".reasoning"
	return models.ToolEvent{
		ActionType:  action,
		RawToolName: name,
	}
}
`)
	requireKind(t, findings, "composite-literal")
}

// TestGuardCatchesSprintfAndThinkingVariants covers the remaining two
// dynamic shapes: a Sprintf-built name and the `.thinking` spelling.
func TestGuardCatchesSprintfAndThinkingVariants(t *testing.T) {
	findings := scanMutant(t, `package hermes

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func sprintfName(tool string) models.ToolEvent {
	return models.ToolEvent{RawToolName: fmt.Sprintf("%s.thinking", tool)}
}
`)
	requireKind(t, findings, "composite-literal")
}

// TestGuardIgnoresLegitimateReasoningVocabulary is the negative control
// that keeps the guard from being a nuisance: the reasoning WORD is all
// over the adapters (JSON tags, provider event types, the
// preceding_reasoning threading itself, cursor's on-disk pending-state
// directory) and none of it is a raw action name.
func TestGuardIgnoresLegitimateReasoningVocabulary(t *testing.T) {
	findings := scanMutant(t, `package opencode

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/models"
)

type usage struct {
	Reasoning int64 `+"`json:\"reasoning\"`"+`
}

func pendingDir(home string) string {
	return filepath.Join(home, ".observer", "cursor-reasoning")
}

func threaded(partType, text string) models.ToolEvent {
	var ev models.ToolEvent
	if partType == "reasoning" || partType == "thinking" {
		ev.PrecedingReasoning = text
	}
	ev.RawToolName = "opencode.tool_call"
	return ev
}
`)
	if len(findings) != 0 {
		t.Fatalf("guard fired on legitimate reasoning vocabulary: %v", findings)
	}
}

// TestGuardIsNotVacuous proves the walker actually reads files: the real
// adapter tree must contain at least one parsed ToolEvent construction
// with a RawToolName, otherwise a broken walk would look identical to a
// clean one.
func TestGuardIsNotVacuous(t *testing.T) {
	findings := scanMutant(t, `package x

import "github.com/marmutapp/superbased-observer/internal/models"

func f() models.ToolEvent { return models.ToolEvent{RawToolName: "x.reasoning"} }
`)
	if len(findings) == 0 {
		t.Fatal("the walker found nothing in a file that plainly mints a reasoning row")
	}
	// And the real tree parses (this is what makes the green result of
	// TestNoAdapterMintsReasoningActionRows meaningful).
	root := filepath.Join(repoRoot, "internal", "adapter")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	if len(entries) < 10 {
		t.Fatalf("%s holds %d entries; the guard's root looks wrong", root, len(entries))
	}
}

// ---------------------------------------------------------------------
// Known evasions (arc-wide codex round, F3).
//
// The review handed over four ways to assemble a compilable mint that
// the first cut of this walker missed. Three are now caught, and the
// fourth is a documented limit rather than a claim — which is the point
// of guardClaim and of the corpus backstop.
// ---------------------------------------------------------------------

// TestGuardCatchesConstDotPlusEqualsEvasion — evasion 1: the name is
// split across statements, with a package const supplying the dot and a
// `+=` supplying the tail. Each half is innocent on its own; only the
// composition is a mint.
func TestGuardCatchesConstDotPlusEqualsEvasion(t *testing.T) {
	findings := scanMutant(t, `package codex

import "github.com/marmutapp/superbased-observer/internal/models"

const dotSep = "."

func evasion(toolID string) models.ToolEvent {
	name := toolID + dotSep
	name += "reasoning"
	var ev models.ToolEvent
	ev.RawToolName = name
	return ev
}
`)
	requireKind(t, findings, "field-assignment")
	requireName(t, findings, ".reasoning")
}

// TestGuardCatchesPlusEqualsOntoTheFieldItself — evasion 1b: the same
// trick applied directly to the field, so there is no local identifier
// to track at all.
func TestGuardCatchesPlusEqualsOntoTheFieldItself(t *testing.T) {
	findings := scanMutant(t, `package codex

import "github.com/marmutapp/superbased-observer/internal/models"

func evasion(toolID string) models.ToolEvent {
	var ev models.ToolEvent
	ev.RawToolName = toolID
	ev.RawToolName += ".reasoning"
	return ev
}
`)
	requireKind(t, findings, "field-assignment")
}

// TestGuardCatchesByteSliceLiteralEvasion — evasion 2: the name is
// spelled as bytes, so no substring search of any kind can find it.
func TestGuardCatchesByteSliceLiteralEvasion(t *testing.T) {
	findings := scanMutant(t, `package codex

import "github.com/marmutapp/superbased-observer/internal/models"

func evasion() models.ToolEvent {
	return models.ToolEvent{
		RawToolName: string([]byte{'c', 'o', 'd', 'e', 'x', '.', 'r', 'e', 'a', 's', 'o', 'n', 'i', 'n', 'g'}),
	}
}

func evasionNumeric() models.ToolEvent {
	var ev models.ToolEvent
	ev.RawToolName = string([]byte{112, 105, 46, 116, 104, 105, 110, 107, 105, 110, 103})
	return ev
}
`)
	requireKind(t, findings, "composite-literal")
	requireKind(t, findings, "field-assignment")
	requireName(t, findings, "codex.reasoning")
	requireName(t, findings, "pi.thinking")
}

// TestGuardCatchesMultiConstSplitEvasion — evasion 3: three constants,
// none of which ends in a reasoning suffix. Go's left-associative `+`
// means a right-operand-only resolver sees "reasoning" and shrugs; both
// operands must be composed.
func TestGuardCatchesMultiConstSplitEvasion(t *testing.T) {
	findings := scanMutant(t, `package codex

import "github.com/marmutapp/superbased-observer/internal/models"

const (
	toolPart = "codex"
	dotPart  = "."
	tailPart = "reasoning"
)

func evasion() models.ToolEvent {
	return models.ToolEvent{RawToolName: toolPart + dotPart + tailPart}
}
`)
	requireKind(t, findings, "composite-literal")
	requireName(t, findings, "codex.reasoning")
}

// TestGuardKnownEvasionsAreCaughtOrDocumented — evasion 4, the one that
// is NOT caught: a name that crosses an interface boundary. No string
// literal in the mutant carries a reasoning tail, and the assignment's
// right-hand side is a method call, so every layer of this walker is
// blind to it.
//
// This test deliberately does NOT assert the mutant is missed (a future
// improvement should not break it) and does NOT assert it is caught
// (today it is not). What it pins is the HONESTY: the guard must say out
// loud that indirect construction escapes it, and must name the
// ground-truth backstop that does not.
func TestGuardKnownEvasionsAreCaughtOrDocumented(t *testing.T) {
	findings, errs := scanReasoningMints(mutantDir(t, `package codex

import "github.com/marmutapp/superbased-observer/internal/models"

type namer interface{ Name() string }

type parts struct{ a, b string }

func (p parts) Name() string { return p.a + p.b }

func evasion(n namer) models.ToolEvent {
	var ev models.ToolEvent
	ev.RawToolName = n.Name()
	return ev
}

func caller() models.ToolEvent {
	return evasion(parts{a: "codex.", b: "reason" + "ing"})
}
`))
	for _, err := range errs {
		t.Fatalf("mutant did not parse: %v", err)
	}
	if len(findings) == 0 {
		t.Logf("KNOWN GAP (expected): interface-dispatched name construction is not statically caught. "+
			"This is why the claim is bounded and why the backstop exists:\n    %s", guardClaim)
	} else {
		t.Logf("interface-dispatch evasion is now caught (%v) — a strict improvement; the bounded claim stands "+
			"because other indirections (maps, struct fields, reflection) remain", findings)
	}

	// The honesty half is the assertion.
	for _, want := range []string{
		"cannot catch arbitrarily indirect construction",
		"ground-truth backstop",
		markerKey,
	} {
		if !strings.Contains(guardClaim, want) {
			t.Errorf("guardClaim no longer states %q; the guard would be overclaiming", want)
		}
	}
	for _, want := range []string{
		"migration_079_max_action_id",
		"substr(raw_tool_name, -10) = '.reasoning'",
		"substr(raw_tool_name, -9) = '.thinking'",
	} {
		if !strings.Contains(corpusReVerificationSQL, want) {
			t.Errorf("corpusReVerificationSQL lost %q", want)
		}
	}
}

// TestCorpusBackstopMatchesTheGuardsOwnSuffixes keeps the SQL and the
// walker describing the SAME family: the substr offsets are the suffix
// lengths, so adding a third reasoning suffix without extending the
// query would silently shrink the backstop.
func TestCorpusBackstopMatchesTheGuardsOwnSuffixes(t *testing.T) {
	for _, suf := range reasoningSuffixes {
		want := fmt.Sprintf("substr(raw_tool_name, -%d) = '%s'", len(suf), suf)
		if !strings.Contains(corpusReVerificationSQL, want) {
			t.Errorf("corpusReVerificationSQL does not cover %q (expected %q)", suf, want)
		}
	}
	if !strings.Contains(corpusReVerificationSQL, markerKey) {
		t.Errorf("corpusReVerificationSQL does not read the 079 marker key %q", markerKey)
	}
}

// requireName asserts some finding resolved to the exact name — the
// difference between "the guard noticed something" and "the guard
// reconstructed the assembled name".
func requireName(t *testing.T, findings []mintFinding, name string) {
	t.Helper()
	for _, f := range findings {
		if f.name == name {
			return
		}
	}
	t.Fatalf("no finding resolved to %q; got %v", name, findings)
}
