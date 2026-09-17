package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newTagCLIFixture writes an isolated config + db seeded with two sessions
// whose ids share a prefix (so ambiguity is exercised) and returns the config
// path.
func newTagCLIFixture(t *testing.T) string {
	t.Helper()
	return newTagCLIFixtureIDs(t, "abc111", "abc222", "zzz999")
}

// newTagCLIFixtureIDs is newTagCLIFixture with the session-id set chosen by the
// caller — the documented-example tests need the id the help text prints, and
// the ambiguity test needs more colliding ids than the candidate-list cap.
// Every seeded session gets the same 1000-in/100-out token profile.
func newTagCLIFixtureIDs(t *testing.T, sessionIDs ...string) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+dbPath+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	st := store.New(database)
	root := t.TempDir()
	base := time.Now().UTC().Add(-time.Hour)
	var events []models.ToolEvent
	var tokens []models.TokenEvent
	for i, sid := range sessionIDs {
		ts := base.Add(time.Duration(i) * time.Minute)
		events = append(events, models.ToolEvent{
			SourceFile: "f.jsonl", SourceEventID: sid + "-e1", SessionID: sid,
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
			Model: "claude-opus-4-7", ActionType: models.ActionReadFile,
			Target: "a.go", Success: true,
		})
		tokens = append(tokens, models.TokenEvent{
			SourceFile: "f.jsonl", SourceEventID: sid + "-t1", SessionID: sid,
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
			Model: "claude-opus-4-7", InputTokens: 1000, OutputTokens: 100,
			Source: "jsonl", Reliability: "unreliable",
		})
	}
	if _, err := st.Ingest(ctx, events, tokens, store.IngestOptions{}); err != nil {
		t.Fatalf("seed Ingest: %v", err)
	}
	return cfgPath
}

func runTagCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newTagCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func runTagsCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newTagsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// TestTagCmdGrammar exercises the documented grammar end to end: `+tag` adds,
// `--rm` removes, `-tag` removes after a `--` marker, and the favorite/note
// flags round-trip. A bare (unsigned) token is an error, never a silent add.
func TestTagCmdGrammar(t *testing.T) {
	cfg := newTagCLIFixture(t)

	out, err := runTagCmd(t, "zzz", "+Experiment", "+ui ux", "--favorite",
		"--note", "baseline run", "--config", cfg)
	if err != nil {
		t.Fatalf("tag add: %v\n%s", err, out)
	}
	if !strings.Contains(out, "zzz999") || !strings.Contains(out, "experiment, ui-ux") {
		t.Fatalf("tag add output = %q", out)
	}
	if !strings.Contains(out, "favorite") || !strings.Contains(out, "baseline run") {
		t.Fatalf("annotation not applied: %q", out)
	}

	out, err = runTagCmd(t, "zzz", "--rm", "experiment", "--config", cfg, "--json")
	if err != nil {
		t.Fatalf("tag --rm: %v\n%s", err, out)
	}
	var res struct {
		SessionID string   `json:"session_id"`
		Tags      []string `json:"tags"`
		Favorite  bool     `json:"favorite"`
		Note      string   `json:"note"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode --json output %q: %v", out, err)
	}
	if res.SessionID != "zzz999" || len(res.Tags) != 1 || res.Tags[0] != "ui-ux" {
		t.Fatalf("after --rm: %+v", res)
	}
	if !res.Favorite || res.Note != "baseline run" {
		t.Fatalf("tag mutation clobbered the annotation: %+v", res)
	}

	// The '-tag' spelling works after the '--' end-of-flags marker.
	out, err = runTagCmd(t, "zzz", "--config", cfg, "--", "-ui-ux")
	if err != nil {
		t.Fatalf("tag -- -tag: %v\n%s", err, out)
	}
	if !strings.Contains(out, "(none)") {
		t.Fatalf("'--' removal did not apply: %q", out)
	}

	// Un-star + clear the note → the annotation returns to zero.
	out, err = runTagCmd(t, "zzz", "--no-favorite", "--clear-note", "--config", cfg, "--json")
	if err != nil {
		t.Fatalf("clear annotation: %v\n%s", err, out)
	}
	if strings.Contains(out, "baseline run") || strings.Contains(out, `"favorite": true`) {
		t.Fatalf("annotation not cleared: %q", out)
	}

	// A bare token is rejected with the grammar help.
	if out, err := runTagCmd(t, "zzz", "junk", "--config", cfg); err == nil {
		t.Fatalf("bare token accepted: %q", out)
	}
	// Mutually exclusive flags.
	if _, err := runTagCmd(t, "zzz", "--favorite", "--no-favorite", "--config", cfg); err == nil {
		t.Fatal("--favorite --no-favorite accepted")
	}
	// An invalid tag surfaces the store's normalization error.
	if _, err := runTagCmd(t, "zzz", "+bad/tag", "--config", cfg); err == nil {
		t.Fatal("invalid tag accepted")
	}
}

// TestTagCmdRating pins the --rating flag: 1-10 sets and shows "N/10", --json
// round-trips it, a mutation that omits --rating LEAVES the score unchanged
// (Changed-based pointer semantics — `--rating 0` clears, an absent flag does
// not), and out-of-range is rejected before any write.
func TestTagCmdRating(t *testing.T) {
	cfg := newTagCLIFixture(t)

	out, err := runTagCmd(t, "zzz", "--rating", "8", "--config", cfg)
	if err != nil {
		t.Fatalf("set rating: %v\n%s", err, out)
	}
	if !strings.Contains(out, "rating: 8/10") {
		t.Fatalf("rating not shown in text output: %q", out)
	}

	// A tag-only mutation (no --rating flag) must leave the rating untouched.
	out, err = runTagCmd(t, "zzz", "+keep", "--config", cfg, "--json")
	if err != nil {
		t.Fatalf("tag add: %v\n%s", err, out)
	}
	var res struct {
		Rating int `json:"rating"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode --json %q: %v", out, err)
	}
	if res.Rating != 8 {
		t.Fatalf("rating changed by an unrelated mutation: %d, want 8", res.Rating)
	}

	// --rating 0 clears it.
	out, err = runTagCmd(t, "zzz", "--rating", "0", "--config", cfg, "--json")
	if err != nil {
		t.Fatalf("clear rating: %v\n%s", err, out)
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode --json %q: %v", out, err)
	}
	if res.Rating != 0 {
		t.Fatalf("rating not cleared: %d, want 0", res.Rating)
	}

	// Out-of-range is rejected (pre-flight, before any write).
	if _, err := runTagCmd(t, "zzz", "--rating", "11", "--config", cfg); err == nil {
		t.Fatal("--rating 11 accepted; want the store's range error")
	}
}

// TestTagCmdPrefixResolution pins unique-prefix resolution and the ambiguity
// error listing the candidates.
func TestTagCmdPrefixResolution(t *testing.T) {
	cfg := newTagCLIFixture(t)

	if out, err := runTagCmd(t, "abc111", "+keep", "--config", cfg); err != nil {
		t.Fatalf("full id: %v\n%s", err, out)
	}
	out, err := runTagCmd(t, "abc", "+keep", "--config", cfg)
	if err == nil {
		t.Fatalf("ambiguous prefix accepted: %q", out)
	}
	msg := err.Error()
	if !strings.Contains(msg, "abc111") || !strings.Contains(msg, "abc222") {
		t.Fatalf("ambiguity error did not list candidates: %v", err)
	}
	if _, err := runTagCmd(t, "nope", "+keep", "--config", cfg); err == nil {
		t.Fatal("unknown prefix accepted")
	}
}

// TestTagsVocabularyCommands pins `observer tags` (rollup, bare + --json),
// `tags rename` (merge) and `tags rm`.
func TestTagsVocabularyCommands(t *testing.T) {
	cfg := newTagCLIFixture(t)

	if _, err := runTagCmd(t, "abc111", "+be", "+backend", "--config", cfg); err != nil {
		t.Fatalf("seed abc111: %v", err)
	}
	if _, err := runTagCmd(t, "abc222", "+be", "--config", cfg); err != nil {
		t.Fatalf("seed abc222: %v", err)
	}

	out, err := runTagsCmd(t, "--config", cfg)
	if err != nil {
		t.Fatalf("tags: %v\n%s", err, out)
	}
	if !strings.Contains(out, "backend") || !strings.Contains(out, "SESSIONS") {
		t.Fatalf("tags table = %q", out)
	}

	out, err = runTagsCmd(t, "--json", "--config", cfg)
	if err != nil {
		t.Fatalf("tags --json: %v\n%s", err, out)
	}
	var rollup struct {
		Tags []struct {
			Tag      string  `json:"tag"`
			Sessions int     `json:"sessions"`
			Tokens   int64   `json:"tokens"`
			CostUSD  float64 `json:"cost_usd"`
		} `json:"tags"`
	}
	if err := json.Unmarshal([]byte(out), &rollup); err != nil {
		t.Fatalf("decode tags --json %q: %v", out, err)
	}
	if len(rollup.Tags) != 2 {
		t.Fatalf("rollup = %+v, want 2 tags", rollup.Tags)
	}
	byTag := map[string]int{}
	tokensByTag := map[string]int64{}
	for _, r := range rollup.Tags {
		byTag[r.Tag] = r.Sessions
		tokensByTag[r.Tag] = r.Tokens
	}
	if byTag["be"] != 2 || byTag["backend"] != 1 {
		t.Fatalf("session counts = %v", byTag)
	}
	if tokensByTag["be"] != 2200 {
		t.Fatalf("be tokens = %d, want 2200 (two sessions × 1100)", tokensByTag["be"])
	}

	out, err = runTagsCmd(t, "rename", "be", "backend", "--config", cfg)
	if err != nil {
		t.Fatalf("tags rename: %v\n%s", err, out)
	}
	if !strings.Contains(out, "2 session(s)") {
		t.Fatalf("rename output = %q", out)
	}
	out, _ = runTagsCmd(t, "--json", "--config", cfg)
	rollup.Tags = nil
	_ = json.Unmarshal([]byte(out), &rollup)
	if len(rollup.Tags) != 1 || rollup.Tags[0].Tag != "backend" || rollup.Tags[0].Sessions != 2 {
		t.Fatalf("after merge: %+v", rollup.Tags)
	}

	out, err = runTagsCmd(t, "rm", "backend", "--config", cfg)
	if err != nil {
		t.Fatalf("tags rm: %v\n%s", err, out)
	}
	if !strings.Contains(out, "2 session(s)") {
		t.Fatalf("rm output = %q", out)
	}
	out, _ = runTagsCmd(t, "--config", cfg)
	if !strings.Contains(out, "No tags yet") {
		t.Fatalf("empty vocabulary output = %q", out)
	}
}

// TestParseTagTokens is the table-driven pin on the positional grammar.
func TestParseTagTokens(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		in         []string
		add, remov []string
		wantErr    bool
	}{
		{"empty", nil, nil, nil, false},
		{"adds", []string{"+a", "+b"}, []string{"a", "b"}, nil, false},
		{"removes", []string{"-a"}, nil, []string{"a"}, false},
		{"mixed", []string{"+a", "-b"}, []string{"a"}, []string{"b"}, false},
		{"bare token rejected", []string{"a"}, nil, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			add, remove, err := parseTagTokens(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseTagTokens(%v) = %v/%v, want error", tc.in, add, remove)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTagTokens(%v): %v", tc.in, err)
			}
			if strings.Join(add, ",") != strings.Join(tc.add, ",") {
				t.Fatalf("add = %v, want %v", add, tc.add)
			}
			if strings.Join(remove, ",") != strings.Join(tc.remov, ",") {
				t.Fatalf("remove = %v, want %v", remove, tc.remov)
			}
		})
	}
}

// TestTagCommandsRegistered pins the two commands into the root command set —
// the constructors must return FRESH commands (the alias-group requirement).
func TestTagCommandsRegistered(t *testing.T) {
	t.Parallel()
	want := map[string]bool{"tag": false, "tags": false}
	for _, c := range observerSubcommandsWith(defaultUsageDeps()) {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("`observer %s` is not registered in observerSubcommandsWith", name)
		}
	}
	if a, b := newTagCmd(), newTagCmd(); a == b {
		t.Error("newTagCmd returned the same instance twice — constructors must return fresh commands")
	}
	if a, b := newTagsCmd(), newTagsCmd(); a == b {
		t.Error("newTagsCmd returned the same instance twice — constructors must return fresh commands")
	}
}

// tagFixtureDBPath returns the observer.db that newTagCLIFixture wrote next to
// its config, so a test can seed rows the CLI surface has no verb for.
func tagFixtureDBPath(cfgPath string) string {
	return filepath.Join(filepath.Dir(cfgPath), "observer.db")
}

// splitTagExample splits a documented example invocation into argv, honouring
// double quotes so `--note "baseline run"` stays one argument — the same thing
// a shell does before cobra ever sees the tokens.
func splitTagExample(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote, started := false, false
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
			started = true
		case r == ' ' && !inQuote:
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}

// tagHelpExampleArgs extracts every `observer tag …` example from
// tagGrammarHelp and returns it as runnable argv (session id first), with
// `--config <path>` spliced in right after the session id — before any `--`
// marker, exactly where the help text says flags must go.
func tagHelpExampleArgs(t *testing.T, cfgPath string) [][]string {
	t.Helper()
	var out [][]string
	for _, line := range strings.Split(tagGrammarHelp, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "observer tag ") {
			continue
		}
		argv := splitTagExample(line)
		if len(argv) < 3 {
			t.Fatalf("unparseable example %q", line)
		}
		args := []string{argv[2], "--config", cfgPath}
		args = append(args, argv[3:]...)
		out = append(out, args)
	}
	if len(out) == 0 {
		t.Fatal("tagGrammarHelp carries no `observer tag` examples to verify")
	}
	return out
}

// TestTagGrammarHelpExamplesActuallyWork is the drift gate between the help
// text and the parser (codex MEDIUM #4). EVERY example printed by
// tagGrammarHelp is executed verbatim (only `--config` is spliced in, ahead of
// any `--` marker) and must succeed. The plan's documented
// `observer tag id +experiment -junk --favorite` never parsed — pflag claims a
// bare `-junk` as a shorthand flag cluster — so the help now documents `--rm`
// as the primary remove spelling and `-tag` only after `--`, and this test
// fails the moment an unrunnable invocation is advertised again.
func TestTagGrammarHelpExamplesActuallyWork(t *testing.T) {
	for i, args := range tagHelpExampleArgs(t, newTagCLIFixtureIDs(t, "a1b2c3")) {
		if out, err := runTagCmd(t, args...); err != nil {
			t.Fatalf("documented example #%d %v failed: %v\n%s", i+1, args, err, out)
		}
	}

	// The primary combined shape the finding calls out, asserted on OUTCOME and
	// not merely on exit status: `+a` adds, `--rm b` removes, and the favorite
	// and note flags apply in the same invocation.
	cfg := newTagCLIFixtureIDs(t, "a1b2c3")
	if out, err := runTagCmd(t, "a1b2c3", "+b", "--config", cfg); err != nil {
		t.Fatalf("seed +b: %v\n%s", err, out)
	}
	out, err := runTagCmd(t, "a1b2c3", "+a", "--rm", "b", "--favorite", "--note", "x", "--config", cfg, "--json")
	if err != nil {
		t.Fatalf("`+a --rm b --favorite --note x` failed: %v\n%s", err, out)
	}
	var res struct {
		Tags     []string `json:"tags"`
		Favorite bool     `json:"favorite"`
		Note     string   `json:"note"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if len(res.Tags) != 1 || res.Tags[0] != "a" || !res.Favorite || res.Note != "x" {
		t.Fatalf("combined invocation state = %+v, want tags=[a] favorite=true note=x", res)
	}

	// The two NEGATIVE claims the help text makes, pinned so the documentation
	// stays true:
	// (1) a bare -tag never reaches this command — the argument parser eats it.
	if out, err := runTagCmd(t, "a1b2c3", "-junk", "--config", cfg); err == nil {
		t.Fatalf("bare -junk was accepted: %q", out)
	}
	// (2) after `--`, a flag spelling is a TAG TOKEN, not a flag: `--favorite`
	//     written there must not star the session (it removes a tag "favorite").
	if _, err := runTagCmd(t, "a1b2c3", "--no-favorite", "--config", cfg); err != nil {
		t.Fatalf("un-star: %v", err)
	}
	out, err = runTagCmd(t, "a1b2c3", "--config", cfg, "--", "--favorite")
	if err != nil {
		t.Fatalf("post-marker tag argument: %v\n%s", err, out)
	}
	if strings.Contains(out, "favorite") {
		t.Fatalf("a --favorite written after `--` was parsed as a flag: %q", out)
	}
}

// TestTagCmdValidatesEverythingBeforeWriting is the CLI half of the
// combined-request atomicity fix (codex MEDIUM #3): `observer tag id +x --note
// <501 chars>` used to commit the tag and only then fail on the note. Nothing
// may be written when any part of the invocation is invalid.
func TestTagCmdValidatesEverythingBeforeWriting(t *testing.T) {
	cfg := newTagCLIFixture(t)

	longNote := strings.Repeat("n", store.MaxNoteLen+1)
	if out, err := runTagCmd(t, "zzz", "+x", "--note", longNote, "--config", cfg); err == nil {
		t.Fatalf("over-long note accepted: %q", out)
	}
	out, err := runTagCmd(t, "zzz", "--config", cfg, "--json")
	if err != nil {
		t.Fatalf("read back: %v\n%s", err, out)
	}
	if strings.Contains(out, `"x"`) {
		t.Fatalf("tag x was committed before the note was validated: %q", out)
	}

	// Symmetric: an invalid tag alongside a valid note writes neither.
	if _, err := runTagCmd(t, "zzz", "+bad/tag", "--note", "keep me out", "--config", cfg); err == nil {
		t.Fatal("invalid tag + valid note accepted")
	}
	out, _ = runTagCmd(t, "zzz", "--config", cfg, "--json")
	if strings.Contains(out, "keep me out") {
		t.Fatalf("note was committed alongside a rejected tag: %q", out)
	}
}

// TestTagCmdJSONEmitsEmptyTagList pins the CLI/HTTP shape parity (codex LOW #6):
// an untagged session must emit "tags":[] like the HTTP surface, never
// "tags":null — a --json consumer should not have to handle two spellings of
// "no tags" depending on which surface produced the document.
func TestTagCmdJSONEmitsEmptyTagList(t *testing.T) {
	cfg := newTagCLIFixture(t)
	out, err := runTagCmd(t, "zzz", "--config", cfg, "--json")
	if err != nil {
		t.Fatalf("tag --json: %v\n%s", err, out)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(strings.TrimSpace(out))); err != nil {
		t.Fatalf("compact %q: %v", out, err)
	}
	if !strings.Contains(compact.String(), `"tags":[]`) {
		t.Fatalf("untagged session --json = %s, want \"tags\":[]", compact.String())
	}
}

// TestTagCmdAmbiguityReportsTruncatedCount pins the honest match count (codex
// LOW #5c): the candidate list is capped, so a prefix matching more sessions
// than the cap must read "10+ sessions" rather than understating the ambiguity
// as exactly the number of ids printed.
func TestTagCmdAmbiguityReportsTruncatedCount(t *testing.T) {
	ids := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		ids = append(ids, fmt.Sprintf("dup%02d", i))
	}
	cfg := newTagCLIFixtureIDs(t, ids...)

	_, err := runTagCmd(t, "dup", "+x", "--config", cfg)
	if err == nil {
		t.Fatal("ambiguous prefix accepted")
	}
	if !strings.Contains(err.Error(), "matches 10+ sessions") {
		t.Fatalf("ambiguity message = %v, want an honest \"matches 10+ sessions\"", err)
	}
}

// TestTagsRollupChunksPastBindLimit is the CLI half of the bind-ceiling fix
// (codex HIGH #1). computeTagRollup scopes every tagged session id into the
// cost engine; as ONE `IN (...)` list that exceeds SQLite's 32766-parameter
// limit, and because the cost error is swallowed the symptom is silently zeroed
// TOKENS/COST columns rather than a visible failure — so this asserts the
// numbers, not the exit status.
func TestTagsRollupChunksPastBindLimit(t *testing.T) {
	cfg := newTagCLIFixture(t)
	if _, err := runTagCmd(t, "abc111", "+bulk", "--config", cfg); err != nil {
		t.Fatalf("seed tag: %v", err)
	}

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: tagFixtureDBPath(cfg)})
	if err != nil {
		t.Fatal(err)
	}
	// 33_000 > 32766 = SQLITE_MAX_VARIABLE_NUMBER in modernc.org/sqlite.
	// session_tags has no FK (migration 075, by design), so padding the id set
	// costs one bulk insert instead of 33k seeded sessions.
	const filler = 33_000
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO session_tags (session_id, tag, created_at) VALUES (?, 'bulk', '2026-07-30T00:00:00Z')`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < filler; i++ {
		if _, err := stmt.ExecContext(ctx, fmt.Sprintf("filler-%06d", i)); err != nil {
			t.Fatalf("insert filler %d: %v", i, err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := runTagsCmd(t, "--json", "--config", cfg)
	if err != nil {
		t.Fatalf("tags --json: %v\n%s", err, out)
	}
	var rollup struct {
		Tags []struct {
			Tag      string  `json:"tag"`
			Sessions int     `json:"sessions"`
			Tokens   int64   `json:"tokens"`
			CostUSD  float64 `json:"cost_usd"`
		} `json:"tags"`
	}
	if err := json.Unmarshal([]byte(out), &rollup); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if len(rollup.Tags) != 1 || rollup.Tags[0].Tag != "bulk" {
		t.Fatalf("rollup = %+v, want the single bulk row", rollup.Tags)
	}
	if rollup.Tags[0].Sessions != filler+1 {
		t.Fatalf("bulk sessions = %d, want %d", rollup.Tags[0].Sessions, filler+1)
	}
	if rollup.Tags[0].Tokens != 1100 {
		t.Fatalf("bulk tokens = %d, want 1100 - the cost pass was dropped (bind-limit regression)", rollup.Tags[0].Tokens)
	}
	if rollup.Tags[0].CostUSD <= 0 {
		t.Fatalf("bulk cost_usd = %v, want > 0 - the cost pass was dropped (bind-limit regression)", rollup.Tags[0].CostUSD)
	}
}
