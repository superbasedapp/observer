package db

import (
	"context"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
)

// Trigger-body guard (defect D3, migration 142). SQLite ignores a conflict
// clause on a statement INSIDE a trigger body whenever the statement that
// fired the trigger carries its own conflict handling: the outer algorithm
// wins (an UPSERT's DO UPDATE half runs as ABORT; an outer OR IGNORE turns
// the inner write into a silent no-op). Migrations 140/141 queued re-sends
// with INSERT OR REPLACE and every enrolled node's ingest failed
// `UNIQUE constraint failed: org_push_changes` once a row was already queued.
// An UPSERT clause (ON CONFLICT ... DO UPDATE/NOTHING) is the one conflict
// resolution the outer statement cannot override, so it is the only one a
// trigger body may use.

var (
	reLineComment = regexp.MustCompile(`--[^\n]*`)
	// A trigger DDL event, in file order: CREATE TRIGGER ... END; or DROP TRIGGER.
	reTriggerEvent = regexp.MustCompile(`(?is)\bCREATE\s+TRIGGER\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\b.*?\bEND\s*;|\bDROP\s+TRIGGER\s+(?:IF\s+EXISTS\s+)?(\w+)\s*;`)
	// A statement-level conflict clause (overridden by the firing statement).
	reConflictClause = regexp.MustCompile(`(?i)\b(?:INSERT|UPDATE)\s+OR\s+(?:REPLACE|IGNORE|ABORT|FAIL|ROLLBACK)\b|\bREPLACE\s+INTO\b`)
	reInsertInto     = regexp.MustCompile(`(?i)\bINSERT\s+INTO\s+(\w+)`)
	reUpsert         = regexp.MustCompile(`(?i)\bON\s+CONFLICT\b`)
)

// upsertRequiredTables are keyed queue tables a trigger may write only with
// an UPSERT: the row a trigger inserts may already be queued, and a plain
// INSERT would ABORT the firing statement (the whole ingest) on that conflict.
// org_push_deletions is deliberately absent: its key is the freshly bumped
// org_push_rev value, unique by construction.
var upsertRequiredTables = map[string]bool{
	"org_push_changes": true,
}

// latestMigrationTriggers replays every migration's trigger DDL in order and
// returns the surviving triggers' latest definitions (comments stripped).
func latestMigrationTriggers(t *testing.T) map[string]string {
	t.Helper()
	entries, err := readMigrationEntries()
	if err != nil {
		t.Fatalf("readMigrationEntries: %v", err)
	}
	defs := map[string]string{}
	for _, e := range entries {
		body, err := fs.ReadFile(migrations.Files, e.filename)
		if err != nil {
			t.Fatalf("read %s: %v", e.filename, err)
		}
		sqlText := reLineComment.ReplaceAllString(string(body), "")
		for _, m := range reTriggerEvent.FindAllStringSubmatch(sqlText, -1) {
			switch {
			case m[1] != "":
				defs[strings.ToLower(m[1])] = m[0]
			case m[2] != "":
				delete(defs, strings.ToLower(m[2]))
			}
		}
	}
	return defs
}

// triggerBodyViolations returns why a trigger definition's body is unsafe.
func triggerBodyViolations(def string) []string {
	up := strings.ToUpper(def)
	begin := regexp.MustCompile(`\bBEGIN\b`).FindStringIndex(up)
	if begin == nil {
		return []string{"no BEGIN ... END body found"}
	}
	body := def[begin[1]:]
	var out []string
	if m := reConflictClause.FindString(body); m != "" {
		out = append(out, "uses the statement conflict clause "+strings.Join(strings.Fields(m), " ")+
			" (the firing statement's conflict handling overrides it; use INSERT ... ON CONFLICT (...) DO UPDATE)")
	}
	for _, stmt := range strings.Split(body, ";") {
		m := reInsertInto.FindStringSubmatch(stmt)
		if m == nil || !upsertRequiredTables[strings.ToLower(m[1])] {
			continue
		}
		if !reUpsert.MatchString(stmt) {
			out = append(out, "inserts into "+m[1]+" without an ON CONFLICT upsert clause")
		}
	}
	return out
}

// TestTriggerBodiesUseUpsertNotConflictClauses parses the LATEST definition
// of every trigger the migrations create and fails if any body carries a
// statement conflict clause, or writes a keyed queue table without an UPSERT.
func TestTriggerBodiesUseUpsertNotConflictClauses(t *testing.T) {
	t.Parallel()
	defs := latestMigrationTriggers(t)
	if len(defs) == 0 {
		t.Fatal("parsed no triggers from the migrations; the parser is broken")
	}
	names := make([]string, 0, len(defs))
	for n := range defs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, v := range triggerBodyViolations(defs[n]) {
			t.Errorf("trigger %s (latest migration definition) %s", n, v)
		}
	}
}

// TestMigrationTriggersExistAfterMigrate pins every trigger the migrations
// define against a later table-REBUILDING migration: CREATE new / copy /
// DROP old / RENAME drops every trigger on the old table without a word, so
// the 140/141/142 org push triggers (and every other) must still be in
// sqlite_master after a fresh migrate. It also runs the body guard over the
// LIVE trigger SQL, which covers a trigger created outside the .sql files.
// A migration that removes a table on purpose must DROP its triggers
// explicitly so this list stays exact.
func TestMigrationTriggersExistAfterMigrate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := Open(ctx, Options{Path: ":memory:"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer database.Close()

	rows, err := database.QueryContext(ctx, `SELECT name, sql FROM sqlite_master WHERE type = 'trigger'`)
	if err != nil {
		t.Fatalf("sqlite_master: %v", err)
	}
	live := map[string]string{}
	for rows.Next() {
		var name, sqlText string
		if err := rows.Scan(&name, &sqlText); err != nil {
			t.Fatal(err)
		}
		live[strings.ToLower(name)] = sqlText
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}

	for name := range latestMigrationTriggers(t) {
		if _, ok := live[name]; !ok {
			t.Errorf("trigger %s is defined by the migrations but missing after migrate "+
				"(a table rebuild dropped it? re-create it in the rebuilding migration)", name)
		}
	}
	for name, sqlText := range live {
		for _, v := range triggerBodyViolations(sqlText) {
			t.Errorf("live trigger %s %s", name, v)
		}
	}

	// The org push re-send triggers, by name (later code and tests match them).
	for _, name := range []string{
		"org_push_change_sessions", "org_push_change_actions", "org_push_change_api_turns",
		"org_push_change_token_usage", "org_push_change_projects", "org_push_change_session_tokens",
		"org_push_insert_sessions",
	} {
		sqlText, ok := live[name]
		if !ok {
			t.Errorf("org push trigger %s missing after migrate", name)
			continue
		}
		if !strings.Contains(sqlText, "ON CONFLICT (tbl, row_id) DO UPDATE SET seq = excluded.seq") {
			t.Errorf("org push trigger %s does not queue with the migration-142 UPSERT:\n%s", name, sqlText)
		}
	}
}

// TestTriggerBodyGuardCatchesTheD3Shape proves the guard is not vacuous: the
// exact migration-140 body it exists to forbid is flagged, and the 142 body
// passes.
func TestTriggerBodyGuardCatchesTheD3Shape(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		def  string
		bad  bool
	}{
		{"140 INSERT OR REPLACE", `CREATE TRIGGER x AFTER UPDATE ON sessions BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT OR REPLACE INTO org_push_changes (tbl, row_id, seq) VALUES ('sessions', NEW.rowid, 1);
END;`, true},
		{"INSERT OR IGNORE", `CREATE TRIGGER x AFTER INSERT ON t BEGIN INSERT OR IGNORE INTO q (a) VALUES (NEW.a); END;`, true},
		{"REPLACE INTO", `CREATE TRIGGER x AFTER INSERT ON t BEGIN REPLACE INTO q (a) VALUES (NEW.a); END;`, true},
		{"UPDATE OR IGNORE", `CREATE TRIGGER x AFTER INSERT ON t BEGIN UPDATE OR IGNORE q SET a = 1; END;`, true},
		{"plain INSERT into the queue", `CREATE TRIGGER x AFTER UPDATE ON t BEGIN
    INSERT INTO org_push_changes (tbl, row_id, seq) VALUES ('t', NEW.id, 1);
END;`, true},
		{"142 UPSERT", `CREATE TRIGGER x AFTER UPDATE ON t BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT INTO org_push_changes (tbl, row_id, seq) VALUES ('t', NEW.id, 1)
    ON CONFLICT (tbl, row_id) DO UPDATE SET seq = excluded.seq;
END;`, false},
		{"141 tombstone plain INSERT (unique seq)", `CREATE TRIGGER x AFTER DELETE ON t BEGIN
    INSERT INTO org_push_deletions (seq, tbl, row_id) VALUES (1, 't', OLD.id);
    DELETE FROM org_push_changes WHERE tbl = 't' AND row_id = OLD.id;
END;`, false},
		{"RAISE(ABORT) guard", `CREATE TRIGGER x BEFORE INSERT ON t WHEN NEW.a IS NULL BEGIN SELECT RAISE(ABORT, 'no'); END;`, false},
	}
	for _, c := range cases {
		if got := len(triggerBodyViolations(c.def)) > 0; got != c.bad {
			t.Errorf("%s: flagged = %v, want %v (%v)", c.name, got, c.bad, triggerBodyViolations(c.def))
		}
	}
}
