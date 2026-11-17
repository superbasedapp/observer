package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func runSessionsCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newSessionsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// fixtureDB opens the fixture's database (newTagCLIFixtureIDs puts it beside
// the config) for direct assertions.
func fixtureDB(t *testing.T, cfgPath string) *sql.DB {
	t.Helper()
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(filepath.Dir(cfgPath), "observer.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

// TestSessionsHoldCmd walks the CLI table: hold by prefix, hold again,
// list, ambiguity and unknown ids refused, release, release again.
func TestSessionsHoldCmd(t *testing.T) {
	cfg := newTagCLIFixture(t) // sessions abc111, abc222, zzz999
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr string
		want    []string
	}{
		{name: "hold by unique prefix", args: []string{"hold", "zzz", "--note", "audit"}, want: []string{"held zzz999", "local to this machine"}},
		{name: "hold again", args: []string{"hold", "zzz999"}, want: []string{"zzz999 was already held"}},
		{name: "ambiguous prefix", args: []string{"hold", "abc"}, wantErr: "matches 2 sessions"},
		{name: "unknown session", args: []string{"hold", "nope"}, wantErr: "no session matches"},
		{name: "list", args: []string{"holds"}, want: []string{"SESSION", "zzz999", "audit"}},
		{name: "release", args: []string{"release", "zzz"}, want: []string{"released zzz999"}},
		{name: "release again", args: []string{"release", "zzz999"}, wantErr: "zzz999 is not held"},
		{name: "list empty", args: []string{"holds"}, want: []string{"no held sessions"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runSessionsCmd(t, append(tc.args, "--config", cfg)...)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q\n%s", err, tc.wantErr, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Fatalf("output %q lacks %q", out, w)
				}
			}
		})
	}
}

// TestSessionsHoldCmdJSONAndStore checks --json and that the CLI writes
// the store seam retention reads.
func TestSessionsHoldCmdJSONAndStore(t *testing.T) {
	cfg := newTagCLIFixture(t)
	out, err := runSessionsCmd(t, "hold", "abc111", "--json", "--config", cfg)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var got struct {
		SessionID string `json:"session_id"`
		Held      bool   `json:"held"`
		Created   bool   `json:"created"`
		Scope     string `json:"scope"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.SessionID != "abc111" || !got.Held || !got.Created || got.Scope != "node" {
		t.Fatalf("json = %q (%v)", out, err)
	}
	database := fixtureDB(t, cfg)
	st := store.New(database)
	if held, err := st.IsSessionHeld(context.Background(), "abc111"); err != nil || !held {
		t.Fatalf("store sees held=%v err=%v", held, err)
	}
	out, err = runSessionsCmd(t, "holds", "--json", "--config", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var list []store.SessionHold
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list) != 1 || list[0].SessionID != "abc111" || !list[0].Exists {
		t.Fatalf("holds json = %q (%v)", out, err)
	}
	// A hold whose session rows are gone still releases by full id.
	if _, err := st.HoldSession(context.Background(), "abc222", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(context.Background(), `UPDATE local_session_holds SET session_id = 'gone-session' WHERE session_id = 'abc222'`); err != nil {
		t.Fatal(err)
	}
	if out, err := runSessionsCmd(t, "release", "gone-session", "--config", cfg); err != nil || !strings.Contains(out, "released gone-session") {
		t.Fatalf("release of a vanished session = %q, %v", out, err)
	}
}

// TestSessionsCmdRegistered pins `observer sessions` into the root set.
func TestSessionsCmdRegistered(t *testing.T) {
	t.Parallel()
	var found bool
	for _, c := range observerSubcommandsWith(defaultUsageDeps()) {
		if c.Name() == "sessions" {
			found = true
		}
	}
	if !found {
		t.Fatal("`observer sessions` is not registered")
	}
}
