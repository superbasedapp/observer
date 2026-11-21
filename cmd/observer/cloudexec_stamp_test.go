package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// openStampStore opens a fresh store with one claude-code session row.
func openStampStore(t *testing.T, sessionID string) *store.Store {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	if _, err := st.EnsureCaptureSession(ctx, sessionID, models.ToolClaudeCode, "/tmp/w", "claude-opus-5-5", time.Now()); err != nil {
		t.Fatal(err)
	}
	return st
}

// TestExecutionStamperWiresStoreWriter pins the CA-A3 -> CA-A1 wiring
// (cmd/observer/cloudsession_stamp.go): the Rail S flush's stamper writes
// through Store.SetSessionExecution, first-wins-unless-empty, and a
// reference the wire grammar refuses is dropped while the location still
// lands.
func TestExecutionStamperWiresStoreWriter(t *testing.T) {
	ctx := context.Background()
	if executionStamperFor(nil) != nil {
		t.Fatal("nil store must give a nil stamper")
	}
	tests := []struct {
		name    string
		ref     string
		wantRef string
	}{
		{"valid cse reference", "cse_0123456789abcdefABCDEFGH", "cse_0123456789abcdefABCDEFGH"},
		{"reference with a slash is dropped", "cse_bad/ref", ""},
		{"no reference", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := openStampStore(t, "sess-stamp")
			stamper := executionStamperFor(st)
			if stamper == nil {
				t.Fatal("store did not yield a stamper")
			}
			stamps := cloudsession.PlanStamps(cloudsession.Detection{InCloud: true, Location: cloudsession.ExecutionVendorCloud, VendorRef: tc.ref}, []string{"sess-stamp", "missing-session"})
			n, err := cloudsession.ApplyStamps(ctx, stamper, stamps)
			if err != nil {
				t.Fatalf("ApplyStamps: %v", err)
			}
			if n != 1 {
				t.Fatalf("changed = %d; want 1 (the missing session is a silent no-op)", n)
			}
			got, err := st.LoadSessionExecution(ctx, "sess-stamp")
			if err != nil {
				t.Fatal(err)
			}
			if got.ExecutionLocation != models.ExecutionVendorCloud || got.VendorSessionRef != tc.wantRef {
				t.Fatalf("stored = %+v; want vendor_cloud / %q", got, tc.wantRef)
			}
			// A second flush is idempotent.
			if n, _ := cloudsession.ApplyStamps(ctx, stamper, stamps); n != 0 {
				t.Errorf("re-stamp changed %d rows; want 0", n)
			}
		})
	}
}

// TestHookCloudExecution pins the hook-environment stamp table: the
// claude-code marker rows of internal/cloudsession decide, the `cse_...`
// reference rides along when well formed, and every off-cloud shape (no
// marker, a local CLAUDE_CODE_REMOTE value other than "true", an empty
// session id, an unknown agent) stamps nothing.
func TestHookCloudExecution(t *testing.T) {
	const cse = "cse_0123456789abcdefABCDEFGH"
	cloud := map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": cse}
	tests := []struct {
		name    string
		agent   string
		session string
		env     map[string]string
		want    []models.SessionExecution
	}{
		{
			"cloud with reference", models.ToolClaudeCode, "s1", cloud,
			[]models.SessionExecution{{SessionID: "s1", ExecutionLocation: models.ExecutionVendorCloud, VendorSessionRef: cse}},
		},
		{
			"cloud without reference", models.ToolClaudeCode, "s1",
			map[string]string{"CLAUDE_CODE_REMOTE": "true"},
			[]models.SessionExecution{{SessionID: "s1", ExecutionLocation: models.ExecutionVendorCloud}},
		},
		{
			"malformed reference dropped", models.ToolClaudeCode, "s1",
			map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": "cse_a b"},
			[]models.SessionExecution{{SessionID: "s1", ExecutionLocation: models.ExecutionVendorCloud}},
		},
		{"developer machine", models.ToolClaudeCode, "s1", map[string]string{}, nil},
		{"marker not true", models.ToolClaudeCode, "s1", map[string]string{"CLAUDE_CODE_REMOTE": "false", "CLAUDE_CODE_REMOTE_SESSION_ID": cse}, nil},
		{"no session id", models.ToolClaudeCode, "", cloud, nil},
		{"unknown agent", "no-such-agent", "s1", cloud, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hookCloudExecution(tc.agent, tc.session, cloudEnv(tc.env))
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v; want %+v", got, tc.want)
			}
			for n := range got {
				if got[n] != tc.want[n] {
					t.Errorf("got[%d] = %+v; want %+v", n, got[n], tc.want[n])
				}
			}
		})
	}
	if hookCloudExecution(models.ToolClaudeCode, "s1", nil) != nil {
		t.Error("nil env must stamp nothing")
	}
}

// TestClaudeCodeHookStampsCloudExecution drives the real claude-code hook
// action handler (Stop) inside a simulated cloud environment and checks
// the session row carries vendor_cloud and the `cse_...` reference; then
// the same hook on a developer machine leaves both columns empty.
func TestClaudeCodeHookStampsCloudExecution(t *testing.T) {
	const cse = "cse_0123456789abcdefABCDEFGH"
	for _, tc := range []struct {
		name    string
		remote  string
		wantLoc string
		wantRef string
	}{
		{"cloud", "true", models.ExecutionVendorCloud, cse},
		{"local", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cloudSessionFixture(t)
			t.Setenv("CLAUDE_CODE_REMOTE", tc.remote)
			t.Setenv("CLAUDE_CODE_REMOTE_SESSION_ID", cse)
			body := `{"session_id":"sess-hook","transcript_path":"/tmp/t.jsonl","cwd":"/tmp/w","hook_event_name":"Stop","last_assistant_message":"Done."}`
			ctx := context.Background()
			var reply bytes.Buffer
			old := hookStdout
			hookStdout = &reply
			t.Cleanup(func() { hookStdout = old })
			handleClaudeCodeActionEvent(ctx, strings.NewReader(body), "claude-code:stop", cfg, buildClaudeStopEvent)
			database, err := db.Open(ctx, db.Options{Path: filepath.Join(filepath.Dir(cfg), "observer.db")})
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			got, err := store.New(database).LoadSessionExecution(ctx, "sess-hook")
			if err != nil {
				t.Fatalf("session row not created by the hook: %v", err)
			}
			if got.ExecutionLocation != tc.wantLoc || got.VendorSessionRef != tc.wantRef {
				t.Fatalf("stored = %+v; want %q / %q", got, tc.wantLoc, tc.wantRef)
			}
		})
	}
}

// TestCloudSessionFlushShipsExecution: the Rail S flush now stamps through
// the wired store writer, so the envelope's session carries both fields.
func TestCloudSessionFlushShipsExecution(t *testing.T) {
	cfg := cloudSessionFixture(t)
	out := filepath.Join(t.TempDir(), "envelopes")
	res, err := runCloudSessionFlush(context.Background(), cloudSessionFlushOptions{
		Timeout: cloudSessionTestFlushTimeout,
		Agent:   "claude-code", Trigger: cloudsession.TriggerFinal, Destination: cloudsession.DestFile,
		// A committed hook block, so the CA-B6 guard verifies and the flush
		// delivers (without it the guard holds delivery and nothing stamps).
		URL: out, ConfigPath: cfg, Repo: cloudSessionRepo(t, "claude-code", true),
		Env: cloudEnv(map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": "cse_0123456789abcdefABCDEFGH"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stamped != "applied" {
		t.Fatalf("Stamped = %q; want applied", res.Stamped)
	}
	envs := readEnvelopes(t, out)
	if len(envs) != 1 || len(envs[0].Sessions) != 1 {
		t.Fatalf("envelopes = %+v", envs)
	}
	s := envs[0].Sessions[0]
	if s.ExecutionLocation != models.ExecutionVendorCloud || s.VendorSessionRef != "cse_0123456789abcdefABCDEFGH" {
		t.Fatalf("session ships execution %q / %q; want vendor_cloud + the cse reference", s.ExecutionLocation, s.VendorSessionRef)
	}
}
