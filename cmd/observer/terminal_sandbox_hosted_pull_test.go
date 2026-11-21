//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestHostedPullTranscripts: only the tool's state is pulled, into the
// run's quarantine directory, owner-only.
func TestHostedPullTranscripts(t *testing.T) {
	c := newFakeBoxClient()
	info, _ := c.Create(context.Background(), sandboxremote.BoxSpec{RunID: "r1"})
	b, _ := c.box(info.ID)
	b.files["/home/user/.claude/projects/p/s.jsonl"] = []byte("{}\n")
	b.files["/home/user/.claude/bin/claude"] = []byte("binary")
	b.files["/home/user/secret.jsonl"] = []byte("nope")
	obs := t.TempDir()
	plan := hostedPlanFile{RunID: "r1", ObserverDir: obs, ToolStateRel: []string{".claude"}}
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	res, err := hostedPullTranscripts(context.Background(), c, info.ID, plan, v.Layout("/w/p"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pulled) != 1 || !strings.HasSuffix(res.Pulled[0], filepath.Join("r1", "0", "projects", "p", "s.jsonl")) {
		t.Fatalf("pulled %v", res.Pulled)
	}
	if fi, err := os.Stat(res.Pulled[0]); err != nil || (posixModes && fi.Mode().Perm() != 0o600) {
		t.Errorf("mode %v %v", fi, err)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Reason != sandboxremote.SkipNotTrans {
		t.Errorf("skipped %v", res.Skipped)
	}
}

func TestHostedQuarantineWriteConfined(t *testing.T) {
	dir := t.TempDir()
	for _, rel := range []string{"../x.jsonl", "/abs.jsonl", "."} {
		if _, err := hostedQuarantineWrite(dir, rel, nil); err == nil {
			t.Errorf("%q accepted", rel)
		}
	}
	outside := t.TempDir()
	if err := testSymlink(t, outside, filepath.Join(dir, "0")); err != nil {
		t.Fatal(err)
	}
	if _, err := hostedQuarantineWrite(dir, "0/a.jsonl", []byte("x")); err == nil {
		t.Error("written through a planted directory link")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Error("a file landed outside the quarantine")
	}
}

// TestHostedIngestRekeys: pulled transcripts land with every session and
// event id under the run, so they can never collide with a local session.
func TestHostedIngestRekeys(t *testing.T) {
	ctx := context.Background()
	d, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "simple-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	q := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(q, src, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := hostedIngestPulled(store.New(d))(ctx, "claude-code", hostedCaptureRuns{Run: "runA"}, []string{q})
	if err != nil || out.Actions == 0 {
		t.Fatalf("ingested %d %v", out.Actions, err)
	}
	if !slices.Equal(out.Sessions, []string{"sess-001"}) {
		t.Errorf("the agent's sessions %v, want [sess-001] (before the re-key)", out.Sessions)
	}
	var plain, keyed int
	rows, err := d.QueryContext(ctx, `SELECT session_id FROM actions`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var s sql.NullString
		_ = rows.Scan(&s)
		if strings.HasPrefix(s.String, "rsbx-runA-") {
			keyed++
		} else {
			plain++
		}
	}
	if keyed == 0 || plain != 0 {
		t.Errorf("keyed %d plain %d", keyed, plain)
	}
	again, err := hostedIngestPulled(store.New(d))(ctx, "claude-code", hostedCaptureRuns{Run: "runA"}, []string{q})
	if err != nil || again.Actions != 0 {
		t.Errorf("a second pull re-inserted %d (%v)", again.Actions, err)
	}
}
