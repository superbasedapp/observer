//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_hosted_leftsbx_test.go: lane LEFT-SBX milestone 4, the
// hosted rows' in-run reattach (held dark) and the in-box database export.

// TestHostedInRunReattach: when the transport of a kept guest PTY is cut, the
// run re-attaches its terminal with the keeper-only key kept at home; an
// attach the keeper refuses (it still sees the old home stream, the attach
// verb exits with the helper failure code) is retried, and the run survives
// with the agent's own exit status. With no keeper key nothing is tried.
func TestHostedInRunReattach(t *testing.T) {
	obs := t.TempDir()
	var out bytes.Buffer
	r := &hostedRun{plan: hostedPlanFile{RunID: "run-a", ObserverDir: obs}, t: hostedTerm{out: &out}}
	prevTries, prevWait, prevAttach := hostedInRunReattachTries, hostedInRunReattachWait, hostedInRunAttach
	t.Cleanup(func() {
		hostedInRunReattachTries, hostedInRunReattachWait, hostedInRunAttach = prevTries, prevWait, prevAttach
	})
	hostedInRunReattachTries, hostedInRunReattachWait = 3, time.Millisecond
	if _, ok := r.reattachInRun(context.Background(), nil); ok || !strings.Contains(out.String(), "keeper key cannot be read") {
		t.Fatalf("no keeper key: %q", out.String())
	}
	key := bytes.Repeat([]byte{7}, 32)
	if err := hostedSaveKeeperKey(obs, "run-a", key); err != nil {
		t.Fatal(err)
	}
	var calls int
	hostedInRunAttach = func(_ context.Context, _ *hostedRun, got []byte, _ func(*relaymux.Host)) (int, error) {
		calls++
		if !bytes.Equal(got, key) {
			t.Errorf("the attach got another key")
		}
		if calls == 1 {
			return sandboxHelperFailCode, nil // busy: the old home stream is still alive to the keeper
		}
		return 7, nil
	}
	code, ok := r.reattachInRun(context.Background(), nil)
	if !ok || code != 7 || calls != 2 {
		t.Fatalf("code %d ok %v calls %d", code, ok, calls)
	}
	calls = 0
	hostedInRunAttach = func(context.Context, *hostedRun, []byte, func(*relaymux.Host)) (int, error) {
		calls++
		return sandboxHelperFailCode, nil
	}
	if _, ok := r.reattachInRun(context.Background(), nil); ok || calls != 3 {
		t.Fatalf("a keeper that never lets go: ok %v after %d tries", ok, calls)
	}
}

// TestHostedExportBoxDatabases (lane LEFT-SBX, the in-box database export):
// at teardown the guest db-copy one-shot runs for each tool state directory
// and the host keeps only the copies the one-shot names, with a SQLite
// header, under the cap, owner-only and after quick_check; a forged name, a
// file with no SQLite header and a manifest-only directory are skipped and
// said.
func TestHostedExportBoxDatabases(t *testing.T) {
	obs := t.TempDir()
	// A real SQLite store, as the one-shot would leave it.
	src := filepath.Join(t.TempDir(), "s.db")
	sdb, err := sql.Open("sqlite", "file:"+src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdb.Exec("CREATE TABLE t(x); INSERT INTO t VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	_ = sdb.Close()
	store, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	c := newFakeBoxClient()
	info, err := c.Create(context.Background(), sandboxremote.BoxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := sandboxremote.VendorFor("modal")
	layout := v.Layout("/w")
	good := sandbox.DBCopyName("projects/x.db")
	c.execs = func(b *fakeBox, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
		if len(spec.Argv) >= 3 && spec.Argv[1] == "sandbox-guest" && spec.Argv[2] == sandbox.GuestDBCopy {
			out := spec.Argv[len(spec.Argv)-1]
			if !strings.HasSuffix(out, "dbcopy-0") {
				return newFakeProcess("", 1), nil // no such state directory
			}
			m, _ := json.Marshal(sandbox.DBCopyManifest{Files: []sandbox.DBCopyEntry{
				{Rel: "projects/x.db", Name: good},
				{Rel: "projects/y.db", Name: strings.Repeat("a", 64) + ".db"}, // not the name of y.db
				{Rel: "notes.db", Name: sandbox.DBCopyName("notes.db")},
			}})
			c.mu.Lock()
			b.files[out+"/"+sandbox.DBCopyManifestName] = m
			b.files[out+"/"+good] = store
			b.files[out+"/"+sandbox.DBCopyName("notes.db")] = []byte("not a database")
			c.mu.Unlock()
			return newFakeProcess("", 0), nil
		}
		return newFakeProcess("", 0), nil
	}
	var out bytes.Buffer
	r := &hostedRun{
		plan: hostedPlanFile{RunID: "run-a", ObserverDir: obs, Tool: "claude-code"}, t: hostedTerm{out: &out},
		client: c, rec: sandboxremote.Record{RunID: "run-a", VendorID: info.ID}, layout: layout, vendor: v,
	}
	r.exportBoxDatabases(context.Background())
	kept := filepath.Join(hostedDBExportDir(obs, "run-a"), "0", good)
	fi, err := os.Stat(kept)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the good copy: %v %v", fi, err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(kept)); len(entries) != 1 {
		t.Fatalf("kept %d files, want only the good copy", len(entries))
	}
	for _, want := range []string{"1 SQLite store(s)", "not a name the one-shot makes", "not a SQLite file"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the terminal does not say %q: %q", want, out.String())
		}
	}
}

// TestHostedTeardownSlowExportStillDeletes (the LEFT-SBX merge, audit
// finding 2): an export that runs until its deadline (and past it, ignoring
// it) neither delays the export's own deadline beyond its bound nor spends
// the delete's time: the box is still deleted, confirmed, and the record
// removed.
func TestHostedTeardownSlowExportStillDeletes(t *testing.T) {
	obs := t.TempDir()
	c := newFakeBoxClient()
	info, err := c.Create(context.Background(), sandboxremote.BoxSpec{TimeoutSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	oldExport, oldE := hostedTeardownExport, hostedTeardownExportTimeout
	t.Cleanup(func() { hostedTeardownExport, hostedTeardownExportTimeout = oldExport, oldE })
	hostedTeardownExportTimeout = 50 * time.Millisecond
	var exportErr error
	hostedTeardownExport = func(ctx context.Context, _ *hostedRun) {
		<-ctx.Done() // a slow export: it runs until its deadline
		exportErr = ctx.Err()
		time.Sleep(20 * time.Millisecond) // and a little past it
	}
	var out bytes.Buffer
	r := &hostedRun{
		plan: hostedPlanFile{RunID: "run-slow", ObserverDir: obs, Tool: "claude-code", DBExport: true}, t: hostedTerm{out: &out},
		client: c, rec: sandboxremote.Record{RunID: "run-slow", VendorID: info.ID, State: sandboxremote.StateRunning},
		now: time.Now, start: time.Now(),
	}
	done := make(chan struct{})
	go func() { r.teardown(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the teardown did not finish")
	}
	if exportErr != context.DeadlineExceeded {
		t.Fatalf("the export ran without its own deadline: %v", exportErr)
	}
	if _, err := c.box(info.ID); err == nil {
		t.Fatalf("the box was not deleted after a slow export: %q", out.String())
	}
	if !strings.Contains(out.String(), "was deleted (confirmed") {
		t.Errorf("the terminal does not say the delete was confirmed: %q", out.String())
	}
}

// TestHostedDBExportIsOptIn (ruling P-141): with db_export off (the
// default) the teardown never runs the in-box export; with it on, it does.
func TestHostedDBExportIsOptIn(t *testing.T) {
	old := hostedTeardownExport
	t.Cleanup(func() { hostedTeardownExport = old })
	for _, on := range []bool{false, true} {
		ran := false
		hostedTeardownExport = func(context.Context, *hostedRun) { ran = true }
		c := newFakeBoxClient()
		info, err := c.Create(context.Background(), sandboxremote.BoxSpec{TimeoutSeconds: 600})
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		r := &hostedRun{
			plan: hostedPlanFile{RunID: "run-optin", ObserverDir: t.TempDir(), Tool: "claude-code", DBExport: on}, t: hostedTerm{out: &out},
			client: c, rec: sandboxremote.Record{RunID: "run-optin", VendorID: info.ID, State: sandboxremote.StateRunning},
			now: time.Now, start: time.Now(),
		}
		r.teardown(context.Background())
		if ran != on {
			t.Errorf("db_export %v: the export ran %v", on, ran)
		}
	}
	if config.Default().Terminal.Sandbox.Hosted.DBExport {
		t.Error("db_export is on by default")
	}
}

// TestHostedDBExportSweptByRetention (ruling P-141): earlier runs' exported
// copies are removed once their newest write is older than
// workspace_retention_days; a fresh run's copies, the current run's and a
// symlinked entry are kept, and 0 keeps everything.
func TestHostedDBExportSweptByRetention(t *testing.T) {
	obs := t.TempDir()
	root := filepath.Join(hostedStateDir(obs), "dbcopies")
	now := time.Now()
	mk := func(run string, age time.Duration) string {
		dir := filepath.Join(root, run, "0")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(dir, "a.db")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{f, dir, filepath.Dir(dir)} {
			if err := os.Chtimes(p, now.Add(-age), now.Add(-age)); err != nil {
				t.Fatal(err)
			}
		}
		return filepath.Dir(dir)
	}
	old := mk("run-old", 10*24*time.Hour)
	fresh := mk("run-fresh", time.Hour)
	current := mk("run-now", 10*24*time.Hour)
	target := t.TempDir()
	if err := testSymlink(t, target, filepath.Join(root, "run-link")); err != nil {
		t.Fatal(err)
	}
	if n, err := hostedSweepDBExports(obs, "run-now", now, 0); n != 0 || err != nil {
		t.Fatalf("retention 0 swept %d %v", n, err)
	}
	n, err := hostedSweepDBExports(obs, "run-now", now, 7)
	if n != 1 || err != nil {
		t.Fatalf("swept %d %v, want 1", n, err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("the old run's copies were kept")
	}
	for _, keep := range []string{fresh, current, target, filepath.Join(root, "run-link")} {
		if _, err := os.Lstat(keep); err != nil {
			t.Errorf("%s was removed: %v", keep, err)
		}
	}
}

// TestHostedRefusesInternetTierUnderEgressHostList (the LEFT-SBX merge,
// audit finding 4): while [terminal.sandbox].egress_allow_hosts is set, or
// an org pin left no host in common (PinnedNoEgressHost), an E2B, Modal or
// Vercel launch on the internet tier is refused naming the key; proxy_only
// and none are not refused for it, and with neither set internet is not.
func TestHostedRefusesInternetTierUnderEgressHostList(t *testing.T) {
	list := config.TerminalSandboxConfig{EgressAllowHosts: []string{"api.example.com"}}
	pinned := config.TerminalSandboxConfig{PinnedNoEgressHost: "terminal.sandbox.egress_allow_hosts"}
	cases := []struct {
		name   string
		cfg    config.TerminalSandboxConfig
		tier   vocab.Tier
		refuse string // the key the refusal names, "" = not refused for it
	}{
		{"list, internet", list, vocab.TierInternet, "[terminal.sandbox].egress_allow_hosts"},
		{"org pin, internet", pinned, vocab.TierInternet, "pin of terminal.sandbox.egress_allow_hosts"},
		{"list, proxy_only", list, vocab.TierProxyOnly, ""},
		{"org pin, none", pinned, vocab.TierNone, ""},
		{"no list, internet", config.TerminalSandboxConfig{}, vocab.TierInternet, ""},
	}
	for _, vid := range []string{sandboxbackend.BackendE2B, sandboxbackend.BackendModal, sandboxbackend.BackendVercelSandbox} {
		v, ok := sandboxremote.VendorFor(vid)
		if !ok {
			t.Fatalf("no vendor %s", vid)
		}
		d := &hostedDriver{vendor: v}
		for _, c := range cases {
			cfg := c.cfg
			cfg.Enabled = true
			cfg.Backends = []string{vid}
			err := d.floor(cfg, c.tier, vocab.CustodyInBoxAPIKey, "")
			named := err != nil && strings.Contains(err.Error(), "cannot honour a host list")
			switch {
			case c.refuse != "" && (!named || !strings.Contains(err.Error(), c.refuse) || !strings.Contains(err.Error(), sandboxselect.VerdictEgressUnsupported)):
				t.Errorf("%s %s: %v, want a refusal naming %q", vid, c.name, err, c.refuse)
			case c.refuse == "" && named:
				t.Errorf("%s %s: refused for the host list: %v", vid, c.name, err)
			}
		}
	}
}
