//go:build !sbo_omit_ui_dashboard && !sbo_omit_org_update

package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestNoLiveRunGoldensUpdateApply: with a running daemon (its real dashboard
// route and update runtime over a fresh database, an unenrolled node) and no
// sandboxed run live, `observer update apply` prints what the pre-lane binary
// printed (testdata/liveruns_goldens/update-apply.stdout).
func TestNoLiveRunGoldensUpdateApply(t *testing.T) {
	saved := updateLiveDeferredHook.Load()
	t.Cleanup(func() { updateLiveDeferredHook.Store(saved) })
	home := t.TempDir()
	setTestHome(t, home)
	dir := filepath.Join(home, ".observer")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "observer.db")
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	cfg := config.Default()
	cfg.Update.Enabled = true
	u := newUpdateRuntime(cfg, "", store.New(database), nil, fakeSandboxManager{live: 0}, nil)
	if u == nil {
		t.Fatal("no update runtime")
	}
	srv, err := dashboard.New(dashboard.Options{DB: database, DBPath: dbPath, ConfigPath: filepath.Join(dir, "config.toml"), UpdateApplyFunc: u.ApplySeam()})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n\n[update]\nenabled = true\n\n[dashboard]\naddr = \"" + strings.TrimPrefix(ts.URL, "http://") + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newUpdateApplyCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--config", cfgPath})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("update apply: %v (stderr %q)", err, errOut.String())
	}
	// The daemon runs the accepted apply on its own goroutine; let it settle
	// (an unenrolled node has no target) before the database closes.
	deadline := time.Now().Add(10 * time.Second)
	for !u.applying.TryLock() {
		if time.Now().After(deadline) {
			t.Fatal("the detached apply never settled")
		}
		time.Sleep(20 * time.Millisecond)
	}
	u.applying.Unlock()
	if want := readLiveRunGolden(t, "update-apply.stdout"); out.String() != want || errOut.Len() != 0 {
		t.Fatalf("stdout = %q (stderr %q), want the pre-lane %q", out.String(), errOut.String(), want)
	}
}
