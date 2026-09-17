package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// runAggregate executes `observer aggregate <args...>` against an isolated
// config file, capturing combined output.
func runAggregate(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newAggregateCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetIn(strings.NewReader("")) // no interactive input; tests use --yes
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// TestAggregateEnableSubmitDisableFlow exercises the whole Phase-3 gate: enable
// records consent + flips config, a dry-run submit is authorized, and disable
// revokes consent so a later submit is refused. Everything runs against a temp
// config + db (no network — submit uses --dry-run).
func TestAggregateEnableSubmitDisableFlow(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	cfgPath := filepath.Join(dir, "config.toml")

	// A minimal config: db_path + the default (approved-host) endpoint, rail off.
	body := "[observer]\ndb_path = \"" + dbPath + "\"\n\n[aggregate_share]\nenabled = false\nendpoint = \"" + config.DefaultAggregateEndpoint + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Ensure the db exists (loadConfigAndDB opens it; migrations create tables).
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	database.Close()

	// Before consent: submit --dry-run is refused.
	if out, err := runAggregate(t, "submit", "--dry-run", "--config", cfgPath); err == nil {
		t.Fatalf("submit before consent should fail; out=%s", out)
	}

	// enable --yes records a receipt and flips enabled=true.
	out, err := runAggregate(t, "enable", "--yes", "--config", cfgPath)
	if err != nil {
		t.Fatalf("enable: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ENABLED") {
		t.Errorf("enable output missing confirmation: %s", out)
	}
	loaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.AggregateShare.Enabled {
		t.Fatal("enable did not persist enabled=true to config.toml")
	}

	// status now shows a valid consent.
	out, err = runAggregate(t, "status", "--config", cfgPath)
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if !strings.Contains(out, "consent:       valid") {
		t.Errorf("status should report valid consent: %s", out)
	}

	// submit --dry-run is now authorized (no network, nothing sent).
	out, err = runAggregate(t, "submit", "--dry-run", "--config", cfgPath)
	if err != nil {
		t.Fatalf("dry-run submit after consent: %v\n%s", err, out)
	}
	if !strings.Contains(out, "[dry-run]") || !strings.Contains(out, "Nothing sent") {
		t.Errorf("dry-run submit output unexpected: %s", out)
	}

	// disable revokes consent + flips enabled=false.
	if out, err := runAggregate(t, "disable", "--config", cfgPath); err != nil {
		t.Fatalf("disable: %v\n%s", err, out)
	}
	loaded, err = config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AggregateShare.Enabled {
		t.Fatal("disable did not persist enabled=false")
	}

	// After disable, submit is refused again.
	if out, err := runAggregate(t, "submit", "--dry-run", "--config", cfgPath); err == nil {
		t.Fatalf("submit after disable should fail; out=%s", out)
	}
}

// TestAggregatePreviewNoNetwork confirms preview is pure-local and works with
// the rail off (no consent required).
func TestAggregatePreviewNoNetwork(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+dbPath+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	database.Close()

	out, err := runAggregate(t, "preview", "--config", cfgPath)
	if err != nil {
		t.Fatalf("preview: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Exact JSON that WOULD be submitted") {
		t.Errorf("preview output unexpected: %s", out)
	}
}
