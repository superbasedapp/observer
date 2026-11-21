package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/db"
)

type fakeKeyGov struct{ hidden, readOnly map[string]bool }

func (g fakeKeyGov) IsSettingsSectionHidden(s string) bool   { return g.hidden[s] }
func (g fakeKeyGov) IsSettingsSectionReadOnly(s string) bool { return g.readOnly[s] }

func configSetFixture(t *testing.T) (string, config.Config) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	body := "# keep me\n[observer]\nlog_level = \"warn\"\n\n[email]\npassword = \"plain-cli-password\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatal(err)
	}
	return path, cfg
}

// TestPlanConfigSet pins `observer config set` to the dashboard's checks.
func TestPlanConfigSet(t *testing.T) {
	_, cfg := configSetFixture(t)
	gov := fakeKeyGov{readOnly: map[string]bool{"watcher": true}}
	cases := []struct {
		name, key, value string
		gov              interface {
			IsSettingsSectionHidden(string) bool
			IsSettingsSectionReadOnly(string) bool
		}
		confirmed bool
		wantErr   string
	}{
		{name: "plain key", key: "observer.log_level", value: "debug"},
		{name: "credential refused", key: "email.password", value: "x", wantErr: "credential"},
		{name: "owned elsewhere refused", key: "org_client.enabled", value: "true", wantErr: "owned by"},
		{name: "sensitive needs --yes", key: "observer.secrets.enable_scrubbing", value: "false", wantErr: "--yes"},
		{name: "sensitive with --yes", key: "observer.secrets.enable_scrubbing", value: "false", confirmed: true},
		{name: "read-only section on a managed machine", key: "observer.watch.poll_interval_seconds", value: "9", gov: gov, wantErr: "pinned by your organization"},
		{name: "unknown key", key: "no.such.key", value: "1", wantErr: "unknown"},
		{name: "map entry", key: "profiles.by_tool.cline", value: "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var g fakeKeyGov
			var err error
			if tc.gov != nil {
				g = tc.gov.(fakeKeyGov)
				_, err = planConfigSet(cfg, tc.key, tc.value, g, tc.confirmed)
			} else {
				_, err = planConfigSet(cfg, tc.key, tc.value, nil, tc.confirmed)
			}
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestConfigSetDryRunThenWrite(t *testing.T) {
	path, cfg := configSetFixture(t)
	before, _ := os.ReadFile(path)
	p, err := planConfigSet(cfg, "observer.log_level", "debug", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := printConfigSetDryRun(&out, path, p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `+log_level = "debug"`) || strings.Contains(out.String(), "plain-cli-password") {
		t.Fatalf("dry run output:\n%s", out.String())
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("dry run wrote the file")
	}
	if err := writeConfigSet(path, p); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "# keep me") || !strings.Contains(string(got), `log_level = "debug"`) {
		t.Fatalf("written file lost comments or the value:\n%s", got)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatal("a write keeps a backup")
	}
}

// TestConfigSetPostureRules pins the T-395 table one row per case: a posture
// the CLI cannot read refuses (fail closed); every state that saved before
// still saves.
func TestConfigSetPostureRules(t *testing.T) {
	cases := []struct {
		name string
		in   configSetPostureInput
		want configSetPostureVerdict
	}{
		{"no database (never enrolled) saves", configSetPostureInput{}, postureUngoverned},
		{"database that does not open refuses", configSetPostureInput{dbExists: true, dbErr: errors.New("locked")}, postureRefuse},
		{"unreadable enrolment refuses", configSetPostureInput{dbExists: true, lkg: lkgEnrolmentUnreadable}, postureRefuse},
		{"applied policy that does not verify refuses", configSetPostureInput{dbExists: true, lkg: lkgUnverified}, postureRefuse},
		{"installed policy with visibility is checked per key", configSetPostureInput{dbExists: true, lkg: lkgInstalled, visibility: true}, postureGoverned},
		{"installed policy without visibility saves", configSetPostureInput{dbExists: true, lkg: lkgInstalled}, postureUngoverned},
		{"not enrolled saves", configSetPostureInput{dbExists: true, lkg: lkgNotEnrolled}, postureUngoverned},
		{"enrolled with no policy ever applied saves", configSetPostureInput{dbExists: true, lkg: lkgNoPolicy}, postureUngoverned},
		{"governance family not accepted by the operator saves", configSetPostureInput{dbExists: true, lkg: lkgFamilyNotAccepted}, postureUngoverned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, msg := resolveConfigSetPosture(tc.in)
			if got != tc.want {
				t.Fatalf("verdict = %v, want %v (%s)", got, tc.want, msg)
			}
			if got == postureRefuse && !strings.Contains(msg, "nothing was written") {
				t.Fatalf("a refusal must say nothing was written: %q", msg)
			}
		})
	}
}

// runConfigSetDryRun runs `observer config set --dry-run` against a config
// whose database path is dbPath. --dry-run never pokes a daemon.
func runConfigSetDryRun(t *testing.T, dbPath string) (string, error) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	body := "[observer]\nlog_level = \"warn\"\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newConfigSetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--config", cfgPath, "--dry-run", "observer.log_level", "debug"})
	err := cmd.Execute()
	if after, _ := os.ReadFile(cfgPath); string(after) != body {
		t.Fatalf("a dry run must never write:\n%s", after)
	}
	return out.String(), err
}

// TestConfigSetFailsClosedOnUnreadableDatabase is the T-395 red/green: an
// existing database that does not open used to be "checked as an unmanaged
// machine" and the set went ahead; now it refuses with an honest error.
func TestConfigSetFailsClosedOnUnreadableDatabase(t *testing.T) {
	// A directory where the database file should be: it exists, and it
	// never opens as SQLite.
	dbDir := filepath.Join(t.TempDir(), "observer.db")
	if err := os.Mkdir(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := runConfigSetDryRun(t, dbDir)
	if err == nil || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("want a fail-closed refusal, got err=%v out=%s", err, out)
	}
	if strings.Contains(out, "unmanaged") {
		t.Fatalf("must never claim an unmanaged check: %s", out)
	}
}

// TestConfigSetStillSavesWhenUngoverned: the saves that were valid before
// T-395 still go through (no database; a database that is not enrolled).
func TestConfigSetStillSavesWhenUngoverned(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "never-created.db")
	if out, err := runConfigSetDryRun(t, missing); err != nil || !strings.Contains(out, `+log_level = "debug"`) {
		t.Fatalf("no database: err=%v out=%s", err, out)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("config set must never create the database")
	}

	fresh := filepath.Join(t.TempDir(), "observer.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: fresh})
	if err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	if out, err := runConfigSetDryRun(t, fresh); err != nil || !strings.Contains(out, `+log_level = "debug"`) {
		t.Fatalf("not enrolled: err=%v out=%s", err, out)
	}
}

// TestPlanConfigSetNumericLeaves pins `observer config set` (and MCP
// set_setting, which plans through the same function) for numeric keys of
// every Go width the config uses: the value is read back with
// configschema.Get in the field's own type, so validation and the surgical
// TOML scalar must accept int as well as int64. Before the fix every plain
// int key was refused with "wants an integer".
func TestPlanConfigSetNumericLeaves(t *testing.T) {
	cases := []struct {
		name, key, value string
		confirmed        bool
		wantRHS          string
		wantErr          string
	}{
		{name: "int leaf", key: "observability.alerts.eval_interval_minutes", value: "7", wantRHS: "7"},
		{name: "int64 leaf", key: "guidance.max_file_bytes", value: "65536", wantRHS: "65536"},
		{name: "float64 leaf", key: "compression.conversation.target_ratio", value: "0.4", wantRHS: "0.4"},
		{name: "bounded int leaf in range", key: "digest.send_hour", value: "23", confirmed: true, wantRHS: "23"},
		{name: "bounded int leaf above max", key: "digest.send_hour", value: "24", confirmed: true, wantErr: "must be <= 23"},
		{name: "bounded float leaf above max", key: "compression.conversation.target_ratio", value: "1.5", wantErr: "must be <= 1"},
		{name: "int leaf given a fraction", key: "observability.alerts.eval_interval_minutes", value: "7.5", wantErr: "observability.alerts.eval_interval_minutes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := planConfigSet(config.Default(), tc.key, tc.value, nil, tc.confirmed)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !p.patch.Scalar || p.patch.RHS != tc.wantRHS {
				t.Fatalf("patch = %+v; want a surgical scalar %q", p.patch, tc.wantRHS)
			}
			leaf, _ := configschema.Lookup(tc.key)
			if got := fmt.Sprint(configschema.Get(&p.cfg, leaf)); got != tc.wantRHS {
				t.Fatalf("planned config holds %s = %s; want %s", tc.key, got, tc.wantRHS)
			}
		})
	}
}
