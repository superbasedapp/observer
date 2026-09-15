package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

func runConfigCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// Never poke a real daemon from tests (WSL2 forwards localhost).
	orig := pokeReload
	pokeReload = func() bool { return false }
	t.Cleanup(func() { pokeReload = orig })
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"config"}, args...))
	err := root.Execute()
	return out.String(), err
}

// TestConfigSet_Global pins the global front door: dotted keys land
// in config.toml through the shared write owner, round-trip through
// config.Load, and invalid values are refused pre-write.
func TestConfigSet_Global(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	out, err := runConfigCmd(t, "set", "compression.conversation.target_ratio", "0.7", "--config", cfgPath)
	if err != nil {
		t.Fatalf("set: %v\n%s", err, out)
	}
	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Compression.Conversation.TargetRatio != 0.7 {
		t.Errorf("persisted ratio: got %v", reloaded.Compression.Conversation.TargetRatio)
	}

	if _, err := runConfigCmd(t, "set", "proxy.port", "99999999", "--config", cfgPath); err == nil {
		t.Error("invariant-violating value must be refused (Validate before write)")
	}
	if _, err := runConfigCmd(t, "set", "no.such.key", "1", "--config", cfgPath); err == nil {
		t.Error("unknown key must error")
	}
}

// TestConfigSet_Project pins the --project front door: keys land in
// the repo-local override file; daemon-level keys are refused.
func TestConfigSet_Project(t *testing.T) {
	repo := t.TempDir()
	out, err := runConfigCmd(t, "set", "--project", repo, "compression.conversation.enabled", "false")
	if err != nil {
		t.Fatalf("project set: %v\n%s", err, out)
	}
	if !strings.Contains(out, "NEW sessions automatically") {
		t.Errorf("project set should explain the no-restart pickup:\n%s", out)
	}
	raw, err := os.ReadFile(filepath.Join(repo, ".observer", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	base := config.Default().Compression
	base.Conversation.Enabled = true
	got, err := config.ProjectCompression(base, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Conversation.Enabled {
		t.Error("project off-switch did not land")
	}

	if _, err := runConfigCmd(t, "set", "--project", repo, "observer.db_path", "/evil"); err == nil {
		t.Error("daemon-level key must be refused in a project file")
	}
}

// TestConfigAdoptDefaults_NoConfigFile pins the honest no-op when
// there's nothing on disk to adopt into.
func TestConfigAdoptDefaults_NoConfigFile(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	out, err := runConfigCmd(t, "adopt-defaults", "--config", cfgPath)
	if err != nil {
		t.Fatalf("adopt-defaults: %v\n%s", err, out)
	}
	if !strings.Contains(out, "nothing to adopt") {
		t.Errorf("missing-file run should say nothing to adopt:\n%s", out)
	}
	if _, statErr := os.Stat(cfgPath); statErr == nil {
		t.Error("adopt-defaults must never create a config file")
	}
}

// TestConfigAdoptDefaults_NoExplicitList pins the honest no-op when
// config.toml exists but never set enabled_adapters — Config.Default()
// already covers every default adapter, so there is nothing to adopt.
func TestConfigAdoptDefaults_NoExplicitList(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	body := "[observer]\ndb_path = \"/tmp/observer.db\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runConfigCmd(t, "adopt-defaults", "--config", cfgPath, "--write")
	if err != nil {
		t.Fatalf("adopt-defaults --write: %v\n%s", err, out)
	}
	if !strings.Contains(out, "nothing to adopt") {
		t.Errorf("no-explicit-key run should say nothing to adopt:\n%s", out)
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Error("adopt-defaults must not touch a file with no explicit enabled_adapters key")
	}
	if _, statErr := os.Stat(cfgPath + ".bak"); statErr == nil {
		t.Error("no backup should be written when nothing changed")
	}
}

// TestConfigAdoptDefaults_DryRunWritesNothing pins the DEFAULT-DRY-RUN
// posture (opposite of `config migrate`'s default): running without
// --write must report the gap but leave the file byte-identical.
func TestConfigAdoptDefaults_DryRunWritesNothing(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	body := "[observer.watch]\nenabled_adapters = [\"claude-code\", \"codex\"]\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runConfigCmd(t, "adopt-defaults", "--config", cfgPath)
	if err != nil {
		t.Fatalf("adopt-defaults: %v\n%s", err, out)
	}
	if !strings.Contains(out, "would add") {
		t.Errorf("dry-run should report what it would add:\n%s", out)
	}
	if !strings.Contains(out, "re-run with --write to apply") {
		t.Errorf("dry-run should point at --write:\n%s", out)
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Error("dry-run (no --write) must leave the file byte-identical")
	}
	if _, statErr := os.Stat(cfgPath + ".bak"); statErr == nil {
		t.Error("dry-run must not write a backup")
	}
}

// TestConfigAdoptDefaults_WriteAppendsAndBacksUp pins the --write path:
// missing default adapters are appended to the existing array (their
// order and formatting otherwise preserved) and a .bak backup lands
// before the write, mirroring `config migrate`'s backup convention.
func TestConfigAdoptDefaults_WriteAppendsAndBacksUp(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	body := "[observer.watch]\nenabled_adapters = [\"claude-code\", \"codex\"]\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runConfigCmd(t, "adopt-defaults", "--config", cfgPath, "--write")
	if err != nil {
		t.Fatalf("adopt-defaults --write: %v\n%s", err, out)
	}
	if !strings.Contains(out, "added") {
		t.Errorf("--write should report what it added:\n%s", out)
	}
	if !strings.Contains(out, "backup written to "+cfgPath+".bak") {
		t.Errorf("--write should report the backup path:\n%s", out)
	}

	backup, err := os.ReadFile(cfgPath + ".bak")
	if err != nil {
		t.Fatalf("backup not written: %v", err)
	}
	if string(backup) != body {
		t.Error("backup must hold the pre-write content")
	}

	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"claude-code"`) || !strings.Contains(string(got), `"codex"`) {
		t.Errorf("write must preserve the operator's existing entries:\n%s", got)
	}
	if !strings.Contains(string(got), `"cline"`) {
		t.Errorf("write must append a currently-missing default adapter (cline):\n%s", got)
	}

	// Running again must be a no-op: every default is now present.
	out2, err := runConfigCmd(t, "adopt-defaults", "--config", cfgPath, "--write")
	if err != nil {
		t.Fatalf("adopt-defaults --write (second run): %v\n%s", err, out2)
	}
	if !strings.Contains(out2, "already lists every default adapter") {
		t.Errorf("second run should report nothing left to adopt:\n%s", out2)
	}
}
