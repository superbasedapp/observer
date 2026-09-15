package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCloudWorkOSClientIDKey pins [cloud].workos_client_id: the compiled-in
// public production default by default (DefaultCloudWorkOSClientID, seeded by
// Default()), overridden by a value read from a partial [cloud] section, with
// the partial merge leaving the other keys untouched.
func TestCloudWorkOSClientIDKey(t *testing.T) {
	t.Parallel()
	if c := Default().Cloud; c.WorkOSClientID != DefaultCloudWorkOSClientID {
		t.Fatalf("workos_client_id default = %q, want compiled default %q", c.WorkOSClientID, DefaultCloudWorkOSClientID)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[cloud]\nworkos_client_id = \"client_01ABC\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Cloud.WorkOSClientID != "client_01ABC" {
		t.Errorf("workos_client_id = %q, want client_01ABC", cfg.Cloud.WorkOSClientID)
	}
	if cfg.Cloud.BaseURL != "" || cfg.Cloud.LoginPort != 0 || cfg.Cloud.AutoSync || cfg.Cloud.AutoEnrich {
		t.Errorf("partial [cloud] merge disturbed siblings: %+v", cfg.Cloud)
	}
	if err := Validate(cfg); err != nil {
		t.Errorf("a client id alone must validate: %v", err)
	}
}

// TestCloudWorkOSClientIDExplicitEmptyClearsDefault pins the loader's
// partial-merge semantics for this key specifically: a key OMITTED from
// config.toml keeps the compiled default (an operator never has to write it
// out to sign in), but a key PRESENT with an explicit empty value overrides
// the default and opts back out to the unconfigured state. This is ordinary
// BurntSushi/toml decode-into-existing-struct behaviour (a key present in the
// document is always applied, even when its value equals the zero value) —
// not special-cased code, so this test is the guardrail against that
// semantics silently changing underneath the compiled default.
func TestCloudWorkOSClientIDExplicitEmptyClearsDefault(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Case 1: [cloud] present but the key omitted entirely -> default holds.
	omittedPath := filepath.Join(dir, "omitted.toml")
	if err := os.WriteFile(omittedPath, []byte("[cloud]\nbase_url = \"https://example.test\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: omittedPath})
	if err != nil {
		t.Fatalf("load (omitted key): %v", err)
	}
	if cfg.Cloud.WorkOSClientID != DefaultCloudWorkOSClientID {
		t.Errorf("omitted key: workos_client_id = %q, want compiled default %q", cfg.Cloud.WorkOSClientID, DefaultCloudWorkOSClientID)
	}

	// Case 2: the key present with an explicit empty string -> cleared.
	clearedPath := filepath.Join(dir, "cleared.toml")
	if err := os.WriteFile(clearedPath, []byte("[cloud]\nworkos_client_id = \"\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err = Load(LoadOptions{GlobalPath: clearedPath})
	if err != nil {
		t.Fatalf("load (explicit empty): %v", err)
	}
	if cfg.Cloud.WorkOSClientID != "" {
		t.Errorf("explicit empty key: workos_client_id = %q, want empty (opted out)", cfg.Cloud.WorkOSClientID)
	}
}
