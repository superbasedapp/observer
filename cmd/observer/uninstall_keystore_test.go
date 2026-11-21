package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/keystore"
)

// TestUninstallAllRemovesThisHomesKeychainEntries: `observer uninstall
// --all` removes every keychain entry this Observer home wrote and none of
// another home's (Windows 11 Pro rerun 2026-10-25, D2: the entries stayed
// in the user's Credential Manager after the kit removed its homes).
func TestUninstallAllRemovesThisHomesKeychainEntries(t *testing.T) {
	setHome := func(dir string) {
		t.Setenv("HOME", dir)
		t.Setenv("USERPROFILE", dir)
		t.Setenv("APPDATA", filepath.Join(dir, "AppData", "Roaming"))
		t.Setenv("LOCALAPPDATA", filepath.Join(dir, "AppData", "Local"))
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	}
	other, mine := t.TempDir(), t.TempDir()
	setHome(other)
	if err := keystore.KeyringSet("sbo-change-record-v1", "change-key-other", "x"); err != nil {
		t.Fatal(err)
	}
	setHome(mine)
	for _, svc := range staticKeystoreServices() {
		if err := keystore.KeyringSet(svc, "rec", "x"); err != nil {
			t.Fatal(err)
		}
	}
	cmd := newUninstallCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--all"})
	_ = cmd.Execute()
	if !strings.Contains(out.String(), "keychain removed this home's entries") {
		t.Fatalf("uninstall --all said nothing about the keychain:\n%s", out.String())
	}
	for _, svc := range staticKeystoreServices() {
		if _, err := keystore.KeyringGet(svc, "rec"); !errors.Is(err, keystore.ErrKeyringNotFound) {
			t.Errorf("%s survived uninstall --all: %v", svc, err)
		}
	}
	setHome(other)
	if _, err := keystore.KeyringGet("sbo-change-record-v1", "change-key-other"); err != nil {
		t.Fatalf("another home's entry was removed: %v", err)
	}
}
