package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	for _, svc := range observerKeystoreServices {
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
	for _, svc := range observerKeystoreServices {
		if _, err := keystore.KeyringGet(svc, "rec"); !errors.Is(err, keystore.ErrKeyringNotFound) {
			t.Errorf("%s survived uninstall --all: %v", svc, err)
		}
	}
	setHome(other)
	if _, err := keystore.KeyringGet("sbo-change-record-v1", "change-key-other"); err != nil {
		t.Fatalf("another home's entry was removed: %v", err)
	}
}

// TestObserverKeystoreServicesAreListed: every keychain service name the
// source declares is in observerKeystoreServices, so uninstall removes it.
func TestObserverKeystoreServicesAreListed(t *testing.T) {
	root := filepath.Join("..", "..")
	re := regexp.MustCompile(`(?i)(KeystoreService|ServiceName|KeychainID)\b[^"\n]*"(sbo-[a-z0-9-]+-v[0-9]+)"`)
	seen := map[string]string{}
	for _, dir := range []string{"cmd", "internal"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.Contains(p, "orgserver") {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			for _, m := range re.FindAllStringSubmatch(string(b), -1) {
				seen[m[2]] = p
			}
			return nil
		})
	}
	if len(seen) < 6 {
		t.Fatalf("the scan found only %v", seen)
	}
	for svc, at := range seen {
		if !slices.Contains(observerKeystoreServices, svc) {
			t.Errorf("%s (declared in %s) is not in observerKeystoreServices", svc, at)
		}
	}
}
