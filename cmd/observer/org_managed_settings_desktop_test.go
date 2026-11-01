package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEmitManagedSettings_ClaudeDesktop pins CC-1b end to end: the route is
// an explicit admin option, it needs a credential helper, and with both it
// writes the Desktop policy on its three channels plus a README naming LC2.
func TestEmitManagedSettings_ClaudeDesktop(t *testing.T) {
	if _, err := runEmitManagedSettings(t, "--provider", "claude-desktop", "--credential-helper", "/usr/local/bin/k"); err == nil ||
		!strings.Contains(err.Error(), "desktop-gateway-route") {
		t.Fatalf("no explicit option: err = %v, want a refusal naming --desktop-gateway-route", err)
	}
	if _, err := runEmitManagedSettings(t, "--provider", "claude-desktop", "--desktop-gateway-route"); err == nil ||
		!strings.Contains(err.Error(), "credential helper") {
		t.Fatalf("no helper: err = %v, want a credential-helper refusal", err)
	}
	out := t.TempDir()
	stdout, err := runEmitManagedSettings(t, "--provider", "claude-desktop", "--desktop-gateway-route",
		"--credential-helper", "/usr/local/bin/k", "--credential-helper-windows", `C:\Org\k.exe`, "--credential-helper-arg", "--org", "--out", out)
	if err != nil {
		t.Fatalf("emit: %v\n%s", err, stdout)
	}
	for _, name := range []string{"managed-settings.json", "managed-settings.mobileconfig", "managed-settings.reg", "README.md"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}
	reg, _ := os.ReadFile(filepath.Join(out, "managed-settings.reg"))
	if len(reg) < 2 || reg[0] != 0xFF || reg[1] != 0xFE {
		t.Error("the .reg file is not UTF-16LE with a BOM")
	}
	js, _ := os.ReadFile(filepath.Join(out, "managed-settings.json"))
	for _, want := range []string{`"inferenceProvider": "gateway"`, `"inferenceCredentialHelper": "/usr/local/bin/k"`, `"--org"`} {
		if !strings.Contains(string(js), want) {
			t.Errorf("policy missing %s:\n%s", want, js)
		}
	}
	// A POSIX helper alone writes no Windows import (CC-1b follow-up).
	posixOnly := t.TempDir()
	if _, err := runEmitManagedSettings(t, "--provider", "claude-desktop", "--desktop-gateway-route",
		"--credential-helper", "/usr/local/bin/k", "--out", posixOnly); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(posixOnly, "managed-settings.reg")); !os.IsNotExist(err) {
		t.Errorf("a POSIX helper alone wrote a Windows import (err %v)", err)
	}
	readme, _ := os.ReadFile(filepath.Join(out, "README.md"))
	if !strings.Contains(string(readme), "Not live-verified (LC2)") {
		t.Errorf("README does not say the route is not live-verified:\n%s", readme)
	}
}
