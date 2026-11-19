//go:build linux && !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
)

// Live run 2026-11-19, defect D9: keys pasted through wsl.exe from Windows
// PowerShell were refused with one message listing every rule.

// TestCredAddCleansAPasteAndNamesTheBrokenRule: a key wrapped the way a
// terminal paste wraps it is stored clean, and a bad key is refused naming
// its one rule, never the key.
func TestCredAddCleansAPasteAndNamesTheBrokenRule(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	const key = "sk-ant-api03-pasteTEST_0123456789"
	if err := credAdd(obs, "anthropic", "\x1b[200~"+key+"\r\n\x1b[201~"); err != nil {
		t.Fatalf("a bracketed paste was refused: %v", err)
	}
	if got, _ := ks.Get(sandboxcred.KeyName("anthropic")); got != key {
		t.Fatalf("stored %q", got)
	}
	cases := []struct{ raw, rule string }{
		{"\r", "nothing was read"},
		{"sk-ant api03", "holds a space"},
		{"sk-ant\napi03", "holds a line break"},
		{sandboxcred.SentinelPrefix + "anthropic-1", "sentinel"},
	}
	for _, c := range cases {
		err := credAdd(obs, "anthropic", c.raw)
		if err == nil || !strings.Contains(err.Error(), c.rule) {
			t.Errorf("%q: %v, want the rule %q", c.raw, err, c.rule)
			continue
		}
		if strings.Contains(err.Error(), "sk-ant") {
			t.Errorf("%q: the error quotes the key: %v", c.raw, err)
		}
	}
}

// TestCredReadPastedAsksAgainAfterAnEmptyRead: an Enter that arrives before
// the paste (an empty read, or only the paste markers) asks again instead of
// refusing; the third empty read is returned for the check to name.
func TestCredReadPastedAsksAgainAfterAnEmptyRead(t *testing.T) {
	reads := [][]byte{[]byte(""), []byte("\x1b[200~\x1b[201~"), []byte("\x1b[200~xai-KEY123\x1b[201~")}
	var out bytes.Buffer
	i := 0
	got, err := credReadPasted(&out, func() ([]byte, error) { b := reads[i]; i++; return b, nil })
	if err != nil || sandboxcred.CleanPastedKey(got) != "xai-KEY123" || i != 3 {
		t.Fatalf("got %q after %d reads, %v", got, i, err)
	}
	if strings.Count(out.String(), "Paste the key again") != 2 {
		t.Fatalf("prompts %q", out.String())
	}
	i = 0
	empty := func() ([]byte, error) { i++; return nil, nil }
	if got, _ := credReadPasted(&bytes.Buffer{}, empty); got != "" || i != credPasteTries {
		t.Fatalf("empty reads: %q after %d", got, i)
	}
}

// TestCredStoreLineSaysTheFileStorePlainly: on a machine with no OS
// keychain (WSL), list says the keys are in owner-only files, not encrypted
// by the OS.
func TestCredStoreLineSaysTheFileStorePlainly(t *testing.T) {
	if got := credStoreLine("file", "credentials are stored in 0600 files at /x"); !strings.Contains(got, "no OS keychain") || !strings.Contains(got, "0600 files") {
		t.Fatalf("file: %q", got)
	}
	if got := credStoreLine("keychain", ""); got != "store: the OS keychain" {
		t.Fatalf("keychain: %q", got)
	}
}
