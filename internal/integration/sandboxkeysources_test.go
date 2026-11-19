package integration

import (
	"path"
	"slices"
	"strings"
	"testing"
)

// TestSandboxKeySourceRowsWellFormed: every saved-keys and login-seed row is
// grounded (a source and a date), names HOME-relative clean files inside
// the tool's own state, valid JSON pointers and known provider ids, and a
// login row never keeps a refresh token.
func TestSandboxKeySourceRowsWellFormed(t *testing.T) {
	t.Parallel()
	known := []string{"anthropic", "openai", "google", "xai", "openrouter"}
	inState := func(c Capability, f string) bool {
		for _, s := range c.Sandbox.StateRW {
			if f == s || strings.HasPrefix(f, s+"/") {
				return true
			}
		}
		return false
	}
	relOK := func(f string) bool {
		return f != "" && !path.IsAbs(f) && path.Clean(f) == f && !strings.HasPrefix(f, "..")
	}
	saved, login := SandboxKeySourceTools()
	if !slices.Contains(saved, "opencode") || !slices.Contains(login, "claude-code") {
		t.Fatalf("the grounded rows are opencode (saved keys) and claude-code (login seed): %v %v", saved, login)
	}
	for _, tool := range saved {
		c, _ := For(tool)
		s, _ := SandboxSavedKeysFor(tool)
		if !strings.Contains(s.Grounding, "read 20") {
			t.Errorf("%s: saved keys row has no dated source", tool)
		}
		for goos, f := range s.Files {
			if !relOK(f) || !inState(c, f) {
				t.Errorf("%s: saved keys file %q (%q) is not a HOME-relative file in the tool's state", tool, f, goos)
			}
		}
		for _, k := range s.Keys {
			if !slices.Contains(known, k.Provider) || !strings.HasPrefix(k.Pointer, "/") || (k.TypePointer != "" && !strings.HasPrefix(k.TypePointer, "/")) {
				t.Errorf("%s: saved key %+v", tool, k)
			}
		}
	}
	for _, tool := range login {
		c, _ := For(tool)
		l, _ := SandboxLoginSeedFor(tool)
		if !strings.Contains(l.Grounding, "read 20") || !relOK(l.File) || !inState(c, l.File) || l.Object == "" || l.Access == "" || l.Expiry == "" {
			t.Errorf("%s: login seed row %+v", tool, l)
		}
		for _, k := range l.Keep {
			if strings.Contains(strings.ToLower(k), "refresh") || k == l.Access {
				t.Errorf("%s: login seed keeps %q", tool, k)
			}
		}
	}
}
