package integration

import (
	"path"
	"strings"
	"testing"
)

// TestSandboxSignInRows pins the sign-in rows (lane BOXSIGNIN): each names
// clean HOME-relative files strictly inside one of the row's own StateRW
// entries, none of them a protected executed config, with the vendor
// document that names them; Claude Code and Codex are grounded.
func TestSandboxSignInRows(t *testing.T) {
	t.Parallel()
	got := SandboxSignInTools()
	for _, want := range []string{"claude-code", "codex"} {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		if !found {
			t.Errorf("%s has no grounded sign-in row", want)
		}
	}
	for _, tool := range got {
		c, _ := For(tool)
		s, _ := SandboxSignInFor(tool)
		if !strings.HasPrefix(s.DocURL, "https://") || s.Grounding == "" {
			t.Errorf("%s: sign-in row with no vendor document", tool)
		}
		for _, f := range s.Files {
			ok := f != "" && !path.IsAbs(f) && path.Clean(f) == f && !strings.HasPrefix(f, "..")
			inside := false
			for _, st := range c.Sandbox.StateRW {
				inside = inside || strings.HasPrefix(f, st+"/")
			}
			if !ok || !inside {
				t.Errorf("%s: sign-in file %q is not strictly inside a StateRW entry", tool, f)
			}
			for _, p := range c.Sandbox.ProtectRO {
				if p == f {
					t.Errorf("%s: sign-in file %q is a protected executed config", tool, f)
				}
			}
		}
		for _, goos := range s.KeychainOn {
			switch goos {
			case "darwin", "windows", "linux":
			default:
				t.Errorf("%s: keychain GOOS %q", tool, goos)
			}
		}
	}
	if s, _ := SandboxSignInFor("claude-code"); !s.KeychainOnOS("darwin") || s.KeychainOnOS("linux") || s.KeychainOnOS("windows") {
		t.Errorf("claude-code keychain OSes %v (the docs: the macOS Keychain, a file on Linux and Windows)", s.KeychainOn)
	}
	if _, ok := SandboxSignInFor("not-a-tool"); ok {
		t.Error("an unknown tool has a sign-in row")
	}
}
