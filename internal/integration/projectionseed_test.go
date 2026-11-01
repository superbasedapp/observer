package integration

import (
	"path"
	"strings"
	"testing"
)

// projectionSeedSecretWords are file-name parts a seeded file may never
// carry: a sign-in, a key, an env block (lane SBX-P3C: credential files are
// never seeded until sign-in seeding has its own consent design).
var projectionSeedSecretWords = []string{"credential", "auth", "token", "secret", "oauth", "key", ".env", "settings", "config", "session", "cookie", ".netrc"}

// TestProjectionSeedsCoverage pins the G27 side table: every row names a
// registry tool with sandbox state, every seeded file and transcript
// subtree is a clean HOME-relative path strictly inside one of the tool's
// StateRW entries, no seeded file can be a credential store or a file the
// credential-file exception lists, and no file is also a transcript root.
func TestProjectionSeedsCoverage(t *testing.T) {
	t.Parallel()
	if len(ProjectionSeeds()) == 0 {
		t.Fatal("no grounded projection seed")
	}
	for _, s := range ProjectionSeeds() {
		c, ok := For(s.Tool)
		if !ok {
			t.Errorf("%s: not a registry tool", s.Tool)
			continue
		}
		if s.Grounding == "" || len(s.Transcripts) == 0 {
			t.Errorf("%s: no grounding or no transcript subtree", s.Tool)
		}
		if len(s.Files) > 0 && !strings.HasPrefix(s.DocURL, "https://") {
			t.Errorf("%s: seeds files with no vendor document naming them", s.Tool)
		}
		inside := func(p string) bool {
			if p == "" || path.IsAbs(p) || path.Clean(p) != p || strings.HasPrefix(p, "..") {
				return false
			}
			for _, st := range c.Sandbox.StateRW {
				if strings.HasPrefix(p, st+"/") {
					return true
				}
			}
			return false
		}
		for _, f := range s.Files {
			if !inside(f) {
				t.Errorf("%s: seed file %q is not strictly inside a StateRW entry", s.Tool, f)
			}
			low := strings.ToLower(path.Base(f))
			for _, w := range projectionSeedSecretWords {
				if strings.Contains(low, w) {
					t.Errorf("%s: seed file %q looks like a credential or config store (%q)", s.Tool, f, w)
				}
			}
			for _, p := range c.Sandbox.ProtectRO {
				if p == f {
					t.Errorf("%s: seed file %q is a protected executed config", s.Tool, f)
				}
			}
		}
		// A sign-in reaches a box only through the consented path (lane
		// BOXSIGNIN, internal/sandboxsignin): never as a seed file.
		if si, ok := SandboxSignInFor(s.Tool); ok {
			for _, f := range s.Files {
				for _, cred := range si.Files {
					if f == cred || strings.HasPrefix(cred, f+"/") || strings.HasPrefix(f, cred+"/") {
						t.Errorf("%s: seed file %q is the sign-in file %q, which only consented sign-in seeding copies", s.Tool, f, cred)
					}
				}
			}
		}
		for _, tr := range s.Transcripts {
			if !inside(tr) {
				t.Errorf("%s: transcript subtree %q is not strictly inside a StateRW entry", s.Tool, tr)
			}
			for _, f := range s.Files {
				if f == tr || strings.HasPrefix(f, tr+"/") {
					t.Errorf("%s: seed file %q lies in the transcript subtree %q", s.Tool, f, tr)
				}
			}
		}
	}
}
