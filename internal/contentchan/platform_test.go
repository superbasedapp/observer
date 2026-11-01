package contentchan

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// guestManifest is a microVM guest set's manifest: its one entry targets
// linux, whatever the node's own OS.
func guestManifest(version int64, b []byte) content.Manifest {
	m := manifest(version, nil)
	m.Kind = content.SandboxGuest
	m.Entries = []content.Entry{{
		Name: "observer-guest", Version: "1.40.0", OS: "linux", Arch: "amd64", SizeBytes: int64(len(b)), SHA256: hexsum(b),
		Source: "cmd/observer@abc", License: "NOASSERTION", Upstream: content.UpstreamCheck{Method: content.UpstreamNone},
	}}
	return m
}

// TestGuestSetIsVerifiedOnEveryNodeOS: a guest set's linux entries are
// selected on a Windows or macOS node too, so a tampered file is refused
// there and a good one installs and loads (Windows 11 Pro rerun
// 2026-10-25: on Windows a tampered set was accepted, because the platform
// walk skipped every linux entry and installed nothing).
func TestGuestSetIsVerifiedOnEveryNodeOS(t *testing.T) {
	pub, priv := key(7)
	tr := Trust{VendorKeys: []ed25519.PublicKey{pub}}
	good := []byte("stand-in guest observer 1.40.0")
	for _, goos := range []string{"windows", "darwin", "linux"} {
		st := Store{Root: t.TempDir(), Now: func() time.Time { return now0 }, GOOS: goos, GOARCH: "amd64"}
		m := guestManifest(1, good)
		bad := filepath.Join(st.Root, ".incoming-bad")
		if err := os.WriteFile(bad, []byte("stand-in guest observer 1.40.X"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := st.InstallFiles(content.SandboxGuest, envelope(t, m, priv), map[string]string{"observer-guest": bad}, tr); content.ReasonOf(err) != content.ContentReasonArtifact {
			t.Fatalf("%s: a tampered guest set: %v, want artifact refusal", goos, err)
		}
		if _, err := st.Install(content.SandboxGuest, envelope(t, m, priv), map[string][]byte{"observer-guest": []byte("stand-in guest observer 1.40.X")}, tr); content.ReasonOf(err) != content.ContentReasonArtifact {
			t.Fatalf("%s: a tampered guest set (in memory): %v, want artifact refusal", goos, err)
		}
		if _, err := st.Install(content.SandboxGuest, envelope(t, m, priv), map[string][]byte{"observer-guest": good}, tr); err != nil {
			t.Fatalf("%s: a good guest set: %v", goos, err)
		}
		l, err := st.Load(content.SandboxGuest, tr, 0)
		if err != nil {
			t.Fatalf("%s: load: %v", goos, err)
		}
		if _, _, err := l.ArtifactPath("observer-guest"); err != nil {
			t.Fatalf("%s: the installed guest binary: %v", goos, err)
		}
	}
}

// TestSinglePlatformEngineManifestImports: a real single-platform engine
// manifest (one Linux-only, one Windows-only pin) imports on the platform
// it names, its bytes required and checked. On any other platform it is
// refused as not_covered_here, with nothing accepted (WINFIX4 audit
// finding 6: before, it installed empty there). The not_covered refusal
// of an empty install (Windows 11 Pro rerun) stays for every other kind
// (TestNoEntryAppliesIsRefused).
func TestSinglePlatformEngineManifestImports(t *testing.T) {
	pub, priv := key(9)
	tr := Trust{VendorKeys: []ed25519.PublicKey{pub}}
	for _, only := range []string{"linux", "windows"} {
		b := []byte("opengrep for " + only)
		m := manifest(1, map[string][]byte{"opengrep_" + only + "_amd64": b})
		m.Kind = content.Engine
		m.Entries[0].OS, m.Entries[0].Arch = only, "amd64"
		for _, goos := range []string{"linux", "windows", "darwin"} {
			st := Store{Root: t.TempDir(), Now: func() time.Time { return now0 }, GOOS: goos, GOARCH: "amd64"}
			env := envelope(t, m, priv)
			if goos == only {
				if _, err := st.Install(content.Engine, env, nil, tr); content.ReasonOf(err) != content.ContentReasonNotCovered {
					t.Fatalf("%s-only on %s with no bytes: %v, want not_covered", only, goos, err)
				}
				if _, err := st.Install(content.Engine, env, map[string][]byte{m.Entries[0].Name: []byte("tampered")}, tr); content.ReasonOf(err) != content.ContentReasonArtifact {
					t.Fatalf("%s-only on %s with other bytes: %v, want artifact", only, goos, err)
				}
				if _, err := st.Install(content.Engine, env, map[string][]byte{m.Entries[0].Name: b}, tr); err != nil {
					t.Fatalf("%s-only on %s: %v", only, goos, err)
				}
			} else {
				if _, err := st.Install(content.Engine, env, nil, tr); content.ReasonOf(err) != content.ContentReasonNotCoveredHere {
					t.Fatalf("%s-only on %s (no bytes): %v, want not_covered_here", only, goos, err)
				}
				if s, _ := st.State(content.Engine); s.Accepted != nil || s.LastFailure != content.ContentReasonNotCoveredHere {
					t.Fatalf("%s-only on %s: %+v", only, goos, s)
				}
				continue
			}
			if s, _ := st.State(content.Engine); s.Accepted == nil {
				t.Fatalf("%s-only on %s: nothing accepted", only, goos)
			}
			if _, err := st.Load(content.Engine, tr, 0); err != nil {
				t.Fatalf("%s-only on %s: load: %v", only, goos, err)
			}
		}
	}
}

// TestNoEntryAppliesIsRefused: a manifest none of whose entries the
// store's walk selects is refused (not_covered), never installed empty.
func TestNoEntryAppliesIsRefused(t *testing.T) {
	pub, priv := key(8)
	tr := Trust{VendorKeys: []ed25519.PublicKey{pub}}
	b := []byte("darwin only")
	m := manifest(1, map[string][]byte{"a.idx": b})
	m.Entries[0].OS = "darwin"
	st := Store{Root: t.TempDir(), Now: func() time.Time { return now0 }, GOOS: "linux", GOARCH: "amd64"}
	if _, err := st.Install(content.MaliciousPackages, envelope(t, m, priv), map[string][]byte{"a.idx": b}, tr); content.ReasonOf(err) != content.ContentReasonNotCovered {
		t.Fatalf("install: %v, want not_covered", err)
	}
	p := filepath.Join(st.Root, ".incoming-a")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InstallFiles(content.MaliciousPackages, envelope(t, m, priv), map[string]string{"a.idx": p}, tr); content.ReasonOf(err) != content.ContentReasonNotCovered {
		t.Fatalf("install files: %v, want not_covered", err)
	}
	if s, _ := st.State(content.MaliciousPackages); s.Accepted != nil {
		t.Fatalf("nothing may be accepted: %+v", s)
	}
}
