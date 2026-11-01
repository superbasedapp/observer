package contentchan

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// engineManifest is a security.engine manifest with one pin per platform
// named in pins (os -> bytes).
func engineManifest(version int64, pins map[string][]byte) content.Manifest {
	files := map[string][]byte{}
	for goos, b := range pins {
		files["opengrep_"+goos+"_amd64"] = b
	}
	m := manifest(version, files)
	m.Kind = content.Engine
	for i := range m.Entries {
		for goos, b := range pins {
			if m.Entries[i].SHA256 == hexsum(b) {
				m.Entries[i].OS, m.Entries[i].Arch = goos, "amd64"
			}
		}
	}
	return m
}

// TestEngineManifestNotCoveringHereKeepsTheLastGood (WINFIX4 audit finding
// 6): a Linux node holds a verified Linux engine. A newer manifest that
// pins only Windows is refused as not_covered_here: the accepted manifest,
// the Linux engine bytes and the high-water mark stay. A newer one that
// pins only Windows but revokes the Linux digest installs, and removes the
// revoked bytes only. Before, the Windows-only manifest installed with no
// bytes and the prune deleted the Linux engine.
func TestEngineManifestNotCoveringHereKeepsTheLastGood(t *testing.T) {
	pub, priv := key(11)
	tr := Trust{VendorKeys: []ed25519.PublicKey{pub}}
	lin, win := []byte("opengrep linux"), []byte("opengrep windows")
	st := Store{Root: t.TempDir(), Now: func() time.Time { return now0 }, GOOS: "linux", GOARCH: "amd64"}
	v1 := engineManifest(1, map[string][]byte{"linux": lin, "windows": win})
	if _, err := st.Install(content.Engine, envelope(t, v1, priv), map[string][]byte{"opengrep_linux_amd64": lin}, tr); err != nil {
		t.Fatalf("v1: %v", err)
	}
	enginePath := filepath.Join(st.Root, string(content.Engine), "opengrep_linux_amd64")
	if _, err := os.Stat(enginePath); err != nil {
		t.Fatalf("the Linux engine was not installed: %v", err)
	}
	v2 := engineManifest(2, map[string][]byte{"windows": win})
	if _, err := st.Install(content.Engine, envelope(t, v2, priv), nil, tr); content.ReasonOf(err) != content.ContentReasonNotCoveredHere {
		t.Fatalf("v2 (Windows only): %v, want not_covered_here", err)
	}
	s, _ := st.State(content.Engine)
	if s.Accepted == nil || s.Accepted.ManifestVersion != 1 || s.LastFailure != content.ContentReasonNotCoveredHere {
		t.Fatalf("after v2: %+v", s)
	}
	if _, err := os.Stat(enginePath); err != nil {
		t.Fatalf("the Linux engine was pruned by a manifest that does not cover Linux: %v", err)
	}
	if l, err := st.Load(content.Engine, tr, 0); err != nil || l.Manifest.ManifestVersion != 1 {
		t.Fatalf("the last good manifest: %v", err)
	}
	keep := filepath.Join(st.Root, string(content.Engine), "other-engine")
	if err := os.WriteFile(keep, []byte("an unrevoked file"), 0o600); err != nil {
		t.Fatal(err)
	}
	v3 := engineManifest(3, map[string][]byte{"windows": win})
	v3.Revoked = []content.Revocation{{SHA256: hexsum(lin), Name: "opengrep_linux_amd64", Reason: "test revocation"}}
	if _, err := st.Install(content.Engine, envelope(t, v3, priv), nil, tr); err != nil {
		t.Fatalf("v3 (a revocation): %v", err)
	}
	if _, err := os.Stat(enginePath); !os.IsNotExist(err) {
		t.Fatalf("the revoked Linux engine stayed: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("a revocation removed an unrevoked file: %v", err)
	}
	if s, _ := st.State(content.Engine); s.Accepted == nil || s.Accepted.ManifestVersion != 3 {
		t.Fatalf("after v3: %+v", s)
	}
}
