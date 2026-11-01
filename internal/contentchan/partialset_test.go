package contentchan

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// partialRootfs is a microVM rootfs set whose SBOM applies everywhere and
// whose kernel exists for arm64 only.
func partialRootfs(sbom, kernel []byte) content.Manifest {
	m := manifest(1, nil)
	m.Kind = content.SandboxRootfs
	m.Entries = []content.Entry{
		{Name: "sbom.spdx.json", Version: "1", SizeBytes: int64(len(sbom)), SHA256: hexsum(sbom), Source: "r@c", License: "CC0-1.0", Upstream: content.UpstreamCheck{Method: content.UpstreamNone}},
		{Name: "vmlinuz", Version: "1", OS: "linux", Arch: "arm64", SizeBytes: int64(len(kernel)), SHA256: hexsum(kernel), Source: "r@c", License: "GPL-2.0-only", Upstream: content.UpstreamCheck{Method: content.UpstreamNone}},
	}
	content.SortEntries(m.Entries)
	return m
}

// TestPartialSetIsRefusedOnEveryPath (WINFIX2 audit finding 8): a set in
// which only the SBOM applies to the node's architecture is refused as
// partial_set by both installers, naming the missing entry, and nothing is
// accepted; on the architecture it was built for it installs and loads.
// Before, it imported (one entry applied, so "no entry applies" did not
// fire) and failed at launch.
func TestPartialSetIsRefusedOnEveryPath(t *testing.T) {
	pub, priv := key(9)
	tr := Trust{VendorKeys: []ed25519.PublicKey{pub}}
	sbom, kernel := []byte(`{"spdxVersion":"SPDX-2.3"}`), []byte("kernel bytes")
	m := partialRootfs(sbom, kernel)
	arts := map[string][]byte{"sbom.spdx.json": sbom, "vmlinuz": kernel}
	for _, goos := range []string{"linux", "windows", "darwin"} {
		st := Store{Root: t.TempDir(), Now: func() time.Time { return now0 }, GOOS: goos, GOARCH: "amd64"}
		_, err := st.Install(content.SandboxRootfs, envelope(t, m, priv), arts, tr)
		if content.ReasonOf(err) != content.ContentReasonPartialSet || !strings.Contains(err.Error(), "vmlinuz") || !strings.Contains(err.Error(), "linux/amd64") {
			t.Fatalf("%s: install: %v, want partial_set naming vmlinuz for linux/amd64", goos, err)
		}
		files := map[string]string{}
		for name, b := range arts {
			p := filepath.Join(st.Root, ".incoming-"+name)
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
			files[name] = p
		}
		if _, err := st.InstallFiles(content.SandboxRootfs, envelope(t, m, priv), files, tr); content.ReasonOf(err) != content.ContentReasonPartialSet {
			t.Fatalf("%s: install files: %v, want partial_set", goos, err)
		}
		if s, _ := st.State(content.SandboxRootfs); s.Accepted != nil {
			t.Fatalf("%s: a partial set was accepted: %+v", goos, s)
		}
	}
	st := Store{Root: t.TempDir(), Now: func() time.Time { return now0 }, GOOS: "linux", GOARCH: "arm64"}
	if _, err := st.Install(content.SandboxRootfs, envelope(t, m, priv), arts, tr); err != nil {
		t.Fatalf("arm64: the set is whole there: %v", err)
	}
	if _, err := st.Load(content.SandboxRootfs, tr, 0); err != nil {
		t.Fatalf("arm64: load: %v", err)
	}
	// The same store read on another architecture refuses the accepted set.
	st.GOARCH = "amd64"
	if _, err := st.Load(content.SandboxRootfs, tr, 0); content.ReasonOf(err) != content.ContentReasonPartialSet {
		t.Fatalf("load on amd64: %v, want partial_set", err)
	}
}
