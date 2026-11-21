package contentchan

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestInstalledArtifact: an installed file is reused only for an entry of
// the same name, size and digest that applies to the store's platform; a
// changed file, another digest, another platform and a name that is not a
// plain file name are not.
func TestInstalledArtifact(t *testing.T) {
	pub, priv := key(3)
	tr := Trust{VendorKeys: []ed25519.PublicKey{pub}}
	s := Store{Root: t.TempDir(), Now: func() time.Time { return now0 }, GOOS: "linux", GOARCH: "amd64"}
	v1 := map[string][]byte{"a.idx": []byte("alpha"), "b.idx": []byte("bravo")}
	m := manifest(1, v1)
	if _, err := s.Install(content.MaliciousPackages, envelope(t, m, priv), v1, tr); err != nil {
		t.Fatal(err)
	}
	dir, _ := s.KindDir(content.MaliciousPackages)
	entry := func(name string, b []byte) content.Entry {
		return content.Entry{Name: name, SizeBytes: int64(len(b)), SHA256: hexsum(b)}
	}
	cases := []struct {
		name string
		kind content.Kind
		e    content.Entry
		want bool
	}{
		{"same name, size and digest", content.MaliciousPackages, entry("a.idx", []byte("alpha")), true},
		{"same size, other digest", content.MaliciousPackages, entry("a.idx", []byte("alphA")), false},
		{"other size", content.MaliciousPackages, entry("a.idx", []byte("alpha2")), false},
		{"not installed", content.MaliciousPackages, entry("c.idx", []byte("alpha")), false},
		{"another platform", content.MaliciousPackages, content.Entry{Name: "a.idx", OS: "darwin", Arch: "arm64", SizeBytes: 5, SHA256: hexsum([]byte("alpha"))}, false},
		{"this platform", content.MaliciousPackages, content.Entry{Name: "a.idx", OS: "linux", Arch: "amd64", SizeBytes: 5, SHA256: hexsum([]byte("alpha"))}, true},
		{"a path, not a name", content.MaliciousPackages, entry("../malicious_packages/a.idx", []byte("alpha")), false},
		{"a channel file", content.MaliciousPackages, entry(StateFile, []byte("alpha")), false},
		{"another kind", content.PopularNames, entry("a.idx", []byte("alpha")), false},
	}
	for _, c := range cases {
		p, ok := s.InstalledArtifact(c.kind, c.e)
		if ok != c.want {
			t.Errorf("%s: ok=%v, want %v", c.name, ok, c.want)
		}
		if ok && p != filepath.Join(dir, c.e.Name) {
			t.Errorf("%s: path %s", c.name, p)
		}
	}
	// A file changed after install (same size) is not reused.
	if err := os.WriteFile(filepath.Join(dir, "b.idx"), []byte("brav0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.InstalledArtifact(content.MaliciousPackages, entry("b.idx", []byte("bravo"))); ok {
		t.Fatal("a changed installed file was reused")
	}
}
