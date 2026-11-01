package contentchan

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

var now0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func key(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

func hexsum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func manifest(version int64, files map[string][]byte) content.Manifest {
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.MaliciousPackages, ManifestVersion: version, Epoch: 1,
		IssuedAt: now0.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now0.Add(5 * 24 * time.Hour).Format(time.RFC3339),
	}
	for n, b := range files {
		m.Entries = append(m.Entries, content.Entry{Name: n, SizeBytes: int64(len(b)), SHA256: hexsum(b), Upstream: content.UpstreamCheck{Method: content.UpstreamNone}})
	}
	content.SortEntries(m.Entries)
	return m
}

func envelope(t *testing.T, m content.Manifest, priv ed25519.PrivateKey) []byte {
	t.Helper()
	env, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := content.EncodeEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInstallLoadAndLastKnownGood(t *testing.T) {
	pub, priv := key(1)
	tr := Trust{VendorKeys: []ed25519.PublicKey{pub}}
	clock := now0
	s := Store{Root: t.TempDir(), Now: func() time.Time { return clock }}
	v1 := map[string][]byte{"a.idx": []byte("one"), "old.idx": []byte("gone later")}
	if _, err := s.Install(content.MaliciousPackages, envelope(t, manifest(1, v1), priv), v1, tr); err != nil {
		t.Fatal(err)
	}
	v2 := map[string][]byte{"a.idx": []byte("two")}
	st, err := s.Install(content.MaliciousPackages, envelope(t, manifest(2, v2), priv), v2, tr)
	if err != nil || st.Accepted.ManifestVersion != 2 {
		t.Fatalf("install v2: %+v %v", st, err)
	}
	dir, _ := s.KindDir(content.MaliciousPackages)
	if _, err := os.Stat(filepath.Join(dir, "old.idx")); !os.IsNotExist(err) {
		t.Error("an artifact the new manifest drops must be removed")
	}

	// Rollback drill: replaying v1 is refused and v2 stays.
	st, err = s.Install(content.MaliciousPackages, envelope(t, manifest(1, v1), priv), v1, tr)
	if content.ReasonOf(err) != content.ContentReasonRollback || st.Accepted.ManifestVersion != 2 || st.LastFailure != content.ContentReasonRollback {
		t.Fatalf("rollback: %+v %v", st, err)
	}
	// A tampered artifact is refused before anything is written.
	bad := map[string][]byte{"a.idx": []byte("thr")}
	m3 := manifest(3, map[string][]byte{"a.idx": []byte("three")})
	if _, err := s.Install(content.MaliciousPackages, envelope(t, m3, priv), bad, tr); content.ReasonOf(err) != content.ContentReasonArtifact {
		t.Fatalf("tampered artifact: %v", err)
	}
	if _, err := s.Install(content.MaliciousPackages, envelope(t, m3, priv), map[string][]byte{}, tr); content.ReasonOf(err) != content.ContentReasonNotCovered {
		t.Fatalf("missing artifact: %v", err)
	}

	l, err := s.Load(content.MaliciousPackages, tr, 0)
	if err != nil || l.Freshness != content.Fresh {
		t.Fatalf("load: %+v %v", l, err)
	}
	if b, err := l.ReadArtifact("a.idx"); err != nil || string(b) != "two" {
		t.Fatalf("read: %q %v", b, err)
	}
	// A file changed after install is refused on read.
	if err := os.WriteFile(filepath.Join(dir, "a.idx"), []byte("tw0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.ReadArtifact("a.idx"); content.ReasonOf(err) != content.ContentReasonArtifact {
		t.Errorf("changed artifact read: %v", err)
	}
	// Past expiry the data loads as stale, past the floor as unknown.
	clock = now0.Add(10 * 24 * time.Hour)
	if l, err := s.Load(content.MaliciousPackages, tr, 0); err != nil || l.Freshness != content.Stale {
		t.Errorf("stale load: %+v %v", l.Freshness, err)
	}
	clock = now0.Add(40 * 24 * time.Hour)
	if l, err := s.Load(content.MaliciousPackages, tr, 0); err != nil || l.Freshness != content.Unknown {
		t.Errorf("unknown load: %+v %v", l.Freshness, err)
	}
	// Another vendor key cannot load what is on disk.
	other, _ := key(9)
	if _, err := s.Load(content.MaliciousPackages, Trust{VendorKeys: []ed25519.PublicKey{other}}, 0); content.ReasonOf(err) != content.ContentReasonVendorSig {
		t.Errorf("foreign key load: %v", err)
	}
}

func TestLoadNotInstalled(t *testing.T) {
	s := Store{Root: t.TempDir()}
	if _, err := s.Load(content.PopularNames, Trust{}, 0); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("err = %v", err)
	}
	if _, err := s.KindDir("nope"); err == nil {
		t.Error("an unknown kind has no directory")
	}
}

func TestManagedRequiresCountersign(t *testing.T) {
	vpub, vpriv := key(1)
	opub, opriv := key(2)
	files := map[string][]byte{"a.idx": []byte("x")}
	s := Store{Root: t.TempDir(), Now: func() time.Time { return now0 }}
	tr := Trust{VendorKeys: []ed25519.PublicKey{vpub}, RequireOrg: true, OrgKey: opub}
	plain := envelope(t, manifest(1, files), vpriv)
	if _, err := s.Install(content.MaliciousPackages, plain, files, tr); content.ReasonOf(err) != content.ContentReasonOrgSig {
		t.Fatalf("uncountersigned on a managed node: %v", err)
	}
	env, _ := content.Sign(manifest(1, files), vpriv)
	env, _ = content.Countersign(env, opriv)
	b, _ := content.EncodeEnvelope(env)
	if _, err := s.Install(content.MaliciousPackages, b, files, tr); err != nil {
		t.Fatalf("countersigned: %v", err)
	}
}

// TestInstallFilesStreamsAndKeepsLastKnownGood: an install from files on
// disk verifies every digest while reading, moves the files in, and a
// tampered file or a rollback keeps the last-known-good.
func TestInstallFilesStreamsAndKeepsLastKnownGood(t *testing.T) {
	pub, priv := key(3)
	tr := Trust{VendorKeys: []ed25519.PublicKey{pub}}
	st := Store{Root: t.TempDir(), Now: func() time.Time { return now0 }}
	stage := func(name string, b []byte) string {
		p := filepath.Join(st.Root, ".incoming-"+name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	big := []byte("npm export bytes")
	m := manifest(2, map[string][]byte{"npm.zip": big})
	m.Kind = content.OSVExport
	src := stage("npm.zip", big)
	if _, err := st.InstallFiles(content.OSVExport, envelope(t, m, priv), map[string]string{"npm.zip": src}, tr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(src); !errors.Is(err, os.ErrNotExist) {
		t.Error("the staged file must be consumed")
	}
	l, err := st.Load(content.OSVExport, tr, 0)
	if err != nil {
		t.Fatal(err)
	}
	p, e, err := l.ArtifactPath("npm.zip")
	if err != nil || e.SizeBytes != int64(len(big)) {
		t.Fatalf("artifact path: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != string(big) {
		t.Fatal("installed bytes differ")
	}
	// A tampered file is refused; the accepted version stays.
	m3 := manifest(3, map[string][]byte{"npm.zip": []byte("newer export")})
	m3.Kind = content.OSVExport
	bad := stage("npm.zip", []byte("tampered!!!!"))
	if _, err := st.InstallFiles(content.OSVExport, envelope(t, m3, priv), map[string]string{"npm.zip": bad}, tr); content.ReasonOf(err) != content.ContentReasonArtifact {
		t.Fatalf("tampered: %v", err)
	}
	// A rollback is refused too.
	m1 := manifest(1, map[string][]byte{"npm.zip": big})
	m1.Kind = content.OSVExport
	if _, err := st.InstallFiles(content.OSVExport, envelope(t, m1, priv), map[string]string{"npm.zip": stage("npm.zip", big)}, tr); content.ReasonOf(err) != content.ContentReasonRollback {
		t.Fatalf("rollback: %v", err)
	}
	s, _ := st.State(content.OSVExport)
	if s.Accepted == nil || s.Accepted.ManifestVersion != 2 || s.LastFailure == "" {
		t.Errorf("last-known-good must stay at version 2 with the failure recorded: %+v", s)
	}
}
