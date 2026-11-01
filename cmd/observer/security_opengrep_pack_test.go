//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// packAtVersion is the floor with its version changed.
func packAtVersion(t *testing.T, v string) *secrulepack.Pack {
	t.Helper()
	floor, err := secrulepack.Floor()
	if err != nil {
		t.Fatal(err)
	}
	files := floor.Files()
	files[secrulepack.ManifestFile] = []byte(strings.Replace(string(files[secrulepack.ManifestFile]), `"version": "`+floor.Version()+`"`, `"version": "`+v+`"`, 1))
	p, err := secrulepack.Parse(files)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// writeSignedPack writes p as an import directory signed with priv at
// manifest version mv, and returns the directory.
func writeSignedPack(t *testing.T, priv ed25519.PrivateKey, p *secrulepack.Pack, mv int64) string {
	t.Helper()
	bundle, err := secrulepack.EncodeBundle(p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.RulePack, ManifestVersion: mv, Epoch: mv,
		IssuedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		Entries: []content.Entry{{
			Name: secrulepack.BundleName, Version: p.Version(), SizeBytes: int64(len(bundle)), SHA256: content.HashBytes(bundle),
			License: "Apache-2.0", Upstream: content.UpstreamCheck{Method: content.UpstreamNone},
		}},
	}
	env, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := content.EncodeEnvelope(env)
	dir := t.TempDir()
	kd := filepath.Join(dir, string(content.RulePack))
	if err := os.MkdirAll(kd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kd, contentchan.ManifestFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kd, secrulepack.BundleName), bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestCodePackChoice: the embedded floor until a newer signed pack is
// imported; an older one, a pack signed by another key and a bundle
// changed after install never displace it.
func TestCodePackChoice(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}}
	store := contentchan.Store{Root: t.TempDir()}

	got, err := loadCodePack(store, tr)
	if err != nil || got.Source != secrulepack.SourceFloor || got.Note != "" {
		t.Fatalf("nothing installed: %+v %v", got, err)
	}

	// Signed by another key: refused at import, nothing installed.
	_, other, _ := ed25519.GenerateKey(nil)
	if _, err := importCodePack(writeSignedPack(t, other, packAtVersion(t, "9.1.0"), 1), store, tr); err == nil {
		t.Fatal("a pack signed by an unknown key was installed")
	}

	// Newer and signed: it wins.
	if _, err := importCodePack(writeSignedPack(t, priv, packAtVersion(t, "9.1.0"), 1), store, tr); err != nil {
		t.Fatalf("import: %v", err)
	}
	got, _ = loadCodePack(store, tr)
	if got.Source != secrulepack.SourceImported || got.Pack.Version() != "9.1.0" || got.Freshness != content.Fresh {
		t.Fatalf("after import: %+v", got)
	}

	// The bundle changed on disk after install: set aside, floor used.
	bundle := filepath.Join(store.Root, string(content.RulePack), secrulepack.BundleName)
	b, _ := os.ReadFile(bundle)
	if err := os.WriteFile(bundle, append(b, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _ = loadCodePack(store, tr)
	if got.Source != secrulepack.SourceFloor || got.Note == "" {
		t.Fatalf("a tampered bundle was used: %+v", got)
	}

	// An older pack at a higher manifest version installs (the channel's
	// order is its own) but never displaces the floor.
	store2 := contentchan.Store{Root: t.TempDir()}
	if _, err := importCodePack(writeSignedPack(t, priv, packAtVersion(t, "0.9.0"), 1), store2, tr); err != nil {
		t.Fatal(err)
	}
	got, _ = loadCodePack(store2, tr)
	if got.Source != secrulepack.SourceFloor || !strings.Contains(got.Note, "not newer") {
		t.Fatalf("an older pack: %+v", got)
	}

	// A bundle that is not a valid pack is refused before install.
	bad := writeSignedPack(t, priv, packAtVersion(t, "9.2.0"), 2)
	if err := os.WriteFile(filepath.Join(bad, string(content.RulePack), secrulepack.BundleName), []byte(`{"schema":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := importCodePack(bad, store, tr); err == nil {
		t.Fatal("an invalid bundle was installed")
	}
}
