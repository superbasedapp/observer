package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestSecIndexBuildInstalls builds both kinds from a small OSV tree and a
// popular list, then installs and reads them through the node's content
// store, so builder and node cannot drift.
func TestSecIndexBuildInstalls(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	in := t.TempDir()
	osvDir := filepath.Join(in, "osv", "malicious", "npm", "evil")
	if err := os.MkdirAll(osvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(osvDir, "MAL-2026-1.json"), `{"id":"MAL-2026-1","affected":[{"package":{"ecosystem":"npm","name":"evil"}}]}`)
	write(filepath.Join(osvDir, "GHSA-1.json"), `{"id":"GHSA-1","affected":[{"package":{"ecosystem":"npm","name":"lodash"}}]}`)
	popFile := filepath.Join(in, "npm.txt")
	write(popFile, "react\nlodash\n")
	out := t.TempDir()
	issued := time.Now().UTC().Add(-time.Minute)
	st, err := buildSecIndex(secIndexOptions{
		OSVDir: filepath.Join(in, "osv"), Popular: map[secfeed.Ecosystem]string{secfeed.EcoNpm: popFile},
		Out: out, ManifestVersion: 7, Epoch: 1, Issued: issued, Key: priv,
	})
	if err != nil || st.Kept != 1 || st.NotMAL != 1 {
		t.Fatalf("build: %+v %v", st, err)
	}
	store := contentchan.Store{Root: t.TempDir()}
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}
	var parts [2][]byte
	for i, k := range []struct {
		kind content.Kind
		name string
	}{{content.MaliciousPackages, secfeed.MaliciousArtifact}, {content.PopularNames, secfeed.PopularArtifact}} {
		env, err := os.ReadFile(filepath.Join(out, string(k.kind), "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(out, string(k.kind), k.name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Install(k.kind, env, map[string][]byte{k.name: data}, tr); err != nil {
			t.Fatalf("install %s: %v", k.kind, err)
		}
		l, err := store.Load(k.kind, tr, 0)
		if err != nil {
			t.Fatal(err)
		}
		if parts[i], err = l.ReadArtifact(k.name); err != nil {
			t.Fatal(err)
		}
	}
	ix, err := secfeed.ParseIndex(parts[0], parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if a := ix.Lookup(secfeed.EcoNpm, "evil", ""); !a.Malicious {
		t.Errorf("evil not listed: %+v", a)
	}
	if a := ix.Lookup(secfeed.EcoNpm, "lodash", ""); a.Malicious || !a.Popular {
		t.Errorf("a GHSA report must never enter the malicious list: %+v", a)
	}

	empty := t.TempDir()
	if _, err := buildSecIndex(secIndexOptions{OSVDir: empty, Out: t.TempDir(), ManifestVersion: 1, Issued: issued, Key: priv}); err == nil {
		t.Error("an empty malicious list must not be published")
	}
}
