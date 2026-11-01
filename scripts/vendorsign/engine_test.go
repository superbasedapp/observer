package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// engineEntryFile writes one verified-looking Opengrep entry, the shape
// `secengine verify` prints.
func engineEntryFile(t *testing.T, dir string, p secengine.Platform, i int) string {
	t.Helper()
	e := content.Entry{
		Name: "opengrep_" + p.OS + "_" + p.Arch, Version: "1.30.1", OS: p.OS, Arch: p.Arch, SizeBytes: 10,
		SHA256: strings.Repeat(string(rune('a'+i)), 64), Source: "github.com/opengrep/opengrep", License: "LGPL-2.1-only",
		Upstream: content.UpstreamCheck{
			Method: content.UpstreamCosignKeylessOnline, Identity: secengine.Identity("1.30.1"), Issuer: secengine.Issuer,
			VerifiedAt: time.Now().UTC().Format(time.RFC3339), VerifiedWhere: "release_pipeline",
		},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, e.Name+".json")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestEngineSignRefusesAMissingPlatform (WINFIX4 audit finding 6): the sign
// step refuses an engine manifest that pins one platform, signs one that
// pins all five, and signs a one-platform manifest only as an explicit
// revocation that revokes a digest.
func TestEngineSignRefusesAMissingPlatform(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	in := t.TempDir()
	var files []string
	for i, p := range secengine.ReleasePlatforms {
		files = append(files, engineEntryFile(t, in, p, i))
	}
	opts := func(entries []string) engineOptions {
		return engineOptions{Entries: entries, Out: t.TempDir(), ManifestVersion: 1, Epoch: 1, Issued: time.Now().UTC().Add(-time.Minute), Validity: 30 * 24 * time.Hour, Key: priv}
	}
	if _, err := buildEngineManifest(opts(files[:1])); err == nil || !strings.Contains(err.Error(), "no Opengrep pin") {
		t.Fatalf("a one-platform manifest: %v", err)
	}
	o := opts(files)
	if m, err := buildEngineManifest(o); err != nil || len(m.Entries) != len(secengine.ReleasePlatforms) {
		t.Fatalf("all five: %v", err)
	}
	if _, err := os.Stat(filepath.Join(o.Out, string(content.Engine), "manifest.json")); err != nil {
		t.Fatalf("no manifest written: %v", err)
	}
	r := opts(files[:1])
	r.Revocation = true
	if _, err := buildEngineManifest(r); err == nil {
		t.Fatal("a revocation that revokes nothing was signed")
	}
	r.Revoked = []content.Revocation{{SHA256: strings.Repeat("f", 64), Reason: "test"}}
	if _, err := buildEngineManifest(r); err != nil {
		t.Fatalf("an explicit revocation: %v", err)
	}
}
