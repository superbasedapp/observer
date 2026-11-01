package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// recordedMXCManifest is mxc-manifest.json as scripts/mxc-files.sh manifest
// wrote it for the pinned MXC 1.0.1 set (the Authenticode thumbprints are
// placeholders; the format is the release job's).
const recordedMXCManifest = "testdata/mxc-manifest.json"

func sandboxNativeOpts(t *testing.T, key ed25519.PrivateKey) sandboxNativeOptions {
	t.Helper()
	return sandboxNativeOptions{
		In: recordedMXCManifest, Arch: "amd64", Out: t.TempDir(), Key: key,
		ManifestVersion: 1, Epoch: 1, Valid: 30 * 24 * time.Hour, Issued: time.Now().UTC().Add(-time.Minute),
	}
}

// TestSandboxNativeSignsTheRecordedManifest: the verb turns the recorded
// mxc-manifest.json into the descriptor and a manifest signed by a TEST
// key, which the node's content store installs and the node's resolution
// accepts as the compiled pins.
func TestSandboxNativeSignsTheRecordedManifest(t *testing.T) {
	pub, priv := testKey(t)
	o := sandboxNativeOpts(t, priv)
	n, err := buildSandboxNative(o)
	if err != nil {
		t.Fatal(err)
	}
	if n.Version != sandboxmxc.ManifestX64.Version || len(n.Files) != 2 {
		t.Fatalf("descriptor: %+v", n)
	}
	dir := filepath.Join(o.Out, string(content.SandboxNative))
	desc, _ := os.ReadFile(filepath.Join(dir, sandboxmxc.NativeFilesName))
	env, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	st := contentchan.Store{Root: t.TempDir(), GOOS: "windows", GOARCH: "amd64"}
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}
	if _, err := st.Install(content.SandboxNative, env, map[string][]byte{sandboxmxc.NativeFilesName: desc}, tr); err != nil {
		t.Fatal(err)
	}
	l, err := st.Load(content.SandboxNative, tr, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.ReadArtifact(sandboxmxc.NativeFilesName)
	if err != nil {
		t.Fatal(err)
	}
	r := sandboxmxc.ResolveSigned(sandboxmxc.SignedInput{
		Compiled: sandboxmxc.ManifestX64, HasCompiled: true, Arch: "amd64", Installed: true,
		Freshness: string(l.Freshness), Descriptor: b,
	})
	if !r.OK || r.Source != sandboxmxc.SignedSourceSigned {
		t.Fatalf("resolve: %+v", r)
	}
	// Unsigned run: the descriptor only.
	o2 := sandboxNativeOpts(t, nil)
	if _, err := buildSandboxNative(o2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(o2.Out, string(content.SandboxNative), "manifest.json")); !os.IsNotExist(err) {
		t.Fatal("an unsigned run wrote a manifest")
	}
	got, _ := os.ReadFile(filepath.Join(o2.Out, string(content.SandboxNative), sandboxmxc.NativeFilesName))
	if string(got) != string(desc) {
		t.Fatal("the descriptor differs between a signed and an unsigned run")
	}
}

func TestSandboxNativeRefusals(t *testing.T) {
	_, priv := testKey(t)
	rec, err := os.ReadFile(recordedMXCManifest)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(string) string
		opt  func(*sandboxNativeOptions)
		want string
	}{
		{"no Authenticode", func(s string) string {
			return strings.Replace(s, `"authenticode": "valid `, `"authenticode": "not_checked `, 1)
		}, nil, "Authenticode"},
		{"another hash", func(s string) string {
			return strings.Replace(s, "bd45522f06dc9cc8001dcd5d7320bc2bf303fb08a39bf10f3404bd9a8001812c", strings.Repeat("c", 64), 1)
		}, nil, "compiled pins"},
		{"another version", func(s string) string { return strings.Replace(s, `"version": "1.0.1"`, `"version": "1.0.2"`, 1) }, nil, "compiled pins"},
		{"another kind", func(s string) string { return strings.Replace(s, mxcReleaseKind, "observer.other.v1", 1) }, nil, "want observer.mxc-files.v1"},
		{"unknown field", func(s string) string { return strings.Replace(s, `"kind"`, `"extra": 1, "kind"`, 1) }, nil, "unknown field"},
		{"no pins for arm64", nil, func(o *sandboxNativeOptions) { o.Arch = "arm64" }, "no MXC pins"},
		{"no expiry", nil, func(o *sandboxNativeOptions) { o.Valid = 0 }, "validity"},
	}
	for _, tc := range cases {
		o := sandboxNativeOpts(t, priv)
		if tc.edit != nil {
			p := filepath.Join(t.TempDir(), "mxc-manifest.json")
			if err := os.WriteFile(p, []byte(tc.edit(string(rec))), 0o600); err != nil {
				t.Fatal(err)
			}
			o.In = p
		}
		if tc.opt != nil {
			tc.opt(&o)
		}
		if _, err := buildSandboxNative(o); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}
