package main

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// fakeLayout is a small OCI layout tarball shaped like buildx's
// `type=oci` output: index.json names one image index, which names one
// manifest per platform plus an attestation manifest, each with a config.
type fakeLayout struct {
	blobs map[string][]byte
	top   string
	ids   map[string]string
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func (f *fakeLayout) add(v any) string {
	b, _ := json.Marshal(v)
	d := sum(b)
	f.blobs[d] = b
	return d
}

func newFakeLayout(platforms ...string) *fakeLayout {
	return newFakeLayoutSized(nil, platforms...)
}

// newFakeLayoutSized is newFakeLayout with each platform's first layer
// sized from sizes (a platform missing there keeps 1,000,000 bytes per
// character of its name).
func newFakeLayoutSized(sizes map[string]int64, platforms ...string) *fakeLayout {
	f := &fakeLayout{blobs: map[string][]byte{}, ids: map[string]string{}}
	var ms []map[string]any
	for _, p := range platforms {
		os_, arch, _ := strings.Cut(p, "/")
		cfg := f.add(map[string]any{"os": os_, "architecture": arch, "rootfs": map[string]any{"type": "layers"}})
		f.ids[p] = cfg
		// Two compressed layers per platform, sized by the platform name so
		// the largest platform is known (R-038).
		first, ok := sizes[p]
		if !ok {
			first = int64(1_000_000 * len(p))
		}
		layers := []map[string]any{{"digest": sum([]byte(p + "/1")), "size": first}, {"digest": sum([]byte(p + "/2")), "size": int64(500_000)}}
		man := f.add(map[string]any{"schemaVersion": 2, "mediaType": mediaManifest, "config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg}, "layers": layers})
		ms = append(ms, map[string]any{"mediaType": mediaManifest, "digest": man, "platform": map[string]any{"os": os_, "architecture": arch}})
	}
	att := f.add(map[string]any{"schemaVersion": 2, "mediaType": mediaManifest, "config": map[string]any{"digest": f.add(map[string]any{})}})
	ms = append(ms, map[string]any{"mediaType": mediaManifest, "digest": att, "platform": map[string]any{"os": "unknown", "architecture": "unknown"}})
	f.top = f.add(map[string]any{"schemaVersion": 2, "mediaType": mediaIndex, "manifests": ms})
	return f
}

func (f *fakeLayout) write(t *testing.T, path string, tamper bool) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	put := func(name string, b []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []map[string]any{{"mediaType": mediaIndex, "digest": f.top}}})
	put("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	put("index.json", idx)
	for d, b := range f.blobs {
		if tamper && d == f.top {
			b = append([]byte(nil), b...)
			b[len(b)-2] ^= 1
		}
		put("blobs/sha256/"+strings.TrimPrefix(d, "sha256:"), b)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sandboxFixture(t *testing.T, platforms ...string) (sandboxImageOptions, *fakeLayout) {
	t.Helper()
	return sandboxFixtureSized(t, nil, platforms...)
}

// sandboxFixtureSized is sandboxFixture over newFakeLayoutSized.
func sandboxFixtureSized(t *testing.T, sizes map[string]int64, platforms ...string) (sandboxImageOptions, *fakeLayout) {
	t.Helper()
	in := t.TempDir()
	f := newFakeLayoutSized(sizes, platforms...)
	oci := filepath.Join(in, "image.oci.tar")
	f.write(t, oci, false)
	pk := filepath.Join(in, "packages")
	for _, p := range platforms {
		arch := strings.TrimPrefix(p, "linux/")
		dir := filepath.Join(pk, strings.ReplaceAll(p, "/", "_"))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "packages.tsv"), []byte("bash\t5.2.15-2+b7\t"+arch+"\ngit\t1:2.39.5-0+deb12u2\t"+arch+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	recipe := filepath.Join("..", "..", "deploy", "sandbox-image", "Dockerfile")
	return sandboxImageOptions{
		OCI: oci, Packages: pk, Recipe: recipe, RecipePath: "deploy/sandbox-image/Dockerfile",
		Repository: "ghcr.io/example/observer-sandbox", Version: "1.0.0", MinVersion: "1.0.0",
		Commit: strings.Repeat("0123456789", 4), Base: "debian:bookworm-slim@sha256:" + strings.Repeat("7", 64),
		Out: t.TempDir(), Created: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		ManifestVersion: 1, Epoch: 1, Valid: 30 * 24 * time.Hour, Issued: time.Now().UTC().Add(-time.Minute),
	}, f
}

// TestSandboxImageBuildInstalls builds the descriptor, SBOM and manifest
// from a layout, signs with a TEST key, then installs and resolves through
// the node's content store and trust check, so builder and node cannot
// drift.
func TestSandboxImageBuildInstalls(t *testing.T) {
	pub, priv := testKey(t)
	o, f := sandboxFixture(t, "linux/amd64", "linux/arm64")
	o.Key = priv
	d, err := buildSandboxImage(o)
	if err != nil {
		t.Fatal(err)
	}
	if d.Digest != f.top || d.ConfigDigests["linux/arm64"] != f.ids["linux/arm64"] || len(d.ConfigDigests) != 2 {
		t.Fatalf("descriptor: %+v", d)
	}
	dir := filepath.Join(o.Out, string(content.SandboxImage))
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	store := contentchan.Store{Root: t.TempDir(), GOOS: "linux", GOARCH: "amd64"}
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}
	arts := map[string][]byte{sandboximage.DescriptorName: read(sandboximage.DescriptorName), sandboximage.SBOMName: read(sandboximage.SBOMName)}
	if _, err := store.Install(content.SandboxImage, read("manifest.json"), arts, tr); err != nil {
		t.Fatal(err)
	}
	l, err := store.Load(content.SandboxImage, tr, 0)
	if err != nil {
		t.Fatal(err)
	}
	in := sandboximage.Input{Manifest: l.Manifest, Freshness: l.Freshness}
	in.Descriptor, in.DescriptorErr = l.ReadArtifact(sandboximage.DescriptorName)
	in.SBOM, in.SBOMErr = l.ReadArtifact(sandboximage.SBOMName)
	r := sandboximage.Resolve(in)
	if !r.OK || r.Ref != "ghcr.io/example/observer-sandbox@"+f.top {
		t.Fatalf("resolve: %+v", r)
	}
	// The same build gives the same descriptor and SBOM bytes.
	o2 := o
	o2.Out = t.TempDir()
	o2.Key = nil
	if _, err := buildSandboxImage(o2); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{sandboximage.DescriptorName, sandboximage.SBOMName} {
		b, _ := os.ReadFile(filepath.Join(o2.Out, string(content.SandboxImage), n))
		if !bytes.Equal(b, read(n)) {
			t.Errorf("%s differs between two builds", n)
		}
	}
	if _, err := os.Stat(filepath.Join(o2.Out, string(content.SandboxImage), "manifest.json")); !os.IsNotExist(err) {
		t.Error("an unsigned build must write no manifest")
	}
}

func TestSandboxImageRefusals(t *testing.T) {
	_, priv := testKey(t)
	cases := []struct {
		name string
		mut  func(t *testing.T, o *sandboxImageOptions, f *fakeLayout)
	}{
		{"tampered layout blob", func(t *testing.T, o *sandboxImageOptions, f *fakeLayout) { f.write(t, o.OCI, true) }},
		{"missing package list", func(t *testing.T, o *sandboxImageOptions, f *fakeLayout) {
			_ = os.RemoveAll(filepath.Join(o.Packages, "linux_arm64"))
		}},
		{"agent package", func(t *testing.T, o *sandboxImageOptions, f *fakeLayout) {
			p := filepath.Join(o.Packages, "linux_amd64", "packages.tsv")
			b, _ := os.ReadFile(p)
			_ = os.WriteFile(p, append(b, []byte("codex\t1.0\tamd64\n")...), 0o600)
		}},
		{"base by tag", func(t *testing.T, o *sandboxImageOptions, f *fakeLayout) { o.Base = "debian:bookworm-slim" }},
		{"bad version", func(t *testing.T, o *sandboxImageOptions, f *fakeLayout) { o.Version = "1.0" }},
		{"no expiry", func(t *testing.T, o *sandboxImageOptions, f *fakeLayout) { o.Valid = 0 }},
	}
	for _, tc := range cases {
		o, f := sandboxFixture(t, "linux/amd64", "linux/arm64")
		o.Key = priv
		tc.mut(t, &o, f)
		if _, err := buildSandboxImage(o); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestSandboxImageRevokeFlag(t *testing.T) {
	var r revokeFlags
	if err := r.Set("sha256:" + strings.Repeat("A", 64)); err != nil || r[0] != strings.Repeat("a", 64) {
		t.Fatalf("%v %v", r, err)
	}
	for _, bad := range []string{"abc", strings.Repeat("z", 64)} {
		if err := r.Set(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestSandboxImageDeclaresItsSize (R-038): the signing step fills the
// descriptor's size_bytes with the largest platform's layer sum, the
// signing seam (-from-build) accepts it and refuses a declared size the
// layout does not add up to.
func TestSandboxImageDeclaresItsSize(t *testing.T) {
	_, priv := testKey(t)
	// The two platforms differ in size, in both orders, so the larger one
	// is shown to win wherever it sits (LEFT2 audit S7).
	for _, c := range []struct {
		sizes map[string]int64
		want  int64
	}{
		{map[string]int64{"linux/amd64": 3_000_000, "linux/arm64": 9_000_000}, 9_500_000},
		{map[string]int64{"linux/amd64": 9_000_000, "linux/arm64": 3_000_000}, 9_500_000},
		{map[string]int64{"linux/amd64": 7_000_000, "linux/arm64": 2_000_000}, 7_500_000},
	} {
		o, _ := sandboxFixtureSized(t, c.sizes, "linux/amd64", "linux/arm64")
		d, err := buildSandboxImage(o)
		if err != nil {
			t.Fatal(err)
		}
		if d.SizeBytes != c.want {
			t.Fatalf("sizes %v: size_bytes = %d, want the larger platform's %d", c.sizes, d.SizeBytes, c.want)
		}
	}
	o, _ := sandboxFixtureSized(t, map[string]int64{"linux/amd64": 3_000_000, "linux/arm64": 9_000_000}, "linux/amd64", "linux/arm64")
	d, err := buildSandboxImage(o)
	if err != nil {
		t.Fatal(err)
	}
	o.Key = priv
	if _, err := signBuiltSandboxImage(o, "ghcr.io/example"); err != nil {
		t.Fatalf("the signing seam refused the build's own size: %v", err)
	}
	// A descriptor whose declared size was changed after the build.
	dir := filepath.Join(o.Out, string(content.SandboxImage))
	bad := d
	bad.SizeBytes = d.SizeBytes + 1
	b, err := bad.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sandboximage.DescriptorName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := signBuiltSandboxImage(o, "ghcr.io/example"); !errors.Is(err, errDigestMismatch) || !strings.Contains(err.Error(), "declares") {
		t.Fatalf("a mismatched size was signed: %v", err)
	}
}
