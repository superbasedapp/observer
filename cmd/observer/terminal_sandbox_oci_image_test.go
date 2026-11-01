//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// installTestImage installs a sandbox.image manifest signed with a TEST key
// (never the vendor's) and returns the store, the trust that accepts that
// key and the descriptor.
func installTestImage(t *testing.T, revoked ...content.Revocation) (contentchan.Store, contentchan.Trust, sandboximage.Descriptor) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 42
	priv := ed25519.NewKeyFromSeed(seed)
	d := sandboximage.Descriptor{
		Schema: sandboximage.DescriptorSchema, Repository: "ghcr.io/example/observer-sandbox",
		Digest: "sha256:" + strings.Repeat("a", 64), ConfigDigests: map[string]string{"linux/amd64": "sha256:" + strings.Repeat("c", 64)},
		Version: "1.0.0", MinVersion: "1.0.0", Platforms: []string{"linux/amd64"},
		Recipe: "deploy/sandbox-image/Dockerfile", RecipeSHA256: strings.Repeat("e", 64),
		SourceCommit: strings.Repeat("ab", 20), BaseImage: "debian:bookworm-slim@sha256:" + strings.Repeat("f", 64),
		SBOM: sandboximage.SBOMName,
	}
	db, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sb, err := sandboximage.SPDX(sandboximage.SBOMInput{Descriptor: d, Created: time.Now().UTC(), Packages: map[string][]sandboximage.Package{
		"linux/amd64": {{Name: "bash", Version: "5.2", Arch: "amd64"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	m, err := sandboximage.BuildManifest(sandboximage.ManifestInput{
		Descriptor: db, SBOM: sb, ManifestVersion: 1, Epoch: 1, Issued: time.Now().UTC().Add(-time.Minute),
		Valid: 24 * time.Hour, Revoked: revoked,
	})
	if err != nil {
		t.Fatal(err)
	}
	env, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	eb, err := content.EncodeEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	store := ociImageStore(t.TempDir())
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}}
	if _, err := store.Install(content.SandboxImage, eb, map[string][]byte{sandboximage.DescriptorName: db, sandboximage.SBOMName: sb}, tr); err != nil {
		t.Fatal(err)
	}
	return store, tr, d
}

// TestOCIImageUnchangedWithNothingInstalled: no release installs a
// sandbox.image manifest yet, so an existing install sees exactly today's
// behaviour (the configured image, or the "not published yet" refusal).
func TestOCIImageUnchangedWithNothingInstalled(t *testing.T) {
	empty := ociImageStore(t.TempDir())
	for _, img := range []string{"", ociTestImage} {
		got := ociResolveImage(config.TerminalSandboxOCIConfig{Image: img}, empty, contentchan.Trust{VendorKeys: sandboxImageVendorKeys()})
		if got.image != img || got.refusal != "" || got.desc != nil {
			t.Errorf("image %q: %+v", img, got)
		}
	}
	if err := sandboxoci.ValidateImageRef(""); err == nil || !strings.Contains(err.Error(), "not published yet") {
		t.Errorf("the empty-image refusal must keep its text: %v", err)
	}
}

func TestOCIImageDefaultResolvesWhenSigned(t *testing.T) {
	store, tr, d := installTestImage(t)
	got := ociResolveImage(config.TerminalSandboxOCIConfig{}, store, tr)
	if got.image != d.Ref() || got.desc == nil || got.refusal != "" {
		t.Fatalf("%+v", got)
	}
	// The real build's key set does not accept the test key: refused.
	got = ociResolveImage(config.TerminalSandboxOCIConfig{}, store, contentchan.Trust{VendorKeys: sandboxImageVendorKeys()})
	if got.image != "" || !strings.HasPrefix(got.refusal, "Observer's default image: "+sandboximage.VerdictArtifactUnverified) {
		t.Fatalf("untrusted: %+v", got)
	}
	// A configured image is the user's own and is used as configured.
	if got := ociResolveImage(config.TerminalSandboxOCIConfig{Image: ociTestImage}, store, tr); got.image != ociTestImage || got.desc != nil {
		t.Fatalf("configured: %+v", got)
	}
	// The engine side.
	ok := sandboxengine.ImageIdentity{Present: true, ID: "sha256:" + strings.Repeat("c", 64), RepoDigests: []string{d.Ref()}, OS: "linux", Architecture: "amd64"}
	trust := ociImageTrust{image: d.Ref(), desc: &d}
	if r := ociCheckDefaultImage(trust, ok); !r.OK {
		t.Fatalf("signed copy: %+v", r)
	}
	bad := ok
	bad.ID = "sha256:" + strings.Repeat("d", 64)
	if r := ociCheckDefaultImage(trust, bad); r.OK || r.Reason != sandboximage.ReasonTampered {
		t.Fatalf("rebuilt copy: %+v", r)
	}
	if r := ociCheckDefaultImage(ociImageTrust{image: ociTestImage}, sandboxengine.ImageIdentity{}); !r.OK {
		t.Fatal("a configured image skips the default image's engine check")
	}
}

func TestOCIImageConfiguredButRevoked(t *testing.T) {
	store, tr, _ := installTestImage(t, content.Revocation{SHA256: ociTestImage[strings.Index(ociTestImage, "@sha256:")+8:]})
	got := ociResolveImage(config.TerminalSandboxOCIConfig{Image: ociTestImage}, store, tr)
	if got.image != "" || !strings.Contains(got.refusal, "revoked") {
		t.Fatalf("%+v", got)
	}
}
