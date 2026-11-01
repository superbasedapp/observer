package sandboximage

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// The tests sign with a TEST key generated here; nothing in this file is,
// or names, the vendor's real key.

var t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func testKey(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

func hex64(c byte) string { return strings.Repeat(string(c), 64) }

func testDescriptor(version, minVersion string, digest byte) Descriptor {
	return Descriptor{
		Schema: DescriptorSchema, Repository: "ghcr.io/example/observer-sandbox",
		Digest:        "sha256:" + hex64(digest),
		ConfigDigests: map[string]string{"linux/amd64": "sha256:" + hex64('c')},
		Version:       version, MinVersion: minVersion,
		Platforms: []string{"linux/amd64", "linux/arm64"},
		Recipe:    "deploy/sandbox-image/Dockerfile", RecipeSHA256: hex64('e'),
		SourceCommit: strings.Repeat("ab", 20),
		BaseImage:    "debian:bookworm-slim@sha256:" + hex64('f'),
		SBOM:         SBOMName,
	}
}

func testSBOM(t *testing.T, d Descriptor) []byte {
	t.Helper()
	b, err := SPDX(SBOMInput{Descriptor: d, Created: t0, Packages: map[string][]Package{
		"linux/amd64": {{Name: "bash", Version: "5.2.15-2+b7", Arch: "amd64"}, {Name: "git", Version: "1:2.39.5-0+deb12u2", Arch: "amd64"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type published struct {
	env       []byte
	artifacts map[string][]byte
}

func publish(t *testing.T, priv ed25519.PrivateKey, version int64, issued time.Time, d Descriptor, revoked ...content.Revocation) published {
	t.Helper()
	db, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sb := testSBOM(t, d)
	m, err := BuildManifest(ManifestInput{Descriptor: db, SBOM: sb, ManifestVersion: version, Epoch: 1, Issued: issued, Valid: 30 * 24 * time.Hour, Revoked: revoked})
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
	return published{env: eb, artifacts: map[string][]byte{DescriptorName: db, SBOMName: sb}}
}

// resolveFrom is what the daemon's glue does: load the kind through the
// content channel, read both artifacts, resolve.
func resolveFrom(s contentchan.Store, tr contentchan.Trust, needFresh bool) Result {
	l, err := s.Load(content.SandboxImage, tr, 0)
	in := Input{LoadErr: err, NeedFresh: needFresh}
	if errors.Is(err, contentchan.ErrNotInstalled) {
		in = Input{NotInstalled: true}
	} else if err == nil {
		in.Manifest, in.Freshness = l.Manifest, l.Freshness
		in.Descriptor, in.DescriptorErr = l.ReadArtifact(DescriptorName)
		in.SBOM, in.SBOMErr = l.ReadArtifact(SBOMName)
	}
	return Resolve(in)
}

func newStore(t *testing.T, clock *time.Time) contentchan.Store {
	return contentchan.Store{Root: t.TempDir(), Now: func() time.Time { return *clock }, GOOS: "linux", GOARCH: "amd64"}
}

func TestResolveAcceptsASignedImage(t *testing.T) {
	pub, priv := testKey(7)
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}
	clock := t0
	s := newStore(t, &clock)
	p := publish(t, priv, 1, t0.Add(-time.Hour), testDescriptor("1.0.0", "1.0.0", 'a'))
	if _, err := s.Install(content.SandboxImage, p.env, p.artifacts, tr); err != nil {
		t.Fatal(err)
	}
	r := resolveFrom(s, tr, true)
	if !r.OK || r.Ref != "ghcr.io/example/observer-sandbox@sha256:"+hex64('a') || r.Stale {
		t.Fatalf("resolve: %+v", r)
	}
}

// TestNoRealKeyIsArtifactUnverified: with the real vendor key absent (an
// empty key set, what update.VendorPublicKeys returns in a build without
// key material), a manifest signed by anyone else is artifact_unverified.
func TestNoRealKeyIsArtifactUnverified(t *testing.T) {
	pub, priv := testKey(7)
	clock := t0
	s := newStore(t, &clock)
	p := publish(t, priv, 1, t0.Add(-time.Hour), testDescriptor("1.0.0", "1.0.0", 'a'))
	if _, err := s.Install(content.SandboxImage, p.env, p.artifacts, contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}); err != nil {
		t.Fatal(err)
	}
	for name, keys := range map[string][]ed25519.PublicKey{"no key": nil, "another key": {func() ed25519.PublicKey { k, _ := testKey(9); return k }()}} {
		r := resolveFrom(s, contentchan.Trust{VendorKeys: keys}, false)
		if r.OK || !strings.HasPrefix(r.Error(), VerdictArtifactUnverified) {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// And an install with no key at all is refused before anything is
	// written.
	empty := newStore(t, &clock)
	if _, err := empty.Install(content.SandboxImage, p.env, p.artifacts, contentchan.Trust{}); content.ReasonOf(err) != content.ContentReasonNoKey {
		t.Errorf("install with no key: %v", err)
	}
	if r := resolveFrom(empty, contentchan.Trust{}, false); r.OK || r.Reason != ReasonNotInstalled || !strings.Contains(r.Detail, "not published yet") {
		t.Errorf("nothing installed: %+v", r)
	}
}

// TestA12SupplyChainRollback is acceptance case A12 for the default image:
// a replayed older manifest, a below-minimum artifact, a revoked artifact
// and a tampered image are each refused before use.
func TestA12SupplyChainRollback(t *testing.T) {
	pub, priv := testKey(7)
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}

	t.Run("replayed older manifest", func(t *testing.T) {
		clock := t0
		s := newStore(t, &clock)
		v1 := publish(t, priv, 1, t0.Add(-2*time.Hour), testDescriptor("1.0.0", "1.0.0", 'a'))
		v2 := publish(t, priv, 2, t0.Add(-time.Hour), testDescriptor("1.1.0", "1.0.0", 'b'))
		for _, p := range []published{v1, v2} {
			if _, err := s.Install(content.SandboxImage, p.env, p.artifacts, tr); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.Install(content.SandboxImage, v1.env, v1.artifacts, tr); content.ReasonOf(err) != content.ContentReasonRollback {
			t.Fatalf("replay install: %v", err)
		}
		if r := resolveFrom(s, tr, false); !r.OK || r.Descriptor.Version != "1.1.0" {
			t.Fatalf("the last-known-good must stay: %+v", r)
		}
		// The older envelope copied over the accepted one on disk.
		dir, _ := s.KindDir(content.SandboxImage)
		if err := os.WriteFile(filepath.Join(dir, contentchan.ManifestFile), v1.env, 0o600); err != nil {
			t.Fatal(err)
		}
		if r := resolveFrom(s, tr, false); r.OK || !strings.HasPrefix(r.Error(), VerdictArtifactUnverified) {
			t.Fatalf("a replayed envelope on disk: %+v", r)
		}
	})

	t.Run("below the minimum", func(t *testing.T) {
		for name, d := range map[string]Descriptor{
			"under the manifest's minimum": testDescriptor("1.1.0", "1.2.0", 'a'),
			"under the agent's floor":      testDescriptor("0.9.0", "0.1.0", 'a'),
		} {
			clock := t0
			s := newStore(t, &clock)
			p := publish(t, priv, 1, t0.Add(-time.Hour), d)
			if _, err := s.Install(content.SandboxImage, p.env, p.artifacts, tr); err != nil {
				t.Fatal(err)
			}
			if r := resolveFrom(s, tr, false); r.OK || r.Reason != ReasonBelowMinimum {
				t.Errorf("%s: %+v", name, r)
			}
		}
	})

	t.Run("revoked", func(t *testing.T) {
		clock := t0
		s := newStore(t, &clock)
		d := testDescriptor("1.0.0", "1.0.0", 'a')
		v1 := publish(t, priv, 1, t0.Add(-2*time.Hour), d)
		if _, err := s.Install(content.SandboxImage, v1.env, v1.artifacts, tr); err != nil {
			t.Fatal(err)
		}
		// The project withdraws the image digest itself.
		v2 := publish(t, priv, 2, t0.Add(-time.Hour), d, content.Revocation{SHA256: hex64('a'), Reason: "withdrawn"})
		if _, err := s.Install(content.SandboxImage, v2.env, v2.artifacts, tr); err != nil {
			t.Fatal(err)
		}
		if r := resolveFrom(s, tr, false); r.OK || r.Reason != ReasonRevoked {
			t.Fatalf("revoked image: %+v", r)
		}
		l, err := s.Load(content.SandboxImage, tr, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !RevokedRef(l.Manifest, "my.registry/own@sha256:"+hex64('a')) || RevokedRef(l.Manifest, "my.registry/own@sha256:"+hex64('b')) {
			t.Error("a hand-pinned image at a revoked digest must be refused too")
		}
	})

	t.Run("tampered", func(t *testing.T) {
		clock := t0
		s := newStore(t, &clock)
		d := testDescriptor("1.0.0", "1.0.0", 'a')
		p := publish(t, priv, 1, t0.Add(-time.Hour), d)
		if _, err := s.Install(content.SandboxImage, p.env, p.artifacts, tr); err != nil {
			t.Fatal(err)
		}
		// The engine's image: re-tagged, rebuilt, or absent.
		good := ImageFacts{Present: true, ID: "sha256:" + hex64('c'), RepoDigests: []string{d.Ref()}, Platform: "linux/amd64"}
		if r := CheckEngineImage(d, good); !r.OK {
			t.Fatalf("the signed image: %+v", r)
		}
		for name, f := range map[string]ImageFacts{
			"other id":          {Present: true, ID: "sha256:" + hex64('d'), RepoDigests: []string{d.Ref()}, Platform: "linux/amd64"},
			"no repo digest":    {Present: true, ID: "sha256:" + hex64('c'), Platform: "linux/amd64"},
			"other repo digest": {Present: true, ID: "sha256:" + hex64('c'), RepoDigests: []string{"ghcr.io/example/observer-sandbox@sha256:" + hex64('9')}, Platform: "linux/amd64"},
			"unsigned platform": {Present: true, ID: "sha256:" + hex64('c'), RepoDigests: []string{d.Ref()}, Platform: "linux/arm64"},
		} {
			if r := CheckEngineImage(d, f); r.OK || r.Reason != ReasonTampered {
				t.Errorf("%s: %+v", name, r)
			}
		}
		if r := CheckEngineImage(d, ImageFacts{}); r.OK || r.Reason != ReasonNotPresent {
			t.Errorf("absent: %+v", r)
		}
		// The descriptor rewritten on disk after install.
		dir, _ := s.KindDir(content.SandboxImage)
		forged := testDescriptor("1.0.0", "1.0.0", '9')
		fb, _ := forged.Encode()
		if len(fb) != len(p.artifacts[DescriptorName]) {
			t.Fatal("the forged descriptor must keep the size so only the digest catches it")
		}
		if err := os.WriteFile(filepath.Join(dir, DescriptorName), fb, 0o600); err != nil {
			t.Fatal(err)
		}
		if r := resolveFrom(s, tr, false); r.OK || r.Reason != ReasonTampered {
			t.Fatalf("a rewritten descriptor: %+v", r)
		}
	})
}

// TestExpiryAndLastKnownGood: an expired manifest keeps an image already
// present usable as last-known-good, reported; a run that needs the image
// fetched is refused; past the age floor nothing is used.
func TestExpiryAndLastKnownGood(t *testing.T) {
	pub, priv := testKey(7)
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}
	clock := t0
	s := newStore(t, &clock)
	p := publish(t, priv, 1, t0.Add(-time.Hour), testDescriptor("1.0.0", "1.0.0", 'a'))
	if _, err := s.Install(content.SandboxImage, p.env, p.artifacts, tr); err != nil {
		t.Fatal(err)
	}
	clock = t0.Add(40 * 24 * time.Hour)
	if r := resolveFrom(s, tr, false); !r.OK || !r.Stale {
		t.Errorf("present, expired: %+v", r)
	}
	if r := resolveFrom(s, tr, true); r.OK || r.Reason != ReasonNeedsFresh {
		t.Errorf("needs a fetch, expired: %+v", r)
	}
	clock = t0.Add(400 * 24 * time.Hour)
	if r := resolveFrom(s, tr, false); r.OK || r.Reason != ReasonUnknownAge {
		t.Errorf("past the age floor: %+v", r)
	}
	// A failed newer install keeps the last-known-good and records why.
	clock = t0.Add(time.Hour)
	bad := publish(t, priv, 2, t0, testDescriptor("1.1.0", "1.0.0", 'b'))
	bad.artifacts[SBOMName] = []byte("{}")
	st, err := s.Install(content.SandboxImage, bad.env, bad.artifacts, tr)
	if err == nil || st.LastFailure == "" || st.Accepted.ManifestVersion != 1 {
		t.Errorf("a bad update must keep the last-known-good: %+v %v", st, err)
	}
}

// TestResolveRules is one case per resolution row that the channel cases
// above do not reach.
func TestResolveRules(t *testing.T) {
	d := testDescriptor("1.0.0", "1.0.0", 'a')
	db, _ := d.Encode()
	sb := testSBOM(t, d)
	base := Input{Manifest: content.Manifest{Kind: content.SandboxImage}, Freshness: content.Fresh, Descriptor: db, SBOM: sb}
	cases := []struct {
		name   string
		mut    func(in *Input)
		reason string
	}{
		{"ok", func(*Input) {}, ""},
		{"not installed", func(in *Input) { in.NotInstalled = true }, ReasonNotInstalled},
		{"load refused", func(in *Input) { in.LoadErr = &content.Refusal{Reason: content.ContentReasonVendorSig} }, string(content.ContentReasonVendorSig)},
		{"load error", func(in *Input) { in.LoadErr = errors.New("disk") }, string(content.ContentReasonEnvelope)},
		{"wrong kind", func(in *Input) { in.Manifest.Kind = content.SandboxRootfs }, string(content.ContentReasonKind)},
		{"unknown age", func(in *Input) { in.Freshness = content.Unknown }, ReasonUnknownAge},
		{"descriptor revoked", func(in *Input) { in.DescriptorErr = &content.Refusal{Reason: content.ContentReasonRevoked} }, ReasonRevoked},
		{"descriptor missing", func(in *Input) { in.DescriptorErr = &content.Refusal{Reason: content.ContentReasonNotCovered} }, ReasonDescriptor},
		{"descriptor garbage", func(in *Input) { in.Descriptor = []byte("{") }, ReasonDescriptor},
		{"agent cli", func(in *Input) {
			x := d
			x.AgentCLI = true
			in.Descriptor, _ = x.Encode()
		}, ReasonDescriptor},
		{"unknown field", func(in *Input) { in.Descriptor = []byte(strings.Replace(string(db), "{", `{"extra":1,`, 1)) }, ReasonDescriptor},
		{"image id revoked", func(in *Input) { in.Manifest.Revoked = []content.Revocation{{SHA256: hex64('c')}} }, ReasonRevoked},
		{"bad floor", func(in *Input) { in.Floor = "x" }, ReasonBelowMinimum},
		{"sbom missing", func(in *Input) { in.SBOMErr = errors.New("gone") }, ReasonSBOM},
		{"sbom garbage", func(in *Input) { in.SBOM = []byte(`{"spdxVersion":"SPDX-2.2"}`) }, ReasonSBOM},
	}
	for _, tc := range cases {
		in := base
		tc.mut(&in)
		r := Resolve(in)
		if r.Reason != tc.reason || r.OK != (tc.reason == "") {
			t.Errorf("%s: got %+v, want reason %q", tc.name, r, tc.reason)
		}
		if !r.OK && r.Ref != "" {
			t.Errorf("%s: a refused image carries no reference", tc.name)
		}
	}
}

func TestDescriptorRules(t *testing.T) {
	cases := []struct {
		name string
		mut  func(d *Descriptor)
	}{
		{"schema", func(d *Descriptor) { d.Schema = "x" }},
		{"repository with digest", func(d *Descriptor) { d.Repository += "@sha256:" + hex64('a') }},
		{"repository upper case", func(d *Descriptor) { d.Repository = "Ghcr.io/x" }},
		{"digest", func(d *Descriptor) { d.Digest = "sha256:abc" }},
		{"config digest", func(d *Descriptor) { d.ConfigDigests = map[string]string{"windows/amd64": "sha256:" + hex64('c')} }},
		{"version", func(d *Descriptor) { d.Version = "v1.0.0" }},
		{"version leading zero", func(d *Descriptor) { d.Version = "1.01.0" }},
		{"min version", func(d *Descriptor) { d.MinVersion = "1.0" }},
		{"no platforms", func(d *Descriptor) { d.Platforms = nil }},
		{"platform", func(d *Descriptor) { d.Platforms = []string{"darwin/arm64"} }},
		{"recipe escapes", func(d *Descriptor) { d.Recipe = "../Dockerfile" }},
		{"recipe digest", func(d *Descriptor) { d.RecipeSHA256 = "x" }},
		{"commit", func(d *Descriptor) { d.SourceCommit = "abc" }},
		{"base by tag", func(d *Descriptor) { d.BaseImage = "debian:bookworm-slim" }},
		{"sbom name", func(d *Descriptor) { d.SBOM = "other.json" }},
		{"agent cli", func(d *Descriptor) { d.AgentCLI = true }},
	}
	if err := testDescriptor("1.0.0", "1.0.0", 'a').Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		d := testDescriptor("1.0.0", "1.0.0", 'a')
		tc.mut(&d)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestSBOMIsDeterministicAndRefusesAgents(t *testing.T) {
	d := testDescriptor("1.0.0", "1.0.0", 'a')
	pk := map[string][]Package{
		"linux/arm64": {{Name: "git", Version: "1:2.39", Arch: "arm64"}, {Name: "bash", Version: "5.2", Arch: "arm64"}},
		"linux/amd64": {{Name: "bash", Version: "5.2", Arch: "amd64"}},
	}
	a, err := SPDX(SBOMInput{Descriptor: d, Created: t0, Packages: pk})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SPDX(SBOMInput{Descriptor: d, Created: t0, Packages: pk})
	if string(a) != string(b) {
		t.Error("the same input must give the same SBOM bytes")
	}
	if err := CheckSBOM(a); err != nil {
		t.Fatal(err)
	}
	pk["linux/amd64"] = append(pk["linux/amd64"], Package{Name: "claude-code", Version: "1.0", Arch: "all"})
	if _, err := SPDX(SBOMInput{Descriptor: d, Created: t0, Packages: pk}); err == nil {
		t.Error("an agent CLI package must refuse the SBOM")
	}
	forged := strings.Replace(string(a), `"name": "git"`, `"name": "codex"`, 1)
	if err := CheckSBOM([]byte(forged)); err == nil {
		t.Error("an SBOM listing an agent CLI must be refused")
	}
	for _, n := range []string{"@anthropic-ai/claude-code", "@openai/codex", "Aider"} {
		if !IsAgentPackage(n) {
			t.Errorf("%s is an agent package", n)
		}
	}
	if IsAgentPackage("git") {
		t.Error("git is not an agent")
	}
}

func TestParsePackagesTSV(t *testing.T) {
	got, err := ParsePackagesTSV([]byte("bash\t5.2.15-2+b7\tamd64\nca-certificates\t20230311\tall\n"))
	if err != nil || len(got) != 2 || got[1].Arch != "all" {
		t.Fatalf("%+v %v", got, err)
	}
	for _, bad := range []string{"", "bash 5.2 amd64\n", "bash\t5.2\ts390x\n", "Bash\t5.2\tamd64\n"} {
		if _, err := ParsePackagesTSV([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestVersionOrder(t *testing.T) {
	for _, c := range [][2]string{{"1.0.0", "1.0.1"}, {"1.9.0", "1.10.0"}, {"0.9.9", "1.0.0"}} {
		a, _ := ParseVersion(c[0])
		b, _ := ParseVersion(c[1])
		if !a.Less(b) || b.Less(a) {
			t.Errorf("%s < %s", c[0], c[1])
		}
	}
	if _, err := ParseVersion(MinVersion); err != nil {
		t.Fatal(err)
	}
}

func TestBuildManifestNeedsAnExpiry(t *testing.T) {
	d := testDescriptor("1.0.0", "1.0.0", 'a')
	db, _ := d.Encode()
	sb := testSBOM(t, d)
	for name, in := range map[string]ManifestInput{
		"no validity":  {Descriptor: db, SBOM: sb, ManifestVersion: 1, Epoch: 1, Issued: t0},
		"too long":     {Descriptor: db, SBOM: sb, ManifestVersion: 1, Epoch: 1, Issued: t0, Valid: 400 * 24 * time.Hour},
		"version zero": {Descriptor: db, SBOM: sb, Epoch: 1, Issued: t0, Valid: time.Hour},
		"bad sbom":     {Descriptor: db, SBOM: []byte("{}"), ManifestVersion: 1, Epoch: 1, Issued: t0, Valid: time.Hour},
	} {
		if _, err := BuildManifest(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
