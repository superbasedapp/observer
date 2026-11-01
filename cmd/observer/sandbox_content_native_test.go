//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// nativeRig installs signed sandbox.native_files manifests (a TEST key)
// into a store and resolves them as the Windows helper does.
type nativeRig struct {
	t    *testing.T
	st   contentchan.Store
	tr   contentchan.Trust
	priv ed25519.PrivateKey
	now  time.Time
}

func newNativeRig(t *testing.T) *nativeRig {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := &nativeRig{t: t, priv: priv, now: time.Now().UTC(), tr: contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}}
	r.st = contentchan.Store{Root: t.TempDir(), GOOS: "windows", GOARCH: "amd64", Now: func() time.Time { return r.now }}
	return r
}

func (r *nativeRig) install(version int64, desc []byte, revoked ...string) error {
	r.t.Helper()
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.SandboxNative, ManifestVersion: version, Epoch: 1,
		IssuedAt: r.now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: r.now.Add(48 * time.Hour).Format(time.RFC3339),
		Entries: []content.Entry{{
			Name: sandboxmxc.NativeFilesName, OS: "windows", Arch: "amd64", SizeBytes: int64(len(desc)), SHA256: content.HashBytes(desc),
			Upstream: content.UpstreamCheck{Method: content.UpstreamAuthenticode},
		}},
	}
	for _, s := range revoked {
		m.Revoked = append(m.Revoked, content.Revocation{SHA256: s})
	}
	env, err := content.Sign(m, r.priv)
	if err != nil {
		r.t.Fatal(err)
	}
	b, _ := content.EncodeEnvelope(env)
	_, err = r.st.Install(content.SandboxNative, b, map[string][]byte{sandboxmxc.NativeFilesName: desc}, r.tr)
	return err
}

func (r *nativeRig) resolve() sandboxmxc.SignedResult {
	return sandboxmxc.ResolveSigned(mxcSignedInput(r.st, r.tr, sandboxmxc.ManifestX64, true, "amd64"))
}

func nativeDesc(t *testing.T, mut func(*sandboxmxc.NativeFiles)) []byte {
	t.Helper()
	n := sandboxmxc.NativeFilesFromManifest(sandboxmxc.ManifestX64, "amd64", "valid test")
	if mut != nil {
		mut(&n)
	}
	b, err := n.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMXCSignedNoneInstalledIsTheCompiledPins: with nothing installed the
// helper's set is exactly the compiled pins (today's behaviour).
func TestMXCSignedNoneInstalledIsTheCompiledPins(t *testing.T) {
	r := newNativeRig(t)
	res := r.resolve()
	if !res.OK || res.Source != sandboxmxc.SignedSourceCompiled || res.Rule != "none_installed" {
		t.Fatalf("%+v", res)
	}
	if res.Manifest.PackageSHA256 != sandboxmxc.ManifestX64.PackageSHA256 || len(res.Manifest.Files) != 2 {
		t.Fatal("not the compiled pins")
	}
	// The real reader over an empty observer directory says the same.
	if got := mxcEffectiveSet(t.TempDir(), "amd64"); !got.OK || got.Source != sandboxmxc.SignedSourceCompiled {
		t.Fatalf("mxcEffectiveSet: %+v", got)
	}
}

func TestMXCSignedLoads(t *testing.T) {
	r := newNativeRig(t)
	if err := r.install(1, nativeDesc(t, nil)); err != nil {
		t.Fatal(err)
	}
	if res := r.resolve(); !res.OK || res.Source != sandboxmxc.SignedSourceSigned || res.Stale {
		t.Fatalf("%+v", res)
	}
}

// TestMXCSignedRefusesAnotherHash: a manifest naming a hash the compiled
// pins do not is refused (it cannot be installed as anything else).
func TestMXCSignedRefusesAnotherHash(t *testing.T) {
	r := newNativeRig(t)
	if err := r.install(1, nativeDesc(t, func(n *sandboxmxc.NativeFiles) { n.Files[1].SHA256 = strings.Repeat("d", 64) })); err != nil {
		t.Fatal(err)
	}
	res := r.resolve()
	if res.OK || res.Rule != "floor" || res.Verdict.Code != sandboxmxc.VerdictArtifactUnverified {
		t.Fatalf("%+v", res)
	}
}

// TestMXCSignedRevokedRefusedBeforeLoad: a later manifest revoking the set
// is refused at the table's revocation row, before the descriptor is read.
func TestMXCSignedRevokedRefusedBeforeLoad(t *testing.T) {
	r := newNativeRig(t)
	if err := r.install(1, nativeDesc(t, nil)); err != nil {
		t.Fatal(err)
	}
	if err := r.install(2, nativeDesc(t, nil), sandboxmxc.ManifestX64.Files[0].SHA256); err != nil {
		t.Fatal(err)
	}
	res := r.resolve()
	if res.OK || res.Rule != "revoked" || !strings.Contains(res.Verdict.Reason, "mxc_ffi.dll") {
		t.Fatalf("%+v", res)
	}
}

// TestMXCSignedExpiredIsLastKnownGood: an expired manifest is used as
// last-known-good and reported stale; past the age floor it is refused.
func TestMXCSignedExpiredIsLastKnownGood(t *testing.T) {
	r := newNativeRig(t)
	if err := r.install(1, nativeDesc(t, nil)); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(72 * time.Hour)
	if res := r.resolve(); !res.OK || !res.Stale {
		t.Fatalf("expired: %+v", res)
	}
	r.now = r.now.Add(400 * 24 * time.Hour)
	if res := r.resolve(); res.OK || res.Rule != "age" {
		t.Fatalf("past the floor: %+v", res)
	}
}

// TestMXCSignedUnverifiableRefused: an installed manifest that no longer
// verifies (another key) refuses.
func TestMXCSignedUnverifiableRefused(t *testing.T) {
	r := newNativeRig(t)
	if err := r.install(1, nativeDesc(t, nil)); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	in := mxcSignedInput(r.st, contentchan.Trust{VendorKeys: []ed25519.PublicKey{other}}, sandboxmxc.ManifestX64, true, "amd64")
	if res := sandboxmxc.ResolveSigned(in); res.OK || res.Rule != "load" {
		t.Fatalf("%+v", res)
	}
}
