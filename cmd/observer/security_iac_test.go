//go:build !sbo_omit_security && !sbo_omit_security_scan_trivy && !sbo_omit_security_scan_kics

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestIaCInertWithNoComponentsBlock is the lane's golden for an existing
// install: no loop starts, every verb refuses before it opens anything,
// status and doctor print fixed lines without probing, and nothing is
// written under the user's home.
func TestIaCInertWithNoComponentsBlock(t *testing.T) {
	cfgPath := iacConfig(t, "")
	var out bytes.Buffer
	legacy := newGatedGroup(namedGroup{}, componentstate.Legacy(), &out)
	// namedGroup{} has no errgroup: a loop that started here would panic.
	startIaCDaemon(context.Background(), legacy, cfgPath, componentstate.Legacy())
	if len(legacy.skipped) != 0 || out.Len() != 0 {
		t.Fatalf("legacy: skipped %v out %q", legacy.skipped, out.String())
	}
	for _, id := range []seciac.EngineID{seciac.Trivy, seciac.KICS} {
		if _, err := openIaCEnv(context.Background(), cfgPath, id); err == nil || !strings.Contains(err.Error(), "not selected") {
			t.Fatalf("%s: the env opened with no block: %v", id, err)
		}
	}
	got := securityIaCDoctorCheck(context.Background(), cfgPath).Message
	want := "Trivy: not selected (opt-in; add security.scan.trivy and security.code under [components]); nothing is installed, downloaded or run; " +
		"KICS: not selected (opt-in; add security.scan.kics and security.code under [components]); nothing is installed, downloaded or run"
	if got != want {
		t.Fatalf("doctor\n got %s\nwant %s", got, want)
	}
	for _, r := range iacStatusRows(context.Background(), cfgPath) {
		if r.Selected || r.Installed || r.Binary != "" || r.Digest != "" {
			t.Fatalf("a not-selected engine was probed: %+v", r)
		}
	}
	home, _ := os.UserHomeDir()
	_ = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			t.Errorf("an existing install gained %s", p)
		}
		return nil
	})
	for _, id := range []string{"security.scan.trivy", "security.scan.kics"} {
		added := componentstate.Resolve(config.ComponentsConfig{Add: []string{id, "security.code"}}, nil)
		if !loopAllowed(added, id) {
			t.Fatalf("selected: the %s loop is not allowed to start", id)
		}
		removed := componentstate.Resolve(config.ComponentsConfig{Remove: []string{id}}, nil)
		if loopAllowed(removed, id) {
			t.Fatalf("removed: the %s loop may still start", id)
		}
	}
}

// fakeIaCNet serves the archive and its bundle and counts requests.
type fakeIaCNet struct {
	files map[string][]byte
	calls []string
}

func (f *fakeIaCNet) Download(_ context.Context, raw string, limit int64, w io.Writer) (int64, string, error) {
	f.calls = append(f.calls, raw)
	b, ok := f.files[raw]
	if !ok {
		return 0, "", errors.New("HTTP 404")
	}
	if int64(len(b)) > limit {
		// A body over its cap is cut: what reached w is discarded.
		_, _ = w.Write(b[:limit])
		return limit, "", errors.New("over its cap")
	}
	n, _ := w.Write(b)
	sum := sha256.Sum256(b)
	return int64(n), hex.EncodeToString(sum[:]), nil
}

func tarGz(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		body []byte
	}{{"README.md", []byte("readme")}, {name, body}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write(f.body)
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// testSigning is a test Fulcio root and a function that signs a digest as
// a sigstore bundle under identity.
func testSigning(t *testing.T) ([]byte, func(identity string, sum [32]byte) []byte) {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(der)
	rootPEM := pemCert(der)
	tr, _ := seciac.Lookup(seciac.Trivy)
	return rootPEM, func(identity string, sum [32]byte) []byte {
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		id, _ := url.Parse(identity)
		issuer, _ := asn1.Marshal(tr.Issuer)
		nb := time.Now().Add(-2 * time.Hour)
		ltpl := &x509.Certificate{
			SerialNumber: big.NewInt(2), NotBefore: nb, NotAfter: nb.Add(10 * time.Minute),
			URIs: []*url.URL{id}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: issuer}},
		}
		ld, _ := x509.CreateCertificate(rand.Reader, ltpl, root, &leafKey.PublicKey, rootKey)
		sig, _ := ecdsa.SignASN1(rand.Reader, leafKey, sum[:])
		b, _ := json.Marshal(map[string]any{
			"mediaType":            "application/vnd.dev.sigstore.bundle.v0.3+json",
			"verificationMaterial": map[string]any{"certificate": map[string]string{"rawBytes": base64.StdEncoding.EncodeToString(ld)}},
			"messageSignature": map[string]any{
				"messageDigest": map[string]string{"algorithm": "SHA2_256", "digest": base64.StdEncoding.EncodeToString(sum[:])},
				"signature":     base64.StdEncoding.EncodeToString(sig),
			},
		})
		return b
	}
}

func pemCert(der []byte) []byte {
	return []byte("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END CERTIFICATE-----\n")
}

// iacFixture is a selected Trivy with a verified engine manifest pinning
// this platform's archive, and the fake lane serving it.
type iacFixture struct {
	cfgPath string
	archive []byte
	binary  []byte
	net     *fakeIaCNet
	pin     seciac.Pin
}

func newIaCFixture(t *testing.T) *iacFixture {
	t.Helper()
	cfgPath := iacConfig(t, "[components]\nadd = [\"security.scan.trivy\", \"security.code\"]\n")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	prevTrust, prevNet, prevRoots := iacTrust, iacTrivyNet, iacFulcioRoots
	t.Cleanup(func() { iacTrust, iacTrivyNet, iacFulcioRoots = prevTrust, prevNet, prevRoots })
	iacTrust = func() contentchan.Trust { return contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}} }
	member := "trivy"
	if runtime.GOOS == "windows" {
		t.Skip("the fixture builds a tar.gz; Windows pins a zip")
	}
	binary := []byte("#!/bin/sh\necho trivy\n")
	tr, _ := seciac.Lookup(seciac.Trivy)
	assetName := "trivy_" + tr.TestedVersion + "_" + map[string]string{"linux": "Linux", "darwin": "macOS"}[runtime.GOOS] + "-" + map[string]string{"amd64": "64bit", "arm64": "ARM64"}[runtime.GOARCH] + ".tar.gz"
	archive := tarGz(t, member, binary)
	sum := sha256.Sum256(archive)
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.Engine, ManifestVersion: 1, Epoch: 1,
		IssuedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), ExpiresAt: time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Entries: []content.Entry{{
			Name: assetName, Version: tr.TestedVersion, OS: runtime.GOOS, Arch: runtime.GOARCH, SizeBytes: int64(len(archive)), SHA256: hex.EncodeToString(sum[:]),
			Upstream: content.UpstreamCheck{Method: content.UpstreamCosignKeylessOnline, Identity: tr.Identity(tr.TestedVersion), Issuer: tr.Issuer, VerifiedAt: time.Now().UTC().Format(time.RFC3339), VerifiedWhere: "release_pipeline"},
		}},
	}
	env, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := content.EncodeEnvelope(env)
	resolved, _ := config.ResolveGlobalPath(cfgPath)
	if _, err := iacContentStore(resolved).Install(content.Engine, raw, map[string][]byte{assetName: archive}, iacTrust()); err != nil {
		t.Fatal(err)
	}
	rootPEM, sign := testSigning(t)
	iacFulcioRoots = func() ([]byte, []byte) { return rootPEM, nil }
	pin := seciac.Pin{Engine: seciac.Trivy, Version: tr.TestedVersion, OS: runtime.GOOS, Arch: runtime.GOARCH, Asset: assetName}
	f := &iacFixture{cfgPath: cfgPath, archive: archive, binary: binary, pin: pin, net: &fakeIaCNet{files: map[string][]byte{
		pin.URL():       archive,
		pin.BundleURL(): sign(tr.Identity(tr.TestedVersion), sum),
	}}}
	iacTrivyNet = func() iacDownloader { return f.net }
	return f
}

func (f *iacFixture) open(t *testing.T) *iacEnv {
	t.Helper()
	env, err := openIaCEnv(context.Background(), f.cfgPath, seciac.Trivy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.cleanup)
	return env
}

// TestIaCGuidedInstall: nothing downloads before the consent; with it, the
// archive and its bundle download, the sha256 and the signature pre-check
// pass, the member is extracted and renamed into place and the install
// record verifies, so the driver decides the binary verified.
func TestIaCGuidedInstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tar.gz fixture")
	}
	f := newIaCFixture(t)
	env := f.open(t)
	if _, err := env.installIaCEngine(context.Background(), "cli", false); !errors.Is(err, errIaCConsentNeeded) {
		t.Fatalf("no consent: %v", err)
	}
	if len(f.net.calls) != 0 {
		t.Fatalf("downloaded before the consent: %v", f.net.calls)
	}
	if _, err := env.installIaCEngine(context.Background(), "agent", true); err == nil {
		t.Fatal("an agent surface gave the consent")
	}
	plan, err := env.installIaCEngine(context.Background(), "cli", true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(iacInstalledPath(seciac.Trivy))
	if err != nil || !bytes.Equal(b, f.binary) {
		t.Fatalf("installed binary %q %v", b, err)
	}
	rec := readIaCInstallRecord(env.secDir, seciac.Trivy)
	binSum := sha256.Sum256(f.binary)
	if rec == nil || rec.ArchiveSHA256 != plan.Pin.AssetSHA256 || rec.BinarySHA256 != hex.EncodeToString(binSum[:]) {
		t.Fatalf("install record %+v", rec)
	}
	d := seciac.Decide(seciac.Input{Engine: seciac.Trivy, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Digest: rec.BinarySHA256, Manifest: env.manifest, Installed: rec, Managed: true})
	if d.Status != seciac.StatusVerified {
		t.Fatalf("the guided install's binary is not verified, even for a managed node: %+v", d)
	}
	// A second install is a no-op: no download.
	n := len(f.net.calls)
	if _, err := f.open(t).installIaCEngine(context.Background(), "cli", false); err != nil || len(f.net.calls) != n {
		t.Fatalf("reinstall: %v, %d new calls", err, len(f.net.calls)-n)
	}
	assertNoTemp(t, filepath.Dir(iacInstalledPath(seciac.Trivy)))
}

func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
}

// TestIaCGuidedInstallRefusals: a half (cut) download, a tampered archive
// and a bundle under another identity each install nothing.
func TestIaCGuidedInstallRefusals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tar.gz fixture")
	}
	cases := map[string]func(f *iacFixture){
		"half download": func(f *iacFixture) {
			f.net.files[f.pin.URL()] = append(append([]byte(nil), f.archive...), make([]byte, 64)...)
		},
		"tampered archive": func(f *iacFixture) {
			b := append([]byte(nil), f.archive...)
			b[len(b)-1] ^= 0xff
			f.net.files[f.pin.URL()] = b
		},
		"another identity": func(f *iacFixture) {
			_, sign := testSigning(t)
			sum := sha256.Sum256(f.archive)
			f.net.files[f.pin.BundleURL()] = sign("https://github.com/evil/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.75.0", sum)
		},
		"no bundle": func(f *iacFixture) { delete(f.net.files, f.pin.BundleURL()) },
	}
	for name, mod := range cases {
		f := newIaCFixture(t)
		mod(f)
		if _, err := f.open(t).installIaCEngine(context.Background(), "cli", true); err == nil {
			t.Errorf("%s: installed", name)
		}
		if _, err := os.Lstat(iacInstalledPath(seciac.Trivy)); err == nil {
			t.Errorf("%s: something is at the install path", name)
		}
		assertNoTemp(t, filepath.Dir(iacInstalledPath(seciac.Trivy)))
	}
}

// fakeIaCMirror installs a fixture's envelope like the org mirror would.
type fakeIaCMirror struct {
	err   error
	calls int
}

func (m *fakeIaCMirror) InstallSecurityContent(context.Context, contentchan.Store, content.Kind, contentchan.Trust) (orgclient.SecurityContentResult, error) {
	m.calls++
	return orgclient.SecurityContentResult{}, m.err
}

// TestIaCManagedMirrorPath: a managed node installs only from the org
// mirror: never the vendor release, refused when the managed pull does not
// name the mirror or the mirror cannot be reached, and installed from the
// mirror's verified archive otherwise.
func TestIaCManagedMirrorPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tar.gz fixture")
	}
	f := newIaCFixture(t)
	mirror := &fakeIaCMirror{}
	prevMirror, prevNamed := iacOrgMirror, iacMirrorNamed
	t.Cleanup(func() { iacOrgMirror, iacMirrorNamed = prevMirror, prevNamed })
	iacOrgMirror = func(context.Context, string) (iacMirror, func(), error) { return mirror, func() {}, nil }
	named := false
	iacMirrorNamed = func(context.Context, config.Config, *store.Store) bool { return named }
	env := f.open(t)
	env.managed = true
	if _, err := env.installIaCEngine(context.Background(), "cli", true); err == nil || !strings.Contains(err.Error(), seciac.BlockManagedNoMirror) {
		t.Fatalf("mirror not named: %v", err)
	}
	named = true
	mirror.err = errors.New("unreachable")
	if _, err := env.installIaCEngine(context.Background(), "cli", true); err == nil {
		t.Fatal("an unreachable mirror installed something")
	}
	mirror.err = nil
	if _, err := env.installIaCEngine(context.Background(), "cli", true); err != nil {
		t.Fatalf("mirror install: %v", err)
	}
	if len(f.net.calls) != 0 {
		t.Fatalf("a managed node reached the vendor release: %v", f.net.calls)
	}
	if b, err := os.ReadFile(iacInstalledPath(seciac.Trivy)); err != nil || !bytes.Equal(b, f.binary) {
		t.Fatalf("mirror-installed binary %q %v", b, err)
	}
}

// TestIaCKICSHasNoGuidedInstall: KICS publishes no release binaries.
func TestIaCKICSHasNoGuidedInstall(t *testing.T) {
	cfgPath := iacConfig(t, "[components]\nadd = [\"security.scan.kics\", \"security.code\"]\n")
	env, err := openIaCEnv(context.Background(), cfgPath, seciac.KICS)
	if err != nil {
		t.Fatal(err)
	}
	defer env.cleanup()
	if _, err := env.installIaCEngine(context.Background(), "cli", true); err == nil || !strings.Contains(err.Error(), seciac.BlockNoVendorRelease) {
		t.Fatalf("kics install: %v", err)
	}
}
