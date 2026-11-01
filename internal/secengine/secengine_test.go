package secengine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// The recorded release files of Opengrep v1.30.1 linux amd64 (the .sig and
// .cert JSP-8 verified; the 46 MB binary itself is not in the repository:
// the signature is over its digest, which is the pin).
func recorded(t *testing.T) (sig, cert []byte) {
	t.Helper()
	dir := filepath.Join("testdata", "opengrep-1.30.1")
	sig, err := os.ReadFile(filepath.Join(dir, "opengrep_manylinux_x86.sig"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err = os.ReadFile(filepath.Join(dir, "opengrep_manylinux_x86.cert"))
	if err != nil {
		t.Fatal(err)
	}
	return sig, cert
}

// tamperedDigest is the sha256 of the v1.30.1 linux amd64 binary with one
// byte appended (measured 2026-10-21).
const tamperedDigest = "dac8140efce6ffb03736a9fd493695679ade9b0f33686a47db294eb743963087"

func TestPrecheckRecordedRelease(t *testing.T) {
	sig, cert := recorded(t)
	pin, _ := CompiledPin("linux", "amd64")
	base := PrecheckInput{Digest: pin.SHA256, SigB64: sig, CertB64: cert, Identity: Identity(TestedVersion), Issuer: Issuer}
	res, err := Precheck(base)
	if err != nil {
		t.Fatalf("the recorded release does not pre-check: %v", err)
	}
	if res.NotAfter.Sub(res.NotBefore) != 10*time.Minute || res.Issuer != Issuer {
		t.Errorf("certificate %+v", res)
	}
	cases := []struct {
		name   string
		mutate func(*PrecheckInput)
		want   string
	}{
		{"a one-byte tamper of the binary", func(in *PrecheckInput) { in.Digest = tamperedDigest }, "does not match"},
		{"another version's identity", func(in *PrecheckInput) { in.Identity = Identity("1.31.0") }, "identity"},
		{"the tag form of the identity", func(in *PrecheckInput) {
			in.Identity = strings.Replace(in.Identity, "refs/heads/release-v", "refs/tags/v", 1)
		}, "identity"},
		{"another issuer", func(in *PrecheckInput) { in.Issuer = "https://accounts.google.com" }, "issuer"},
		{"a flipped signature byte", func(in *PrecheckInput) {
			raw, _ := base64.StdEncoding.DecodeString(string(in.SigB64))
			raw[len(raw)-3] ^= 1
			in.SigB64 = []byte(base64.StdEncoding.EncodeToString(raw))
		}, "signature"},
		{"another root", func(in *PrecheckInput) {
			_, _, rootPEM, _ := testCA(t)
			in.RootPEM, in.IntermediatePEM = rootPEM, nil
		}, "chain"},
		{"not a digest", func(in *PrecheckInput) { in.Digest = "abc" }, "sha256"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base
			c.mutate(&in)
			_, err := Precheck(in)
			if !errors.Is(err, ErrPrecheck) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Precheck = %v, want a refusal naming %q", err, c.want)
			}
		})
	}
}

// testCA builds a root, an intermediate signer and their PEM.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// TestPrecheckSyntheticChain: a ten-minute leaf, long expired, still
// pre-checks at its signing time; the v2 issuer extension is read.
func TestPrecheckSyntheticChain(t *testing.T) {
	root, rootKey, rootPEM, _ := testCA(t)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := url.Parse(Identity("9.9.9"))
	issuer, _ := asn1.Marshal(Issuer)
	nb := time.Now().Add(-2 * time.Hour)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: nb, NotAfter: nb.Add(10 * time.Minute),
		URIs: []*url.URL{id}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{Id: oidIssuerV2, Value: issuer}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	blob := []byte("an engine binary")
	sum := sha256.Sum256(blob)
	sig, _ := ecdsa.SignASN1(rand.Reader, leafKey, sum[:])
	in := PrecheckInput{
		Digest: hex.EncodeToString(sum[:]), SigB64: []byte(base64.StdEncoding.EncodeToString(sig)),
		CertB64:  []byte(base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))),
		Identity: Identity("9.9.9"), Issuer: Issuer, RootPEM: rootPEM,
	}
	if _, err := Precheck(in); err != nil {
		t.Fatalf("an expired ten-minute leaf did not pre-check at its signing time: %v", err)
	}
	tampered := sha256.Sum256(append(blob, 'x'))
	in.Digest = hex.EncodeToString(tampered[:])
	if _, err := Precheck(in); err == nil {
		t.Fatal("a one-byte tamper pre-checked")
	}
}

func TestDecide(t *testing.T) {
	pin, _ := CompiledPin("linux", "amd64")
	other := strings.Repeat("ab", 32)
	man := &ManifestPins{Pins: []Pin{{Version: "1.31.0", OS: "linux", Arch: "amd64", SHA256: other, Status: PinPinned, Source: "manifest"}}}
	winMan := &ManifestPins{Pins: []Pin{{Version: TestedVersion, OS: "windows", Arch: "amd64", SHA256: other, Status: PinPinned, Source: "manifest"}}}
	revoke := &ManifestPins{Revoked: []string{pin.SHA256}}
	cases := []struct {
		name   string
		in     Input
		status Status
		detail string
	}{
		{"the compiled pin runs", Input{GOOS: "linux", GOARCH: "amd64", Digest: pin.SHA256}, StatusVerified, DetailCompiled},
		{"the compiled pin, upper case", Input{GOOS: "linux", GOARCH: "amd64", Digest: strings.ToUpper(pin.SHA256)}, StatusVerified, DetailCompiled},
		{"another digest on an individual node runs labelled", Input{GOOS: "linux", GOARCH: "amd64", Digest: other}, StatusUnverifiedLabelled, DetailNoMatch},
		{"another digest on a managed node is refused", Input{GOOS: "linux", GOARCH: "amd64", Digest: other, Managed: true}, StatusRefused, DetailNoMatch},
		{"a pin-owed platform is refused, individual", Input{GOOS: "windows", GOARCH: "amd64", Digest: other}, StatusRefused, DetailPinOwed},
		{"a pin-owed platform is refused, managed", Input{GOOS: "darwin", GOARCH: "arm64", Digest: other, Managed: true}, StatusRefused, DetailPinOwed},
		{"an unknown platform is refused", Input{GOOS: "freebsd", GOARCH: "amd64", Digest: other}, StatusRefused, DetailPinOwed},
		{"a manifest fills an owed platform", Input{GOOS: "windows", GOARCH: "amd64", Digest: other, Manifest: winMan}, StatusVerified, DetailManifest},
		{"a manifest pin runs", Input{GOOS: "linux", GOARCH: "amd64", Digest: other, Manifest: man}, StatusVerified, DetailManifest},
		{"a manifest supersedes the compiled pin of its platform", Input{GOOS: "linux", GOARCH: "amd64", Digest: pin.SHA256, Manifest: man}, StatusUnverifiedLabelled, DetailNoMatch},
		{"a revoked digest is refused", Input{GOOS: "linux", GOARCH: "amd64", Digest: pin.SHA256, Manifest: revoke}, StatusRefused, DetailRevoked},
		{"a changed tree on an individual node runs labelled", Input{GOOS: "linux", GOARCH: "amd64", Digest: pin.SHA256, Tree: TreeChanged}, StatusUnverifiedLabelled, DetailTreeChanged},
		{"a changed tree on a managed node is refused", Input{GOOS: "linux", GOARCH: "amd64", Digest: pin.SHA256, Tree: TreeChanged, Managed: true}, StatusRefused, DetailTreeChanged},
		{"an unreadable tree on a managed node is refused", Input{GOOS: "linux", GOARCH: "amd64", Digest: pin.SHA256, Tree: TreeUnreadable, Managed: true}, StatusRefused, DetailTreeUnreadable},
		{"an old version is refused", Input{GOOS: "linux", GOARCH: "amd64", Digest: other, Version: "1.29.0"}, StatusRefused, DetailTooOld},
	}
	for _, c := range cases {
		d := Decide(c.in)
		if d.Status != c.status || d.Detail != c.detail {
			t.Errorf("%s: Decide = %s %s, want %s %s", c.name, d.Status, d.Detail, c.status, c.detail)
		}
		if (d.Status == StatusVerified) == (d.Reason == ReasonUnverified) {
			t.Errorf("%s: reason %q with status %s", c.name, d.Reason, d.Status)
		}
	}
}

func TestFromManifest(t *testing.T) {
	entry := func(id string) content.Entry {
		return content.Entry{
			Name: "opengrep_manylinux_x86", Version: "1.31.0", OS: "linux", Arch: "amd64", SizeBytes: 1, SHA256: strings.Repeat("CD", 32),
			Upstream: content.UpstreamCheck{Method: content.UpstreamCosignKeylessOnline, Identity: id, Issuer: Issuer, VerifiedAt: "2026-10-21T00:00:00Z"},
		}
	}
	m := content.Manifest{Kind: content.Engine, ManifestVersion: 3, Entries: []content.Entry{entry(Identity("1.31.0"))}, Revoked: []content.Revocation{{SHA256: strings.Repeat("EF", 32)}}}
	mp, err := FromManifest(m)
	if err != nil || len(mp.Pins) != 1 || mp.Pins[0].SHA256 != strings.Repeat("cd", 32) || mp.Revoked[0] != strings.Repeat("ef", 32) {
		t.Fatalf("FromManifest = %+v %v", mp, err)
	}
	m.Entries = []content.Entry{entry(Identity("1.30.1"))}
	if _, err := FromManifest(m); err == nil {
		t.Error("an entry whose identity names another version was accepted")
	}
	e := entry(Identity("1.31.0"))
	e.Upstream.Method = content.UpstreamNone
	m.Entries = []content.Entry{e}
	if _, err := FromManifest(m); err == nil {
		t.Error("an entry not verified keyless online was accepted")
	}
	m.Kind = content.RulePack
	if _, err := FromManifest(m); err == nil {
		t.Error("a manifest of another kind was read")
	}
}

func TestCheckTree(t *testing.T) {
	rec, ok := NewTreeRecord("bin", TestedVersion, map[string]string{"opengrep.bin": strings.Repeat("a", 64), "lib/_opcode.so": strings.Repeat("b", 64)}, time.Now())
	if !ok {
		t.Fatal("NewTreeRecord refused a good tree")
	}
	cases := []struct {
		name string
		rec  *TreeRecord
		bin  string
		l    TreeListing
		want TreeState
	}{
		{"no record", nil, "bin", TreeListing{}, TreeNone},
		{"a record of another binary", &rec, "other", TreeListing{Files: []string{"x"}}, TreeNone},
		{"the same names", &rec, "bin", TreeListing{Files: []string{"lib/_opcode.so", "opengrep.bin"}}, TreeSame},
		{"an added file", &rec, "bin", TreeListing{Files: []string{"lib/_opcode.so", "opengrep.bin", "lib/evil.so"}}, TreeChanged},
		{"a missing file", &rec, "bin", TreeListing{Files: []string{"opengrep.bin"}}, TreeChanged},
		{"a symlink in the tree", &rec, "bin", TreeListing{Files: []string{"lib/_opcode.so", "opengrep.bin"}, Irregular: true}, TreeChanged},
		{"an unreadable directory", &rec, "bin", TreeListing{Err: "permission denied"}, TreeUnreadable},
		{"a removed directory is unpacked and recorded again", &rec, "bin", TreeListing{Missing: true}, TreeNone},
	}
	for _, c := range cases {
		if got, _ := CheckTree(c.rec, c.bin, c.l); got != c.want {
			t.Errorf("%s: CheckTree = %s, want %s", c.name, got, c.want)
		}
	}
	for _, bad := range []map[string]string{
		{},
		{"../x": strings.Repeat("a", 64)},
		{"/abs": strings.Repeat("a", 64)},
		{"a/./b": strings.Repeat("a", 64)},
		{"x": "short"},
	} {
		if _, ok := NewTreeRecord("bin", TestedVersion, bad, time.Now()); ok {
			t.Errorf("NewTreeRecord accepted %v", bad)
		}
	}
	if got := TreeDir(`C:\u\cache\`, "1.30.1"); got != "C:/u/cache/opengrep/v1.30.1" {
		t.Errorf("TreeDir = %s", got)
	}
}

func TestPinsTable(t *testing.T) {
	pinned := 0
	for _, p := range CompiledPins() {
		if p.Status == PinPinned {
			pinned++
			if len(p.SHA256) != 64 {
				t.Errorf("%s/%s pinned without a sha256", p.OS, p.Arch)
			}
		} else if p.SHA256 != "" {
			t.Errorf("%s/%s owed but carries a digest", p.OS, p.Arch)
		}
		if !strings.HasPrefix(p.URL(), "https://github.com/opengrep/opengrep/releases/download/v1.30.1/opengrep_") {
			t.Errorf("URL %s", p.URL())
		}
	}
	if pinned != 1 {
		t.Errorf("%d pinned platforms, want 1 (linux amd64 from JSP-8)", pinned)
	}
	if Identity("1.30.1") != "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v1.30.1" {
		t.Error("the branch-form identity changed")
	}
}
