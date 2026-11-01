package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// The cosign outputs JSP-8 recorded (results/verify-output.txt): a full
// verification prints "Verified OK"; with the Sigstore hosts blocked it
// fails on the TUF fetch.
const (
	recordedOK      = "Verified OK\n"
	recordedOffline = `Error: getting Rekor public keys: updating local metadata and targets: error updating to TUF remote mirror: tuf: failed to download 13.root.json: Get "https://tuf-repo-cdn.sigstore.dev/13.root.json": Forbidden
error during command execution: getting Rekor public keys: updating local metadata and targets: error updating to TUF remote mirror: tuf: failed to download 13.root.json: Get "https://tuf-repo-cdn.sigstore.dev/13.root.json": Forbidden`
)

// fixture writes a small asset signed by a test Fulcio-shaped chain, its
// .sig and .cert, and a stand-in cosign file, and points trustRoots at the
// test root.
type fixture struct {
	dir, asset, sig, cert, cosign, cosignSum string
}

func newFixture(t *testing.T, version string) fixture {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test fulcio"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	prev := trustRoots
	trustRoots = func() ([]byte, []byte) {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), nil
	}
	t.Cleanup(func() { trustRoots = prev })

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := url.Parse(secengine.Identity(version))
	issuer, _ := asn1.Marshal(secengine.Issuer)
	nb := time.Now().Add(-3 * time.Hour)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: nb, NotAfter: nb.Add(10 * time.Minute), URIs: []*url.URL{id},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: issuer}},
	}, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{dir: t.TempDir()}
	f.asset = filepath.Join(f.dir, "opengrep_manylinux_x86")
	blob := []byte("a stand-in engine binary")
	sum := sha256.Sum256(blob)
	sig, _ := ecdsa.SignASN1(rand.Reader, leafKey, sum[:])
	f.sig, f.cert, f.cosign = f.asset+".sig", f.asset+".cert", filepath.Join(f.dir, "cosign")
	for p, b := range map[string][]byte{
		f.asset:  blob,
		f.sig:    []byte(base64.StdEncoding.EncodeToString(sig)),
		f.cert:   []byte(base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))),
		f.cosign: []byte("a stand-in cosign"),
	} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cs := sha256.Sum256([]byte("a stand-in cosign"))
	f.cosignSum = hex.EncodeToString(cs[:])
	return f
}

func (f fixture) args(extra ...string) []string {
	return append([]string{"verify", "-asset", f.asset, "-sig", f.sig, "-cert", f.cert, "-cosign", f.cosign, "-cosign-sha256", f.cosignSum, "-version", "1.30.1"}, extra...)
}

// fakeCosign records its calls and answers with out.
type fakeCosign struct {
	calls [][]string
	out   string
	ok    bool
}

func (c *fakeCosign) run(_ context.Context, _ string, args []string) ([]byte, bool, error) {
	c.calls = append(c.calls, args)
	return []byte(c.out), c.ok, nil
}

var fixedNow = func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) }

func TestVerifyPrintsAnUnsignedEntry(t *testing.T) {
	f := newFixture(t, "1.30.1")
	c := &fakeCosign{out: recordedOK, ok: true}
	var out bytes.Buffer
	if err := run(context.Background(), f.args(), &out, c.run, fixedNow); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(c.calls) != 1 {
		t.Fatalf("cosign calls %v", c.calls)
	}
	want := []string{"verify-blob", f.asset, "--signature", f.sig, "--certificate", f.cert,
		"--certificate-identity", "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v1.30.1",
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"}
	if strings.Join(c.calls[0], " ") != strings.Join(want, " ") {
		t.Errorf("cosign args %v", c.calls[0])
	}
	var e content.Entry
	if err := json.Unmarshal(out.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("a stand-in engine binary"))
	if e.SHA256 != hex.EncodeToString(sum[:]) || e.Upstream.Method != content.UpstreamCosignKeylessOnline ||
		e.Upstream.VerifiedAt != "2026-10-21T12:00:00Z" || e.Upstream.VerifiedWhere != "release_pipeline" || e.OS != "linux" || e.Arch != "amd64" {
		t.Errorf("entry %+v", e)
	}
	// The entry is what an engine manifest may carry: secengine reads it.
	m := content.Manifest{Kind: content.Engine, ManifestVersion: 1, Entries: []content.Entry{e}}
	if _, err := secengine.FromManifest(m); err != nil {
		t.Errorf("the printed entry is not a valid engine pin: %v", err)
	}
}

func TestVerifyRefuses(t *testing.T) {
	cases := []struct {
		name     string
		prepare  func(t *testing.T, f fixture) []string
		cosign   fakeCosign
		want     string
		noCosign bool
	}{
		{"a one-byte tamper is refused offline, before cosign", func(t *testing.T, f fixture) []string {
			b, _ := os.ReadFile(f.asset)
			if err := os.WriteFile(f.asset, append(b, 'x'), 0o600); err != nil {
				t.Fatal(err)
			}
			return f.args()
		}, fakeCosign{out: recordedOK, ok: true}, "refused before going online", true},
		{"another version's identity", func(_ *testing.T, f fixture) []string {
			a := f.args()
			a[len(a)-1] = "1.31.0"
			return a
		}, fakeCosign{out: recordedOK, ok: true}, "identity", true},
		{"an unpinned cosign", func(_ *testing.T, f fixture) []string {
			a := f.args()
			for i := range a {
				if a[i] == f.cosignSum {
					a[i] = strings.Repeat("0", 64)
				}
			}
			return a
		}, fakeCosign{out: recordedOK, ok: true}, "not the pinned", true},
		{"no Rekor (JSP-8's offline output)", func(_ *testing.T, f fixture) []string { return f.args() },
			fakeCosign{out: recordedOffline, ok: false}, "did not verify", false},
		{"exit 0 without Verified OK", func(_ *testing.T, f fixture) []string { return f.args() },
			fakeCosign{out: "", ok: true}, "did not verify", false},
		{"a bad -where", func(_ *testing.T, f fixture) []string { return f.args("-where", "laptop") },
			fakeCosign{out: recordedOK, ok: true}, "-where", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, "1.30.1")
			args := c.prepare(t, f)
			cs := c.cosign
			var out bytes.Buffer
			err := run(context.Background(), args, &out, cs.run, fixedNow)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("run = %v, want an error naming %q", err, c.want)
			}
			if c.noCosign && len(cs.calls) != 0 {
				t.Errorf("cosign ran: %v", cs.calls)
			}
			if out.Len() != 0 {
				t.Errorf("an entry was printed on a refusal: %s", out.String())
			}
		})
	}
}
