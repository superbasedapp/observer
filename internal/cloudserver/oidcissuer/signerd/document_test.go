package signerd_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// document_test.go proves the document signer (M6.3): the monotonic version
// per (kind, scope) and its durability across a restart, that no signature
// leaves before its version is recorded, the body checks, that each purpose
// signs with its own key and its signatures verify only as their own family,
// host-API request signing inside the replay window, and the socket protocol.

const workerUID = 1002

var docClock = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func edKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func edPub(k ed25519.PrivateKey) ed25519.PublicKey {
	pub, _ := k.Public().(ed25519.PublicKey)
	return pub
}

func testKeys() signerd.DocumentKeys {
	return signerd.DocumentKeys{
		Entitlements: []ed25519.PrivateKey{edKey(1), edKey(4)},
		Availability: []ed25519.PrivateKey{edKey(2)},
		HostAPI:      []ed25519.PrivateKey{edKey(3)},
	}
}

func newVersions(t *testing.T) (*signerd.FileVersions, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "versions.json")
	if err := signerd.CreateVersionFile(path); err != nil {
		t.Fatal(err)
	}
	v, err := signerd.OpenFileVersions(path)
	if err != nil {
		t.Fatal(err)
	}
	return v, path
}

func newDocSigner(t *testing.T, v signerd.VersionStore) *signerd.DocumentSigner {
	t.Helper()
	d, err := signerd.NewDocumentSigner(testKeys(), v, func() time.Time { return docClock })
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func availabilityBody(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(platformcontract.AvailabilityBody{
		IssuedAt: "2026-11-13T12:00:00Z",
		Components: []platformcontract.ComponentAvailability{
			{Component: "org.gateway", Reach: platformcontract.ReachOff, Reason: "incident", Author: "system"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDocumentSignerVersionsAreMonotonicAndDurable(t *testing.T) {
	t.Parallel()
	v, path := newVersions(t)
	d := newDocSigner(t, v)
	ent := []byte(`{"plan":"team"}`)
	if _, err := d.SignDocument(platformcontract.KindEntitlements, org, 5, ent); err != nil {
		t.Fatalf("v5: %v", err)
	}
	for _, ver := range []int64{5, 4} {
		if _, err := d.SignDocument(platformcontract.KindEntitlements, org, ver, ent); !errors.Is(err, platformcontract.ErrVersionNotNewer) {
			t.Errorf("v%d after v5 = %v, want ErrVersionNotNewer", ver, err)
		}
	}
	// Another scope and another kind are separate streams.
	if _, err := d.SignDocument(platformcontract.KindEntitlements, "1b5c3f1e-2d4a-4c6b-9e8f-1a2b3c4d5e6f", 1, ent); err != nil {
		t.Errorf("another org's v1: %v", err)
	}
	if _, err := d.SignDocument(platformcontract.KindAvailability, platformcontract.AvailabilityScope, 1, availabilityBody(t)); err != nil {
		t.Errorf("availability v1: %v", err)
	}
	// A restarted signer reads the record back and still refuses v5.
	reopened, err := signerd.OpenFileVersions(path)
	if err != nil {
		t.Fatal(err)
	}
	d2 := newDocSigner(t, reopened)
	if _, err := d2.SignDocument(platformcontract.KindEntitlements, org, 5, ent); !errors.Is(err, platformcontract.ErrVersionNotNewer) {
		t.Fatalf("v5 after a restart = %v, want ErrVersionNotNewer", err)
	}
	if _, err := d2.SignDocument(platformcontract.KindEntitlements, org, 6, ent); err != nil {
		t.Fatalf("v6 after a restart: %v", err)
	}
}

// failingVersions refuses every commit.
type failingVersions struct{}

func (failingVersions) Last(platformcontract.DocumentKind, string) (int64, error) { return 0, nil }

func (failingVersions) Commit(platformcontract.DocumentKind, string, int64) error {
	return errors.New("disk full")
}

func TestDocumentSignerReleasesNoSignatureWithoutARecord(t *testing.T) {
	t.Parallel()
	d := newDocSigner(t, failingVersions{})
	got, err := d.SignDocument(platformcontract.KindEntitlements, org, 1, []byte(`{}`))
	if err == nil || got.Signature != nil {
		t.Fatalf("SignDocument = (%v, %v), want no signature and an error", got, err)
	}
}

func TestDocumentSignerRefusesBadInput(t *testing.T) {
	t.Parallel()
	d := newDocSigner(t, failingVersions{})
	cases := []struct {
		name  string
		kind  platformcontract.DocumentKind
		scope string
		body  []byte
	}{
		{"unknown kind", "licence", org, []byte(`{}`)},
		{"entitlements for the platform scope", platformcontract.KindEntitlements, platformcontract.AvailabilityScope, []byte(`{}`)},
		{"availability for an org", platformcontract.KindAvailability, org, availabilityBody(t)},
		{"entitlements not an object", platformcontract.KindEntitlements, org, []byte(`[1]`)},
		{"entitlements not JSON", platformcontract.KindEntitlements, org, []byte(`{plan`)},
		{"availability unknown field", platformcontract.KindAvailability, platformcontract.AvailabilityScope, []byte(`{"issued_at":"2026-11-13T12:00:00Z","widen":true}`)},
		{"availability invalid section", platformcontract.KindAvailability, platformcontract.AvailabilityScope, []byte(`{"issued_at":"2026-11-13T12:00:00Z","components":[{"component":"x","reach":"named","reason":"r","author":"a"}]}`)},
		{"availability trailing data", platformcontract.KindAvailability, platformcontract.AvailabilityScope, append(availabilityBody(t), []byte(` {}`)...)},
	}
	for _, tc := range cases {
		if _, err := d.SignDocument(tc.kind, tc.scope, 1, tc.body); !errors.Is(err, signerd.ErrDocumentRefused) {
			t.Errorf("%s: %v, want ErrDocumentRefused", tc.name, err)
		}
	}
}

// TestDocumentSignerKeysAreSeparated: each purpose signs with its own first
// key, and a signature verifies only as its own family.
func TestDocumentSignerKeysAreSeparated(t *testing.T) {
	t.Parallel()
	v, _ := newVersions(t)
	d := newDocSigner(t, v)
	entKeys := platformcontract.KeySet{platformcontract.NewDocumentKey(edPub(edKey(1)))}
	availKeys := platformcontract.KeySet{platformcontract.NewDocumentKey(edPub(edKey(2)))}
	ent := []byte(`{"plan":"team"}`)
	s, err := d.SignDocument(platformcontract.KindEntitlements, org, 1, ent)
	if err != nil {
		t.Fatal(err)
	}
	doc := platformcontract.EntitlementDocument{Version: 1, Body: ent, Signature: s.Signature, KeyID: s.KeyID}
	if err := platformcontract.VerifyEntitlements(doc, org, entKeys, 0); err != nil {
		t.Fatalf("entitlements: %v", err)
	}
	if err := platformcontract.VerifyEntitlements(doc, org, availKeys, 0); !errors.Is(err, platformcontract.ErrUnknownDocumentKey) {
		t.Errorf("entitlements under the availability key set: %v", err)
	}
	ab := availabilityBody(t)
	a, err := d.SignDocument(platformcontract.KindAvailability, platformcontract.AvailabilityScope, 1, ab)
	if err != nil {
		t.Fatal(err)
	}
	adoc := platformcontract.AvailabilityDocument{Version: 1, Body: ab, Signature: a.Signature, KeyID: a.KeyID}
	if err := platformcontract.VerifyAvailability(adoc, availKeys, 0); err != nil {
		t.Fatalf("availability: %v", err)
	}
	// Even under a key set that pins every key, the domains keep them apart.
	all := append(append(platformcontract.KeySet{}, entKeys...), availKeys...)
	if err := platformcontract.VerifyAvailability(platformcontract.AvailabilityDocument(doc), all, 0); err == nil {
		t.Error("an entitlements signature verified as availability")
	}
	keys := d.PublicKeys()
	if len(keys) != 4 || !keys[0].Signing || keys[1].Signing || keys[0].Purpose != signerd.PurposeEntitlements {
		t.Errorf("PublicKeys = %+v, want the entitlements signing key first and its rollover key published only", keys)
	}
}

func TestNewDocumentSignerRefusesSharedOrMissingKeys(t *testing.T) {
	t.Parallel()
	shared := signerd.DocumentKeys{Entitlements: []ed25519.PrivateKey{edKey(1)}, Availability: []ed25519.PrivateKey{edKey(1)}}
	if _, err := signerd.NewDocumentSigner(shared, failingVersions{}, nil); err == nil {
		t.Error("one key for two purposes was accepted")
	}
	if _, err := signerd.NewDocumentSigner(signerd.DocumentKeys{Entitlements: []ed25519.PrivateKey{edKey(1)}}, failingVersions{}, nil); err == nil {
		t.Error("no availability key was accepted")
	}
	noHost := signerd.DocumentKeys{Entitlements: []ed25519.PrivateKey{edKey(1)}, Availability: []ed25519.PrivateKey{edKey(2)}}
	d, err := signerd.NewDocumentSigner(noHost, failingVersions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SignRequest("PUT", platformcontract.PathTenantEntitlements(org), "n", platformcontract.BodyDigest(nil), docClock.Unix()); !errors.Is(err, signerd.ErrNoKey) {
		t.Errorf("SignRequest without a host-API key = %v, want ErrNoKey", err)
	}
}

func TestDocumentSignerSignsHostAPIRequests(t *testing.T) {
	t.Parallel()
	d := newDocSigner(t, failingVersions{})
	body := []byte(`{"tenant_id":"` + org + `"}`)
	target := platformcontract.PathTenantEntitlements(org)
	e, err := d.SignRequest("PUT", target, "nonce-1", platformcontract.BodyDigest(body), docClock.Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(edPub(edKey(3)), "PUT", target, body, docClock); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	cases := []struct {
		name, method, target, nonce, digest string
		ts                                  int64
	}{
		{"stale", "PUT", target, "n", platformcontract.BodyDigest(body), docClock.Add(-platformcontract.ReplayWindow - time.Second).Unix()},
		{"outside the host API", "PUT", "/portal/api/me", "n", platformcontract.BodyDigest(body), docClock.Unix()},
		{"method", "DELETE", target, "n", platformcontract.BodyDigest(body), docClock.Unix()},
		{"nonce", "PUT", target, "", platformcontract.BodyDigest(body), docClock.Unix()},
		{"digest", "PUT", target, "n", "abc", docClock.Unix()},
	}
	for _, tc := range cases {
		if _, err := d.SignRequest(tc.method, tc.target, tc.nonce, tc.digest, tc.ts); !errors.Is(err, signerd.ErrDocumentRefused) {
			t.Errorf("%s: %v, want ErrDocumentRefused", tc.name, err)
		}
	}
}

func serveDocs(t *testing.T, peerUID int) *signerd.DocumentClient {
	t.Helper()
	v, _ := newVersions(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := &signerd.DocumentServer{
		Signer: newDocSigner(t, v), AllowUID: workerUID, Logger: quiet(),
		PeerUID: func(net.Conn) (int, error) { return peerUID, nil },
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return &signerd.DocumentClient{Network: "tcp", Address: ln.Addr().String()}
}

func TestDocumentSignerProtocol(t *testing.T) {
	t.Parallel()
	c := serveDocs(t, workerUID)
	ctx := context.Background()
	keys, err := c.PublicKeys(ctx)
	if err != nil || len(keys) != 4 {
		t.Fatalf("keys = %d (%v)", len(keys), err)
	}
	ent := []byte(`{"plan":"team"}`)
	s, err := c.SignDocument(ctx, platformcontract.KindEntitlements, org, 2, ent)
	if err != nil {
		t.Fatal(err)
	}
	set := platformcontract.KeySet{platformcontract.NewDocumentKey(keys[0].Public)}
	if err := platformcontract.VerifyEntitlements(platformcontract.EntitlementDocument{Version: 2, Body: ent, Signature: s.Signature, KeyID: s.KeyID}, org, set, 1); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := c.SignDocument(ctx, platformcontract.KindEntitlements, org, 2, ent); !errors.Is(err, platformcontract.ErrVersionNotNewer) {
		t.Errorf("repeat = %v, want ErrVersionNotNewer", err)
	}
	if _, err := c.SignDocument(ctx, platformcontract.KindEntitlements, org, 3, []byte(`nope`)); !errors.Is(err, signerd.ErrDocumentRefused) {
		t.Errorf("bad body = %v, want ErrDocumentRefused", err)
	}
	if _, err := c.SignRequest(ctx, "PUT", platformcontract.PathTenantEntitlements(org), "n", platformcontract.BodyDigest(ent), docClock.Unix()); err != nil {
		t.Errorf("sign_request: %v", err)
	}
}

func TestDocumentSignerRefusesOtherPeers(t *testing.T) {
	t.Parallel()
	c := serveDocs(t, workerUID+1)
	if _, err := c.PublicKeys(context.Background()); !errors.Is(err, signerd.ErrPeerRefused) {
		t.Fatalf("a stranger uid got %v, want ErrPeerRefused", err)
	}
}

func TestVersionFileLifecycle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "versions.json")
	if _, err := signerd.OpenFileVersions(path); err == nil {
		t.Fatal("a missing state file opened")
	}
	if err := signerd.CreateVersionFile(path); err != nil {
		t.Fatal(err)
	}
	if err := signerd.CreateVersionFile(path); err == nil {
		t.Fatal("CreateVersionFile overwrote an existing record")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"v":1,"versions":{"entitlements":{"platform":3}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := signerd.OpenFileVersions(bad); err == nil {
		t.Error("a record with an entitlements entry for the platform scope opened")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := signerd.OpenFileVersions(path); err == nil {
			t.Error("a group-readable state file opened")
		}
	}
}

func TestEd25519KeyFileRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "k.pem")
	id, err := signerd.GenerateEd25519KeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signerd.GenerateEd25519KeyFile(path); err == nil {
		t.Error("GenerateEd25519KeyFile overwrote a key")
	}
	k, err := signerd.LoadEd25519Key(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := platformcontract.DocumentKeyID(edPub(k)); got != id {
		t.Errorf("loaded key id %s, generated %s", got, id)
	}
	if _, err := signerd.ParseEd25519KeyPEM([]byte("not pem")); err == nil {
		t.Error("garbage parsed as a key")
	}
}
