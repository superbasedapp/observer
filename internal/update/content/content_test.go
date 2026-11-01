package content

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func contentKey(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sampleContent(version, epoch int64) Manifest {
	data := []byte("index bytes")
	return Manifest{
		Schema: SchemaV1, Kind: MaliciousPackages, ManifestVersion: version, Epoch: epoch,
		IssuedAt:  testNow.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: testNow.Add(6 * 24 * time.Hour).Format(time.RFC3339),
		Entries: []Entry{{
			Name: "malicious.idx", Version: "2026-10-20", SizeBytes: int64(len(data)), SHA256: digestOf(data),
			Source: "osv:MAL", License: "Apache-2.0", Upstream: UpstreamCheck{Method: UpstreamNone},
		}},
	}
}

func signed(t *testing.T, m Manifest, priv ed25519.PrivateKey) []byte {
	t.Helper()
	env, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncodeEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestContentKindTable(t *testing.T) {
	seen := map[Kind]bool{}
	for _, s := range Kinds() {
		if seen[s.Kind] {
			t.Errorf("kind %s repeated", s.Kind)
		}
		seen[s.Kind] = true
		if s.MaxValidity <= 0 || s.AgeFloor < s.MaxValidity || s.Owner == "" || s.Class == "" {
			t.Errorf("kind %s row incomplete or floor below validity: %+v", s.Kind, s)
		}
	}
	for _, k := range []Kind{MaliciousPackages, PopularNames, Engine, SandboxImage} {
		if !seen[k] {
			t.Errorf("kind %s missing", k)
		}
	}
}

func TestVerifyContentRules(t *testing.T) {
	vpub, vpriv := contentKey(t, 1)
	opub, opriv := contentKey(t, 2)
	_, otherPriv := contentKey(t, 3)
	good := signed(t, sampleContent(5, 3), vpriv)

	tamper := func(f func(*Envelope)) []byte {
		var env Envelope
		_ = json.Unmarshal(good, &env)
		f(&env)
		b, _ := json.Marshal(env)
		return b
	}
	counter := func(m Manifest, orgPriv ed25519.PrivateKey) []byte {
		env, err := Sign(m, vpriv)
		if err != nil {
			t.Fatal(err)
		}
		env, err = Countersign(env, orgPriv)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := EncodeEnvelope(env)
		return b
	}
	expired := sampleContent(6, 3)
	expired.IssuedAt = testNow.Add(-10 * 24 * time.Hour).Format(time.RFC3339)
	expired.ExpiresAt = testNow.Add(-time.Hour).Format(time.RFC3339)
	tooLong := sampleContent(6, 3)
	tooLong.ExpiresAt = testNow.Add(400 * 24 * time.Hour).Format(time.RFC3339)
	future := sampleContent(6, 3)
	future.IssuedAt = testNow.Add(2 * time.Hour).Format(time.RFC3339)
	other := sampleContent(6, 3)
	other.Kind = PopularNames

	cases := []struct {
		name     string
		env      []byte
		in       func(*VerifyInput)
		want     Reason
		countsig bool
	}{
		{name: "valid", env: good},
		{name: "empty envelope", env: nil, want: ContentReasonEnvelope},
		{name: "not json", env: []byte("{"), want: ContentReasonEnvelope},
		{name: "unknown envelope field", env: []byte(`{"manifest":"","x":1}`), want: ContentReasonEnvelope},
		{name: "hash mismatch", env: tamper(func(e *Envelope) { e.ManifestHash = strings.Repeat("0", 64) }), want: ContentReasonHash},
		{name: "body swapped", env: tamper(func(e *Envelope) {
			b, _ := CanonicalJSON(sampleContent(9, 3))
			e.ManifestB64 = base64.StdEncoding.EncodeToString(b)
			e.ManifestHash = digestOf(b)
		}), want: ContentReasonVendorSig},
		{name: "signed by another key", env: signed(t, sampleContent(5, 3), otherPriv), want: ContentReasonVendorSig},
		{name: "no vendor key in build", env: good, in: func(in *VerifyInput) { in.VendorKeys = []ed25519.PublicKey{} }, want: ContentReasonNoKey},
		{name: "org required, missing", env: good, in: func(in *VerifyInput) { in.RequireOrg, in.OrgKey = true, opub }, want: ContentReasonOrgSig},
		{name: "org required, present", env: counter(sampleContent(5, 3), opriv), in: func(in *VerifyInput) { in.RequireOrg, in.OrgKey = true, opub }, countsig: true},
		{name: "org required, wrong org", env: counter(sampleContent(5, 3), otherPriv), in: func(in *VerifyInput) { in.RequireOrg, in.OrgKey = true, opub }, want: ContentReasonOrgSig},
		{name: "org sig on individual node ignored", env: counter(sampleContent(5, 3), otherPriv)},
		{name: "wrong kind", env: signed(t, other, vpriv), want: ContentReasonKind},
		{name: "rollback replay", env: good, in: func(in *VerifyInput) {
			in.Accepted = &Accepted{ManifestVersion: 6, Epoch: 3, ManifestHash: strings.Repeat("a", 64)}
		}, want: ContentReasonRollback},
		{name: "fork at same version", env: good, in: func(in *VerifyInput) {
			in.Accepted = &Accepted{ManifestVersion: 5, Epoch: 3, ManifestHash: strings.Repeat("a", 64)}
		}, want: ContentReasonFork},
		{name: "same version same bytes", env: good, in: func(in *VerifyInput) {
			var env Envelope
			_ = json.Unmarshal(good, &env)
			in.Accepted = &Accepted{ManifestVersion: 5, Epoch: 3, ManifestHash: env.ManifestHash}
		}},
		{name: "epoch backwards", env: good, in: func(in *VerifyInput) {
			in.Accepted = &Accepted{ManifestVersion: 4, Epoch: 4, ManifestHash: strings.Repeat("a", 64)}
		}, want: ContentReasonEpoch},
		{name: "expired", env: signed(t, expired, vpriv), want: ContentReasonExpired},
		{name: "issued in the future", env: signed(t, future, vpriv), want: ContentReasonNotYet},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := VerifyInput{Envelope: tc.env, Kind: MaliciousPackages, VendorKeys: []ed25519.PublicKey{vpub}, Now: testNow}
			if tc.in != nil {
				tc.in(&in)
			}
			res, err := Verify(in)
			if got := ReasonOf(err); got != tc.want {
				t.Fatalf("reason = %q (%v), want %q", got, err, tc.want)
			}
			if tc.want == "" && res.Countersigned != tc.countsig {
				t.Errorf("countersigned = %v, want %v", res.Countersigned, tc.countsig)
			}
		})
	}
	if _, err := Sign(tooLong, vpriv); !errors.Is(err, ErrInvalid) {
		t.Errorf("a validity past the kind's bound must not sign: %v", err)
	}
}

// TestContentKeyRotationDrill is the compromised-key drill (X25): a key
// that is no longer in the accepted set verifies nothing, and the new key
// verifies during and after the overlap.
func TestContentKeyRotationDrill(t *testing.T) {
	oldPub, oldPriv := contentKey(t, 7)
	newPub, newPriv := contentKey(t, 8)
	byOld := signed(t, sampleContent(1, 1), oldPriv)
	byNew := signed(t, sampleContent(2, 1), newPriv)
	verify := func(env []byte, keys ...ed25519.PublicKey) Reason {
		_, err := Verify(VerifyInput{Envelope: env, Kind: MaliciousPackages, VendorKeys: keys, Now: testNow})
		return ReasonOf(err)
	}
	if r := verify(byOld, newPub, oldPub); r != "" {
		t.Errorf("overlap: old key refused: %s", r)
	}
	if r := verify(byNew, newPub, oldPub); r != "" {
		t.Errorf("overlap: new key refused: %s", r)
	}
	if r := verify(byOld, newPub); r != ContentReasonVendorSig {
		t.Errorf("after revocation the old key must verify nothing, got %q", r)
	}
}

func TestContentStructure(t *testing.T) {
	base := sampleContent(1, 0)
	sums := func(lines string) string { return base64.StdEncoding.EncodeToString([]byte(lines)) }
	cases := []struct {
		name string
		mut  func(*Manifest)
		ok   bool
	}{
		{name: "base", mut: func(*Manifest) {}, ok: true},
		{name: "unknown kind", mut: func(m *Manifest) { m.Kind = "x" }},
		{name: "zero version", mut: func(m *Manifest) { m.ManifestVersion = 0 }},
		{name: "no expiry", mut: func(m *Manifest) { m.ExpiresAt = "" }},
		{name: "path in name", mut: func(m *Manifest) { m.Entries[0].Name = "../x" }},
		{name: "bad digest", mut: func(m *Manifest) { m.Entries[0].SHA256 = "abc" }},
		{name: "revoked and listed", mut: func(m *Manifest) {
			m.Revoked = []Revocation{{SHA256: m.Entries[0].SHA256}}
		}},
		{name: "cosign without identity", mut: func(m *Manifest) {
			m.Entries[0].Upstream = UpstreamCheck{Method: UpstreamCosignKeylessOnline, Issuer: "https://token.actions.githubusercontent.com", VerifiedAt: testNow.Format(time.RFC3339)}
		}},
		{name: "cosign pinned", ok: true, mut: func(m *Manifest) {
			m.Kind = Engine
			m.Entries[0].Upstream = UpstreamCheck{
				Method:   UpstreamCosignKeylessOnline,
				Identity: "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v1.30.1",
				Issuer:   "https://token.actions.githubusercontent.com", VerifiedAt: testNow.Format(time.RFC3339), VerifiedWhere: "release_pipeline",
			}
		}},
		{name: "sums missing digest", mut: func(m *Manifest) {
			m.Entries[0].Upstream = UpstreamCheck{Method: UpstreamSHA256Sums, SHA256SumsB64: sums(strings.Repeat("b", 64) + "  other\n")}
		}},
		{name: "sums listing digest", ok: true, mut: func(m *Manifest) {
			m.Entries[0].Upstream = UpstreamCheck{Method: UpstreamSHA256Sums, SHA256SumsB64: sums(m.Entries[0].SHA256 + "  malicious.idx\n")}
		}},
		{name: "slsa without bundle", mut: func(m *Manifest) {
			m.Entries[0].Upstream = UpstreamCheck{Method: UpstreamSLSABundle, SHA256SumsB64: sums(m.Entries[0].SHA256 + "  x\n")}
		}},
		{name: "unknown method", mut: func(m *Manifest) { m.Entries[0].Upstream.Method = "trust_me" }},
		{name: "duplicate entry", mut: func(m *Manifest) { m.Entries = append(m.Entries, m.Entries[0]) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := base
			m.Entries = append([]Entry(nil), base.Entries...)
			tc.mut(&m)
			err := Validate(m)
			if (err == nil) != tc.ok {
				t.Fatalf("Validate = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestFreshnessAt(t *testing.T) {
	m := sampleContent(1, 0)
	issued := testNow.Add(-time.Hour)
	cases := []struct {
		at    time.Time
		floor time.Duration
		want  Freshness
	}{
		{testNow, 0, Fresh},
		{issued.Add(8 * 24 * time.Hour), 0, Stale},
		{issued.Add(31 * 24 * time.Hour), 0, Unknown},
		{issued.Add(8 * 24 * time.Hour), 72 * time.Hour, Unknown},
		{issued.Add(8 * 24 * time.Hour), 400 * 24 * time.Hour, Stale},
	}
	for i, tc := range cases {
		if got := FreshnessAt(m, tc.at, tc.floor); got != tc.want {
			t.Errorf("case %d: %s, want %s", i, got, tc.want)
		}
	}
}

func TestEntryForAndArtifact(t *testing.T) {
	m := sampleContent(1, 0)
	e, err := EntryFor(m, "malicious.idx", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckArtifact(e, []byte("index bytes")); err != nil {
		t.Errorf("good bytes refused: %v", err)
	}
	if r := ReasonOf(CheckArtifact(e, []byte("index bytez"))); r != ContentReasonArtifact {
		t.Errorf("tampered bytes: %q", r)
	}
	if r := ReasonOf(CheckArtifact(e, []byte("short"))); r != ContentReasonArtifact {
		t.Errorf("short bytes: %q", r)
	}
	if _, err := EntryFor(m, "other", "linux", "amd64"); ReasonOf(err) != ContentReasonNotCovered {
		t.Errorf("uncovered artifact: %v", err)
	}
	m.Entries[0].OS = "windows"
	if _, err := EntryFor(m, "malicious.idx", "linux", "amd64"); ReasonOf(err) != ContentReasonNotCovered {
		t.Errorf("other platform: %v", err)
	}
}

func TestApplyContentResultKeepsLastKnownGood(t *testing.T) {
	m := sampleContent(4, 2)
	s := Apply(State{}, Result{Manifest: m, Hash: strings.Repeat("c", 64)}, nil, testNow)
	if s.Accepted == nil || s.Accepted.ManifestVersion != 4 || s.LastFailure != "" {
		t.Fatalf("success state: %+v", s)
	}
	f := Apply(s, Result{}, &Refusal{Reason: ContentReasonRollback}, testNow.Add(time.Hour))
	if f.Accepted == nil || f.Accepted.ManifestVersion != 4 || f.LastFailure != ContentReasonRollback || f.LastFailureAt == "" {
		t.Fatalf("failure must keep the last-known-good and record why: %+v", f)
	}
	g := Apply(f, Result{}, fmt.Errorf("network"), testNow)
	if g.LastFailure != ContentReasonEnvelope {
		t.Errorf("an untyped failure records a reason: %+v", g)
	}
}

func TestContentSigningMessagesAreDomainSeparated(t *testing.T) {
	h := strings.Repeat("d", 64)
	v := SigningMessage(Engine, 3, h)
	o := MirrorMessage(Engine, 3, h, "sig")
	if string(v) == string(o) || !strings.HasPrefix(string(v), SigningDomain+"\x00") || !strings.HasPrefix(string(o), MirrorDomain+"\x00") {
		t.Errorf("messages not separated: %q %q", v, o)
	}
	if string(SigningMessage(Engine, 3, h)) == string(SigningMessage(RulePack, 3, h)) {
		t.Error("kind not bound")
	}
	for _, other := range []string{"sbo-update-manifest-v1", "sbo-update-manifest-v2", "sbo-release-index-v1"} {
		if strings.HasPrefix(string(v), other) {
			t.Errorf("collides with the %s domain", other)
		}
	}
}
