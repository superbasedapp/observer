package platformcontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTransportGolden(t *testing.T) {
	t.Parallel()
	cases := map[string]any{
		"error_response":         ErrorResponse{Code: CodeInvalid, Field: "tenant_id"},
		"error_response_version": ErrorResponse{Code: CodeUnknownVersion, SupportedVersions: []string{Version}},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join("testdata", name+".golden.json")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.ReplaceAll(string(want), "\r\n", "\n") != string(got) {
				t.Fatalf("golden mismatch for %s:\n got %s\nwant %s", name, got, want)
			}
		})
	}
}

func TestErrorCodesUnique(t *testing.T) {
	t.Parallel()
	seen := map[ErrorCode]bool{}
	for _, c := range KnownErrorCodes {
		if seen[c] || !c.Valid() || c == "" {
			t.Fatalf("code %q duplicated or invalid", c)
		}
		seen[c] = true
	}
	if ErrorCode("nope").Valid() {
		t.Fatal("unknown code reported valid")
	}
}

func TestSigningTarget(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ path, q, want string }{
		{"/platform/v1/usage", "day=2026-11-12", "/platform/v1/usage?day=2026-11-12"},
		{"/platform/v1/tenants", "", "/platform/v1/tenants"},
	} {
		if got := SigningTarget(c.path, c.q); got != c.want {
			t.Fatalf("SigningTarget(%q,%q) = %q, want %q", c.path, c.q, got, c.want)
		}
	}
}

func TestEnvelopeHeadersRoundTrip(t *testing.T) {
	t.Parallel()
	e := Envelope{KeyID: "k1", Timestamp: 1700000000, Nonce: "n1", BodyDigest: BodyDigest([]byte("x")), Signature: "c2ln"}
	h := map[string]string{}
	for _, p := range e.HeaderPairs() {
		h[p[0]] = p[1]
	}
	back, err := ParseEnvelopeHeaders(func(n string) string { return h[n] })
	if err != nil || back != e {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	for _, drop := range []string{HeaderKeyID, HeaderTimestamp, HeaderNonce, HeaderDigest, HeaderSignature} {
		_, err := ParseEnvelopeHeaders(func(n string) string {
			if n == drop {
				return ""
			}
			return h[n]
		})
		if !errors.Is(err, ErrUnsigned) {
			t.Fatalf("missing %s: %v", drop, err)
		}
	}
	h[HeaderTimestamp] = "soon"
	if _, err := ParseEnvelopeHeaders(func(n string) string { return h[n] }); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("bad timestamp: %v", err)
	}
}

func TestResponseEnvelope(t *testing.T) {
	t.Parallel()
	seed := sha256.Sum256([]byte("host-key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	now := time.Unix(1700000000, 0)
	body := []byte(`{"evicted":true}`)
	const method, target = "POST", "/platform/v1/tenants/org_1/evict"
	e, err := NewResponseEnvelope(priv, "h1", "n1", method, target, body, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.VerifyResponse(pub, "n1", method, target, body, now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := e.VerifyResponse(pub, "n2", method, target, body, now); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("nonce mismatch: %v", err)
	}
	if err := e.VerifyResponse(pub, "n1", method, target, body, now.Add(ReplayWindow+time.Second)); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	if err := e.VerifyResponse(pub, "n1", method, target, []byte("{}"), now); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("digest: %v", err)
	}
	// Domain separation: a response signature never verifies as a request.
	if err := e.Verify(pub, method, target, body, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("response verified as request: %v", err)
	}
	req, err := NewEnvelope(priv, "h1", "n1", method, target, body, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.VerifyResponse(pub, "n1", method, target, body, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("request verified as response: %v", err)
	}
}
