package pricingfeedgate

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

const testKeyID = "pricing-feed-test"

// signedEnvelope builds a valid, signed feed envelope plus the KeySet that
// verifies it. The key is throwaway (generated per-call); no test ever embeds
// the production private key.
func signedEnvelope(t *testing.T, feedVersion int64, rows []pricingfeed.Row) (pricingfeed.Envelope, pricingfeed.KeySet, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keys, err := pricingfeed.NewKeySet(map[string]string{testKeyID: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatalf("new key set: %v", err)
	}
	digest, err := pricingfeed.Digest(rows)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	env := pricingfeed.Envelope{
		SchemaVersion: pricingfeed.SupportedSchemaVersion,
		FeedVersion:   feedVersion,
		GeneratedAt:   "2026-09-11T00:00:00Z",
		Rows:          rows,
		Digest:        digest,
		KeyID:         testKeyID,
	}
	sig, err := pricingfeed.Sign(priv, env)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	env.Signature = sig
	return env, keys, priv
}

func sampleRows() []pricingfeed.Row {
	return []pricingfeed.Row{{
		PricingPolicyRow: orgcontract.PricingPolicyRow{
			Model:         "claude-opus-4-8",
			InputPerMTok:  orgcontract.Rate(4),
			OutputPerMTok: orgcontract.Rate(20),
			Source:        "list",
		},
		Grade: "verified",
	}}
}

// serve returns an httptest server that answers 304 when If-None-Match matches
// wantDigest, else 200 with the given body.
func serve(t *testing.T, body []byte, wantDigest string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantDigest != "" && r.Header.Get("If-None-Match") == `"`+wantDigest+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"`+wantDigest+`"`)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A verified 200 body is returned with NotModified false.
func TestPricingFeedGateFetchVerifies200(t *testing.T) {
	env, keys, _ := signedEnvelope(t, 3, sampleRows())
	body, _ := json.Marshal(env)
	srv := serve(t, body, env.Digest)

	res, err := Fetch(context.Background(), Options{URL: srv.URL, Keys: keys})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.NotModified {
		t.Fatal("a fresh 200 must not report NotModified")
	}
	if res.Envelope.FeedVersion != 3 || len(res.Envelope.Rows) != 1 {
		t.Fatalf("envelope = %+v, want the verified v3 body", res.Envelope)
	}
}

// If-None-Match on the applied digest short-circuits to 304.
func TestPricingFeedGateFetch304(t *testing.T) {
	env, keys, _ := signedEnvelope(t, 3, sampleRows())
	body, _ := json.Marshal(env)
	srv := serve(t, body, env.Digest)

	res, err := Fetch(context.Background(), Options{URL: srv.URL, LastDigest: env.Digest, Keys: keys})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.NotModified {
		t.Fatal("a matching If-None-Match must report NotModified")
	}
}

// An unsigned body is refused (ErrUnsigned) and no envelope is returned.
func TestPricingFeedGateRefusesUnsigned(t *testing.T) {
	env, keys, _ := signedEnvelope(t, 3, sampleRows())
	env.Signature = "" // strip the signature
	body, _ := json.Marshal(env)
	srv := serve(t, body, env.Digest)

	_, err := Fetch(context.Background(), Options{URL: srv.URL, Keys: keys})
	if !errors.Is(err, pricingfeed.ErrUnsigned) {
		t.Fatalf("want ErrUnsigned, got %v", err)
	}
}

// A body signed by a key this build does not accept is refused.
func TestPricingFeedGateRefusesUnknownKey(t *testing.T) {
	env, _, _ := signedEnvelope(t, 3, sampleRows())
	body, _ := json.Marshal(env)
	srv := serve(t, body, env.Digest)

	// A DIFFERENT key set — the envelope's key id is not in it.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	otherKeys, _ := pricingfeed.NewKeySet(map[string]string{"other": hex.EncodeToString(otherPub)})

	_, err := Fetch(context.Background(), Options{URL: srv.URL, Keys: otherKeys})
	if !errors.Is(err, pricingfeed.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

// A tampered body (digest no longer matches the rows) is refused before the
// signature math.
func TestPricingFeedGateRefusesTamperedDigest(t *testing.T) {
	env, keys, _ := signedEnvelope(t, 3, sampleRows())
	env.Digest = "deadbeef" // corrupt
	body, _ := json.Marshal(env)
	srv := serve(t, body, "deadbeef")

	_, err := Fetch(context.Background(), Options{URL: srv.URL, Keys: keys})
	if !errors.Is(err, pricingfeed.ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got %v", err)
	}
}
