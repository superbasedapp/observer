package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

func sampleEnvelope() pricingfeed.Envelope {
	return pricingfeed.Envelope{
		SchemaVersion: pricingfeed.SupportedSchemaVersion,
		FeedVersion:   9,
		GeneratedAt:   "2026-09-11T00:00:00Z",
		KeyID:         "k",
		Digest:        "dig-9",
		Signature:     "sig",
		Rows: []pricingfeed.Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{
			Model: "m", InputPerMTok: orgcontract.Rate(1),
		}}},
	}
}

// A 200 body decodes into the envelope (unverified — the lane does not check
// signatures).
func TestPricingFeedFetchDecodes200(t *testing.T) {
	body, _ := json.Marshal(sampleEnvelope())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	res, err := New(nil).Fetch(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.NotModified || res.Envelope.FeedVersion != 9 {
		t.Fatalf("res = %+v, want the decoded v9 body", res)
	}
}

// A conditional request with a matching digest gets a 304 and NotModified.
func TestPricingFeedFetch304SendsIfNoneMatch(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("If-None-Match")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	res, err := New(nil).Fetch(context.Background(), srv.URL, "dig-9")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.NotModified {
		t.Fatal("a 304 must report NotModified")
	}
	if got != `"dig-9"` {
		t.Errorf("If-None-Match = %q, want the quoted last digest", got)
	}
}

// A non-200/304 status is a typed ErrStatus.
func TestPricingFeedFetchBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := New(nil).Fetch(context.Background(), srv.URL, "")
	if !errors.Is(err, ErrStatus) {
		t.Fatalf("want ErrStatus, got %v", err)
	}
}

// An undecodable 200 body is a typed ErrDecode.
func TestPricingFeedFetchBadBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()

	_, err := New(nil).Fetch(context.Background(), srv.URL, "")
	if !errors.Is(err, ErrDecode) {
		t.Fatalf("want ErrDecode, got %v", err)
	}
}

// An empty or relative URL is refused before any network attempt.
func TestPricingFeedFetchBadURL(t *testing.T) {
	for _, u := range []string{"", "not-a-url", "ftp://x/y"} {
		if _, err := New(nil).Fetch(context.Background(), u, ""); !errors.Is(err, ErrBadURL) {
			t.Errorf("Fetch(%q): want ErrBadURL, got %v", u, err)
		}
	}
}
