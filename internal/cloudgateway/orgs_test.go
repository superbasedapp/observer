package cloudgateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestBootstrapDiscoveryWorksWithoutAnyGrant pins D-IND-2: organization
// discovery is the user's own connect action (R2 F10), so with no consent
// source at all both calls still reach the service and come back validated.
func TestBootstrapDiscoveryWorksWithoutAnyGrant(t *testing.T) {
	var hits []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/orgs", func(w http.ResponseWriter, _ *http.Request) {
		hits = append(hits, "list")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"orgs":[]}`))
	})
	mux.HandleFunc("POST /v1/orgs/personal:ensure", func(w http.ResponseWriter, _ *http.Request) {
		hits = append(hits, "ensure")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"org":{"org_id":"o1","slug":"u-abcdefgh","display_name":"Personal","kind":"personal","status":"provisioning","tenancy":"individual","stage":"queued"},"created":true}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cred := &memCred{}
	g, err := Open(Options{
		Grants:     nil, // deliberately no consent source at all
		Cred:       cred,
		BaseURL:    srv.URL,
		MaxRetries: 0,
		Backoff:    func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := cred.SaveAPIToken("tok-1"); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	ctx := context.Background()
	list, err := g.BootstrapListOrgs(ctx)
	if err != nil {
		t.Fatalf("BootstrapListOrgs: %v", err)
	}
	if len(list.Orgs) != 0 {
		t.Fatalf("orgs = %+v", list.Orgs)
	}
	ens, err := g.BootstrapEnsurePersonalOrg(ctx)
	if err != nil {
		t.Fatalf("BootstrapEnsurePersonalOrg: %v", err)
	}
	if !ens.Created || ens.Org.Stage != "queued" {
		t.Fatalf("ensure = %+v", ens)
	}
	if len(hits) != 2 || hits[0] != "list" || hits[1] != "ensure" {
		t.Fatalf("hits = %v", hits)
	}
}

// TestBootstrapDiscoveryUnconfigured: with no base URL neither call has a
// network to reach.
func TestBootstrapDiscoveryUnconfigured(t *testing.T) {
	g := newTestGateway(t, nil, "")
	if _, err := g.BootstrapListOrgs(context.Background()); !errors.Is(err, ErrNoBaseURL) {
		t.Fatalf("BootstrapListOrgs: %v, want ErrNoBaseURL", err)
	}
	if _, err := g.BootstrapEnsurePersonalOrg(context.Background()); !errors.Is(err, ErrNoBaseURL) {
		t.Fatalf("BootstrapEnsurePersonalOrg: %v, want ErrNoBaseURL", err)
	}
}
