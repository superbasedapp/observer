package cloudclient

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// orgsTestClient starts a fake service serving the exchange plus one
// discovery handler, and returns a signed-in client.
func orgsTestClient(t *testing.T, pattern string, h func(fs *fakeServer, w http.ResponseWriter, r *http.Request)) *Client {
	t.Helper()
	fs := newFakeServer(t)
	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", fs.handler())
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { h(fs, w, r) })
	srv := startServer(t, mux)
	c, _ := newTestClient(t, srv.URL, "workos-access-tok")
	if err := c.Exchange(context.Background()); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	return c
}

const personalOrgJSON = `{"org_id":"org-1","slug":"u-abcdefgh","display_name":"Personal","kind":"personal",` +
	`"status":"active","tenancy":"individual","server_url":"https://u-abcdefgh.example.test"}`

func TestListOrgsDecodesAndValidates(t *testing.T) {
	c := orgsTestClient(t, "GET /v1/orgs", func(fs *fakeServer, w http.ResponseWriter, r *http.Request) {
		if bearerOf(r) != fs.apiToken {
			http.Error(w, "bad bearer", http.StatusUnauthorized)
			return
		}
		verifyProof(t, r, fs.thumbprint, fs.apiToken, nil)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"orgs":[` + personalOrgJSON + `,` +
			`{"org_id":"org-2","slug":"acme","display_name":"Acme","kind":"team","status":"provisioning","tenancy":"managed","stage":"creating"}]}`))
	})
	got, err := c.ListOrgs(context.Background())
	if err != nil {
		t.Fatalf("ListOrgs: %v", err)
	}
	if len(got.Orgs) != 2 || got.Orgs[0].Kind != cloudcontract.DeviceOrgPersonal || got.Orgs[1].Stage != "creating" {
		t.Fatalf("orgs = %+v", got.Orgs)
	}
	if got.Orgs[0].ServerURL != "https://u-abcdefgh.example.test" {
		t.Fatalf("server url = %q", got.Orgs[0].ServerURL)
	}
}

func TestListOrgsRefusesInvalidAnswer(t *testing.T) {
	cases := []struct {
		name, body string
	}{
		{"http server url", `{"orgs":[{"org_id":"o","slug":"acme","kind":"team","status":"active","tenancy":"managed","server_url":"http://acme.example.test"}]}`},
		{"foreign host", `{"orgs":[{"org_id":"o","slug":"acme","kind":"team","status":"active","tenancy":"managed","server_url":"https://evil.example.test"}]}`},
		{"managed personal", `{"orgs":[{"org_id":"o","slug":"u-x","kind":"personal","status":"active","tenancy":"managed"}]}`},
		{"unknown status", `{"orgs":[{"org_id":"o","slug":"acme","kind":"team","status":"weird","tenancy":"managed"}]}`},
		{"not json", `<html>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := orgsTestClient(t, "GET /v1/orgs", func(_ *fakeServer, w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})
			if _, err := c.ListOrgs(context.Background()); err == nil {
				t.Fatal("an invalid answer was accepted")
			}
		})
	}
}

func TestEnsurePersonalOrgCreatedAndExisting(t *testing.T) {
	for _, tc := range []struct {
		status  int
		created bool
	}{{http.StatusCreated, true}, {http.StatusOK, false}} {
		var method string
		c := orgsTestClient(t, "/v1/orgs/personal:ensure", func(fs *fakeServer, w http.ResponseWriter, r *http.Request) {
			method = r.Method
			verifyProof(t, r, fs.thumbprint, fs.apiToken, nil)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			created := "false"
			if tc.created {
				created = "true"
			}
			_, _ = w.Write([]byte(`{"org":` + personalOrgJSON + `,"created":` + created + `}`))
		})
		got, err := c.EnsurePersonalOrg(context.Background())
		if err != nil {
			t.Fatalf("EnsurePersonalOrg (%d): %v", tc.status, err)
		}
		if method != http.MethodPost {
			t.Fatalf("method = %s, want POST", method)
		}
		if got.Created != tc.created || got.Org.Slug != "u-abcdefgh" {
			t.Fatalf("ensure (%d) = %+v", tc.status, got)
		}
	}
}

func TestEnsurePersonalOrgRefusesATeamOrg(t *testing.T) {
	c := orgsTestClient(t, "/v1/orgs/personal:ensure", func(_ *fakeServer, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"org":{"org_id":"o","slug":"acme","kind":"team","status":"active","tenancy":"managed"},"created":true}`))
	})
	_, err := c.EnsurePersonalOrg(context.Background())
	if err == nil || !strings.Contains(err.Error(), "refused an invalid answer") {
		t.Fatalf("a team org from ensure was accepted: %v", err)
	}
}

func TestDiscoveryNeedsSignIn(t *testing.T) {
	c, _ := newTestClient(t, "http://127.0.0.1:1", "workos-access-tok")
	if _, err := c.ListOrgs(context.Background()); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("ListOrgs without a token: %v, want ErrNotAuthenticated", err)
	}
	if _, err := c.EnsurePersonalOrg(context.Background()); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("EnsurePersonalOrg without a token: %v, want ErrNotAuthenticated", err)
	}
}

func TestDiscoveryServerErrorIsAnAPIError(t *testing.T) {
	c := orgsTestClient(t, "GET /v1/orgs", func(_ *fakeServer, w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"code":"not_found","error":"no"}`, http.StatusNotFound)
	})
	_, err := c.ListOrgs(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("want a 404 APIError, got %v", err)
	}
}
