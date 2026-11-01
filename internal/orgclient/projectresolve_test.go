package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestResolveProjectChecksThePin is milestone 1's sender: the request goes to
// /api/agent/project/resolve with the bearer and the node's hashes only; an
// answer signed by the pinned org key is returned; one signed by any other
// key, an unpinned node, a 404 and a 429 are each their own error.
func TestResolveProjectChecksThePin(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	signer, status := priv, http.StatusOK
	var got orgcontract.ProjectResolveRequest
	var path, authz string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, authz = r.URL.Path, r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		writeTestJSON(w, http.StatusOK, orgcontract.SignProjectResolveAnswer(signer, orgcontract.ProjectResolveAnswer{
			OrgID: "org-1", Subject: "u-1", Epoch: 1, BundleVersion: 1, Nonce: got.Nonce,
			RequestDigest: orgcontract.ProjectResolveRequestDigest(got), OrgProjectIDs: []string{"X"},
		}))
	}))
	defer srv.Close()
	c, s, _ := enrolledClient(t, srv.URL)
	orgURL := srv.URL
	ctx := context.Background()
	nonce, err := NewProjectResolveNonce()
	if err != nil || len(nonce) < 16 {
		t.Fatalf("nonce %q %v", nonce, err)
	}
	req := orgcontract.ProjectResolveRequest{RemoteHashes: []string{"aa"}, Nonce: nonce}

	if _, err := c.ResolveProject(ctx, req); !errors.Is(err, ErrProjectResolveKey) {
		t.Fatalf("an unpinned node: %v", err)
	}
	seedKeyPinWithProvenance(t, s, orgURL, pub, "")
	a, err := c.ResolveProject(ctx, req)
	if err != nil || len(a.OrgProjectIDs) != 1 || a.Nonce != nonce {
		t.Fatalf("pinned answer = %+v, %v", a, err)
	}
	if path != "/api/agent/project/resolve" || authz == "" || got.Nonce != nonce || len(got.RemoteHashes) != 1 {
		t.Fatalf("request: path %q auth %q body %+v", path, authz, got)
	}
	signer = other
	if _, err := c.ResolveProject(ctx, req); !errors.Is(err, ErrProjectResolveKey) {
		t.Fatalf("another key: %v", err)
	}
	signer = priv
	status = http.StatusNotFound
	if _, err := c.ResolveProject(ctx, req); !errors.Is(err, ErrProjectResolveUnavailable) {
		t.Fatalf("404: %v", err)
	}
	status = http.StatusTooManyRequests
	if _, err := c.ResolveProject(ctx, req); !errors.Is(err, ErrProjectResolveLimited) {
		t.Fatalf("429: %v", err)
	}
}
