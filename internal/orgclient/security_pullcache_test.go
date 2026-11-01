package orgclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestSecurityPullCacheKeepsNoDedupeKey (lane LEFT-SHARED merge audit finding
// 4): the org dedupe key reaches the caller in the applied body but never the
// managed pull cache; a restart restores the cached document from the key the
// node holds (its key file) and re-verifies it; without the key the cached
// document does not verify, so the node asks again unconditionally.
func TestSecurityPullCacheKeepsNoDedupeKey(t *testing.T) {
	m := newMPServer(t)
	c, priv, now := managedPullFixture(t, m.srv.URL)
	ctx := context.Background()
	exp := now.Unix() + 3600
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, orgcontract.SecurityOrgDedupeKeyBytes))
	body, err := orgcontract.ComposeSecurityServed([]byte(`{"version":1,"finding_share":"findings"}`),
		[]string{orgcontract.SecurityCapabilityOrgDedupe}, orgcontract.SecurityServedInput{Dedupe: &orgcontract.SecurityOrgDedupe{Version: 4, Key: key}})
	if err != nil {
		t.Fatal(err)
	}
	m.set(serveDoc(signFor(t, priv, "security", "scim-42", 2, exp, string(body))))
	saved := SecurityOrgDedupeKeySource
	t.Cleanup(func() { SecurityOrgDedupeKeySource = saved })
	SecurityOrgDedupeKeySource = nil

	out, err := c.FetchManagedPull(ctx, "security", managed)
	if err != nil || !out.InForce || !strings.Contains(string(out.Body), key) {
		t.Fatalf("the applied body must carry the key: %+v %v", out, err)
	}
	ident, err := c.managedPullIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	row, ok, err := c.store.LoadManagedPull(ctx, "security", ident.orgKey, ident.generation)
	if err != nil || !ok {
		t.Fatalf("cached row: %v %v", ok, err)
	}
	if strings.Contains(row.DocJSON, key) {
		t.Fatal("the dedupe key reached managed_pull_cache.doc_json")
	}

	// A restart with the key file held: the cached document verifies.
	SecurityOrgDedupeKeySource = func() (orgcontract.SecurityOrgDedupe, bool) {
		return orgcontract.SecurityOrgDedupe{Version: 4, Key: key}, true
	}
	if got, _ := c.LoadPersistedManagedPull(ctx, "security", managed); !got.InForce || got.Version != 2 || !strings.Contains(string(got.Body), key) {
		t.Fatalf("restart with the key held: %+v", got)
	}
	// Without it (no file, or another version) nothing is in force from the
	// cache and the next fetch asks without If-None-Match.
	for _, src := range []func() (orgcontract.SecurityOrgDedupe, bool){
		nil,
		func() (orgcontract.SecurityOrgDedupe, bool) {
			return orgcontract.SecurityOrgDedupe{Version: 3, Key: key}, true
		},
	} {
		SecurityOrgDedupeKeySource = src
		if got, _ := c.LoadPersistedManagedPull(ctx, "security", managed); got.InForce || got.Version != 0 {
			t.Fatalf("restart without the key: %+v", got)
		}
	}
	m.mu.Lock()
	m.inm = nil
	m.mu.Unlock()
	if out, err := c.FetchManagedPull(ctx, "security", managed); err != nil || !out.InForce {
		t.Fatalf("refetch: %+v %v", out, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.inm) != 1 || m.inm[0] != "" {
		t.Fatalf("a cached document that does not verify must not be asked for conditionally: %q", m.inm)
	}
}
