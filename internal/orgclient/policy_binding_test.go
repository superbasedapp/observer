package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// boundTestBundle signs a bundle bound to b (nil = the v1 envelope).
func boundTestBundle(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, version int64, toml string, b *orgcontract.PolicyBinding) orgcontract.PolicyBundle {
	t.Helper()
	out := signedTestBundle(t, priv, pub, version, toml)
	if b != nil {
		out.Binding = b
		out.Signature = orgcontract.SignPolicyBundleEnvelope(priv, out)
	}
	return out
}

// TestFetchPolicyBundle_Binding pins C156-15 on the node: the fetch asks for
// a binding; a bundle bound to another member is refused although the org
// signed it; a bound bundle for this member lands and sticks, so a later
// unbound one is a refused downgrade; an unbound bundle from a server that
// never bound (an older server) is still accepted; and the same content
// re-served bound over an unbound cache upgrades the cache.
func TestFetchPolicyBundle_Binding(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var serve *orgcontract.PolicyBundle
	var caps []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caps = r.URL.Query()["policy_caps"]
		writeTestJSON(w, http.StatusOK, serve)
	}))
	t.Cleanup(srv.Close)
	mine := &orgcontract.PolicyBinding{OrgID: "org-1", Subject: "scim-42"}
	fetch := func(c *Client, cachePath string, b orgcontract.PolicyBundle) PolicyResult {
		t.Helper()
		serve = &b
		res, err := c.FetchPolicyBundle(context.Background(), cachePath)
		if err != nil {
			t.Fatalf("FetchPolicyBundle: %v", err)
		}
		return res
	}
	cachedBinding := func(path string) *orgcontract.PolicyBinding {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var held orgcontract.PolicyBundle
		if err := json.Unmarshal(raw, &held); err != nil {
			t.Fatal(err)
		}
		return held.Binding
	}

	t.Run("bound to another member is refused", func(t *testing.T) {
		c, _, cachePath := enrolledClient(t, srv.URL)
		res := fetch(c, cachePath, boundTestBundle(t, priv, pub, 3, escalatingTOML, &orgcontract.PolicyBinding{OrgID: "org-1", Subject: "scim-7"}))
		if res.Status != PolicyRejected || res.RejectCode != RejectSigInvalid {
			t.Fatalf("another member's bundle = %+v, want rejected sig_invalid", res)
		}
		// project-families-v1 rides along where security.scanning is
		// linked (lane sec-p3, projectFamiliesAdvertised).
		wantCaps := 2
		if projectFamiliesAdvertised() {
			wantCaps = 3
		}
		if len(caps) != wantCaps || caps[0] != orgcontract.PolicyBindingCapability || caps[1] != orgcontract.PolicyBindingV3Capability ||
			(wantCaps == 3 && caps[2] != orgcontract.ProjectFamiliesCapability) {
			t.Fatalf("the fetch advertised %q, want the binding capability", caps)
		}
		if _, err := os.Stat(cachePath); err == nil {
			t.Fatal("a refused bundle was cached")
		}
		res = fetch(c, cachePath, boundTestBundle(t, priv, pub, 3, escalatingTOML, &orgcontract.PolicyBinding{OrgID: "org-2", Subject: "scim-42"}))
		if res.Status != PolicyRejected {
			t.Fatalf("another org's bundle = %+v, want rejected", res)
		}
	})

	t.Run("bound lands and an unbound one is then a downgrade", func(t *testing.T) {
		c, _, cachePath := enrolledClient(t, srv.URL)
		if res := fetch(c, cachePath, boundTestBundle(t, priv, pub, 3, escalatingTOML, mine)); res.Status != PolicyApplied {
			t.Fatalf("own bound bundle = %+v, want applied", res)
		}
		if b := cachedBinding(cachePath); b == nil || *b != *mine {
			t.Fatalf("cached binding = %+v", b)
		}
		res := fetch(c, cachePath, boundTestBundle(t, priv, pub, 4, escalatingTOML, nil))
		if res.Status != PolicyRejected || res.RejectCode != RejectSigInvalid {
			t.Fatalf("unbound after bound = %+v, want rejected sig_invalid", res)
		}
	})

	t.Run("an older server's unbound bundle still applies and upgrades in place", func(t *testing.T) {
		c, _, cachePath := enrolledClient(t, srv.URL)
		if res := fetch(c, cachePath, boundTestBundle(t, priv, pub, 3, escalatingTOML, nil)); res.Status != PolicyApplied {
			t.Fatalf("unbound bundle on a fresh node = %+v, want applied", res)
		}
		if b := cachedBinding(cachePath); b != nil {
			t.Fatalf("cached binding = %+v, want none", b)
		}
		res := fetch(c, cachePath, boundTestBundle(t, priv, pub, 3, escalatingTOML, mine))
		if res.Status == PolicyRejected {
			t.Fatalf("same content re-served bound = %+v, want accepted", res)
		}
		if b := cachedBinding(cachePath); b == nil || *b != *mine {
			t.Fatalf("cache not upgraded to the bound envelope: %+v", b)
		}
	})
}
