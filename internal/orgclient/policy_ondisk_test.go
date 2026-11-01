package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestVerifyCachedPolicyBundle pins the T-846 on-disk check, one case per
// row: after a verified fetch the file reads verified, and every way of
// editing it afterwards reads tampered with the gen1 reason the policy-state
// row carries; a deleted file the node had accepted reads missing (T-864).
func TestVerifyCachedPolicyBundle(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	tests := []struct {
		name       string
		mutate     func(t *testing.T, path string)
		wantInteg  string
		wantReject PolicyRejectCode
	}{
		{"untouched", func(*testing.T, string) {}, orgcontract.BundleIntegrityVerified, RejectNone},
		{"body edited, version kept (audit b2)", func(t *testing.T, path string) {
			rewriteCache(t, path, func(b *orgcontract.PolicyBundle) { b.BundleTOML = strings.Replace(b.BundleTOML, "deny", "allow", 1) })
		}, orgcontract.BundleIntegrityTampered, RejectSigInvalid},
		{"re-signed with a forged key", func(t *testing.T, path string) {
			rewriteCache(t, path, func(b *orgcontract.PolicyBundle) {
				*b = signedTestBundle(t, otherPriv, otherPub, b.Version, b.BundleTOML)
			})
		}, orgcontract.BundleIntegrityTampered, RejectKeyPinMismatch},
		{"corrupt JSON", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("}{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, orgcontract.BundleIntegrityTampered, RejectSigInvalid},
		{"deleted", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}, orgcontract.BundleIntegrityMissing, RejectNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ps := newPolicyBundleServer(t)
			b := signedTestBundle(t, priv, pub, 3, escalatingTOML)
			ps.bundle = &b
			c, _, cachePath := enrolledClient(t, ps.srv.URL)
			if res, err := c.FetchPolicyBundle(context.Background(), cachePath); err != nil || res.Status != PolicyApplied {
				t.Fatalf("seed fetch = %+v, %v", res, err)
			}
			tc.mutate(t, cachePath)
			got, err := c.VerifyCachedPolicyBundle(context.Background(), cachePath)
			if err != nil {
				t.Fatalf("VerifyCachedPolicyBundle: %v", err)
			}
			if got.Integrity != tc.wantInteg || got.RejectCode != tc.wantReject {
				t.Fatalf("check = %+v, want %s/%q", got, tc.wantInteg, tc.wantReject)
			}
		})
	}
}

// TestFetchPolicyBundle_TamperedCacheIsRefetched pins T-846 (b): a cache
// edited on disk is never kept by a 304. The poll drops If-None-Match, the
// server answers 200, and the same-version bundle is re-materialised, so
// the hooks get the org layer back at the next poll.
func TestFetchPolicyBundle_TamperedCacheIsRefetched(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyBundleServer(t)
	b := signedTestBundle(t, priv, pub, 3, escalatingTOML)
	ps.bundle = &b
	c, _, cachePath := enrolledClient(t, ps.srv.URL)
	if _, err := c.FetchPolicyBundle(context.Background(), cachePath); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}
	rewriteCache(t, cachePath, func(b *orgcontract.PolicyBundle) { b.BundleTOML = strings.Replace(b.BundleTOML, "deny", "allow", 1) })

	res, err := c.FetchPolicyBundle(context.Background(), cachePath)
	if err != nil {
		t.Fatalf("FetchPolicyBundle: %v", err)
	}
	if got := ps.seen[len(ps.seen)-1]; got != "" {
		t.Fatalf("If-None-Match = %q on a tampered cache, want none (a 304 would keep the edited file)", got)
	}
	if res.Status != PolicyApplied {
		t.Fatalf("result = %+v, want the bundle re-applied", res)
	}
	check, err := c.VerifyCachedPolicyBundle(context.Background(), cachePath)
	if err != nil || check.Integrity != orgcontract.BundleIntegrityVerified {
		t.Fatalf("after re-fetch: %+v, %v, want verified", check, err)
	}
	// And a verified cache still rides the 304.
	if res, err := c.FetchPolicyBundle(context.Background(), cachePath); err != nil || res.Status != PolicyUnchanged {
		t.Fatalf("third poll = %+v, %v, want unchanged via 304", res, err)
	}
}

// TestKickPolicyBundlePollCoalesces pins the kick seam: nonblocking, and two
// kicks before the loop drains are one wake-up.
func TestKickPolicyBundlePollCoalesces(t *testing.T) {
	c, _, _ := enrolledClient(t, "http://127.0.0.1:1")
	c.KickPolicyBundlePoll()
	c.KickPolicyBundlePoll()
	if n := len(c.policyBundleKick); n != 1 {
		t.Fatalf("queued kicks = %d, want 1", n)
	}
	var nilClient *Client
	nilClient.KickPolicyBundlePoll() // must not panic
}

func rewriteCache(t *testing.T, path string, edit func(*orgcontract.PolicyBundle)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var b orgcontract.PolicyBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	edit(&b)
	out, _ := json.Marshal(b)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyCachedPolicyBundle_NeverFetchedIsAbsent: with no accepted bundle
// on record, no file is "nothing published", not a deletion (T-864 gap 1).
func TestVerifyCachedPolicyBundle_NeverFetchedIsAbsent(t *testing.T) {
	ps := newPolicyBundleServer(t)
	c, _, cachePath := enrolledClient(t, ps.srv.URL)
	got, err := c.VerifyCachedPolicyBundle(context.Background(), cachePath)
	if err != nil {
		t.Fatalf("VerifyCachedPolicyBundle: %v", err)
	}
	if got.Integrity != orgcontract.BundleIntegrityAbsent {
		t.Fatalf("check = %+v, want absent", got)
	}
}
