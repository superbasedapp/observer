package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestFetchPolicyBundle_ReportsCacheRepair pins T-869: a fetch that
// re-materialises a cache the node had accepted and that no longer verifies
// (edited, deleted, displaced) says so on PolicyResult, so the daemon can
// record the tamper the poll repaired before the posture check saw it. A
// clean upgrade, a never-accepted absent cache and a 304 repair nothing.
func TestFetchPolicyBundle_ReportsCacheRepair(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		name string
		// seed fetches v1 first (false: the node never accepted a bundle).
		seed bool
		// between runs after the seed fetch, before the fetch under test.
		between       func(t *testing.T, ps *policyBundleServer, path string)
		wantStatus    PolicyStatus
		wantRepair    CacheRepair
		wantCode      PolicyRejectCode
		wantDisplaced bool
	}{
		{"edited cache, version kept", true, func(t *testing.T, _ *policyBundleServer, path string) {
			rewriteCache(t, path, func(b *orgcontract.PolicyBundle) { b.BundleTOML = strings.Replace(b.BundleTOML, "deny", "allow", 1) })
		}, PolicyApplied, CacheRepairTampered, RejectSigInvalid, false},
		{"cache deleted after it was accepted", true, func(t *testing.T, _ *policyBundleServer, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}, PolicyApplied, CacheRepairMissing, RejectNone, false},
		{"a directory planted at the cache path", true, func(t *testing.T, _ *policyBundleServer, path string) {
			plantLockedDirectory(t, path)
		}, PolicyApplied, CacheRepairMissing, RejectNone, true},
		{"normal upgrade v1 to v2", true, func(t *testing.T, ps *policyBundleServer, _ string) {
			b2 := signedTestBundle(t, priv, pub, 2, escalatingTOML+"# v2\n")
			ps.bundle = &b2
		}, PolicyApplied, CacheRepairNone, RejectNone, false},
		{"never accepted, absent cache", false, func(*testing.T, *policyBundleServer, string) {}, PolicyApplied, CacheRepairNone, RejectNone, false},
		{"verified cache rides the 304", true, func(*testing.T, *policyBundleServer, string) {}, PolicyUnchanged, CacheRepairNone, RejectNone, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := newPolicyBundleServer(t)
			b1 := signedTestBundle(t, priv, pub, 1, escalatingTOML)
			ps.bundle = &b1
			c, _, cachePath := enrolledClient(t, ps.srv.URL)
			if tc.seed {
				if res, err := c.FetchPolicyBundle(context.Background(), cachePath); err != nil || res.Status != PolicyApplied || res.RepairedCache != CacheRepairNone {
					t.Fatalf("seed fetch = %+v, %v, want applied with no repair", res, err)
				}
			}
			tc.between(t, ps, cachePath)
			res, err := c.FetchPolicyBundle(context.Background(), cachePath)
			if err != nil {
				t.Fatalf("FetchPolicyBundle: %v", err)
			}
			if res.DisplacedTo != "" {
				t.Cleanup(func() { _ = os.Chmod(res.DisplacedTo, 0o700) })
			}
			if res.Status != tc.wantStatus || res.RepairedCache != tc.wantRepair || res.RepairedCode != tc.wantCode || (res.DisplacedTo != "") != tc.wantDisplaced {
				t.Fatalf("result = %+v, want status %s repair %q code %q displaced %v", res, tc.wantStatus, tc.wantRepair, tc.wantCode, tc.wantDisplaced)
			}
		})
	}
}

// TestCacheRepairFor pins the classification, one row per pre-fetch verdict:
// only a tampered or missing cache is a repair, and a check that failed (an
// I/O or store fault) never is.
func TestCacheRepairFor(t *testing.T) {
	for _, tc := range []struct {
		name       string
		check      CachedBundleCheck
		err        error
		wantRepair CacheRepair
		wantCode   PolicyRejectCode
	}{
		{"verified", CachedBundleCheck{Integrity: orgcontract.BundleIntegrityVerified, Version: 1}, nil, CacheRepairNone, RejectNone},
		{"tampered", CachedBundleCheck{Integrity: orgcontract.BundleIntegrityTampered, RejectCode: RejectKeyPinMismatch}, nil, CacheRepairTampered, RejectKeyPinMismatch},
		{"missing after acceptance", CachedBundleCheck{Integrity: orgcontract.BundleIntegrityMissing}, nil, CacheRepairMissing, RejectNone},
		{"absent, never accepted", CachedBundleCheck{Integrity: orgcontract.BundleIntegrityAbsent}, nil, CacheRepairNone, RejectNone},
		{"I/O fault", CachedBundleCheck{}, os.ErrPermission, CacheRepairNone, RejectNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repair, code := cacheRepairFor(tc.check, tc.err)
			if repair != tc.wantRepair || code != tc.wantCode {
				t.Fatalf("cacheRepairFor = %q/%q, want %q/%q", repair, code, tc.wantRepair, tc.wantCode)
			}
		})
	}
}
