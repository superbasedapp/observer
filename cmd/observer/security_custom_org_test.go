//go:build !sbo_omit_security && !sbo_omit_security_scan_custom

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/seccustom"
)

// TestCustomOrgPolicyFromThePull (lane SEC-E4, milestone 3): the pull's
// custom mode and the server's four-eyes catalog become the node's
// OrgPolicy; on a managed node a manifest whose digests are not in the
// catalog is refused, forbid stops every driver, require reports a missing
// one, and an individual node takes nothing.
func TestCustomOrgPolicyFromThePull(t *testing.T) {
	m, x := strings.Repeat("a", 64), strings.Repeat("b", 64)
	other := strings.Repeat("c", 64)
	pull := &orgcontract.SecurityManagedPolicyV1{
		Version: 1, CustomManifests: []string{"sha256:" + m},
		CustomCatalog: []orgcontract.SecurityCustomCatalogEntry{{
			ManifestSHA256: "sha256:" + m, ExecutableSHA256: "sha256:" + x,
			BlockingRules: []orgcontract.SecurityCustomBlockingRule{{RuleID: "G101", Precision: 0.9}},
		}},
	}
	pol := customOrgPolicyFrom(pull, nil)
	if pol.Mode != seccustom.OrgModeRequire || len(pol.Entries) != 1 || pol.Entries[0].ExecutableSHA256 != x {
		t.Fatalf("policy %+v", pol)
	}
	rec := func(manifest, exe string) seccustom.Record {
		return seccustom.Record{ManifestSHA256: manifest, Manifest: seccustom.Manifest{ExecutableSHA256: exe, BlockingRules: []string{"G101"}}}
	}
	managed := seccustom.OrgFacts{Managed: true, Isolated: true}
	if d := seccustom.DecideOrg(pol, managed, rec(m, x)); !d.Run || !d.OrgApproved || !d.BlockingRule("G101") {
		t.Errorf("a catalog manifest: %+v", d)
	}
	if d := seccustom.DecideOrg(pol, managed, rec(other, x)); d.Run || d.Reason != "not_in_org_catalog" {
		t.Errorf("a manifest outside the catalog must be refused: %+v", d)
	}
	if d := seccustom.DecideOrg(pol, managed, rec(m, other)); d.Run {
		t.Errorf("a catalog manifest with another executable digest must be refused: %+v", d)
	}
	if miss := seccustom.RequiredMissing(pol, managed, nil); len(miss) != 1 {
		t.Errorf("require reports the missing manifest: %v", miss)
	}
	forbid := *pull
	forbid.CustomMode = "forbid"
	if d := seccustom.DecideOrg(customOrgPolicyFrom(&forbid, nil), managed, rec(m, x)); d.Run {
		t.Errorf("forbid: %+v", d)
	}
	catalogOnly := *pull
	catalogOnly.CustomMode = "catalog_only"
	if p := customOrgPolicyFrom(&catalogOnly, nil); p.Mode != seccustom.OrgModeCatalogOnly || seccustom.RequiredMissing(p, managed, nil) != nil {
		t.Errorf("catalog_only: %+v", p)
	}
	// An individual node takes no remote restriction.
	if d := seccustom.DecideOrg(pol, seccustom.OrgFacts{}, rec(other, x)); !d.Run || d.OrgApproved {
		t.Errorf("individual: %+v", d)
	}
	// A floor allow.custom_manifests narrows the catalog, fail closed, and
	// raises an unset mode to catalog_only.
	if p := customOrgPolicyFrom(pull, []string{"sha256:" + other}); len(p.Entries) != 0 {
		t.Errorf("a floor without the manifest must leave no entry: %+v", p)
	}
	if p := customOrgPolicyFrom(nil, []string{"sha256:" + m}); p.Mode != seccustom.OrgModeCatalogOnly || len(p.Entries) != 0 {
		t.Errorf("a floor with no pull: %+v", p)
	}
	if p := customOrgPolicyFrom(nil, nil); p.Mode != seccustom.OrgModeUnset {
		t.Errorf("nothing: %+v", p)
	}
}
