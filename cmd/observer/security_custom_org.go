//go:build !sbo_omit_security && !sbo_omit_security_scan_custom

package main

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/seccustom"
	"github.com/marmutapp/superbased-observer/internal/seccustomsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_custom_org.go applies the org's custom driver policy on a
// managed node (security plan 8.6 "Org control", lane SEC-E4): the node half
// seccustom.OrgPolicy (catalog_only, require, forbid; entries pinned by
// manifest and executable digest) is built from the security managed pull
// in force (custom_mode, and custom_catalog: the server's four-eyes catalog
// entries for the manifests the body names) and from the floor
// allow.custom_manifests (security_scanning_wire.go). An individual node,
// or a managed node whose grant does not hold enforce.security, gets no
// remote raise or restriction: the decision table's first row.

// customOrgModeFor is the pull's custom mode: as authored, or require when
// the body names manifests without a mode (naming a manifest switches it
// on, so it must be present).
func customOrgModeFor(p *orgcontract.SecurityManagedPolicyV1) seccustom.OrgMode {
	switch {
	case p == nil:
		return seccustom.OrgModeUnset
	case p.CustomMode != "":
		return seccustom.OrgMode(p.CustomMode)
	case len(p.CustomManifests) > 0:
		return seccustom.OrgModeRequire
	}
	return seccustom.OrgModeUnset
}

// customOrgPolicyFrom is the pure half: the pull's policy and the floor's
// allow-set (nil: no floor) to the node's OrgPolicy. Digests on the wire are
// "sha256:<hex>"; the node's records keep bare hex. A floor raises an unset
// mode to catalog_only and keeps only the catalog entries it allows.
func customOrgPolicyFrom(p *orgcontract.SecurityManagedPolicyV1, allowed []string) seccustom.OrgPolicy {
	pol := seccustom.OrgPolicy{Mode: customOrgModeFor(p)}
	if p != nil {
		for _, e := range p.CustomCatalog {
			oe := seccustom.OrgEntry{
				ManifestSHA256:   strings.TrimPrefix(e.ManifestSHA256, "sha256:"),
				ExecutableSHA256: strings.TrimPrefix(e.ExecutableSHA256, "sha256:"),
			}
			for _, r := range e.BlockingRules {
				oe.BlockingRules = append(oe.BlockingRules, seccustom.OrgBlockingRule{RuleID: r.RuleID, Precision: r.Precision})
			}
			pol.Entries = append(pol.Entries, oe)
		}
	}
	if allowed != nil {
		if pol.Mode == seccustom.OrgModeUnset {
			pol.Mode = seccustom.OrgModeCatalogOnly
		}
		kept := pol.Entries[:0]
		for _, e := range pol.Entries {
			if slices.Contains(allowed, "sha256:"+e.ManifestSHA256) {
				kept = append(kept, e)
			}
		}
		pol.Entries = kept
	}
	return pol
}

// customOrgSource is the service's OrgSource: read per call from the
// verified store, so a process (the dashboard, the CLI, the scheduled loop)
// sees the pull in force now. ok is "managed with enforce.security".
func customOrgSource(cfg config.Config, st *store.Store) seccustomsvc.OrgSource {
	return func(ctx context.Context) (seccustom.OrgPolicy, bool) {
		if st == nil {
			return seccustom.OrgPolicy{}, false
		}
		consent := securityManagedConsent(ctx, st, time.Now())
		if !consent.Managed || !consent.HoldsAuthority {
			return seccustom.OrgPolicy{}, false
		}
		var p *orgcontract.SecurityManagedPolicyV1
		if s, err := securityManagedPersisted(ctx, cfg, st, consent); err == nil {
			p = s.Policy
		}
		return customOrgPolicyFrom(p, securityCustomManifestsAllowed(cfg.Security)), true
	}
}
