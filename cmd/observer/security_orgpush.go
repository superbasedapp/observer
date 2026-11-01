//go:build !sbo_omit_security

package main

import (
	"context"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_orgpush.go binds the security pillar's org wire (security plan
// 7.4, lane SEC-E2): the store's SecurityOrgProviders seam, only while the
// `security` module is active (nil otherwise, so the push is byte-identical
// to a node without the module). The rows are read by
// internal/store/secorgrows.go; this file adds what only the daemon knows:
//
//   - the share level: an INDIVIDUAL node follows its own
//     [org_client.share].security (default off, never remote, Q7); a MANAGED
//     node follows the finding_share of its in-force enforce.security pull,
//     posture by default (store.ResolveSecurityShare is the table);
//   - org_key ships only when the in-force pull carries the org dedupe key;
//   - the posture's detectors, online-check state and floor keys (the E1
//     evaluation, as closed enums).
//
// With sbo_omit_security, security_orgpush_omit.go binds nothing.

// bindSecurityOrgProviders binds (active) or unbinds the security wire seam
// on the daemon's org-push store. The daemon calls it wherever it runs the
// push loop (cmd/observer/start.go, right after the org bundle is built), so
// a headless daemon (--no-dashboard, or the dashboard component inactive)
// sends its rows too (lane SEC-E2 audit finding 3).
func bindSecurityOrgProviders(st *store.Store, active bool) {
	if st == nil {
		return
	}
	if !active {
		st.SetSecurityOrgProviders(store.SecurityOrgProviders{})
		return
	}
	st.SetSecurityOrgProviders(store.SecurityOrgProviders{
		Level: func(_ context.Context, share store.ShareOptions) store.SecurityShare {
			base, _ := secScanning.baseNow()
			return securityShareFor(base.Managed, securityManagedCurrent().Policy, share.Security)
		},
		Posture: func(ctx context.Context, day string, scope store.SecurityScope) (orgcontract.SecurityPostureRow, bool, error) {
			row, err := st.SecurityPostureFacts(ctx, day, time.Now().UTC(), scope)
			if err != nil {
				return row, false, err
			}
			securityPostureNodeFacts(&row, secScanning.facts(), securityOnlineChecksOn())
			// Lane SEC-H2: database ages and platform gaps
			// (security_posture_facts.go), only from a base config that
			// loaded (SEC-H2 merge, audit finding 4).
			if base, ok := secScanning.baseNow(); ok {
				securityPostureDaemonFacts(&row, secScanning.facts(), base.ConfigPath, time.Now().UTC())
			}
			return row, true, nil
		},
		// The stored, version-tagged org_key ships as the bare digest only
		// while the node holds that key version (lane LEFT-SHARED).
		Findings: securityFindingsWithOrgKey(st.SelectSecurityFindingRows, securityHeldDedupeVersion),
		// AI change records (lane sec-f2a): rows only while the
		// security.provenance loop runs (security_provenance.go).
		ChangeRecords:     provenanceChangeRecords(st),
		ChangeRecordsLive: func() bool { return provenanceRT.Load() != nil },
	})
}

// securityShareFor resolves the share for the node's tenancy, its in-force
// pull (nil when none) and its own key.
func securityShareFor(managed bool, pull *orgcontract.SecurityManagedPolicyV1, local string) store.SecurityShare {
	f := store.ResolveSecurityShareFacts{Managed: managed, LocalLevel: local}
	if pull != nil {
		// The node holds the org dedupe key when the pull served it (lane
		// LEFT-SHARED); an org_dedupe_key name alone carries no key.
		f.PullLevel, f.PullOrgKey = pull.FindingShare, pull.OrgDedupe != nil
	}
	return store.ResolveSecurityShare(f)
}

// securityOnlineChecksOn is the online package check state in force: the
// node's own setting with the managed pull and the floors applied, and only
// while the package checks child runs.
func securityOnlineChecksOn() bool {
	base, _ := secScanning.baseNow()
	if !secScanning.facts().Active["security.deps"] {
		return false
	}
	return securityFloorsApplied(base.Security).Deps.Online
}

// securityPostureNodeFacts adds the daemon's facts to a posture row: the
// active security components, the online-check state and every in-force
// floor key with what it does here.
func securityPostureNodeFacts(row *orgcontract.SecurityPostureRow, facts securityscanning.NodeFacts, online bool) {
	if !facts.ModuleOff {
		row.Detectors = append(row.Detectors, securityManagedModule)
	}
	for id, on := range facts.Active {
		if on && !facts.ModuleOff {
			row.Detectors = append(row.Detectors, id)
		}
	}
	sort.Strings(row.Detectors)
	row.OnlineChecks = "off"
	if online {
		row.OnlineChecks = "on"
	}
	if facts.Held == nil {
		return
	}
	for _, k := range securityscanning.Evaluate(*facts.Held, facts) {
		k = securityKeyStateOnNode(k, facts)
		row.FloorKeys = append(row.FloorKeys, orgcontract.SecurityFloorKeyState{Key: k.Key, State: k.State, Reason: k.Reason})
	}
}

// securityShareLevelLine is the `observer security status` line for the
// share level, so a developer sees what reaches the org.
func securityShareLevelLine(managed bool, pull *orgcontract.SecurityManagedPolicyV1, cfg config.Config) string {
	sh := securityShareFor(managed, pull, cfg.OrgClient.Share.Security)
	from := "[org_client.share].security"
	if managed {
		from = "the managed pull (enforce.security), posture by default"
	}
	line := "Org sharing: " + sh.Level + " (from " + from + ")"
	if sh.HoldsOrgKey {
		line += ", org dedupe key held"
	}
	return line
}
