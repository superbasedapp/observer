//go:build !sbo_omit_security

package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_managedpull.go is the node consumer of the security managed pull
// (GET /api/agent/security, authority enforce.security; security plan 4.9,
// lane SEC-E milestone 3). The fetch, verification and apply ladder are the
// kit's (orgclient.FetchManagedPull, LoadPersistedManagedPull); this file
// decodes the closed body (orgcontract.SecurityManagedPolicyV1) and applies
// it, only while the kit says it is IN FORCE (a managed node whose honoured
// grant holds enforce.security, with an unexpired document):
//
//   - components and drivers are switched on through the component
//     resolver's verified-grant input (securityManagedGranted, read by
//     components_governance.go in every process), never by rewriting
//     config.toml;
//   - online_checks "on" applies only once the one-time disclosure (plan
//     8.3) was shown on this node (securityManagedOverlay, inside the read
//     seam securityFloorsApplied);
//   - every other key is reported with what it does here
//     (securityManagedKeyLines), not_built where no setting exists yet.
//
// Nothing here polls: the shared poll step (lane SBX-P1C,
// managedpull_wire.go) calls applySecurityManagedPull with each outcome, and
// only on a node whose security module is active (the consumer below), and
// it makes a request only for a managed node whose grant holds
// enforce.security (its consent table). At start the node also reads what
// is already stored (LoadPersistedManagedPull). Pulled components take
// effect at the next process start.

// securityManagedRail is the kit rail name.
const securityManagedRail = "security"

// securityManagedModule is the component the consumer runs under.
const securityManagedModule = "security"

func init() {
	registerManagedPullConsumer(managedPullConsumer{
		rail:   securityManagedRail,
		active: func(s componentstate.Snapshot) bool { return s.ModuleActive(securityManagedModule) },
		sink:   func(o orgclient.ManagedPullOutcome) { applySecurityManagedPull(o) },
	})
}

// securityManagedState is the pull as last applied in this process.
type securityManagedState struct {
	Outcome orgclient.ManagedPullOutcome
	// Policy is the decoded body while the outcome is in force and the body
	// decodes; nil otherwise.
	Policy *orgcontract.SecurityManagedPolicyV1
	// Refused is why an in-force body was refused by this build's decoder.
	Refused string
}

var secManaged struct {
	mu  sync.Mutex
	cur securityManagedState
}

// securityDisclosureShown reports whether the online-check disclosure was
// shown on this node (the deps child's record). It answers false in a build
// without the deps child (security_managedpull_deps.go binds it), so the
// pull never switches the online check on there.
var securityDisclosureShown = func(configPath string) bool { return false }

// decideSecurityManagedPull is the pure half of the consumer: what one
// outcome means for this node.
func decideSecurityManagedPull(o orgclient.ManagedPullOutcome) securityManagedState {
	st := securityManagedState{Outcome: o}
	if !o.InForce {
		return st
	}
	p, ok, err := orgcontract.DecodeSecurityManagedPolicy(o.Body)
	switch {
	case err != nil:
		st.Refused = err.Error()
	case ok:
		st.Policy = &p
	}
	return st
}

// applySecurityManagedPull records one managed-pull outcome as this
// process's state. It is the sink the shared poll step calls.
func applySecurityManagedPull(o orgclient.ManagedPullOutcome) securityManagedState {
	st := decideSecurityManagedPull(o)
	secManaged.mu.Lock()
	secManaged.cur = st
	secManaged.mu.Unlock()
	// Followers of the applied state (lane LEFT-SHARED: the org's baseline
	// approvals and its dedupe key, security_baseline_org.go and
	// security_orgkey.go).
	for _, f := range securityManagedFollowers {
		f(st)
	}
	return st
}

// securityManagedFollowers run after every applied outcome, in order.
var securityManagedFollowers []func(securityManagedState)

func securityManagedCurrent() securityManagedState {
	secManaged.mu.Lock()
	defer secManaged.mu.Unlock()
	return secManaged.cur
}

// securityManagedOverlay applies the in-force pull's settings to sc (the
// first step of securityFloorsApplied; the floors apply after it, so the
// org's privacy floor allow.online_checks = forbidden wins over the pull).
func securityManagedOverlay(sc config.SecurityConfig, disclosureShown bool) config.SecurityConfig {
	p := securityManagedCurrent().Policy
	if p == nil {
		return sc
	}
	switch {
	case p.OnlineChecks == "on" && disclosureShown:
		sc.Deps.Online = true
	case p.OnlineChecks == "off":
		sc.Deps.Online = false
	}
	return sc
}

// securityManagedComponents are the component ids an in-force body switches
// on: its components plus each driver's component.
func securityManagedComponents(p *orgcontract.SecurityManagedPolicyV1) []string {
	if p == nil {
		return nil
	}
	set := map[string]bool{}
	for _, c := range p.Components {
		set[c] = true
	}
	// Each driver's owning component, from the family's driver table: a
	// driver no catalog component owns (actionlint today) switches none on.
	for _, d := range p.Drivers {
		if dr, ok := securityscanning.LookupDriver(d); ok && dr.Component != "" {
			set[dr.Component] = true
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// securityManagedConsent resolves the kit's consent from the honoured grant.
func securityManagedConsent(ctx context.Context, st *store.Store, now time.Time) orgclient.ManagedPullConsent {
	loader := governanceIdentityLoader(st)
	if loader == nil {
		return orgclient.ManagedPullConsent{}
	}
	grant, live, err := loader(ctx)
	if err != nil || grant == nil {
		return orgclient.ManagedPullConsent{}
	}
	eff := govern.Resolve(govern.Delivered{}, grant, live, now)
	return orgclient.ManagedPullConsent{Managed: securityManagedFrom(eff), HoldsAuthority: eff.GrantsSecurityEnforcement()}
}

// securityManagedPersisted reads the stored pull (no request) re-verified
// against the pinned key, the way a short-lived process sees it.
func securityManagedPersisted(ctx context.Context, cfg config.Config, st *store.Store, consent orgclient.ManagedPullConsent) (securityManagedState, error) {
	if st == nil {
		return securityManagedState{}, nil
	}
	c := orgclient.New(cfg.OrgClient, st, nil, "", nil, nil)
	o, err := c.LoadPersistedManagedPull(ctx, securityManagedRail, consent)
	if err != nil {
		return securityManagedState{Outcome: o}, err
	}
	return decideSecurityManagedPull(o), nil
}

// securityManagedGranted is the component resolver's input from the pull:
// the ids an in-force, decodable stored body switches on. Read in every
// process (components_governance.go) from the verified store.
func securityManagedGranted(ctx context.Context, cfg config.Config, st *store.Store, consent orgclient.ManagedPullConsent) []string {
	s, err := securityManagedPersisted(ctx, cfg, st, consent)
	if err != nil {
		return nil
	}
	return securityManagedComponents(s.Policy)
}

// loadSecurityManagedAtStart applies the stored pull to the daemon's state
// once at start (no request: the shared poll step fetches).
func loadSecurityManagedAtStart(ctx context.Context, cfg config.Config, st *store.Store) {
	if s, err := securityManagedPersisted(ctx, cfg, st, securityManagedConsent(ctx, st, time.Now())); err == nil {
		applySecurityManagedPull(s.Outcome)
	}
}

// securityManagedOnlineState is what the pull's online_checks = on does on
// a managed node once the disclosure was shown (SEC-E4 merge finding 8):
// the install gate's checks and, since lane SEC-H2, the dependency scanners'
// online matching both go to the org relay only.
const securityManagedOnlineState = "applied to the install gate and the dependency scanners' online matching, both sent to the org relay only, never to a public host (online_unknown, or unmatched, while the org server has no relay configured)"

// securityManagedKeyLines reports each key of an in-force body with what it
// does on this node.
func securityManagedKeyLines(p *orgcontract.SecurityManagedPolicyV1, disclosureShown bool, active func(id string) bool) []string {
	if p == nil {
		return nil
	}
	var out []string
	add := func(key, v, state string) { out = append(out, fmt.Sprintf("  %s = %s: %s", key, v, state)) }
	for _, id := range securityManagedComponents(p) {
		if active(id) {
			add("components", id, "applied (switched on through the component resolver)")
		} else {
			add("components", id, "not_applicable: component_absent (not in this build, or blocked by the local ceiling or the component policy)")
		}
	}
	// A managed node takes its scanner databases and its package index only
	// from the org mirror and sends its online checks only to the org relay
	// (lane SEC-E4): both answer "not supported" until the org server's
	// relay is configured, which the node then reads as online_unknown and
	// "not scanned", never as clean.
	rows := []struct{ key, v, state string }{
		{"scanner_source", p.ScannerSource, "applied (the package index and the OSV exports are fetched from the org mirror only)"},
		{"scan_schedule", p.ScanSchedule, "not_applicable: not_built"},
		// The org wire (lane SEC-E2, security_orgpush.go): finding_share
		// sets the level this managed node pushes at, and org_dedupe_key lets
		// its finding rows carry org_key (none is computed by a detector yet,
		// so the org dedupes on project, rule and evidence hash meanwhile).
		{"org_dedupe_key", p.OrgDedupeKey, securityDedupeKeyState(p)},
		{"finding_share", p.FindingShare, "applied (the level this node pushes security rows at; " + p.FindingShare + ")"},
		{"feedback", p.Feedback, "not_applicable: not_built"},
		{"ai_change_record", p.AIChangeRecord, "not_applicable: not_built"},
	}
	switch {
	case p.OnlineChecks == "on" && !disclosureShown:
		rows = append(rows, struct{ key, v, state string }{"online_checks", "on", "not_applicable: disclosure_not_shown (the one-time disclosure has not been shown on this node)"})
	case p.OnlineChecks == "on":
		rows = append(rows, struct{ key, v, state string }{"online_checks", "on", securityManagedOnlineState})
	case p.OnlineChecks != "":
		rows = append(rows, struct{ key, v, state string }{"online_checks", p.OnlineChecks, "applied (online checks stay off)"})
	}
	if len(p.CustomManifests) > 0 {
		// The custom driver policy applies them (security_custom_org.go,
		// lane SEC-E4): only catalog entries the org approved under four
		// eyes run, and only with the pinned executable already present.
		rows = append(rows, struct{ key, v, state string }{
			"custom_manifests", fmt.Sprintf("%d digests, %d approved in the org catalog", len(p.CustomManifests), len(p.CustomCatalog)),
			"applied (a manifest not in the catalog is refused: not_in_org_catalog)",
		})
	}
	if p.OrgDedupe != nil {
		// The served org dedupe key (lane LEFT-SHARED, security_orgkey.go).
		rows = append(rows, struct{ key, v, state string }{"org_dedupe", "version " + strconv.FormatInt(p.OrgDedupe.Version, 10), securityOrgDedupeState(p)})
	}
	if len(p.ApprovedBaselines) > 0 {
		// The org's baseline approvals (security_baseline_org.go).
		rows = append(rows, struct{ key, v, state string }{"approved_baselines", strconv.Itoa(len(p.ApprovedBaselines)), "applied (a label on the matching baselines, \"approved by the org\"; no verdict changes)"})
	}
	if p.CustomMode != "" {
		rows = append(rows, struct{ key, v, state string }{"custom_mode", p.CustomMode, "applied (custom scanners on this node)"})
	}
	if p.Defaults != nil {
		rows = append(rows, struct{ key, v, state string }{"defaults", "set", "not_applicable: not_built (managed defaults of the local settings are shown, not yet applied)"})
	}
	for _, r := range rows {
		if r.v != "" {
			add(r.key, r.v, r.state)
		}
	}
	return out
}

// securityManagedStatusLines are the status lines for the pull, then the
// org sharing line (security_orgpush.go).
func securityManagedStatusLines(ctx context.Context, configPath string, cfg config.Config, st *store.Store) []string {
	consent := securityManagedConsent(ctx, st, time.Now())
	lines, pull := securityManagedPullLines(ctx, configPath, cfg, st, consent)
	return append(lines, securityShareLevelLine(consent.Managed, pull, cfg))
}

// securityManagedPullLines are the pull's own status lines and the body in
// force (nil when none).
func securityManagedPullLines(ctx context.Context, configPath string, cfg config.Config, st *store.Store, consent orgclient.ManagedPullConsent) ([]string, *orgcontract.SecurityManagedPolicyV1) {
	s, err := securityManagedPersisted(ctx, cfg, st, consent)
	o := s.Outcome
	switch {
	case err != nil:
		return []string{"Managed pull (enforce.security): none (" + o.State + ")"}, nil
	case o.Version == 0:
		return []string{"Managed pull (enforce.security): none stored"}, nil
	case !o.InForce:
		return []string{fmt.Sprintf("Managed pull (enforce.security): version %d verified but inert (%s)", o.Version, o.Reason)}, nil
	case s.Refused != "":
		return []string{fmt.Sprintf("Managed pull (enforce.security): version %d refused by this build: %s", o.Version, s.Refused)}, nil
	case s.Policy == nil:
		return []string{fmt.Sprintf("Managed pull (enforce.security): version %d in force, empty", o.Version)}, nil
	}
	lines := []string{fmt.Sprintf("Managed pull (enforce.security): version %d in force", o.Version)}
	snap := componentSnapshotForConfig(cfg)
	return append(lines, securityManagedKeyLines(s.Policy, securityDisclosureShown(configPath), snap.ModuleActive)...), s.Policy
}

// securityDedupeKeyState is the org_dedupe_key row: the authored name of the
// org's key. The key itself arrives as the served org_dedupe field (lane
// LEFT-SHARED), and finding rows carry org_key only at the findings level.
func securityDedupeKeyState(p *orgcontract.SecurityManagedPolicyV1) string {
	if p.FindingShare != orgcontract.SecurityShareFindings {
		return "not_applicable: finding_share is not findings (no finding rows ship, so no org_key)"
	}
	if p.OrgDedupe == nil {
		return "applied (a name only: the org server has not served its key, so finding rows carry no org_key and the org dedupes on project, rule and evidence hash)"
	}
	return "applied (secret findings carry org_key under the served key, version " + strconv.FormatInt(p.OrgDedupe.Version, 10) + ")"
}
