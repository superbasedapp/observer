package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/managedconfig"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodecomponents"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// components_governance.go is the cmd boundary of managed component
// governance (modular packaging P4, lane MP-GOV; plan 6.2, 6.2.1, 6.2.2).
// It reads what only I/O can (the enrolment, the stored grant re-verified
// under the pinned org key, the verified node.components policy and its last
// known good, the local ceiling from its fixed per-OS source) and hands the
// pure producers plain data: nodecomponents.Govern picks the policy in force
// and componentstate.ResolveGoverned applies it through the one resolver.
//
// Every process that resolves component state calls componentGovernanceFor:
// the daemon at start, the watcher and proxy builders, the CLI verbs and
// their gate, the dashboard service, doctor and hook auto-registration. A
// short-lived process therefore reaches the same answer as the daemon from
// the same signed inputs and never trusts a daemon-written effective set.

// componentGovernanceTimeout bounds the DB read: a busy database must never
// stall a CLI verb, and a read that does not finish resolves ungoverned
// (with the ceiling still applied), the fail-open posture every other
// component gate takes on an unreadable input.
const componentGovernanceTimeout = 3 * time.Second

// componentGovernanceInputs is everything resolveComponentGovernance reads,
// already loaded and verified.
type componentGovernanceInputs struct {
	// Enrolment is the stored enrolment, nil when not enrolled.
	Enrolment *store.Enrolment
	// Grant is the stored grant with its integrity verdict, nil when none.
	Grant *govern.Grant
	// Live is the live enrolment identity and key pin.
	Live govern.LiveIdentity
	// Now decides grant expiry.
	Now time.Time
	// Ceiling is the local ceiling loader's verdict.
	Ceiling managedconfig.Result
	// Policy and LastKnownGood are the verified node.components policies,
	// nil when none.
	Policy, LastKnownGood *nodecomponents.PolicySpec
	// Initial is the grant's signed initial_components set, nil when the
	// grant carries none.
	Initial []string
	// Granted are ids of verified, unexpired component_enable grants.
	Granted []string
}

// resolveComponentGovernance is the pure half of componentGovernanceFor.
func resolveComponentGovernance(in componentGovernanceInputs) componentstate.Governed {
	out := nodeComponentsOutcome(in)
	g := componentstate.Governed{Source: string(out.Source), Rule: out.Rule}
	return finishComponentGovernance(in, out, g)
}

// nodeComponentsOutcome runs nodecomponents.Govern over the loaded inputs.
// It is shared with the update rail (update_distro.go), which reads the
// policy in force for its distro (plan 5.6.1) from the same signed inputs,
// so the two can never disagree about which policy governs the node.
func nodeComponentsOutcome(in componentGovernanceInputs) nodecomponents.Outcome {
	ni := nodecomponents.Inputs{
		// Managed by enrolment or by its org's switch to enterprise (P-204).
		Managed:       in.Enrolment.IsManaged() || govern.GrantIsManaged(in.Grant),
		Current:       in.Policy,
		LastKnownGood: in.LastKnownGood,
		Initial:       in.Initial,
		Compiled:      components.Compiled(components.BinaryNode),
		Granted:       in.Granted,
	}
	ni.CeilingPinned, ni.Ceiling = in.Ceiling.Pinned()
	if in.Grant != nil {
		// The grant is live exactly when govern's identity rows let it
		// through: the integrity, expiry, identity and key-pin rows are the
		// same ones node.governance uses, so the two families can never
		// disagree about whether this enrolment governs the node.
		eff := govern.Resolve(govern.Delivered{}, in.Grant, in.Live, in.Now)
		ni.Live = eff.State == govern.StateNoPolicy
		for _, a := range govern.HonoredAuthority(in.Grant) {
			if a == nodecomponents.Authority {
				ni.Authorized = true
			}
		}
	}
	return nodecomponents.Govern(ni)
}

// finishComponentGovernance renders a governance outcome for the resolver.
func finishComponentGovernance(in componentGovernanceInputs, out nodecomponents.Outcome, g componentstate.Governed) componentstate.Governed {
	switch out.Source {
	case nodecomponents.SourceLocal, nodecomponents.SourceDormant:
	default:
		g.OrgManaged = true
		if in.Grant != nil {
			g.OrgName = in.Grant.OrgName
		}
		if g.OrgName == "" && in.Enrolment != nil {
			g.OrgName = in.Enrolment.OrgName
		}
	}
	if out.Governance.Policy != nil || out.Governance.CeilingPinned {
		gov := out.Governance
		g.Governance = &gov
	}
	g.Notes = ceilingNotes(in.Ceiling)
	if out.Spec != nil {
		for _, id := range out.Spec.IgnoredIDs {
			g.Notes = append(g.Notes, "the organization's component policy names "+id+", which this build does not know; ignored")
		}
	}
	return g
}

// ceilingNotes names a ceiling that is in force or failed a check.
func ceilingNotes(r managedconfig.Result) []string {
	switch r.Status {
	case managedconfig.StatusInvalidCoreOnly, managedconfig.StatusInvalidLastKnown:
		what := "only core runs"
		if r.Status == managedconfig.StatusInvalidLastKnown {
			what = "the last valid ceiling stays in force"
		}
		check := r.FailedCheck
		if r.Err != "" {
			check += ": " + r.Err
		}
		return []string{"the local component ceiling at " + r.Source + " failed a check (" + check + "); " + what + " and updates are refused until it is fixed"}
	}
	var out []string
	for _, n := range r.Notes {
		out = append(out, "local component ceiling: "+n)
	}
	return out
}

// componentGovernanceFor reads the governance inputs for a loaded config.
// It never creates the DB: a node with no database file is not enrolled.
func componentGovernanceFor(ctx context.Context, cfg config.Config) componentstate.Governed {
	g, _ := componentGovernanceWithOutcome(ctx, cfg)
	return g
}

// componentGovernanceWithOutcome is componentGovernanceFor plus the
// nodecomponents outcome it was rendered from (the policy in force and its
// on_remove), for the daemon's scheduled purge and live teardown pass
// (components_policy_follow.go, T-682).
func componentGovernanceWithOutcome(ctx context.Context, cfg config.Config) (componentstate.Governed, nodecomponents.Outcome) {
	ctx, cancel := context.WithTimeout(ctx, componentGovernanceTimeout)
	defer cancel()
	in := componentGovernanceInputs{Now: time.Now()}
	var notes []string
	st, closeDB := openComponentGovernanceStore(ctx, cfg.Observer.DBPath)
	if st != nil {
		defer closeDB()
		in.Ceiling = loadCeilingWithLastKnown(ctx, managedconfig.Load, st)
		notes = loadComponentGovernanceInputs(ctx, cfg, st, &in)
	} else {
		in.Ceiling = loadCeilingWithLastKnown(ctx, managedconfig.Load, nil)
	}
	out := nodeComponentsOutcome(in)
	g := finishComponentGovernance(in, out, componentstate.Governed{Source: string(out.Source), Rule: out.Rule})
	if g.OrgManaged {
		g.Notes = append(g.Notes, notes...)
	}
	return g, out
}

// ceilingStore is the update_state seam the ceiling's last-known set lives
// in (agent migration 160, store/update.go).
type ceilingStore interface {
	LoadCeilingLastKnown(ctx context.Context) (string, error)
	SaveCeilingLastKnown(ctx context.Context, js string) error
}

// loadCeilingWithLastKnown runs the local ceiling loader with the stored
// last-known explicit set and stores the set the loader asks to persist
// (T-682; plan 6.2.2, fourth-pass M1). Without it an invalid ceiling source
// fell to core only even on a node that had read a valid ceiling before;
// with it the last valid set stays in force until the source is fixed. A
// node with no database (st nil) has no last-known set, which is the
// loader's core-only row. A store error never widens: an unreadable
// last-known set is treated as none (core only on an invalid source).
func loadCeilingWithLastKnown(ctx context.Context, load func(*managedconfig.Ceiling) managedconfig.Result, st ceilingStore) managedconfig.Result {
	var lastKnown *managedconfig.Ceiling
	if st != nil {
		if js, err := st.LoadCeilingLastKnown(ctx); err == nil && strings.TrimSpace(js) != "" {
			var c managedconfig.Ceiling
			if json.Unmarshal([]byte(js), &c) == nil {
				lastKnown = &c
			}
		}
	}
	res := load(lastKnown)
	if res.Persist && res.Ceiling != nil && st != nil {
		if js, err := json.Marshal(res.Ceiling); err == nil {
			_ = st.SaveCeilingLastKnown(ctx, string(js))
		}
	}
	return res
}

// loadComponentGovernanceInputs fills the store-backed inputs. A read error
// leaves the inputs as an unenrolled node's (ungoverned, ceiling applied).
// It returns notes about a delivered component policy that is not applied.
func loadComponentGovernanceInputs(ctx context.Context, cfg config.Config, st *store.Store, in *componentGovernanceInputs) []string {
	enr, err := st.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return nil
	}
	loader := governanceIdentityLoader(st)
	grant, live, err := loader(ctx)
	if err != nil {
		return nil
	}
	in.Enrolment, in.Grant, in.Live = enr, grant, live
	if grant != nil {
		in.Initial = storedInitialComponents(ctx, st, grant.OrgKey)
	}
	// Verified, unexpired component_enable grants (the request rail, T-670).
	if granted, gerr := orgclient.ComponentGrants(ctx, st, in.Now); gerr == nil {
		in.Granted = granted
	}
	// The security managed pull's components (lane SEC-E), only while the
	// honoured grant holds enforce.security (security_managedpull.go).
	if grant != nil {
		if eff := govern.Resolve(govern.Delivered{}, grant, live, in.Now); eff.Managed && eff.GrantsSecurityEnforcement() {
			in.Granted = append(in.Granted, securityManagedGranted(ctx, cfg, st, orgclient.ManagedPullConsent{Managed: true, HoldsAuthority: true})...)
		}
	}
	var note string
	in.Policy, in.LastKnownGood, note = loadComponentPolicy(ctx, cfg, st, enr)
	if note != "" {
		return []string{note}
	}
	return nil
}

// storedInitialComponents returns the grant's signed initial component set
// (agent migration 159), nil when the grant carried none. The row's
// signature, which covers the set, is re-verified on the same identity
// refresh that produced the grant (governanceIdentityLoader), and an
// invalid grant never reaches the source table's initial-grant row: govern's
// integrity row makes it not live.
func storedInitialComponents(ctx context.Context, st *store.Store, orgKey string) []string {
	row, ok, err := st.LoadEnrolmentGrant(ctx, orgKey)
	if err != nil || !ok || row.InitialComponents == nil {
		return nil
	}
	ids := append([]string{}, row.InitialComponents.IDs...)
	return ids
}

// loadComponentPolicy reads the node.components policy this node accepted
// from the signature-verified on-disk cache (the same envelope the policy
// poller wrote and verifyCachedPolicyResource checks for every family: the
// pinned org key, the closed envelope, the member binding, the selectors and
// a lenient compile against this build's catalog). Short-lived processes
// therefore verify the signed policy themselves (plan 6.2.1) instead of
// trusting a daemon-written effective set.
//
// A verified envelope at the durable floor is the current policy; a
// verified envelope that is not at the floor (a newer delivery was refused,
// or the floor moved and the cache has not caught up) is the last known good
// one. Nothing verified means no policy, which leaves the grant's initial
// set or the pinned compiled set in force (never a fail-open window). A
// family the node has not accepted, or not preauthorized to enforce, applies
// nothing.
func loadComponentPolicy(ctx context.Context, cfg config.Config, st *store.Store, enr *store.Enrolment) (current, lkg *nodecomponents.PolicySpec, note string) {
	opts := policyResourceOptionsFor(cfg, nil)
	family := policyfam.FamilyNodeComponents
	if !containsString(family, opts.AcceptFamilies) {
		return nil, nil, ""
	}
	if !containsString(family, opts.PreauthorizeEnforce) {
		return nil, nil, "the organization's component policy is accepted but not preauthorized to apply ([org_client.policy].preauthorize_enforce lacks node.components); the pinned set stays in force"
	}
	orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	gen, ok, err := st.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil || !ok || gen.Tombstoned {
		return nil, nil, ""
	}
	path := filepath.Join(opts.CacheDir, orgKey, strconv.FormatInt(gen.Generation, 10), family+".json")
	if _, err := os.Stat(path); err != nil {
		return nil, nil, ""
	}
	cached, err := verifyCachedPolicyResource(ctx, st, enr.OrgServerURL, family, path, opts.NodeAttrs)
	if err != nil {
		return nil, nil, "the organization's cached component policy does not verify (" + err.Error() + "); the pinned set stays in force"
	}
	spec, ok := cached.spec.(nodecomponents.PolicySpec)
	if !ok {
		return nil, nil, ""
	}
	state, hasState, err := st.LoadPolicyResourceState(ctx, orgKey, family)
	if err == nil && hasState && state.Generation == gen.Generation &&
		cached.resource.Version == state.FloorVersion && cached.digest == state.MsgDigest {
		return &spec, nil, ""
	}
	return nil, &spec, ""
}

// openComponentGovernanceStore opens an existing node DB without running
// migrations (a read of a few rows from a short-lived process must never
// migrate the daemon's database). It returns nil when there is no file.
func openComponentGovernanceStore(ctx context.Context, path string) (*store.Store, func()) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	if fi, err := os.Stat(path); err != nil || fi.IsDir() {
		return nil, nil
	}
	database, err := db.OpenPlain(ctx, path)
	if err != nil {
		return nil, nil
	}
	return store.New(database), func() { _ = database.Close() }
}

// componentSnapshotForConfig resolves the component state of a loaded
// config, governed. Every caller that used componentstate.FromConfig on a
// node config uses this instead, so a managed node is never resolved from
// its local block alone (ledger MODPKG-7).
func componentSnapshotForConfig(cfg config.Config) componentstate.Snapshot {
	return componentstate.ResolveGoverned(cfg.Components, nil, componentGovernanceFor(context.Background(), cfg))
}
