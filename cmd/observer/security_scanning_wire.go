//go:build !sbo_omit_security

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/postureop"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_scanning_wire.go is the node side of the security.scanning floors
// (security plan 4.9 and 7.3, lane SEC-E milestone 2). It owns:
//
//   - the one NodeFacts provider the family's pure evaluator reads
//     (securityscanning.SetNodeFactsProvider), bound at daemon start: the
//     node's managed tenancy, the active security children and the node's
//     own value on every axis that has a built setting;
//   - the floor in force (secScanning.held), set by the policy-resource
//     install seam (publishPolicyResourceResult) and cleared by it;
//   - THE read seam securityFloorsApplied: a consumer that reads a
//     [security] setting a floor can raise reads it through this function,
//     which walks securityFloorRows (key to setting, as data) over the floor
//     in force;
//   - the node-security policy-state reader and `observer security status`
//     lines;
//   - the PROJECT-AWARE read seam securityFloorsAppliedAt (lane sec-p3,
//     security plan 7.11): the org-wide floor first, then every matched
//     project's security.scanning section merged raise-only over it, for a
//     consumer that knows its project root (securityProjectView). The
//     sections ride the per-project guard envelopes and are read through the
//     guard's own project reader (guard.OrgProjectFamilies), so a directory
//     matches exactly as the guard's project layer does (a linked worktree
//     by its main repository, P-041).
//
// Opt-in, with no component and no securityOptIn entry of its own: the
// compiler links wherever `security` is compiled and nothing changes until
// an admin publishes a body AND the node lists security.scanning in both
// [org_client.policy] lists (a managed enrolment's backfill writes them).

// securityFloorRow binds one posture axis to the [security] setting it
// raises. Read gives the node's own value on the axis; Write stores the
// effective value back. An axis with no row has no setting built yet, so a
// floor on it is reported not_applicable: not_built.
type securityFloorRow struct {
	Axis  string
	Read  func(config.SecurityConfig) postureop.Value
	Write func(*config.SecurityConfig, postureop.Value)
}

// securityFloorRows is the key-to-setting table.
var securityFloorRows = []securityFloorRow{
	{
		Axis:  securityscanning.AxisFindingRetention,
		Read:  func(c config.SecurityConfig) postureop.Value { return postureop.Value{N: int64(c.Retention.Days)} },
		Write: func(c *config.SecurityConfig, v postureop.Value) { c.Retention.Days = int(v.N) },
	},
	{
		// require.online_checks = required (managed only): the online
		// package checks on. The disclosure and the relay-only routing of a
		// managed node stay with the online lane itself.
		Axis: securityscanning.AxisOnlineChecks,
		Read: func(c config.SecurityConfig) postureop.Value {
			return postureop.Value{S: map[bool]string{true: "required", false: "leave"}[c.Deps.Online]}
		},
		Write: func(c *config.SecurityConfig, v postureop.Value) { c.Deps.Online = v.S == "required" },
	},
	{
		// allow.online_checks = forbidden: the org's privacy floor.
		Axis: securityscanning.AxisAllowOnlineChecks,
		Read: func(c config.SecurityConfig) postureop.Value {
			return postureop.Value{S: map[bool]string{true: "allowed", false: "forbidden"}[c.Deps.Online]}
		},
		Write: func(c *config.SecurityConfig, v postureop.Value) { c.Deps.Online = v.S == "allowed" },
	},
	// The deps and custom rows (lane SEC-E4). Each writes a field that is
	// not a user setting (toml:"-"): only a floor sets it, and the readers
	// (the index and OSV export loads, the database download gate, the
	// custom driver policy) read it through this seam.
	{
		// require.max_advisory_db_age_h: the oldest advisory data still used
		// (the package index, the OSV exports); 0 locally means each
		// content kind's own age floor, which any floor tightens.
		Axis: securityscanning.AxisMaxAdvisoryDBAge,
		Read: func(c config.SecurityConfig) postureop.Value {
			return postureop.Value{N: int64(c.Deps.MaxAdvisoryDBAgeH)}
		},
		Write: func(c *config.SecurityConfig, v postureop.Value) { c.Deps.MaxAdvisoryDBAgeH = int(v.N) },
	},
	{
		// allow.scanner_sources: where advisory databases may come from;
		// locally every source is allowed, a floor narrows the set.
		Axis: securityscanning.AxisAllowScannerSources,
		Read: func(c config.SecurityConfig) postureop.Value {
			if c.Deps.ScannerSources == nil {
				return postureop.Value{Set: append([]string(nil), securityscanning.ScannerSources...)}
			}
			return postureop.Value{Set: c.Deps.ScannerSources}
		},
		Write: func(c *config.SecurityConfig, v postureop.Value) { c.Deps.ScannerSources = v.Set },
	},
	{
		// allow.custom_manifests (managed only): the custom driver
		// manifests a managed node may run. The node's own value has no
		// set (the accepted records live in their own store), so the merge
		// never narrows here; the floor is applied, fail closed, by the
		// custom driver policy (securityCustomManifestsAllowed reads the
		// floor's set itself: an empty overlap allows nothing).
		Axis:  securityscanning.AxisAllowCustomManifests,
		Read:  func(config.SecurityConfig) postureop.Value { return postureop.Value{} },
		Write: func(*config.SecurityConfig, postureop.Value) {},
	},
	// Lane SEC-P4 decision 9: the commit gate and pre-launch trust floors.
	// Both write floor-only fields (toml:"-"); the node's own value is the
	// weakest of the axis (the node's own commit gate, the guard mode's
	// trust step), so only a floor changes them. The daemon signs both into
	// each project's posture (securityPostureFloors), read per project.
	{
		// require.commit_gate (managed only): "quick_scan" makes S-791 to
		// S-794 take the decision table's managed-floor cells.
		Axis: securityscanning.AxisCommitGate,
		Read: func(c config.SecurityConfig) postureop.Value {
			if c.CommitGateFloor == "" {
				return postureop.Value{S: securityscanning.CommitGateValues[0]}
			}
			return postureop.Value{S: c.CommitGateFloor}
		},
		Write: func(c *config.SecurityConfig, v postureop.Value) { c.CommitGateFloor = v.S },
	},
	{
		// require.prelaunch_trust: the least step a launch's trust verdict
		// takes (warn, ask, refuse).
		Axis: securityscanning.AxisPrelaunchTrust,
		Read: func(c config.SecurityConfig) postureop.Value {
			if c.PrelaunchTrustFloor == "" {
				return postureop.Value{S: securityscanning.PrelaunchTrustValues[0]}
			}
			return postureop.Value{S: c.PrelaunchTrustFloor}
		},
		Write: func(c *config.SecurityConfig, v postureop.Value) { c.PrelaunchTrustFloor = v.S },
	},
	// Lane LEFT-SEC milestone 1: the axes that had no node setting. Each
	// reads and writes a [security.scanning] or [security.deps] key whose
	// default is the built-in behaviour it replaced, so a node with no
	// floor and no key behaves as before (security_scanning_settings.go).
	{
		// require.quick_scan_budget_s: seconds, longer is stronger.
		Axis: securityscanning.AxisQuickScanBudget,
		Read: func(c config.SecurityConfig) postureop.Value {
			return postureop.Value{N: int64(c.Scanning.QuickScanBudgetS)}
		},
		Write: func(c *config.SecurityConfig, v postureop.Value) { c.Scanning.QuickScanBudgetS = int(v.N) },
	},
	{
		// require.max_scan_staleness_min: minutes, shorter is stronger, 0 off.
		Axis: securityscanning.AxisMaxScanStaleness,
		Read: func(c config.SecurityConfig) postureop.Value {
			return postureop.Value{N: int64(c.Scanning.MaxScanStalenessMin)}
		},
		Write: func(c *config.SecurityConfig, v postureop.Value) { c.Scanning.MaxScanStalenessMin = int(v.N) },
	},
	{
		// require.min_blocking_severity: lower is stronger.
		Axis: securityscanning.AxisMinBlockingSeverity,
		Read: func(c config.SecurityConfig) postureop.Value {
			return postureop.Value{S: c.Scanning.MinBlockingSeverity}
		},
		Write: func(c *config.SecurityConfig, v postureop.Value) { c.Scanning.MinBlockingSeverity = v.S },
	},
	{
		// require.history_scan_on_enrol: false < true.
		Axis: securityscanning.AxisHistoryScanOnEnrol,
		Read: func(c config.SecurityConfig) postureop.Value {
			return postureop.Value{S: strconv.FormatBool(c.Scanning.HistoryScanOnEnrol)}
		},
		Write: func(c *config.SecurityConfig, v postureop.Value) { c.Scanning.HistoryScanOnEnrol = v.S == "true" },
	},
	{
		// require.install_unknown (S-744): flag < ask on the axis; the node's
		// own "deny" is stronger than every floor value, so it reads as the
		// axis maximum and no floor ever writes over it.
		Axis: securityscanning.AxisInstallUnknown,
		Read: func(c config.SecurityConfig) postureop.Value {
			return postureop.Value{S: depsActionAxis(c.Deps.UnknownAction, false)}
		},
		Write: func(c *config.SecurityConfig, v postureop.Value) { c.Deps.UnknownAction = depsActionFromAxis(v.S) },
	},
	{
		// require.install_online_unknown (S-748, managed only): flag < ask <
		// deny.
		Axis: securityscanning.AxisInstallOnlineUnknown,
		Read: func(c config.SecurityConfig) postureop.Value {
			return postureop.Value{S: depsActionAxis(c.Deps.OnlineUnknownAction, true)}
		},
		Write: func(c *config.SecurityConfig, v postureop.Value) {
			c.Deps.OnlineUnknownAction = depsActionFromAxis(v.S)
		},
	},
}

// securityCustomManifestsAllowed is the floor allow.custom_manifests in
// force on a managed node ("sha256:<hex>" digests), nil when no such floor
// applies: no floor, not in effect, the module off, or not managed. It reads
// the floor's own set, so a floor naming no manifest the node has allows
// nothing (fail closed), unlike the generic merge.
func securityCustomManifestsAllowed(config.SecurityConfig) []string {
	secScanning.mu.Lock()
	off := secScanning.moduleOff
	secScanning.mu.Unlock()
	if off {
		return nil
	}
	if base, _ := secScanning.baseNow(); !base.Managed {
		return nil
	}
	h := secScanning.heldCopy()
	if h == nil || !h.InEffect || h.Spec.Body.Allow == nil || h.Spec.Body.Allow.CustomManifests == nil {
		return nil
	}
	return append([]string{}, h.Spec.Body.Allow.CustomManifests...)
}

// securityScanningCachedHeld reads the floor accepted on this node from the
// verified policy-resource cache (a CLI process has no daemon memory); nil
// when none. A test swaps it.
var securityScanningCachedHeld = func(ctx context.Context, cfg config.Config, st *store.Store) *securityScanningHeld {
	if st == nil || !policyfam.IsFamilyLinked(policyfam.FamilySecurityScanning) {
		return nil
	}
	enr, err := st.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return nil
	}
	orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	gen, ok, err := st.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil || !ok || gen.Tombstoned {
		return nil
	}
	path := filepath.Join(policyResourceCacheDir(cfg), orgKey, strconv.FormatInt(gen.Generation, 10), policyfam.FamilySecurityScanning+".json")
	cached, err := verifyCachedPolicyResource(ctx, st, enr.OrgServerURL, policyfam.FamilySecurityScanning, path, policyResourceNodeAttrs(cfg))
	if err != nil {
		return nil
	}
	spec, ok := cached.spec.(securityscanning.PolicySpec)
	if !ok {
		return nil
	}
	accepted := slices.Contains(cfg.OrgClient.Policy.AcceptedFamilies(), policyfam.FamilySecurityScanning)
	inEffect := accepted && slices.Contains(cfg.OrgClient.Policy.PreauthorizedFamilies(), policyfam.FamilySecurityScanning)
	return &securityScanningHeld{Spec: spec, Version: cached.resource.Version, InEffect: inEffect}
}

// bindSecurityFloorsForCLI makes securityFloorsApplied (and with it
// depsInForce) read the floors and the managed pull in force in a process
// that is not the daemon: `observer security deps status`, `observer
// doctor`, the custom driver commands (decision log P-051, SECP-10's
// residual). It binds once per process and never over a daemon's own
// binding.
func bindSecurityFloorsForCLI(ctx context.Context, configPath string, cfg config.Config, st *store.Store) {
	secScanning.mu.Lock()
	bound := secScanning.load != nil
	secScanning.mu.Unlock()
	if bound {
		return
	}
	bindSecurityScanning(configPath, componentSnapshotForConfig(cfg))
	if h := securityScanningCachedHeld(ctx, cfg, st); h != nil {
		secScanning.mu.Lock()
		secScanning.held = h
		secScanning.mu.Unlock()
	}
	loadSecurityManagedAtStart(ctx, cfg, st)
}

// securityFloorNotBuilt is why each floor key with no row in
// securityFloorRows stays not_built: no [security] setting on the node holds
// the axis, so the family reports the key not_applicable: not_built and this
// reason is shown beside it in status. A key moves to securityFloorRows, and
// out of this table, in the lane that builds its setting. Lane LEFT-SEC
// built the last six (the quick scan budget, the scan staleness, the least
// blocking severity, the history scan at enrolment and the two unknown
// package actions, security_scanning_settings.go), so the table is empty;
// it stays the one place a future axis with no setting names its reason.
var securityFloorNotBuilt = map[string]string{}

// securityLocalPosture is the node's own value on every built axis.
func securityLocalPosture(c config.SecurityConfig) postureop.Posture {
	p := make(postureop.Posture, len(securityFloorRows))
	for _, r := range securityFloorRows {
		p[r.Axis] = r.Read(c)
	}
	return p
}

// securityScanningHeld is the floor accepted on this node.
type securityScanningHeld struct {
	Spec     securityscanning.PolicySpec
	Version  int64
	BodyHash string
	// InEffect is false while the body is accepted but inert (not in
	// [org_client.policy].preauthorize_enforce).
	InEffect bool
	Inert    string
}

// securityScanningBase is what the provider loads from disk: the tenancy
// and the node's own [security] settings.
type securityScanningBase struct {
	Managed  bool
	Security config.SecurityConfig
	// FamilyInEffect: security.scanning is in both [org_client.policy]
	// lists (accepted and preauthorized), the consent the org-wide floor
	// needs too; project sections apply only then (lane sec-p3).
	FamilyInEffect bool
	// FamilyAccepted: in the accept list only (project sections inert).
	FamilyAccepted bool
	// DBPath and Guard locate the guard whose project reader the project
	// sections are read through.
	DBPath string
	Guard  config.GuardConfig
	// OrgKeyPin and BundleExpected are the org-policy inputs the fallback
	// project guard is built from, read by nodeGuardPolicyInputs exactly as
	// for the daemon's own guard (SEC-P3 merge, finding 1).
	OrgKeyPin      string
	BundleExpected bool
	// Disclosure is the online-check disclosure shown on this node (the
	// managed pull's online_checks "on" waits for it).
	Disclosure bool
	// ConfigPath is the config the base was read from (the posture's
	// daemon facts locate the node's databases from it, lane SEC-H2).
	ConfigPath string
}

// securityScanningNode is the one owner of the node-side family state.
type securityScanningNode struct {
	mu     sync.Mutex
	held   *securityScanningHeld
	active map[string]bool
	// moduleOff is true when the security module is not active on this
	// node: every floor key is not_applicable (module_inactive), nothing is
	// applied and the point reports no floor (SEC-E merge audit finding 11).
	moduleOff bool
	load      func(context.Context) (securityScanningBase, error)
	base      securityScanningBase
	baseOK    bool
	loadedAt  time.Time
	now       func() time.Time
}

// securityBaseTTL bounds how stale the provider's view of config.toml and
// the enrolment may be (they are read at accept time and by the read seam).
const securityBaseTTL = 30 * time.Second

var secScanning = &securityScanningNode{now: time.Now}

// bindSecurityScanning binds the family's facts provider for this daemon:
// the active security children from the start-time component snapshot,
// and a cached loader of the tenancy and [security] settings.
func bindSecurityScanning(configPath string, snap componentstate.Snapshot) {
	active := map[string]bool{}
	for _, c := range securityscanning.Children {
		if securitySelected(snap, c.Component) {
			active[c.Component] = true
		}
	}
	secScanning.mu.Lock()
	secScanning.active = active
	secScanning.moduleOff = !snap.ModuleActive(securityManagedModule)
	secScanning.load = securityScanningLoader(configPath)
	secScanning.baseOK = false
	secScanning.mu.Unlock()
	securityscanning.SetNodeFactsProvider(secScanning.facts)
}

// securityScanningLoader reads config.toml and the enrolment.
func securityScanningLoader(configPath string) func(context.Context) (securityScanningBase, error) {
	return func(ctx context.Context) (securityScanningBase, error) {
		cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
		if err != nil {
			return securityScanningBase{}, err
		}
		defer cleanup()
		st := store.New(database)
		managed, err := securityNodeManaged(ctx, st, time.Now())
		if err != nil {
			return securityScanningBase{}, err
		}
		pin, _, bundleExpected := nodeGuardPolicyInputs(ctx, st, nil)
		accepted := slices.Contains(cfg.OrgClient.Policy.AcceptedFamilies(), policyfam.FamilySecurityScanning)
		return securityScanningBase{
			Managed: managed, Security: cfg.Security, Disclosure: securityDisclosureShown(configPath), ConfigPath: configPath,
			FamilyAccepted: accepted,
			FamilyInEffect: accepted && slices.Contains(cfg.OrgClient.Policy.PreauthorizedFamilies(), policyfam.FamilySecurityScanning),
			DBPath:         cfg.Observer.DBPath, Guard: cfg.Guard,
			OrgKeyPin: pin, BundleExpected: bundleExpected,
		}, nil
	}
}

// securityManagedFrom is "managed" for the floors and the security managed
// pull: a managed grant the resolver honours (govern.Resolve(...).Managed
// && !GrantRefused()), never the enrolment record alone (SEC-E merge audit
// finding 4). A lapsed, refused or absent grant reads as an individual node,
// which keeps its floors' posture check and never applies a managed-only key.
func securityManagedFrom(eff govern.Effective) bool {
	return eff.Managed && !eff.GrantRefused()
}

// securityNodeManaged resolves securityManagedFrom from the stored grant.
func securityNodeManaged(ctx context.Context, st *store.Store, now time.Time) (bool, error) {
	loader := governanceIdentityLoader(st)
	if loader == nil {
		return false, nil
	}
	grant, live, err := loader(ctx)
	if err != nil {
		return false, err
	}
	if grant == nil {
		return false, nil
	}
	return securityManagedFrom(govern.Resolve(govern.Delivered{}, grant, live, now)), nil
}

// baseNow returns the cached base, reloading it past the TTL. A failed
// reload keeps the last good base; with none, the node reads as managed=false
// with default settings, and ok is false.
func (n *securityScanningNode) baseNow() (securityScanningBase, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.load != nil && (!n.baseOK || n.now().Sub(n.loadedAt) > securityBaseTTL) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		b, err := n.load(ctx)
		cancel()
		if err == nil {
			n.base, n.baseOK, n.loadedAt = b, true, n.now()
		}
	}
	if !n.baseOK {
		return securityScanningBase{Security: config.DefaultSecurityConfig()}, false
	}
	return n.base, true
}

// facts is the provider bound into the family's evaluator.
func (n *securityScanningNode) facts() securityscanning.NodeFacts {
	base, _ := n.baseNow()
	n.mu.Lock()
	defer n.mu.Unlock()
	f := securityscanning.NodeFacts{
		Managed:   base.Managed,
		Active:    n.active,
		Local:     securityLocalPosture(base.Security),
		ModuleOff: n.moduleOff,
	}
	if n.held != nil && n.held.InEffect {
		spec := n.held.Spec
		f.Held = &spec
	}
	return f
}

// install records an accepted body (PRApplied or PRAppliedInert).
func (n *securityScanningNode) install(res orgclient.PolicyResourceResult) bool {
	spec, ok := res.Spec.(securityscanning.PolicySpec)
	if !ok {
		return false
	}
	n.mu.Lock()
	n.held = &securityScanningHeld{Spec: spec, Version: res.Version, BodyHash: res.BodyHash, InEffect: res.EnforceAllowed, Inert: res.InertReason}
	n.mu.Unlock()
	return true
}

func (n *securityScanningNode) clear() {
	n.mu.Lock()
	n.held = nil
	n.mu.Unlock()
}

func (n *securityScanningNode) heldCopy() *securityScanningHeld {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.held == nil {
		return nil
	}
	h := *n.held
	return &h
}

// securityScanningPublish is the family's install seam
// (publishPolicyResourceResult).
func securityScanningPublish(res orgclient.PolicyResourceResult, logger *slog.Logger) {
	if !secScanning.install(res) {
		if logger != nil {
			logger.Warn("policy resource: security.scanning accepted with a spec this build cannot read; keeping the node's own settings", "version", res.Version)
		}
		return
	}
	if logger != nil {
		logger.Info("policy resource: security.scanning floor accepted",
			"version", res.Version, "in_effect", res.EnforceAllowed, "inert_reason", res.InertReason)
	}
}

// securityScanningClear is the family's clear seam (clearOrgLayer).
func securityScanningClear() { secScanning.clear() }

// securityFloorsApplied is THE read seam: sc with the floor in force merged
// over it, row by row through securityFloorRows. Only rows whose effective
// value differs from the node's own are written, so two rows on one setting
// never undo each other. With no floor in force, or a floor that no longer
// merges (an allow-set that would allow nothing), sc is returned unchanged.
func securityFloorsApplied(sc config.SecurityConfig) config.SecurityConfig {
	return secScanning.applied(sc)
}

func (n *securityScanningNode) applied(sc config.SecurityConfig) config.SecurityConfig {
	return n.appliedWith(sc, n.inForceSpec())
}

// inForceSpec is the org-wide floor in force (nil when none).
func (n *securityScanningNode) inForceSpec() *securityscanning.PolicySpec {
	held := n.heldCopy()
	if held == nil || !held.InEffect {
		return nil
	}
	spec := held.Spec
	return &spec
}

// appliedWith is sc with the managed pull and then spec (a floor, nil for
// none) merged over it row by row.
func (n *securityScanningNode) appliedWith(sc config.SecurityConfig, spec *securityscanning.PolicySpec) config.SecurityConfig {
	n.mu.Lock()
	off := n.moduleOff
	n.mu.Unlock()
	if off {
		// No security module runs here: nothing reads a raised setting.
		return sc
	}
	base, _ := n.baseNow()
	// The managed pull first, the floors over it (security_managedpull.go).
	sc = securityManagedOverlay(sc, base.Disclosure)
	// A managed node refuses a picker's looser value (lane LEFT-SEC,
	// security_scanning_settings.go).
	sc = securityManagedRefusals(sc, base.Managed)
	if spec == nil {
		return sc
	}
	n.mu.Lock()
	active := n.active
	n.mu.Unlock()
	local := securityLocalPosture(sc)
	eff, err := securityscanning.Effective(spec, securityscanning.NodeFacts{Managed: base.Managed, Active: active, Local: local})
	if err != nil {
		return sc
	}
	out := sc
	for _, r := range securityFloorRows {
		if v, ok := eff[r.Axis]; ok && !postureop.Equal(securityAxisScalar(v), securityAxisScalar(local[r.Axis])) {
			r.Write(&out, v)
		}
	}
	return out
}

// securityAxisScalar flattens a value for comparison (a built row is a
// string, a number or, since lane SEC-E4, a set).
func securityAxisScalar(v postureop.Value) any {
	if v.S != "" {
		return v.S
	}
	if v.Set != nil {
		set := append([]string(nil), v.Set...)
		sort.Strings(set)
		return "set:" + strings.Join(set, ",")
	}
	return v.N
}

// securityRetentionDaysNow is the retention the daemon's prune applies now:
// [security.retention].days raised by the floor in force (0 keeps forever).
func securityRetentionDaysNow(local int) int {
	sc := config.DefaultSecurityConfig()
	sc.Retention.Days = local
	return securityFloorsApplied(sc).Retention.Days
}

// newSecurityScanningPointReader is the node-security policy-state reader:
// the floor in force (effective), an accepted inert one (observe), or none.
func newSecurityScanningPointReader(lastFetch func() orgclient.PolicyResourceFetchOutcome, now func() time.Time) policystate.PointReader {
	return func(context.Context) (policystate.PointFacts, error) {
		o := orgclient.PolicyResourceFetchOutcome{}
		if lastFetch != nil {
			o = lastFetch()
		}
		reject := wirePolicyResourceRejectReason(o.RejectCode)
		f := policystate.PointFacts{
			LastSeen:            now(),
			LatestFetchRejected: reject != "",
			RejectCode:          reject,
			RejectedVersion:     o.Version,
			Unreachable:         o.Unreachable,
			EnforceMode:         "off",
		}
		secScanning.mu.Lock()
		off := secScanning.moduleOff
		secScanning.mu.Unlock()
		if h := secScanning.heldCopy(); h != nil && !off {
			f.HasOrgRail = true
			f.CachedAcceptedVersion, f.RunningVersion, f.EffectiveHash = h.Version, h.Version, h.BodyHash
			f.EnforceMode = "enforce"
			if !h.InEffect {
				f.EnforceMode, f.InertReason = "observe", h.Inert
			}
		}
		return f, nil
	}
}

// securityScanningStatusLines are the `observer security status` and
// `observer org status` lines for the floor accepted on this node, read
// from the verified policy-resource cache (a CLI process has no daemon
// memory). Each key the body sets is listed with what it does here.
func securityScanningStatusLines(ctx context.Context, cfg config.Config, st *store.Store, snap componentstate.Snapshot) []string {
	if !policyfam.IsFamilyLinked(policyfam.FamilySecurityScanning) {
		return []string{"Org floors (security.scanning): not in this build"}
	}
	accepted := slices.Contains(cfg.OrgClient.Policy.AcceptedFamilies(), policyfam.FamilySecurityScanning)
	enr, err := st.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return []string{"Org floors (security.scanning): none (not enrolled)"}
	}
	managed, merr := securityNodeManaged(ctx, st, time.Now())
	if merr != nil {
		managed = false
	}
	orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	gen, ok, err := st.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil || !ok || gen.Tombstoned {
		return []string{"Org floors (security.scanning): none"}
	}
	path := filepath.Join(policyResourceCacheDir(cfg), orgKey, strconv.FormatInt(gen.Generation, 10), policyfam.FamilySecurityScanning+".json")
	cached, err := verifyCachedPolicyResource(ctx, st, enr.OrgServerURL, policyfam.FamilySecurityScanning, path, policyResourceNodeAttrs(cfg))
	if err != nil {
		if !accepted {
			return []string{"Org floors (security.scanning): none (the family is not in [org_client.policy] accept_families or accept_module_families)"}
		}
		return []string{"Org floors (security.scanning): none accepted"}
	}
	spec, ok := cached.spec.(securityscanning.PolicySpec)
	if !ok {
		return []string{"Org floors (security.scanning): accepted body not readable by this build"}
	}
	inEffect := accepted && slices.Contains(cfg.OrgClient.Policy.PreauthorizedFamilies(), policyfam.FamilySecurityScanning)
	head := fmt.Sprintf("Org floors (security.scanning): version %d, ", cached.resource.Version)
	if inEffect {
		head += "in effect"
	} else {
		head += "accepted but inert (add security.scanning to [org_client.policy].preauthorize_module_enforce)"
	}
	active := map[string]bool{}
	for _, c := range securityscanning.Children {
		if securitySelected(snap, c.Component) {
			active[c.Component] = true
		}
	}
	facts := securityscanning.NodeFacts{Managed: managed, Active: active, Local: securityLocalPosture(cfg.Security), ModuleOff: !snap.ModuleActive(securityManagedModule)}
	lines := []string{head}
	for _, k := range securityscanning.Evaluate(spec, facts) {
		k = securityKeyStateOnNode(k, facts)
		line := "  " + k.String()
		if k.Floor != "" {
			line += " (floor " + k.Floor + ")"
		}
		if why := securityKeyNote(k, facts); why != "" {
			line += ": " + why
		}
		lines = append(lines, line)
	}
	return lines
}

// securityManagedRefusedKeys are floor keys the family reports applied on a
// managed node that this node's own gates refuse there: status names what
// actually happens instead of "applied" (SEC-E merge audit finding 6). Empty
// since lane SEC-E4: a managed node's online checks go to the org relay, so
// require.online_checks = required is applied there too (the relay answers
// online_unknown while the org server has none configured).
var securityManagedRefusedKeys = map[string]string{}

// securityManagedOnlineNote is what require.online_checks = required does on
// a managed node (SEC-E4 merge finding 8): the install gate's checks and,
// since lane SEC-H2, the dependency scanners' online matching go to the org
// relay only, so status names where the names go.
const securityManagedOnlineNote = "applied through the org relay only, never a public host: the install gate's checks (online_unknown while the org server has no relay configured) and the dependency scanners' online matching (unmatched while the relay is off or down; in mirror mode the local database from the org mirror decides)"

// securityKeyNote is the reason shown beside one floor key in status: why a
// not_built key has no setting, or which parts of an applied key a managed
// node refuses; "" when nothing needs saying.
func securityKeyNote(k securityscanning.KeyState, f securityscanning.NodeFacts) string {
	if why, ok := securityFloorNotBuilt[k.Key]; ok && k.Reason == securityscanning.ReasonNotBuilt {
		return why
	}
	if f.Managed && k.Key == securityscanning.AxisOnlineChecks && k.State == securityscanning.StateApplied && k.Floor == "required" {
		return securityManagedOnlineNote
	}
	return ""
}

// securityKeyStateOnNode corrects one key's state for what this node does.
func securityKeyStateOnNode(k securityscanning.KeyState, f securityscanning.NodeFacts) securityscanning.KeyState {
	if reason, ok := securityManagedRefusedKeys[k.Key]; ok && f.Managed && k.State == securityscanning.StateApplied && k.Floor == "required" {
		k.State, k.Reason = securityscanning.StateRefused, reason
	}
	return k
}

// securityOrgStatusLines are the security lines of `observer security status`
// and `observer org status`: the org floors (security.scanning) and the
// managed pull (enforce.security).
func securityOrgStatusLines(ctx context.Context, configPath string, cfg config.Config, st *store.Store) []string {
	lines := securityScanningStatusLines(ctx, cfg, st, componentSnapshotForConfig(cfg))
	// The project sections that apply in the current directory (lane
	// sec-p3), read through the same seam the per-project consumers use.
	if wd, err := os.Getwd(); err == nil && st != nil {
		bindSecurityFloorsForCLI(ctx, configPath, cfg, st)
		lines = append(lines, securityProjectStatusLines(wd)...)
	}
	lines = append(lines, securityManagedStatusLines(ctx, configPath, cfg, st)...)
	// The node settings lane LEFT-SEC built, each named when not at its
	// default or overridden by a floor or the managed rule.
	return append(lines, securityNodeSettingStatus(ctx, configPath, cfg, st)...)
}
