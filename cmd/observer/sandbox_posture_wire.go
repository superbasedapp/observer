//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/policyfam/terminalsisolation"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_posture_wire.go is the sandbox module's registration on the
// settings.pin posture-provider seam (nodegov.RegisterPinPosture, N3; sandbox
// plan v2 section 8.5, SBX-GOV-5). The accept path calls it only for a
// node.governance body that pins a [terminal.sandbox] key: it reads the
// node's OWN config (no governance overlay), applies the pins through the
// one config overlay, and asks sandboxselect whether the result is weaker on
// any axis. It never probes and never writes; a build without the module
// compiles sandbox_posture_wire_omit.go and registers nothing.

// sandboxPinOwner is the owner name on the seam: the module's component id.
const sandboxPinOwner = sandboxComponent

// sandboxPinPrefix is the dotted prefix of every key this module owns.
const sandboxPinPrefix = "terminal.sandbox."

// sandboxCompiledDrivers are the backend drivers this build compiles (the
// rows sandboxProbes probes; every other row drops at S1): bwrap, built into
// the runtime, and every driver registered from init (registerSandboxDriver:
// oci-runc when terminals.sandbox.oci is compiled in). SBX-P3A merge finding
// F4: the list named bwrap only.
func sandboxCompiledDrivers() map[string]bool {
	out := map[string]bool{sandboxbackend.BackendBwrap: true}
	for id := range sandboxDriverRegs {
		out[id] = true
	}
	return out
}

// sandboxDriverUsable reports whether backend id can run under snap: compiled
// in, and for a registered driver selected by the node's [components] block
// (sandboxDriverSelected, the opt-in rule); bwrap needs only the module.
func sandboxDriverUsable(snap componentstate.Snapshot, id string) bool {
	if !sandboxCompiledDrivers()[id] {
		return false
	}
	if reg, ok := sandboxDriverRegs[id]; ok {
		return sandboxDriverSelected(snap, reg.component)
	}
	return true
}

// sandboxPinKeys derives the module's keys from the pin table, so a row
// added there is covered without a second list.
func sandboxPinKeys() []string {
	var out []string
	for _, k := range nodegov.PinnableKeys {
		if strings.HasPrefix(k.Key, sandboxPinPrefix) {
			out = append(out, k.Key)
		}
	}
	return out
}

// loadOwnSandboxConfig reads the node's own config, without the governance
// overlay. A seam for tests.
var loadOwnSandboxConfig = func() (config.Config, error) {
	return config.Load(config.LoadOptions{GlobalPath: daemonConfigPath(), GovernanceSidecar: config.NoGovernanceSidecar})
}

func init() {
	if err := nodegov.RegisterPinPosture(sandboxPinOwner, sandboxPinKeys(), checkSandboxPinPosture); err != nil {
		slog.Default().Warn("sandbox: the pin posture check is not registered; sandbox pins keep their per-key directions only", "err", err)
	}
}

// checkSandboxPinPosture is the module's evaluator for one pin set. The
// sandbox pins are not applicable on a node where the sandbox module is not
// active or the sandbox is off (sandboxPinsNotApplicable): nothing they
// govern runs there, so the evaluator records that and never refuses the
// node.governance body (its guard and share pins apply). A pin the overlay
// skips is reported not honoured key by key (GovernanceOutcome.Skipped) and
// never refuses the body either (SBX-P1B merge audit finding 3); only a
// loosened posture axis does.
func checkSandboxPinPosture(pins map[string]any) (string, error) {
	own, err := loadOwnSandboxConfig()
	if err != nil {
		// Fail closed: a node that cannot read its own settings cannot show
		// that the pins leave it at least as strict.
		return "config", fmt.Errorf("the node's own config could not be read to check the pins: %w", err)
	}
	if why := sandboxPinsNotApplicable(own); why != "" {
		slog.Default().Info("sandbox: the organization's sandbox pins are not applicable on this node; the rest of node.governance applies",
			"reason", why, "keys", len(pins))
		return "", nil
	}
	after, out := config.ApplyGovernancePinsTo(own, pins)
	for k, why := range out.Skipped {
		if strings.HasPrefix(k, sandboxPinPrefix) {
			slog.Default().Warn("sandbox: an organization sandbox pin is not honoured on this node; the rest of node.governance applies",
				"key", k, "reason", why)
		}
	}
	return sandboxselect.CheckPinPosture(sandboxselect.PinPostureInput{
		Before: sandboxPostureSettings(own),
		After:  sandboxPostureSettings(after),
		Env:    sandboxPostureEnv(own),
	})
}

// sandboxPinsNotApplicableRows says when the sandbox pins govern nothing on
// this node, top down: the module not active under [components] (or
// blocked), then the sandbox switched off. A build without the module
// registers no evaluator at all (sandbox_posture_wire_omit.go).
var sandboxPinsNotApplicableRows = []struct {
	reason string
	holds  func(cfg config.Config) bool
}{
	{"the sandbox module is not active", func(cfg config.Config) bool {
		return !sandboxModuleActive(componentSnapshotForConfig(cfg))
	}},
	{"the sandbox is off ([terminal.sandbox].enabled = false)", func(cfg config.Config) bool { return !cfg.Terminal.Sandbox.Enabled }},
}

// sandboxPinsNotApplicable returns why the sandbox pins govern nothing on a
// node with config cfg, or "" when they apply.
func sandboxPinsNotApplicable(cfg config.Config) string {
	for _, r := range sandboxPinsNotApplicableRows {
		if r.holds(cfg) {
			return r.reason
		}
	}
	return ""
}

// sandboxPostureEnv is this host and build for the evaluator: the drivers
// this build compiles that the node's own [components] block selects, so
// the auto pick (and the engine privilege it carries) is the driver the node
// would actually use.
func sandboxPostureEnv(cfg config.Config) sandboxselect.PostureEnv {
	snap := componentSnapshotForConfig(cfg)
	return sandboxselect.PostureEnv{
		Host:     sandboxHostKind(),
		Compiled: func(id string) bool { return sandboxDriverUsable(snap, id) },
	}
}

// sandboxPostureSettings reduces a config to the settings the axes read.
func sandboxPostureSettings(cfg config.Config) sandboxselect.PostureSettings {
	ts := cfg.Terminal.Sandbox
	return sandboxselect.PostureSettings{
		Enabled:               ts.Enabled,
		Backends:              config.SandboxEffectiveBackends(&cfg),
		Egress:                ts.Egress,
		RemoteAllowedHosts:    ts.RemoteAllowedHosts,
		MaskPaths:             ts.MaskPaths,
		ExtraROBinds:          ts.ExtraROBinds,
		ExtraRWBinds:          ts.ExtraRWBinds,
		EgressAllowCIDRs:      ts.EgressAllowCIDRs,
		AllowRemoteClone:      ts.AllowRemoteClone,
		AllowWorktreeSource:   ts.AllowWorktreeSource,
		AllowToolConfigWrites: ts.AllowToolConfigWrites,
		DefaultOn:             ts.DefaultOn,
		HomeMode:              ts.HomeMode,
		RetentionDays:         int64(ts.WorkspaceRetentionDays),
		RootfulEngineAllowed:  ts.OCI.AllowRootful,
	}
}

// ---- the terminals.isolation floors (sandbox plan v2 sections 8.1 to 8.3) ----

// isolationFloorsState is the accepted terminals.isolation body: its identity
// for the policy-state row, and the compiled floors only while they are in
// effect (accepted and preauthorized). One owner: isolationFloors.
type isolationFloorsState struct {
	hasOrgRail  bool
	version     int64
	bodyHash    string
	inertReason string
	spec        *terminalsisolation.PolicySpec
}

// isolationFloors is the daemon-lifetime holder the policy-resource dispatch
// writes and every sandbox selection reads. Nothing is held (and nothing
// changes for any launch) until a body is accepted.
var isolationFloors struct {
	mu sync.Mutex
	st isolationFloorsState
}

// isolationFloorsPublish installs an accepted terminals.isolation result
// (publishPolicyResourceResult calls it). An inert body (not preauthorized)
// is recorded for the policy-state row and applies no floor.
func isolationFloorsPublish(res orgclient.PolicyResourceResult) {
	spec, ok := res.Spec.(terminalsisolation.PolicySpec)
	if !ok {
		return
	}
	st := isolationFloorsState{hasOrgRail: true, version: res.Version, bodyHash: res.BodyHash, inertReason: res.InertReason}
	if !res.EnforceAllowed && st.inertReason == "" {
		st.inertReason = "not_preauthorized"
	}
	if st.inertReason == "" {
		st.spec = &spec
	}
	isolationFloors.mu.Lock()
	isolationFloors.st = st
	isolationFloors.mu.Unlock()
	// A require_full_capture floor now in force ends the live runs that
	// drifted before it arrived (SBX-P2E audit finding 4).
	relayFloorsApplied()
}

// isolationFloorsClear removes the org floors (a signed withdrawal, an
// unenrolment).
func isolationFloorsClear() {
	isolationFloors.mu.Lock()
	isolationFloors.st = isolationFloorsState{}
	isolationFloors.mu.Unlock()
}

// isolationFloorsInForce returns the floors in effect, if any.
func isolationFloorsInForce() (terminalsisolation.PolicySpec, bool) {
	isolationFloors.mu.Lock()
	defer isolationFloors.mu.Unlock()
	if isolationFloors.st.spec == nil || !isolationFloors.st.spec.InForce() {
		return terminalsisolation.PolicySpec{}, false
	}
	return *isolationFloors.st.spec, true
}

// sandboxOrgFloors maps the floors in effect onto the selection table's
// Floors (S4b, S6, S6b, S7, S7b, S12b). With no floor in force it is the
// zero value, so selection is exactly what it was.
func sandboxOrgFloors() sandboxselect.Floors {
	return sandboxFloorsFromSpec(isolationFloorsInForce())
}

// sandboxFloorsFromSpec maps one terminals.isolation spec (ok false: none in
// force) onto the selection table's Floors: the one mapping the daemon's
// in-memory floors and a CLI's cached read share (R-035).
func sandboxFloorsFromSpec(spec terminalsisolation.PolicySpec, ok bool) sandboxselect.Floors {
	if !ok {
		// AllowRemote alone is not a floor (Floors.InForce ignores it).
		return sandboxselect.Floors{AllowRemote: sandboxRemoteAllowed(false)}
	}
	return sandboxselect.Floors{
		OrgMinClass:          spec.MinIsolation,
		AllowedBackends:      spec.AllowedBackends,
		MinEgress:            spec.MinEgress,
		FloorAcceptsBeta:     spec.FloorAcceptsBeta,
		RequireFullCapture:   spec.RequireFullCapture,
		AllowedRegions:       spec.AllowedRegions,
		ForbidProviderInject: spec.ForbidProviderKeyInjection,
		// AllowRemote (lane SBX-P7): true only while a hosted row is in the
		// local backends and no org floor sets allow_remote = false (a floor
		// can never turn hosted sandboxes on: false is the only value the
		// compiler accepts).
		AllowRemote: sandboxRemoteAllowed(spec.ForbidRemote),
	}
}

// isolationFloorVerdictKey names the floor key behind an org-floor drop
// verdict, so a refusal names the org setting by its admin label.
var isolationFloorVerdictKey = map[string]string{
	sandboxselect.VerdictBelowOrgFloor:            "min_isolation",
	sandboxselect.VerdictBackendNotAllowed:        "allowed_backends",
	sandboxselect.VerdictBelowEgressFloor:         "min_egress",
	sandboxselect.VerdictBetaBelowFloor:           "floor_accepts_beta",
	sandboxselect.VerdictReducedCaptureNotAllowed: "require_full_capture",
	sandboxselect.VerdictRegionNotAllowed:         "allowed_regions",
	sandboxselect.VerdictCustodyNotAllowed:        "provider_key_injection",
}

// isolationFloorRefusal is the launch's answer when the org floors in force
// rule out the bwrap layer this build would build (sandbox plan v2 section
// 8.1: a refusal naming the org setting, the shipped org_disallow copy
// pattern, never an unsandboxed fallback). nil when no floor is in force or
// bwrap meets them.
func isolationFloorRefusal(cfg config.TerminalSandboxConfig) error {
	floors := sandboxOrgFloors()
	if !floors.InForce() {
		return nil
	}
	row, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	tier := vocab.Tier(cfg.Egress)
	if tier == "" {
		tier = vocab.TierInternet
	}
	beta := true
	if v, ok := row.VerificationOn(sandboxHostKind()); ok {
		beta = v.Kind.IsBeta()
	}
	in := sandboxselect.Input{
		Request: sandboxselect.Request{Backend: row.ID, Tier: tier, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true, ProviderDirect: cfg.EffectiveProviderDirect()},
		Host:    sandboxHostKind(),
		Floors:  floors,
		Tool:    sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
	}
	d, dropped := sandboxselect.FloorDrop(row, in, beta)
	if !dropped {
		return nil
	}
	return sandboxRefusalError{msg: isolationFloorMessage(d)}
}

// isolationFloorMessage renders one floor drop as the org_disallow copy.
func isolationFloorMessage(d sandboxselect.Drop) string {
	label := "isolation floor"
	if k, ok := terminalsisolation.LookupFloorKey(isolationFloorVerdictKey[d.Verdict]); ok {
		label = k.Label
	}
	return fmt.Sprintf("terminal_sandbox: %s: your organization's sandbox setting %q is not met by any sandbox backend here (%s); the terminal is refused, never run without it",
		d.Verdict, label, d.Reason)
}

// isolationFloorsAllowUnsandboxed is the terminal feature gate's floor check
// (nodeFeaturesHandle.TerminalAllowed): a floor that implies
// sandbox_required (min_isolation, allowed_backends, min_egress) refuses an
// unsandboxed terminal, naming the floor; the qualifying floors do not.
func isolationFloorsAllowUnsandboxed() (bool, string) {
	spec, ok := isolationFloorsInForce()
	if !ok {
		return true, ""
	}
	k, implied := spec.ImpliedBy()
	if !implied {
		return true, ""
	}
	// Plan 11.5: on a machine that cannot run a sandbox at all the reason
	// names the floor and why (the module or the platform), instead of
	// asking for a retry that cannot work.
	if why := sandboxCannotRunHere(); why != "" {
		return false, fmt.Sprintf("your organization's sandbox setting %q requires a sandboxed terminal on this machine, and this machine cannot run a sandbox: %s; new terminals are refused, never run without one", k.Label, why)
	}
	return false, fmt.Sprintf("your organization's sandbox setting %q requires a sandboxed terminal on this machine; retry with sandbox enabled", k.Label)
}

// sandboxCannotRunHere says why this machine cannot run any sandbox, or ""
// when it might (a probe can still fail at launch). A seam for tests.
var sandboxCannotRunHere = func() string {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: daemonConfigPath()})
	if err != nil {
		return ""
	}
	return sandboxCannotRunReason(cfg, sandboxHostKind())
}

// sandboxCannotRunRows are the static reasons, top down, a machine cannot run
// a sandbox: the module not active under [components] (or blocked), then a
// host no compiled backend runs on, then a host whose only backends are
// opt-in drivers none of which is selected. Nothing here probes.
var sandboxCannotRunRows = []struct {
	reason func(host sandboxbackend.HostKind) string
	holds  func(cfg config.Config, host sandboxbackend.HostKind) bool
}{
	{
		reason: func(sandboxbackend.HostKind) string {
			return "the Sandboxes and VMs module is not active (blocked or deactivated)"
		},
		holds: func(cfg config.Config, _ sandboxbackend.HostKind) bool {
			return !sandboxModuleActive(componentSnapshotForConfig(cfg))
		},
	},
	{
		reason: func(host sandboxbackend.HostKind) string {
			return fmt.Sprintf("this platform (%s) has no sandbox backend in this build", host)
		},
		holds: func(_ config.Config, host sandboxbackend.HostKind) bool {
			for id := range sandboxCompiledDrivers() {
				if row, ok := sandboxbackend.Get(id); ok && row.RunsOn(host) {
					return false
				}
			}
			return true
		},
	},
	{
		// A backend in the build that runs here but is an opt-in driver
		// whose component is not selected (the macOS and Windows drivers,
		// inactive in every distro) cannot run a sandbox either.
		reason: func(host sandboxbackend.HostKind) string {
			return fmt.Sprintf("this platform (%s) has no sandbox backend selected: its backends are opt-in drivers, none selected in Settings > Components", host)
		},
		holds: func(cfg config.Config, host sandboxbackend.HostKind) bool {
			snap := componentSnapshotForConfig(cfg)
			for id := range sandboxCompiledDrivers() {
				if row, ok := sandboxbackend.Get(id); ok && row.RunsOn(host) && sandboxDriverUsable(snap, id) {
					return false
				}
			}
			return true
		},
	},
}

// sandboxCannotRunReason walks sandboxCannotRunRows for cfg on host.
func sandboxCannotRunReason(cfg config.Config, host sandboxbackend.HostKind) string {
	for _, r := range sandboxCannotRunRows {
		if r.holds(cfg, host) {
			return r.reason(host)
		}
	}
	return ""
}

// newIsolationFloorsPointReader is the terminals.isolation policy-state row,
// enum-only like every other point.
func newIsolationFloorsPointReader(lastFetch func() orgclient.PolicyResourceFetchOutcome, now func() time.Time) policystate.PointReader {
	return func(context.Context) (policystate.PointFacts, error) {
		isolationFloors.mu.Lock()
		st := isolationFloors.st
		isolationFloors.mu.Unlock()
		f := policystate.PointFacts{HasOrgRail: st.hasOrgRail, InertReason: st.inertReason, LastSeen: now(), EnforceMode: "off"}
		if lastFetch != nil {
			o := lastFetch()
			reject := wirePolicyResourceRejectReason(o.RejectCode)
			f.LatestFetchRejected = reject != ""
			f.RejectCode = reject
			f.RejectedVersion = o.Version
			f.Unreachable = o.Unreachable
		}
		if st.hasOrgRail {
			f.CachedAcceptedVersion = st.version
			f.RunningVersion = st.version
			f.EffectiveHash = st.bodyHash
			f.EnforceMode = "enforce"
			if st.inertReason != "" {
				f.EnforceMode = "observe"
			}
		}
		return f, nil
	}
}

// sandboxOrgView is what the organization sets for this node's sandbox, for
// the probe API and the Sandbox isolation card (shown read-only, "Set by
// your organization"): the floors in force and the applied
// [terminal.sandbox] pins. nil when the organization sets nothing. It reads
// the governance sidecar through the config loader on the probe request; it
// never writes and starts nothing.
func sandboxOrgView() *dashapi.SandboxOrgSettings {
	var out dashapi.SandboxOrgSettings
	if spec, ok := isolationFloorsInForce(); ok {
		for _, k := range spec.Keys {
			fk, _ := terminalsisolation.LookupFloorKey(k)
			out.Floors = append(out.Floors, dashapi.SandboxOrgValue{Key: k, Label: fk.Label, Value: isolationFloorValue(spec, k)})
		}
	}
	cfg, gout, err := config.LoadGovernance(config.LoadOptions{GlobalPath: daemonConfigPath()})
	if err == nil && gout.Governed() {
		var keys []string
		for _, k := range gout.Applied {
			if strings.HasPrefix(k, sandboxPinPrefix) {
				keys = append(keys, k)
			}
		}
		vals := config.PinnableEffectiveValues(cfg, keys)
		for _, k := range keys {
			row, _ := nodegov.LookupPinnableKey(k)
			out.Pins = append(out.Pins, dashapi.SandboxOrgValue{
				Key: strings.TrimPrefix(k, sandboxPinPrefix), Label: row.Label, Value: displayValue(vals[k]),
			})
		}
	}
	if err == nil {
		out.Managed, out.ManagedRefused = sandboxManagedView(cfg)
	}
	if len(out.Floors) == 0 && len(out.Pins) == 0 && len(out.Managed) == 0 && len(out.ManagedRefused) == 0 {
		return nil
	}
	return &out
}

// sandboxManagedView is what the in-force sandbox managed body does on this
// node, for the Card (SBX-P2E, P1c audit F10): each key it sets with the
// EFFECTIVE value after composition, and each key it could not apply with
// its reason. Both empty when no body is in force; it reads the daemon's
// overlay and writes nothing.
func sandboxManagedView(cfg config.Config) (managed, refusedOut []dashapi.SandboxOrgValue) {
	p, pins := processSandboxManaged.snapshot(context.Background(), time.Now())
	if p == nil {
		return nil, nil
	}
	env := sandboxManagedEnvFor(cfg, pins)
	eff, refused := composeSandboxManaged(cfg.Terminal.Sandbox, *p, env)
	for _, r := range refused {
		row, _ := nodegov.LookupPinnableKey(r.Key)
		refusedOut = append(refusedOut, dashapi.SandboxOrgValue{Key: strings.TrimPrefix(r.Key, sandboxPinPrefix), Label: row.Label, Value: r.Reason})
	}
	keys := sandboxManagedApplied(*p, env, refused)
	effCfg := cfg
	effCfg.Terminal.Sandbox = eff
	vals := config.PinnableEffectiveValues(effCfg, keys)
	for _, k := range keys {
		row, _ := nodegov.LookupPinnableKey(k)
		managed = append(managed, dashapi.SandboxOrgValue{Key: strings.TrimPrefix(k, sandboxPinPrefix), Label: row.Label, Value: displayValue(vals[k])})
	}
	// node.skip_repo_scan is not a [terminal.sandbox] key: the Card shows
	// it beside the binds it names (ruling P-060).
	if skip := sandboxManagedOrgBindsFor(p, refused).skipScan; len(skip) > 0 {
		managed = append(managed, dashapi.SandboxOrgValue{Key: "skip_repo_scan", Label: sandboxSkipRepoScanLabel, Value: displayValue(skip)})
	}
	return managed, refusedOut
}

// isolationFloorValue renders one floor's value for display.
func isolationFloorValue(s terminalsisolation.PolicySpec, key string) string {
	switch key {
	case "min_isolation":
		return string(s.MinIsolation)
	case "allowed_backends":
		return strings.Join(s.AllowedBackends, ", ")
	case "min_egress":
		return string(s.MinEgress)
	case "allowed_regions":
		return strings.Join(s.AllowedRegions, ", ")
	case "allow_remote":
		return "false"
	case "provider_key_injection", "provider_memory_images":
		return terminalsisolation.Forbidden
	}
	return "true"
}

func displayValue(v any) string {
	switch x := v.(type) {
	case []string:
		if len(x) == 0 {
			return "(empty)"
		}
		return strings.Join(x, ", ")
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}
