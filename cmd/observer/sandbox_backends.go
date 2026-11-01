//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandbox_backends.go turns the shipped bwrap probe into the per-backend
// list of the probe API and `observer sandbox status` (sandbox plan v2
// sections 4.5 and 9, phase P1a): one call into the selection table per
// registry row, so the dashboard, the CLI and (later) doctor render the same
// drop reasons. Only bwrap is compiled as a driver in P1a; every other row
// is listed as planned.

// sandboxComponent is the node catalog id of the sandbox module.
const sandboxComponent = "terminals.sandbox"

// sandboxDriverSelected is the opt-in rule of the sandbox drivers (sandbox
// plan v2 section 10.1: drivers are inactive by default, bwrap is active
// when the module is): a driver component runs only when a [components]
// block selects it. A config with no block resolves every compiled module
// active (componentstate.Legacy), so without this an existing install would
// gain a driver it never chose. It is the one place that rule lives for
// sandbox drivers, as securityOptIn is for the security children.
func sandboxDriverSelected(snap componentstate.Snapshot, component string) bool {
	// The block must select the driver itself (by add, or by its distro),
	// not merely exist (D-MU3).
	if !snap.BlockSelects(component) {
		return false
	}
	return sandboxModuleActive(snap) && snap.ModuleActive(component)
}

// The status surfaces (`observer components status`, doctor, start's
// summary) and config.Load's component gate apply the same opt-in rule,
// through componentOptInRules, so they agree with the sandbox module's own
// active check.
func init() {
	componentOptInRules = append(componentOptInRules, sandboxDriverOptIn)
}

// sandboxDriverOptIn governs the registered sandbox drivers' components.
func sandboxDriverOptIn(snap componentstate.Snapshot, id string) (governs, active bool) {
	for _, reg := range sandboxDriverRegs {
		if reg.component == id {
			return true, sandboxDriverSelected(snap, id)
		}
	}
	return false, false
}

// sandboxModuleActive reports whether the Sandboxes and VMs module is active
// under snap, with the module's own root-removal rule (plans decision log
// P-057, the SBX-P3A merge's F6 ruling; core componentstate is unchanged): a
// [components] block whose remove list names terminals.sandbox switches the
// module off even while a driver child (terminals.sandbox.oci, selected from
// the base) keeps it active in the core resolver through its Requires, so a
// removal written before the driver row existed still removes the module. A
// block that adds a driver child by name keeps the core answer (the module
// stays active and the snapshot says why). On a managed node the remove
// entries are ignored, so the module stays selected and this rule never
// fires there.
func sandboxModuleActive(snap componentstate.Snapshot) bool {
	return snap.ModuleActive(sandboxComponent) && !sandboxRootRemoved(snap)
}

// sandboxRootRemoved reports whether the block removed the module root
// itself: it names terminals.sandbox in remove, the removal applied (the
// root is not selected), and no driver child is added by name.
func sandboxRootRemoved(snap componentstate.Snapshot) bool {
	if !snap.Configured || !slices.Contains(snap.Remove, sandboxComponent) || slices.Contains(snap.Selected, sandboxComponent) {
		return false
	}
	for _, id := range snap.Add {
		if strings.HasPrefix(id, sandboxComponent+".") {
			return false
		}
	}
	return true
}

// sandboxHostKind classifies the daemon's host for the registry.
func sandboxHostKind() sandboxbackend.HostKind {
	switch runtime.GOOS {
	case "linux":
		if crossmount.IsWSL() {
			return sandboxbackend.HostWSL2
		}
		return sandboxbackend.HostLinux
	case "darwin":
		return sandboxbackend.HostMacOS
	case "windows":
		return sandboxbackend.HostWindows
	}
	return sandboxbackend.HostKind(runtime.GOOS)
}

// sandboxEnabledBackends is the local enabled list in preference order: the
// legacy single `backend` key (bwrap when empty), the only key P1a reads.
// The master switch off enables nothing (every row drops at S2).
func sandboxEnabledBackends(cfg config.TerminalSandboxConfig) []string {
	if !cfg.Enabled || cfg.PinnedNoBackend != "" {
		// An organization pin that left none of the node's backends enables
		// none (the governance overlay sets PinnedNoBackend).
		return nil
	}
	// backends (sandbox plan v2 section 10) wins over the one-element
	// backend key when it is set.
	if len(cfg.Backends) > 0 {
		out := make([]string, 0, len(cfg.Backends))
		for _, b := range cfg.Backends {
			if b = strings.TrimSpace(b); b != "" {
				out = append(out, b)
			}
		}
		return out
	}
	if b := strings.TrimSpace(cfg.Backend); b != "" {
		return []string{b}
	}
	return []string{sandbox.BackendBwrap}
}

// sandboxLocalFloor refuses a bwrap launch the local config does not allow:
// bwrap must be among the enabled backends, and its class must meet
// [terminal.sandbox].min_isolation. A floor is an explicit requirement, so
// the answer is a refusal naming the key, never a weaker run.
func sandboxLocalFloor(cfg config.TerminalSandboxConfig) error {
	if cfg.PinnedNoBackend != "" {
		return fmt.Errorf("terminal_sandbox: your organization's pin of %s allows none of the sandbox backends this machine is set to use, so no backend is enabled; the sandboxed terminal is refused, never run without it", cfg.PinnedNoBackend)
	}
	enabled := false
	for _, b := range sandboxEnabledBackends(cfg) {
		enabled = enabled || b == sandboxbackend.BackendBwrap
	}
	if !enabled {
		return fmt.Errorf("terminal_sandbox: bwrap is not in [terminal.sandbox].backends %v, and no other listed backend has a driver in this build", cfg.Backends)
	}
	row, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	if floor := vocab.IsoClass(cfg.MinIsolation); floor != "" && row.Iso.Class.Rank() < floor.Rank() {
		return fmt.Errorf("terminal_sandbox: bwrap builds %s isolation, below [terminal.sandbox].min_isolation = %s", row.Iso.Class, floor)
	}
	// The org's terminals.isolation floors in force (sandbox plan v2
	// section 8.1, lane SBX-P1B): a floor bwrap cannot meet refuses the
	// launch naming the org setting, never runs it weaker.
	return isolationFloorRefusal(cfg)
}

// launchFloorConfig is the config a launch re-checks the floors against:
// cfg with the egress tier the run actually builds (the resolved egress
// profile's mode), never the configured [terminal.sandbox].egress, which
// can differ from it.
func launchFloorConfig(cfg config.TerminalSandboxConfig, effectiveEgress string) config.TerminalSandboxConfig {
	if effectiveEgress != "" {
		cfg.Egress = effectiveEgress
	}
	return cfg
}

// sandboxProbes maps the shipped bwrap probe onto the selection input. A
// driver this build does not compile has no probe and drops at S1.
func sandboxProbes(av sandbox.Availability, sources []string) map[string]sandboxselect.Probe {
	return map[string]sandboxselect.Probe{
		sandboxbackend.BackendBwrap: {
			Compiled: true,
			Verdict:  av.Verdict,
			Reason:   av.Reason,
			Version:  av.BackendVersion,
			Sources:  sources,
		},
	}
}

// sandboxSelectInput is the selection input for one request on this host.
// The tool facts are those of a proxy-routed agent holding its own
// credential (the common case and the strictest for capture); a launch
// replaces them with the real tool's.
func sandboxSelectInput(cfg config.TerminalSandboxConfig, av sandbox.Availability, sources []string, backend string, tier vocab.Tier) sandboxselect.Input {
	return sandboxSelectInputWith(cfg, av, sources, backend, tier, nil)
}

// sandboxSelectInputWith is sandboxSelectInput with the registered drivers'
// probes added beside bwrap's (lane SBX-P3A); nil adds none, which is
// exactly sandboxSelectInput.
func sandboxSelectInputWith(cfg config.TerminalSandboxConfig, av sandbox.Availability, sources []string, backend string, tier vocab.Tier, drivers map[string]sandboxselect.Probe) sandboxselect.Input {
	probes := sandboxProbes(av, sources)
	for id, p := range drivers {
		if id != sandboxbackend.BackendBwrap {
			probes[id] = p
		}
	}
	custody, inReach := vocab.CustodyHostBound, true
	if row, ok := sandboxbackend.Get(backend); ok && row.Iso.Location == vocab.LocationRemote {
		// A hosted row's custody is [terminal.sandbox.hosted].key_custody
		// (lane SBX-P7); only home_relay keeps the credential out of reach.
		custody = sandboxRequestCustody(cfg, row)
		inReach = hostedCredentialInReach(custody)
	}
	return sandboxselect.Input{
		Request: sandboxselect.Request{
			Backend: backend, Tier: tier, Interactive: true,
			Custody: custody, AcceptReducedCapture: true,
			MinClass:       vocab.IsoClass(cfg.MinIsolation),
			ProviderDirect: cfg.EffectiveProviderDirect(),
			Region:         sandboxRequestRegion(cfg, backend),
		},
		Host:    sandboxHostKind(),
		Enabled: sandboxEnabledBackends(cfg),
		Probes:  probes,
		// The org floors in force (terminals.isolation, lane SBX-P1B); the
		// zero value while none is, so selection is unchanged.
		Floors: sandboxOrgFloors(),
		Tool:   sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: inReach},
	}
}

// reconcileLegacyProbe makes the legacy top-level probe fields agree with
// the bwrap row of backends[] (lane sbx-p1a2, audit finding P-006 (6)):
// the shipped probe only knows whether bwrap runs, the registry also
// refuses a version below its required minimum (S2b,
// backend_version_untested). When the row refuses for that reason the
// legacy fields say the same, so a client reading either never sees
// "available" for a backend the launch would refuse.
func reconcileLegacyProbe(av sandbox.Availability, backends []dashapi.SandboxBackendAvail) sandbox.Availability {
	if !av.Available {
		return av
	}
	for _, b := range backends {
		if b.ID == sandboxbackend.BackendBwrap && (b.Verdict == sandboxselect.VerdictBackendVersionUntested || sandboxselect.IsFloorRule(b.Rule)) {
			// A version below the minimum, or an org floor bwrap does not
			// meet (lane SBX-P1B): the legacy fields say the same, so the
			// dialog never offers a sandbox the launch would refuse.
			av.Available = false
			av.Verdict, av.Reason = b.Verdict, b.Reason
		}
	}
	return av
}

// sandboxOverallIn is what the overall verdict is decided from: the probe
// so far (the bwrap probe, reconciled, with a chosen driver preferred), the
// offered rows that run on this host, and the host.
type sandboxOverallIn struct {
	av   sandbox.Availability
	here []dashapi.SandboxBackendAvail
	host sandboxbackend.HostKind
}

// sandboxOverallRules decide the overall verdict `observer sandbox status`,
// doctor and the probe API print, walked top-down: the first row whose match
// holds decides. No operating system is named: which rows run here is the
// registry's Hosts column. Before it, a Mac with Seatbelt available, or
// Windows with mxc-process, printed bwrap's "sandboxing requires a Linux
// daemon" (macOS live run 2026-10-22, D2).
var sandboxOverallRules = []struct {
	name   string
	match  func(in sandboxOverallIn) bool
	decide func(in sandboxOverallIn) sandbox.Availability
}{
	{
		// Available, or a verdict about a row that runs here (bwrap on
		// Linux, a driver's own refusal): kept as it is, so Linux is
		// unchanged.
		name: "answered_here",
		match: func(in sandboxOverallIn) bool {
			row, ok := sandboxbackend.Get(in.av.Backend)
			return in.av.Available || (ok && row.RunsOn(in.host))
		},
		decide: func(in sandboxOverallIn) sandbox.Availability { return in.av },
	},
	{
		name:  "nothing_runs_here",
		match: func(in sandboxOverallIn) bool { return len(in.here) == 0 },
		decide: func(in sandboxOverallIn) sandbox.Availability {
			return sandbox.Availability{
				Verdict: sandbox.VerdictUnsupportedPlatform, Backend: in.av.Backend,
				Reason: "no sandbox backend runs on " + string(in.host),
			}
		},
	},
	{
		// This host's own rows say why none is available: the verdict of the
		// first unavailable row whose driver is selected (one that is not
		// module_inactive), else of the first unavailable row, and every
		// row's reason.
		name:  "platform_rows",
		match: func(sandboxOverallIn) bool { return true },
		decide: func(in sandboxOverallIn) sandbox.Availability {
			out := sandbox.Availability{Verdict: sandbox.VerdictUnsupportedPlatform, Backend: in.here[0].ID}
			if b, ok := sandboxOverallPick(in.here); ok {
				out.Verdict, out.Backend = b.Verdict, b.ID
			}
			parts := make([]string, 0, len(in.here))
			for _, b := range in.here {
				if b.Available {
					parts = append(parts, b.ID+" (available, not chosen automatically)")
					continue
				}
				parts = append(parts, b.ID+" ("+b.Verdict+"): "+b.Reason)
			}
			out.Reason = "no sandbox backend is available on " + string(in.host) + ": " + strings.Join(parts, "; ")
			return out
		},
	},
}

// sandboxOverallPick is the row whose verdict the platform_rows rule
// reports: the first unavailable row that is not module_inactive, else the
// first unavailable row with a verdict.
func sandboxOverallPick(here []dashapi.SandboxBackendAvail) (dashapi.SandboxBackendAvail, bool) {
	for _, selected := range []bool{true, false} {
		for _, b := range here {
			if b.Available || b.Verdict == "" || (selected && b.Verdict == verdictModuleInactive) {
				continue
			}
			return b, true
		}
	}
	return dashapi.SandboxBackendAvail{}, false
}

// sandboxPlatformOverall is the overall verdict for host over the probe so
// far and the rendered rows (sandboxOverallRules).
func sandboxPlatformOverall(av sandbox.Availability, backends []dashapi.SandboxBackendAvail, host sandboxbackend.HostKind) sandbox.Availability {
	in := sandboxOverallIn{av: av, host: host}
	for _, b := range backends {
		if row, ok := sandboxbackend.Get(b.ID); ok && row.Offered() && row.RunsOn(host) {
			in.here = append(in.here, b)
		}
	}
	for _, rule := range sandboxOverallRules {
		if rule.match(in) {
			return rule.decide(in)
		}
	}
	return av
}

// sandboxBackendList renders every registry row for the probe API.
func sandboxBackendList(cfg config.TerminalSandboxConfig, av sandbox.Availability, sources []string, tier vocab.Tier) []dashapi.SandboxBackendAvail {
	return sandboxBackendListWith(cfg, av, sources, tier, nil)
}

// sandboxBackendListWith is sandboxBackendList with the registered drivers'
// probes (lane SBX-P3A); a driver row's version is its own probe's.
func sandboxBackendListWith(cfg config.TerminalSandboxConfig, av sandbox.Availability, sources []string, tier vocab.Tier, drivers map[string]sandboxselect.Probe) []dashapi.SandboxBackendAvail {
	host := sandboxHostKind()
	var out []dashapi.SandboxBackendAvail
	for _, id := range sandboxbackend.IDs() {
		row, _ := sandboxbackend.Get(id)
		e := dashapi.SandboxBackendAvail{
			ID: row.ID, Label: row.Label, Class: string(row.Iso.Class), Location: string(row.Iso.Location),
			Maturity: string(row.Maturity), Phase: row.Phase, Component: sandboxComponent,
		}
		for _, t := range row.Net.Egress {
			e.Egress = append(e.Egress, string(t))
		}
		if v, ok := row.VerificationOn(host); ok {
			e.Verification, e.RegisterRef = string(v.Kind), v.RegisterRef
		}
		if p, ok := drivers[id]; ok {
			e.Hint = p.Hint
		}
		res := sandboxselect.Select(sandboxSelectInputWith(cfg, av, sources, id, tier, drivers))
		if res.Chosen != nil {
			e.Available, e.Beta = true, res.Chosen.Beta
			e.Version = av.BackendVersion
			if p, ok := drivers[id]; ok {
				e.Version = p.Version
			}
		} else if len(res.Drops) > 0 {
			d := res.Drops[0]
			e.Verdict, e.Rule, e.Reason = d.Verdict, d.Rule, d.Reason
			e.Beta = vocab.Verification(e.Verification).IsBeta()
		}
		if row.Offered() {
			e.CaptureByTier = map[string]string{}
			custody := sandboxRequestCustody(cfg, row)
			for t, r := range sandboxselect.CaptureByTier(row, custody, true, row.Iso.Location != vocab.LocationRemote || hostedCredentialInReach(custody), cfg.EffectiveProviderDirect()) {
				e.CaptureByTier[string(t)] = sandboxselect.CaptureLabel(r)
			}
		}
		out = append(out, e)
	}
	return out
}

// sourceIDs returns the available workspace source ids.
func sourceIDs(src []dashapi.SandboxSourceAvail) []string {
	var out []string
	for _, s := range src {
		if s.Available {
			out = append(out, s.ID)
		}
	}
	return out
}

// sandboxRunCapture computes the capture level of a bwrap run on tier for a
// tool (section 4.4): the tool's bound state holds its own credential, so a
// credential is in reach; whether the tool is proxy-routed is its registry
// proxy capability, never its name. providerDirect is the organization's
// direct provider egress posture in force (DEC-9,
// config.TerminalSandboxConfig.EffectiveProviderDirect).
func sandboxRunCapture(proxyRouted bool, tier vocab.Tier, providerDirect vocab.ProviderDirect) sandboxselect.CaptureResult {
	row, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	return sandboxRunCaptureFor(row, proxyRouted, tier, providerDirect)
}

// sandboxRunCaptureFor is sandboxRunCapture on any row (a driver's).
func sandboxRunCaptureFor(row sandboxbackend.Capability, proxyRouted bool, tier vocab.Tier, providerDirect vocab.ProviderDirect) sandboxselect.CaptureResult {
	return sandboxselect.ComputeCapture(sandboxselect.CaptureInput{
		Row: row, Tier: tier, Custody: vocab.CustodyHostBound,
		ProxyRouted: proxyRouted, CredentialInReach: true,
		ProviderDirect: providerDirect,
	})
}

// proxyUpstreamHosts lists the host names of the proxy's configured
// upstreams ([proxy.upstreams] and [proxy.agent_upstreams]), sorted and
// deduplicated; loopback and unparsable entries are skipped. They join the
// gateway's model-provider block, so the set has one owner per source.
func proxyUpstreamHosts(p config.ProxyConfig) []string {
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			return
		}
		h := strings.ToLower(u.Hostname())
		if h == "" || h == "localhost" || seen[h] {
			return
		}
		if ip := net.ParseIP(h); ip != nil {
			return // a literal IP is refused by the block's literal-IP rule anyway
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, v := range p.Upstreams {
		add(v)
	}
	for _, v := range p.AgentUpstreams {
		add(v)
	}
	sort.Strings(out)
	return out
}

// bindSandboxCapability binds the store's sandbox capability seam (the
// SandboxPostureRow aggregate, sandbox plan v2 section 8.4) while the
// Sandboxes and VMs module is active and a prober exists. The capability is
// read from the probe's backends[] rows on each push (the probe caches for
// its own TTL), so it follows a bwrap installed or removed after start.
func bindSandboxCapability(ctx context.Context, st *store.Store, active bool, prober dashapi.SandboxProber) {
	if st == nil {
		return
	}
	if !active || prober == nil {
		st.SetSandboxCapabilityProvider(nil)
		return
	}
	st.SetSandboxCapabilityProvider(func() (orgcontract.SandboxCapabilityRow, bool) {
		av := prober.ProbeSandbox(ctx)
		row := sandboxCapabilityFrom(av)
		// The managed body keys this node refused, by name and closed
		// reason (SBX-P2E): nil unless a managed body is in force.
		row.ManagedRefused = sandboxManagedRefusedForPush(ctx)
		return row, true
	})
}

// sandboxCapabilityFrom reduces a probe answer to the enum-only capability:
// the available backend ids, the strongest class they build, whether one of
// them computes full capture on the configured tier, and whether every one
// of them is beta.
func sandboxCapabilityFrom(av dashapi.SandboxAvailability) orgcontract.SandboxCapabilityRow {
	var out orgcontract.SandboxCapabilityRow
	best := -1
	allBeta := true
	for _, b := range av.Backends {
		if !b.Available {
			continue
		}
		out.Backends = append(out.Backends, b.ID)
		if r := vocab.IsoClass(b.Class).Rank(); r > best {
			best, out.MaxClass = r, b.Class
		}
		if strings.HasPrefix(b.CaptureByTier[av.Egress], string(vocab.CaptureFull)) {
			out.FullCapture = true
		}
		allBeta = allBeta && b.Beta
	}
	out.Beta = len(out.Backends) > 0 && allBeta
	return out
}

// sandboxNativeVerdict judges tool's own sandbox inside the bwrap layer on
// tier (nesting rows N11 to N14) from the integration side table, reduced
// to capability facts here at the boundary. judged is false for a native
// sandbox that is off by default: Observer cannot know whether the user
// turned it on, so it neither refuses nor records a state for it.
func sandboxNativeVerdict(tool string, tier vocab.Tier) (sandboxselect.NativeVerdict, bool) {
	row, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	return sandboxNativeVerdictFor(row, tool, tier)
}

// sandboxNativeVerdictFor is sandboxNativeVerdict inside any row's layer.
// A sandbox is judged when the agent turns it on by default, when a vendor
// managed policy forces it on (vendor_forced_native, lane SBX-P3D), or when
// the user turned it on and the row has a grounded per-run weak mode.
func sandboxNativeVerdictFor(row sandboxbackend.Capability, tool string, tier vocab.Tier) (sandboxselect.NativeVerdict, bool) {
	n, ok := integration.NativeSandboxFor(tool)
	if !ok {
		return sandboxselect.NativeNesting(row, tier, sandboxselect.NativeSandbox{}), true
	}
	f := nativeFactsFor(n)
	if !n.DefaultOn && !f.forced && !(f.userOn && n.WeakMode.PerRun()) {
		return sandboxselect.NativeVerdict{}, false
	}
	return sandboxselect.NativeNesting(row, tier, sandboxselect.NativeSandbox{
		Present:        true,
		NeedsFreshProc: n.NeedsAny(integration.NeedFreshProc),
		NeedsDevNetTUN: n.NeedsAny(integration.NeedDevNetTUN),
		AppContainer:   n.NeedsAny(integration.NeedAppContainer),
		PerRunDisable:  n.Disable.PerRun(),
		PerRunWeak:     n.WeakMode.PerRun(),
		UserOn:         f.userOn,
		VendorForced:   f.forced,
		ForcedPolicy:   f.policy,
		HostOS:         runtime.GOOS,
	}), true
}

// sandboxNativeRefusal turns a verdict into the launch's answer: a refusal
// for tool_conflict; for a verdict that turns the agent's sandbox off or
// weak, nil when the row's switch is a grounded per-run flag, which the
// launch composition appends to the agent's own arguments from the same
// recorded state (integration.NativeSwitchArgsForState, lane SBX-P3D), so
// the evidence disabled_by_observer or weak never exists without the
// switch. An environment switch is applied only by the driver that owns
// the box environment (Seatbelt); the rows that call this refuse it.
func sandboxNativeRefusal(tool string, v sandboxselect.NativeVerdict) error {
	switch v.Outcome {
	case sandboxselect.NativeRefuse:
		return fmt.Errorf("terminal_sandbox: %s (%s): %s", sandboxselect.VerdictToolConflict, v.Rule, v.Reason)
	case sandboxselect.NativeDisable, sandboxselect.NativeWeakMode:
		args, err := integration.NativeSwitchArgsForState(tool, sandboxselect.NativeStateFor(v))
		if err != nil || len(args) == 0 {
			return fmt.Errorf("terminal_sandbox: %s (%s): %s's own sandbox must be changed for this run, and it has no grounded per-run command-line switch this backend can apply", sandboxselect.VerdictToolConflict, v.Rule, tool)
		}
		return nil
	default:
		return nil
	}
}
