package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// components_gate.go is the daemon and CLI side of the L2 "installed but
// inert" gate (modular packaging plan section 4, phase P1, lane MP-GATE).
// Every daemon goroutine, builder and CLI verb of an optional component
// consults ONE predicate, componentstate.Snapshot.Active, through the data
// tables below; an optional module's rows (moduleGates) consult its
// fail-invisible twin, Snapshot.ModuleActive. An install with no
// [components] block resolves every compiled component active, so nothing
// here changes what it runs.

// daemonLoopComponents maps every named core `observer start` goroutine
// (gatedGroup.Go names in start.go) to the components it serves. An empty
// list is core: it always runs. A loop serving several components runs
// when any of them is active. An optional module's loops are rows of
// moduleGates instead. TestEveryDaemonLoopIsClassified keeps both tables in
// step with every gatedGroup.Go call in this package; a name neither table
// classifies does not start.
var daemonLoopComponents = map[string][]string{
	"watcher":          nil,
	"surface-enricher": nil,
	"spend-verdicts":   nil,
	"db-maintenance":   nil,
	"retention":        nil,
	"wal-watchdog":     nil,
	"temp-watchdog":    nil,
	// T-849: periodic hook re-registration + the managed-integrity report on
	// the policy-state heartbeat. Core: it gates itself on integration.hooks
	// (autoRegisterHooks) and on a managed enrolment.
	"hook-maintenance": nil,
	// The lifecycle hook spool drainer ingests rows hooks already wrote; a
	// spool left behind by hooks that were since removed still ingests.
	"hook-lifecycle": nil,
	// Plans & limits reads the local database only until an account is added.
	"plans": nil,

	"proxy":          {"capture.proxy"},
	"dashboard":      {"ui.dashboard"},
	"guidance-scan":  {"analytics"},
	"session-score":  {"analytics"},
	"advisor-digest": {"analytics"},
	"commit-scan":    {"projects"},
	// Delivery (D-689) serves the Projects page; it reads the local
	// database only until a code host is connected or a mirror scheduled.
	"delivery":            {"projects"},
	"codeintel":           {"codeintel"},
	"cloud-auto-sync":     {"cloud.intelligence"},
	"cloud-auto-enrich":   {"cloud.intelligence"},
	"pricing-auto-sync":   {"egress.pricing-feed"},
	"attach-socket":       {"terminals"},
	"tailnet-backend":     {"remote"},
	"mcp-relay":           {"agentaccess.relay"},
	"guard-cloud":         {"guard.cloud"},
	"otel-exporter":       {"export.otel"},
	"guard-otel-tail":     {"export.otel"},
	"otlp-receiver":       {"ingest.otlp", "obs"},
	"browser-listener":    {"capture.browser"},
	"obs-alerts":          {"obs"},
	"guard-posture":       {"guard"},
	"guard-git-aliases":   {"guard"},
	"guard-user-policy":   {"guard"},
	"guard-baseline-scan": {"guard"},
	"digest":              {"notify.email"},
	"process-observer":    {"processobs"},
	"node-intervention":   {"intervention"},

	"governance-sidecar":     {"org.client"},
	"budget-warn":            {"org.client"},
	"policy-state-reporter":  {"org.client"},
	"org-push":               {"org.client"},
	"policy-freshness":       {"org.client"},
	"activity-stamp":         {"org.client"},
	"org-policy-bundle-poll": {"org.client"},
	// The project audience matcher (security plan section 7.11, lane
	// sec-p): writes match records only once the org delivered a v3
	// project-scoped bundle.
	"project-audience-match": {"org.client"},
	"policy-resource-poller": {"org.client"},
	"grant-renewal":          {"org.client"},
}

// gatedGroup is namedGroup behind the component gate: Go starts a loop only
// when its classification (loopClass) says one of its components is active,
// and says
// once on stderr which loops an inactive component kept from starting.
type gatedGroup struct {
	ng   namedGroup
	snap componentstate.Snapshot
	out  io.Writer

	mu      sync.Mutex
	skipped []string
}

func newGatedGroup(ng namedGroup, snap componentstate.Snapshot, out io.Writer) *gatedGroup {
	return &gatedGroup{ng: ng, snap: snap, out: out}
}

// Go runs fn as the named loop when its components allow it. A name no
// table classifies is not started (fail closed, lane OPTMOD): a loop must
// say which component it serves before it can run, and
// TestEveryDaemonLoopIsClassified keeps every call site classified.
func (g *gatedGroup) Go(name string, fn func() error) {
	if !loopAllowed(g.snap, name) {
		g.mu.Lock()
		g.skipped = append(g.skipped, name)
		g.mu.Unlock()
		ids, _, ok := loopClass(name)
		if !ok {
			fmt.Fprintf(g.out, "WARN components: %s not started (daemon loop not classified in cmd/observer/components_gate.go; a build defect, please report it)\n", name)
			return
		}
		fmt.Fprintf(g.out, "components: %s not started (%s)\n", name, loopSkipReason(g.snap, ids))
		return
	}
	g.ng.Go(name, fn)
}

// loopSkipReason says why a gated loop did not start (D-514): a component
// compiled out of this binary is "not in this build" with the builds that
// include it; one that is merely inactive points at Settings > Components.
func loopSkipReason(snap componentstate.Snapshot, ids []string) string {
	var absent, inactive []string
	for _, id := range ids {
		if d, ok := snap.Decision(id); ok && d.State == components.StateAbsent {
			absent = append(absent, id)
		} else {
			inactive = append(inactive, id)
		}
	}
	var parts []string
	for _, id := range absent {
		parts = append(parts, id+" is not in this build; "+components.DistrosHaving(id))
	}
	if len(inactive) > 0 {
		parts = append(parts, strings.Join(inactive, " / ")+" inactive; "+components.SettingsHint())
	}
	return strings.Join(parts, "; ")
}

// loopAllowed is the per-loop decision. An unclassified name does not run
// (fail closed): before lane OPTMOD it ran, so a module loop that forgot its
// row started even while its module was off. A core row runs while any of
// its components is active (Snapshot.AnyActive; no components means always);
// a module row runs only while its component is active under
// Snapshot.ModuleActive, so a misspelt id keeps the loop stopped.
func loopAllowed(snap componentstate.Snapshot, name string) bool {
	ids, module, ok := loopClass(name)
	switch {
	case !ok:
		return false
	case module:
		return snap.AnyModuleActive(ids...)
	default:
		return snap.AnyActive(ids...)
	}
}

// loopClass classifies a named daemon loop: the components it serves,
// whether it is an optional module's loop (moduleGates) rather than a core
// row (daemonLoopComponents), and whether any table names it at all.
func loopClass(name string) (ids []string, module, ok bool) {
	if ids, ok := daemonLoopComponents[name]; ok {
		return ids, false, true
	}
	for _, row := range moduleGates {
		for _, l := range row.loops {
			if l == name {
				return []string{row.component}, true, true
			}
		}
	}
	return nil, false, false
}

// componentSnapshotFor resolves the component state a process should use
// for configPath. A config that does not load resolves the legacy
// everything-active snapshot, the same fail-open posture every other start
// gate takes on a missing config.
func componentSnapshotFor(configPath string) componentstate.Snapshot {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return componentstate.Legacy()
	}
	return componentSnapshotForConfig(cfg)
}

// reportComponentIssues prints the snapshot's selection problems once at
// start. An unconfigured snapshot has none, so a legacy install prints
// nothing. A distro build (phase P3) always prints the summary line, block
// or not: its base is its distro, not everything compiled, and the
// operator should see that at start.
func reportComponentIssues(w io.Writer, snap componentstate.Snapshot) {
	for _, is := range componentIssues(snap) {
		fmt.Fprintf(w, "WARN components: %s\n", is)
	}
	if snap.Configured || snap.Base != componentstate.BaseAll {
		active := 0
		for _, id := range snap.ActiveIDs() {
			if moduleRuleActive(snap, id) {
				active++
			}
		}
		fmt.Fprintf(w, "components: %d of %d compiled components active (base %s; observer components status)\n",
			active, len(snap.Compiled), snap.Base)
	}
}

// moduleRuleActive is the one activity answer for node component id under
// snap with the optional modules' own rules applied (a moduleGates row's
// active, today the sandbox module's root removal, sandboxModuleActive,
// plans decision log P-057): id is active when core says so and no row with
// its own rule, naming id or a dotted parent of it, says the module is off.
// The status text (componentIssues, componentStateView) and config.Load's
// component gate (the init below) read it, so a removed module root is off
// in every one of them, not only in the daemon's inert overlay.
func moduleRuleActive(snap componentstate.Snapshot, id string) bool {
	if !snap.ModuleActive(id) {
		return false
	}
	for _, g := range moduleGates {
		if g.active != nil && (id == g.component || strings.HasPrefix(id, g.component+".")) && !g.active(snap) {
			return false
		}
	}
	return optInActive(snap, id)
}

// componentOptInRules are optional modules' opt-in rules for single
// components, registered from the module's own files so no core function
// names one (today the sandbox drivers: a driver runs only when a
// [components] block selects it, sandboxDriverSelected). Each answers
// whether it governs id and, when it does, whether id is active. Without
// them `observer components status` counted the OCI driver active on a
// node with no [components] block, while the sandbox module itself left
// it off (live check InstaBox 2026-10-22, D1).
var componentOptInRules []func(snap componentstate.Snapshot, id string) (governs, active bool)

// componentOptInBecause is the status text of a component an opt-in rule
// keeps off.
const componentOptInBecause = "until a [components] block selects it (it is opt-in)"

// optInActive applies the registered opt-in rules to id.
func optInActive(snap componentstate.Snapshot, id string) bool {
	for _, r := range componentOptInRules {
		if governs, active := r(snap, id); governs && !active {
			return false
		}
	}
	return true
}

// moduleRulesOff lists the module roots that core keeps active but whose own
// rule switches them off under snap, in table order.
func moduleRulesOff(snap componentstate.Snapshot) []string {
	var out []string
	for _, g := range moduleGates {
		if g.active != nil && snap.ModuleActive(g.component) && !g.active(snap) {
			out = append(out, g.component)
		}
	}
	return out
}

// moduleRootOf returns the root of roots that id is or is a dotted child of.
func moduleRootOf(id string, roots []string) string {
	for _, r := range roots {
		if id == r || strings.HasPrefix(id, r+".") {
			return r
		}
	}
	return ""
}

// componentIssues is snap.Issues as the status surfaces print them: core's
// "stays active because <child> requires it" line for a module root that its
// own rule switched off is replaced by one that says the module is off, with
// the children it takes along.
func componentIssues(snap componentstate.Snapshot) []string {
	off := moduleRulesOff(snap)
	if len(off) == 0 {
		return snap.Issues
	}
	out := make([]string, 0, len(snap.Issues)+len(off))
	for _, is := range snap.Issues {
		keep := true
		for _, r := range off {
			if strings.HasPrefix(is, fmt.Sprintf("[components] remove: %q stays active because ", r)) {
				keep = false
			}
		}
		if keep {
			out = append(out, is)
		}
	}
	for _, r := range off {
		var children []string
		for _, id := range snap.ActiveIDs() {
			if strings.HasPrefix(id, r+".") {
				children = append(children, id)
			}
		}
		line := fmt.Sprintf("[components] remove: %q switches the module off", r)
		if len(children) > 0 {
			line += fmt.Sprintf(", with %s", strings.Join(children, ", "))
		}
		out = append(out, line+"; its config sections are not used while it is off")
	}
	sort.Strings(out)
	return out
}

// componentStateView is snap.View() with the modules' own rules applied: a
// module root its rule switched off, and its dotted children, read as not
// active (available, not_selected), as does a component an opt-in rule
// keeps off (componentOptInRules); the active count follows, and the
// issues are componentIssues.
func componentStateView(snap componentstate.Snapshot) componentstate.View {
	v := snap.View()
	off := moduleRulesOff(snap)
	if len(off) > 0 {
		v.Issues = componentIssues(snap)
	}
	for i, r := range v.Components {
		if r.State != components.StateActive {
			continue
		}
		because := ""
		switch {
		case moduleRootOf(r.ID, off) != "":
		case !optInActive(snap, r.ID):
			because = componentOptInBecause
		default:
			continue
		}
		v.Components[i].State = components.StateAvailable
		v.Components[i].Reason = components.ReasonNotSelected
		v.Components[i].Because = because
		v.ActiveCount--
	}
	return v
}

func init() {
	// config.Load's component gate (config.SetComponentGate), registered
	// over internal/componentstate's (which this package's imports
	// initialise first): the same core resolution with the modules' own
	// rules applied, so `remove = ["terminals.sandbox"]` sets aside an
	// invalid [terminal.sandbox] (and [terminal.sandbox.oci]) exactly as
	// the daemon's inert overlay switches the module off.
	config.SetComponentGate(func(sel config.ComponentsConfig, id string) bool {
		return moduleRuleActive(componentstate.Resolve(sel, nil), id)
	})
}

// inertOverlay is the start-time config overlay of an inactive component:
// the switches of the builders `observer start` itself runs, turned off so
// each builder takes its existing honest-disabled path (no stack, no
// listener, no loop). It is applied to the daemon's in-memory copy only and
// never written. Loops that reload their own config are gated by
// daemonLoopComponents instead.
var inertOverlay = []struct {
	component string
	apply     func(*config.Config)
}{
	{"terminals", func(c *config.Config) {
		c.Handoff.AllowDashboardLaunch = false
		c.Terminal.Attach.Enabled = false
	}},
	{"remote", func(c *config.Config) { c.Remote.Enabled = false }},
	{"export.otel", func(c *config.Config) { c.Exporter.OTel.Enabled = false }},
	{"obs", func(c *config.Config) { c.Observability.Enabled = false }},
	{"capture.browser", func(c *config.Config) { c.Browser.Enabled = false }},
	{"org.update", func(c *config.Config) { c.Update.Enabled = false }},
	{"integration.shell-wrap", func(c *config.Config) { c.ShellWrap.Enabled = false }},
}

// moduleGate is the daemon-side contract of one OPTIONAL MODULE component
// (lane OPTMOD: the security pillar's `security` rows and the sandbox
// module's `terminals.sandbox` rows): the named `observer start` loops it
// starts and the start-time switches its inert overlay turns off. Both are
// gated by Snapshot.ModuleActive, so an id the catalog does not know keeps
// the loop stopped and the switches off ("fail invisible").
type moduleGate struct {
	// component is the node catalog id the row gates (a module root or one
	// of its drivers).
	component string
	// loops are the namedGroup names the component's goroutines start under.
	loops []string
	// inert switches the component's start-time config off on the daemon's
	// in-memory copy (never written); nil when it has none.
	inert func(*config.Config)
	// active is the module's own activity rule when it has one (the sandbox
	// module's root removal, sandboxModuleActive, plans decision log P-057);
	// nil means Snapshot.ModuleActive.
	active func(componentstate.Snapshot) bool
}

// isActive applies the row's activity rule to snap.
func (g moduleGate) isActive(snap componentstate.Snapshot) bool {
	if g.active != nil {
		return g.active(snap)
	}
	return snap.ModuleActive(g.component)
}

// moduleGates is the module table. A new optional module adds one row per
// component that starts a loop or has a start-time switch, and touches no
// other line here. The rows stay in this core file, not in a module's own
// build-tagged file, because a build that compiles the module out still
// loads its config section and must still switch it off.
var moduleGates = []moduleGate{
	{
		// Sandboxes and VMs (sandbox plan v2 section 11). Phase P1a adds no
		// named daemon loop: the probe, `observer sandbox status` and the
		// doctor rows all run on request. The master switch is its one
		// start-time switch, so a [terminal.sandbox] enabled = true left in
		// the file does nothing while the module is inactive or not in this
		// build. The isolation engine (component `isolation`) has no loop
		// and no start-time switch either: its one surface, the one-shot
		// factory, is gated where it is handed out (isolation_wire.go).
		// A later phase that starts a loop (the engine event stream, the
		// orphan sweep, image upkeep) adds it to this row's loops.
		component: "terminals.sandbox",
		inert:     func(c *config.Config) { c.Terminal.Sandbox.Enabled = false },
		// `remove = ["terminals.sandbox"]` switches the module off even
		// while its selected driver child keeps it active in the core
		// resolver (P-057).
		active: sandboxModuleActive,
	},
	{
		// Code security (security pillar plan section 4.3): the posture
		// writer and the quick-scan endpoint. [security] has no start-time
		// switch of its own (the module is on or off as a component), and
		// a bad [security] value of an inactive module is set aside by
		// config.Load (component_sections.go).
		component: "security",
		loops:     []string{"security.posture", "security.quickscan", "security.exceptions", "security.notify"},
	},
	{
		// Secret detection (security Phase C): the post-write feed, which
		// also publishes the commit scanner's secret step.
		component: "security.secrets",
		loops:     []string{"security.postwrite"},
	},
	{
		// Repository trust (security pillar plan section 5.1): the config
		// baseline loop that snapshots each project's agent config files
		// and raises a finding per change.
		component: "security.trust",
		loops:     []string{"security.trust.baseline"},
	},
	{
		// Package checks (security pillar plan sections 5.4 and 8.3, Phase
		// D1): the hook's ask endpoint with the online lookups, and the
		// signed index refresh with the prefetch. [security.deps] online is
		// not a start-time switch: the loops still serve the offline index
		// and refuse every online query while it is off.
		component: "security.deps",
		loops:     []string{"security.deps.ask", "security.deps.feed"},
	},
	{
		// Dependency scanners (security pillar plan sections 4.4 and 8.4,
		// Phase D2): each driver's loop refreshes the local OSV databases
		// (behind the security.deps online gate) and scans active
		// projects' dependencies, one heavy scan at a time.
		component: "security.scan.scalibr",
		loops:     []string{"security.scan.scalibr"},
	},
	{
		component: "security.scan.osv",
		loops:     []string{"security.scan.osv"},
	},
	{
		// Custom scanners (security pillar plan sections 4.4 and 8.6, lane
		// sec-custom2): the scheduled-run loop, which runs nothing until
		// [security.custom] schedule_hours is set and holds on battery by
		// default. The component is opt-in (security_optin.go).
		component: "security.scan.custom",
		loops:     []string{"security.custom.schedule"},
	},
	{
		// Code rules (security pillar plan section 5.5, lane sec-g2): the
		// post-write, commit-diff and scheduled scans and the rule pack and
		// engine pins refresh, all in one loop that starts no process while
		// Opengrep is not installed. The component is opt-in
		// (security_optin.go).
		component: "security.scan.opengrep",
		loops:     []string{"security.scan.opengrep"},
	},
	{
		// IaC checks (security pillar plan 5.6 P2, lane GATES-SEC): one loop
		// per engine, post-write and scheduled scans, both off by default,
		// starting no process while the engine is not installed. Opt-in
		// (security_optin.go).
		component: "security.scan.trivy",
		loops:     []string{"security.scan.trivy"},
	},
	{
		component: "security.scan.kics",
		loops:     []string{"security.scan.kics"},
	},
	{
		// Code rule inferences, fix observations and unverified_fix (security
		// pillar plan 5.7 and 5.11 (a), lane sec-g5): one loop; its start
		// function also asks for a [components] block (fixObsSelected in
		// security_fixobs.go), so the legacy snapshot never starts it.
		component: "security.code",
		loops:     []string{"security.code.fixobs"},
	},
	{
		// AI change records (security pillar plan 7.10, lane sec-f2a): the
		// loop that publishes the record builder to the commit scanner's
		// per-commit seam and writes the consented git notes. Opt-in
		// (security_optin.go).
		component: "security.provenance",
		loops:     []string{"security.provenance"},
	},
}

// applyInertOverlay returns cfg with every inactive component's start-time
// switches off. A legacy snapshot returns cfg unchanged.
func applyInertOverlay(cfg config.Config, snap componentstate.Snapshot) config.Config {
	for _, row := range inertOverlay {
		if !snap.Active(row.component) {
			row.apply(&cfg)
		}
	}
	for _, row := range moduleGates {
		if row.inert != nil && !row.isActive(snap) {
			row.inert(&cfg)
		}
	}
	return cfg
}

// verbComponents maps every top-level verb an optional node component owns
// to that component: the catalog's Verbs (the one owner of verb ownership;
// the former override table was folded into the catalog, T-661) and every
// adapter's launcher subcommand from the integration registry.
func verbComponents() map[string]string {
	out := map[string]string{}
	for _, c := range components.ForBinary(components.BinaryNode) {
		if c.Class == components.ClassCore {
			continue
		}
		for _, v := range c.Verbs {
			out[v] = c.ID
		}
	}
	for _, tool := range integration.Tools() {
		c, ok := integration.For(tool)
		if !ok || c.Handoff.Launch == nil || c.Handoff.Launch.Subcommand == "" {
			continue
		}
		if _, known := components.Get(components.AdapterID(tool)); !known {
			continue
		}
		if _, taken := out[c.Handoff.Launch.Subcommand]; !taken {
			out[c.Handoff.Launch.Subcommand] = components.AdapterID(tool)
		}
	}
	return out
}

// gateComponentVerbs wraps every top-level verb of an optional component
// (and its subcommands) so it refuses with the component's state and the
// fix, exit code 3, when the component is not active (plan 7.3). The state
// is resolved when the verb runs, from the config the verb itself names
// with --config (else the default), so a bare CLI never trusts a
// daemon-written file.
func gateComponentVerbs(root *cobra.Command) {
	owners := verbComponents()
	for _, c := range root.Commands() {
		id, ok := owners[c.Name()]
		if !ok {
			continue
		}
		wrapVerbTree(c, id)
	}
}

// gateExempt are the command paths below the root that the verb gate never
// wraps (with their subcommands), each with its reason. Keep it short: an
// entry runs while its component is inactive, so it must be a command that
// reads and writes nothing of the node.
var gateExempt = map[string]string{
	// The CI check (security pillar plan section 7.9, phase F1) is
	// hermetic: it reads no Observer config, database, managed config or
	// OBSERVER_* variable. The gate would read all of them first (the
	// config, then the governed component state), so the claim would not
	// hold, and a runner's own config could refuse the check (lane sec-a2,
	// SEC-F1 audit). It is still absent from a build without the module.
	"security verify": "hermetic CI check",
}

// gateExempted reports whether c, as attached to its root, is a gateExempt
// command path.
func gateExempted(c *cobra.Command) bool {
	parts := strings.Fields(c.CommandPath())
	if len(parts) < 2 {
		return false
	}
	_, ok := gateExempt[strings.Join(parts[1:], " ")]
	return ok
}

func wrapVerbTree(c *cobra.Command, id string) {
	if gateExempted(c) {
		return
	}
	if c.RunE != nil || c.Run != nil {
		origE, orig := c.RunE, c.Run
		c.Run = nil
		c.RunE = func(cmd *cobra.Command, args []string) error {
			cfgPath := ""
			if f := cmd.Flags().Lookup("config"); f != nil {
				cfgPath = f.Value.String()
			}
			snap := componentSnapshotFor(cfgPath)
			switch {
			case snap.Active(id):
			case teardownVerb(cmd, id):
				// The component's own teardown step names this verb: it
				// undoes a write the component made, so it runs while the
				// component is inactive (the teardown preview tells the
				// operator to run it after removal).
				fmt.Fprintf(cmd.ErrOrStderr(), "components: %s is not active; running its teardown step\n", id)
			case offerActivation(cmd, snap, id, cfgPath):
				// T-734: turned on at the operator's yes; run the verb.
			default:
				fmt.Fprintln(cmd.ErrOrStderr(), snap.RefusalLine(id))
				// The line above is the whole message: no cobra error
				// banner, no usage.
				cmd.SilenceErrors, cmd.SilenceUsage = true, true
				if r := cmd.Root(); r != nil {
					r.SilenceErrors = true
				}
				return exitErr(componentstate.RefusalExitCode)
			}
			if origE != nil {
				return origE(cmd, args)
			}
			orig(cmd, args)
			return nil
		}
	}
	for _, sub := range c.Commands() {
		wrapVerbTree(sub, id)
	}
}

// teardownVerb reports whether cmd, as invoked, is the undo command one of
// component id's own teardown steps names (componentsvc.TeardownFor, the
// one owner of teardown steps; StepManual.Command). The command path must
// match exactly and every flag the step names must be set on the
// invocation, so `observer routing apply --tool claude-code --revert`
// passes while a plain `observer routing apply` (a write) stays refused.
// Without this, removing a component would refuse the very verb its
// teardown preview tells the operator to run (`observer mcp unwrap` for
// agentaccess.relay, T-681).
func teardownVerb(cmd *cobra.Command, id string) bool {
	got := strings.Fields(cmd.CommandPath())
	if len(got) < 2 {
		return false
	}
	got = got[1:] // drop the root's own name
	for _, st := range componentsvc.TeardownFor(id) {
		if st.Kind != componentsvc.StepManual || st.Command == "" {
			continue
		}
		path, flags := teardownCommandShape(st.Command)
		if strings.Join(path, " ") != strings.Join(got, " ") {
			continue
		}
		set := true
		for _, f := range flags {
			fl := cmd.Flags().Lookup(f)
			if fl == nil || !fl.Changed {
				set = false
				break
			}
		}
		if set {
			return true
		}
	}
	return false
}

// teardownCommandShape splits a teardown step's command line ("observer mcp
// unwrap", "observer routing apply --tool claude-code --revert") into its
// verb path after the binary name and the flag names it sets.
func teardownCommandShape(line string) (path, flags []string) {
	fields := strings.Fields(line)
	if len(fields) > 0 {
		fields = fields[1:] // the binary name
	}
	inFlags := false
	for _, f := range fields {
		if strings.HasPrefix(f, "--") {
			inFlags = true
			name, _, _ := strings.Cut(strings.TrimPrefix(f, "--"), "=")
			flags = append(flags, name)
			continue
		}
		if !inFlags {
			path = append(path, f)
		}
	}
	return path, flags
}

// gatedVerbNames lists the verbs gateComponentVerbs wraps, sorted (tests
// and `observer components status`).
func gatedVerbNames(root *cobra.Command) []string {
	owners := verbComponents()
	var out []string
	for _, c := range root.Commands() {
		if _, ok := owners[c.Name()]; ok {
			out = append(out, c.Name())
		}
	}
	sort.Strings(out)
	return out
}
