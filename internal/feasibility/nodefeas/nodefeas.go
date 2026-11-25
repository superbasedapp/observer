package nodefeas

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/feasibility"
)

// ComponentsStep is where a component choice is made on a node.
const ComponentsStep = "Settings > Components"

// componentReason is one row of the reason table.
type componentReason struct {
	reason components.Reason
	// text renders the reason for component id (because names the other
	// component when the reason is about a dependency).
	text func(id, because string) string
	fix  func(id, because string) string
	step string
}

// componentReasons is walked in order; the first row whose reason matches
// decides the copy (CLAUDE.md module rule 5). A reason with no row is
// feasible (active, selected, available).
var componentReasons = []componentReason{
	{
		reason: components.ReasonNotCompiled,
		text:   func(id, _ string) string { return id + " is not in this build; " + components.DistrosHaving(id) },
		fix:    func(string, string) string { return "Install a build that includes it." },
		step:   ComponentsStep,
	},
	{
		reason: components.ReasonRequiresNotCompiled,
		text: func(id, b string) string {
			return id + " needs " + b + ", which is not in this build; " + components.DistrosHaving(b)
		},
		fix:  func(string, string) string { return "Install a build that includes both." },
		step: ComponentsStep,
	},
	{
		reason: components.ReasonDenied,
		text:   func(id, _ string) string { return id + " is switched off by [components].remove" },
		fix:    func(id, _ string) string { return "Add " + id + " back in Settings > Components." },
		step:   ComponentsStep,
	},
	{
		reason: components.ReasonDeniedDependency,
		text:   func(id, b string) string { return id + " needs " + b + ", which is switched off" },
		fix:    func(_, b string) string { return "Add " + b + " first." },
		step:   ComponentsStep,
	},
	{
		reason: components.ReasonAboveCeiling,
		text:   func(id, _ string) string { return id + " is outside this machine's local component ceiling" },
		fix:    func(string, string) string { return "Ask the administrator of this machine to widen the ceiling." },
		step:   "the local component ceiling (managed config)",
	},
	{
		reason: components.ReasonPolicyDenied,
		text:   func(id, _ string) string { return id + " is denied by your organization's component policy" },
		fix:    func(string, string) string { return "Request it from your organization." },
		step:   "Request from your organization",
	},
	{
		reason: components.ReasonPolicyUnlisted,
		text:   func(id, _ string) string { return id + " is not allowed by your organization's component policy yet" },
		fix:    func(string, string) string { return "Request it from your organization." },
		step:   "Request from your organization",
	},
	{
		reason: components.ReasonPolicyRequired,
		text: func(id, _ string) string {
			return id + " is required by your organization's component policy but not in this build; " + components.DistrosHaving(id)
		},
		fix: func(string, string) string {
			return "Install a build that includes it (your organization requires it)."
		},
		step: ComponentsStep,
	},
}

// ComponentVerdicts evaluates every resolver decision as a chooser option:
// configured is whether the operator selected it; an infeasible one carries
// the reason, the fix and the step. Feasible rows are returned too, so a
// chooser renders every option from one list.
func ComponentVerdicts(decisions []components.Decision, selected []string) []feasibility.Verdict {
	sel := map[string]bool{}
	for _, id := range selected {
		sel[id] = true
	}
	out := make([]feasibility.Verdict, 0, len(decisions))
	for _, d := range decisions {
		v := feasibility.Verdict{ID: d.ID, Option: titleOf(d.ID), Configured: sel[d.ID], Feasible: true}
		if d.State == components.StateAbsent || d.State == components.StateBlocked || d.State == components.StateRequiredMissing {
			for _, r := range componentReasons {
				if r.reason != d.Reason {
					continue
				}
				v.Feasible = false
				v.Cause = d.ID
				if d.Because != "" {
					v.Cause = d.Because
				}
				v.Reason = r.text(d.ID, d.Because)
				v.Fix = r.fix(d.ID, d.Because)
				v.FixStep = r.step
				break
			}
		}
		switch {
		case v.Feasible:
			v.Effect = feasibility.EffectNone
		case v.Configured:
			v.Effect = feasibility.EffectOff
		default:
			v.Effect = feasibility.EffectUnavailable
		}
		out = append(out, v)
	}
	return out
}

func titleOf(id string) string {
	if c, ok := components.Get(id); ok && c.Title != "" {
		return c.Title + " (" + id + ")"
	}
	return id
}

// Host fact ids SettingRules may need besides component ids. The caller
// sets Input.Unavailable[fact] to why the fact does not hold.
const (
	FactRemoteReady  = "host.remote-ready"
	FactSandboxReady = "host.sandbox-ready"
)

// SettingRules are the node settings that need a component or a host fact.
// The daemon evaluates them at start (Effect off: start with the setting
// off and one reason; nothing here is unsafe to run without), doctor prints
// the infeasible ones, and the dashboard settings page shows each one
// unavailable with the reason.
var SettingRules = []feasibility.Rule{
	{
		ID: "dashboard.addr.nonloopback", Option: "Dashboard on a non-loopback address ([dashboard].addr)",
		Needs: []string{"remote", FactRemoteReady},
		Fix:   "Bind 127.0.0.1, or turn on remote access (the remote component and [remote]) so the dashboard is served through it.", FixStep: "Settings > Remote",
	},
	{
		ID: "terminal.sandbox.enabled", Option: "Sandboxed terminals ([terminal.sandbox].enabled)",
		Needs: []string{"terminals.sandbox", FactSandboxReady}, FixStep: "Terminals > Settings > Sandbox isolation",
	},
	{
		ID: "observability.admission.enabled", Option: "Input admission ([observability.admission].enabled)",
		Needs: []string{"obs"}, FixStep: ComponentsStep,
	},
	{
		ID: "exporter.otel.enabled", Option: "OpenTelemetry export ([exporter.otel].enabled)",
		Needs: []string{"export.otel"}, FixStep: ComponentsStep,
	},
	{
		ID: "archive.enabled", Option: "Corpus archive ([archive].enabled)",
		Needs: []string{"archive"}, FixStep: ComponentsStep,
	},
	{
		ID: "digest.enabled", Option: "Email digest ([digest].enabled)",
		Needs: []string{"notify.email"}, FixStep: ComponentsStep,
	},
	// Lane MP-L1I (T-715): the settings of the components that round made
	// L1 (each can now be compiled out).
	{
		ID: "routing.enabled", Option: "Model routing ([routing].enabled)",
		Needs: []string{"proxy.routing"}, FixStep: ComponentsStep,
	},
	{
		ID: "remote.enabled", Option: "Remote access ([remote].enabled)",
		Needs: []string{"remote"}, FixStep: ComponentsStep,
	},
	{
		ID: "remote.notify.enabled", Option: "Session-finished notifications ([remote.notify].enabled)",
		Needs: []string{"remote"}, FixStep: ComponentsStep,
	},
	{
		ID: "mcp_relay.enabled", Option: "Agent Access MCP relay ([mcp_relay].enabled)",
		Needs: []string{"agentaccess.relay"}, FixStep: ComponentsStep,
	},
	{
		ID: "cloud.auto_sync", Option: "Cloud auto-sync ([cloud].auto_sync)",
		Needs: []string{"cloud.intelligence"}, FixStep: ComponentsStep,
	},
}

// Settings evaluates SettingRules. on are the settings the config turns on;
// decisions are the resolver's (a component that is not active is
// unavailable with the reason table's sentence); facts maps a host fact id
// to why it does not hold ("" or missing = holds).
func Settings(on map[string]bool, decisions []components.Decision, facts map[string]string) feasibility.Report {
	in := feasibility.Input{Configured: on, Unavailable: map[string]string{}, Fixes: map[string]string{}}
	for _, v := range ComponentVerdicts(decisions, nil) {
		if !v.Feasible {
			in.Unavailable[v.ID] = v.Reason
			in.Fixes[v.ID] = v.Fix
		}
	}
	active := map[string]bool{}
	for _, d := range decisions {
		active[d.ID] = d.State == components.StateActive
	}
	for _, r := range SettingRules {
		for _, n := range r.Needs {
			if _, known := active[n]; known && !active[n] && in.Unavailable[n] == "" {
				in.Unavailable[n] = n + " is installed but not active"
				in.Fixes[n] = "Turn " + n + " on in " + ComponentsStep + "."
			}
		}
	}
	for k, why := range facts {
		if strings.TrimSpace(why) != "" {
			in.Unavailable[k] = why
		}
	}
	return feasibility.Evaluate(SettingRules, in)
}
