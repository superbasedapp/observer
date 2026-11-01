// pi_route.go — the `observer pi` provider/model routing decision.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// piObserverModels is the observer provider's model list, in order: the
// FIRST entry is the provider's configured default (what the launcher picks
// when neither the operator nor pi's own settings name a model it serves).
var piObserverModels = []struct{ id, name string }{
	{"gpt-4o", "gpt-4o (observer proxy)"},
	{"gpt-4o-mini", "gpt-4o-mini (observer proxy)"},
}

// piObserverModelEntries renders piObserverModels for models.json.
func piObserverModelEntries() []any {
	out := make([]any, 0, len(piObserverModels))
	for _, m := range piObserverModels {
		out = append(out, piModel(m.id, m.name))
	}
	return out
}

// piObserverModelIDs returns the observer provider's model ids, default first.
func piObserverModelIDs() []string {
	out := make([]string, 0, len(piObserverModels))
	for _, m := range piObserverModels {
		out = append(out, m.id)
	}
	return out
}

// piAgentDir is pi's agent directory (~/.pi/agent, or $PI_CODING_AGENT_DIR:
// the pi/user-models artifact's rule, S-17), the home of models.json and
// settings.json. "" when it cannot be named (no home directory, or a
// relative PI_CODING_AGENT_DIR); piAgentDirErr says why.
func piAgentDir() string {
	d, _ := piAgentDirErr()
	return d
}

// piAgentDirErr is piAgentDir with the reason it cannot be named.
func piAgentDirErr() (string, error) {
	p, err := launcherArtifactPath("pi/user-models")
	if err != nil {
		return "", err
	}
	return filepath.Dir(p), nil
}

// readPiDefaults returns pi's own configured default provider and model
// (settings.json defaultProvider / defaultModel). Missing or unreadable
// settings yield empty strings: the decision table treats that as "pi has no
// default", never as an error.
func readPiDefaults(agentDir string) (provider, model string) {
	if agentDir == "" {
		return "", ""
	}
	data, err := os.ReadFile(filepath.Join(agentDir, "settings.json")) //nolint:gosec // pi's own settings file
	if err != nil {
		return "", ""
	}
	var s struct {
		DefaultProvider string `json:"defaultProvider"`
		DefaultModel    string `json:"defaultModel"`
	}
	if json.Unmarshal(data, &s) != nil {
		return "", ""
	}
	return strings.TrimSpace(s.DefaultProvider), strings.TrimSpace(s.DefaultModel)
}

// piRouteInputs are the facts piRouteFor walks. Pure values: the settings
// read happens in the caller so the decision is testable without touching
// the operator's real ~/.pi.
type piRouteInputs struct {
	// args is the operator's raw remainder (plus any seeded prompt).
	args []string
	// defaultProvider / defaultModel are pi's own settings.json defaults.
	defaultProvider, defaultModel string
	// providerModels is the observer provider's model list, default first.
	providerModels []string
}

// piRoute is the resolved invocation: the argv handed to pi, whether it is
// proxy-routed, and an optional one-line stderr notice.
type piRoute struct {
	args   []string
	routed bool
	notice string
}

// piRouteRule is one row of the ordered decision table below.
type piRouteRule struct {
	name string
	when func(piRouteInputs) bool
	then func(piRouteInputs) piRoute
}

// piRouteRules is the ordered routing table (CLAUDE.md #5: first match wins),
// fixing the launch that failed with
//
//	Error: --provider requires --model (for example: --provider observer --model <pattern>)
//
// pi 1.0's buildSessionOptions refuses `--provider` without `--model`, and
// the launcher used to prepend only `--provider observer`. pi parses both
// flags in the space form only (`--model <v>`), last value wins.
//
//  0. the operator passed their OWN --provider (not observer)
//     -> forward untouched, NOT routed, notice
//  1. the operator passed --model <non-empty>
//     -> add --provider observer, routed
//  2. the operator passed --model with an empty value
//     -> forward untouched, NOT routed, notice (pi rejects a provider with a
//     blank model and last-wins means observer cannot substitute one)
//  3. pi's own default model is one the observer provider serves
//     -> add --provider observer --model <that default>, routed
//  4. pi's own default model is on a provider the observer provider does not
//     serve (and the operator did not pass --provider observer)
//     -> forward untouched, NOT routed, notice; pi runs on the developer's
//     own default, never a substitute
//  5. the observer provider has a configured default model (pi has NO default
//     model, or the operator explicitly selected the observer provider)
//     -> add --provider observer --model <provider default>, routed, notice
//  6. otherwise -> forward untouched, NOT routed, notice
//
// Never switch the developer's model behind their back: row 3 uses their own
// default, row 4 leaves it alone unrouted, and row 5 picks the observer
// provider's configured default only when they have none, saying so.
var piRouteRules = []piRouteRule{
	{
		name: "provider-supplied",
		when: func(in piRouteInputs) bool {
			f := piFlagValue(in.args, "--provider")
			return f.present && strings.TrimSpace(f.value) != piProviderName
		},
		then: func(in piRouteInputs) piRoute {
			name := strings.TrimSpace(piFlagValue(in.args, "--provider").value)
			if name == "" {
				name = "(empty)"
			}
			return piRoute{
				args: in.args,
				notice: "--provider " + name + " supplied; leaving it alone, so this run is NOT proxy-routed " +
					"(drop --provider to route through observer)",
			}
		},
	},
	{
		name: "model-supplied",
		when: func(in piRouteInputs) bool {
			f := piFlagValue(in.args, "--model")
			return f.present && strings.TrimSpace(f.value) != ""
		},
		then: func(in piRouteInputs) piRoute {
			return piRoute{args: piWithProvider(in.args), routed: true}
		},
	},
	{
		name: "blank-model",
		when: func(in piRouteInputs) bool { return piFlagValue(in.args, "--model").present },
		then: func(in piRouteInputs) piRoute {
			return piRoute{
				args: in.args,
				notice: "an EMPTY --model value was supplied; pi rejects a provider paired with a blank model, " +
					"so this run is NOT proxy-routed (give --model a real model id to route it)",
			}
		},
	},
	{
		name: "pi-default-served",
		when: func(in piRouteInputs) bool {
			return in.defaultModel != "" && piContains(in.providerModels, in.defaultModel)
		},
		then: func(in piRouteInputs) piRoute {
			return piRoute{args: piWithProvider(in.args, "--model", in.defaultModel), routed: true}
		},
	},
	{
		// The developer's own pi default is on a provider the observer
		// provider does not serve: never swap it for one of ours. pi runs
		// UNROUTED on that default and the notice says how to route (the
		// same rule as A5-08: a collision launches unrouted, never a
		// substitute). An explicit `--provider observer` is the operator
		// asking for the observer provider, so it skips this row.
		name: "pi-default-unserved",
		when: func(in piRouteInputs) bool {
			return in.defaultModel != "" && !piFlagValue(in.args, "--provider").present
		},
		then: func(in piRouteInputs) piRoute {
			where := "is on " + in.defaultProvider
			if in.defaultProvider == "" {
				where = "is not on the observer provider"
			}
			return piRoute{
				args: in.args,
				notice: "not routed through Observer: your default model " + in.defaultModel + " " + where +
					"; pass --model <an OpenAI model> to route (served: " + strings.Join(in.providerModels, ", ") + ")",
			}
		},
	},
	{
		name: "observer-default",
		when: func(in piRouteInputs) bool { return len(in.providerModels) > 0 },
		then: func(in piRouteInputs) piRoute {
			model := in.providerModels[0]
			why := "pi has no default model configured"
			if in.defaultModel != "" {
				// Reached only with an explicit `--provider observer`.
				why = "your pi default " + piQualified(in.defaultProvider, in.defaultModel) +
					" is not served by the observer provider you selected"
			}
			return piRoute{
				args:   piWithProvider(in.args, "--model", model),
				routed: true,
				notice: "no --model given and " + why + "; using the observer provider's default model " + model +
					" (pass --model <id> to choose another: " + strings.Join(in.providerModels, ", ") + ")",
			}
		},
	},
	{
		name: "no-model",
		when: func(piRouteInputs) bool { return true },
		then: func(in piRouteInputs) piRoute {
			return piRoute{
				args: in.args,
				notice: "could not resolve a model for the observer provider (no --model, no served pi default); " +
					"this run is NOT proxy-routed; pass --model <id> to route it",
			}
		},
	},
}

// piRouteFor walks piRouteRules top-down; the last row always matches.
func piRouteFor(in piRouteInputs) piRoute {
	for _, rule := range piRouteRules {
		if rule.when(in) {
			return rule.then(in)
		}
	}
	return piRoute{args: in.args}
}

// piWithProvider prepends `--provider observer` (unless the operator already
// selected it) plus extra, returning a NEW slice; the operator's args follow
// and are never mutated.
func piWithProvider(args []string, extra ...string) []string {
	out := make([]string, 0, len(args)+len(extra)+2)
	if f := piFlagValue(args, "--provider"); !f.present {
		out = append(out, "--provider", piProviderName)
	}
	out = append(out, extra...)
	return append(out, args...)
}

// piFlag is a scanned flag occurrence.
type piFlag struct {
	present bool
	value   string
}

// piFlagValue returns the LAST occurrence of flag in args the way pi's own
// parser reads it (space form only, `--flag <value>`, last one wins). A
// trailing flag with no value is reported present with an empty value. A
// literal `--` ends the scan.
func piFlagValue(args []string, flag string) piFlag {
	var f piFlag
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			break
		}
		if args[i] != flag {
			continue
		}
		f.present = true
		f.value = ""
		if i+1 < len(args) {
			f.value = args[i+1]
			i++
		}
	}
	return f
}

func piContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func piQualified(provider, model string) string {
	if provider == "" {
		return model
	}
	return provider + "/" + model
}
