//go:build !sbo_omit_terminals

package main

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// pinnedVerbCompiledOut reports whether the top-level verb of a pinned
// command path belongs to a component this build compiled out (its owner
// in the catalog's Verbs column). Such a verb is only the compiled-out
// stand-in, so its subcommands (benchmark run, shell-wrap launch-env) are
// absent by design and their rows are not stale.
func pinnedVerbCompiledOut(path string) bool {
	words := strings.Fields(path)
	if len(words) == 0 {
		return false
	}
	for _, c := range components.ForBinary(components.BinaryNode) {
		if slices.Contains(c.Verbs, words[0]) && compiledOut(c.ID) {
			return true
		}
	}
	return false
}

// launch_commands_pin_test.go pins guard rule R-168's CLI table against the
// command tree (lane cli-2 fixes-1, audit H1). Every command whose words say
// it starts something (its Short begins "Launch", or its last word is a
// start verb) must be either a launch command R-168 asks about, or listed in
// notALaunch with the reason it starts no agent. A new launch verb fails
// here until R-168 (internal/policy/rules_agentlaunch.go) has a row.

// launchCommandSamples are the launch commands beside the registry's
// launcher verbs, each with an argument line R-168 must ask about.
var launchCommandSamples = map[string]string{
	"launch":        "launch claude --detach",
	"ide":           "ide cursor",
	"benchmark run": "benchmark run spec.toml --confirm-spend",
	// The cloud-agents line's customer-worker run (fold, P-230).
	"cloud-session worker run": "cloud-session worker run --env github-actions -- claude",
}

// startWords are command names that may start something.
var startWords = map[string]bool{
	"launch": true, "run": true, "start": true, "restore": true, "resume": true, "adopt": true,
	"readopt": true, "spawn": true, "open": true, "confirm": true, "drive": true, "exec": true, "serve": true,
}

// notALaunch are the start-worded commands that start no agent.
var notALaunch = map[string]string{
	"run":                   "runs a command through the shell filter, as the shell itself would: no Observer launch path, the same-user residual of LAUNCH-2",
	"eval run":              "scores a dataset; starts no agent",
	"obs eval run":          "scores a dataset; starts no agent",
	"security scanners run": "runs a configured scanner",
	"proxy start":           "starts the API proxy",
	"service start":         "starts the observer service",
	"start":                 "starts the observer daemon",
	"experiment start":      "starts a compression experiment",
	"setup launch":          "starts the observer daemon",
	"shell-wrap launch-env": "prints a routing environment",
	"sandbox readopt":       "re-attaches a run already running; starts none",
	"sandbox hosted adopt":  "re-attaches a hosted box already running; starts none",
	"sandbox restore":       "restarts a checkpointed run: R-165's (the readopt rows), which denies it under enforce",
	"sandbox setup run":     "runs one sandbox setup step the person approves; starts no agent (R-165's setup verb rows, lane guard)",
	"terminals confirm":     "confirms a held launch: R-165's (an agent may not confirm its own launch)",
	"serve":                 "the MCP server an AI tool spawns",
	"relay serve":           "the route relay",
	"mcp relay":             "an MCP stdio relay the AI client spawns",
	"mcp-relay wrap":        "an MCP stdio relay the AI client spawns",
	"mcp-relay restore":     "restores client MCP configs",
	// The cloud-agents line (fold, P-230).
	"cloud-session worker start":        "starts a background API proxy and hands the route to later steps; the vendor starts the agent",
	"cloud-session worker serve":        "the background proxy process `worker start` spawns; starts no agent",
	"cloud-session otel-receiver serve": "serves the loopback OTLP receiver in the foreground; starts no agent",
}

// TestEveryLaunchCommandAsks is the pin.
func TestEveryLaunchCommandAsks(t *testing.T) {
	var verbs []string
	for _, tool := range integration.Tools() {
		if c, ok := integration.For(tool); ok && c.Handoff.Launch != nil && c.Handoff.Launch.Subcommand != "" {
			verbs = append(verbs, c.Handoff.Launch.Subcommand)
		}
	}
	isVerb := map[string]bool{}
	for _, v := range verbs {
		isVerb[v] = true
	}
	e, err := policy.New(policy.Config{Mode: policy.ModeEnforce, Home: "/home/u", LaunchVerbs: verbs})
	if err != nil {
		t.Fatal(err)
	}
	asks := func(line string) bool {
		v := e.Evaluate(policy.Event{Kind: policy.KindShellExec, Target: "observer " + line, Cwd: "/home/u/p", ProjectRoot: "/home/u/p", SessionID: "s1"})
		return v.RuleID == "R-168" && v.Decision == policy.DecisionAsk
	}
	seen := map[string]bool{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		path := strings.TrimPrefix(strings.TrimPrefix(c.CommandPath(), "observer"), " ")
		path = strings.TrimPrefix(path, "observer ") // the deprecated alias group
		for _, sub := range c.Commands() {
			walk(sub)
		}
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		words := strings.Fields(path)
		last := words[len(words)-1]
		switch {
		case len(words) == 1 && isVerb[path]:
			if !asks(path) {
				t.Errorf("launcher verb %q is not asked about by R-168", path)
			}
			return
		case launchCommandSamples[path] != "":
			if !asks(launchCommandSamples[path]) {
				t.Errorf("launch command %q (sample %q) is not asked about by R-168", path, launchCommandSamples[path])
			}
			return
		}
		if !strings.HasPrefix(c.Short, "Launch") && !startWords[last] {
			return
		}
		if _, ok := notALaunch[path]; !ok {
			t.Errorf("command %q may start something (%q): add it to R-168 and launchCommandSamples, or to notALaunch with the reason it starts no agent", path, c.Short)
		}
	}
	walk(newRootCmd())
	if len(seen) < 300 {
		t.Fatalf("only %d commands walked; the pin would be vacuous", len(seen))
	}
	var stale []string
	for p := range launchCommandSamples {
		if !seen[p] && !pinnedVerbCompiledOut(p) {
			stale = append(stale, p)
		}
	}
	for p := range notALaunch {
		if !seen[p] && !pinnedVerbCompiledOut(p) {
			stale = append(stale, p)
		}
	}
	sort.Strings(stale)
	for _, p := range stale {
		t.Errorf("pinned command %q no longer exists; drop its row", p)
	}
}
