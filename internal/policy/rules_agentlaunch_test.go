package policy

import (
	"testing"
	"time"
)

// testLaunchVerbs stands in for the registry's launcher verbs the guard
// layer injects (Config.LaunchVerbs).
var testLaunchVerbs = []string{"claude", "codex", "gemini"}

// TestAgentLaunchRuleR168 walks one case per R-168 row and per route of
// agentLaunchRoutes, plus the shapes that must not ask. Every hit asks in
// BOTH modes (its observe decision is ask: the operator's opt-in ruling),
// and the non-launch Observer verbs never match.
func TestAgentLaunchRuleR168(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, line string
		dialect    Dialect
		hit        bool
		// stricterInEnforce: in enforce mode a stricter rule's deny wins;
		// R-168 still asks in observe mode, where that rule only flags.
		stricterInEnforce string
	}{
		// CLI row: observer launch.
		{name: "observer launch", line: `observer launch claude --detach --json`, hit: true},
		{name: "observer launch sandboxed", line: `observer launch codex --sandbox auto --workspace clone-local`, hit: true},
		{name: "launch with a flag first", line: `observer --config /tmp/c.toml launch claude`, hit: true},
		{name: "launch through npx", line: `npx -y @superbased/observer launch claude --detach`, hit: true},
		{name: "launch inside a script line", line: `cd /work && observer launch claude --detach`, hit: true},
		{name: "launch exe path", line: `/usr/local/bin/observer launch gemini`, hit: true},
		{name: "PowerShell launch", line: `observer.exe launch claude --detach`, dialect: DialectPowerShell, hit: true},
		// CLI row: the registry's launcher verbs.
		{name: "launcher verb", line: `observer claude -- -p "fix the tests"`, hit: true},
		{name: "launcher verb sandboxed", line: `observer codex --observer-sandbox auto`, hit: true},
		{name: "launcher verb through pnpm dlx", line: `pnpm dlx @superbased/observer gemini`, hit: true},
		// CLI row: help only prints.
		{name: "launch --help", line: `observer launch --help`},
		{name: "launcher verb -h", line: `observer claude -h`},
		{name: "a tool's own -h after -- still asks", line: `observer claude -- -h`, hit: true},
		// Detaching wrappers are stripped (fixes-1, low).
		{name: "setsid observer launch", line: `setsid observer launch claude --detach`, hit: true},
		{name: "setsid -f launcher verb", line: `setsid -f observer codex`, hit: true},
		{name: "systemd-run --user observer launch", line: `systemd-run --user --unit x -p MemoryMax=1G observer launch claude`, hit: true},
		{name: "nohup observer launch", line: `nohup observer launch claude --detach &`, hit: true},
		// Help off is not help (pflag's reading, lane cli-2 fixes-1, M1).
		{name: "launch --help=false launches", line: `observer launch claude --detach --help=false`, hit: true},
		{name: "launch --help=0 launches", line: `observer launch claude --help=0`, hit: true},
		{name: "launcher verb -h=false launches", line: `observer claude -h=false`, hit: true},
		{name: "launch --help=true is help", line: `observer launch --help=true`},
		// The rest of the CLI table (fixes-1, H1).
		{name: "ide opens an agent host", line: `observer ide cursor`, hit: true},
		{name: "benchmark spend run", line: `observer benchmark run spec.toml --confirm-spend`, hit: true},
		{name: "benchmark dry run", line: `observer benchmark run spec.toml`},
		{name: "benchmark run --confirm-spend=false is a dry run", line: `observer benchmark run spec.toml --confirm-spend=false`},
		{name: "deprecated alias group", line: `observer observer launch claude`, hit: true},
		{name: "deprecated alias group launcher verb", line: `observer observer claude`, hit: true},
		// Confirming a held launch starts it: asked about like a launch
		// (fixes-2, H-A), in both modes.
		{name: "terminals confirm", line: `observer terminals confirm pend-1`, hit: true},
		{name: "terminals confirm through npx", line: `npx -y @superbased/observer terminals confirm pend-1`, hit: true},
		{name: "terminals reject is not a launch", line: `observer terminals reject pend-1`},
		// A worker run starts the agent as its child (fold of the
		// cloud-agents line, P-230); the background proxy and the plan do not.
		{name: "cloud-session worker run", line: `observer cloud-session worker run --env github-actions -- claude -p hi`, hit: true},
		{name: "cloud-session worker start is not a launch", line: `observer cloud-session worker start --env github-actions`},
		{name: "cloud-session worker check is not a launch", line: `observer cloud-session worker check --env github-actions`},
		// Resuming a held org sandbox box starts the agent in it (fold
		// audit H1, lane FX5); the other org-shell verbs start none.
		{name: "sandbox org-shell resume", line: `observer sandbox org-shell resume run-1 --tool codex`, hit: true},
		{name: "sandbox org-shell resume through npx", line: `npx -y @superbased/observer sandbox org-shell resume run-1`, hit: true},
		{name: "sandbox org-shell resume --help", line: `observer sandbox org-shell resume --help`},
		{name: "sandbox org-shell hold is not a launch", line: `observer sandbox org-shell hold run-1`},
		{name: "sandbox org-shell held is not a launch", line: `observer sandbox org-shell held`},
		{name: "sandbox org-shell login is not a launch", line: `observer sandbox org-shell login`},
		{name: "sandbox org-shell resume binary by path", line: `/opt/observer/bin/observer sandbox org-shell resume run-1`, hit: true},
		// A flag before or between the subcommand words may take the next
		// word as its value, the way cobra finds the subcommand (fix round
		// 1, audit FX5-A1): one case per agentLaunchCommands row and for a
		// launcher verb, then shapes that must still not ask.
		{name: "flags before: launch", line: `observer --model opus launch claude --detach`, hit: true},
		{name: "flags before: ide", line: `observer --profile work ide cursor`, hit: true},
		{name: "flags before: benchmark run", line: `observer benchmark --suite s1 run spec.toml --confirm-spend`, hit: true},
		{name: "flags before: terminals confirm", line: `observer terminals --as me confirm pend-1`, hit: true},
		{name: "flags before: cloud-session worker run", line: `observer cloud-session worker --env github-actions run -- claude -p hi`, hit: true},
		{name: "flags before: sandbox org-shell resume", line: `observer sandbox org-shell --tool codex resume run-1`, hit: true},
		{name: "flags before at the root: sandbox org-shell resume", line: `observer --tool codex sandbox org-shell resume run-1`, hit: true},
		{name: "short flag before: sandbox org-shell resume", line: `observer sandbox -t codex org-shell resume run-1`, hit: true},
		{name: "flags before through npx: sandbox org-shell resume", line: `npx -y @superbased/observer sandbox org-shell --tool codex resume run-1`, hit: true},
		{name: "flags before: a launcher verb", line: `observer --model opus claude -p hi`, hit: true},
		{name: "flags before: the alias group", line: `observer observer --tool codex sandbox org-shell resume run-1`, hit: true},
		{name: "flags before: benchmark dry run", line: `observer benchmark --suite s1 run spec.toml`},
		{name: "flags before: org-shell hold is not a launch", line: `observer sandbox org-shell --tool codex hold run-1`},
		{name: "flags before: worker start is not a launch", line: `observer cloud-session worker --env github-actions start`},
		{name: "a known value flag's value is never a word", line: `observer --session launch sessions`},
		{name: "a word after -- is not a subcommand for the reach", line: `observer terminals --as me -- confirm pend-1`},
		{name: "POST pending confirm", line: `curl -X POST http://127.0.0.1:8821/api/terminal/pending/pend-1/confirm -d '{}'`, hit: true},
		{name: "POST pending reject is not a launch", line: `curl -X POST http://127.0.0.1:8821/api/terminal/pending/pend-1/reject -d '{}'`},
		{name: "wget POST tools launch", line: `wget --post-data '{"tool":"claude-code"}' http://localhost:8821/api/tools/launch`, hit: true},
		// Not launches.
		{name: "terminals ls", line: `observer terminals ls --json`},
		{name: "terminals stop", line: `observer terminals stop abc123`},
		{name: "terminals wait", line: `observer terminals wait abc123 --for session`},
		{name: "a verb the registry does not list", line: `observer aider`},
		{name: "the vendor binary itself", line: `claude -p "hi"`},
		{name: "npx of another package", line: `npx other-tool launch claude`},
		// HTTP row: one case per agentLaunchRoutes row.
		{name: "POST terminal launch", line: `curl -X POST http://127.0.0.1:8821/api/terminal/launch -d '{"tool":"claude-code"}'`, hit: true},
		{name: "POST arena runs", line: `curl -d '{"candidates":[]}' localhost:8821/api/arena/runs`, hit: true},
		{name: "POST session launch", line: `curl -X POST http://127.0.0.1:8821/api/session/abc/launch`, hit: true},
		{name: "POST session resume", line: `wget --post-data '{}' http://localhost:8821/api/session/abc/resume`, hit: true},
		{name: "PowerShell POST terminal launch", line: `Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8821/api/terminal/launch -Body '{}'`, dialect: DialectPowerShell, hit: true},
		{name: "POST tools launch", line: `curl -X POST localhost:8821/api/tools/launch -d '{"tool":"claude-code"}'`, hit: true},
		{name: "POST security fix launch", line: `curl -X POST localhost:8821/api/security/fix/launch -d '{"tool":"codex","project_root_hash":"h"}'`, hit: true},
		{name: "GET security fix plan", line: `curl localhost:8821/api/security/fix/plan?finding=x`},
		{name: "POST security assessments launch", line: `curl -X POST localhost:8821/api/security/assessments/launch -d '{"tool":"codex","assessment":"threat_model","project_root_hash":"h"}'`, hit: true},
		{name: "GET security assessments plan", line: `curl localhost:8821/api/security/assessments/plan?kind=threat_model`},
		{name: "POST security assessments fix", line: `curl -X POST localhost:8821/api/security/assessments/fix -d '{"tool":"codex","run":"3fa9c2d17b0e4a56","item":"T-1"}'`, hit: true},
		{name: "GET security assessments fix plan", line: `curl "localhost:8821/api/security/assessments/fix?run=3fa9c2d17b0e4a56&item=T-1"`},
		{name: "GET security assessments export", line: `curl "localhost:8821/api/security/assessments/export?run=3fa9c2d17b0e4a56&format=md"`},
		{name: "GET security assessments report", line: `curl localhost:8821/api/security/assessments/report?run=3fa9c2d17b0e4a56`},
		{name: "POST benchmark spend run", line: `curl -X POST http://127.0.0.1:8821/api/benchmarks/run -d '{"spec":"x","confirm_spend":true}'`, hit: true},
		{name: "POST benchmark run with an unreadable body", line: `curl -X POST http://127.0.0.1:8821/api/benchmarks/run -d @body.json`, hit: true},
		{name: "POST benchmark dry run", line: `curl -X POST http://127.0.0.1:8821/api/benchmarks/run -d '{"spec":"x"}'`},
		// HTTP shapes that are not launches.
		{name: "GET terminal runs", line: `curl http://127.0.0.1:8821/api/terminal/runs`},
		{name: "GET arena runs", line: `curl http://127.0.0.1:8821/api/arena/runs`},
		{name: "POST launch preflight", line: `curl -X POST http://127.0.0.1:8821/api/terminal/launch/preflight -d '{}'`},
		{name: "POST session handoff document", line: `curl -X POST http://127.0.0.1:8821/api/session/abc/handoff`},
		{name: "POST to a remote host", line: `curl -X POST https://example.com/api/terminal/launch -d '{}'`},
		// Sweep finding UI-1: every spelling of this machine the dashboard
		// answers is a loopback target.
		{name: "POST terminal launch through a mapped IPv6 host", line: `curl -X POST 'http://[::ffff:127.0.0.1]:8821/api/terminal/launch' -d '{}'`, hit: true},
		{name: "POST terminal launch through a hex mapped host", line: `curl -X POST 'http://[::ffff:7f00:1]:8821/api/terminal/launch' -d '{}'`, hit: true},
		{name: "POST terminal launch through an integer host", line: `curl -X POST http://2130706433:8821/api/terminal/launch -d '{}'`, hit: true},
		{name: "POST terminal launch through an integer host and a Host header", line: `curl -X POST -H 'Host: 127.0.0.1:8821' http://2130706433:8821/api/terminal/launch -d '{}'`, hit: true},
		{name: "POST terminal launch through a .localhost name", line: `curl -X POST http://x.localhost:8821/api/terminal/launch -d '{}'`, hit: true},
		{name: "POST terminal launch with a loopback Host header", line: `curl -X POST -H 'Host: localhost' http://sbo.example.test:8821/api/terminal/launch -d '{}'`, hit: true},
		{name: "POST terminal launch through --connect-to", line: `curl -X POST --connect-to sbo.example.test:8821:127.0.0.1:8821 http://sbo.example.test:8821/api/terminal/launch -d '{}'`, hit: true},
		{name: "POST terminal launch to a public quad", line: `curl -X POST http://93.184.216.34:8821/api/terminal/launch -d '{}'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const home, root = "/home/u", "/home/u/proj"
			ev := Event{
				Kind: KindShellExec, Target: tc.line, Dialect: tc.dialect,
				Cwd: root, ProjectRoot: root, SessionID: "s1",
				Now: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC),
			}
			for _, mode := range []Mode{ModeObserve, ModeEnforce} {
				e, err := New(Config{Mode: mode, Home: home, LaunchVerbs: testLaunchVerbs})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				v := e.Evaluate(ev)
				if mode == ModeEnforce && tc.stricterInEnforce != "" {
					if v.RuleID != tc.stricterInEnforce || v.Decision != DecisionDeny {
						t.Fatalf("enforce: want %s deny, got %q %s", tc.stricterInEnforce, v.RuleID, v.Decision)
					}
					continue
				}
				switch {
				case tc.hit && (v.RuleID != "R-168" || v.Decision != DecisionAsk):
					t.Fatalf("%s: want R-168 ask, got %q %s (%q)", mode, v.RuleID, v.Decision, v.Reason)
				case !tc.hit && v.RuleID == "R-168":
					t.Fatalf("%s: want no R-168 hit, got %s (%q)", mode, v.Decision, v.Reason)
				}
			}
		})
	}
}

// TestAgentLaunchVerbsComeFromConfig pins that the launcher verbs are the
// injected list: with none injected only `observer launch` asks.
func TestAgentLaunchVerbsComeFromConfig(t *testing.T) {
	t.Parallel()
	e, err := New(Config{Mode: ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := func(line string) Event {
		return Event{Kind: KindShellExec, Target: line, Cwd: "/home/u/p", ProjectRoot: "/home/u/p", SessionID: "s1"}
	}
	if v := e.Evaluate(ev(`observer claude`)); v.RuleID == "R-168" {
		t.Fatalf("observer claude matched with no injected verbs: %q", v.Reason)
	}
	if v := e.Evaluate(ev(`observer launch claude`)); v.RuleID != "R-168" {
		t.Fatalf("observer launch did not match: %q %q", v.RuleID, v.Reason)
	}
}

// TestAgentLaunchIsIntegrityAndAsksEveryUse pins R-168's two protections:
// no below-org layer may disable or cap it, and no grant covers it.
func TestAgentLaunchIsIntegrityAndAsksEveryUse(t *testing.T) {
	t.Parallel()
	if !IsIntegrityRuleID("R-168") {
		t.Fatal("R-168 is not in the integrity set")
	}
	if !AsksEveryUse("R-168") {
		t.Fatal("R-168 does not ask on every use")
	}
	// IsIntegrityRuleID spells R-168 as a literal (the web2 mirror test
	// reads it), while AsksEveryUse and the rows use agentLaunchRuleID:
	// the two must name the same rule (fold audit L3, lane FX5).
	if agentLaunchRuleID != "R-168" || !IsIntegrityRuleID(agentLaunchRuleID) || !AsksEveryUse(agentLaunchRuleID) {
		t.Fatalf("agentLaunchRuleID %q is not the R-168 literal IsIntegrityRuleID names", agentLaunchRuleID)
	}
	for _, r := range agentLaunchRules() {
		if r.ID != agentLaunchRuleID || !IsIntegrityRuleID(r.ID) {
			t.Fatalf("an agent launch row carries id %q, not the integrity literal %q", r.ID, agentLaunchRuleID)
		}
	}
	for _, id := range []string{"R-165", "R-101", "R-160", ""} {
		if AsksEveryUse(id) {
			t.Fatalf("AsksEveryUse(%q) = true; only R-168 asks every use", id)
		}
	}
	// A user-layer disable and an enforce=false cap leave the row asking.
	d := DecisionFlag
	e, err := New(Config{
		Mode: ModeObserve, Home: "/home/u", Disabled: []string{"R-168"},
		Overrides: []Override{{RuleID: "R-168", Decision: &d, Source: "user"}, {RuleID: "R-168", EnforceOff: true, Source: "user"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v := e.Evaluate(Event{Kind: KindShellExec, Target: `observer launch claude`, Cwd: "/home/u/p", ProjectRoot: "/home/u/p", SessionID: "s1"})
	if v.RuleID != "R-168" || v.Decision != DecisionAsk {
		t.Fatalf("a user layer relaxed R-168: got %q %s", v.RuleID, v.Decision)
	}
	// The rows ask through their own observe decision, never Enforced: an
	// enforced row would make every observe-mode tool gate fail closed.
	for _, r := range e.RuleInfos() {
		if r.ID == "R-168" && r.Enforced {
			t.Fatal("an R-168 row is Enforced; it must ask through its observe decision")
		}
	}
}

// TestTerminalLaunchPolicyIsSelfApproval pins the R-165 rows lane cli-2
// added: widening the launch policy is the owner's call.
func TestTerminalLaunchPolicyIsSelfApproval(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		sh("PUT terminal policy", `curl -X PUT http://127.0.0.1:8821/api/terminal/policy -d '{"allow_fresh_agent":true}'`, "R-165", DecisionDeny),
		sh("GET terminal policy is a read", `curl http://127.0.0.1:8821/api/terminal/policy`, "", 0),
		sh("POST first-launch consent", `curl -X POST http://127.0.0.1:8821/api/terminal/first-launch -d '{"tool":"claude-code","folder":"","changes":["allow_tool"]}'`, "R-165", DecisionDeny),
		sh("config set terminal.launch key", `observer config set terminal.launch.allow_fresh_agent true`, "R-165", DecisionDeny),
		sh("config set another terminal key", `observer config set terminal.attach.enabled true`, "", 0),
		sh("config keys body names terminal.launch", `curl -X POST http://127.0.0.1:8821/api/config/keys -d '{"patches":[{"key":"terminal.launch.allowed_tools","value":["codex"]}]}'`, "R-165", DecisionDeny),
		sh("config section terminal.launch", `curl -X PUT http://127.0.0.1:8821/api/config/section/terminal.launch -d '{}'`, "R-165", DecisionDeny),
		sh("config section terminal with a launch member", `curl -X PUT http://127.0.0.1:8821/api/config/section/terminal -d '{"Launch":{"AllowFreshAgent":true}}'`, "R-165", DecisionDeny),
		sh("config section terminal without a launch member", `curl -X PUT http://127.0.0.1:8821/api/config/section/terminal -d '{"RouteProxy":false}'`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}
