package policy

import (
	"regexp"
	"strings"
)

// R-168 (lane cli-2, tracker PT-61, discovery
// docs/plans/discovery-cli-2026-11-03.md section 4.4): an agent starting
// another agent. Observer can launch a coding agent from its CLI (`observer
// launch`, the per-tool launcher verbs such as `observer claude`) and from
// the loopback dashboard's launch routes. An agent that runs one of those
// from its own shell fans out: the launched agent runs with the owner's
// credentials, spends the owner's budget and may itself launch more.
//
// The operator's ruling: an agent-started launch is opt-in, and the human is
// asked on EACH launch. So the rows ask in BOTH modes: their observe
// decision is ask too, because observe is the fresh-install default and a
// row that only flagged there would let every agent launch through on a
// default install. They deliberately do NOT carry Enforced: an enforced row
// makes the node's tool gate count as enforcing (Guard.GateEnforcement), so
// every tool call on an observe-mode node would fail closed when its hook
// times out or crashes; R-168 asks only while its hook runs, and a hook
// failure on an observe-mode node fails open as before (named residual,
// docs/guard.md "Agent-initiated launches"). Where the host cannot ask, the
// ask degrades to a deny (the hook-parity table,
// internal/guard/degradedask.go), and the deny text says the developer
// starts the run themselves.
//
// No grant lifts R-168 (AsksEveryUse): a local approval and an org grant
// would turn one yes into a standing pass for every later launch in that
// scope, which is exactly what "ask on each launch" rules out. And R-168 is
// in the integrity set (IsIntegrityRuleID): a layer below the org may not
// disable it or cap it at a flag, or an agent could lift the ask by
// editing a policy file it can reach.
//
// What the rows see: a shell command the agent's pre-tool hook judges. A
// launch the agent starts some other way (a script it wrote and then runs,
// a program that calls the attach endpoint) is not asked here; the daemon
// still records it as initiator agent with its parent session when the
// caller descends from a live agent session (cmd/observer
// launch_initiator.go), so the owner sees who launched what.

// agentLaunchCommand is one Observer CLI command that starts an agent or a
// harness of agents, beside the per-tool launcher verbs the guard layer
// injects (Config.LaunchVerbs).
type agentLaunchCommand struct {
	// path is the subcommand path.
	path []string
	// when, if set, narrows the row by the full argument list.
	when func(args []string) bool
	// desc names what the command starts, for the verdict detail.
	desc string
}

// agentLaunchCommands is the R-168 CLI table, one row per command; its
// completeness against the command tree is pinned in cmd/observer
// (TestEveryLaunchCommandAsks, lane cli-2 fixes-1).
var agentLaunchCommands = []agentLaunchCommand{
	{path: []string{"launch"}, desc: "launches an agent through the daemon"},
	{path: []string{"ide"}, desc: "opens an IDE or desktop app, an agent host, wrapped for the proxy"},
	{
		path: []string{"benchmark", "run"}, desc: "drives agent harnesses on a spend run",
		when: func(args []string) bool { return boolFlagTrue(args, "--confirm-spend") },
	},
	// Confirming a launch the daemon holds for a human starts it (lane
	// cli-2 fixes-2, audit H-A): an agent's shell running it is asked about
	// like any launch, every time, and the daemon refuses a confirm it
	// traces to an agent as well.
	{path: []string{"terminals", "confirm"}, desc: "confirms a launch the daemon holds for a human, which starts it"},
	// `cloud-session worker run -- <agent>` (the cloud-agents line, Rail S
	// customer-run compute) runs the agent as its child behind a worker
	// proxy, like a launcher verb; customer compute is proven from the
	// environment, which the agent's own shell can set, so it is asked about
	// like any launch (fold of the cloud-agents line, P-230). `worker start`
	// only starts a background proxy and the vendor starts the agent.
	{path: []string{"cloud-session", "worker", "run"}, desc: "runs an agent as a child behind a worker proxy"},
	// `sandbox org-shell resume <run>` takes over a held org sandbox box and
	// starts the agent in it through the tool's launcher verb, as a
	// foreground sandboxed launch does (fold audit H1, lane FX5). Its
	// sibling org-shell verbs (hold, discard, held, hold-on-end, fetch,
	// login, logout, status, check, opt-in, opt-out) start no agent.
	{path: []string{"sandbox", "org-shell", "resume"}, desc: "resumes a held org sandbox box and starts the agent in it"},
	// `sandbox restore` restarts a checkpointed agent run; it is R-165's
	// already (the readopt rows, lane GATES-SBX), which denies it under
	// enforce, so it is not repeated here.
}

// agentLaunchHelpFlags only print help; nothing is launched.
var agentLaunchHelpFlags = []string{"--help", "-h"}

// sessionLaunchRoute matches the dashboard's per-session launch routes: a
// handoff launch (/api/session/<id>/launch) and a resume
// (/api/session/<id>/resume).
var sessionLaunchRoute = regexp.MustCompile(`^/api/session/[^/]+/(?:launch|resume)$`)

// pendingConfirmRoute matches a held launch's confirm route
// (/api/terminal/pending/<id>/confirm).
var pendingConfirmRoute = regexp.MustCompile(`^/api/terminal/pending/[^/]+/confirm$`)

// agentLaunchRoutes are the loopback dashboard routes whose write starts an
// agent or a harness, one row per route (TestAgentLaunchRuleR168). Their
// completeness against the dashboard's registered routes is pinned in
// internal/intelligence/dashboard (TestEveryLaunchRouteIsHeldAndAsked).
var agentLaunchRoutes = []struct {
	match func(path string) bool
	// body, when set, narrows the row to a request whose body starts
	// something (an unreadable body counts).
	body func(cmd *Command) bool
	desc string
}{
	{match: func(p string) bool { return p == "/api/terminal/launch" }, desc: "the dashboard's New Terminal launch route"},
	{match: func(p string) bool { return p == "/api/arena/runs" }, desc: "the Agent Arena run route, which starts one agent per candidate"},
	{match: sessionLaunchRoute.MatchString, desc: "the dashboard's session continue and resume routes"},
	{match: func(p string) bool { return p == "/api/tools/launch" }, desc: "the Tools card's launch route, which opens a terminal window running the agent"},
	{match: func(p string) bool { return p == "/api/security/fix/launch" }, desc: "the Code security page's Fix with an agent route, which starts an agent on findings"},
	{match: func(p string) bool { return p == "/api/security/assessments/launch" }, desc: "the Code security page's Security assessments route, which starts an agent on an assessment of a project"},
	{match: func(p string) bool { return p == "/api/security/assessments/fix" }, desc: "the Code security page's fix route for a security assessment item, which starts an agent that edits the project"},
	{match: pendingConfirmRoute.MatchString, desc: "the held launches' confirm route, which starts the held launch"},
	{
		match: func(p string) bool { return p == "/api/benchmarks/run" }, desc: "the Benchmarks spend run, which drives agent harnesses",
		body: func(cmd *Command) bool { return bodyMemberLowers(cmd, "confirm_spend", jsonTrueOrOdd) },
	},
}

// launchVerb reports whether word is a per-tool launcher verb of the
// integration registry (cfg.LaunchVerbs).
func launchVerb(cfg *Config, word string) bool {
	if cfg == nil {
		return false
	}
	for _, v := range cfg.LaunchVerbs {
		if v == word {
			return true
		}
	}
	return false
}

// matchAgentLaunchCLI is the R-168 CLI matcher: a row of agentLaunchCommands
// or a launcher verb (the binary, or a package runner starting the Observer
// package; the deprecated `observer observer ...` alias group included),
// unless it only prints help.
func matchAgentLaunchCLI(ctx *MatchContext, cmd *Command) (bool, string) {
	args, ok := observerArgs(cmd)
	if !ok {
		return false, ""
	}
	words := cliWords(args)
	if len(words) > 0 && words[0] == "observer" {
		words = words[1:] // the deprecated alias group repeats every verb
	}
	if len(words) == 0 || helpOnly(args) {
		return false, ""
	}
	var cfg *Config
	if ctx != nil {
		cfg = ctx.Cfg
	}
	if launchVerb(cfg, words[0]) {
		return true, "observer " + words[0] + " launches an agent"
	}
	for _, c := range agentLaunchCommands {
		if !wordsHavePrefix(words, c.path) || (c.when != nil && !c.when(args)) {
			continue
		}
		detail := "observer " + strings.Join(c.path, " ")
		if len(words) > len(c.path) {
			detail += " " + clampDetail(words[len(c.path)])
		}
		return true, detail + " (" + c.desc + ")"
	}
	// A flag the table does not know, before or between the subcommand
	// words, may take the next word as its value the way cobra finds a
	// subcommand (fold audit FX5-A1): `observer sandbox org-shell --tool
	// codex resume run-1` runs resume. The prefix match above reads codex
	// as a subcommand word and misses it, so every row and launcher verb is
	// matched again with each such flag read both ways. This only adds asks.
	if cfg != nil {
		for _, v := range cfg.LaunchVerbs {
			if cobraReachesPath(args, []string{v}) {
				return true, "observer " + v + " launches an agent"
			}
		}
	}
	for _, c := range agentLaunchCommands {
		if (c.when != nil && !c.when(args)) || !cobraReachesPath(args, c.path) {
			continue
		}
		return true, "observer " + strings.Join(c.path, " ") + " (" + c.desc + ")"
	}
	return false, ""
}

// cobraReachesPath reports whether cobra v1.10.2 could resolve args to the
// subcommand path (or to the deprecated `observer` alias group followed by
// it), reading each flag the way its stripFlags does: "--" ends the
// subcommand words; a `--name` or two-letter `-x` with no "=" takes the
// next argument as its value unless the flag is a boolean at that level;
// any other dash argument takes none. Whether an unknown flag is a boolean
// is not known here, so both readings are tried (deny-biased: a match on
// either asks). A flag of observerValueFlags always takes its value, as
// cliWords reads it. Any other bare word is a subcommand word and must be
// the path's next word. Residual: cobra re-reads the flags at each level
// with that level's flag set, so a flag that is unknown at the root and a
// boolean further down could put a path word before its parent; the reach
// assumes one reading per flag.
func cobraReachesPath(args []string, path []string) bool {
	return cobraReach(args, path) || cobraReach(args, append([]string{"observer"}, path...))
}

// cobraPathWords returns the word lists a CLI table row's narrowing reads
// (its path followed by the operands), one per way cobra could resolve args
// to path. words is cliWords(args). When words start with path (the prefix
// match), that is words itself. Otherwise, when cobraReachesPath finds a
// reading in which a flag before or between the subcommand words takes the
// next word (OSH-141, the R-165 and R-167 tables), the path's words lie in
// words in order with flag values between them, so each place the path's
// last word could end is one reading: path followed by the words after it.
// Every reading is returned and a row matches on any (deny-biased, like
// cobraReachesPath); nil means args cannot reach path.
func cobraPathWords(args, words, path []string) [][]string {
	if wordsHavePrefix(words, path) {
		return [][]string{words}
	}
	if len(path) == 0 || !cobraReachesPath(args, path) {
		return nil
	}
	var out [][]string
	last := len(path) - 1
	for m, w := range words {
		if w != path[last] || !wordsHaveSubsequence(words[:m], path[:last]) {
			continue
		}
		out = append(out, append(append([]string(nil), path...), words[m+1:]...))
	}
	return out
}

// wordsHaveSubsequence reports whether sub appears in words in order.
func wordsHaveSubsequence(words, sub []string) bool {
	j := 0
	for _, w := range words {
		if j < len(sub) && w == sub[j] {
			j++
		}
	}
	return j == len(sub)
}

// cobraReach is cobraReachesPath for one path, memoized on (arg, path)
// positions so a long flag list stays linear.
func cobraReach(args []string, path []string) bool {
	seen := map[[2]int]bool{}
	var reach func(i, j int) bool
	reach = func(i, j int) bool {
		if j == len(path) {
			return true
		}
		if i >= len(args) {
			return false
		}
		key := [2]int{i, j}
		if done, ok := seen[key]; ok {
			return done
		}
		seen[key] = false
		a := args[i]
		var ok bool
		switch {
		case a == "--":
			ok = false
		case a == "" || a == "-":
			ok = reach(i+1, j) // cobra reads neither as a word or a flag
		case !strings.HasPrefix(a, "-"):
			ok = a == path[j] && reach(i+1, j+1)
		case strings.Contains(a, "="):
			ok = reach(i+1, j)
		case observerValueFlags[a]:
			ok = reach(i+2, j)
		case strings.HasPrefix(a, "--") || len(a) == 2:
			// Unknown: a boolean takes no value, any other flag takes one.
			ok = reach(i+1, j) || reach(i+2, j)
		default:
			ok = reach(i+1, j) // a grouped shorthand such as -abc takes none
		}
		seen[key] = ok
		return ok
	}
	return reach(0, 0)
}

// helpOnly reports whether args ask Observer's own CLI for help: a help
// flag set true the way pflag reads it (boolFlagTrue: `--help=false` and
// `-h=0` are help off), before "--". After "--" the words are the tool's
// own arguments, and a tool may read -h as something other than help, so
// they never exempt a launch.
func helpOnly(args []string) bool {
	for _, h := range agentLaunchHelpFlags {
		if boolFlagTrue(args, h) {
			return true
		}
	}
	return false
}

// matchAgentLaunchHTTP is the R-168 route matcher: an HTTP client writing
// to a loopback launch route.
func matchAgentLaunchHTTP(_ *MatchContext, cmd *Command) (bool, string) {
	method, paths := loopbackWritePaths(cmd)
	for _, p := range paths {
		for _, r := range agentLaunchRoutes {
			if r.match(p) && (r.body == nil || r.body(cmd)) {
				return true, method + " " + p + " (" + r.desc + ")"
			}
		}
	}
	return false, ""
}

// agentLaunchRuleID is R-168's public id.
const agentLaunchRuleID = "R-168"

// AsksEveryUse reports whether no grant may cover rule id: neither a local
// approval nor an org grant, so its ask is put to a human on every use
// (R-168, lane cli-2). Widening this set is a deliberate edit.
func AsksEveryUse(id string) bool { return id == agentLaunchRuleID }

// agentLaunchRules returns the R-168 rows (appended to the boundary table).
func agentLaunchRules() []Rule {
	shell := []EventKind{KindShellExec}
	const advice = "The developer decides each launch an agent starts. Ask the developer to start the run themselves (the dashboard's New Terminal or `observer launch` in their own terminal), or wait for them to answer this prompt; no standing approval covers it."
	return []Rule{
		{
			ID: agentLaunchRuleID, Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchAgentLaunchCLI,
			Observe: DecisionAsk, Enforce: DecisionAsk,
			Doc:    "agent launching another agent (observer launch or a launcher verb)",
			Advice: advice,
		},
		{
			ID: agentLaunchRuleID, Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchAgentLaunchHTTP,
			Observe: DecisionAsk, Enforce: DecisionAsk,
			Doc:    "agent calling the local dashboard's launch routes",
			Advice: advice,
		},
	}
}
