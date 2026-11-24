package policy

import (
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/ipclass"
)

// R-165 (D-761): an agent approving its own guard exception. A block is
// only worth something if the agent cannot lift it: an agent that runs
// `observer guard approve`, posts to the dashboard's approval routes on
// loopback, or writes a grant into guard_approvals itself has turned the
// block into a self-granted pass. The human decides an exception, so the
// rule denies the APPROVAL under enforce and only flags an exception
// REQUEST (`observer request ...`): asking is the path the deny text points
// the agent at (security pillar plan section 6.1, X32).
//
// R-165 is in the guard's integrity set (IsIntegrityRuleID): a layer below
// the org may not disable or relax it, because doing so would let an agent
// lift any other rule one grant at a time. Writes into ~/.observer (where
// the database and the policy files live) stay R-160, except the
// developer's consent records (consentRecordPatterns), which are R-165's:
// writing one IS giving the consent.

// observerPackages are the package names a package runner starts
// Observer's CLI from (npm and PyPI distributions).
var observerPackages = setOf("@superbased/observer", "superbased-observer")

// packageRunners are command bases that run a package's CLI, with the
// subcommand word that must come first ("" when none).
var packageRunners = map[string]string{
	"npx": "", "pnpx": "", "bunx": "", "uvx": "",
	"pnpm": "dlx", "yarn": "dlx", "npm": "exec", "pipx": "run",
}

// observerValueFlags are Observer CLI flags that take the next word as
// their value, so it is never read as a subcommand or as a flag of its own:
// in `guard recipe apply --level none --pack --dry-run` the word --dry-run
// is the pack's name, and the command applies (sweep finding CFG-10).
// --level, --pack, --replay and --file are the guard recipe verbs' value
// flags (cmd/observer/guard_recipe.go).
var observerValueFlags = setOf("--config", "--db", "--session", "--ttl", "--project", "--since", "--reason",
	"--level", "--pack", "--replay", "--file")

// observerArgs returns the arguments of an Observer CLI invocation: the
// `observer` binary itself, or a package runner starting the Observer
// package.
func observerArgs(cmd *Command) ([]string, bool) {
	if cmd.Base == "observer" {
		return cmd.Args(), true
	}
	verb, ok := packageRunners[cmd.Base]
	if !ok {
		return nil, false
	}
	args := cmd.Args()
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			continue
		}
		if verb != "" {
			if a != verb {
				return nil, false
			}
			verb = ""
			continue
		}
		pkg := a
		if at := strings.LastIndexByte(pkg, '@'); at > 0 {
			pkg = pkg[:at]
		}
		if !observerPackages[strings.ToLower(pkg)] {
			return nil, false
		}
		rest := args[i+1:]
		if len(rest) > 0 && canonicalBase(rest[0], cmd.Dialect) == "observer" {
			rest = rest[1:]
		}
		return rest, true
	}
	return nil, false
}

// cliWords returns the words of a CLI argument list that are not flags or
// flag values: the subcommand path and its operands.
func cliWords(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return append(out, args[i+1:]...)
		}
		if strings.HasPrefix(a, "-") {
			if name, _, hasVal := strings.Cut(a, "="); !hasVal && observerValueFlags[name] {
				i++
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

// hasFlag reports whether args carry the flag name (alone or with "=").
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

// boolFlagTrue reports whether args set the boolean flag name to true the
// way the CLI's flag parser (pflag) reads them: the bare flag, or name=v
// where strconv.ParseBool reads v as true (1, t, T, TRUE, true, True), the
// last occurrence winning. A value flag's operand (observerValueFlags: in
// `--config --plan` the word --plan is the config path) is never read as
// the flag, and nothing after "--" is a flag. A false value (0, f, F,
// FALSE, false, False) and anything ParseBool refuses (name=, name=yes,
// on which pflag refuses the command line) read as not set, so a row that
// allows on it stays deny-biased (lane SEC-G2 audit finding 1: `install
// --plan=false --yes` and `install --config --plan --yes` installed and
// recorded the consent) without denying a real preview such as
// `--dry-run=1` (lane SEC-G4 audit finding 7).
func boolFlagTrue(args []string, name string) bool {
	set := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") {
			continue
		}
		flag, val, hasVal := strings.Cut(a, "=")
		if flag == name {
			if !hasVal {
				set = true
			} else {
				b, err := strconv.ParseBool(val)
				set = err == nil && b
			}
			continue
		}
		if !hasVal && observerValueFlags[flag] {
			i++
		}
	}
	return set
}

// selfApprovalVerb is one Observer CLI command that lifts a guard block
// (grant) or asks a human to (request).
type selfApprovalVerb struct {
	// path is the subcommand path.
	path []string
	// when, if set, narrows the row by the full argument list and words.
	when func(args, words []string) bool
	// grant is true for a command that lifts a block itself; false for a
	// request a human decides.
	grant bool
	// desc names what the command does, for the verdict detail.
	desc string
}

// selfApprovalVerbs is the R-165 CLI table, one row per command.
var selfApprovalVerbs = []selfApprovalVerb{
	{path: []string{"guard", "approve"}, grant: true, desc: "grants a guard exception"},
	{path: []string{"guard", "mcp", "approve"}, grant: true, desc: "approves an MCP server the guard flagged"},
	{path: []string{"guard", "prompt", "allow"}, grant: true, desc: "allows a prompt detector the guard blocks"},
	{path: []string{"guard", "disable"}, grant: true, desc: "switches the guard off"},
	// Guard recipes (plan docs/plans/profile-guard-recipes-repo-grouping-
	// plan-2026-11-07.md section 3): applying or removing one changes what
	// the guard enforces on this machine or in a project, and a saved recipe
	// is one a person may apply later, so all four are the person's call.
	// Only an explicit --dry-run is a read; list and show are reads.
	{
		path: []string{"guard", "recipe", "apply"}, grant: true, desc: "applies a guard recipe, which changes what the guard enforces",
		when: func(args, _ []string) bool { return !boolFlagTrue(args, "--dry-run") },
	},
	{
		path: []string{"guard", "recipe", "remove"}, grant: true, desc: "removes a guard recipe, which changes what the guard enforces",
		when: func(args, _ []string) bool { return !boolFlagTrue(args, "--dry-run") },
	},
	{path: []string{"guard", "recipe", "save"}, grant: true, desc: "saves a guard recipe a person may later apply"},
	{path: []string{"guard", "recipe", "delete"}, grant: true, desc: "deletes one of the person's guard recipes"},
	{
		path: []string{"guard", "enable"}, grant: true, desc: "sets the guard to observe mode, so nothing blocks",
		when: func(args, _ []string) bool { return !hasFlag(args, "--enforce") },
	},
	{
		path: []string{"config", "set"}, grant: true, desc: "changes a [guard], [security], [terminal.launch] or [observer.hooks] setting, or a D19 sharing, capture, egress, admission, budget or SDK destination setting, or another setting that needs your confirm (ask through MCP set_setting, which files a proposal for the person)",
		when: func(_, words []string) bool { return len(words) > 2 && selfLoweringConfigKey(words[2]) },
	},
	// Plane A W2-8 (ruling D19): a settings change an agent asked for through
	// MCP set_setting waits for the person; approving or rejecting it is
	// theirs. `config proposals` alone (the list) stays allowed.
	{path: []string{"config", "proposals", "approve"}, grant: true, desc: "approves and applies a settings change an AI agent asked for"},
	{path: []string{"config", "proposals", "reject"}, grant: true, desc: "rejects a settings change an AI agent asked for"},
	// Plane A W2-7 (ruling D18): minting the person's own SDK key on their
	// organization (which lets apps send data off the machine) and revoking
	// it are the person's. `sdk status` only prints.
	{path: []string{"sdk", "sign-in"}, grant: true, desc: "mints your SDK key on your organization, which lets apps send data off this machine"},
	{path: []string{"sdk", "sign-out"}, grant: true, desc: "revokes your SDK key on your organization"},
	// Review finding R-C02 (ruling D19): the machine's alert channels are
	// where alert data (rule, metric, value, dimensions, an end user among
	// them) is sent off this machine, and the admission setup wizard writes
	// the admission policy and its judge (where an app's prompts are sent
	// to be judged). Each is the owner's, like the HTTP routes below; the
	// test sends stay allowed. cmd/observer's
	// TestEveryObsWriterIsR165OrExcepted walks every obs route and verb.
	{path: []string{"obs", "alerts", "slack", "set"}, grant: true, desc: "stores the Slack alert webhook, where alert data is sent off this machine"},
	{path: []string{"obs", "alerts", "slack", "clear"}, grant: true, desc: "removes the Slack alert webhook, so alerts stop reaching the person"},
	{path: []string{"obs", "alerts", "pagerduty", "set"}, grant: true, desc: "stores the PagerDuty routing key, where alert data is sent off this machine"},
	{path: []string{"obs", "alerts", "pagerduty", "clear"}, grant: true, desc: "removes the PagerDuty routing key, so alerts stop reaching the person"},
	{path: []string{"obs", "admission", "setup"}, grant: true, desc: "writes the admission policy and its judge (where an app's prompts are sent to be judged), a setting you change yourself"},
	// The repository trust accept flow (security pillar plan section 5.1
	// item 5): accepting a repository's commands is the developer's call.
	{path: []string{"security", "trust", "accept"}, grant: true, desc: "accepts a repository's commands for the repository trust check"},
	// A custom scanner runs a program on every scan (security plan section
	// 8.6): accepting one is the developer's call, never an agent's.
	{path: []string{"security", "scanners", "import"}, grant: true, desc: "accepts a custom scanner that runs a program on every scan"},
	// The code rules' pack import (lane SEC-G1): a newer pack replaces the
	// rules every code scan runs, which is the developer's call, never an
	// agent's. Listing the rules and the install text stay allowed
	// (install-opengrep only prints; it writes nothing).
	{path: []string{"security", "code", "rules", "import"}, grant: true, desc: "installs a code rule pack that every code scan runs"},
	// Lane SEC-G2: the guided Opengrep install downloads about 47 MB and
	// installs a third-party engine on the developer's one-time size
	// consent, never an agent's. Only an explicit --plan (or --plan=true)
	// is a read: it prints and writes nothing (boolFlagTrue).
	{
		path: []string{"security", "code", "install"}, grant: true, desc: "downloads and installs the Opengrep engine on the developer's size consent",
		when: func(args, _ []string) bool { return !boolFlagTrue(args, "--plan") },
	},
	// Lane GATES-SEC: the IaC engines' guided install downloads and
	// installs a third-party engine on the developer's one-time size
	// consent, never an agent's; --plan only prints.
	{
		path: []string{"security", "iac", "install"}, grant: true, desc: "downloads and installs an IaC engine (Trivy) on the developer's size consent",
		when: func(args, _ []string) bool { return !boolFlagTrue(args, "--plan") },
	},
	// Lane sec-c3: a finding exception and a baseline approval lift a
	// finding out of the commit gate's blocking set.
	{path: []string{"security", "exception", "add"}, grant: true, desc: "excepts a code security finding"},
	// The local git hooks (security.githooks) are the developer's
	// per-repository consent, never an agent's: removing them lifts a
	// check, and installing them is the consent itself (lane sec-gate2,
	// decision log P-025: denied, no longer only flagged).
	{path: []string{"security", "githooks", "uninstall"}, grant: true, desc: "removes the code security git hooks"},
	{path: []string{"security", "githooks", "install"}, grant: true, desc: "installs the code security git hooks (the developer's consent)"},
	// The AI change records (security.provenance, lane sec-f2a): consent
	// for the repository writers (git notes, the commit trailer) is a
	// person's per-repository call either way, and a key reset changes
	// what every later record is signed with.
	{path: []string{"security", "provenance", "consent"}, grant: true, desc: "gives or withdraws consent for the AI change records' repository writers (git notes, the commit trailer)"},
	{path: []string{"security", "provenance", "rotate-key"}, grant: true, desc: "resets the AI change records' signing key"},
	// The online package checks' consent (lane SEC-D1FIX2 milestone 2e):
	// accepting what the checks send is the developer's call, never an
	// agent's. Reading the disclosure stays allowed.
	{
		path: []string{"security", "deps", "disclosure"}, grant: true, desc: "accepts the online package checks' disclosure, which turns them on",
		when: func(args, _ []string) bool { return hasFlag(args, "--accept") },
	},
	// The scanners' one-time OSV database accept (operator ruling PT-19
	// (2), lane sec-deps4): about 300 MB downloaded on the developer's
	// word, never an agent's. Reading the state (scan status) stays
	// allowed.
	//
	// OS-2 (ruling Q1 (b)): the one accept of the OS release databases, the
	// same verb with --os (any value: --os=false is the language accept,
	// denied by the next row), so this row only names it in the verdict.
	{
		path: []string{"security", "scan", "db", "accept"}, grant: true, desc: "accepts the OS release databases' download (the per-release databases scanned images use)",
		when: func(args, _ []string) bool { return hasFlag(args, "--os") },
	},
	{path: []string{"security", "scan", "db", "accept"}, grant: true, desc: "accepts the dependency scanners' OSV database download"},
	// Reserved for the Trivy image driver (plan 6.7, lane OS-2 T): the Trivy
	// database's one accept, denied before the verb exists so that lane needs
	// no R-165 edit.
	{path: []string{"security", "scan", "trivy-db", "accept"}, grant: true, desc: "accepts the Trivy vulnerability database download"},
	// The package lookup posture (OS and CI vulnerability scanning plan
	// sections 13.4 and 13.10, lane RM-2): what leaves the machine at every
	// dependency scan is the developer's call, never an agent's. Each verb
	// that changes the posture or gives or withdraws one of its consents is
	// denied; `observer security lookup` and `lookup status` only print.
	// `security scan remote accept` is the 13.4 spelling, denied before any
	// verb carries it.
	{path: []string{"security", "lookup", "mode"}, grant: true, desc: "chooses the package lookup mode (download the databases, or the superbased lookup), recording its consent"},
	{path: []string{"security", "lookup", "kinds"}, grant: true, desc: "chooses which package kinds the superbased lookup covers"},
	{path: []string{"security", "lookup", "private"}, grant: true, desc: "chooses whether the superbased lookup sends private and internal package names, recording its consent"},
	{path: []string{"security", "lookup", "withdraw"}, grant: true, desc: "withdraws a package lookup consent"},
	{path: []string{"security", "scan", "remote", "accept"}, grant: true, desc: "accepts the superbased package lookup"},
	// Lane OS-2 T (plan 6.7): choosing the image driver writes
	// [security.scan.image] driver, the developer's call like db_source (its
	// config-set and PUT forms fall under the config set row's [security]
	// section). Without a name the verb only prints the state.
	{
		path: []string{"security", "scan", "image", "driver"}, grant: true, desc: "chooses the driver that scans container images' OS packages ([security.scan.image] driver)",
		when: func(_, words []string) bool { return len(words) > 4 },
	},
	// Static feed mirroring plan section 8: installing an OSV database set
	// from a directory replaces what every dependency scan matches against,
	// which is the developer's call, never an agent's. (Its config keys,
	// security.deps.db_source and db_fallback_upstream, fall under the
	// config set row's [security] section.)
	{path: []string{"security", "scan", "db", "import"}, grant: true, desc: "installs an OSV database set (and the CISA KEV and FIRST EPSS exploit data beside it) from a directory, which every dependency scan then matches and ranks against"},
	// The build artifact folders (OS and CI vulnerability scanning plan
	// section 14.6, M3L-2 item 4, operator ruling 2026-11-05): full artifact
	// scanning is opt-in per folder, "an agent may not enable it on the
	// developer's behalf". Turning a folder on opens every program, archive
	// and wheel in it on each scan; turning one off lowers the coverage the
	// developer chose. `scan artifacts` alone and `list` only print, and
	// `scan --artifacts DIR` names a folder for one run and stores nothing.
	{path: []string{"security", "scan", "artifacts", "enable"}, grant: true, desc: "turns a build artifact folder on for dependency scanning, so every scan of the project opens the programs, archives and wheels in it"},
	{path: []string{"security", "scan", "artifacts", "disable"}, grant: true, desc: "turns a build artifact folder off for dependency scanning (the developer's chosen coverage)"},
	// The Go source check, 3b-src (OS and CI vulnerability scanning plan
	// sections 14.5 item 3b and 14.13 "Consent and R-165"): it runs the
	// project's own Go toolchain (go, cgo and the C compiler on project
	// input) under a multi-gigabyte memory cap, so the per-project opt-in
	// and every run are the developer's. `scan reach enable` records the
	// opt-in (with --allow-unisolated, also the isolation override) and
	// `disable` withdraws it; any `scan --reach ...` run is denied, its
	// --allow-unisolated override included. `scan reach` alone and `status`
	// only print.
	{path: []string{"security", "scan", "reach", "enable"}, grant: true, desc: "opts a project in to the Go source check, which runs the project's Go toolchain on its code (with --allow-unisolated, also outside isolation)"},
	{path: []string{"security", "scan", "reach", "disable"}, grant: true, desc: "withdraws a project's opt-in to the Go source check (the developer's chosen coverage)"},
	{
		path: []string{"security", "scan"}, grant: true, desc: "runs the Go source check, which runs the project's Go toolchain on its code (the developer starts every run)",
		when: func(args, _ []string) bool { return hasFlag(args, "--reach") || hasFlag(args, "--allow-unisolated") },
	},
	// The local passive DAST checker (OS and CI vulnerability scanning plan
	// section 14.9, phase M3L-5): "every run starts from the developer (card
	// or CLI); an agent cannot start it or give the accept". The accept, and
	// any run (`security dast <url>`), are denied; `security dast` alone
	// (help) and `security dast candidates` (reads .claude/launch.json,
	// contacts nothing) stay allowed.
	{path: []string{"security", "dast", "accept"}, grant: true, desc: "accepts the local DAST checker's requests to dev servers on this machine"},
	{
		path: []string{"security", "dast"}, grant: true, desc: "runs the local DAST checker against a dev server (the developer starts every run)",
		when: func(_, words []string) bool { return len(words) > 2 && words[2] != "candidates" },
	},
	// Lane GATES-SBX (G24): storing a provider key that the proxy then adds
	// to a sandboxed run's model requests is the person's call, never an
	// agent's. list and remove stay allowed (remove only takes injection
	// away).
	{path: []string{"sandbox", "credentials", "add"}, grant: true, desc: "stores a provider key that credential injection adds to sandboxed runs' model requests"},
	// Dashboard CLI parity (docs/plans/dashboard-cli-parity-plan-2026-11-06.md,
	// B-G2): the Hosted sandboxes panel's Connect route is pinned below, so its
	// CLI twin is too: storing a hosted provider credential is the person's call.
	{path: []string{"sandbox", "hosted", "connect"}, grant: true, desc: "stores a hosted sandbox provider credential that hosted sandbox launches use"},
	// Lane GATES-SBX (G50, audit F5): re-adopting a container run (or ending
	// it with --end), checkpointing it and restoring it are the person's
	// actions, never an agent's: a re-adoption attaches another box's
	// terminal, a checkpoint writes the box's memory to disk. `sandbox runs`
	// (the list) stays allowed.
	{path: []string{"sandbox", "readopt"}, grant: true, desc: "re-adopts (or, with --end, ends) a sandboxed container run whose helper went away"},
	{path: []string{"sandbox", "checkpoint"}, grant: true, desc: "checkpoints a sandboxed container run's memory to a file"},
	{path: []string{"sandbox", "restore"}, grant: true, desc: "restores a checkpointed sandboxed container run"},
	// Lane sbxinstall-guard (PT-89, plan sandbox-installation-lifecycle
	// section 8, ledger SBXSETUP-1): setting a sandbox backend up installs
	// and turns on host software (a package, a pinned download, an elevated
	// step in a terminal, a backends entry), one step per click or TTY
	// answer of the person's, never an agent's. `sandbox setup status` and
	// `records` only print; `check` asks (consentAskVerbs).
	{path: []string{"sandbox", "setup", "run"}, grant: true, desc: "installs and turns on a sandbox backend's prerequisites (packages, pinned downloads, elevated steps, the backends entry)"},
	{path: []string{"sandbox", "setup", "undo"}, grant: true, desc: "undoes a sandbox setup step (removes what it installed, or takes a backend out of the backends list)"},
	{path: []string{"sandbox", "setup", "update"}, grant: true, desc: "updates a sandbox prerequisite that setup installed"},
	{path: []string{"sandbox", "setup", "repair"}, grant: true, desc: "re-runs a sandbox setup step whose check now fails (re-downloads or reinstalls it)"},
	// Ruling R5 (PT-89): storing a hosted sandbox provider's key in the OS
	// keychain is the person's call, like `sandbox credentials add`.
	// `hosted disconnect` only removes the key.
	{path: []string{"sandbox", "hosted", "connect"}, grant: true, desc: "stores a hosted sandbox provider's key in the OS keychain"},
	{
		path: []string{"security", "baseline"}, grant: true, desc: "approves a baseline commit, so findings there read as pre-existing",
		when: func(args, _ []string) bool { return hasFlag(args, "--approve") },
	},
	// Lane sec-gate3 (decision log P-033): removing the security module
	// or one of its children switches the commit gate and the secret checks
	// off, and a teardown of one undoes what it wrote (the git hooks). A
	// remove without --yes only previews, which lowers nothing.
	{
		path: []string{"components", "remove"}, grant: true, desc: "removes a code security component, or one it requires, which switches its checks off",
		when: func(args, words []string) bool { return hasFlag(args, "--yes") && namesSecurityRemoval(words[2:]) },
	},
	// Lane sec-gate4 milestone 2b (the SECP-6 residual): a base selection
	// whose distro leaves a code security component, or one the tree
	// requires, inactive switches its checks off as surely as a remove.
	{
		path: []string{"components", "select"}, grant: true, desc: "selects a base without a code security component, or one it requires, which switches its checks off",
		when: func(args, words []string) bool {
			return hasFlag(args, "--yes") && len(words) > 2 && !keepsSecurityBase(words[2])
		},
	},
	// Only an explicit --dry-run (or --dry-run=true) previews: the CLI's
	// --dry-run is a bool flag, so `--dry-run=false` tears down (lane SEC-G4
	// milestone 1, the SEC-G2 audit's routed item, decision log P-073).
	{
		path: []string{"components", "teardown"}, grant: true, desc: "undoes what a code security component wrote (its git hooks)",
		when: func(args, words []string) bool {
			return !boolFlagTrue(args, "--dry-run") && namesSecurityComponent(words[2:])
		},
	},
	// Lane SEC-P4 decision 7 (SECP-6, the P-053 follow-up): a rollback
	// restores the previous binary, and with it the settings and the
	// guard rules that binary shipped, which can lower what the current
	// one enforces; the developer's call, never an agent's. Without --yes
	// it only prints what it would restore, which lowers nothing.
	{
		path: []string{"update", "rollback"}, grant: true, desc: "rolls the node back to its previous binary, which can lower a guard or code security setting",
		when: func(args, _ []string) bool { return boolFlagTrue(args, "--yes") },
	},
	// cli-parity L4 (plan docs/plans/dashboard-cli-parity-plan-2026-11-06.md,
	// B-G8): the audit chain repairs rewrite guard_events rows (repair-anchors
	// writes proven action ids, dedup-events deletes rows and re-hashes the
	// chain after them, relink-gaps rewrites every link after a gap). The
	// developer applies them (Security > Coverage, Repair audit chain, or
	// the CLI), never an agent. Without --apply each only reports; any
	// spelling of --apply counts (deny-biased, like disclosure --accept).
	{
		path: []string{"guard", "repair-anchors"}, grant: true, desc: "writes action ids into the guard audit chain's rows",
		when: func(args, _ []string) bool { return hasFlag(args, "--apply") },
	},
	{
		path: []string{"guard", "dedup-events"}, grant: true, desc: "deletes guard audit rows and re-hashes the audit chain",
		when: func(args, _ []string) bool { return hasFlag(args, "--apply") },
	},
	{
		path: []string{"guard", "relink-gaps"}, grant: true, desc: "rewrites the guard audit chain's links over deleted rows",
		when: func(args, _ []string) bool { return hasFlag(args, "--apply") },
	},
	// end cli-parity L4
	// Sweep finding SA-2: the gate hooks are how the guard judges a tool's
	// actions at all, so removing them from an AI tool switches every rule
	// off for it. The uninstall verbs remove them (only an explicit
	// --dry-run is a read; `setup uninstall` has none), and a component
	// change or teardown of integration.hooks or an adapter undoes that
	// tool's hook writes (a remove without --yes only previews).
	{
		path: []string{"uninstall"}, grant: true, desc: "removes Observer's gate hooks (and MCP entries and proxy routes) from AI tools, which switches the guard off for them",
		when: func(args, _ []string) bool { return !boolFlagTrue(args, "--dry-run") },
	},
	{path: []string{"setup", "uninstall"}, grant: true, desc: "runs `observer uninstall --all`, which removes Observer's gate hooks from every AI tool"},
	{
		path: []string{"components", "remove"}, grant: true, desc: "removes the hook registration or an adapter, which undoes the gate hooks it wrote into AI tools",
		when: func(args, words []string) bool { return hasFlag(args, "--yes") && namesHooksComponent(words[2:]) },
	},
	{
		path: []string{"components", "teardown"}, grant: true, desc: "undoes the gate hooks the hook registration or an adapter wrote into AI tools",
		when: func(args, words []string) bool {
			return !boolFlagTrue(args, "--dry-run") && namesHooksComponent(words[2:])
		},
	},
	{path: []string{"request", "access"}, desc: "requests a guard exception (a human decides it)"},
}

// hooksComponentRoot is the component that registers the gate hooks; an
// adapter's own row ("adapter.<tool>") undoes that tool's hook writes when
// it goes inactive (internal/components catalog).
const hooksComponentRoot = "integration.hooks"

// isHooksComponent reports whether a component id is the hook registration
// (or a child of it) or an adapter.
func isHooksComponent(id string) bool {
	id = strings.TrimSpace(id)
	return strings.EqualFold(id, hooksComponentRoot) || hasFoldPrefix(id, hooksComponentRoot+".") || hasFoldPrefix(id, "adapter.")
}

// namesHooksComponent reports whether any operand is a hooks component.
func namesHooksComponent(ids []string) bool {
	for _, id := range ids {
		if isHooksComponent(id) {
			return true
		}
	}
	return false
}

// consentAskVerbs are the R-165 CLI rows that ask in both modes: a consent
// that is the person's, which an agent's shell must not give, but which a
// person may script (so the row asks rather than denies, and asks with or
// without the command's own --yes). The grant field is unused here.
var consentAskVerbs = []selfApprovalVerb{
	// OSH-142 (plans ruling P-241): the laptop-relay opt-in (design 3.7)
	// lets this laptop relay org sandbox runs; `--yes` skips the command's
	// own disclosure prompt, so the guard asks instead.
	{path: []string{"sandbox", "org-shell", "opt-in"}, desc: "gives the person's consent to relay org sandbox runs through this laptop"},
	// Ruling R1 (PT-89, ledger SBXSETUP-3): the active check builds one
	// sandbox driver and runs its probe on this machine, which sandbox plan
	// v2 section 10.1 allows only on the person's word (a click or this
	// verb typed by them). It installs nothing, so the guard asks rather
	// than denies; `sandbox setup status` (passive facts) stays allowed.
	{path: []string{"sandbox", "setup", "check"}, desc: "runs a sandbox driver's probe on this machine on the person's word"},
	// The hosted consent (decision SBXD-5): agreeing to what a hosted run
	// sends to its provider is the person's; the guard asks.
	{path: []string{"sandbox", "hosted", "consent"}, desc: "records the person's agreement to what a hosted sandbox run sends to its provider"},
}

// verbRowMatches reports whether a CLI invocation (args, and their
// cliWords) runs row v: its path is the words' prefix, or cobra could reach
// it with a flag before or between the subcommand words (cobraPathWords,
// OSH-141), and its when func, if any, holds on one of those readings.
func verbRowMatches(args, words []string, v selfApprovalVerb) bool {
	for _, w := range cobraPathWords(args, words, v.path) {
		if v.when == nil || v.when(args, w) {
			return true
		}
	}
	return false
}

// matchConsentAskCLI is the R-165 CLI matcher for consentAskVerbs.
func matchConsentAskCLI(_ *MatchContext, cmd *Command) (bool, string) {
	args, ok := observerArgs(cmd)
	if !ok {
		return false, ""
	}
	words := cliWords(args)
	for _, v := range consentAskVerbs {
		if verbRowMatches(args, words, v) {
			return true, "observer " + strings.Join(v.path, " ") + " " + v.desc
		}
	}
	return false, ""
}

// securityComponentRoot is the component id of the security module; its
// children are "security.<child>".
const securityComponentRoot = "security"

// isSecurityComponent reports whether a component id is the security
// module or one of its children.
func isSecurityComponent(id string) bool {
	id = strings.TrimSpace(id)
	return strings.EqualFold(id, securityComponentRoot) || hasFoldPrefix(id, securityComponentRoot+".")
}

// namesSecurityComponent reports whether any operand is a security
// component id.
func namesSecurityComponent(ids []string) bool {
	for _, id := range ids {
		if isSecurityComponent(id) {
			return true
		}
	}
	return false
}

// securityTreeRequires lists every component id outside the security
// tree that the security module or one of its children requires, directly
// or through another (lane sec-gate3 audit finding 1). The components
// service removes every component that requires a removed one, so removing
// one of these switches the security module off as surely as removing it
// by name. A static list, because the policy package does not read the
// catalog; TestSecurityTreeRequiresMatchesCatalog pins it against
// internal/components so it cannot drift.
var securityTreeRequires = []string{"guard"}

// securityKeepingBases are the base selections (`components select`, the
// API's set_base) under which every code security component stays active,
// in the full build's terms: "" and "all" (everything compiled in) and the
// distros whose cells keep on every component of the security tree, and
// everything it requires, that the full distro has on. It is the fallback
// for a process whose binary injected nothing (SetSecurityKeepingBases),
// pinned against the catalog by TestSecurityKeepingBasesMatchCatalog.
// Selecting any other base switches security off unless the add list keeps
// it, which the policy cannot read, so R-165 matches it.
var securityKeepingBases = []string{"", "all", "full"}

// injectedKeepingBases is the binary's own list (SetSecurityKeepingBases).
var injectedKeepingBases atomic.Pointer[func() []string]

// SetSecurityKeepingBases injects the prebuilt base selections under which
// every code security component THIS binary compiles in and runs today
// stays active (plans decision log P-045). A base counts as dropping
// security only when it would switch off a security component, or one the
// security tree requires, that this build compiles and runs: selecting
// developer in a developer build (which does not compile
// security.scan.scalibr in) drops nothing, while in a build that compiles
// and runs that scanner it drops it. The binary computes the list from its
// own catalog and compiled set, which this package reads neither of; f is
// called on each check, so it should be memoized. "" and "all" always keep;
// a name the list does not hold (minimal, managed, an unknown or misspelt
// name) never does. nil restores the static fallback.
func SetSecurityKeepingBases(f func() []string) {
	if f == nil {
		injectedKeepingBases.Store(nil)
		return
	}
	injectedKeepingBases.Store(&f)
}

// keepsSecurityBase reports whether selecting base keeps the security
// module on.
func keepsSecurityBase(base string) bool {
	base = strings.TrimSpace(base)
	if base == "" || strings.EqualFold(base, "all") {
		return true
	}
	list := securityKeepingBases
	if f := injectedKeepingBases.Load(); f != nil {
		list = (*f)()
	}
	for _, b := range list {
		if strings.EqualFold(base, b) {
			return true
		}
	}
	return false
}

// lowersSecurityOnRemove reports whether removing a component id switches
// a code security component off: the id is in the security tree, or the
// tree requires it.
func lowersSecurityOnRemove(id string) bool {
	if isSecurityComponent(id) {
		return true
	}
	id = strings.TrimSpace(id)
	for _, r := range securityTreeRequires {
		if strings.EqualFold(id, r) {
			return true
		}
	}
	return false
}

// namesSecurityRemoval reports whether any operand is a component whose
// removal switches a code security component off.
func namesSecurityRemoval(ids []string) bool {
	for _, id := range ids {
		if lowersSecurityOnRemove(id) {
			return true
		}
	}
	return false
}

// matchSelfApprovalCLI is the R-165 CLI matcher for the grant (or, with
// grant false, the request) rows.
func matchSelfApprovalCLI(grant bool) MatchCmdFn {
	return func(_ *MatchContext, cmd *Command) (bool, string) {
		args, ok := observerArgs(cmd)
		if !ok {
			return false, ""
		}
		words := cliWords(args)
		for _, v := range selfApprovalVerbs {
			if v.grant != grant || !verbRowMatches(args, words, v) {
				continue
			}
			return true, "observer " + strings.Join(v.path, " ") + " " + v.desc
		}
		return false, ""
	}
}

// selfLoweringSections are the config sections an agent may not change:
// the guard's and the security pillar's (`security.secrets.write_check
// false` switches the in-hook secret check off; lane sec-gate2).
//
// [terminal.launch] joined them in lane cli-2 (PT-61): its keys
// (allow_fresh_agent, allowed_tools, allowed_project_roots) widen what an
// agent-started launch may start, which only the owner decides.
//
// [observer.hooks] joined them with sweep finding SA-2: auto_register =
// false and periodic_register = "off" stop the daemon putting back a gate
// hook an agent removed, and a short timeout_ms makes a gate hook give up.
var selfLoweringSections = []string{"guard", "security", "terminal.launch", "observer.hooks"}

// selfLoweringConfigKey reports whether a config key is in one of the
// selfLoweringSections (the section itself or a dotted key under it).
func selfLoweringConfigKey(key string) bool {
	if settingsApprovalConfigKey(key) {
		return true
	}
	for _, sec := range selfLoweringSections {
		if strings.EqualFold(key, sec) || hasFoldPrefix(key, sec+".") {
			return true
		}
	}
	return false
}

// wordsHavePrefix reports whether words start with path.
func wordsHavePrefix(words, path []string) bool {
	if len(words) < len(path) {
		return false
	}
	for i, p := range path {
		if words[i] != p {
			return false
		}
	}
	return true
}

// guardGrantRoute is one dashboard route R-165 guards.
type guardGrantRoute struct {
	path string
	// prefix also matches path + "/...".
	prefix bool
	// dotted also matches path + ".<key>" (a [guard.x] config section).
	dotted bool
	// body, when set, narrows the row to a request whose body lowers the
	// guard or the security module (the route carries every config key, or
	// every component change).
	body func(cmd *Command) bool
	desc string
}

// matchesPath reports whether a decoded, cleaned request path is this
// route (urlPath's form).
func (r guardGrantRoute) matchesPath(p string) bool {
	return p == r.path || (r.prefix && strings.HasPrefix(p, r.path+"/")) || (r.dotted && strings.HasPrefix(p, r.path+"."))
}

// guardGrantRouteFor returns the first guardGrantRoutes row whose path p
// is, its body narrowing aside.
func guardGrantRouteFor(p string) (guardGrantRoute, bool) {
	for _, r := range guardGrantRoutes {
		if r.matchesPath(p) {
			return r, true
		}
	}
	return guardGrantRoute{}, false
}

// guardGrantRoutes are the dashboard routes that lift a guard block or
// loosen the guard's policy, matched as a path or a path prefix.
var guardGrantRoutes = []guardGrantRoute{
	{path: "/api/guard/approvals", prefix: true, desc: "the guard exception register"},
	{path: "/api/guard/mcp/approve", desc: "the MCP approval route"},
	{path: "/api/guard/prompt/allow", prefix: true, desc: "the prompt detector allow route"},
	{path: "/api/guard/policy", desc: "the guard policy editor"},
	{path: "/api/guard/policy/project", desc: "the trusted project policy editor"},
	{path: "/api/guard/policy/backup", desc: "the guard policy backup restore"},
	{path: "/api/security/scanners/custom", prefix: true, desc: "the custom scanner accept route"},
	// Lane sec-c3: the Code security page's exception grant and baseline
	// approval (the revoke route only reopens a finding).
	{path: "/api/security/exceptions", desc: "the code security exception register"},
	{path: "/api/security/baseline", desc: "the code security baseline approval"},
	{path: "/api/guard/rules", prefix: true, desc: "the guard rule editor"},
	// cli-parity L4 (plan docs/plans/dashboard-cli-parity-plan-2026-11-06.md):
	// the [guard.cloud] consent card's write (B-G5, decision P-2: turning on
	// reputation lookups, the LLM judge, whose confident allow resolves an
	// ask, or the webhooks is the person's network consent) and the audit
	// chain repair jobs (B-G8: an apply rewrites guard_events rows). Every
	// write to either route matches; the GETs are reads.
	{path: "/api/guard/cloud", desc: "the guard cloud consent route (reputation lookups, LLM judge, webhooks)"},
	{path: "/api/guard/jobs/chain", desc: "the guard audit chain repair route"},
	// Guard recipes: the apply, remove, save and delete routes (POST
	// /api/guard/recipes/apply, /remove, /user, /user/delete). The GETs
	// (the catalog, show and preview) are reads.
	{path: "/api/guard/recipes", prefix: true, desc: "the guard recipe routes"},
	// end cli-parity L4
	// The dashboard form of `observer security trust accept` (lane
	// SEC-TRUSTFIX): its POST accepts a repository's commands.
	{path: "/api/security/trust", desc: "the repository trust accept route"},
	// The dashboard form of `observer security deps disclosure --accept`
	// (lane SEC-D1FIX2): its POST records the online checks' consent.
	{path: "/api/security/deps", desc: "the package checks consent route"},
	// The dashboard form of `observer security scan db accept` (lane
	// sec-deps4): its POST records the scanner database accept.
	//
	// Its POST with {"os":true} records the OS release databases' accept
	// (OS-2); the sibling path is reserved should that accept move to one.
	{path: "/api/security/scanners/db", desc: "the scanner database accept route"},
	{path: "/api/security/scanners/db/os", desc: "the OS release databases' accept route"},
	// Reserved for the Trivy image driver (plan 6.7, lane OS-2 T): its
	// database accept route.
	{path: "/api/security/scanners/trivydb", desc: "the Trivy database accept route"},
	// The package lookup posture card (lane RM-2, plan section 13.10): its
	// PUT writes [security.deps] match, remote_kinds and remote_private and
	// records or withdraws their consents. The 13.4 spelling of the remote
	// accept route is reserved beside it.
	{path: "/api/security/lookup", desc: "the package lookup posture route"},
	{path: "/api/security/scanners/remote", desc: "the superbased package lookup accept route"},
	// The build artifact folders (M3L-2 item 4, ruling 2026-11-05): the
	// Scanners card's per-folder opt-in; its PUT turns a folder on or off.
	{path: "/api/security/artifacts", desc: "the build artifact folder opt-in route"},
	// The Go source check's card (3b-src): its PUT records or withdraws a
	// project's opt-in (and the isolation override), its POST starts a run;
	// a GET is a read.
	{path: "/api/security/reach/go-source", prefix: true, desc: "the Go source check's opt-in and run route"},
	// The dashboard form of `observer security code install` (lane
	// SEC-G2): its POST records the size consent and starts the install.
	{path: "/api/security/code/install", desc: "the code rules' guided install and its size consent"},
	// The dashboard form of `observer security iac install` (lane
	// GATES-SEC): its POST records the size consent and starts the install.
	{path: "/api/security/iac/install", desc: "the IaC engines' guided install and its size consent"},
	// Reserved for the local DAST checker's dashboard card (plan 14.9,
	// M3L-5): its accept and its runs, under one prefix (a GET is a read).
	{path: "/api/security/dast", prefix: true, desc: "the local DAST checker's accept and run routes"},
	// The agent-run assessments: filing or taking back the organization request
	// of a held run (plan section 13.6). An agent that sends either is asking to
	// start a run under a lifted guardrail, which is the developer's call.
	{path: "/api/security/assessments/request", desc: "the security assessment organization request route"},
	{path: "/api/security/assessments/cancel", desc: "the held security assessment cancel route"},
	// Stopping a run and deleting the evidence stored for one are the developer's:
	// an agent that ends its own run record or removes the checked model and git
	// snapshots of its own run is hiding what it did.
	{path: "/api/security/assessments/stop", desc: "the security assessment stop route"},
	{path: "/api/security/assessments/delete-data", desc: "the security assessment stored-evidence delete route"},
	// The HTTP forms of `observer config set guard.*` and `security.*`.
	{path: "/api/config/section/guard", dotted: true, desc: "the [guard] settings section"},
	{path: "/api/config/section/security", dotted: true, desc: "the [security] settings section"},
	{path: "/api/config/keys", body: guardConfigKeyBody, desc: "a [guard], [security], [terminal.launch] or [observer.hooks] setting, or a D19 or confirm-tier settings key (ask through MCP set_setting instead)"},
	// Plane A W2-8 (ruling D19): the dashboard form of `observer config
	// proposals approve|reject`. A GET of the list is a read.
	{path: "/api/config/proposals", prefix: true, desc: "the settings proposals an AI agent filed, waiting for the person's approval"},
	// Plane A W2-7: the dashboard form of `observer sdk sign-in|sign-out`.
	{path: "/api/sdk/credential", desc: "the SDK key sign-in and sign-out route"},
	// Lane SEC-GATE5 milestone 3: the settings backup restore swaps the
	// previous config.toml back in, which can bring back a lower [guard] or
	// [security] setting (security.feedback.after_write = false among
	// them) with no key on the request to read, so every restore matches
	// (a GET of the backup is a read).
	{path: "/api/config/backup", desc: "the settings backup restore, which can bring back a lower [guard] or [security] setting"},
	// Lane SEC-GATE5 milestone 3: the route form of `observer security
	// code rules import` (no route serves it yet; lane G2's Scanners card
	// adds one under this prefix): a newer pack replaces the rules every
	// code scan runs, the developer's call.
	{path: "/api/security/code/rules", prefix: true, desc: "the code rule pack routes, whose import replaces the rules every code scan runs"},
	// The HTTP forms of `observer components remove security...` and
	// `components teardown security...` (lane sec-gate3).
	{path: "/api/components/apply", body: componentRemoveBody, desc: "a component change that removes a code security component or one it requires"},
	// Lane sec-gate4 milestone 2b: the API forms of `components select`
	// (set_base) and of the selection reset. A reset clears the add list,
	// which may be what keeps a code security component on; the policy
	// cannot read the list, so every reset matches.
	{path: "/api/components/apply", body: componentSetBaseBody, desc: "a component change that selects a base without a code security component or one it requires"},
	{path: "/api/components/apply", body: componentResetBody, desc: "a component change that resets the selection, which can drop a code security component the add list kept on"},
	{path: "/api/components/teardown", body: componentTeardownBody, desc: "a teardown of a code security component"},
	// Sweep finding SA-2: the HTTP forms of `components remove|teardown
	// integration.hooks|adapter.*`, the setup wizard's hooks undo (the
	// Connected tools Remove step) and the [observer.hooks] settings.
	{path: "/api/components/apply", body: hooksComponentRemoveBody, desc: "a component change that removes the hook registration or an adapter, which undoes the gate hooks it wrote"},
	{path: "/api/components/teardown", body: hooksComponentTeardownBody, desc: "a teardown of the gate hooks the hook registration or an adapter wrote"},
	{path: "/api/setup/hooks", body: setupHooksUndoBody, desc: "the setup wizard's hooks undo, which removes the gate hooks from an AI tool"},
	{path: "/api/config/section/observer.hooks", dotted: true, desc: "the [observer.hooks] settings section"},
	{path: "/api/config/section/observer", body: observerHooksSectionBody, desc: "the [observer] settings section's hook registration"},
	// The Code security page's git hooks route (lane sec-gate2, decision
	// log P-025): its POST installs or removes the hooks, both the
	// developer's per-repository call.
	{path: "/api/security/githooks", desc: "the code security git hooks route"},
	// The dashboard form of `observer sandbox credentials add` (lane
	// GATES-SBX, G24): its POST stores a provider key for injection.
	{path: "/api/terminal/sandbox/credentials", desc: "the sandbox credential injection key route"},
	// The sandbox card's strace switch (lane ptrace, PT-96): its POST lifts
	// PTRACE_SEIZE from the sandbox's syscall filter, the person's call on
	// this machine. The config file itself is R-160's, and `observer config
	// set` refuses the key (it is owned by this route).
	{path: "/api/terminal/sandbox/ptrace-seize", desc: "the sandbox strace switch, which lets sandboxed runs trace processes they start"},
	// The dashboard forms of `observer sandbox readopt --end`, `checkpoint`
	// and `restore` (lane GATES-SBX, audit F5): each POST under this prefix
	// ends, checkpoints or restores a run (the GET list is a read).
	{path: "/api/terminal/sandbox/readopt", prefix: true, desc: "the sandbox run re-adoption routes (end, checkpoint, restore)"},
	// The Terminals page's "Changes from sandboxed runs" panel (lane
	// RETURNS): each POST under this prefix opens a run's saved diff as a
	// branch of the person's repository, removes a saved diff, or removes a
	// sandboxed run's copy. An agent that sends one is applying, or erasing,
	// its own work; the GET list and diff preview are reads.
	{path: "/api/terminal/sandbox/returns", prefix: true, desc: "the routes that open a sandboxed run's changes as a branch or remove them"},
	// The dashboard forms of `observer sandbox setup run|undo|update|repair`
	// and `check` (lane sbxinstall-guard, PT-89, ledger SBXSETUP-1): each
	// POST under this prefix ({backend}/run, {backend}/check) installs,
	// turns on or probes a sandbox backend on the person's click. The GETs
	// (the summary, a backend's plan, an op's progress) are reads.
	{path: "/api/terminal/sandbox/setup", prefix: true, desc: "the sandbox setup routes, which install and turn on sandbox backends on the person's click"},
	// Ruling R5 (PT-89): the dashboard form of `observer sandbox hosted
	// connect`, whose POST stores a provider key in the OS keychain. It is
	// also the Hosted sandboxes panel's Connect form (cli-parity L3, B-G2;
	// one route, one row).
	{path: "/api/terminal/sandbox/hosted/connect", desc: "the hosted sandbox provider key route"},
	// The hosted consent (sandbox terminal gaps, decision SBXD-5's inline
	// clone consent): its POST records the person's agreement to what a
	// hosted run sends to the provider (the upload or the clone, the key
	// custody, the network), so an agent that sends one agrees for them.
	// The GET (the consent screen) is a read.
	{path: "/api/terminal/sandbox/hosted/consent", desc: "the hosted sandbox consent route, which records the person's agreement to what leaves this machine"},
	// Decision SBXD-4: its POST turns on a tool's own saved keys or its
	// login as a source of the model key a hosted box gets.
	{path: "/api/terminal/sandbox/hosted/key-sources", desc: "the hosted sandbox key sources route, which lets an agent's own saved keys or login go into a hosted box"},
	// Ruling R2 (PT-89, ledger TOOLINSTALL-GUARD-1): the guided install,
	// uninstall and record of AI tools. The double-submit confirm pair can
	// be minted by a local process, so without a row an agent could start
	// an AI tool install or uninstall through loopback. The GET list of
	// records (/api/terminal/installs) is a read.
	{path: "/api/terminal/install", desc: "the guided install, uninstall and record of AI tools"},
	{path: "/api/terminal/uninstall", desc: "the guided install, uninstall and record of AI tools"},
	{path: "/api/terminal/installs/forget", desc: "the guided install, uninstall and record of AI tools"},
	// cli-parity L3 (plan docs/plans/dashboard-cli-parity-plan-2026-11-06.md):
	// the Hosted sandboxes panel's Connect form (B-G2) stores a provider
	// credential that hosted sandbox launches use, the person's call like the
	// key route above; it is that route's row (R5 above), and its disconnect
	// only takes access away. A sandbox
	// settings save, or a More settings key write, that leaves the MXC tier
	// floor anywhere but process_container (B-G6) lets this machine use MXC's
	// weaker AppContainer tier: a loosening only the person makes. A body
	// whose windows block is present and not null without that value counts
	// (the server reads a missing mxc_tier as "", no floor). A sandbox
	// settings body the matcher cannot decode is R-167's: it denies every
	// one on that route (rules_sandboxallow.go), so this row reads only a
	// decoded body or, when it sees none, the command text. The re-attach
	// route (B-G3) sits under the readopt prefix above.
	{path: "/api/terminal/sandbox/config", body: func() func(cmd *Command) bool {
		text := regexp.MustCompile(`(?i)\\?["']?mxc_tier\\?["']?\s*[:=]\s*(?:null\b|\\?["']\s*(?:appcontainer\b|\\?["']))`)
		holdsProcessContainer := func(v *jsonNode) bool {
			tiers := v.members("mxc_tier")
			if len(tiers) == 0 {
				return false
			}
			last := tiers[len(tiers)-1] // encoding/json keeps the last of two equal keys
			return last.kind == jsonString && strings.TrimSpace(last.str) == "process_container"
		}
		return func(cmd *Command) bool {
			n, st := requestJSONBody(cmd)
			switch st {
			case bodyDecoded:
				hit := false
				n.walkMembers("windows", func(v *jsonNode) {
					hit = hit || (v.kind != jsonNull && !holdsProcessContainer(v))
				})
				return hit
			case bodyNone:
				for _, s := range []string{cmd.Raw, cmd.Heredoc, cmd.Payload} {
					if s != "" && text.MatchString(s) {
						return true
					}
				}
			}
			return false
		}
	}(), desc: "the sandbox settings editor, lowering the MXC tier floor"},
	{path: "/api/config/keys", body: func() func(cmd *Command) bool {
		const key = "terminal.sandbox.windows.mxc_tier"
		text := regexp.MustCompile(`(?i)\bkey\\?["']?\s*[:=]\s*\\?["']?\s*` + regexp.QuoteMeta(key) + `(?:\\?["'\s,}&]|$)`)
		return func(cmd *Command) bool {
			return bodyMemberLowers(cmd, "key", jsonStringJudged(func(k string) bool { return strings.EqualFold(strings.TrimSpace(k), key) })) || bodyMatches(cmd, text)
		}
	}(), desc: "the MXC tier floor setting"},
	// end cli-parity L3
	// The AI change records card (lane sec-f2a): its POST gives or
	// withdraws the per-repository writer consent or resets the key.
	{path: "/api/security/provenance", desc: "the AI change records route (repository writer consent, key reset)"},
	// The HTTP form of `observer update rollback --yes` (lane SEC-P4
	// decision 7): a body whose decoded rollback is true. A dry_run does
	// not preview a rollback (the daemon's apply takes the rollback branch
	// first, cmd/observer/update_wire.go applyLocked), so it never exempts
	// one; a plain apply or its dry run passes.
	{path: "/api/update/apply", body: updateRollbackBody, desc: "an update rollback, which restores the previous binary and can lower a guard or code security setting"},
	// Lane cli-2 (PT-61, security ledger LAUNCH-1): the launch policy is
	// the owner's to widen. Its editor (PUT /api/terminal/policy turns on
	// allow_fresh_agent and adds tools and project roots) and the settings
	// forms of the same [terminal.launch] keys are a self-approval of the
	// launches R-168 asks about.
	{path: "/api/terminal/policy", desc: "the terminal launch policy editor"},
	// The local dashboard's first-launch consent (launchpad, door A) writes
	// the same three [terminal.launch] keys in one save.
	{path: "/api/terminal/first-launch", desc: "the first-launch consent, which allows a tool, fresh launches and a project folder"},
	{path: "/api/config/section/terminal.launch", dotted: true, desc: "the [terminal.launch] settings section"},
	{path: "/api/config/section/terminal", body: terminalLaunchSectionBody, desc: "the [terminal] settings section's launch policy"},
	// Dashboard CLI parity follow-up (plan docs/plans/dashboard-cli-parity-
	// plan-2026-11-06.md section 9, ledger PARITY-7). The launch binary path
	// editor points a tool's launch at any file on the host, which the next
	// dashboard launch runs. A routing section save that sets the privacy
	// rules or the local upstreams decides which provider, or which host,
	// receives a prompt, and one that sets the path classes can make a
	// privacy rule's class match nothing. All are the owner's to change.
	{path: "/api/launch/tool-paths", desc: "the launch binary path editor"},
	{path: "/api/config/section/routing", body: routingEgressSectionBody, desc: "the [routing] settings section's privacy rules, path classes or local upstreams"},
	// Plane A review findings R-B01/R-B07 (ruling D19): the section and
	// policy routes that write a D19 family or a sensitive leaf. Each is
	// the HTTP form of `observer config set` of keys an agent may only
	// propose (MCP set_setting); settingsSectionRoutes lists them and the
	// dashboard's TestEverySectionWriterOfAnApprovalKeyIsR165 walks every
	// section writer against this table.
	sectionRoute("observability", nil, "the [observability] settings section (content capture, judges, admission)"),
	sectionRoute("org", nil, "the [org_client] sharing, scope and policy settings section"),
	// Found by the drift test (R-B01's "every section writer"): sections that
	// replace their whole struct (so any body resets a confirm-tier leaf) are
	// guarded whole; the process section is narrowed to its capture and ETW
	// listener members. "hooks" is the section id the Settings page writes
	// [observer.hooks] through (the observer.hooks row above names a path no
	// section serves).
	sectionRoute("hooks", nil, "the [observer.hooks] settings section (the gate hooks' registration and timeout)"),
	sectionRoute("proxy", nil, "the [proxy] settings section (upstreams, org route, client auth)"),
	sectionRoute("dashboard", nil, "the [dashboard] settings section (its listen address)"),
	sectionRoute("otel", nil, "the OTel exporter settings section (where telemetry and prompt content are sent)"),
	sectionRoute("secrets", nil, "the secrets scrubbing settings section"),
	sectionRoute("intelligence", nil, "the [intelligence] settings section (the summary model's key variable)"),
	sectionRoute("messages", nil, "the [messages] settings section (read receipts sent to the organization)"),
	sectionRoute("browser", nil, "the [browser] settings section (the stored capture ceiling)"),
	sectionRoute("process", sectionMembersBody("CaptureBodies", "ListenAddr", "AllowNonLoopback", "TokenPath"), "the process capture section's network body capture or ETW listener"),
	// E-24 (ruling D29): observer.db_path joined the D19 family; the
	// [observer] section writes it as the DBPath member.
	sectionRoute("observer", sectionMembersBody("DBPath"), "the [observer] settings section's database path"),
	// The dedicated editors of confirm-tier keys (R-B01's route sweep): the
	// SSH profiles editor ([terminal.ssh] enabled and profiles), the update
	// auto-apply switch and the pricing table (what budgets are measured in).
	{path: "/api/terminal/ssh/profiles", desc: "the SSH terminal profiles editor"},
	{path: "/api/update/auto-apply", desc: "the update auto-apply switch"},
	{path: "/api/config/pricing", desc: "the model pricing table, which budgets and cost limits are measured in"},
	{path: "/api/obs/admission/policy", desc: "the admission policy editor (what an app's requests are checked against, and whether they are blocked)"},
	{path: "/api/obs/egress/policy", desc: "the egress policy editor (where an app's model requests are routed)"},
	{path: "/api/obs/alerts/slack", desc: "the Slack alert webhook, where alert data is sent off this machine"},
	{path: "/api/obs/alerts/pagerduty", desc: "the PagerDuty routing key, where alert data is sent off this machine"},
}

// sectionMembersBody matches a section save whose body carries any of the
// named members (at any depth, in any case, as encoding/json reads them), or
// a body the matcher cannot read.
func sectionMembersBody(members ...string) func(cmd *Command) bool {
	anyValue := func(*jsonNode) bool { return true }
	return func(cmd *Command) bool {
		for _, m := range members {
			if bodyMemberLowers(cmd, m, anyValue) {
				return true
			}
		}
		return false
	}
}

// sectionRoute is a /api/config/section/<name> row (and its dotted
// /api/config/section/<name>.<sub> form). A nil body matches every write.
func sectionRoute(name string, body func(cmd *Command) bool, desc string) guardGrantRoute {
	return guardGrantRoute{path: "/api/config/section/" + name, dotted: true, body: body, desc: desc}
}

// routingEgressSectionBody: a [routing] section save whose body carries the
// privacy rules, the path classes those rules select by, or the local
// upstreams (a SetPrivacyRules, SetPathClasses or SetLocalUpstreams member at
// any depth, in any case; the server reads the exact name, so this matches
// more than it needs to), or a body the matcher cannot read.
func routingEgressSectionBody(cmd *Command) bool {
	anyValue := func(*jsonNode) bool { return true }
	for _, key := range []string{"SetPrivacyRules", "SetPathClasses", "SetLocalUpstreams"} {
		if bodyMemberLowers(cmd, key, anyValue) {
			return true
		}
	}
	return false
}

// guardConfigKey finds a self-lowering key path (selfLoweringSections, a D19
// family or a sensitive leaf) named as a key in a config keys request body
// ({"patches":[{"key":"security.x",...}]}): the "key" field's value, not any
// text that mentions the word (lane sec-gate3 milestone 2b; R-B07).
var guardConfigKey = regexp.MustCompile(selfLoweringKeyText())

// securityComponentList finds a security component id, or one of the
// exact ids in also, in a JSON list field of a components request body:
// the field name, then the list up to its closing bracket.
func securityComponentList(field string, also ...string) *regexp.Regexp {
	ids := `security(?:\.[a-z0-9_.-]*)?`
	for _, id := range also {
		ids += `|` + regexp.QuoteMeta(id)
	}
	return regexp.MustCompile(`(?i)\\?["']?` + field + `\\?["']?\s*:\s*\[[^\]]*\\?["']\s*(?:` + ids + `)\s*\\?["']`)
}

var (
	// componentRemoveList also names what the security tree requires: its
	// removal cascades to the security module (audit finding 1).
	componentRemoveList   = securityComponentList("remove", securityTreeRequires...)
	componentTeardownList = securityComponentList("ids")
	// componentSetBase reads a set_base field's value (quoted or escaped);
	// componentReset finds a reset field set true. Both are the text
	// fallback behind the decoded body.
	componentSetBase = regexp.MustCompile(`(?i)\\?["']?set_base\\?["']?\s*:\s*\\?["']([^"'\\]*)\\?["']`)
	componentReset   = regexp.MustCompile(`(?i)\\?["']?reset\\?["']?\s*:\s*true\b`)
)

// bodyUnreadable reports whether an HTTP client unit sends its body from a
// file or standard input (curl -d @f, --data-binary @-, -T, --json @f;
// wget --post-file; Invoke-WebRequest -InFile or a -Body variable): a body
// the matcher cannot read counts as one that names what the row guards, so
// an unreadable body never allows what a spelled-out one would deny.
func bodyUnreadable(cmd *Command) bool {
	switch cmd.Base {
	case "curl":
		if cmd.HasShortFlag('T') || cmd.HasLongFlag("--upload-file") {
			return true
		}
		for _, f := range []string{"-d", "--data", "--data-binary", "--data-ascii", "--json", "--data-urlencode"} {
			if v, ok := cmd.FlagValue(f); ok && strings.HasPrefix(strings.TrimLeft(v, "'\""), "@") {
				return true
			}
		}
	case "wget":
		return cmd.HasLongFlag("--post-file", "--body-file")
	case "invoke-webrequest", "invoke-restmethod":
		args := cmd.Args()
		for i, a := range args {
			name, inline, hasInline := strings.Cut(a, ":")
			if psParamMatches(name, "infile", 2) {
				return true
			}
			if psParamMatches(name, "body", 2) {
				v := inline
				if !hasInline && i+1 < len(args) {
					v = args[i+1]
				}
				if v == "" || strings.ContainsAny(v[:1], "$(@") {
					return true
				}
			}
		}
	}
	return false
}

// bodyMatches reports whether a request's readable body texts match re, or
// its body is unreadable.
func bodyMatches(cmd *Command, re *regexp.Regexp) bool {
	if bodyUnreadable(cmd) {
		return true
	}
	for _, text := range []string{cmd.Raw, cmd.Heredoc, cmd.Payload} {
		if text != "" && re.MatchString(text) {
			return true
		}
	}
	return false
}

// The body rows below judge the DECODED JSON body first (requestJSONBody,
// lane sec-gate4 audit finding 2: a \u escape in a value or a key, a key
// in another case, a duplicate key), at any depth and every occurrence, an
// undecodable body counting as one that names what the row guards; the
// text regexes over the command line, heredoc and payload stay as a second
// reading for a body the matcher does not see as such.

// guardConfigKeyBody: a config keys request that names a [guard] or
// [security] key.
func guardConfigKeyBody(cmd *Command) bool {
	return bodyMemberLowers(cmd, "key", jsonStringJudged(selfLoweringConfigKey)) || bodyMatches(cmd, guardConfigKey)
}

// terminalLaunchSectionBody: a [terminal] section save whose body carries
// the launch policy (a "launch" member at any depth, in any case, as the
// server's decoder reads it), or a body the matcher cannot read.
func terminalLaunchSectionBody(cmd *Command) bool {
	return bodyMemberLowers(cmd, "launch", func(*jsonNode) bool { return true })
}

// componentRemoveBody: a component change whose remove list names a
// security component or one the security tree requires.
func componentRemoveBody(cmd *Command) bool {
	return bodyMemberLowers(cmd, "remove", jsonListNames(lowersSecurityOnRemove)) || bodyMatches(cmd, componentRemoveList)
}

// updateRollbackBody: an update apply whose body asks for a rollback
// (any occurrence of rollback true, or neither a boolean nor null, as the
// server's decoder may read it), or a body the matcher cannot read (fail
// closed).
func updateRollbackBody(cmd *Command) bool {
	n, st := requestJSONBody(cmd)
	switch st {
	case bodyUndecodable:
		return true
	case bodyNone:
		return false
	}
	for _, v := range n.members("rollback") {
		if jsonTrueOrOdd(v) {
			return true
		}
	}
	return false
}

// componentTeardownBody: a teardown whose ids name a security component,
// unless its body decodes to an object whose top-level dry_run is true,
// every occurrence of it (it only previews, like the CLI's --dry-run; lane
// sec-gate4 milestone 2c). A "dry_run":true anywhere else, a header, a
// nested field, or a duplicate key the server reads as false, never
// allows (audit finding 1).
func componentTeardownBody(cmd *Command) bool {
	if bodyTopLevelTrue(cmd, "dry_run") {
		return false
	}
	return bodyMemberLowers(cmd, "ids", jsonListNames(isSecurityComponent)) || bodyMatches(cmd, componentTeardownList)
}

// hooksComponentIDs is the text form of isHooksComponent.
const hooksComponentIDs = `integration\.hooks(?:\.[a-z0-9_.-]*)?|adapter\.[a-z0-9_.-]+`

var (
	hooksComponentRemoveList   = componentListText("remove", hooksComponentIDs)
	hooksComponentTeardownList = componentListText("ids", hooksComponentIDs)
	// setupUndoText is the text fallback for an undo set true.
	setupUndoText = regexp.MustCompile(`(?i)\\?["']?undo\\?["']?\s*:\s*true\b`)
)

// componentListText finds one of ids (a regexp alternation) in a JSON list
// field of a components request body, as securityComponentList does.
func componentListText(field, ids string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)\\?["']?` + field + `\\?["']?\s*:\s*\[[^\]]*\\?["']\s*(?:` + ids + `)\s*\\?["']`)
}

// hooksComponentRemoveBody: a component change whose remove list names the
// hook registration or an adapter (an unreadable body counts).
func hooksComponentRemoveBody(cmd *Command) bool {
	return bodyMemberLowers(cmd, "remove", jsonListNames(isHooksComponent)) || bodyMatches(cmd, hooksComponentRemoveList)
}

// hooksComponentTeardownBody: a teardown whose ids name the hook
// registration or an adapter, unless its top-level dry_run is true (the
// componentTeardownBody rule).
func hooksComponentTeardownBody(cmd *Command) bool {
	if bodyTopLevelTrue(cmd, "dry_run") {
		return false
	}
	return bodyMemberLowers(cmd, "ids", jsonListNames(isHooksComponent)) || bodyMatches(cmd, hooksComponentTeardownList)
}

// setupHooksUndoBody: a setup wizard hooks request whose undo is true (or
// neither a boolean nor null, at any depth), unless its top-level dry_run
// is true, which only reports (setup_wizard.go wizardRemove). An
// unreadable body counts.
func setupHooksUndoBody(cmd *Command) bool {
	if bodyTopLevelTrue(cmd, "dry_run") {
		return false
	}
	return bodyMemberLowers(cmd, "undo", jsonTrueOrOdd) || bodyMatches(cmd, setupUndoText)
}

// observerHooksSectionBody: an [observer] section save whose body carries
// the hook settings (a "hooks" member at any depth, in any case, as the
// server's decoder reads it), or a body the matcher cannot read.
func observerHooksSectionBody(cmd *Command) bool {
	return bodyMemberLowers(cmd, "hooks", func(*jsonNode) bool { return true })
}

// componentSetBaseBody: a component change whose set_base selects a base
// that does not keep the security module on (an unreadable body counts).
func componentSetBaseBody(cmd *Command) bool {
	if bodyMemberLowers(cmd, "set_base", jsonStringJudged(func(b string) bool { return !keepsSecurityBase(b) })) || bodyUnreadable(cmd) {
		return true
	}
	for _, text := range []string{cmd.Raw, cmd.Heredoc, cmd.Payload} {
		for _, m := range componentSetBase.FindAllStringSubmatch(text, -1) {
			if !keepsSecurityBase(m[1]) {
				return true
			}
		}
	}
	return false
}

// componentResetBody: a component change that resets the selection (an
// unreadable body counts).
func componentResetBody(cmd *Command) bool {
	return bodyMemberLowers(cmd, "reset", jsonTrueOrOdd) || bodyMatches(cmd, componentReset)
}

// httpWriteMethods are the methods that create or change a resource. A
// DELETE on these routes revokes, which never loosens the guard.
var httpWriteMethods = setOf("POST", "PUT", "PATCH")

// httpClientMethod reads the request method of an HTTP client unit: an
// explicit method option, or the method a body implies. ok is false for a
// unit that is not a known HTTP client.
func httpClientMethod(cmd *Command) (string, bool) {
	switch cmd.Base {
	case "curl":
		if m, ok := cmd.FlagValue("-X", "--request"); ok {
			return strings.ToUpper(m), true
		}
		if cmd.HasShortFlag('G') || cmd.HasLongFlag("--get") {
			return "GET", true
		}
		if cmd.HasShortFlag('T') || cmd.HasLongFlag("--upload-file") {
			return "PUT", true
		}
		for _, f := range []string{"-d", "--data", "--data-binary", "--data-ascii", "--data-raw", "--data-urlencode", "--json", "-F", "--form"} {
			if _, ok := cmd.FlagValue(f); ok {
				return "POST", true
			}
		}
		return "GET", true
	case "wget":
		if m, ok := cmd.FlagValue("--method"); ok {
			return strings.ToUpper(m), true
		}
		if cmd.HasLongFlag("--post-data", "--post-file") {
			return "POST", true
		}
		return "GET", true
	case "invoke-webrequest", "invoke-restmethod":
		return psWebMethod(cmd), true
	case "http", "https", "xh", "xhs":
		for _, p := range cmd.Positionals() {
			if up := strings.ToUpper(p); httpWriteMethods[up] || up == "GET" || up == "DELETE" {
				return up, true
			}
			if strings.Contains(p, "=") && !strings.Contains(p, "==") {
				return "POST", true
			}
		}
		return "GET", true
	}
	return "", false
}

// psWebMethod reads the method of an Invoke-WebRequest / Invoke-RestMethod
// unit (PSRULES lane). PowerShell binds a parameter by any unambiguous
// prefix (-Me, -Meth), takes an inline value (-Method:Post) and, in
// PowerShell 7, a -CustomMethod. A value the reader cannot know (a
// variable or an expression) counts as a write, so an unreadable method
// never allows what a spelled-out POST would deny. No method is GET, as in
// PowerShell (a -Body alone does not change it).
func psWebMethod(cmd *Command) string {
	args := cmd.Args()
	for i := 0; i < len(args); i++ {
		name, inline, hasInline := strings.Cut(args[i], ":")
		if !psParamMatches(name, "method", 2) && !psParamMatches(name, "custommethod", 2) {
			continue
		}
		v := inline
		if !hasInline {
			if i+1 >= len(args) {
				return "POST"
			}
			v = args[i+1]
		}
		if v == "" || strings.ContainsAny(v[:1], "$(@") {
			return "POST"
		}
		return strings.ToUpper(v)
	}
	return "GET"
}

// urlPath returns the path of a URL argument (scheme and host removed,
// query and fragment cut) in the form the dashboard's ServeMux routes on:
// percent-decoded once, cleaned (dot segments resolved, repeated slashes
// collapsed, the trailing slash dropped) and lowercased (audit finding
// N5-A2: `%61llow`, `//allow`, which the mux answers with a redirect a
// client follows with its method and body, and `./` spellings all reach
// the handler a raw comparison missed). ok is false when the path does not
// percent-decode; a caller treats that as a match (fail closed), since the
// path cannot be told apart from a guarded route.
func urlPath(u string) (p string, ok bool) {
	lu := strings.ToLower(u)
	rest := strings.TrimPrefix(strings.TrimPrefix(lu, "https://"), "http://")
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return "", true
	}
	p = rest[i:]
	if j := strings.IndexAny(p, "?#"); j >= 0 {
		p = p[:j]
	}
	dec, err := url.PathUnescape(p)
	if err != nil {
		return p, false
	}
	return strings.TrimRight(path.Clean(strings.ToLower(dec)), "/"), true
}

// loopbackURLHost reports whether a lowercased http(s) URL names a host
// the local dashboard answers on (loopbackHost), under every reading of its
// authority a client may take (urlHostCandidates).
func loopbackURLHost(u string) bool {
	for _, h := range urlHostCandidates(u) {
		if loopbackHost(h) {
			return true
		}
	}
	return false
}

// urlHostCandidates returns the host of a lowercased URL (scheme optional)
// under each reading a client may take, port and brackets kept for
// loopbackHost to strip: the userinfo ending at the first '@' and at the
// last one (clients disagree; `http://a@b@127.0.0.1/` is 127.0.0.1 to
// most), each also percent-decoded (a WHATWG parser decodes
// `%31%32%37.0.0.1`).
func urlHostCandidates(u string) []string {
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		rest = rest[:end]
	}
	auths := []string{rest}
	if first, last := strings.IndexByte(rest, '@'), strings.LastIndexByte(rest, '@'); first >= 0 {
		auths = []string{rest[first+1:]}
		if last != first {
			auths = append(auths, rest[last+1:])
		}
	}
	var out []string
	for _, a := range auths {
		out = append(out, a)
		if strings.Contains(a, "%") {
			if dec, err := url.PathUnescape(a); err == nil && dec != a {
				out = append(out, strings.ToLower(dec))
			}
		}
	}
	return out
}

// splitHostPort strips a port and IPv6 brackets from host[:port]. ok is
// false for a bracketed host with no closing bracket.
func splitHostPort(hp string) (host string, bracketed, ok bool) {
	if strings.HasPrefix(hp, "[") {
		end := strings.IndexByte(hp, ']')
		if end < 0 {
			return hp, true, false
		}
		return hp[1:end], true, true
	}
	if i := strings.IndexByte(hp, ':'); i >= 0 {
		hp = hp[:i]
	}
	return hp, false, true
}

// loopbackHostRow is one row of the loopback host table: the first row
// whose test holds answers.
type loopbackHostRow struct {
	// why names the row for a reader of the table.
	why string
	// test reports whether the row decides the host (already lowercased,
	// port and brackets stripped, one trailing dot removed).
	test func(h string, bracketed bool) bool
	// loopback is the row's answer.
	loopback bool
}

// loopbackHostRows decide whether a URL host names this machine for the
// dashboard's route rules (R-165, R-167, R-168; sweep finding UI-1). The
// dashboard accepts a request whose Host is loopback by net.ParseIP, which
// reads an IPv4-mapped IPv6 literal (`[::ffff:127.0.0.1]`, `[::ffff:7f00:1]`)
// as loopback, and the client may dial an inet_aton spelling
// (`2130706433`, `0x7f.1`) with a loopback Host header. The rows read the
// host as ipclass does (ipclass.ParseHostIP: inet_aton forms, brackets,
// zone ids), unmap it (ipclass.Detail), and fail closed where clients and
// resolvers disagree. Deny-biased: a false "loopback" only matters when the
// path is also a guarded route.
var loopbackHostRows = []loopbackHostRow{
	{why: "no host", test: func(h string, _ bool) bool { return h == "" }, loopback: false},
	{
		// IDNA folds full-width and other compatibility forms onto ASCII
		// (`ｌｏｃａｌｈｏｓｔ`, `127。0。0。1`), which this table does not
		// reimplement.
		why: "a non-ASCII host fails closed",
		test: func(h string, _ bool) bool {
			for i := 0; i < len(h); i++ {
				if h[i] >= 0x80 {
					return true
				}
			}
			return false
		},
		loopback: true,
	},
	{
		// curl and the browsers resolve every name under .localhost to the
		// loopback address themselves (RFC 6761).
		why:      "localhost and *.localhost",
		test:     func(h string, _ bool) bool { return h == "localhost" || strings.HasSuffix(h, ".localhost") },
		loopback: true,
	},
	{
		why: "an IP literal that is loopback or unspecified (any inet_aton or IPv6 spelling, mapped or embedded IPv4 unwrapped)",
		test: func(h string, _ bool) bool {
			ip, ok := ipclass.ParseHostIP(h)
			if !ok {
				return false
			}
			k := ipclass.Detail(ip)
			return k == ipclass.KindLoopback || k == ipclass.KindUnspecified
		},
		loopback: true,
	},
	{
		// A bracketed host is an IPv6 literal by construction; one this
		// reader cannot parse is one a client may still parse its own way.
		why: "a bracketed literal that does not parse fails closed",
		test: func(h string, bracketed bool) bool {
			_, ok := ipclass.ParseHostIP(h)
			return bracketed && !ok
		},
		loopback: true,
	},
	{
		// `3232235777`, `0300.0250.1.1`, `1.2.3.4.5`: readers differ on
		// octal, hex and short forms (and Windows, glibc and curl's own
		// parser disagree), so only a plain dotted quad is trusted to mean
		// the address it spells.
		why:      "a numeric host that is not a plain dotted quad fails closed",
		test:     func(h string, _ bool) bool { return numericHost(h) && !plainDottedQuad(h) },
		loopback: true,
	},
}

// loopbackHost classifies one host[:port] by loopbackHostRows (one
// trailing dot removed first: `localhost.` and `127.0.0.1.` are the same
// hosts). Anything no row decides is not loopback.
func loopbackHost(hostport string) bool {
	h, bracketed, ok := splitHostPort(strings.ToLower(strings.TrimSpace(hostport)))
	if !ok {
		return true // an unclosed bracket: fail closed
	}
	h = strings.TrimSuffix(h, ".")
	for _, row := range loopbackHostRows {
		if row.test(h, bracketed) {
			return row.loopback
		}
	}
	return false
}

// numericHost reports a host every dot-separated label of which reads as a
// number to inet_aton (decimal digits, or a 0x hex form).
func numericHost(h string) bool {
	if h == "" {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || label[0] < '0' || label[0] > '9' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c == 'x') {
				return false
			}
		}
	}
	return true
}

// plainDottedQuad reports four decimal labels of at most three digits, no
// leading zero, each at most 255: the one numeric spelling every reader
// agrees on.
func plainDottedQuad(h string) bool {
	labels := strings.Split(h, ".")
	if len(labels) != 4 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 3 || (len(l) > 1 && l[0] == '0') {
			return false
		}
		n, err := strconv.Atoi(l)
		if err != nil || n > 255 {
			return false
		}
	}
	return true
}

// hostHeaderText finds a Host header set on a command line in any client's
// spelling: curl -H 'Host: x' (and the attached -HHost: x), wget
// --header='Host: x', HTTPie's Host:x item, PowerShell's -Headers
// @{Host='x'}. It captures the value.
var hostHeaderText = regexp.MustCompile(`(?i)(?:^|[\s'"{;,@(=]|-h)host\s*[:=]\s*['"]?\s*([^\s'",;}]+)`)

// loopbackTargetForced reports whether an HTTP client unit sends whatever
// URL it names to this machine's dashboard, so every URL it names counts as
// a loopback target: a loopback Host header (the dashboard checks only the
// Host, and a name such as localtest.me resolves to 127.0.0.1), a header
// read from a file (unreadable, so it may be one), or curl's --resolve /
// --connect-to pointing a name at a loopback address.
func loopbackTargetForced(cmd *Command) bool {
	for _, m := range hostHeaderText.FindAllStringSubmatch(cmd.Raw, -1) {
		if loopbackHost(strings.Trim(m[1], `'"`)) {
			return true
		}
	}
	if cmd.Base != "curl" {
		return false
	}
	args := cmd.Args()
	for i := 0; i < len(args); i++ {
		for _, f := range []string{"-H", "--header"} {
			if v, n := flagValueAt(args, i, f); n > 0 && strings.HasPrefix(strings.TrimSpace(v), "@") {
				return true
			}
		}
		if v, n := flagValueAt(args, i, "--resolve"); n > 0 {
			// [+]host:port:addr[,addr]...
			if parts := splitColons(strings.TrimPrefix(v, "+")); len(parts) >= 3 {
				for _, a := range strings.Split(strings.Join(parts[2:], ":"), ",") {
					if loopbackHost(a) {
						return true
					}
				}
			}
		}
		if v, n := flagValueAt(args, i, "--connect-to"); n > 0 {
			// HOST1:PORT1:HOST2:PORT2; an empty HOST2 keeps the URL's host.
			if parts := splitColons(v); len(parts) >= 3 && parts[2] != "" && loopbackHost(parts[2]) {
				return true
			}
		}
	}
	return false
}

// splitColons splits a colon-separated value, keeping a bracketed IPv6
// literal ([::1]) whole.
func splitColons(v string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				out = append(out, v[start:i])
				start = i + 1
			}
		}
	}
	return append(out, v[start:])
}

// loopbackPath is one loopback URL's path as urlPath reads it; decoded is
// false when the path does not percent-decode (R-165 then fails closed).
type loopbackPath struct {
	path    string
	decoded bool
}

// loopbackWritePaths returns the write method of an HTTP client unit and
// the lowercased paths of every loopback URL it names; no paths when the
// unit is not an HTTP client or its method does not write (R-165 and
// R-168 share it).
func loopbackWritePaths(cmd *Command) (method string, paths []string) {
	method, urls := loopbackWriteURLs(cmd)
	for _, u := range urls {
		paths = append(paths, u.path)
	}
	return method, paths
}

// loopbackWriteURLs is loopbackWritePaths keeping each path's decoded flag.
func loopbackWriteURLs(cmd *Command) (method string, paths []loopbackPath) {
	method, ok := httpClientMethod(cmd)
	if !ok || !httpWriteMethods[method] {
		return "", nil
	}
	return method, loopbackURLArgs(cmd)
}

// loopbackURLArgs returns the path of every loopback URL an HTTP client
// unit's arguments name, the one reading R-165, R-167 and R-168 share. When
// loopbackTargetForced holds, every URL-shaped argument (one carrying a
// scheme, or a positional) is a loopback target whatever host it names.
func loopbackURLArgs(cmd *Command) []loopbackPath {
	forced := loopbackTargetForced(cmd)
	var positional map[string]bool
	if forced {
		positional = setOf(cmd.Positionals()...)
	}
	var paths []loopbackPath
	for _, a := range cmd.Args() {
		la := strings.ToLower(a)
		if _, v, ok := strings.Cut(la, ":"); ok && strings.HasPrefix(la, "-") && strings.Contains(v, "://") {
			// A PowerShell parameter with an inline value: -Uri:http://...
			la = v
		}
		hasScheme := strings.HasPrefix(la, "http://") || strings.HasPrefix(la, "https://")
		if !hasScheme {
			la = "http://" + la
		}
		switch {
		case forced && (hasScheme || positional[a]):
		case loopbackURLHost(la):
		default:
			continue
		}
		p, decoded := urlPath(la)
		paths = append(paths, loopbackPath{path: p, decoded: decoded})
	}
	return paths
}

// matchSelfApprovalHTTP is the R-165 route matcher: an HTTP client writing
// to a loopback guard grant route.
func matchSelfApprovalHTTP(_ *MatchContext, cmd *Command) (bool, string) {
	method, urls := loopbackWriteURLs(cmd)
	for _, u := range urls {
		p := u.path
		if !u.decoded {
			return true, method + " " + p + " (a path that does not percent-decode, read as a guard grant route)"
		}
		for _, r := range guardGrantRoutes {
			if !r.matchesPath(p) {
				continue
			}
			if r.body != nil && !r.body(cmd) {
				continue
			}
			return true, method + " " + p + " (" + r.desc + ")"
		}
	}
	return false, ""
}

// inlineURLText finds a URL literal in program text, up to the first
// character that closes a string or an argument.
var inlineURLText = regexp.MustCompile("(?i)\\bhttps?://[^\\s'\"`<>(){},;\\\\]+")

// inlineLoopbackPaths returns the paths an interpreter's program text
// (python -c, node -e, ruby -e, perl -e, a heredoc or a script piped into
// one: inlinePrograms, the source the consent-record rows read) or a
// PowerShell .NET call (`[Net.WebClient]::new().UploadString(...)`, which
// no HTTP client unit carries) names on this machine's dashboard (sweep
// finding SA-4):
//
//   - every URL literal whose host is loopback (loopbackURLHost), and
//   - when the text names this machine at all (such a URL, or a quoted
//     literal that is a loopback host, `HTTPConnection('127.0.0.1', 8820)`),
//     every quoted literal that is a path, so a base URL and a path joined
//     at run time are read together.
//
// Program text shows no method, so the caller judges a named route as a
// write to it.
func inlineLoopbackPaths(ctx *MatchContext, cmd *Command) []loopbackPath {
	programs, _ := inlinePrograms(ctx, cmd)
	if cmd.Dialect == DialectPowerShell {
		if _, ok := httpClientMethod(cmd); !ok {
			if lr := strings.ToLower(cmd.Raw); strings.Contains(lr, "]::") || strings.Contains(lr, "new-object") {
				programs = append(programs, cmd.Raw)
			}
		}
	}
	var out []loopbackPath
	for _, p := range programs {
		names := false
		for _, u := range inlineURLText.FindAllString(p, -1) {
			lu := strings.ToLower(u)
			if !loopbackURLHost(lu) {
				continue
			}
			names = true
			if path, decoded := urlPath(lu); path != "" {
				out = append(out, loopbackPath{path: path, decoded: decoded})
			}
		}
		lits := scriptLiterals(p)
		if !names {
			for _, l := range lits {
				if t := strings.TrimSpace(l.text); t != "" && !strings.ContainsAny(t, " /") && loopbackHost(t) {
					names = true
					break
				}
			}
		}
		if !names {
			continue
		}
		for _, l := range lits {
			t := strings.TrimSpace(strings.ToLower(l.text))
			if strings.Contains(t, "://") || strings.ContainsAny(t, " \t\r\n") {
				continue
			}
			if !strings.HasPrefix(t, "/") {
				if !strings.HasPrefix(t, "api/") {
					continue
				}
				t = "/" + t
			}
			path, decoded := urlPath("http://x" + t)
			out = append(out, loopbackPath{path: path, decoded: decoded})
		}
	}
	return out
}

// matchSelfApprovalInlineHTTP is the R-165 inline-program route matcher: a
// guardGrantRoutes path the program text names on this machine. A row's
// body narrowing does not apply: the body is built by the program, which
// this reader does not run, so it counts as one that names what the row
// guards (the bodyUnreadable rule).
func matchSelfApprovalInlineHTTP(ctx *MatchContext, cmd *Command) (bool, string) {
	for _, u := range inlineLoopbackPaths(ctx, cmd) {
		if !u.decoded {
			return true, u.path + " (a path that does not percent-decode, named in an inline script, read as a guard grant route)"
		}
		if r, ok := guardGrantRouteFor(u.path); ok {
			return true, u.path + " (" + r.desc + ", named in an inline script)"
		}
	}
	return false, ""
}

// sqlSchemaPrefix matches an optional schema qualifier before a table
// name, quoted or not (main.sec_findings, "main"."sec_findings",
// [temp].x; lane sec-gate3 milestone 2b), and the table name's own
// opening quote.
const sqlSchemaPrefix = `(?:["'\x60\[]?\w+["'\x60\]]?\s*\.\s*)?["'\x60\[]?`

// guardRegisterTables are the registers guardGrantSQL guards, and
// findingTables the ones findingDropSQL does. Every name must satisfy
// mayNameGuardRegister (TestGuardRegisterTablesCarryTheHint).
var (
	guardRegisterTables = []string{"guard_approvals", "sec_config_baseline", "sec_finding_exceptions", "sec_baselines", "sec_findings", "sec_finding_commits", "sec_change_consent", "sec_change_keys"}
	findingTables       = []string{"sec_findings", "sec_finding_commits"}
)

// guardGrantSQL finds SQL that writes a grant into the approvals register.
var guardGrantSQL = regexp.MustCompile(`(?i)\b(?:insert(?:\s+or\s+\w+)?\s+into|replace\s+into|update(?:\s+or\s+\w+)?)\s+` + sqlSchemaPrefix +
	`(` + strings.Join(guardRegisterTables, "|") + `)\b`)

// findingDropSQL finds SQL that deletes findings outright (lane sec-gate2,
// decision log P-025): a deleted open finding leaves the commit gate's
// blocking set as surely as a suppressed one. Deleting an approval or an
// exception revokes it, which never loosens anything, so only the findings
// table is named.
var findingDropSQL = regexp.MustCompile(`(?i)\b(?:delete\s+from|drop\s+table(?:\s+if\s+exists)?|truncate(?:\s+table)?)\s+` + sqlSchemaPrefix +
	`(?:` + strings.Join(findingTables, "|") + `)\b`)

// mayNameGuardRegister is the cheap necessary condition of guardGrantSQL
// and findingDropSQL (demo bug #14, R3-5): both end in a register table
// name, and every name holds "ec_" or "_approval", so a text holding
// neither cannot match either expression. The test is ASCII
// case-insensitive, which is the regexes' (?i) for these letters exactly:
// no rune outside ASCII case-folds to e, c, a, p, r, o, v or l (only k and
// s have non-ASCII fold partners, and the hints avoid both;
// TestGuardRegisterHintFoldsAreASCII). Before it, two case-insensitive
// regexes with a leading word boundary scanned every unit's text, a tenth
// of a week's replay.
func mayNameGuardRegister(s string) bool {
	for i := 0; i < len(s); {
		j := strings.IndexByte(s[i:], '_')
		if j < 0 {
			return false
		}
		u := i + j
		if u >= 2 && s[u-2]|0x20 == 'e' && s[u-1]|0x20 == 'c' {
			return true
		}
		if hasFoldPrefix(s[u+1:], "approval") {
			return true
		}
		i = u + 1
	}
	return false
}

// matchSelfApprovalSQL is the R-165 database matcher: a command line,
// heredoc or interpreter one-liner writing into guard_approvals (or a
// register beside it), or deleting findings.
func matchSelfApprovalSQL(_ *MatchContext, cmd *Command) (bool, string) {
	for _, text := range []string{cmd.Raw, cmd.Heredoc, cmd.Payload} {
		if text != "" && mayNameGuardRegister(text) && (guardGrantSQL.MatchString(text) || findingDropSQL.MatchString(text)) {
			return true, "SQL writing a grant into the guard exception, repository trust or code security finding register (" + clampDetail(cmd.Base) + ")"
		}
	}
	return false, ""
}

// consentRecordPatterns are the developer's consent records in the
// security directory (lane sec-deps4 audit finding 1): the scanners' one-
// time OSV database accept (osv-db-consent.json, about 300 MB downloaded on
// the developer's word) and the online checks' disclosure
// (online-disclosure.json, which turns on queries that name packages).
// Writing either is giving that consent, so an agent's write is refused
// here as surely as the CLI verbs and the routes above; the records are
// also signed under the node's posture key, so a hand-written one that got
// through would still not count. Matched by name under any security
// directory, so an observer home in another place is covered too.
var consentRecordPatterns = []pathPattern{
	{"**/security/osv-db-consent.json", "the scanner database accept record"},
	// OS-2 (ruling Q1 (b)): the OS release databases' one accept.
	{"**/security/osv-os-db-consent.json", "the OS release databases' accept record"},
	// Reserved for the Trivy image driver (plan 6.7, lane OS-2 T).
	{"**/security/trivy-db-consent.json", "the Trivy database accept record"},
	// Lane RM-2 (plan section 13.10): the SuperBased package lookup's two
	// records, the lookup itself and the private-names choice.
	{"**/security/osv-remote-consent.json", "the superbased package lookup consent record"},
	{"**/security/osv-remote-private-consent.json", "the superbased package lookup's private-names consent record"},
	{"**/security/online-disclosure.json", "the online package checks' disclosure record"},
	// Lane SEC-G2: the developer's one-time size consent to the guided
	// Opengrep install (about 47 MB downloaded on their word).
	{"**/security/opengrep-install-consent.json", "the Opengrep install consent record"},
	// Plan 14.9 (M3L-5): the local DAST checker's one accept.
	{"**/security/dast-consent.json", "the local DAST checker's accept record"},
	// The build artifact folders the developer turned on (M3L-2 item 4): an
	// agent writing this file would enable full artifact scanning for a
	// project without the developer's word.
	{"**/security/artifact-dirs.json", "the build artifact folder choice record"},
	// The Go source check's per-project opt-in (3b-src): an agent writing
	// this file would let the check run a project's toolchain (or run it
	// unisolated) without the developer's word.
	{"**/security/reach-go-source-optin.json", "the Go source check's opt-in record"},
	// The AI change records' trailer (lane sec-f2a): the per-repository
	// flag the consent writes, and the hook's "the agent is committing"
	// marker; an agent writing either would put the trailer where no
	// person or hook put it.
	{"**/security/provenance/trailer/**", "the AI change records' trailer consent flag"},
	{"**/security/provenance/pending/**", "the AI change records' agent-commit marker"},
}

// matchConsentRecordInline is the inline-script consent-record row: a
// literal in interpreter program text (python -c, node -e, a heredoc, a
// PowerShell [IO.File] call) that names a consent record. Program text
// does not show the direction, and nothing but the accept path has a
// reason to touch these files, so naming one is judged as writing it.
// Judged from every anchor the unit runs in (unitPathCandidates, T-387).
func matchConsentRecordInline(ctx *MatchContext, cmd *Command) (bool, string) {
	return inlinePathMatch(ctx, cmd, consentRecordPatterns)
}

// consentRecordRules returns the R-165 consent-record rows. R-160's
// ~/.observer judgement leaves these two files to them
// (observerConfigPath), so a write to a consent record reports R-165 and
// its advice.
func consentRecordRules() []Rule {
	faCfg := []EventKind{KindFileAccess, KindConfigChange}
	shell := []EventKind{KindShellExec}
	const advice = "Only the developer gives this consent, on the Observer dashboard's Code security page or with the CLI accept command they run themselves. Stop and tell the developer what needs accepting."
	return []Rule{
		{
			ID: "R-165", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: faCfg, Match: faPathMatch(consentRecordPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent writing the developer's consent record (the scanner database accept or the online checks' disclosure)",
			Advice: advice,
		},
		{
			ID: "R-165", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: shPathMatch(consentRecordPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "shell command writing the developer's consent record (redirect, tee, cp, mv and their kin)",
			Advice: advice,
		},
		{
			ID: "R-165", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchConsentRecordInline,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "interpreter one-liner or inline script naming the developer's consent record",
			Advice: advice,
		},
	}
}

// guardEnvPrefix is the prefix of the environment overrides the config
// loader applies to [guard] in every process, every hook included
// (internal/config, OBSERVER_GUARD_*). Windows reads environment names
// without case, so the match does too.
const guardEnvPrefix = "observer_guard_"

// namesGuardEnv reports whether s names a guard environment override.
func namesGuardEnv(s string) bool {
	return strings.Contains(strings.ToLower(s), guardEnvPrefix)
}

// positionalNamesGuardEnv reports whether one of a unit's positionals from
// index from on is (or assigns) a guard environment override.
func positionalNamesGuardEnv(cmd *Command, from int) bool {
	pos := cmd.Positionals()
	for i := from; i < len(pos); i++ {
		if hasFoldPrefix(strings.TrimLeft(pos[i], `'"`), guardEnvPrefix) {
			return true
		}
	}
	return false
}

// firstPositionalIs reports whether a unit's first positional is word.
func firstPositionalIs(cmd *Command, word string) bool {
	pos := cmd.Positionals()
	return len(pos) > 0 && strings.EqualFold(pos[0], word)
}

// guardEnvSetters are the commands that persist an environment variable for
// processes started later (sweep finding SA-9): a later AI tool, and the
// hooks it runs, then loads [guard] with the override. Setting one for the
// agent's own shell (`export`) reaches no hook and is not listed. One row
// per setter; the first that holds names the verdict.
var guardEnvSetters = []struct {
	desc  string
	match func(cmd *Command) bool
}{
	{"setx (the Windows user or machine environment)", func(c *Command) bool {
		return c.Base == "setx" && positionalNamesGuardEnv(c, 0)
	}},
	{"reg add under an Environment key", func(c *Command) bool {
		return c.Base == "reg" && firstPositionalIs(c, "add") && strings.Contains(strings.ToLower(c.Raw), `\environment`) && namesGuardEnv(c.Raw)
	}},
	{"Set-ItemProperty or New-ItemProperty on an Environment registry key", func(c *Command) bool {
		return (c.Base == "set-itemproperty" || c.Base == "new-itemproperty") && strings.Contains(strings.ToLower(c.Raw), `\environment`) && namesGuardEnv(c.Raw)
	}},
	{"launchctl setenv (every app launchd starts)", func(c *Command) bool {
		return c.Base == "launchctl" && firstPositionalIs(c, "setenv") && positionalNamesGuardEnv(c, 1)
	}},
	{"systemctl set-environment (the user or system manager)", func(c *Command) bool {
		return c.Base == "systemctl" && hasPositionalWord(c, "set-environment") && positionalNamesGuardEnv(c, 0)
	}},
	{"dbus-update-activation-environment", func(c *Command) bool {
		return c.Base == "dbus-update-activation-environment" && positionalNamesGuardEnv(c, 0)
	}},
	{"a .NET SetEnvironmentVariable call", func(c *Command) bool {
		return guardEnvDotNetSetter.MatchString(c.Raw)
	}},
}

// guardEnvDotNetSetter finds [Environment]::SetEnvironmentVariable naming a
// guard override (in a PowerShell unit, or in any program text).
var guardEnvDotNetSetter = regexp.MustCompile(`(?i)setenvironmentvariable\W+observer_guard_`)

// shellStartupPatterns are the files a shell or session reads at start, so
// an assignment written into one reaches every later process it starts:
// R-154's shell profile table (its one owner, rules_boundary.go) plus the
// session and system environment files a guard override also persists
// through. R-154 already denies any agent write to the profiles in enforce
// mode; R-165's rows add the integrity floor for one that names the guard.
var shellStartupPatterns = append(append([]pathPattern{}, shellProfilePatterns...), []pathPattern{
	{"~/.config/fish/conf.d/**", "a fish startup file"},
	{"~/.config/powershell/*profile*.ps1", "PowerShell profile"},
	{"~/.config/environment.d/**", "the systemd user environment"},
	{"~/.pam_environment", "the PAM session environment"},
	{"/etc/environment", "the system environment"},
	{"/etc/profile", "the system login profile"},
	{"/etc/profile.d/**", "a system login profile"},
	{"/etc/bash.bashrc", "the system bash startup file"},
	{"/etc/zshenv", "the system zsh environment file"},
	{"/etc/zsh/**", "a system zsh startup file"},
	{"**/powershell/*profile*.ps1", "PowerShell profile"},
	{"**/windowspowershell/*profile*.ps1", "PowerShell profile"},
}...)

// psProfileWriters are the PowerShell cmdlets that write a file's content.
var psProfileWriters = setOf("add-content", "set-content", "out-file", "tee-object")

// matchGuardEnvPersist is the R-165 shell matcher for a persisted guard
// override: a setter row, or a write to a shell startup file (a redirect,
// tee, cp and their kin, an interpreter literal, or a PowerShell write to
// $PROFILE) on a command line that names OBSERVER_GUARD_.
func matchGuardEnvPersist(ctx *MatchContext, cmd *Command) (bool, string) {
	if !namesGuardEnv(ctx.Event.Target) && !namesGuardEnv(cmd.Raw) && !namesGuardEnv(cmd.Heredoc) {
		return false, ""
	}
	for _, s := range guardEnvSetters {
		if s.match(cmd) {
			return true, "an OBSERVER_GUARD_ environment override persisted with " + s.desc
		}
	}
	if ok, d := shPathMatch(shellStartupPatterns, true)(ctx, cmd); ok {
		return true, "an OBSERVER_GUARD_ environment override written into " + d
	}
	if ok, d := inlinePathMatch(ctx, cmd, shellStartupPatterns); ok {
		return true, "an OBSERVER_GUARD_ environment override written into " + d
	}
	if psProfileWriters[cmd.Base] && strings.Contains(strings.ToLower(cmd.Raw), "$profile") {
		return true, "an OBSERVER_GUARD_ environment override written into the PowerShell profile ($PROFILE)"
	}
	for _, r := range cmd.RedirectTargets {
		if hasFoldPrefix(r, "$profile") {
			return true, "an OBSERVER_GUARD_ environment override written into the PowerShell profile ($PROFILE)"
		}
	}
	return false, ""
}

// matchGuardEnvPersistFile is the file-access form: an agent edit or write
// of a shell startup file whose text (either side of the edit) names
// OBSERVER_GUARD_, or whose content the guard cannot see (an apply_patch
// rename onto the file, EditUnknown), which may name it (FR-SEC-11, review
// 2026-11-22; the marker HOOKSW-REN-1 added for R-162 and R-114).
func matchGuardEnvPersistFile(ctx *MatchContext) (bool, string) {
	if !isWriteEvent(ctx.Event) {
		return false, ""
	}
	desc, ok := homePathPatternMatch(ctx, ctx.Path, shellStartupPatterns)
	if !ok {
		return false, ""
	}
	named := namesGuardEnv(string(ctx.Event.Raw))
	for _, e := range ctx.Event.Edits {
		named = named || namesGuardEnv(e.Old) || namesGuardEnv(e.New)
	}
	if named {
		return true, "an OBSERVER_GUARD_ environment override written into " + desc + " (" + ctx.Event.Target + ")"
	}
	if hasUnseenEdit(ctx.Event.Edits) {
		return true, desc + " (" + ctx.Event.Target + ") written with content the guard cannot see, by a rename onto it; it may set an OBSERVER_GUARD_ override"
	}
	return false, ""
}

// selfApprovalRules returns the R-165 rows (appended to the boundary
// table).
func selfApprovalRules() []Rule {
	shell := []EventKind{KindShellExec}
	const advice = "An agent cannot approve its own exception. Stop and tell the developer what was blocked and why; the developer decides, on the Observer dashboard Security page."
	return []Rule{
		{
			ID: "R-165", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchSelfApprovalCLI(true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent approving its own guard exception or loosening the guard (observer guard approve, guard disable and their siblings)",
			Advice: advice,
		},
		{
			ID: "R-165", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchSelfApprovalHTTP,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent calling the local dashboard's guard approval or policy routes",
			Advice: advice,
		},
		// Sweep finding SA-4: the same routes named in an interpreter's
		// program text or a PowerShell .NET call.
		{
			ID: "R-165", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchSelfApprovalInlineHTTP,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "interpreter one-liner or inline script calling the local dashboard's guard approval or policy routes",
			Advice: advice,
		},
		{
			ID: "R-165", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchSelfApprovalSQL,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent writing a grant into the guard's approvals table",
			Advice: advice,
		},
		// Sweep finding SA-9: an OBSERVER_GUARD_* override persisted for
		// later processes lowers [guard] in every hook those start.
		{
			ID: "R-165", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchGuardEnvPersist,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent persisting an OBSERVER_GUARD_ environment override (setx, the registry or .NET setters, launchctl setenv, a shell startup file)",
			Advice: advice,
		},
		{
			ID: "R-165", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: []EventKind{KindFileAccess, KindConfigChange}, Match: matchGuardEnvPersistFile,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent writing an OBSERVER_GUARD_ environment override into a shell startup file",
			Advice: advice,
		},
		// OSH-142: asks in observe mode too (the R-168 shape), because
		// observe is the fresh-install default and the consent is the
		// person's whatever the guard mode. Not Enforced, as R-168's rows are
		// not (Guard.GateEnforcement).
		{
			ID: "R-165", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchConsentAskCLI,
			Observe: DecisionAsk, Enforce: DecisionAsk,
			Doc:    "agent giving the person's consent to relay org sandbox runs through this laptop or to probe a sandbox backend on this machine (observer sandbox org-shell opt-in, observer sandbox setup check; with or without --yes)",
			Advice: "Only the person gives this consent. Ask the developer to run the command in their own terminal or to click it on the Observer dashboard (the org relay: Terminals > Settings, the org-hosted sandbox card, Run org sandboxes through this laptop; a backend check: Terminals > Settings, the backend's Set up or Manage), or wait for them to answer this prompt.",
		},
		{
			ID: "R-165", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchSelfApprovalCLI(false),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "agent requesting a guard exception (recorded; a human decides it)",
			Advice: "Recorded so the developer sees who asked. The request goes to a human; the agent waits for the decision.",
		},
	}
}
