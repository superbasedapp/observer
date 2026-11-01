package policy

import (
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
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
// their value, so it is never read as a subcommand.
var observerValueFlags = setOf("--config", "--db", "--session", "--ttl", "--project", "--since", "--reason")

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
	{
		path: []string{"guard", "enable"}, grant: true, desc: "sets the guard to observe mode, so nothing blocks",
		when: func(args, _ []string) bool { return !hasFlag(args, "--enforce") },
	},
	{
		path: []string{"config", "set"}, grant: true, desc: "changes a [guard] or [security] setting",
		when: func(_, words []string) bool { return len(words) > 2 && selfLoweringConfigKey(words[2]) },
	},
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
	{path: []string{"security", "scan", "db", "accept"}, grant: true, desc: "accepts the dependency scanners' OSV database download"},
	// Lane GATES-SBX (G24): storing a provider key that the proxy then adds
	// to a sandboxed run's model requests is the person's call, never an
	// agent's. list and remove stay allowed (remove only takes injection
	// away).
	{path: []string{"sandbox", "credentials", "add"}, grant: true, desc: "stores a provider key that credential injection adds to sandboxed runs' model requests"},
	// Lane GATES-SBX (G50, audit F5): re-adopting a container run (or ending
	// it with --end), checkpointing it and restoring it are the person's
	// actions, never an agent's: a re-adoption attaches another box's
	// terminal, a checkpoint writes the box's memory to disk. `sandbox runs`
	// (the list) stays allowed.
	{path: []string{"sandbox", "readopt"}, grant: true, desc: "re-adopts (or, with --end, ends) a sandboxed container run whose helper went away"},
	{path: []string{"sandbox", "checkpoint"}, grant: true, desc: "checkpoints a sandboxed container run's memory to a file"},
	{path: []string{"sandbox", "restore"}, grant: true, desc: "restores a checkpointed sandboxed container run"},
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
	{path: []string{"request", "access"}, desc: "requests a guard exception (a human decides it)"},
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
			if v.grant != grant || !wordsHavePrefix(words, v.path) {
				continue
			}
			if v.when != nil && !v.when(args, words) {
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
var selfLoweringSections = []string{"guard", "security"}

// selfLoweringConfigKey reports whether a config key is in one of the
// selfLoweringSections (the section itself or a dotted key under it).
func selfLoweringConfigKey(key string) bool {
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

// guardGrantRoutes are the dashboard routes that lift a guard block or
// loosen the guard's policy, matched as a path or a path prefix.
var guardGrantRoutes = []struct {
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
}{
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
	// The dashboard form of `observer security trust accept` (lane
	// SEC-TRUSTFIX): its POST accepts a repository's commands.
	{path: "/api/security/trust", desc: "the repository trust accept route"},
	// The dashboard form of `observer security deps disclosure --accept`
	// (lane SEC-D1FIX2): its POST records the online checks' consent.
	{path: "/api/security/deps", desc: "the package checks consent route"},
	// The dashboard form of `observer security scan db accept` (lane
	// sec-deps4): its POST records the scanner database accept.
	{path: "/api/security/scanners/db", desc: "the scanner database accept route"},
	// The dashboard form of `observer security code install` (lane
	// SEC-G2): its POST records the size consent and starts the install.
	{path: "/api/security/code/install", desc: "the code rules' guided install and its size consent"},
	// The dashboard form of `observer security iac install` (lane
	// GATES-SEC): its POST records the size consent and starts the install.
	{path: "/api/security/iac/install", desc: "the IaC engines' guided install and its size consent"},
	// The HTTP forms of `observer config set guard.*` and `security.*`.
	{path: "/api/config/section/guard", dotted: true, desc: "the [guard] settings section"},
	{path: "/api/config/section/security", dotted: true, desc: "the [security] settings section"},
	{path: "/api/config/keys", body: guardConfigKeyBody, desc: "a [guard] or [security] setting"},
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
	// The Code security page's git hooks route (lane sec-gate2, decision
	// log P-025): its POST installs or removes the hooks, both the
	// developer's per-repository call.
	{path: "/api/security/githooks", desc: "the code security git hooks route"},
	// The dashboard form of `observer sandbox credentials add` (lane
	// GATES-SBX, G24): its POST stores a provider key for injection.
	{path: "/api/terminal/sandbox/credentials", desc: "the sandbox credential injection key route"},
	// The dashboard forms of `observer sandbox readopt --end`, `checkpoint`
	// and `restore` (lane GATES-SBX, audit F5): each POST under this prefix
	// ends, checkpoints or restores a run (the GET list is a read).
	{path: "/api/terminal/sandbox/readopt", prefix: true, desc: "the sandbox run re-adoption routes (end, checkpoint, restore)"},
	// The AI change records card (lane sec-f2a): its POST gives or
	// withdraws the per-repository writer consent or resets the key.
	{path: "/api/security/provenance", desc: "the AI change records route (repository writer consent, key reset)"},
	// The HTTP form of `observer update rollback --yes` (lane SEC-P4
	// decision 7): a body whose decoded rollback is true. A dry_run does
	// not preview a rollback (the daemon's apply takes the rollback branch
	// first, cmd/observer/update_wire.go applyLocked), so it never exempts
	// one; a plain apply or its dry run passes.
	{path: "/api/update/apply", body: updateRollbackBody, desc: "an update rollback, which restores the previous binary and can lower a guard or code security setting"},
}

// guardConfigKey finds a [guard] or [security] key path named as a key in
// a config keys request body ({"patches":[{"key":"security.x",...}]},
// selfLoweringSections): the "key" field's value, not any text that
// mentions the word (lane sec-gate3 milestone 2b).
var guardConfigKey = regexp.MustCompile(`(?i)\bkey\\?["']?\s*[:=]\s*\\?["']?\s*(?:guard|security)(?:\.|\\?["'\s,}&]|$)`)

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
// query and fragment cut), lowercased.
func urlPath(u string) string {
	lu := strings.ToLower(u)
	rest := strings.TrimPrefix(strings.TrimPrefix(lu, "https://"), "http://")
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return "/"
	}
	p := rest[i:]
	if j := strings.IndexAny(p, "?#"); j >= 0 {
		p = p[:j]
	}
	return strings.TrimRight(p, "/")
}

// loopbackURLHost reports whether a lowercased http(s) URL names a
// loopback host: localhost, any 127.x address, [::1] or 0.0.0.0.
func loopbackURLHost(u string) bool {
	rest := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if at := strings.IndexByte(rest, '@'); at >= 0 && at < strings.IndexAny(rest+"/", "/?#") {
		rest = rest[at+1:]
	}
	host := rest
	if strings.HasPrefix(rest, "[") {
		if end := strings.IndexByte(rest, ']'); end > 0 {
			host = rest[:end+1]
		}
	} else if i := strings.IndexAny(rest, "/:?#"); i >= 0 {
		host = rest[:i]
	}
	return host == "localhost" || strings.HasPrefix(host, "127.") || host == "[::1]" || host == "0.0.0.0"
}

// matchSelfApprovalHTTP is the R-165 route matcher: an HTTP client writing
// to a loopback guard grant route.
func matchSelfApprovalHTTP(_ *MatchContext, cmd *Command) (bool, string) {
	method, ok := httpClientMethod(cmd)
	if !ok || !httpWriteMethods[method] {
		return false, ""
	}
	for _, a := range cmd.Args() {
		la := strings.ToLower(a)
		if _, v, ok := strings.Cut(la, ":"); ok && strings.HasPrefix(la, "-") && strings.Contains(v, "://") {
			// A PowerShell parameter with an inline value: -Uri:http://...
			la = v
		}
		if !strings.HasPrefix(la, "http://") && !strings.HasPrefix(la, "https://") {
			la = "http://" + la
		}
		if !loopbackURLHost(la) {
			continue
		}
		p := urlPath(la)
		for _, r := range guardGrantRoutes {
			if p != r.path && !(r.prefix && strings.HasPrefix(p, r.path+"/")) && !(r.dotted && strings.HasPrefix(p, r.path+".")) {
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

// sqlSchemaPrefix matches an optional schema qualifier before a table
// name, quoted or not (main.sec_findings, "main"."sec_findings",
// [temp].x; lane sec-gate3 milestone 2b), and the table name's own
// opening quote.
const sqlSchemaPrefix = `(?:["'\x60\[]?\w+["'\x60\]]?\s*\.\s*)?["'\x60\[]?`

// guardGrantSQL finds SQL that writes a grant into the approvals register.
var guardGrantSQL = regexp.MustCompile(`(?i)\b(?:insert(?:\s+or\s+\w+)?\s+into|replace\s+into|update(?:\s+or\s+\w+)?)\s+` + sqlSchemaPrefix +
	`(guard_approvals|sec_config_baseline|sec_finding_exceptions|sec_baselines|sec_findings|sec_finding_commits|sec_change_consent|sec_change_keys)\b`)

// findingDropSQL finds SQL that deletes findings outright (lane sec-gate2,
// decision log P-025): a deleted open finding leaves the commit gate's
// blocking set as surely as a suppressed one. Deleting an approval or an
// exception revokes it, which never loosens anything, so only the findings
// table is named.
var findingDropSQL = regexp.MustCompile(`(?i)\b(?:delete\s+from|drop\s+table(?:\s+if\s+exists)?|truncate(?:\s+table)?)\s+` + sqlSchemaPrefix +
	`(?:sec_findings|sec_finding_commits)\b`)

// matchSelfApprovalSQL is the R-165 database matcher: a command line,
// heredoc or interpreter one-liner writing into guard_approvals (or a
// register beside it), or deleting findings.
func matchSelfApprovalSQL(_ *MatchContext, cmd *Command) (bool, string) {
	for _, text := range []string{cmd.Raw, cmd.Heredoc, cmd.Payload} {
		if text != "" && (guardGrantSQL.MatchString(text) || findingDropSQL.MatchString(text)) {
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
	{"**/security/online-disclosure.json", "the online package checks' disclosure record"},
	// Lane SEC-G2: the developer's one-time size consent to the guided
	// Opengrep install (about 47 MB downloaded on their word).
	{"**/security/opengrep-install-consent.json", "the Opengrep install consent record"},
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
		{
			ID: "R-165", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchSelfApprovalSQL,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent writing a grant into the guard's approvals table",
			Advice: advice,
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
