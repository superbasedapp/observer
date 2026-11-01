package policy

import (
	"regexp"
	"strconv"
	"strings"
)

// R-112, R-113 and R-114 (D-761): an agent getting a commit or a push past
// the repository's own git hooks. They are core Guard rules, not part of
// the optional security module: they ship with Guard, follow Guard's mode
// and overrides, and stay when the module is skipped (security pillar plan
// section 5.2).
//
//   - R-112 is the bypass on the command line: an option that skips the
//     hooks (`git commit --no-verify` / `-n`, `git push --no-verify`),
//     core.hooksPath set for one command (`git -c core.hooksPath=...`,
//     `--config-env`, GIT_CONFIG_PARAMETERS, GIT_CONFIG_COUNT), and an alias
//     that expands to any of these, whether defined on the command line, by
//     `git config alias.x ...`, or found in the per-project alias table the
//     daemon precomputes (Config.GitAliases; the hook never runs git).
//   - R-113 is a hook manager's own skip switch in the command's
//     environment (HUSKY=0, SKIP=..., LEFTHOOK=0, ...), as a prefix
//     assignment, an `env` operand or an export earlier in the same line,
//     plus a record of the export alone for a persistent shell.
//   - R-114 is a lasting change to where or whether hooks run: `git config`
//     writing core.hooksPath or core.fsmonitor, a write into git's own
//     files (.git/config, .git/info/attributes, .git/refs, .git/objects,
//     the global git config), an edit of a hook manager's config
//     (.husky/, .pre-commit-config.yaml, lefthook.yml, ...), and a
//     .gitattributes filter or driver key that names a custom program.
//
// Writes into .git/hooks stay R-156; a hook switch in an agent's own
// settings stays R-162 / R-163. What these rows cannot see is named in
// docs/guard-rules.md and the docs/security.md ledger (SECP-6): a script
// the agent writes and then runs (R-157 covers only an unanalysable
// wrapper), a git subcommand reached through another program (`npm run
// release`), and an export made in an earlier call of a persistent shell
// whose payload the host does not show.

// gitHookSkipOption is one command-line option that runs a git subcommand
// without its hooks.
type gitHookSkipOption struct {
	// sub is the git subcommand.
	sub string
	// long is the long option; an unambiguous prefix of at least
	// gitMinNoVerifyPrefix bytes counts too, as git's option parser
	// accepts it.
	long string
	// short is the short option letter, 0 when the subcommand has none
	// (`git push -n` is a dry run, not a skip).
	short byte
	// hooks names the hooks the option skips, for the verdict detail.
	hooks string
}

// gitHookSkipOptions is the R-112 option table, one row per subcommand.
var gitHookSkipOptions = []gitHookSkipOption{
	{sub: "commit", long: "--no-verify", short: 'n', hooks: "pre-commit and commit-msg"},
	{sub: "am", long: "--no-verify", short: 'n', hooks: "pre-applypatch and applypatch-msg"},
	{sub: "merge", long: "--no-verify", hooks: "pre-merge-commit and commit-msg"},
	{sub: "pull", long: "--no-verify", hooks: "pre-merge-commit and commit-msg"},
	{sub: "push", long: "--no-verify", hooks: "pre-push"},
	{sub: "rebase", long: "--no-verify", hooks: "pre-rebase"},
}

// gitMinNoVerifyPrefix is the shortest abbreviation of --no-verify git
// accepts without ambiguity ("--no-ver" also abbreviates --no-verbose).
const gitMinNoVerifyPrefix = len("--no-veri")

// gitOptionValues lists, per subcommand, the options that take a value, so
// a value is never read as an option (`git commit -m -n` commits the
// message "-n"; `git commit -uno` is --untracked-files=no).
type gitOptionValues struct {
	// short letters take a value: the rest of the cluster or the next word.
	short string
	// shortAttached letters take an optional value attached to the cluster.
	shortAttached string
	// long options take the next word as their value when written without
	// "=".
	long map[string]bool
}

// gitSubOptionValues is the value-option table of the subcommands
// gitHookSkipOptions names.
var gitSubOptionValues = map[string]gitOptionValues{
	"commit": {short: "mFCct", shortAttached: "uS", long: setOf("--message", "--file", "--reuse-message",
		"--reedit-message", "--fixup", "--squash", "--author", "--date", "--template", "--cleanup",
		"--trailer", "--pathspec-from-file")},
	"am":     {shortAttached: "CpS", long: setOf("--patch-format", "--resolvemsg", "--exclude", "--include", "--directory", "--whitespace", "--empty")},
	"merge":  {short: "mFsX", shortAttached: "S", long: setOf("--message", "--file", "--strategy", "--strategy-option", "--into-name", "--cleanup")},
	"pull":   {short: "sX", shortAttached: "S", long: setOf("--strategy", "--strategy-option", "--depth", "--deepen", "--shallow-since", "--shallow-exclude", "--upload-pack", "--push-option")},
	"push":   {short: "o", long: setOf("--repo", "--receive-pack", "--exec", "--push-option")},
	"rebase": {short: "sXx", shortAttached: "S", long: setOf("--onto", "--exec", "--strategy", "--strategy-option", "--whitespace", "--empty")},
}

// gitGlobalValueOptions are git's own options, before the subcommand,
// that take the next word as their value.
var gitGlobalValueOptions = setOf("-C", "-c", "--git-dir", "--work-tree", "--namespace",
	"--super-prefix", "--config-env", "--attr-source")

// gitBuiltinSubs are subcommands git runs itself, never as an alias (git
// ignores an alias that shadows one), so their name is never looked up in
// an alias table. Best effort: a builtin missing here only costs a lookup.
var gitBuiltinSubs = setOf("add", "am", "apply", "archive", "bisect", "blame", "branch", "bundle",
	"checkout", "cherry", "cherry-pick", "clean", "clone", "commit", "commit-tree", "config",
	"describe", "diff", "fetch", "format-patch", "gc", "grep", "help", "init", "log", "ls-files",
	"ls-remote", "merge", "mv", "notes", "pull", "push", "range-diff", "rebase", "reflog", "remote",
	"reset", "restore", "rev-list", "rev-parse", "revert", "rm", "shortlog", "show", "show-ref",
	"sparse-checkout", "stash", "status", "submodule", "switch", "tag", "update-ref", "version",
	"worktree")

// gitConfigEntry is one configuration value a git command line sets for
// that one command (`-c`, `--config-env`, the GIT_CONFIG_* environment).
type gitConfigEntry struct {
	// key is the dotted key, section and name lowercased ("" when unseen).
	key string
	// value is the value as written.
	value string
	// seen is false when the value or the key cannot be read (it comes
	// from another environment variable, or holds an expansion).
	seen bool
	// origin names where the entry came from, for the verdict detail.
	origin string
}

// gitInvocation is one parsed git command line.
type gitInvocation struct {
	sub    string
	args   []string
	config []gitConfigEntry
	// dir is the last -C value ("" when none).
	dir string
}

// parseGitInvocation reads git's own options, then the subcommand and its
// arguments, from a git unit's argv.
func parseGitInvocation(argv []string) gitInvocation {
	var inv gitInvocation
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		if !strings.HasPrefix(t, "-") || t == "-" {
			inv.sub = t
			inv.args = argv[i+1:]
			return inv
		}
		name, val, hasVal := strings.Cut(t, "=")
		if !hasVal && gitGlobalValueOptions[name] {
			if i+1 >= len(argv) {
				return inv
			}
			i++
			val = argv[i]
		}
		switch name {
		case "-C":
			inv.dir = val
		case "-c":
			k, v, _ := strings.Cut(val, "=")
			inv.config = append(inv.config, gitConfigEntry{key: normGitKey(k), value: v, seen: true, origin: "-c " + k})
		case "--config-env":
			k, envName, _ := strings.Cut(val, "=")
			inv.config = append(inv.config, gitConfigEntry{key: normGitKey(k), value: "${" + envName + "}", origin: "--config-env " + k})
		}
	}
	return inv
}

// normGitKey lowercases a config key's section and name; a subsection
// (between the first and the last dot) keeps its case, as git does.
func normGitKey(k string) string {
	i, j := strings.IndexByte(k, '.'), strings.LastIndexByte(k, '.')
	if i < 0 || i == j {
		return strings.ToLower(k)
	}
	return strings.ToLower(k[:i]) + k[i:j] + strings.ToLower(k[j:])
}

// hasExpansion reports whether a value holds shell expansion syntax, so
// the guard cannot know what it becomes. The lexer has removed quoting, so
// a single-quoted literal "$" counts too (the safe direction).
func hasExpansion(v string) bool { return strings.ContainsAny(v, "$`%") }

// gitEnvConfig reads the configuration a git command takes from its
// environment: GIT_CONFIG_PARAMETERS (what `git -c` forwards to child
// processes) and the GIT_CONFIG_COUNT / GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n
// set. An entry the guard cannot read is returned with seen=false.
func gitEnvConfig(env map[string]string) []gitConfigEntry {
	var out []gitConfigEntry
	if p, ok := env["GIT_CONFIG_PARAMETERS"]; ok && p != "" {
		entries, parsed := parseGitConfigParameters(p)
		if !parsed || hasExpansion(p) {
			out = append(out, gitConfigEntry{origin: "GIT_CONFIG_PARAMETERS"})
		}
		out = append(out, entries...)
	}
	c, ok := env["GIT_CONFIG_COUNT"]
	if !ok {
		return out
	}
	n, err := strconv.Atoi(c)
	if err != nil || hasExpansion(c) {
		return append(out, gitConfigEntry{origin: "GIT_CONFIG_COUNT"})
	}
	const maxCount = 64
	for i := 0; i < n && i < maxCount; i++ {
		idx := strconv.Itoa(i)
		k, v := env["GIT_CONFIG_KEY_"+idx], env["GIT_CONFIG_VALUE_"+idx]
		e := gitConfigEntry{key: normGitKey(k), value: v, seen: !hasExpansion(k), origin: "GIT_CONFIG_KEY_" + idx}
		if !e.seen {
			e.key = ""
		}
		out = append(out, e)
	}
	return out
}

// parseGitConfigParameters reads GIT_CONFIG_PARAMETERS: space-separated
// single-quoted words, each `'key'='value'` or the older `'key=value'`.
// ok is false when the text is not in that form.
func parseGitConfigParameters(s string) ([]gitConfigEntry, bool) {
	var out []gitConfigEntry
	i := 0
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n') {
			i++
		}
		if i >= len(s) {
			return out, true
		}
		k, n, ok := sqDequote(s[i:])
		if !ok {
			return out, false
		}
		i += n
		v := ""
		if i < len(s) && s[i] == '=' {
			v, n, ok = sqDequote(s[i+1:])
			if !ok {
				return out, false
			}
			i += 1 + n
		} else {
			k, v, _ = strings.Cut(k, "=")
		}
		out = append(out, gitConfigEntry{key: normGitKey(k), value: v, seen: true, origin: "GIT_CONFIG_PARAMETERS " + k})
	}
}

// sqDequote reads one shell single-quoted word as git writes it (an
// embedded quote is `'\”`), returning the text and the bytes consumed.
func sqDequote(s string) (string, int, bool) {
	var b strings.Builder
	i := 0
	for {
		if i >= len(s) || s[i] != '\'' {
			return "", 0, false
		}
		j := strings.IndexByte(s[i+1:], '\'')
		if j < 0 {
			return "", 0, false
		}
		b.WriteString(s[i+1 : i+1+j])
		i += j + 2
		if strings.HasPrefix(s[i:], `\'`) {
			b.WriteByte('\'')
			i += 2
			continue
		}
		return b.String(), i, true
	}
}

// skipWhen says which values of a skip switch turn its hooks off.
type skipWhen int

const (
	// skipWhenOff: only a boolean off spelling ("0", "false", "no",
	// "off"), as with HUSKY=0.
	skipWhenOff skipWhen = iota
	// skipWhenTrue: any non-empty value that is not an off spelling, as
	// with OVERCOMMIT_DISABLE=1.
	skipWhenTrue
	// skipWhenSet: any non-empty value (a list of hook ids), as with
	// SKIP=flake8.
	skipWhenSet
)

// hookSkipVar is one hook manager's environment skip switch (R-113).
type hookSkipVar struct {
	// name is the variable name, upper case (matched case-insensitively:
	// Windows environment names are).
	name string
	// when says which values skip.
	when skipWhen
	// manager names the hook manager, for the verdict detail.
	manager string
}

// hookSkipVars is the R-113 variable table, one row per switch.
var hookSkipVars = []hookSkipVar{
	{name: "HUSKY", when: skipWhenOff, manager: "husky"},
	{name: "HUSKY_SKIP_HOOKS", when: skipWhenTrue, manager: "husky 4"},
	{name: "SKIP", when: skipWhenSet, manager: "pre-commit"},
	{name: "PRE_COMMIT_ALLOW_NO_CONFIG", when: skipWhenTrue, manager: "pre-commit"},
	{name: "LEFTHOOK", when: skipWhenOff, manager: "lefthook"},
	{name: "LEFTHOOK_EXCLUDE", when: skipWhenSet, manager: "lefthook"},
	{name: "OVERCOMMIT_DISABLE", when: skipWhenTrue, manager: "overcommit"},
	{name: "SKIP_SIMPLE_GIT_HOOKS", when: skipWhenTrue, manager: "simple-git-hooks"},
}

// offValue reports whether v is a boolean off spelling.
func offValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off":
		return true
	}
	return false
}

// skips reports whether value v of the variable switches its hooks off. A
// value the guard cannot read (an expansion) counts: unknown never relaxes.
func (h hookSkipVar) skips(v string) bool {
	if hasExpansion(v) {
		return true
	}
	switch h.when {
	case skipWhenOff:
		return offValue(v)
	case skipWhenTrue:
		return strings.TrimSpace(v) != "" && !offValue(v)
	default:
		return strings.TrimSpace(v) != ""
	}
}

// skipVarFor returns the table row for an environment name.
func skipVarFor(name string) (hookSkipVar, bool) {
	for _, h := range hookSkipVars {
		if strings.EqualFold(h.name, name) {
			return h, true
		}
	}
	return hookSkipVar{}, false
}

// envAssignment is one NAME=value a command line sets.
type envAssignment struct {
	name, value string
	// how names the shape, for the verdict detail ("export", "setx", ...).
	how string
}

// exportAssignments lists the environment a unit sets for LATER commands
// in the same shell (`export`, `declare -x`, cmd's `set`, PowerShell's
// `$env:NAME = value`) or for every later process of the user (`setx`).
func exportAssignments(cmd *Command) []envAssignment {
	var out []envAssignment
	addWord := func(w, how string) {
		if !isEnvAssign(w) {
			return
		}
		n, v, _ := strings.Cut(w, "=")
		out = append(out, envAssignment{name: n, value: v, how: how})
	}
	switch {
	case cmd.Base == "export":
		for _, w := range cmd.Args() {
			addWord(w, "export")
		}
	case (cmd.Base == "declare" || cmd.Base == "typeset") && cmd.HasShortFlag('x'):
		for _, w := range cmd.Args() {
			addWord(w, cmd.Base+" -x")
		}
	case cmd.Base == "set" && cmd.Dialect == DialectCmd:
		for _, w := range cmd.Args() {
			addWord(w, "set")
		}
	case cmd.Base == "setx":
		if p := cmd.Positionals(); len(p) >= 2 {
			out = append(out, envAssignment{name: p[0], value: p[1], how: "setx"})
		}
	case psEnvItemCmdlets[cmd.Base]:
		if n, v, ok := psEnvItemAssignment(cmd); ok {
			out = append(out, envAssignment{name: n, value: v, how: cmd.Argv[0] + " env:"})
		}
	default:
		if n, v, ok := psEnvAssignment(cmd); ok {
			out = append(out, envAssignment{name: n, value: v, how: "$env:"})
		} else if n, v, ok := dotnetEnvAssignment(cmd); ok {
			out = append(out, envAssignment{name: n, value: v, how: "[Environment]::SetEnvironmentVariable"})
		}
	}
	return out
}

// psEnvItemCmdlets are the PowerShell item and content cmdlets (canonical
// names and the aliases that canonicalize only in the PowerShell dialect)
// that set an environment variable through the env: drive: `Set-Item
// env:HUSKY 0`, `New-Item -Path Env: -Name SKIP -Value all`, `Set-Content
// env:LEFTHOOK 0`. Matched in every dialect, as $env: is (a PowerShell line
// can arrive tagged posix).
var psEnvItemCmdlets = setOf("set-item", "si", "new-item", "ni", "set-content", "sc", "add-content", "ac")

// psEnvItemParam is one parameter of psEnvItemCmdlets the reader needs:
// its canonical name and the shortest prefix PowerShell binds without
// ambiguity among the three cmdlets (-Pa is -Path or -PassThru, -V is
// -Value or -Verbose, -N is -Name or -NoNewline).
var psEnvItemParams = []struct {
	name   string
	minLen int
}{
	{"path", 3}, {"literalpath", 1}, {"pspath", 3}, {"lp", 2}, {"name", 2}, {"value", 2},
}

// psEnvItemAssignment reads the variable an env: item cmdlet sets. The
// target is the -Path / -LiteralPath value or any operand naming the env:
// drive (a bare `Env:` takes the variable name from -Name); the value is
// -Value, else the operand after the target. A value the reader cannot
// find is "" (unset), and an unknown parameter is skipped without
// consuming a word, so an operand is never lost to a guess.
func psEnvItemAssignment(cmd *Command) (name, value string, ok bool) {
	var path, nameParam string
	haveValue := false
	pathAt := -1
	var pos []string
	args := cmd.Args()
	for i := 0; i < len(args); i++ {
		t := args[i]
		if len(t) < 2 || t[0] != '-' {
			if pathAt < 0 && isEnvDrivePath(t) {
				path, pathAt = t, len(pos)
			}
			pos = append(pos, t)
			continue
		}
		pname, inline, hasInline := strings.Cut(t[1:], ":")
		param := ""
		for _, p := range psEnvItemParams {
			if psParamMatches("-"+pname, p.name, p.minLen) {
				param = p.name
				break
			}
		}
		if param == "" {
			continue
		}
		val := inline
		if !hasInline {
			if i+1 >= len(args) {
				break
			}
			i++
			val = args[i]
		}
		switch param {
		case "value":
			value, haveValue = val, true
		case "name":
			nameParam = val
		default:
			path, pathAt = val, -2
		}
	}
	if !isEnvDrivePath(path) {
		return "", "", false
	}
	name = strings.TrimLeft(path[len("env:"):], `\/`)
	if name == "" {
		name = nameParam
	}
	if name == "" {
		return "", "", false
	}
	switch {
	case haveValue:
	case pathAt >= 0 && pathAt+1 < len(pos):
		value = pos[pathAt+1]
	case pathAt == -2 && len(pos) > 0:
		// The target was named, so the first operand binds to -Value.
		value = pos[0]
	}
	return name, value, true
}

// isEnvDrivePath reports a path on PowerShell's env: drive.
func isEnvDrivePath(p string) bool {
	return len(p) >= len("env:") && strings.EqualFold(p[:len("env:")], "env:")
}

// dotnetEnvAssignment reads `[Environment]::SetEnvironmentVariable(NAME,
// VALUE[, TARGET])` (also spelled [System.Environment]): the lexer has
// removed the quotes and split the call at its spaces, so the words are
// joined back and the argument list split at its commas. A TARGET of User
// or Machine makes the change last for later processes too, like setx. A
// $null value removes the variable.
func dotnetEnvAssignment(cmd *Command) (name, value string, ok bool) {
	if len(cmd.Argv) == 0 || !strings.HasPrefix(cmd.Argv[0], "[") {
		return "", "", false
	}
	joined := strings.Join(cmd.Argv, "")
	lower := strings.ToLower(joined)
	var rest string
	for _, p := range []string{"[environment]::setenvironmentvariable(", "[system.environment]::setenvironmentvariable("} {
		if strings.HasPrefix(lower, p) {
			rest = joined[len(p):]
			break
		}
	}
	if rest == "" {
		return "", "", false
	}
	rest = strings.TrimRight(rest, ");")
	parts := strings.Split(rest, ",")
	name = strings.TrimSpace(parts[0])
	if name == "" {
		return "", "", false
	}
	if len(parts) > 1 {
		value = strings.TrimSpace(parts[1])
	}
	if strings.EqualFold(value, "$null") {
		value = ""
	}
	return name, value, true
}

// psEnvAssignment reads a PowerShell `$env:NAME = value` (or `${env:NAME}`)
// unit: the lexer leaves the target as the command word.
func psEnvAssignment(cmd *Command) (name, value string, ok bool) {
	if len(cmd.Argv) == 0 {
		return "", "", false
	}
	w := cmd.Argv[0]
	lw := strings.ToLower(w)
	var rest string
	switch {
	case strings.HasPrefix(lw, "$env:"):
		rest = w[len("$env:"):]
	case strings.HasPrefix(lw, "${env:"):
		rest = strings.Replace(w[len("${env:"):], "}", "", 1)
	default:
		return "", "", false
	}
	if n, v, found := strings.Cut(rest, "="); found {
		return n, v, n != ""
	}
	if len(cmd.Argv) >= 3 && cmd.Argv[1] == "=" {
		return rest, cmd.Argv[2], rest != ""
	}
	return "", "", false
}

// gitUnitEnv is the environment a git unit runs with, as far as the line
// shows it: every export-style assignment anywhere in the line, then the
// unit's own prefix and `env` assignments, which win.
func gitUnitEnv(ctx *MatchContext, cmd *Command) map[string]string {
	env := map[string]string{}
	for i := range ctx.Cmds {
		for _, a := range exportAssignments(&ctx.Cmds[i]) {
			env[strings.ToUpper(a.name)] = a.value
		}
	}
	addEnvWords(env, cmd.Env)
	return env
}

// addEnvWords folds NAME=value words into env.
func addEnvWords(env map[string]string, words []string) {
	for _, w := range words {
		n, v, _ := strings.Cut(w, "=")
		env[strings.ToUpper(n)] = v
	}
}

// gitFinding is one hook-bypass fact a git unit carries.
type gitFinding struct {
	rule   string
	detail string
}

// maxGitAliasDepth bounds alias expansion (git itself refuses a loop).
const maxGitAliasDepth = 4

// gitScan collects the findings of one git unit, through its aliases.
type gitScan struct {
	ctx *MatchContext
	// dir is the directory the alias table is asked for.
	dir string
	out []gitFinding
}

// gitFindings returns the R-112 / R-113 / R-114 findings of a git unit.
func gitFindings(ctx *MatchContext, cmd *Command) []gitFinding {
	if cmd.Base != "git" {
		return nil
	}
	s := &gitScan{ctx: ctx}
	s.scan(cmd.Argv, gitUnitEnv(ctx, cmd), "", 0)
	return s.out
}

func (s *gitScan) add(rule, detail, via string) {
	s.out = append(s.out, gitFinding{rule: rule, detail: clampDetail(detail) + via})
}

// scan judges one git argv under env. via is the alias chain that led to
// it ("" at the top).
func (s *gitScan) scan(argv []string, env map[string]string, via string, depth int) {
	inv := parseGitInvocation(argv)
	if s.dir == "" && inv.dir != "" {
		ev := s.ctx.Event
		s.dir = resolvePath(inv.dir, s.ctx.Cfg.Home, ev.Cwd, ev.ProjectRoot)
	}
	for _, h := range hookSkipVars {
		if v, ok := env[h.name]; ok && h.skips(v) {
			s.add("R-113", h.name+"="+v+" switches the "+h.manager+" hooks off for this git command", via)
		}
	}
	aliases := map[string]string{}
	for _, e := range append(gitEnvConfig(env), inv.config...) {
		s.judgeConfig(e, aliases, via, depth)
	}
	if inv.sub == "" {
		return
	}
	for _, o := range gitHookSkipOptions {
		if o.sub == inv.sub && hasGitSkipOption(inv.args, o) {
			s.add("R-112", "git "+o.sub+" "+o.long+" skips the "+o.hooks+" hooks", via)
		}
	}
	if inv.sub == "config" {
		s.scanConfig(inv.args, via, depth)
		return
	}
	if gitBuiltinSubs[inv.sub] || depth >= maxGitAliasDepth {
		return
	}
	exp, ok := aliases[strings.ToLower(inv.sub)]
	if !ok {
		exp, ok = s.tableAlias(inv.sub)
	}
	if ok {
		s.expand(inv.sub, exp, inv.args, env, via, depth)
	}
}

// tableAlias looks a subcommand up in the injected alias table.
func (s *gitScan) tableAlias(sub string) (string, bool) {
	if s.ctx.Cfg.GitAliases == nil {
		return "", false
	}
	dir := s.dir
	if dir == "" {
		dir = s.ctx.Event.Cwd
	}
	if dir == "" {
		dir = s.ctx.Event.ProjectRoot
	}
	if dir == "" {
		return "", false
	}
	table, ok := s.ctx.Cfg.GitAliases(dir)
	if !ok {
		return "", false
	}
	exp, ok := table[strings.ToLower(sub)]
	return exp, ok
}

// expand judges an alias expansion as git runs it: a `!` alias is a shell
// command line (git appends the arguments), any other is a git argv.
func (s *gitScan) expand(name, exp string, args []string, env map[string]string, via string, depth int) {
	via = via + " (through git alias " + strconv.Quote(name) + " = " + strconv.Quote(clampDetail(exp)) + ")"
	if strings.HasPrefix(exp, "!") {
		line := unwrapAliasFunction(strings.TrimPrefix(exp, "!"))
		if len(args) > 0 {
			line += " " + strings.Join(args, " ")
		}
		for _, u := range ParseCommand(line, DialectPosix) {
			if u.Base != "git" {
				continue
			}
			sub := make(map[string]string, len(env)+len(u.Env))
			for k, v := range env {
				sub[k] = v
			}
			addEnvWords(sub, u.Env)
			s.scan(u.Argv, sub, via, depth+1)
		}
		return
	}
	argv := append([]string{"git"}, splitGitAlias(exp)...)
	s.scan(append(argv, args...), env, via, depth+1)
}

// aliasFunction is the usual shape of a shell alias that takes arguments:
// `f() { git push --no-verify "$@"; }; f`.
var aliasFunction = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{(.*)\}\s*;?\s*([A-Za-z_][A-Za-z0-9_]*)\s*$`)

// unwrapAliasFunction returns the body of a shell alias written as a
// function that the alias then calls, so the commands inside are judged
// (the shell parser does not read a function body); any other line is
// returned as is.
func unwrapAliasFunction(line string) string {
	m := aliasFunction.FindStringSubmatch(line)
	if m == nil || m[1] != m[3] {
		return line
	}
	return m[2]
}

// splitGitAlias splits a non-shell alias value into words the way git
// does: on whitespace, honouring single and double quotes.
func splitGitAlias(v string) []string {
	var out []string
	var b strings.Builder
	in, quote := false, byte(0)
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				b.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote, in = c, true
		case c == ' ' || c == '\t' || c == '\n':
			if in {
				out = append(out, b.String())
				b.Reset()
				in = false
			}
		default:
			b.WriteByte(c)
			in = true
		}
	}
	if in {
		out = append(out, b.String())
	}
	return out
}

// judgeConfig records what one per-command configuration entry does, and
// collects alias definitions into aliases.
func (s *gitScan) judgeConfig(e gitConfigEntry, aliases map[string]string, via string, depth int) {
	switch {
	case !e.seen && e.key == "":
		s.add("R-112", "git configuration injected through "+e.origin+" that the guard cannot read", via)
	case e.key == "core.hookspath":
		s.add("R-112", "core.hooksPath set for this command through "+e.origin+", so git runs hooks from another place", via)
	case e.key == "core.fsmonitor" && !fsmonitorHarmless(e.value):
		s.add("R-114", "core.fsmonitor set through "+e.origin+", a program git runs on every status", via)
	case strings.HasPrefix(e.key, "alias."):
		name := strings.TrimPrefix(e.key, "alias.")
		aliases[name] = e.value
		s.judgeAliasDefinition(name, e.value, "defines git alias "+strconv.Quote(name)+" through "+e.origin, via, depth)
	}
}

// fsmonitorHarmless reports a core.fsmonitor value that names no program:
// a boolean (false, or true for git's own built-in daemon).
func fsmonitorHarmless(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "1", "false", "true", "no", "yes", "off", "on":
		return true
	}
	return false
}

// judgeAliasDefinition records an alias whose expansion bypasses hooks,
// under the rule its expansion breaks.
func (s *gitScan) judgeAliasDefinition(name, exp, what, via string, depth int) {
	if depth >= maxGitAliasDepth {
		return
	}
	sub := &gitScan{ctx: s.ctx, dir: s.dir}
	sub.expand(name, exp, nil, map[string]string{}, "", depth+1)
	if len(sub.out) == 0 {
		return
	}
	s.add(sub.out[0].rule, what+", which expands to a hook bypass: "+sub.out[0].detail, via)
}

// hasGitSkipOption reports whether args carry the skip option o, reading
// values as values (gitSubOptionValues) and stopping at "--".
func hasGitSkipOption(args []string, o gitHookSkipOption) bool {
	vals := gitSubOptionValues[o.sub]
	for i := 0; i < len(args); i++ {
		t := args[i]
		switch {
		case t == "--":
			return false
		case strings.HasPrefix(t, "--"):
			name, _, hasVal := strings.Cut(t, "=")
			if name == o.long || (len(name) >= gitMinNoVerifyPrefix && strings.HasPrefix(o.long, name)) {
				return true
			}
			if !hasVal && vals.long[name] {
				i++
			}
		case len(t) > 1 && t[0] == '-':
			for j := 1; j < len(t); j++ {
				c := t[j]
				if o.short != 0 && c == o.short {
					return true
				}
				if strings.IndexByte(vals.short, c) >= 0 {
					if j == len(t)-1 {
						i++
					}
					break
				}
				if strings.IndexByte(vals.shortAttached, c) >= 0 {
					break
				}
			}
		}
	}
	return false
}

// gitConfigValueOptions are `git config` options that take the next word
// as their value.
var gitConfigValueOptions = setOf("-f", "--file", "--blob", "--type", "--default", "--comment", "--value", "--url")

// gitConfigActions maps a `git config` action option or subcommand to
// what it does to the configuration.
var gitConfigActions = map[string]string{
	"--get": "read", "--get-all": "read", "--get-regexp": "read", "--get-urlmatch": "read",
	"--get-color": "read", "--get-colorbool": "read", "--list": "read", "-l": "read",
	"--add": "set", "--replace-all": "set",
	"--unset": "unset", "--unset-all": "unset",
	"--rename-section": "section", "--remove-section": "section",
	"--edit": "edit", "-e": "edit",
}

// gitConfigSubcommands are the `git config <subcommand>` forms (git 2.46+).
var gitConfigSubcommands = map[string]string{
	"get": "read", "list": "read", "set": "set", "unset": "unset",
	"rename-section": "section", "remove-section": "section", "edit": "edit",
}

// scanConfig judges a `git config` invocation that changes the
// configuration for good: core.hooksPath and core.fsmonitor writes (R-114)
// and an alias defined to a bypass (R-112).
func (s *gitScan) scanConfig(args []string, via string, depth int) {
	action := ""
	var pos []string
	for i := 0; i < len(args); i++ {
		t := args[i]
		name, _, hasVal := strings.Cut(t, "=")
		switch {
		case gitConfigActions[name] != "":
			action = gitConfigActions[name]
		case strings.HasPrefix(t, "-") && t != "-":
			if !hasVal && gitConfigValueOptions[name] {
				i++
			}
		default:
			pos = append(pos, t)
		}
	}
	if action == "" && len(pos) > 0 && !strings.Contains(pos[0], ".") {
		if a, ok := gitConfigSubcommands[pos[0]]; ok {
			action, pos = a, pos[1:]
		}
	}
	if action == "" {
		action = "read"
		if len(pos) >= 2 {
			action = "set"
		}
	}
	if len(pos) == 0 {
		if action == "edit" {
			s.add("R-114", "git config --edit opens the configuration in an editor, so the guard cannot see the change", via)
		}
		return
	}
	key := normGitKey(pos[0])
	switch action {
	case "edit":
		s.add("R-114", "git config --edit opens the configuration in an editor, so the guard cannot see the change", via)
	case "section":
		if strings.EqualFold(pos[0], "core") {
			s.add("R-114", "git config removes or renames the [core] section, which holds core.hooksPath", via)
		}
	case "unset":
		if key == "core.hookspath" {
			s.add("R-114", "git config unsets core.hooksPath, so the repository's hook manager stops running", via)
		}
	case "set":
		value := ""
		if len(pos) >= 2 {
			value = pos[1]
		}
		switch {
		case key == "core.hookspath":
			s.add("R-114", "git config sets core.hooksPath to "+strconv.Quote(clampDetail(value))+", changing where git looks for hooks", via)
		case key == "core.fsmonitor" && !fsmonitorHarmless(value):
			s.add("R-114", "git config sets core.fsmonitor to "+strconv.Quote(clampDetail(value))+", a program git runs on every status", via)
		case strings.HasPrefix(key, "alias."):
			name := strings.TrimPrefix(key, "alias.")
			s.judgeAliasDefinition(name, value, "git config defines alias "+strconv.Quote(name), via, depth)
		}
	}
}

// matchGitFinding builds the shell matcher of one rule's git findings.
func matchGitFinding(rule string) MatchCmdFn {
	return func(ctx *MatchContext, cmd *Command) (bool, string) {
		for _, f := range gitFindings(ctx, cmd) {
			if f.rule == rule {
				return true, f.detail
			}
		}
		return false, ""
	}
}

// matchHookSkipExport is the R-113 record of an export alone: a skip
// switch set for later commands of a persistent shell, or for every later
// process (`setx`). The git command that would use it may come in a later
// call the guard judges on its own.
func matchHookSkipExport(_ *MatchContext, cmd *Command) (bool, string) {
	for _, a := range exportAssignments(cmd) {
		if h, ok := skipVarFor(a.name); ok && h.skips(a.value) {
			return true, a.how + " " + a.name + "=" + a.value + " switches the " + h.manager + " hooks off for later git commands"
		}
	}
	return false, ""
}

// gitInternalsPatterns is the R-114 deny surface: git's own configuration,
// attributes, refs and objects, and the user's global git config.
// .git/hooks is R-156.
var gitInternalsPatterns = []pathPattern{
	{"**/.git/config", "repository git config"},
	{"**/.git/config.worktree", "worktree git config"},
	{"**/.git/worktrees/*/config.worktree", "worktree git config"},
	{"**/.git/info/attributes", "repository git attributes"},
	{"**/.git/refs/**", "git refs"},
	{"**/.git/packed-refs", "git refs"},
	{"**/.git/objects/**", "git object store"},
	{"~/.gitconfig", "global git config"},
	{"~/.config/git/config", "global git config"},
	{"?:/users/*/.gitconfig", "global git config"},
}

// hookManagerConfigPatterns is the R-114 ask surface: the files a hook
// manager reads to decide which hooks run.
var hookManagerConfigPatterns = []pathPattern{
	{"**/.husky/**", "husky hooks"},
	{"**/.pre-commit-config.yaml", "pre-commit config"},
	{"**/.pre-commit-config.yml", "pre-commit config"},
	{"**/lefthook.yml", "lefthook config"},
	{"**/lefthook.yaml", "lefthook config"},
	{"**/.lefthook.yml", "lefthook config"},
	{"**/.lefthook.yaml", "lefthook config"},
	{"**/lefthook-local.yml", "lefthook config"},
	{"**/lefthook-local.yaml", "lefthook config"},
	{"**/.lefthook-local.yml", "lefthook config"},
	{"**/.lefthook-local.yaml", "lefthook config"},
	{"**/.lefthook/**", "lefthook scripts"},
	{"**/.overcommit.yml", "overcommit config"},
	{"**/.simple-git-hooks.json", "simple-git-hooks config"},
	{"**/.simple-git-hooks.js", "simple-git-hooks config"},
	{"**/.simple-git-hooks.cjs", "simple-git-hooks config"},
	{"**/simple-git-hooks.json", "simple-git-hooks config"},
	{"**/simple-git-hooks.js", "simple-git-hooks config"},
}

// gitAttributesPatterns are the attribute files R-114 judges by content.
var gitAttributesPatterns = []pathPattern{{"**/.gitattributes", "git attributes"}}

// gitAttrDriver finds a filter, diff or merge driver assignment in
// .gitattributes text.
var gitAttrDriver = regexp.MustCompile(`(?:^|[\s])(filter|diff|merge)=([A-Za-z0-9_.+-]+)`)

// gitBuiltinDrivers are driver names that need no configured program: git's
// built-in diff patterns and merge drivers, and Git LFS.
var gitBuiltinDrivers = map[string]map[string]bool{
	"diff": setOf("ada", "bash", "bibtex", "cpp", "csharp", "css", "dts", "elixir", "fortran", "fountain",
		"golang", "html", "java", "kotlin", "markdown", "matlab", "objc", "pascal", "perl", "php",
		"python", "ruby", "rust", "scheme", "tex", "lfs"),
	"merge":  setOf("text", "binary", "union", "lfs"),
	"filter": setOf("lfs"),
}

// customDrivers returns the custom driver assignments in text
// ("filter=x"), which name a program the git config must define.
func customDrivers(text string) map[string]bool {
	if len(text) > maxSwitchDoc {
		text = text[:maxSwitchDoc]
	}
	out := map[string]bool{}
	for _, m := range gitAttrDriver.FindAllStringSubmatch(text, -1) {
		if !gitBuiltinDrivers[m[1]][strings.ToLower(m[2])] {
			out[m[1]+"="+m[2]] = true
		}
	}
	return out
}

// newDriver returns a custom driver after has that before lacks.
func newDriver(before, after string) (string, bool) {
	had := customDrivers(before)
	for d := range customDrivers(after) {
		if !had[d] {
			return d, true
		}
	}
	return "", false
}

// matchGitAttributesWrite is the R-114 file row: a write or edit of
// .gitattributes that adds a custom filter or driver.
func matchGitAttributesWrite(ctx *MatchContext) (bool, string) {
	ev := ctx.Event
	if !isWriteEvent(ev) || len(ev.Edits) == 0 {
		return false, ""
	}
	if _, ok := pathPatternMatch(ctx.Path, ctx.Cfg.Home, gitAttributesPatterns); !ok {
		return false, ""
	}
	var current []byte
	have := false
	if ctx.Cfg.ReadFile != nil {
		current, have = ctx.Cfg.ReadFile(ctx.Path)
	}
	if after, ok := replayEdits(ev.Edits, string(current), have); ok {
		if d, hit := newDriver(string(current), after); hit {
			return true, d + " (" + ev.Target + ")"
		}
		return false, ""
	}
	for _, e := range ev.Edits {
		if d, hit := newDriver(e.Old, e.New); hit {
			return true, d + " (" + ev.Target + ")"
		}
	}
	return false, ""
}

// matchGitAttributesShell is the R-114 shell row: a unit writes
// .gitattributes and the command line names a custom driver.
func matchGitAttributesShell(ctx *MatchContext, cmd *Command) (bool, string) {
	anchors := unitAnchors(ctx, cmd)
	for _, t := range sensitivePathTokens(cmd) {
		if !classifyWrite(cmd, t.text) {
			continue
		}
		for _, c := range unitPathCandidates(ctx, anchors, t.text) {
			if _, ok := pathPatternMatch(c.path, ctx.Cfg.Home, gitAttributesPatterns); !ok {
				continue
			}
			if d, hit := newDriver("", shellLine(ctx.Event)); hit {
				return true, movedReason(d+" ("+t.text+")", c.moved)
			}
		}
	}
	return false, ""
}

// shWriteNotDelete is shPathMatch for writes that are not deletes.
func shWriteNotDelete(pats []pathPattern) MatchCmdFn {
	inner := shPathMatch(pats, true)
	return func(ctx *MatchContext, cmd *Command) (bool, string) {
		if _, isDelete := deleteShape(cmd); isDelete {
			return false, ""
		}
		return inner(ctx, cmd)
	}
}

// gitHookRules returns the R-112, R-113 and R-114 rows (appended to the
// boundary table).
func gitHookRules() []Rule {
	faCfg := []EventKind{KindFileAccess, KindConfigChange}
	shell := []EventKind{KindShellExec}
	const bypassAdvice = "Git hooks are the repository's own checks. Fix what the hook reports and commit normally; if a hook is wrong, ask the developer to change it." //nolint:gosec // G101: advice wording ("bypass"), not a credential
	const internalsAdvice = "Use git commands for git's own files, and leave hook settings to the developer."
	const managerAdvice = "Hook manager config decides which checks run on commit; the developer reviews changes to it."
	return []Rule{
		{
			ID: "R-112", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchGitFinding("R-112"),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "git command that skips the repository's hooks (--no-verify, -n, core.hooksPath for one command, injected git config, or an alias that does so)",
			Advice: bypassAdvice,
		},
		{
			ID: "R-113", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchGitFinding("R-113"),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "git command run with a hook manager's skip switch in its environment (HUSKY=0, SKIP=, LEFTHOOK=0 and their siblings)",
			Advice: bypassAdvice,
		},
		{
			ID: "R-113", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchHookSkipExport,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "export of a hook manager's skip switch for later commands (HUSKY=0, SKIP=, LEFTHOOK=0 and their siblings)",
			Advice: bypassAdvice,
		},
		{
			ID: "R-114", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchGitFinding("R-114"),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "git config change to where or whether hooks run (core.hooksPath, core.fsmonitor)",
			Advice: internalsAdvice,
		},
		{
			ID: "R-114", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: faCfg, Match: faPathMatch(gitInternalsPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent write to git's own config, attributes, refs or objects, or the global git config",
			Advice: internalsAdvice,
		},
		{
			// A delete is not a write here: removing .git/objects destroys
			// history, which R-102 judges; it does not reroute hooks.
			ID: "R-114", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: shWriteNotDelete(gitInternalsPatterns),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "shell command writing git's own config, attributes, refs or objects, or the global git config",
			Advice: internalsAdvice,
		},
		{
			ID: "R-114", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: faCfg, Match: faPathMatch(hookManagerConfigPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "agent edit of a git hook manager's config (.husky/, .pre-commit-config.yaml, lefthook.yml and their siblings)",
			Advice: managerAdvice,
		},
		{
			ID: "R-114", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: shPathMatch(hookManagerConfigPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "shell command writing a git hook manager's config",
			Advice: managerAdvice,
		},
		{
			ID: "R-114", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: faCfg, Match: matchGitAttributesWrite,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "agent edit of .gitattributes adding a custom filter, diff or merge driver (a program the git config runs)",
			Advice: managerAdvice,
		},
		{
			ID: "R-114", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchGitAttributesShell,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "shell command writing .gitattributes with a custom filter, diff or merge driver",
			Advice: managerAdvice,
		},
	}
}
