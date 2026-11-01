package policy

import "strings"

// Remote-tracking state writes (lane sec-gate4 audit finding 3). The
// daemon's per-remote credit for a held commit reads the repository's
// remote-tracking refs (refs/remotes/<remote>/...) and its remote
// configuration: a remote is credited with a held commit when one of its
// tracking refs holds it and its push URL is its fetch URL. An agent that
// writes a tracking ref itself (`git update-ref refs/remotes/backup/x
// HEAD`, `git fetch . HEAD:refs/remotes/backup/x`, a redirect into
// .git/refs/remotes), or rewires a remote (`git remote set-url`, `git
// config remote.backup.url`, an edit of .git/config), would make the next
// history pass credit a remote that never received the commit, and the
// push gate would then let a push of the secret through. RemoteStateWriteOf
// reads those writes; the security pack's commit gate (S-792) gates them
// while the project's posture is blocking.

// remoteStatePathPatterns are the files that hold the remote-tracking refs
// and the remote configuration, matched by name under any repository.
var remoteStatePathPatterns = []pathPattern{
	{"**/.git/refs/remotes/**", "a remote-tracking ref"},
	{"**/.git/packed-refs", "the packed refs file, which holds the remote-tracking refs"},
	{"**/.git/config", "the repository's git config, which names the remotes and their URLs"},
	{"**/.git/config.worktree", "a worktree's git config"},
	{"**/.git/worktrees/*/config.worktree", "a worktree's git config"},
}

// remoteConfigSections are the config sections whose keys decide where a
// push goes or what a fetch writes (and the include keys, which can pull
// in a file that sets them). Matched on the normalized key (normGitKey).
var remoteConfigSections = []string{"remote.", "url.", "branch.", "include.", "includeif."}

// remoteConfigKey reports a config key in remoteConfigSections, or a bare
// section name of one (`--remove-section remote.backup`).
func remoteConfigKey(k string) bool {
	k = strings.ToLower(strings.TrimSpace(k))
	for _, s := range remoteConfigSections {
		if strings.HasPrefix(k, s) || k == strings.TrimSuffix(s, ".") {
			return true
		}
	}
	return false
}

// pushRedirectEnv are the environment variables that change where a git
// command's push goes or which repository it runs in: any assignment of
// one on the command line makes the push's target unknown (audit finding
// 3).
var pushRedirectEnv = []string{"GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_DIR", "GIT_COMMON_DIR"}

// envRedirects reports an assignment of one of pushRedirectEnv in env
// (names upper-cased, as gitUnitEnv folds them).
func envRedirects(env map[string]string) bool {
	for _, n := range pushRedirectEnv {
		if _, ok := env[n]; ok {
			return true
		}
	}
	return false
}

// configRedirects reports a `-c` or `--config-env` entry naming a key in
// remoteConfigSections, or one whose key cannot be read.
func configRedirects(cfg []gitConfigEntry) bool {
	for _, e := range cfg {
		if e.key == "" || remoteConfigKey(e.key) {
			return true
		}
	}
	return false
}

// lineEnv is the export-style environment every unit of a command line
// can see (gitUnitEnv's first half): `export`, cmd's `set`, PowerShell's
// `$env:NAME = value` and their kin, anywhere in the line.
func lineEnv(cmds []Command) map[string]string {
	env := map[string]string{}
	for i := range cmds {
		for _, a := range exportAssignments(&cmds[i]) {
			env[strings.ToUpper(a.name)] = a.value
		}
	}
	return env
}

// gitLineUnitEnv is lineEnv with the unit's own prefix and `env` assignments.
func gitLineUnitEnv(line map[string]string, cmd *Command) map[string]string {
	env := make(map[string]string, len(line)+len(cmd.Env))
	for k, v := range line {
		env[k] = v
	}
	addEnvWords(env, cmd.Env)
	return env
}

// pushStateSubs are the git subcommands that can change where a later
// push on the same command line goes (the branch it pushes, its upstream,
// a remote's URL): a push after one of them on the same line has an
// unknown target, because the posture's remote state predates the line.
var pushStateSubs = setOf("checkout", "switch", "branch", "config", "remote")

// isLocalRepoOperand reports a fetch source that is the repository itself
// or a local path rather than a configured remote's name.
func isLocalRepoOperand(s string) bool {
	if s == "" {
		return false
	}
	ls := strings.ToLower(s)
	switch {
	case s == ".", s[0] == '.', s[0] == '/', s[0] == '~', s[0] == '\\':
		return true
	case strings.HasPrefix(ls, "file:"):
		return true
	case len(s) >= 2 && s[1] == ':' && ((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')):
		return true
	}
	return false
}

// writesTrackingRef reports a ref name (or a refspec destination) in the
// remote-tracking namespace. "remotes/<x>" counts too: git's ref
// shorthand rules may place it under refs/.
func writesTrackingRef(ref string) bool {
	r := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(ref), "+"))
	return strings.HasPrefix(r, "refs/remotes/") || strings.HasPrefix(r, "remotes/")
}

// gitOperands returns a subcommand's operands (words that are not
// options), skipping the separate value of each option in values.
func gitOperands(args []string, values map[string]bool) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return append(out, args[i+1:]...)
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			if !strings.Contains(a, "=") && values[a] {
				i++
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

// gitArgHas reports whether args carry one of the options (alone or with
// an "=" value).
func gitArgHas(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a == n || strings.HasPrefix(a, n+"=") {
				return true
			}
		}
	}
	return false
}

var (
	updateRefValues = setOf("-m")
	fetchValues     = setOf("--depth", "--deepen", "--shallow-since", "--shallow-exclude", "--refmap", "-o", "--server-option",
		"-j", "--jobs", "--negotiation-tip", "--upload-pack", "--filter", "--submodule-prefix", "--recurse-submodules-default")
	configValues = setOf("-f", "--file", "--blob", "--type", "--default", "--comment")
	// configReadOptions are the git config options that only read.
	configReadOptions = []string{"--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l", "--list", "--get-color", "--get-colorbool"}
	// configReadVerbs are git 2.46's read verbs (`git config get`).
	configReadVerbs = setOf("get", "list")
)

// remoteStateGitWrite judges one git invocation: whether it writes the
// remote-tracking state the per-remote credit reads.
func remoteStateGitWrite(inv gitInvocation, redirect bool) (bool, string) {
	switch inv.sub {
	case "update-ref", "symbolic-ref":
		if gitArgHas(inv.args, "--stdin") {
			return true, "git " + inv.sub + " --stdin may write a remote-tracking ref"
		}
		for _, op := range gitOperands(inv.args, updateRefValues) {
			if writesTrackingRef(op) {
				return true, "git " + inv.sub + " writes the remote-tracking ref " + clampDetail(op)
			}
		}
	case "fast-import":
		return true, "git fast-import may write a remote-tracking ref"
	case "fetch", "pull":
		return remoteStateFetchWrite(inv, redirect)
	case "remote":
		ops := gitOperands(inv.args, nil)
		if len(ops) > 0 {
			switch ops[0] {
			case "add", "rename", "mv", "set-url", "remove", "rm":
				return true, "git remote " + ops[0] + " changes the configured remotes"
			}
		}
	case "config":
		return gitConfigWritesRemote(inv.args)
	case "branch":
		if gitArgHas(inv.args, "-u", "--set-upstream-to", "--set-upstream", "--unset-upstream") {
			return true, "git branch changes a branch's upstream remote"
		}
		for _, a := range inv.args {
			if len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.IndexByte(a[1:], 'u') >= 0 {
				return true, "git branch changes a branch's upstream remote"
			}
		}
	}
	return false, ""
}

// remoteStateFetchWrite is remoteStateGitWrite's fetch and pull case.
func remoteStateFetchWrite(inv gitInvocation, redirect bool) (bool, string) {
	if gitArgHas(inv.args, "--stdin") {
		return true, "git " + inv.sub + " --stdin reads refspecs that may write a remote-tracking ref"
	}
	for i, a := range inv.args {
		v, ok := strings.CutPrefix(a, "--refmap=")
		if !ok && a == "--refmap" && i+1 < len(inv.args) {
			v, ok = inv.args[i+1], true
		}
		if ok {
			if _, dst, _ := strings.Cut(v, ":"); writesTrackingRef(dst) {
				return true, "git " + inv.sub + " --refmap writes remote-tracking refs"
			}
		}
	}
	ops := gitOperands(inv.args, fetchValues)
	if inv.sub == "fetch" && len(ops) > 0 && isLocalRepoOperand(ops[0]) {
		return true, "git fetch from the repository itself or a local path (" + clampDetail(ops[0]) + ")"
	}
	if len(ops) > 1 {
		for _, spec := range ops[1:] {
			if _, dst, ok := strings.Cut(spec, ":"); ok && writesTrackingRef(dst) {
				return true, "git " + inv.sub + " refspec " + clampDetail(spec) + " writes a remote-tracking ref"
			}
		}
	}
	if redirect {
		return true, "git " + inv.sub + " with a remote, url or include setting on the command line"
	}
	return false, ""
}

// gitConfigWritesRemote reports a `git config` that changes a key in
// remoteConfigSections (set, unset, add, replace, a section removal or
// rename), or opens the config in an editor.
func gitConfigWritesRemote(args []string) (bool, string) {
	if gitArgHas(args, "-e", "--edit") {
		return true, "git config --edit can change the remote configuration"
	}
	if gitArgHas(args, configReadOptions...) {
		return false, ""
	}
	ops := gitOperands(args, configValues)
	if len(ops) > 0 && configReadVerbs[ops[0]] {
		return false, ""
	}
	if len(ops) > 0 && ops[0] == "edit" {
		return true, "git config edit can change the remote configuration"
	}
	for _, op := range ops {
		if remoteConfigKey(op) {
			return true, "git config writes " + clampDetail(op)
		}
	}
	for i, a := range args {
		for _, opt := range []string{"--remove-section", "--rename-section", "--unset", "--unset-all", "--replace-all", "--add"} {
			if v, ok := strings.CutPrefix(a, opt+"="); ok && remoteConfigKey(v) {
				return true, "git config " + opt + " " + clampDetail(v)
			}
			if a == opt && i+1 < len(args) && remoteConfigKey(args[i+1]) {
				return true, "git config " + opt + " " + clampDetail(args[i+1])
			}
		}
	}
	return false, ""
}

// remoteStateScan judges one git argv through its aliases.
func remoteStateScan(argv []string, env map[string]string, inline, table map[string]string, depth int) (bool, string) {
	inv := parseGitInvocation(argv)
	if inv.sub == "" {
		return false, ""
	}
	redirect := envRedirects(env) || configRedirects(inv.config)
	if ok, d := remoteStateGitWrite(inv, redirect); ok {
		return true, d
	}
	if gitBuiltinSubs[inv.sub] || depth >= maxGitAliasDepth {
		return false, ""
	}
	exp, ok := inline[strings.ToLower(inv.sub)]
	if !ok && table != nil {
		exp, ok = table[strings.ToLower(inv.sub)]
	}
	if !ok {
		return false, ""
	}
	if line, shell := strings.CutPrefix(exp, "!"); shell {
		line = unwrapAliasFunction(line)
		if len(inv.args) > 0 {
			line += " " + strings.Join(inv.args, " ")
		}
		for _, u := range ParseCommand(line, DialectPosix) {
			if u.Base == "git" {
				if ok, d := remoteStateScan(u.Argv, env, inline, table, depth+1); ok {
					return true, d
				}
			}
		}
		return false, ""
	}
	next := append([]string{"git"}, splitGitAlias(exp)...)
	return remoteStateScan(append(next, inv.args...), env, inline, table, depth+1)
}

// RemoteStateWriteOf reports an agent write to the repository's
// remote-tracking refs or remote configuration (see the file comment): a
// git command (update-ref or symbolic-ref on refs/remotes/, a fetch from
// the repository itself or a local path or whose refspec writes
// refs/remotes/, git remote add/rename/set-url/remove, git config on a
// remote, url, branch or include key, git branch --set-upstream-to), and
// a file write into .git/refs/remotes or to .git/packed-refs or
// .git/config, by the Write and Edit tools' paths, a shell redirect, tee,
// cp, mv and their kin, or an interpreter one-liner naming one. The
// detail names the write.
func RemoteStateWriteOf(ctx *MatchContext) (bool, string) {
	if ctx == nil || ctx.Event == nil {
		return false, ""
	}
	switch ctx.Event.Kind {
	case KindFileAccess, KindConfigChange:
		return faPathMatch(remoteStatePathPatterns, true)(ctx)
	case KindShellExec:
	default:
		return false, ""
	}
	var table map[string]string
	if ctx.Cfg != nil && ctx.Cfg.GitAliases != nil {
		dir := ctx.Event.Cwd
		if dir == "" {
			dir = ctx.Event.ProjectRoot
		}
		if t, ok := ctx.Cfg.GitAliases(dir); ok {
			table = t
		}
	}
	line := lineEnv(ctx.Cmds)
	inline := map[string]string{}
	paths := shPathMatch(remoteStatePathPatterns, true)
	for i := range ctx.Cmds {
		c := &ctx.Cmds[i]
		if c.Base == "git" {
			if ok, d := remoteStateScan(c.Argv, gitLineUnitEnv(line, c), inline, table, 0); ok {
				return true, d
			}
			recordAliasDefinition(c.Argv, inline)
		}
		if ctx.Cfg != nil {
			if ok, d := paths(ctx, c); ok {
				return true, d
			}
			if ok, d := inlinePathMatch(ctx, c, remoteStatePathPatterns); ok {
				return true, d
			}
		}
	}
	return false, ""
}

// inlinePathMatch is matchConsentRecordInline over another pattern table:
// a literal in interpreter program text that names one of pats, judged as
// a write (program text does not show the direction).
func inlinePathMatch(ctx *MatchContext, cmd *Command, pats []pathPattern) (bool, string) {
	ops := inlineOperands(ctx, cmd)
	if len(ops) == 0 {
		return false, ""
	}
	anchors := unitAnchors(ctx, cmd)
	for _, op := range ops {
		for _, c := range unitPathCandidates(ctx, anchors, op.text) {
			if desc, ok := pathPatternMatch(c.path, ctx.Cfg.Home, pats); ok {
				return true, movedReason(desc+" ("+op.text+", named in a "+op.kind+" inline script)", c.moved)
			}
		}
	}
	return false, ""
}
