package policy

import (
	"strings"
)

// The git_commit classifier (security pillar plan section 4.7 item 4,
// revisions 2.4 and 2.5 [JSP-6]): which commands record, move or merge
// commits, so the commit-gate rules (S-791 to S-794, security Phase C) can
// stop an agent's commit whose changes have not been scanned.
//
// Two data tables, one test case per row:
//
//   - the shell table (commitShellTable): git porcelain and plumbing that
//     records or moves commits, and the gh routes that merge or write
//     repository content;
//   - the MCP table (commitMCPTable): MCP tools known to commit, matched by
//     the tool name only, because MCP git tools arrive as mcp_call events
//     with the tool name as the target.
//
// The classifier keys on the PARSED intent (the git subcommand, its
// global options and its flags), never on one exact command string: a
// model whose commit was denied often retries it in other words (Kilo,
// JSP-6 live half), and a rewording must reach the same rule. It reads
// only the event's command field (Target or Args, which the boundary
// fills from the payload's command, cmd or commands field): a planning
// tool that restates the next command in a summary (Gemini's
// update_topic) is not a shell event and is never classified.
//
// Named residuals (docs/security.md SECP rows): interpreter one-liners
// (`python3 -c`, `node -e`) and package scripts (`npm run release`) are
// opaque. They are reported as CommitResidual so a verdict or an audit row
// can name them, and no gate rule decides on them.

// The classifier's output is the contract type GitWrite (security.go, lane
// SEC-A's type contract): its Form is one of the closed GitWriteForm
// values. Two shapes ride beside the forms, both with an empty Form: a
// push (Push set; the git_push sink, S-792) and a named residual
// (FlagOnly set, an opaque interpreter one-liner or package script that
// may commit; never gated).

// ClassifiedGitWrite is one classified write with a bounded detail naming
// the command, for a verdict reason.
type ClassifiedGitWrite struct {
	Write  GitWrite
	Detail string
}

// GitWriteGates reports whether w is one the commit-gate rules decide on:
// it records, moves or merges a commit, or pushes, and is not flag-only.
func GitWriteGates(w GitWrite) bool { return !w.FlagOnly }

// GitWriteIsPush reports a push (the git_push sink) rather than a commit.
func GitWriteIsPush(w GitWrite) bool { return w.Push && w.Form == "" }

// PushTarget is where one classified push goes, read off the command
// line (lane sec-gate4 milestone 1a): the remote it names and its
// refspecs. Known is false when the remote cannot be read off the command:
// a URL or a path, an option that changes what is sent (PushOpaque), a
// command line that may have changed where it goes (PushRedirect), a `-C
// dir` / `--git-dir` naming another repository, or no remote operand when
// the default push remote is not known. The push gate then treats nothing
// as already on the target.
type PushTarget struct {
	Remote   string
	Refspecs []string
	Known    bool
}

// maxRemoteName bounds a remote name the target reads.
const maxRemoteName = 128

// PushTargetOf reads the target of a push write (GitWriteIsPush) off the
// command alone: a push with no remote operand is unknown.
func PushTargetOf(w GitWrite) PushTarget { return PushTargetFor(w, "") }

// PushTargetFor is PushTargetOf with the project's default push remote
// (lane sec-gate4 audit finding 5: the remote the daemon resolved and
// signed for the checked-out branches, branch.<b>.pushRemote, then
// remote.pushDefault, then branch.<b>.remote, "" when it could not): a
// plain `git push` (no remote operand, no redirect) goes there.
func PushTargetFor(w GitWrite, defaultRemote string) PushTarget {
	if !GitWriteIsPush(w) || w.PushOpaque || w.PushRedirect || w.Dir != "" {
		return PushTarget{}
	}
	if len(w.PushOperands) == 0 {
		if !IsRemoteName(defaultRemote) {
			return PushTarget{}
		}
		return PushTarget{Remote: defaultRemote, Known: true}
	}
	t := PushTarget{Remote: w.PushOperands[0], Refspecs: append([]string(nil), w.PushOperands[1:]...)}
	t.Known = IsRemoteName(t.Remote)
	if !t.Known {
		t.Remote = ""
	}
	return t
}

// IsRemoteName reports whether s reads as a configured remote's name, not
// a URL or a path: letters, digits and . _ - /, not starting with a dot,
// a dash or a slash, no "..", at most maxRemoteName bytes. A name that is
// not a configured remote is still never on the posture's remote list, so
// a path that passes this check is gated like an unknown target.
func IsRemoteName(s string) bool {
	if s == "" || len(s) > maxRemoteName || strings.Contains(s, "..") || strings.HasSuffix(s, "/") {
		return false
	}
	switch s[0] {
	case '.', '-', '/':
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-', c == '/':
		default:
			return false
		}
	}
	return true
}

// commitShellRow is one row of the shell table: a git subcommand and how
// it is read.
type commitShellRow struct {
	sub string
	// form is the row's GitWriteForm; push marks the push row instead.
	form GitWriteForm
	push bool
	// skip lists options under which the subcommand records no commit
	// (an abort, a listing); any one of them drops the row.
	skip []string
	// flagOnly marks a row the gate records but never stops on.
	flagOnly bool
	// onlyActions, when set, restricts the row to these first operands
	// ("" is the bare subcommand), for subcommands with verbs (stash).
	onlyActions []string
	// needOperand drops the bare subcommand (`git replace` alone lists).
	needOperand bool
}

// commitShellTable is THE shell table (security plan section 4.7 item 4).
var commitShellTable = []commitShellRow{
	{sub: "commit", form: GitWriteCommit, skip: []string{"--dry-run"}},
	{sub: "commit-tree", form: GitWriteCommitTree},
	{sub: "update-ref", form: GitWriteUpdateRef},
	{sub: "merge", form: GitWriteMerge, skip: []string{"--abort", "--quit"}},
	{sub: "cherry-pick", form: GitWriteCherryPick, skip: []string{"--abort", "--quit"}},
	{sub: "am", form: GitWriteAm, skip: []string{"--abort", "--quit", "--show-current-patch"}},
	{sub: "rebase", form: GitWriteRebase, skip: []string{"--abort", "--quit", "--edit-todo", "--show-current-patch"}},
	{sub: "revert", form: GitWriteRevert, skip: []string{"--abort", "--quit"}},
	{sub: "stash", form: GitWriteStash, flagOnly: true, onlyActions: []string{"", "push", "save"}},
	{sub: "push", push: true, skip: []string{"--dry-run"}},
	// `git pull` merges (or, with --rebase, rebases) what it fetched, and
	// a merge records a merge commit.
	{sub: "pull", form: GitWriteMerge, skip: []string{"--dry-run"}},
	// History writers with no commit form of their own take the closest
	// one; the quick scan answers unknown for every form but commit.
	{sub: "fast-import", form: GitWriteUpdateRef},
	{sub: "filter-branch", form: GitWriteRebase},
	{sub: "filter-repo", form: GitWriteRebase, skip: []string{"--analyze", "--dry-run"}},
	{sub: "replace", form: GitWriteUpdateRef, skip: []string{"-l", "--list", "-d", "--delete"}, needOperand: true},
}

// pushOpaqueOptions are the push options that change what is sent in a
// way the quick scan does not model: it answers unknown for them.
var pushOpaqueOptions = setOf("--all", "--branches", "--mirror", "--tags", "--follow-tags",
	"--delete", "-d", "--prune", "--repo")

// maxPushOperands bounds the push operands a GitWrite carries; a push
// with more is opaque.
const maxPushOperands = 32

// mcpPlace is where a commit-capable MCP tool's write is placed (the
// placement column of commitMCPTable; lane SEC-P4 decision 2).
type mcpPlace int

const (
	// mcpPlaceEvent: the write runs in the event's own directory (today's
	// placement): the GitHub server's merge_pull_request and delete_file.
	mcpPlaceEvent mcpPlace = iota
	// mcpPlaceRepoPath: the reference git server places the write by its
	// repo_path argument; an absent, unreadable or network path reads
	// unknown.
	mcpPlaceRepoPath
	// mcpPlaceContent: the GitHub server writes the file contents its
	// arguments carry; they are scanned with the hook's secret detector
	// like a file write's edits (a hit gates as blocking, an over-cap or
	// unreadable argument reads unknown), on top of the event's own
	// placement.
	mcpPlaceContent
)

// commitMCPTable lists MCP tool names known to commit or write repository
// content (the reference git server's git_commit, git_merge,
// git_cherry_pick, git_rebase and git_revert; the GitHub server's
// push_files, create_or_update_file, merge_pull_request and delete_file;
// create_commit), each with its placement column. The match is on the
// tool name after the server prefix, lowercased.
var commitMCPTable = map[string]mcpPlace{
	"git_commit":            mcpPlaceRepoPath,
	"git_merge":             mcpPlaceRepoPath,
	"git_cherry_pick":       mcpPlaceRepoPath,
	"git_rebase":            mcpPlaceRepoPath,
	"git_revert":            mcpPlaceRepoPath,
	"push_files":            mcpPlaceContent,
	"create_or_update_file": mcpPlaceContent,
	"create_commit":         mcpPlaceContent,
	"merge_pull_request":    mcpPlaceEvent,
	"delete_file":           mcpPlaceEvent,
}

// ghAPIWriteRoutes are path fragments of the GitHub REST routes that write
// repository content or merge (`gh api`).
var ghAPIWriteRoutes = []string{"/contents/", "/git/commits", "/git/refs", "/git/trees", "/git/blobs", "/merges", "/merge"}

// interpreterEvalFlags are the interpreters whose one-line program flag
// makes the command opaque, with that flag.
var interpreterEvalFlags = map[string][]string{
	"python": {"-c"}, "python3": {"-c"}, "py": {"-c"},
	"node": {"-e", "--eval", "-p", "--print"}, "deno": {"eval"}, "bun": {"-e", "--eval"},
	"ruby": {"-e"}, "perl": {"-e", "-E"},
}

// packageScriptRunners are the package managers whose `run <script>` is
// opaque; packageCommitScripts are the script names that commonly commit
// or publish.
var (
	packageScriptRunners = setOf("npm", "pnpm", "yarn", "bun")
	packageCommitScripts = setOf("release", "publish", "commit", "version", "deploy", "ship")
)

// ClassifyGitWrites classifies an event at the git_commit and git_push
// sinks: every command unit of a shell event (Target or Args, nested
// shells unwrapped), or the tool name of an MCP event. A shell line with
// several commits yields several intents. It reads no other event field.
func ClassifyGitWrites(ev *Event) []GitWrite {
	cls := ClassifyGitWritesDetailed(ev)
	out := make([]GitWrite, 0, len(cls))
	for _, c := range cls {
		out = append(out, c.Write)
	}
	return out
}

// ClassifyGitWritesDetailed is ClassifyGitWrites with each write's bounded
// command detail.
func ClassifyGitWritesDetailed(ev *Event) []ClassifiedGitWrite {
	if ev == nil {
		return nil
	}
	switch ev.Kind {
	case KindMCPCall:
		if in, ok := classifyCommitMCP(ev.Target); ok {
			return []ClassifiedGitWrite{in}
		}
		return nil
	case KindShellExec:
		var cmds []Command
		if len(ev.Args) > 0 {
			cmds = ParseArgv(ev.Args, ev.Dialect)
		} else {
			cmds = ParseCommand(ev.Target, ev.Dialect)
		}
		return ClassifyCommitCommands(cmds, nil)
	}
	return nil
}

// ClassifyGitWritesCtx is ClassifyGitWritesDetailed for a rule's match
// context: it also reads the per-directory alias table the daemon
// precomputes (Config.GitAliases, for the event's Cwd, else its
// ProjectRoot), so `git ci` reaches the same answer as `git commit`. The
// git_commit sink and the commit-gate rules call this one. A `git -C dir`
// alias is read from the event's directory table, not dir's (a named
// residual: aliases are per repository and the hook never runs git).
//
// A shell line with a second reading (Event.AltDialect: a generic shell
// tool on a Windows working directory, which Codex and Copilot CLI run
// through PowerShell) is classified under both, the way the engine reads
// both (buildContext) and GitWriteLocations places both, and the results
// are combined (unionGitWriteReadings): a write either reading sees is
// classified, once (SEC-GATE5 follow-up: `cd C:\x\; git commit` is a
// commit only the PowerShell reading sees, since `\;` escapes the separator
// for POSIX).
func ClassifyGitWritesCtx(ctx *MatchContext) []ClassifiedGitWrite {
	if ctx == nil || ctx.Event == nil {
		return nil
	}
	ev := ctx.Event
	if ev.Kind != KindShellExec {
		return ClassifyGitWritesDetailed(ev)
	}
	var aliases map[string]string
	if ctx.Cfg != nil && ctx.Cfg.GitAliases != nil {
		dir := ev.Cwd
		if dir == "" {
			dir = ev.ProjectRoot
		}
		if table, ok := ctx.Cfg.GitAliases(dir); ok {
			aliases = table
		}
	}
	if len(ev.Args) > 0 {
		return ClassifyCommitCommands(ParseArgv(ev.Args, ev.Dialect), aliases)
	}
	out := ClassifyCommitCommands(ParseCommand(ev.Target, ev.Dialect), aliases)
	if alt := ev.AltDialect; alt != "" && normDialect(alt) != normDialect(ev.Dialect) {
		out = unionGitWriteReadings(out, ClassifyCommitCommands(ParseCommand(ev.Target, alt), aliases))
	}
	return out
}

// unionGitWriteReadings combines the writes one shell line yields under two
// readings, most restrictive first. Every write of a is kept in order; each
// write of b is folded into the first write of a of the same kind (its
// form, whether it is a push, whether it is flag-only) not yet paired, and
// a write of b with no such partner is added after them. So each kind
// counts the larger of the two readings' numbers, never their sum, and a
// line both readings read alike is returned as a reads it. Pure.
func unionGitWriteReadings(a, b []ClassifiedGitWrite) []ClassifiedGitWrite {
	if len(b) == 0 {
		return a
	}
	out := append(make([]ClassifiedGitWrite, 0, len(a)+len(b)), a...)
	paired := make([]bool, len(a))
	for _, w := range b {
		j := -1
		for i := range a {
			if !paired[i] && sameGitWriteKind(out[i].Write, w.Write) {
				j = i
				break
			}
		}
		if j < 0 {
			out = append(out, w)
			continue
		}
		paired[j] = true
		out[j].Write = foldGitWrite(out[j].Write, w.Write)
		if out[j].Detail == "" {
			out[j].Detail = w.Detail
		}
	}
	return out
}

// sameGitWriteKind reports two writes of one kind for unionGitWriteReadings.
func sameGitWriteKind(x, y GitWrite) bool {
	return x.Form == y.Form && GitWriteIsPush(x) == GitWriteIsPush(y) && x.FlagOnly == y.FlagOnly
}

// foldGitWrite folds y, the same write under the other shell reading, into
// x, keeping whichever reading is the more restrictive: a flag either sets
// is set; pathspecs the readings disagree on are combined and read as an
// all-files commit (the quick scan then reads the working tree, not only
// the index); push operands they disagree on make the push's target
// unknown (PushOpaque); a directory only y names is kept.
func foldGitWrite(x, y GitWrite) GitWrite {
	x.Push = x.Push || y.Push
	x.All = x.All || y.All
	x.Amend = x.Amend || y.Amend
	x.Exec = x.Exec || y.Exec
	x.PushOpaque = x.PushOpaque || y.PushOpaque
	x.PushRedirect = x.PushRedirect || y.PushRedirect
	if !sameStrings(x.Pathspecs, y.Pathspecs) {
		ps := append([]string(nil), x.Pathspecs...)
		for _, p := range y.Pathspecs {
			if !containsString(ps, p) {
				ps = append(ps, p)
			}
		}
		x.Pathspecs, x.All = ps, true
	}
	if !sameStrings(x.PushOperands, y.PushOperands) {
		x.PushOpaque = true
	}
	if x.Dir == "" {
		x.Dir = y.Dir
	} else if y.Dir != "" && y.Dir != x.Dir && GitWriteIsPush(x) {
		x.PushOpaque = true
	}
	return x
}

// sameStrings reports two string slices with the same elements in order.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// GatedGitWrites returns the commits (never a push, never a flag-only
// form) ClassifyGitWritesCtx finds: what the git_commit sink gates.
func GatedGitWrites(ctx *MatchContext) []GitWrite {
	var out []GitWrite
	for _, c := range ClassifyGitWritesCtx(ctx) {
		if GitWriteGates(c.Write) && !GitWriteIsPush(c.Write) {
			out = append(out, c.Write)
		}
	}
	return out
}

// ClassifyCommitCommands classifies parsed command units. aliases, when
// non-nil, is the per-project git alias table the daemon precomputes
// (Config.GitAliases for the event's directory); an alias defined earlier
// on the same line (`git config alias.ci commit && git ci`) or with
// `git -c alias.x=...` is read too.
func ClassifyCommitCommands(cmds []Command, aliases map[string]string) []ClassifiedGitWrite {
	inline := map[string]string{}
	var out []ClassifiedGitWrite
	line := lineEnv(cmds)
	// stateChanged: an earlier git unit on this line switched the branch or
	// rewired a remote, so a later push's target is unknown (audit finding
	// 3; the posture's remote state predates the line).
	stateChanged := false
	for i := range cmds {
		c := &cmds[i]
		switch {
		case c.Base == "git":
			redirect := stateChanged || envRedirects(gitLineUnitEnv(line, c))
			out = append(out, classifyGitArgv(c.Argv, inline, aliases, 0, redirect)...)
			recordAliasDefinition(c.Argv, inline)
			if pushStateSubs[parseGitInvocation(c.Argv).sub] {
				stateChanged = true
			}
		case c.Base == "gh":
			if in, ok := classifyGH(c); ok {
				out = append(out, in)
			}
		case !c.scriptBlock && posixFuncDefHeader(c.Argv) > 0:
			// A POSIX function definition glues its header to the body's
			// first command (`f(){ git commit; }` is one unit whose base is
			// "f(){"): the body's git command is read, so the commit is
			// gated, not missed (lane SEC-P4 decision 1). Stricter only:
			// before, the unit matched nothing.
			if body := c.Argv[posixFuncDefHeader(c.Argv):]; len(body) > 0 && canonicalBase(body[0], "") == "git" {
				out = append(out, classifyGitArgv(body, inline, aliases, 0, stateChanged || envRedirects(gitLineUnitEnv(line, c)))...)
			}
		default:
			if in, ok := classifyResidual(c); ok {
				out = append(out, in)
			}
		}
	}
	return out
}

// classifyGitArgv classifies one git argv, expanding an alias up to
// maxGitAliasDepth levels. redirect carries a push redirect the line or an
// outer alias level already showed.
func classifyGitArgv(argv []string, inline, table map[string]string, depth int, redirect bool) []ClassifiedGitWrite {
	inv := parseGitInvocation(argv)
	if inv.sub == "" {
		return nil
	}
	redirect = redirect || configRedirects(inv.config)
	gitDir := gitDirOption(argv)
	for _, e := range inv.config {
		if name, ok := strings.CutPrefix(e.key, "alias."); ok && e.seen {
			inline[strings.ToLower(name)] = e.value
		}
	}
	for _, row := range commitShellTable {
		if row.sub != inv.sub {
			continue
		}
		in, ok := readCommitRow(row, inv.args)
		if !ok {
			return nil
		}
		in.Dir = inv.dir
		if in.Dir == "" {
			in.Dir = gitDir
		}
		if in.Push {
			in.PushRedirect = redirect
		}
		return []ClassifiedGitWrite{{Write: in, Detail: clampDetail(strings.Join(argv, " "))}}
	}
	if gitBuiltinSubs[inv.sub] || depth >= maxGitAliasDepth {
		return nil
	}
	exp, ok := inline[strings.ToLower(inv.sub)]
	if !ok && table != nil {
		exp, ok = table[strings.ToLower(inv.sub)]
	}
	if !ok {
		return nil
	}
	if line, shell := strings.CutPrefix(exp, "!"); shell {
		line = unwrapAliasFunction(line)
		if len(inv.args) > 0 {
			line += " " + strings.Join(inv.args, " ")
		}
		var out []ClassifiedGitWrite
		for _, u := range ParseCommand(line, DialectPosix) {
			if u.Base == "git" {
				out = append(out, classifyGitArgv(u.Argv, inline, table, depth+1, redirect)...)
			}
		}
		return out
	}
	next := append([]string{"git"}, splitGitAlias(exp)...)
	return classifyGitArgv(append(next, inv.args...), inline, table, depth+1, redirect)
}

// readCommitRow reads a subcommand's arguments under its table row.
func readCommitRow(row commitShellRow, args []string) (GitWrite, bool) {
	in := GitWrite{Form: row.form, Push: row.push, FlagOnly: row.flagOnly}
	vals := gitSubOptionValues[row.sub]
	var operands []string
	rest := false
	// skipped holds until a later negation: git's parse-options takes the
	// last of --dry-run and --no-dry-run (or --abort and --no-abort), so a
	// skip option followed by its negation still writes (RB1 sweep H1).
	skipped := false
	for i := 0; i < len(args); i++ {
		t := args[i]
		if rest || !strings.HasPrefix(t, "-") || t == "-" {
			operands = append(operands, t)
			continue
		}
		if t == "--" {
			rest = true
			continue
		}
		if containsString(row.skip, t) {
			skipped = true
			continue
		}
		if negatesSkip(row.skip, t) {
			skipped = false
		}
		name, val, hasVal := strings.Cut(t, "=")
		if strings.HasPrefix(t, "--") {
			applyLongFlag(row, &in, name, val, hasVal)
			// git accepts any unambiguous prefix of a long option, so an
			// abbreviated value option (--mes) takes the next word too.
			if !hasVal && longValueOption(vals.long, name) {
				i++
			}
			continue
		}
		if row.push && pushOpaqueOptions[name] {
			in.PushOpaque = true
		}
		// A short cluster: letters until one that takes a value.
		for j := 1; j < len(t); j++ {
			l := t[j]
			applyShortFlag(row, &in, l)
			if strings.IndexByte(vals.shortAttached, l) >= 0 {
				break
			}
			if strings.IndexByte(vals.short, l) >= 0 {
				if j == len(t)-1 {
					i++
				}
				break
			}
		}
	}
	if skipped {
		return GitWrite{}, false
	}
	if row.onlyActions != nil {
		act := ""
		if len(operands) > 0 {
			act = operands[0]
		}
		if !containsString(row.onlyActions, act) {
			return GitWrite{}, false
		}
	}
	if row.needOperand && len(operands) == 0 {
		return GitWrite{}, false
	}
	if row.sub == "commit" {
		in.Pathspecs = operands
	}
	if row.push {
		if len(operands) > maxPushOperands {
			in.PushOpaque = true
			operands = operands[:maxPushOperands]
		}
		in.PushOperands = operands
	}
	return in, true
}

// negatesSkip reports whether t is the negation of one of the long skip
// options (--no-dry-run, or any abbreviation git would expand to it:
// --no-dry), which cancels an earlier skip option. Erring toward a
// negation only gates more.
func negatesSkip(skip []string, t string) bool {
	rest, ok := strings.CutPrefix(t, "--no-")
	if !ok || rest == "" || strings.Contains(rest, "=") {
		return false
	}
	for _, s := range skip {
		if name, long := strings.CutPrefix(s, "--"); long && strings.HasPrefix(name, rest) {
			return true
		}
	}
	return false
}

// longValueOption reports whether name (a long option without "=") is a
// value-taking option of the subcommand, spelled out or abbreviated to an
// unambiguous-looking prefix of one (git expands --mes to --message).
func longValueOption(long map[string]bool, name string) bool {
	if long[name] {
		return true
	}
	if len(name) < len("--x") {
		return false
	}
	for opt := range long {
		if strings.HasPrefix(opt, name) {
			return true
		}
	}
	return false
}

// applyLongFlag records what one long option of row's subcommand says
// about the write.
func applyLongFlag(row commitShellRow, in *GitWrite, name, val string, hasVal bool) {
	if row.push && pushOpaqueOptions[name] {
		in.PushOpaque = true
	}
	switch {
	case name == "--all" && row.sub == "commit":
		in.All = true
	case name == "--amend":
		in.Amend = true
	case name == "--exec" && row.sub == "rebase":
		in.Exec = true
	case name == "--rebase" && row.sub == "pull" && (!hasVal || val != "false"):
		in.Form = GitWriteRebase
	}
}

// shortFlagEffects is what a short option letter says, per subcommand.
var shortFlagEffects = map[string]map[byte]func(*GitWrite){
	"commit": {'a': func(w *GitWrite) { w.All = true }},
	"rebase": {'x': func(w *GitWrite) { w.Exec = true }},
	"pull":   {'r': func(w *GitWrite) { w.Form = GitWriteRebase }},
	"push":   {'d': func(w *GitWrite) { w.PushOpaque = true }},
}

// applyShortFlag records what one short option letter says.
func applyShortFlag(row commitShellRow, in *GitWrite, l byte) {
	if fn, ok := shortFlagEffects[row.sub][l]; ok {
		fn(in)
	}
}

// gitDirOption returns git's `--git-dir` value from argv ("" when none).
func gitDirOption(argv []string) string {
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		if !strings.HasPrefix(t, "-") {
			return ""
		}
		if v, ok := strings.CutPrefix(t, "--git-dir="); ok {
			return v
		}
		if t == "--git-dir" && i+1 < len(argv) {
			return argv[i+1]
		}
		if gitGlobalValueOptions[t] {
			i++
		}
	}
	return ""
}

// recordAliasDefinition reads `git config [--global|--local] alias.x value`
// into inline, so a later unit on the same line expands it.
func recordAliasDefinition(argv []string, inline map[string]string) {
	inv := parseGitInvocation(argv)
	if inv.sub != "config" {
		return
	}
	var words []string
	for _, a := range inv.args {
		if !strings.HasPrefix(a, "-") {
			words = append(words, a)
		}
	}
	if len(words) < 2 {
		return
	}
	if name, ok := strings.CutPrefix(normGitKey(words[0]), "alias."); ok {
		inline[strings.ToLower(name)] = strings.Join(words[1:], " ")
	}
}

// classifyGH reads `gh pr merge` and the content-writing `gh api` routes.
func classifyGH(c *Command) (ClassifiedGitWrite, bool) {
	pos := ghPositionals(c.Args())
	if len(pos) >= 2 && pos[0] == "pr" && pos[1] == "merge" {
		return ClassifiedGitWrite{Write: GitWrite{Form: GitWriteGHPRMerge}, Detail: clampDetail(c.Raw)}, true
	}
	if len(pos) < 2 || pos[0] != "api" {
		return ClassifiedGitWrite{}, false
	}
	route := strings.ToLower(pos[1])
	if route == "graphql" {
		if ghGraphQLWrites(c.Args()) {
			return ClassifiedGitWrite{Write: GitWrite{Form: GitWriteGHAPIWrite}, Detail: clampDetail(c.Raw)}, true
		}
		return ClassifiedGitWrite{}, false
	}
	write := false
	for _, r := range ghAPIWriteRoutes {
		if strings.Contains(route, r) {
			write = true
			break
		}
	}
	if !write {
		return ClassifiedGitWrite{}, false
	}
	method, ok := c.FlagValue("-X", "--method")
	if !ok {
		// gh api defaults to GET, and to POST when a field is given.
		for _, a := range c.Args() {
			if a == "-f" || a == "-F" || a == "--field" || a == "--raw-field" || a == "--input" ||
				strings.HasPrefix(a, "--field=") || strings.HasPrefix(a, "--raw-field=") || strings.HasPrefix(a, "--input=") {
				method = "POST"
				break
			}
		}
	}
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return ClassifiedGitWrite{Write: GitWrite{Form: GitWriteGHAPIWrite}, Detail: clampDetail(c.Raw)}, true
	}
	return ClassifiedGitWrite{}, false
}

// ghGraphQLWriteMutations are the GraphQL mutations (lowercased) that
// record or merge commits.
var ghGraphQLWriteMutations = []string{"createcommitonbranch", "mergebranch", "mergepullrequest"}

// ghGraphQLWrites reports a `gh api graphql` call that writes commits: a
// field naming one of ghGraphQLWriteMutations, or a query the classifier
// cannot see (read from a file with `=@` or `--input`), which is counted
// as a write (the safe direction).
func ghGraphQLWrites(args []string) bool {
	for i, a := range args {
		if a == "--input" || strings.HasPrefix(a, "--input=") {
			return true
		}
		if (a == "-F" || a == "--field") && i+1 < len(args) && strings.Contains(args[i+1], "=@") {
			return true
		}
		if strings.HasPrefix(a, "--field=") && strings.Contains(a, "=@") {
			return true
		}
		l := strings.ToLower(a)
		for _, m := range ghGraphQLWriteMutations {
			if strings.Contains(l, m) {
				return true
			}
		}
	}
	return false
}

// ghValueFlags are the gh options that take the next word as their value.
var ghValueFlags = setOf("-X", "--method", "-f", "--raw-field", "-F", "--field", "-H", "--header",
	"--input", "-q", "--jq", "-t", "--template", "--hostname", "-p", "--preview", "--cache", "-R", "--repo")

// ghPositionals returns gh's operands, skipping options and their values.
func ghPositionals(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		t := args[i]
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			if !strings.Contains(t, "=") && ghValueFlags[t] {
				i++
			}
			continue
		}
		out = append(out, t)
	}
	return out
}

// classifyResidual reports an opaque command that may commit: an
// interpreter one-liner whose program mentions git with a commit verb, or
// a package script with a commit-like name.
func classifyResidual(c *Command) (ClassifiedGitWrite, bool) {
	if flags, ok := interpreterEvalFlags[c.Base]; ok {
		args := c.Args()
		for i, a := range args {
			if !containsString(flags, a) || i+1 >= len(args) {
				continue
			}
			p := strings.ToLower(args[i+1])
			if strings.Contains(p, "git") && containsAny(p, "commit", "push", "merge", "update-ref", "cherry-pick", "rebase") {
				return ClassifiedGitWrite{Write: GitWrite{FlagOnly: true}, Detail: clampDetail(c.Raw)}, true
			}
		}
		return ClassifiedGitWrite{}, false
	}
	if packageScriptRunners[c.Base] {
		pos := c.Positionals()
		name := ""
		switch {
		case len(pos) >= 2 && (pos[0] == "run" || pos[0] == "run-script"):
			name = pos[1]
		case len(pos) >= 1 && c.Base != "npm":
			name = pos[0] // `yarn release`, `pnpm release`
		}
		base, _, _ := strings.Cut(strings.ToLower(name), ":")
		if packageCommitScripts[base] {
			return ClassifiedGitWrite{Write: GitWrite{FlagOnly: true}, Detail: clampDetail(c.Raw)}, true
		}
	}
	return ClassifiedGitWrite{}, false
}

// classifyCommitMCP matches an MCP tool name (with any server prefix:
// mcp__github__push_files, github.push_files, github/push_files) against
// commitMCPTable.
func classifyCommitMCP(target string) (ClassifiedGitWrite, bool) {
	name := strings.ToLower(strings.TrimSpace(target))
	// "server:tool" is Cursor's spelling (internal/adapter/cursor builds
	// the beforeMCPExecution target so; audit SEC-P4 F5).
	if i := strings.LastIndexAny(name, "/.:"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.LastIndex(name, "__"); i >= 0 {
		name = name[i+2:]
	}
	if _, ok := commitMCPTable[name]; ok {
		return ClassifiedGitWrite{Write: GitWrite{Form: GitWriteMCP}, Detail: clampDetail(target)}, true
	}
	return ClassifiedGitWrite{}, false
}

// containsAny reports whether s contains any of subs.
func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// CommitStaging is what a shell line stages for its first commit, read off
// the command line alone (security plan 7.10 "Where it lives"; lane
// SEC-F2B, decision log P-078 ruling 2): the `git add`, `git rm` and `git
// mv` units before the commit on the same line, and the commit's own `-a`
// and pathspecs. The AI change record trailer binds a commit to it, so an
// agent's one-line `git add X && git commit` or `git commit -a` keeps its
// trailer. It is a read-only accessor: no gate rule reads it, and nothing
// here changes what ClassifyGitWritesCtx decides.
type CommitStaging struct {
	// Commit reports a commit (GitWriteCommit) on the line; the fields
	// below describe the first one.
	Commit bool
	// Readable is false when a unit before the commit, or the commit
	// itself, stages in a way the accessor cannot read (a variable, a
	// subshell, a glob, an alias it cannot expand, a directory change, an
	// interactive or file-fed pathspec, another index or repository);
	// Reason names it. A caller binds nothing to an unreadable line.
	Readable bool
	Reason   string
	// Scopes are the staged scopes, in line order.
	Scopes []StagedScope
}

// StagedScope is one scope a line stages: a pathspec as written (relative
// to the command's working directory, or absolute), or the whole working
// tree.
type StagedScope struct {
	// Path is the pathspec as written; "" with WholeTree.
	Path string
	// WholeTree is `git add -A`, `git add -u` or `git commit -a` with no
	// pathspec: every path of the working tree.
	WholeTree bool
	// TrackedOnly is `-u` and `-a`: only paths the index already tracks.
	TrackedOnly bool
}

// The CommitStaging unreadable reasons.
const (
	StagingDirChange    = "dir_change"
	StagingIndexEnv     = "index_env"
	StagingOtherRepo    = "other_repository"
	StagingAlias        = "alias_unreadable"
	StagingOption       = "option_unreadable"
	StagingPathspec     = "pathspec_unreadable"
	StagingNested       = "nested_unreadable"
	StagingReadingsDiff = "readings_differ"
	StagingTooMany      = "too_many_paths"
)

// maxStagedScopes bounds the scopes one line carries; more is unreadable.
const maxStagedScopes = 256

// stagingDirChangeBases change the shell's directory for the rest of the
// line, so a later pathspec is relative to an unknown directory.
var stagingDirChangeBases = setOf("cd", "pushd", "popd", "chdir", "set-location", "push-location", "pop-location")

// stagingIndexEnv are the variables that point git at another index or
// repository.
var stagingIndexEnv = setOf("GIT_INDEX_FILE", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY")

// stagingIndexSubs are the subcommands whose operands the accessor reads.
var stagingIndexSubs = setOf("add", "rm", "mv")

// commandHadSubstitution reports a unit a command substitution was stripped
// out of (its step's argument is unknown, cwdtrack.go).
func commandHadSubstitution(c *Command) bool {
	if c.seq == nil || c.seqPos < 0 || c.seqPos >= len(c.seq.steps) {
		return false
	}
	return c.seq.steps[c.seqPos].argUnknown
}

// stagingAddFlags are the `git add` options the accessor reads; any other
// option makes the line unreadable. The letter is the short spelling.
var stagingAddLong = map[string]byte{
	"--all": 'A', "--no-ignore-removal": 'A', "--update": 'u',
	"--force": 'f', "--verbose": 'v', "--ignore-errors": 0, "--ignore-missing": 0,
}

// stagingRmMvLong are the `git rm` and `git mv` options the accessor reads.
var stagingRmMvLong = setOf("--cached", "--force", "--quiet", "--ignore-unmatch", "--verbose", "-r", "-f", "-q", "-k", "-v", "--sparse")

// stagingCommitUnreadable are the commit options whose staging the
// accessor cannot read.
var stagingCommitUnreadable = setOf("--pathspec-from-file", "--pathspec-file-nul", "-p", "--patch", "--interactive")

// PlannedCommitStaging reads the staging of the first commit of a shell
// event (KindShellExec; any other kind answers Commit=false), with the
// per-directory alias table ClassifyGitWritesCtx reads. A line with a
// second reading (Event.AltDialect) must stage the same under both, or it
// is unreadable.
func PlannedCommitStaging(ctx *MatchContext) CommitStaging {
	if ctx == nil || ctx.Event == nil || ctx.Event.Kind != KindShellExec {
		return CommitStaging{}
	}
	ev := ctx.Event
	var aliases map[string]string
	if ctx.Cfg != nil && ctx.Cfg.GitAliases != nil {
		dir := ev.Cwd
		if dir == "" {
			dir = ev.ProjectRoot
		}
		if table, ok := ctx.Cfg.GitAliases(dir); ok {
			aliases = table
		}
	}
	if len(ev.Args) > 0 {
		return StagingOfCommands(ParseArgv(ev.Args, ev.Dialect), aliases)
	}
	out := StagingOfCommands(ParseCommand(ev.Target, ev.Dialect), aliases)
	if alt := ev.AltDialect; alt != "" && normDialect(alt) != normDialect(ev.Dialect) {
		other := StagingOfCommands(ParseCommand(ev.Target, alt), aliases)
		if !sameStaging(out, other) {
			return CommitStaging{Commit: out.Commit || other.Commit, Reason: StagingReadingsDiff}
		}
	}
	return out
}

// sameStaging reports two readings that stage the same.
func sameStaging(a, b CommitStaging) bool {
	if a.Commit != b.Commit || a.Readable != b.Readable || len(a.Scopes) != len(b.Scopes) {
		return false
	}
	for i := range a.Scopes {
		if a.Scopes[i] != b.Scopes[i] {
			return false
		}
	}
	return true
}

// StagingOfCommands is PlannedCommitStaging over parsed command units.
func StagingOfCommands(cmds []Command, aliases map[string]string) CommitStaging {
	inline := map[string]string{}
	var scopes []StagedScope
	unreadable := ""
	for i := range cmds {
		c := &cmds[i]
		if stagingDirChangeBases[c.Base] {
			unreadable = firstReason(unreadable, StagingDirChange)
			continue
		}
		if c.Unanalyzed != "" {
			unreadable = firstReason(unreadable, StagingNested)
		}
		if c.Base != "git" {
			continue
		}
		for _, kv := range c.Env {
			k, _, _ := strings.Cut(kv, "=")
			if stagingIndexEnv[strings.ToUpper(k)] {
				unreadable = firstReason(unreadable, StagingIndexEnv)
			}
		}
		commit, add, reason := stagingGitUnit(c.Argv, inline, aliases, 0)
		if !commit && stagingIndexSubs[parseGitInvocation(c.Argv).sub] && commandHadSubstitution(c) {
			// A stripped command substitution (`git add $(ls)`) left words
			// the accessor never sees. On the commit itself it is read as
			// written: a message (`-m "$(cat <<EOF ...)"`, the common
			// agent spelling) stages nothing, and a pathspec it hid only
			// narrows the plan, which the trailer's index comparison then
			// refuses (fail safe).
			reason = firstReason(reason, StagingPathspec)
		}
		recordAliasDefinition(c.Argv, inline)
		scopes = append(scopes, add...)
		unreadable = firstReason(unreadable, reason)
		if commit {
			if len(scopes) > maxStagedScopes {
				unreadable = firstReason(unreadable, StagingTooMany)
			}
			if unreadable != "" {
				return CommitStaging{Commit: true, Reason: unreadable}
			}
			return CommitStaging{Commit: true, Readable: true, Scopes: scopes}
		}
	}
	return CommitStaging{}
}

func firstReason(have, next string) string {
	if have != "" {
		return have
	}
	return next
}

// stagingGitUnit reads one git unit: whether it is the commit, the scopes
// it stages, and why it cannot be read ("" when it can).
func stagingGitUnit(argv []string, inline, table map[string]string, depth int) (commit bool, scopes []StagedScope, reason string) {
	inv := parseGitInvocation(argv)
	if inv.sub == "" {
		return false, nil, ""
	}
	for _, e := range inv.config {
		if name, ok := strings.CutPrefix(e.key, "alias."); ok && e.seen {
			inline[strings.ToLower(name)] = e.value
		}
	}
	other := inv.dir != "" || gitDirOption(argv) != "" || gitWorkTreeOption(argv)
	switch inv.sub {
	case "commit":
		for _, a := range inv.args {
			if a == "--dry-run" {
				return false, nil, ""
			}
		}
		w, ok := readCommitRow(commitShellRow{sub: "commit", form: GitWriteCommit}, inv.args)
		if !ok {
			return false, nil, ""
		}
		if other {
			return true, nil, StagingOtherRepo
		}
		for _, a := range inv.args {
			name, _, _ := strings.Cut(a, "=")
			if stagingCommitUnreadable[name] {
				return true, nil, StagingOption
			}
		}
		if w.All {
			scopes = append(scopes, StagedScope{WholeTree: true, TrackedOnly: true})
		}
		for _, p := range w.Pathspecs {
			if !stagingPathReadable(p) {
				return true, nil, StagingPathspec
			}
			scopes = append(scopes, StagedScope{Path: p})
		}
		return true, scopes, ""
	case "add":
		if other {
			return false, nil, StagingOtherRepo
		}
		scopes, reason = stagingAdd(inv.args)
		return false, scopes, reason
	case "rm", "mv":
		if other {
			return false, nil, StagingOtherRepo
		}
		scopes, reason = stagingRmMv(inv.args)
		return false, scopes, reason
	}
	if gitBuiltinSubs[inv.sub] {
		return false, nil, ""
	}
	if depth >= maxGitAliasDepth {
		return false, nil, StagingAlias
	}
	exp, ok := inline[strings.ToLower(inv.sub)]
	if !ok && table != nil {
		exp, ok = table[strings.ToLower(inv.sub)]
	}
	if !ok || strings.HasPrefix(exp, "!") {
		// An unknown subcommand may be an alias the hook cannot see, and a
		// shell alias runs a program the accessor does not read.
		return false, nil, StagingAlias
	}
	next := append([]string{"git"}, splitGitAlias(exp)...)
	return stagingGitUnit(append(next, inv.args...), inline, table, depth+1)
}

// gitWorkTreeOption reports git's `--work-tree` before the subcommand.
func gitWorkTreeOption(argv []string) bool {
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		if !strings.HasPrefix(t, "-") {
			return false
		}
		if t == "--work-tree" || strings.HasPrefix(t, "--work-tree=") {
			return true
		}
		if gitGlobalValueOptions[t] {
			i++
		}
	}
	return false
}

// stagingAdd reads `git add`'s options and pathspecs.
func stagingAdd(args []string) ([]StagedScope, string) {
	all, update := false, false
	var paths []string
	rest := false
	for _, t := range args {
		switch {
		case rest || !strings.HasPrefix(t, "-") || t == "-":
			if !stagingPathReadable(t) {
				return nil, StagingPathspec
			}
			paths = append(paths, t)
		case t == "--":
			rest = true
		case strings.HasPrefix(t, "--"):
			l, ok := stagingAddLong[t]
			if !ok {
				return nil, StagingOption
			}
			all, update = all || l == 'A', update || l == 'u'
		default:
			for j := 1; j < len(t); j++ {
				switch t[j] {
				case 'A':
					all = true
				case 'u':
					update = true
				case 'f', 'v':
				default:
					return nil, StagingOption
				}
			}
		}
	}
	tracked := update && !all
	if len(paths) == 0 {
		if all || update {
			return []StagedScope{{WholeTree: true, TrackedOnly: tracked}}, ""
		}
		return nil, ""
	}
	out := make([]StagedScope, 0, len(paths))
	for _, p := range paths {
		out = append(out, StagedScope{Path: p, TrackedOnly: tracked})
	}
	return out, ""
}

// stagingRmMv reads `git rm` and `git mv`: every operand is staged.
func stagingRmMv(args []string) ([]StagedScope, string) {
	var out []StagedScope
	rest := false
	for _, t := range args {
		switch {
		case rest || !strings.HasPrefix(t, "-") || t == "-":
			if !stagingPathReadable(t) {
				return nil, StagingPathspec
			}
			out = append(out, StagedScope{Path: t})
		case t == "--":
			rest = true
		case !stagingRmMvLong[t]:
			if strings.HasPrefix(t, "--") {
				return nil, StagingOption
			}
			for j := 1; j < len(t); j++ {
				if strings.IndexByte("rfqkv", t[j]) < 0 {
					return nil, StagingOption
				}
			}
		}
	}
	return out, ""
}

// stagingPathReadable reports a pathspec the accessor reads as a plain
// path: no expansion ($, `, %), no glob (*, ?, [), no pathspec magic (a
// leading ':'), no home shortcut and no control character.
func stagingPathReadable(p string) bool {
	if p == "" || p[0] == ':' || p[0] == '~' {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c < 0x20 || c == 0x7f || strings.IndexByte("$`%*?[{", c) >= 0 {
			return false
		}
	}
	return true
}
