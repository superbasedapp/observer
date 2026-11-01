package policy

import (
	"path"
	"strings"
)

// gitwritedirs.go places each gating write of a shell line (lane
// SEC-GATE5 milestone 1, decision log P-021 and P-041): the directories
// the git command can run in and the repository it records into. The
// commit gate's posture is the event's project; a write that runs in
// another repository (`cd /other && git commit`, `git -C /other commit`,
// `git --git-dir=/other/.git commit`, `GIT_DIR=/other/.git git commit`,
// `(cd /other && git commit)`) is judged on that repository's own
// posture, and a write the model cannot place is judged unknown, never on
// the event's project alone.
//
// The working directories come from the same frame model the delete and
// sensitive-path rules use (cwdtrack.go, unitAnchors), so a subshell, a
// directory stack and a failed `cd` are read the way those rules read
// them; it over-approximates (every frame a unit can run in counts). Pure:
// no I/O. The caller resolves each directory to its repository.

// GitWriteLocation is one gating write and where it can run.
type GitWriteLocation struct {
	// Write is the classified write (as ClassifyGitWritesCtx gives it).
	Write GitWrite
	// Dirs are the normalized directories (forward slashes, as normPath
	// spells them) the write can run in or record into: the working
	// directory of every frame, moved by `-C`, and any `--git-dir`,
	// `--work-tree`, GIT_DIR or GIT_WORK_TREE the unit names. A git
	// directory is listed as given (".../.git" for a work tree's own).
	Dirs []string
	// Unknown is true when some frame cannot be placed: a directory change
	// the model cannot resolve, an evaluated payload that moves, or a
	// `-C`, git directory or work tree holding an expansion.
	Unknown bool
	// UnknownVia names the step behind Unknown (reason text only).
	UnknownVia string
}

// maxLocatedUnits bounds the units GitWriteLocations walks; a longer line
// reads every write unknown.
const maxLocatedUnits = 64

// GitWriteLocations returns every gating write of an event (commits and
// pushes, never a flag-only form) with the places it can run. An MCP
// event's write runs in the event's own directory. The event's anchor is
// its Cwd, else its ProjectRoot; an event with neither has no anchor and
// its writes are unknown.
//
// A shell line with a second reading (Event.AltDialect: a generic shell
// tool on a Windows working directory, which Codex and Copilot CLI run
// through PowerShell) is placed under both readings, the way the engine
// reads both (buildContext), and the results are combined so the most
// restrictive wins: each write's places are the union of both readings',
// it is unknown when either reading cannot place it, and when the two
// readings find a different number of writes every write is unknown
// (merge finding F1 of lane SEC-GATE5: `Set-Location C:\elsewhere; git
// commit` is a move only the PowerShell reading sees).
func GitWriteLocations(ctx *MatchContext) []GitWriteLocation {
	if ctx == nil || ctx.Event == nil {
		return nil
	}
	ev := ctx.Event
	out := gitWriteLocationsOne(ctx)
	if ev.Kind != KindShellExec || len(ev.Args) > 0 {
		return out
	}
	alt := ev.AltDialect
	if alt == "" || normDialect(alt) == normDialect(ev.Dialect) {
		return out
	}
	aev := *ev
	aev.Dialect, aev.AltDialect = alt, ""
	return mergeGitWriteReadings(out, gitWriteLocationsOne(&MatchContext{Event: &aev, Cfg: ctx.Cfg}))
}

// mergeGitWriteReadings combines the placements of one line under two
// shell readings, most restrictive first (see GitWriteLocations).
func mergeGitWriteReadings(a, b []GitWriteLocation) []GitWriteLocation {
	if len(a) != len(b) {
		out := make([]GitWriteLocation, 0, len(a)+len(b))
		for _, l := range append(append([]GitWriteLocation(nil), a...), b...) {
			if !l.Unknown {
				l.Unknown, l.UnknownVia = true, "the POSIX and PowerShell readings of the line find different writes"
			}
			out = append(out, l)
		}
		return out
	}
	out := make([]GitWriteLocation, len(a))
	for i, bi := range b {
		m := a[i]
		m.Dirs = append([]string(nil), a[i].Dirs...)
		for _, d := range bi.Dirs {
			if !containsString(m.Dirs, d) {
				m.Dirs = append(m.Dirs, d)
			}
		}
		if bi.Unknown && !m.Unknown {
			m.Unknown, m.UnknownVia = true, bi.UnknownVia
		}
		out[i] = m
	}
	return out
}

// gitWriteLocationsOne places the event's writes under its own Dialect.
func gitWriteLocationsOne(ctx *MatchContext) []GitWriteLocation {
	ev := ctx.Event
	base := ev.Cwd
	if base == "" {
		base = ev.ProjectRoot
	}
	if ev.Kind != KindShellExec {
		var out []GitWriteLocation
		for _, c := range ClassifyGitWritesCtx(ctx) {
			if !GitWriteGates(c.Write) {
				continue
			}
			out = append(out, locateMCPWrite(ev, c.Write, base))
		}
		return out
	}
	var aliases map[string]string
	if ctx.Cfg != nil && ctx.Cfg.GitAliases != nil {
		if table, ok := ctx.Cfg.GitAliases(base); ok {
			aliases = table
		}
	}
	var cmds []Command
	if len(ev.Args) > 0 {
		cmds = ParseArgv(ev.Args, ev.Dialect)
	} else {
		cmds = ParseCommand(ev.Target, ev.Dialect)
	}
	all := ClassifyCommitCommands(cmds, aliases)
	if len(cmds) > maxLocatedUnits {
		var out []GitWriteLocation
		for _, c := range all {
			if GitWriteGates(c.Write) {
				out = append(out, GitWriteLocation{Write: c.Write, Unknown: true, UnknownVia: "too many commands on the line"})
			}
		}
		return out
	}
	home := ""
	if ctx.Cfg != nil {
		home = ctx.Cfg.Home
	}
	mctx := &MatchContext{Event: ev, Cfg: &Config{Home: home}}
	line := lineEnv(cmds)
	var out []GitWriteLocation
	// Each unit's writes are the writes the prefix ending at it adds: the
	// classifier is order-preserving and reads inline aliases and the
	// line's state from the units before, so the prefix gives exactly what
	// the whole line gives for that unit.
	seen := 0
	for i := range cmds {
		got := ClassifyCommitCommands(cmds[:i+1], aliases)
		if len(got) <= seen {
			continue
		}
		mine := got[seen:]
		seen = len(got)
		for _, c := range mine {
			if !GitWriteGates(c.Write) {
				continue
			}
			out = append(out, locateGitWrite(mctx, &cmds[i], c.Write, gitLineUnitEnv(line, &cmds[i])))
		}
	}
	if lineDefinesFunction(ev, cmds) {
		// A function body runs wherever the line calls it, after any
		// directory change in between, and the frame model walks it where
		// it is written: every gating write of such a line is unplaced
		// (lane SEC-P4 decision 1, SECP-18).
		for i := range out {
			if !out[i].Unknown {
				out[i].Unknown, out[i].UnknownVia = true, funcDefVia
			}
		}
	}
	return out
}

// locateGitWrite places one write of unit cmd in every frame it can run in.
func locateGitWrite(ctx *MatchContext, cmd *Command, w GitWrite, env map[string]string) GitWriteLocation {
	loc := GitWriteLocation{Write: w}
	home := ctx.Cfg.Home
	moves, gitDir, workTree := gitUnitPlaces(cmd)
	if w.Dir != "" && !containsString(moves, w.Dir) && w.Dir != gitDir {
		// An alias expansion's own `-C` (the unit's argv does not show it).
		moves = append(moves, w.Dir)
	}
	if gitDir == "" {
		gitDir = env["GIT_DIR"]
	}
	if workTree == "" {
		workTree = env["GIT_WORK_TREE"]
	}
	anchor := ""
	if ctx.Event != nil {
		anchor = ctx.Event.Cwd
		if anchor == "" {
			anchor = ctx.Event.ProjectRoot
		}
		anchor = normPath(anchor)
	}
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			loc.Dirs = append(loc.Dirs, p)
		}
	}
	unknown := func(via string) {
		if !loc.Unknown {
			loc.Unknown, loc.UnknownVia = true, via
		}
	}
	// Another index, common directory or work tree than the one the
	// directory implies: the write records somewhere the frames do not
	// show, so it is unknown (merge finding F5).
	if via := gitUnitRedirect(cmd, env); via != "" {
		unknown(via)
	}
	for _, a := range unitAnchors(ctx, cmd) {
		if a.unknown || a.opaque {
			via := a.unknownVia
			if via == "" {
				via = a.opaqueVia
			}
			unknown(via)
			continue
		}
		// An anchorless frame ("") can still be placed by an absolute
		// `-C` or git directory; anything relative to it is unknown.
		dir := normPath(a.cwd)
		ok := true
		for _, m := range moves {
			if next, good := locatePlace(dir, m, home); good {
				if gitPlaceIsNetwork(m, next, anchor) {
					unknown(gitNetworkVia)
					ok = false
					break
				}
				dir = next
				continue
			}
			unknown(cmd.Raw)
			ok = false
			break
		}
		if !ok {
			continue
		}
		// With no git directory named, git finds the repository from the
		// working directory, so it is a place even when a work tree is
		// named too.
		if gitDir == "" {
			if dir == "" {
				unknown("no working directory")
				continue
			}
			add(dir)
		}
		for _, p := range []string{gitDir, workTree} {
			if p == "" {
				continue
			}
			at, good := locatePlace(dir, p, home)
			switch {
			case !good:
				unknown(cmd.Raw)
			case gitPlaceIsNetwork(p, at, anchor):
				unknown(gitNetworkVia)
			case p == gitDir && gitDirIsLinkedWorktree(at):
				// A linked worktree's own git directory: the work tree
				// it records into is named only inside it (merge
				// finding F5).
				unknown("a git directory under .git/worktrees")
			default:
				add(at)
			}
		}
	}
	return loc
}

// gitUnitPlaces reads git's own location options from a unit's argv, before
// the subcommand: every `-C` in order (git applies each against the one
// before), and the last `--git-dir` and `--work-tree`.
func gitUnitPlaces(cmd *Command) (moves []string, gitDir, workTree string) {
	if cmd == nil || cmd.Base != "git" {
		return nil, "", ""
	}
	argv := cmd.Argv
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		if !strings.HasPrefix(t, "-") || t == "-" {
			break
		}
		name, val, hasVal := strings.Cut(t, "=")
		if !hasVal && gitGlobalValueOptions[name] {
			if i+1 >= len(argv) {
				break
			}
			i++
			val = argv[i]
		}
		switch name {
		case "-C":
			moves = append(moves, val)
		case "--git-dir":
			gitDir = val
		case "--work-tree":
			workTree = val
		}
	}
	return moves, gitDir, workTree
}

// gitRedirectEnv are the environment variables that move the index or the
// common git directory away from the one the working directory implies.
var gitRedirectEnv = [...]string{"GIT_INDEX_FILE", "GIT_COMMON_DIR"}

// gitUnitRedirect names how a unit points git at another index, common
// directory or work tree than its directory implies (GIT_INDEX_FILE,
// GIT_COMMON_DIR, `-c core.worktree=`, `--config-env core.worktree=`),
// "" when it does not. Such a write is unknown (merge finding F5).
func gitUnitRedirect(cmd *Command, env map[string]string) string {
	for _, name := range gitRedirectEnv {
		if env[name] != "" {
			return name + " names another place"
		}
	}
	if cmd == nil || cmd.Base != "git" {
		return ""
	}
	argv := cmd.Argv
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		if !strings.HasPrefix(t, "-") || t == "-" {
			break
		}
		name, val, hasVal := strings.Cut(t, "=")
		if !hasVal && gitGlobalValueOptions[name] {
			if i+1 >= len(argv) {
				break
			}
			i++
			val = argv[i]
		}
		if name != "-c" && name != "--config-env" {
			continue
		}
		key, _, _ := strings.Cut(val, "=")
		if strings.EqualFold(strings.TrimSpace(key), "core.worktree") {
			return name + " core.worktree names another work tree"
		}
	}
	return ""
}

// gitDirIsLinkedWorktree reports a git directory inside some repository's
// worktrees directory (".../.git/worktrees/<name>", or a bare
// repository's "<name>.git/worktrees/<name>"): a linked worktree's own git
// directory, whose work tree is named only in its files.
func gitDirIsLinkedWorktree(p string) bool {
	segs := strings.Split(normPath(p), "/")
	for i := 1; i < len(segs)-1; i++ {
		if strings.EqualFold(segs[i], "worktrees") && strings.HasSuffix(strings.ToLower(segs[i-1]), ".git") {
			return true
		}
	}
	return false
}

// gitNetworkVia is the reason text of a write placed on a network path.
const gitNetworkVia = "a network or automount path is never read on the hook path"

// gitNetworkRoots are the directories POSIX systems mount network and
// automount file systems under (autofs's /net and /misc, AFS, macOS's
// /Network). A git location under one would make the hook stat a remote
// file system, outside any time budget.
var gitNetworkRoots = [...]string{"/net", "/misc", "/afs", "/Network"}

// gitPlaceIsNetwork reports a git location value the agent chose that is a
// UNC path (`\\host\share`, `//host/share`, read as given, since
// normPath folds the leading pair) or that resolves under a network or
// automount root, unless it lies inside the event's own anchor (a
// repository that itself lives on a share is the session's own). Such a
// place is never stat-ed on the hook path and reads unknown (merge
// finding F9). Pure: path text only.
func gitPlaceIsNetwork(val, at, anchor string) bool {
	raw := strings.TrimSpace(val)
	network := len(raw) >= 2 && (raw[0] == '/' || raw[0] == '\\') && (raw[1] == '/' || raw[1] == '\\')
	if !network {
		for _, root := range gitNetworkRoots {
			if at == root || strings.HasPrefix(at, root+"/") {
				network = true
				break
			}
		}
	}
	if !network {
		return false
	}
	if anchor != "" && (at == anchor || strings.HasPrefix(at, strings.TrimRight(anchor, "/")+"/")) {
		return false
	}
	return true
}

// IsNetworkPlace is gitPlaceIsNetwork for a caller outside the package: a
// directory value an agent chose (val as written, at the absolute place it
// resolves to, anchor the event's own working directory) that is a UNC
// path or lies under a network or automount root, outside the anchor. The
// hook's cd walk (cmd/observer securityLineDirs) reads such a target
// unknown without a stat, as a `-C` or GIT_DIR here is (SEC-GATE5
// follow-up). A UNC val is its own place, whatever the caller joined it
// to (a non-Windows filepath does not read `\\host\share` as absolute).
// Pure: path text only.
func IsNetworkPlace(val, at, anchor string) bool {
	if raw := strings.TrimSpace(val); len(raw) >= 2 && (raw[0] == '/' || raw[0] == '\\') && (raw[1] == '/' || raw[1] == '\\') {
		at = raw
	}
	return gitPlaceIsNetwork(val, normPath(at), normPath(anchor))
}

// locatePlace resolves a git location value against dir: false when it
// holds an expansion the package cannot perform, or a home spelling with
// no home to expand.
func locatePlace(dir, val, home string) (string, bool) {
	if val == "" {
		return dir, true
	}
	if strings.ContainsAny(val, "$%`") && expandHome(val, home) == val {
		return "", false
	}
	p := expandHome(val, home)
	if strings.HasPrefix(p, "~") || strings.ContainsAny(p, "$%`") {
		return "", false
	}
	if isAbsPath(p) {
		return normPath(p), true
	}
	if dir == "" {
		return "", false
	}
	return normPath(strings.TrimRight(dir, `/\`) + "/" + p), true
}

// GitDirWorkTree maps a git directory spelling to the work tree it belongs
// to when it is a work tree's own `.git` (its parent); any other path is
// returned unchanged (a bare repository, a linked worktree's gitdir, a work
// tree itself). Pure: path text only.
func GitDirWorkTree(p string) string {
	n := normPath(p)
	if path.Base(n) == ".git" {
		return path.Dir(n)
	}
	return p
}

// funcDefVia is the reason text of a write on a line that defines a
// function.
const funcDefVia = "the line defines a function, whose body runs wherever it is called"

// lineDefinesFunction reports a shell line that defines a function: a
// POSIX `name()` or `function name` header (glued to its body or not, in
// the line's text or a nested shell's `-c` payload) or a PowerShell
// `function` or `filter` definition (whose body units the parser marks).
// Over-approximating: a false positive only reads the line's writes
// unknown. Pure: text and parsed units only.
func lineDefinesFunction(ev *Event, cmds []Command) bool {
	for i := range cmds {
		c := &cmds[i]
		if len(c.defIn) > 0 || c.Base == "function" || c.Base == "filter" || posixFuncDefHeader(c.Argv) > 0 {
			return true
		}
		if posixShellBases[c.Base] {
			for _, a := range c.Args() {
				if posixFuncHeaderIn(a) {
					return true
				}
			}
			// A heredoc fed to a shell is that shell's program text.
			if posixFuncHeaderIn(c.Heredoc) {
				return true
			}
		}
	}
	return ev != nil && len(ev.Args) == 0 && normDialect(ev.Dialect) != DialectPowerShell && posixFuncHeaderIn(ev.Target)
}

// posixFuncDefHeader returns how many leading words of argv are a POSIX
// function definition's header (the name with its `()`, the `function`
// keyword, and an opening `{` or `(`), 0 when argv does not open one. The
// words after it are the body's first command.
func posixFuncDefHeader(argv []string) int {
	if len(argv) == 0 {
		return 0
	}
	i := 0
	if argv[0] == "function" {
		if len(argv) < 2 || !posixFuncName(strings.TrimRight(strings.SplitN(argv[1], "(", 2)[0], "{")) {
			return 0
		}
		i = 2
		if i < len(argv) && (argv[i] == "()" || argv[i] == "(){") {
			i++
		}
	} else {
		name, rest, ok := strings.Cut(argv[0], "()")
		if !ok || !posixFuncName(name) || (rest != "" && rest != "{" && rest != "(") {
			return 0
		}
		i = 1
	}
	if i < len(argv) && (argv[i] == "{" || argv[i] == "(") {
		i++
	}
	return i
}

// posixFuncName reports a word that can name a shell function.
func posixFuncName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '_' && r != '-' && r != '.' && r != ':' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// posixFuncHeaderIn reports a `name ()` function header in POSIX shell
// text, outside quotes and outside heredoc bodies: a name, optional blanks,
// `(`, optional blanks and `)`, at the start of a command. It catches the
// spelling the parser reads as a name followed by an empty subshell
// (`f () { git commit; }`). Heredoc bodies are cut through the parser's own
// extractHeredocs first, so a commit message or a file's text naming a call
// (`fix parse() bug`, `main()`) is data, not a header (audit SEC-P4 F1);
// a heredoc fed to a shell is checked as that shell's program text by
// lineDefinesFunction.
func posixFuncHeaderIn(text string) bool {
	text, _ = extractHeredocs(text)
	var quote byte
	for i := 0; i < len(text); i++ {
		ch := text[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			} else if ch == '\\' && quote == '"' {
				i++
			}
			continue
		case ch == '\\':
			i++
			continue
		case ch == '\'' || ch == '"':
			quote = ch
			continue
		case ch != '(':
			continue
		}
		j := i + 1
		for j < len(text) && (text[j] == ' ' || text[j] == '\t') {
			j++
		}
		if j >= len(text) || text[j] != ')' {
			continue
		}
		k := i
		for k > 0 && (text[k-1] == ' ' || text[k-1] == '\t') {
			k--
		}
		end := k
		for k > 0 && posixFuncName(text[k-1:k]) {
			k--
		}
		if end == k {
			continue
		}
		if k == 0 || strings.ContainsRune(" \t\n;&|({", rune(text[k-1])) {
			return true
		}
	}
	return false
}

// MaxMCPToolInput bounds the MCP tool input the placement column decodes
// (Event.Raw of a KindMCPCall event); a longer input is unreadable and
// reads unknown.
const MaxMCPToolInput = 64 << 10

// mcpToolArgs decodes an MCP event's tool input (Event.Raw) through the
// one bounded decoder: an object, or a JSON string holding one. ok is
// false when it is absent, over the cap or not one JSON object.
func mcpToolArgs(ev *Event) (*jsonNode, bool) {
	if ev == nil || len(ev.Raw) == 0 || len(ev.Raw) > MaxMCPToolInput {
		return nil, false
	}
	n, ok := decodeJSONText(string(ev.Raw))
	if ok && n.kind == jsonString {
		n, ok = decodeJSONText(n.str)
	}
	if !ok || n.kind != jsonObject {
		return nil, false
	}
	return n, true
}

// mcpToolPlace is the placement column's row for an MCP event's tool
// name (mcpPlaceEvent when the tool is not in commitMCPTable).
func mcpToolPlace(target string) mcpPlace {
	name := strings.ToLower(strings.TrimSpace(target))
	// "server:tool" is Cursor's spelling (internal/adapter/cursor builds
	// the beforeMCPExecution target so; audit SEC-P4 F5).
	if i := strings.LastIndexAny(name, "/.:"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.LastIndex(name, "__"); i >= 0 {
		name = name[i+2:]
	}
	return commitMCPTable[name]
}

// locateMCPWrite places one MCP write by its row's placement column: the
// reference git server's rows at their repo_path argument (one string,
// absolute or relative to the event's directory; absent, unreadable, a
// network path or an expansion reads unknown), every other row at the
// event's own directory.
func locateMCPWrite(ev *Event, w GitWrite, base string) GitWriteLocation {
	loc := GitWriteLocation{Write: w}
	if mcpToolPlace(ev.Target) == mcpPlaceRepoPath {
		args, ok := mcpToolArgs(ev)
		var vals []*jsonNode
		if ok {
			vals = args.members("repo_path")
		}
		if len(vals) != 1 || vals[0].kind != jsonString || strings.TrimSpace(vals[0].str) == "" {
			loc.Unknown, loc.UnknownVia = true, "the MCP tool's repo_path argument is absent or unreadable"
			return loc
		}
		at, good := locatePlace(normPath(base), vals[0].str, "")
		switch {
		case !good:
			loc.Unknown, loc.UnknownVia = true, "the MCP tool's repo_path argument cannot be resolved"
		case gitPlaceIsNetwork(vals[0].str, at, ""):
			loc.Unknown, loc.UnknownVia = true, gitNetworkVia
		default:
			loc.Dirs = []string{at}
		}
		return loc
	}
	if base == "" {
		loc.Unknown, loc.UnknownVia = true, "no working directory"
	} else {
		loc.Dirs = []string{normPath(base)}
	}
	return loc
}

// MCPCommitContents returns the file contents a content-writing MCP commit
// tool's arguments carry (the placement column's mcpPlaceContent rows:
// push_files' files[].content, create_or_update_file's and create_commit's
// content and files[].content), for the hook's secret detector. applies is
// false for every other event; ok is false when the arguments are absent,
// over MaxMCPToolInput, not one object, or a content value is not a string
// (the caller reads that unknown). Pure.
func MCPCommitContents(ev *Event) (texts []string, applies, ok bool) {
	if ev == nil || ev.Kind != KindMCPCall || mcpToolPlace(ev.Target) != mcpPlaceContent {
		return nil, false, false
	}
	if _, isCommit := classifyCommitMCP(ev.Target); !isCommit {
		return nil, false, false
	}
	args, good := mcpToolArgs(ev)
	if !good {
		return nil, true, false
	}
	ok = true
	take := func(v *jsonNode) {
		switch v.kind {
		case jsonString:
			texts = append(texts, v.str)
		case jsonNull:
		default:
			ok = false
		}
	}
	for _, v := range args.members("content") {
		take(v)
	}
	for _, files := range args.members("files") {
		if files.kind != jsonArray {
			ok = false
			continue
		}
		for _, f := range files.arr {
			if f.kind != jsonObject {
				ok = false
				continue
			}
			for _, v := range f.members("content") {
				take(v)
			}
		}
	}
	return texts, true, ok
}
