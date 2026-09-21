package processobs

import (
	"strings"
	"time"
)

// CorrelationWindow is the default time tolerance between a run_command
// action and the process it spawned: the AI tool logs the command, then the
// shell/binary starts within a few seconds. A process that starts much later
// is not considered part of that command's spawn.
const CorrelationWindow = 30 * time.Second

// correlationBackSkew allows a small negative delta (process start observed
// slightly before the action timestamp) for clock differences between the
// proxy/hook clock and the backend clock.
const correlationBackSkew = 2 * time.Second

// ProcRunRef is the minimal persisted process-run projection the action
// correlator reads. The store loads these; the correlator is pure.
type ProcRunRef struct {
	ProcessKey       string
	ParentProcessKey string
	StartedAt        time.Time
	ArgvPreview      string
	ExeBasename      string
	// Linked is true when the run already carries an action_id — it is left
	// untouched (idempotent: a second pass re-confirms, never re-links).
	Linked bool
}

// ActionRef is a run_command-class action a process subtree may be
// attributed to. Command is the action's target (the command string);
// TurnIndex is nil when the action row has none.
//
// Duration is the command's measured runtime when the source records it
// (codex logs run_command at exec_command_end — the command FINISH — and
// carries a duration). It widens the back-skew in bestAction so a process
// that started up to `Duration` before the action's (end) timestamp still
// links: without it, every command running longer than correlationBackSkew
// fails to link to the message that spawned it. Zero for sources that log
// at command START (the Claude Code PreToolUse hook), which keep the tight
// 2s back-skew.
type ActionRef struct {
	ActionID  int64
	TurnIndex *int
	Command   string
	Timestamp time.Time
	Duration  time.Duration
	// Success is the action's recorded outcome (actions.success). It is
	// consumed by DeriveCommandRuns (derive.go) to set the synthetic run's
	// coarse exit state; the correlator itself ignores it. The actions table
	// has no numeric exit_code column, so a derived run can only distinguish
	// success from failure, not the specific exit code.
	Success bool
}

// ActionLink assigns one process (by key) to the action that spawned it.
type ActionLink struct {
	ProcessKey string
	ActionID   int64
	TurnIndex  *int
}

// CorrelateActions implements the §9.2.4 deferred pass: it links each
// unlinked process to the run_command action that spawned it. A process
// whose leading executable or argv matches an action within `window` becomes
// an ANCHOR; the action then propagates DOWN that process's subtree (via
// parent_process_key) until another anchor is reached — a nested command owns
// its own subtree, so the nearest anchor ancestor always wins.
//
// Pure: the store loads runs+actions and applies the returned links. window
// <= 0 uses CorrelationWindow. Already-Linked runs are never reassigned.
func CorrelateActions(runs []ProcRunRef, actions []ActionRef, window time.Duration) []ActionLink {
	if window <= 0 {
		window = CorrelationWindow
	}

	byKey := make(map[string]*ProcRunRef, len(runs))
	children := make(map[string][]string)
	for i := range runs {
		r := &runs[i]
		byKey[r.ProcessKey] = r
		if r.ParentProcessKey != "" {
			children[r.ParentProcessKey] = append(children[r.ParentProcessKey], r.ProcessKey)
		}
	}

	// Parse-derived per-action fields are computed ONCE here, not once per
	// (process, action) pair: parseInvokedBinaries is a multi-split,
	// map-allocating parse, and the scoring loop below is O(procs × actions) —
	// hundreds of millions of pairs on a large session, re-run every background
	// sweep. Caching collapses the parse to one call per action.
	prepped := prepActions(actions)

	// Anchors: each unlinked run that directly matches an action.
	anchors := make(map[string]ActionRef)
	for i := range runs {
		r := &runs[i]
		if r.Linked {
			continue
		}
		if a, ok := bestAction(r, prepped, window); ok {
			anchors[r.ProcessKey] = a
		}
	}

	links := make([]ActionLink, 0, len(anchors))
	assigned := make(map[string]bool)
	for anchorKey, act := range anchors {
		// DFS the anchor's subtree, assigning the action to unlinked nodes and
		// stopping at any OTHER anchor (that subtree belongs to its own action).
		stack := []string{anchorKey}
		for len(stack) > 0 {
			k := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if assigned[k] {
				continue
			}
			if k != anchorKey {
				if _, isOtherAnchor := anchors[k]; isOtherAnchor {
					continue
				}
			}
			r := byKey[k]
			if r == nil || r.Linked {
				continue
			}
			assigned[k] = true
			links = append(links, ActionLink{ProcessKey: k, ActionID: act.ActionID, TurnIndex: act.TurnIndex})
			stack = append(stack, children[k]...)
		}
	}
	return links
}

// preppedAction caches an action's parse-derived fields (the invoked binaries,
// already normalized for comparison, and the normalized command prefix) so the
// O(procs × actions) scoring loop computes them once per action instead of once
// per (process, action) pair.
type preppedAction struct {
	ref      ActionRef
	normBins []string // normExe of each parseInvokedBinaries(ref.Command) entry
	normCmd  string   // firstN(stripQuotes(lower(ref.Command)), 60); "" when the command is empty
}

// prepActions precomputes the per-action match inputs once.
func prepActions(actions []ActionRef) []preppedAction {
	out := make([]preppedAction, len(actions))
	for i, a := range actions {
		bins := parseInvokedBinaries(a.Command)
		normBins := make([]string, 0, len(bins))
		for _, b := range bins {
			normBins = append(normBins, normExe(b))
		}
		out[i] = preppedAction{
			ref:      a,
			normBins: normBins,
			normCmd:  firstN(stripQuotes(strings.ToLower(a.Command)), 60),
		}
	}
	return out
}

// bestAction picks the action that unambiguously explains a process. It
// gathers every in-window action with a positive match score, keeps only the
// actions at the top score, and:
//   - returns the single top action when there is exactly one (unambiguous);
//   - when several tie at the top score it does NOT time-tie-break (that was a
//     coin-flip that systematically mis-linked repeated identical commands like
//     `go build` run twice in the window). It anchors only if EXACTLY ONE of
//     the tied actions has its normalized command prefix carried in the
//     process's normalized argv (a wrapper whose argv names the one specific
//     command instance); otherwise it returns ok=false and the process stays
//     unlinked, to be reached later by DFS propagation from an unambiguous
//     ancestor anchor.
//
// Returns ok=false when nothing matches inside the window. The process's
// normalized exe basename and normalized argv are computed once here and
// threaded into matchScore.
func bestAction(r *ProcRunRef, actions []preppedAction, window time.Duration) (ActionRef, bool) {
	ne := normExe(r.ExeBasename)
	na := stripQuotes(strings.ToLower(r.ArgvPreview))
	topScore := 0
	var top []preppedAction
	for i := range actions {
		a := &actions[i]
		delta := r.StartedAt.Sub(a.ref.Timestamp)
		// The action timestamp is the command START for hook-logged sources
		// (delta ≈ +small) but the command END for codex (logged at
		// exec_command_end). For the latter the process started ~Duration
		// before the action, so widen the back-skew by the recorded duration;
		// the forward window stays put.
		backSkew := correlationBackSkew + a.ref.Duration
		if delta < -backSkew || delta > window {
			continue
		}
		score := matchScore(ne, na, a)
		if score == 0 {
			continue
		}
		if score > topScore {
			topScore = score
			top = top[:0]
			top = append(top, *a)
		} else if score == topScore {
			top = append(top, *a)
		}
	}
	if topScore == 0 || len(top) == 0 {
		return ActionRef{}, false
	}
	if len(top) == 1 {
		return top[0].ref, true
	}
	// Ambiguous: the process ties at the top score across several in-window
	// actions (e.g. `go build` run more than once, or a standalone command that
	// also appears as a clause inside a compound one). We do NOT guess. An argv
	// substring tie-break systematically mis-picks a compound parent's child for
	// its standalone look-alike — the child's short argv (`go build`) matches the
	// standalone action, not the compound `cd /x && go build` that actually
	// spawned it — and a time tie-break was the original coin-flip defect. Leave
	// the process unlinked; the DFS reaches it from its true parent anchor (the
	// wrapper whose full argv names the one specific command instance), which is
	// the only reliable signal here.
	return ActionRef{}, false
}

// matchScore rates how well a process matches an action's command: 2 when the
// process's executable basename is one of the real binaries actually invoked
// by the command (seeing through wrapper/compound commands like
// `cd /x && go build` or `bash -lc '…'`), 1 when the command string appears in
// the (quote-normalized) argv preview (the `sh -c "<cmd>"` wrapper case), 0
// otherwise. ne is the process's precomputed normalized exe basename (normExe);
// na is its precomputed normalized argv (stripQuotes+lower). Both a.normBins and
// a.normCmd are precomputed, so this is allocation-free in the hot pair loop.
func matchScore(ne, na string, a *preppedAction) int {
	if ne != "" {
		for _, nb := range a.normBins {
			if execMatchesNormalized(ne, nb) {
				return 2
			}
		}
	}
	if na != "" && a.normCmd != "" && strings.Contains(na, a.normCmd) {
		return 1
	}
	return 0
}

// stripQuotes removes single and double quote characters from s. The argv
// preview is de-quoted + full-path-expanded by the capture layer while the
// action command is the raw quoted shell line, so a substring test between the
// two must first normalize away the quote boundaries that would otherwise break
// the match (e.g. `bash -lc 'cd /x && go build'` vs `…bash.exe -c cd /x && go
// build`).
func stripQuotes(s string) string {
	if !strings.ContainsAny(s, "'\"") {
		return s
	}
	return strings.Map(func(rr rune) rune {
		if rr == '\'' || rr == '"' {
			return -1
		}
		return rr
	}, s)
}

// shellWrappers are the interpreter/launcher binaries whose real work is an
// inner command string we recurse into rather than anchoring on the wrapper
// itself. Compared lowercased with any `.exe` suffix trimmed.
var shellWrappers = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true,
	"wsl": true, "cmd": true, "powershell": true, "pwsh": true,
}

// commandBuiltins are shell builtins that spawn no OS process, so they must
// never anchor a captured process. Compared lowercased with any `.exe` suffix
// trimmed.
var commandBuiltins = map[string]bool{
	"cd": true, "echo": true, "export": true, "set": true, "unset": true,
	"source": true, ".": true, ":": true, "pushd": true, "popd": true,
	"true": true, "false": true, "alias": true, "umask": true, "wait": true,
	"read": true,
}

// parseInvokedBinaries returns the distinct set of real leading binaries a
// command actually invokes, seeing through wrapper/compound commands. Real
// commands are wrapper/builtin-led — `cd /mnt/d && go build`,
// `wsl.exe -d Ubuntu -- bash -lc 'cd /x && go build'` — so the naive
// leadingBinary would return `cd`/`wsl.exe` and never the `go` that spawns the
// process. Pure, defensive, and bounded (recursion depth 3, clause count ~32).
func parseInvokedBinaries(cmd string) []string {
	seen := make(map[string]bool)
	var out []string
	collectInvokedBinaries(cmd, 0, seen, &out)
	return out
}

const (
	maxInvokedDepth   = 3
	maxInvokedClauses = 32
)

func collectInvokedBinaries(cmd string, depth int, seen map[string]bool, out *[]string) {
	if depth > maxInvokedDepth || cmd == "" {
		return
	}
	clauses := splitTopLevelClauses(cmd)
	if len(clauses) > maxInvokedClauses {
		clauses = clauses[:maxInvokedClauses]
	}
	for _, clause := range clauses {
		fields := strings.Fields(clause)
		lead, rest := skipCommandPrefix(fields)
		if lead == "" {
			continue
		}
		norm := strings.TrimSuffix(strings.ToLower(lead), ".exe")
		if shellWrappers[norm] {
			if inner := innerWrappedCommand(norm, rest); inner != "" {
				collectInvokedBinaries(inner, depth+1, seen, out)
			}
			continue
		}
		bin := basename(lead)
		bn := strings.TrimSuffix(strings.ToLower(bin), ".exe")
		if commandBuiltins[bn] {
			continue // builtin: no OS process
		}
		if bin != "" && !seen[bin] {
			seen[bin] = true
			*out = append(*out, bin)
		}
	}
}

// splitTopLevelClauses splits a command on the shell separators `&&`, `||`,
// `|`, and `;`. A plain string split is intentional: over-splitting inside a
// quoted string only produces harmless extra candidate clauses, never a wrong
// anchor (each clause is still binary-classified).
func splitTopLevelClauses(cmd string) []string {
	fields := strings.FieldsFunc(cmd, func(r rune) bool { return r == ';' })
	var clauses []string
	for _, f := range fields {
		clauses = append(clauses, splitOnOperators(f)...)
	}
	if len(clauses) == 0 {
		return []string{cmd}
	}
	return clauses
}

// splitOnOperators splits a single `;`-free segment on `&&`, `||`, and `|`.
func splitOnOperators(seg string) []string {
	seg = strings.ReplaceAll(seg, "&&", "\x00")
	seg = strings.ReplaceAll(seg, "||", "\x00")
	seg = strings.ReplaceAll(seg, "|", "\x00")
	parts := strings.Split(seg, "\x00")
	out := parts[:0]
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

// skipCommandPrefix returns the first real executable token and the remaining
// fields, skipping `sudo`/`env` prefixes and leading `VAR=val` assignments
// (the same skip logic as leadingBinary). lead is "" when nothing remains.
func skipCommandPrefix(fields []string) (lead string, rest []string) {
	for i, f := range fields {
		if f == "sudo" || f == "env" {
			continue
		}
		if strings.Contains(f, "=") && !strings.HasPrefix(f, "-") && !strings.ContainsAny(f, "/\\") {
			continue // VAR=val
		}
		return f, fields[i+1:]
	}
	return "", nil
}

// innerWrappedCommand extracts the inner command string a shell wrapper runs.
// For `bash -lc '<inner>'` / `sh -c '<inner>'` it is the argument after a
// `-c`/`-lc` flag; for `wsl … -- <inner>` it is everything after the `--`; for
// `cmd /c <inner>` it is everything after `/c`. Surrounding single/double
// quotes are stripped. "" when no inner command is found.
func innerWrappedCommand(wrapperNorm string, rest []string) string {
	// wsl: everything after a `--` separator.
	if wrapperNorm == "wsl" {
		for i, f := range rest {
			if f == "--" {
				return unquote(strings.Join(rest[i+1:], " "))
			}
		}
	}
	// cmd: everything after a `/c` (or `/k`) switch.
	if wrapperNorm == "cmd" {
		for i, f := range rest {
			lf := strings.ToLower(f)
			if lf == "/c" || lf == "/k" {
				return unquote(strings.Join(rest[i+1:], " "))
			}
		}
	}
	// POSIX shells (and, as a fallback, any wrapper): the argument after a
	// `-c`/`-lc`-style flag (a `-`-led token that ends in `c`).
	for i, f := range rest {
		if len(f) >= 2 && f[0] == '-' && strings.HasSuffix(f, "c") && !strings.ContainsAny(f[1:], "/\\") {
			if i+1 < len(rest) {
				return unquote(strings.Join(rest[i+1:], " "))
			}
		}
	}
	return ""
}

// unquote strips a single pair of surrounding single or double quotes from s
// (after trimming surrounding whitespace), so the inner command recurses clean.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// normExe normalizes an exe basename or command binary for comparison:
// lowercased with any trailing `.exe` removed. Precomputed once per process and
// once per action (preppedAction.normBins) so the hot pair loop compares
// already-normalized strings without re-allocating.
func normExe(s string) string {
	return strings.TrimSuffix(strings.ToLower(s), ".exe")
}

// execMatchesNormalized reports whether two ALREADY-normalized (normExe) names
// name the same executable, tolerating an interpreter VERSION tail (the command
// says `python3`/`node`, the process is `python3.8`/`node18`). Callers pass
// normExe output; it does no allocation of its own.
func execMatchesNormalized(e, c string) bool {
	if e == "" || c == "" {
		return false
	}
	if e == c {
		return true
	}
	// Version-tail tolerance: the longer name must extend the shorter at a
	// version boundary (a digit or dot), so `python3`↔`python3.8` and
	// `node`↔`node18` match but `git`↔`gitk` does not.
	longer, shorter := e, c
	if len(c) > len(e) {
		longer, shorter = c, e
	}
	if strings.HasPrefix(longer, shorter) {
		tail := longer[len(shorter):]
		if tail != "" && (tail[0] == '.' || (tail[0] >= '0' && tail[0] <= '9')) {
			return true
		}
	}
	return false
}

// execMatchesLeadingBinary reports whether a captured process's exe basename is
// the command's leading binary, tolerating the two systematic skews between the
// two sources: the Windows `.exe` suffix (the command says `git`, the captured
// process is `git.exe`) and an interpreter VERSION tail (the command says
// `python3`/`node`, the process is `python3.8`/`node18`). Without this, every
// Windows command and every versioned-interpreter command scores 0 and the
// process never links to the action that spawned it. Case-insensitive.
func execMatchesLeadingBinary(exeBasename, cmdLead string) bool {
	return execMatchesNormalized(normExe(exeBasename), normExe(cmdLead))
}

// leadingBinary returns the basename of the first real executable token in a
// command, skipping leading `VAR=val` env assignments and the common
// `sudo`/`env` prefixes. "" when the command is empty.
func leadingBinary(cmd string) string {
	for _, f := range strings.Fields(cmd) {
		if f == "sudo" || f == "env" {
			continue
		}
		if strings.Contains(f, "=") && !strings.HasPrefix(f, "-") && !strings.ContainsAny(f, "/\\") {
			continue // VAR=val
		}
		return basename(f)
	}
	return ""
}

// firstN returns the first n bytes of s (commands are ASCII-ish; a mid-rune
// cut only weakens a substring match, never corrupts state).
func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
