package policy

import (
	"strconv"
	"strings"
)

// maxUnwrapDepth bounds recursive unwrapping of nested shell payloads
// (`bash -c "bash -c ..."`), command substitutions and dialect
// switches (spec §4.3: ≤5 levels). A payload at the limit is NOT
// analysed, and that fact is recorded on Command.Unanalyzed so R-157
// fails CLOSED on it — see the Unanalyzed field comment for why the
// old "recorded on Payload rather than dropped" wording was a
// fail-OPEN dressed up as preservation.
const maxUnwrapDepth = 5

// maxExpansionUnits bounds how many times one top-level parse may
// EXPAND a wrapper — a `-c` payload unwrapped, a launcher candidate
// re-parsed. It is NOT a cap on the total number of Commands a parse
// can produce, and the name and comment say so because the previous
// pair claimed exactly that and an independent review measured the
// claim false (docs/security.md H5 round 4): `sh -c "true; true"`
// yields two units for one charge, and top-level units and command
// substitutions are not charged at all.
//
// WHAT IT ACTUALLY BOUNDS, AND WHY THAT IS THE PART THAT MATTERS.
// Unwrapping is MULTIPLICATIVE, not linear: a launcher unit resolves
// to several candidate readings (launcher.go deliberately emits every
// reading rather than guessing), and each of those may itself be a
// launcher. Depth alone bounds the tree's HEIGHT, so the leaf count is
// fan-out^depth — a crafted line can turn a few kilobytes into
// millions of units, and the guard hook's watchdog fails OPEN on
// timeout. Charging per expansion SITE bounds that product, and
// exhausting the budget is recorded on Unanalyzed (fail CLOSED), never
// silently dropped.
//
// The uncharged paths are uncharged because they are already bounded
// by the INPUT LENGTH rather than multiplied by it: a line of N bytes
// holds at most N separator-split units, at most N substitutions, and
// a payload of M bytes at most M units. None of them compounds with
// depth, and a substitution has no wrapper unit to record an
// Unanalyzed reason on.
const maxExpansionUnits = 4096

// maxLauncherCandidates bounds how many candidate readings ONE
// launcher unit may expand into. The shipped resolvers emit at most
// eighteen: the cross-product of the FOUR Start-Process binding
// ambiguities (2^4, and only over the ones a given argv actually
// contains) plus the two cmd-START operand positions — see
// launcher.go's psBindModes. Truncating drops a reading, which is
// exactly the defect docs/security.md H5 round 2 records, so a
// truncated unit is marked Unanalyzed and R-157 denies rather than
// analysing part of a line and calling it clean.
const maxLauncherCandidates = 18

// Unanalyzed reasons. Each names the specific fail-CLOSED path so the
// R-157 verdict tells the operator which limit was hit.
const (
	unanalyzedNestingLimit    = "nesting exceeded the analysis limit"
	unanalyzedLauncherTarget  = "launcher target not statically recoverable"
	unanalyzedLauncherFanOut  = "launcher readings exceeded the fan-out bound"
	unanalyzedExpansionBudget = "nested expansion exceeded the unit budget"
)

// parseState carries the per-parse recursion state: the unwrap depth
// and the expansion budget SHARED by the whole tree.
type parseState struct {
	depth  int
	budget *int
	// cur and curPos name the unit sequence (cwdtrack.go) and the step
	// position the unit being processed occupies, so a Command can later
	// ask which working directories it may run in. A nested payload's
	// sequence starts from its wrapper's position; curPos -1 means
	// "anywhere in cur" (a command substitution). nil outside parseDepth
	// (ParseArgv): such a unit keeps the event's own working directory.
	cur    *unitSeq
	curPos int
	// psTicks marks the PowerShell tick reading of one line (parseDepth):
	// backticks are escapes there, never substitution spans. deeper() does
	// not carry it: a nested payload is a new line with its own readings.
	psTicks bool
}

// newParseState starts a fresh top-level parse.
func newParseState() parseState {
	b := maxExpansionUnits
	return parseState{budget: &b}
}

// deeper returns the state one unwrap level down, sharing the budget.
func (s parseState) deeper() parseState {
	return parseState{depth: s.depth + 1, budget: s.budget, cur: s.cur, curPos: s.curPos}
}

// afford charges n nested units against the shared budget, reporting
// whether they fit. A false result is a fail-CLOSED signal: the
// caller records unanalyzedExpansionBudget rather than expanding
// fewer units and reporting nothing.
func (s parseState) afford(n int) bool {
	if s.budget == nil {
		return true // a zero-value state (tests) is unbounded
	}
	if *s.budget < n {
		return false
	}
	*s.budget -= n
	return true
}

// Command is one parsed command unit — the shape every rule matcher
// consumes, identical across dialects so rules express facts
// ("recursive delete") rather than syntax. A single Event commonly
// yields several Commands: separator-split units, pipeline segments,
// recursively unwrapped `-c` payloads and command substitutions all
// flatten into one list.
type Command struct {
	// Base is the canonical command name: directory prefix stripped
	// (both separator flavors), lowercased, known executable
	// extensions (.exe/.com/.bat/.cmd) stripped, and — in the
	// PowerShell dialect — aliases resolved to canonical cmdlet
	// names ("rm" → "remove-item"). Lowercasing is deliberately
	// conservative: a case-sensitive-FS binary named "RM" matches
	// the rm rules, which errs toward flagging.
	Base string
	// Argv is the unit's argument vector after wrapper stripping;
	// Argv[0] is the original (pre-canonicalization) command word.
	//
	// INVARIANT: non-empty for every unit this package emits.
	// processUnit gets this for free (it returns early on no words);
	// every other construction site must too, which is why
	// markSubstitutionLimit's synthetic unit carries a placeholder
	// word. Pinned by TestParsedCommandsAlwaysHaveArgv, and read
	// through Args() so that a future construction site breaking the
	// invariant costs a missed match rather than a panicking guard —
	// seven matchers used to slice Argv[1:] raw, and the synthetic
	// unit reached them.
	Argv []string
	// Raw is the unit's text, reconstructed by joining its words —
	// original quoting is not preserved (lexer strips it).
	Raw string
	// ArgvLiterals runs parallel to Argv: for each word, the byte
	// offsets of the '$', '%' and '`' characters the lexer read from a
	// single-quoted or escaped region, i.e. literal text the shell
	// does not expand (`rm -rf '$x'` names a directory called $x).
	// The quoting itself is gone from Argv; this is the part of it the
	// destructive rules need (Sol A2-04). nil, or a length that differs
	// from Argv (ParseArgv, a synthetic unit), means unknown: every such
	// character is then treated as a possible expansion.
	ArgvLiterals [][]int
	// Dialect the unit was parsed under (payload units inherit the
	// dialect of their wrapper, e.g. `powershell -Command` payloads
	// are DialectPowerShell).
	Dialect Dialect
	// Depth is the unwrap depth the unit was found at (0 = the
	// event's own command line).
	Depth int
	// Sudo records that a sudo/doas wrapper was stripped — the
	// privilege escalation fact survives even though matching runs
	// against the inner command.
	Sudo bool
	// Wrappers lists every stripped wrapper in order ("sudo",
	// "xargs", ...) so rules can match chain shapes (R-103's
	// `xargs rm`).
	Wrappers []string
	// Pipeline is true when the unit is a segment of a multi-stage
	// pipeline (`a | b`).
	Pipeline bool
	// RedirectTargets are the output-redirection targets (`> file`,
	// `>> file`) — write-classified path candidates for the
	// boundary rules. Input redirections are consumed and dropped
	// (no current rule needs them).
	RedirectTargets []string
	// Heredoc is the concatenated heredoc body attached to the unit
	// (`psql <<EOF ... EOF`), scanned by R-120.
	Heredoc string
	// Env lists the NAME=value environment assignments that apply to
	// this unit's command: POSIX prefix assignments (`HUSKY=0 git
	// commit`) and the assignment operands of a stripped wrapper (`env
	// SKIP=x git commit`). Values are as the lexer left them: quotes
	// removed, expansions not expanded. nil when there are none. The
	// git hook-bypass rules read it (R-112, R-113).
	Env []string
	// Payload is a nested code payload that was NOT unwrapped into
	// further Commands: interpreter one-liners (`python -c '...'`,
	// always opaque) and shell payloads at maxUnwrapDepth.
	//
	// HONEST STATUS (corrected 2026-07-27, docs/security.md H5 round
	// 2). NO built-in rule, matcher or compiled user rule reads this
	// field today — gap F1's "rules scan it with regexes" is not
	// implemented, and the previous comment claiming it was made the
	// depth limit look like preservation when it was a silent
	// fail-OPEN (`wsl -- ` ×6 ALLOWED while ×5 denied). The field is
	// kept because it carries the un-analysed text into the verdict
	// record; ENFORCEMENT is Unanalyzed's job, not Payload's.
	Payload string
	// PayloadKind labels Payload: "python" | "node" | "perl" |
	// "ruby" | "shell" | "powershell" | "cmd".
	PayloadKind string
	// Unanalyzed names the reason a nested command this unit WRAPS
	// was not analysed — "" when everything nested was. It is the
	// fail-CLOSED signal R-157 enforces, and it exists because every
	// limit in this parser used to fail OPEN: exceeding
	// maxUnwrapDepth, a launcher that named a target no reading
	// could recover, a truncated candidate set and an exhausted
	// expansion budget all ended with "return nil" and nothing
	// recorded, so the wrapper analysed as an ordinary command that
	// matched no rule.
	//
	// It is deliberately NOT a bool: the reason is carried into the
	// verdict so an operator can tell a depth limit from an
	// unparsable wrapper.
	Unanalyzed string

	// seq and seqPos place the unit in its command line's step sequence
	// (cwdtrack.go): the directory changes and link creations that run
	// before it decide where its relative operands point (pass-2 review
	// M2-01: `cd ~ && rm -rf ./*`). nil for a unit built outside
	// parseDepth, which keeps the event's own working directory.
	seq    *unitSeq
	seqPos int
	// chdir lists the directories stripped wrappers run this unit in
	// (`env -C DIR`, `sudo -D DIR`), outermost first; nil when none.
	chdir []operand
	// scriptBlock records that a PowerShell script-block argument of this
	// unit was parsed into nested units (psblock.go). A block runs in the
	// caller's runspace, so cwdtrack.go treats such a unit like an
	// evaluator.
	scriptBlock bool
	// argvQuotedBraces runs parallel to Argv like ArgvLiterals: the
	// offsets of the braces the lexer read from a quoted or escaped
	// region (ptoken.qbr). psblock.go reads it so a brace inside a string
	// literal never opens or closes a script block (T-525, D-338). nil, or
	// a length that differs from Argv, means none are known to be quoted.
	argvQuotedBraces [][]int
	// inScriptBlock records that the unit was parsed directly from the
	// body of a PowerShell script block (psblock.go), where `$_` is the
	// pipeline item the block is handed rather than a variable of the
	// line (R-101's pipeline-item row).
	inScriptBlock bool
	// defIn names every PowerShell function this unit sits in the body of
	// (innermost first, canonical names); nil outside any definition.
	defIn []string
	// uncalledDef is the function whose definition this unit sits in and
	// which nothing in the command line calls, so the unit only runs if a
	// later command calls it: every verdict a rule draws from the unit is
	// capped at ASK (engine.go, D-338). "" when the unit can run.
	uncalledDef string
	// altReading marks a unit from the event's second reading
	// (Event.AltDialect). A unit rule's reason comes from that reading
	// first (engine.go applyRuleCeiling); whether the rule hits never
	// depends on it.
	altReading bool
}

// Args returns the unit's argument tokens — everything after the
// command word — and nil for a unit that has none.
//
// It exists so no matcher writes `cmd.Argv[1:]`, which panics on a
// zero-length Argv. Command.Argv's invariant says that cannot happen
// and a test pins it, but an invariant plus seven unguarded slice
// expressions is one construction-site mistake away from a panicking
// guard, and a panicking guard is a worse failure than any verdict.
func (c *Command) Args() []string {
	if len(c.Argv) <= 1 {
		return nil
	}
	return c.Argv[1:]
}

// HasLongFlag reports whether any argv token equals one of the given
// long flags exactly or carries it with an embedded value
// ("--signal=KILL"). Matching is exact per name — "--force" does NOT
// match "--force-with-lease".
func (c *Command) HasLongFlag(names ...string) bool {
	for _, t := range c.flagTokens() {
		for _, n := range names {
			if t == n || strings.HasPrefix(t, n+"=") {
				return true
			}
		}
	}
	return false
}

// HasShortFlag reports whether any single-dash cluster token contains
// one of the given flag letters (`-rf` has 'r' and 'f'). Letters are
// case-sensitive (`chmod -R` vs `rm -r` differ).
func (c *Command) HasShortFlag(letters ...byte) bool {
	for _, t := range c.flagTokens() {
		if len(t) < 2 || t[0] != '-' || t[1] == '-' {
			continue
		}
		for _, l := range letters {
			if strings.IndexByte(t[1:], l) >= 0 {
				return true
			}
		}
	}
	return false
}

// flagTokens returns the argv tokens in flag position: everything
// after Argv[0] up to a literal "--" terminator.
func (c *Command) flagTokens() []string {
	for i := 1; i < len(c.Argv); i++ {
		if c.Argv[i] == "--" {
			return c.Argv[1:i]
		}
	}
	if len(c.Argv) <= 1 {
		return nil
	}
	return c.Argv[1:]
}

// valueFlags lists, per canonical base, the flags known to consume a
// following value, so Positionals doesn't mistake the value for an
// operand ("git -C /x push" — /x is -C's value, not a subcommand).
// The table is best-effort: an unlisted value-flag makes its value
// appear as a positional, which errs toward analyzing MORE (a
// documented approximation, pinned by tests).
var valueFlags = map[string]map[string]bool{
	"git":     setOf("-C", "-c", "--work-tree", "--git-dir", "--namespace"),
	"aws":     setOf("--profile", "--region", "--output", "--endpoint-url"),
	"kubectl": setOf("-n", "--namespace", "--context", "--kubeconfig", "-l", "--selector", "-f", "--filename", "-o"),
	"helm":    setOf("-n", "--namespace", "--kube-context", "-f", "--values"),
	"psql":    setOf("-h", "-p", "-U", "-d", "--host", "--port", "--username", "--dbname"),
	"mysql":   setOf("-h", "-P", "-u", "-D", "--host", "--port", "--user", "--database"),
	"mariadb": setOf("-h", "-P", "-u", "-D", "--host", "--port", "--user", "--database"),
	"find":    setOf("-name", "-iname", "-path", "-ipath", "-type", "-maxdepth", "-mindepth", "-newer", "-mtime", "-mmin", "-size", "-perm", "-user", "-group"),
	"chown":   setOf("--reference", "--from"),
}

// setOf builds a string set from its arguments.
func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

// Positionals returns the unit's non-flag operands (subcommands,
// targets), honoring "--" termination, dialect flag prefixes ("-" and
// additionally "/" for cmd) and the per-base valueFlags table. In the
// PowerShell dialect parameter VALUES are intentionally kept ("-Path
// C:\x" — the value IS the target of interest).
func (c *Command) Positionals() []string {
	idx := c.positionalIndexes()
	if idx == nil {
		return nil
	}
	out := make([]string, len(idx))
	for k, i := range idx {
		out[k] = c.Argv[i]
	}
	return out
}

// positionalIndexes is Positionals as Argv indexes.
func (c *Command) positionalIndexes() []int {
	vf := valueFlags[c.Base]
	var out []int
	rest := false
	for i := 1; i < len(c.Argv); i++ {
		t := c.Argv[i]
		if rest {
			out = append(out, i)
			continue
		}
		if t == "--" {
			rest = true
			continue
		}
		if c.isFlagToken(t) {
			// An "=" form ("--name=value") embeds its value; only
			// the separate form consumes the next token.
			if !strings.ContainsRune(t, '=') && vf[t] && i+1 < len(c.Argv) {
				i++ // skip the flag's value
			}
			continue
		}
		out = append(out, i)
	}
	return out
}

// operand is one positional word with its literal-character offsets
// (Command.ArgvLiterals; nil when unknown).
type operand struct {
	text string
	lit  []int
	// item marks the bare pipeline variable of a script block (`$_`,
	// `$PSItem`) as an operand of a unit inside that block (psblock.go).
	item bool
}

// positionalOperands is Positionals with each word's literal offsets.
func (c *Command) positionalOperands() []operand {
	idx := c.positionalIndexes()
	known := len(c.ArgvLiterals) == len(c.Argv)
	out := make([]operand, 0, len(idx))
	for _, i := range idx {
		op := operand{text: c.Argv[i]}
		if known {
			op.lit = c.ArgvLiterals[i]
		}
		op.item = c.inScriptBlock && isPipelineItem(op.text, op.lit)
		out = append(out, op)
	}
	return out
}

// isFlagToken reports whether t is flag-shaped in the unit's dialect.
func (c *Command) isFlagToken(t string) bool {
	if len(t) < 2 {
		return false
	}
	if t[0] == '-' {
		return true
	}
	return c.Dialect == DialectCmd && t[0] == '/'
}

// Sub returns the unit's first positional operand — the subcommand
// for multi-command CLIs ("push" in `git push -f origin main`).
func (c *Command) Sub() string {
	p := c.Positionals()
	if len(p) == 0 {
		return ""
	}
	return p[0]
}

// FlagValue returns the value of the first matching flag, supporting
// both the separate form ("-c VALUE") and the embedded form
// ("--command=VALUE").
func (c *Command) FlagValue(names ...string) (string, bool) {
	for i := 1; i < len(c.Argv); i++ {
		t := c.Argv[i]
		for _, n := range names {
			if t == n && i+1 < len(c.Argv) {
				return c.Argv[i+1], true
			}
			if strings.HasPrefix(t, n+"=") {
				return t[len(n)+1:], true
			}
		}
	}
	return "", false
}

// ParseCommand parses a raw command line in the given dialect into
// the flattened, recursively-unwrapped command-unit list. An empty
// dialect means DialectPosix. Parsing is pure analysis: nothing is
// expanded against an environment or executed.
func ParseCommand(raw string, dialect Dialect) []Command {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return settleDefinitions(parseDepth(raw, dialect, newParseState()))
}

// ParseArgv parses a pre-split argument vector (boundaries that
// receive argv rather than a command string) through the same
// wrapper-strip / unwrap pipeline as ParseCommand. Command
// substitutions embedded in argv words are stripped and parsed as
// additional units, mirroring parseDepth.
func ParseArgv(argv []string, dialect Dialect) []Command {
	if len(argv) == 0 {
		return nil
	}
	var subs []string
	words := make([]string, 0, len(argv))
	for _, w := range argv {
		// Every dialect, for the reason parseDepth documents: a
		// cmd-tagged line routinely carries a command for another
		// shell, and skipping the strip there lost the substitution
		// entirely.
		cw, s := stripSubstitutions(w)
		subs = append(subs, s...)
		w = cw
		if strings.TrimSpace(w) != "" || len(words) > 0 {
			words = append(words, w)
		}
	}
	var out []Command
	st := newParseState()
	processUnit(unit{words: words}, dialect, st, &out)
	for _, sub := range subs {
		out = append(out, parseDepth(sub, dialect, st.deeper())...)
	}
	return settleDefinitions(out)
}

// unit is one separator-delimited command segment as produced by the
// lexers, before wrapper stripping and unwrapping.
type unit struct {
	words []string
	// lits and qbr run parallel to words (ptoken.lit, ptoken.qbr).
	lits      [][]int
	qbr       [][]int
	redirects []string
	heredoc   string
	pipeline  bool
	// sep is the list operator in front of the unit (`;` or start of
	// line, `&&`, `||`, `|`); opens and closes count the subshell
	// parentheses between the previous unit and this one. cwdtrack.go
	// reads them to decide which earlier directory changes this unit
	// can see.
	sep           seqSep
	opens, closes int
	// hadSub records that a command substitution was stripped out of
	// this unit's text (stripSubstitutions leaves subMarker in its
	// place), so a directory change or link it named cannot be resolved.
	hadSub bool
}

// parseDepth lexes raw under the dialect's rules and processes each
// unit, recursing (bounded by maxUnwrapDepth) through nested
// payloads. Command substitutions ("$(...)", backticks) are stripped
// from the line BEFORE lexing — a substitution can span word
// boundaries, so per-word handling would corrupt unit splitting —
// and their contents parse as additional units. The substituted-away
// value is unknowable statically, so a target like `rm -rf $(pwd)`
// analyzes as a target-less rm plus a separate pwd unit (documented
// approximation).
//
// SUBSTITUTIONS ARE STRIPPED IN EVERY DIALECT, AND THE DEPTH LIMIT
// FAILS CLOSED ON THEM. Both halves of that sentence are round-4 fixes
// (docs/security.md H5 round 4) to the same fail-OPEN family, found
// from one measured line:
//
//	cmd /c cmd /c cmd /c cmd /c sh -c echo$(crontab)
//
// which ALLOWED under the CMD dialect while denying under posix and
// powershell. Understanding the dialect split is what found the rest:
//
//   - posix and powershell strip at depth 0, so the nested `crontab`
//     is lifted out of the WHOLE line before any unwrapping.
//   - cmd.exe has no `$( )` of its own, so the old code never stripped
//     under that dialect AT ALL. But a cmd-tagged line routinely
//     carries a command for another shell — that is why cmdWrappers
//     and the dialect-agnostic launcher rows exist — and the payload
//     re-join (`strings.Join(argv[i+1:], " ")`) does not preserve
//     quoting, so a substitution containing a SPACE was torn into
//     `$(crontab` + `-e` and lost at ANY depth: `cmd /c sh -c
//     "$(crontab -e)"` ALLOWED under cmd while denying under the other
//     two (measured 2026-07-27 while fixing the line above).
//     Stripping in every dialect closes that whole class. The cost is
//     over-analysis of a LITERAL `$(…)` in a genuine cmd line, which
//     is the direction this package errs in everywhere else
//     (unconditional lowercasing, launchers matched under every
//     dialect).
//   - AT maxUnwrapDepth the substitution's contents are not parsed —
//     but they are still stripped, and the line they came out of is
//     marked Unanalyzed so R-157 denies. Suppressing the strip instead
//     (the old `st.depth < maxUnwrapDepth` guard) left `echo$(crontab)`
//     as one literal word with Base `echo$(crontab)`, matching nothing.
//     This is unwrapPayload's fail-OPEN one layer out, closed the same
//     way.
//
// The dialects can still differ in WHICH rule fires (R-155 where the
// substitution is seen below the cap, R-157 where it is only reached at
// it); the DECISION no longer does.
//
// TWO POWERSHELL ESCAPE FACTS, AND ONLY TWO (T-534). The strip above
// stays dialect-agnostic on purpose (a backtick span is still a
// substitution under PowerShell, so the line cmd /c ... sh -c
// echo`crontab -e` keeps its fail-closed DENY even though PowerShell would read those
// backticks as escapes), with two PowerShell-only readings that can only
// ADD analysis or remove a brace's code reading (stripSubstitutionsFor,
// psEscape): an escaped brace ("`{", "`}") is a literal brace, copied
// through so the lexer marks it quoted and never opens a block on it
// (`Write-Output `{ rm -r ~ `}` is text, like its quoted twin); and a
// backslash does not escape a dollar, so `"C:\x\$(crontab -e)"` has its
// subexpression stripped and analysed as PowerShell runs it.
func parseDepth(raw string, dialect Dialect, st parseState) []Command {
	orig := raw
	ps := dialect == DialectPowerShell
	raw, subs, tickSpan := stripSubstitutionsOpts(raw, stripOpts{mark: true, psEscape: ps, psTicks: ps && st.psTicks})
	atLimit := st.depth >= maxUnwrapDepth && len(subs) > 0
	if atLimit {
		subs = nil
	}
	var units []unit
	switch dialect {
	case DialectPowerShell:
		units = buildUnits(lexLine(blankPSDefinitionParams(raw), psLexSpec), nil)
	case DialectCmd:
		units = buildUnits(lexLine(raw, cmdLexSpec), nil)
	default:
		clean, bodies := extractHeredocs(raw)
		units = buildUnits(lexLine(clean, posixLexSpec), bodies)
	}
	seq := &unitSeq{parent: st.cur, parentPos: st.curPos, dialect: dialect}
	var out []Command
	for _, u := range units {
		ust := st
		ust.cur, ust.curPos = seq, len(seq.steps)
		before := len(out)
		processUnit(u, dialect, ust, &out)
		seq.add(u, out[before:])
	}
	if atLimit {
		markSubstitutionLimit(orig, dialect, st, &out)
	}
	// A substitution runs in a subshell at an unknown point of this
	// line, so it may see any working directory the line passes through.
	sst := st.deeper()
	sst.cur, sst.curPos = seq, -1
	for _, sub := range subs {
		out = append(out, parseDepth(sub, dialect, sst)...)
	}
	if ps && tickSpan && !st.psTicks {
		out = appendPSTickReading(orig, st, out)
	}
	return out
}

// appendPSTickReading adds the PowerShell tick reading of a PowerShell line
// whose backticks the substitution pass took as POSIX spans: the line as
// PowerShell itself reads it, every backtick an escape (PSRULES lane).
//
// Both readings are kept. The span reading is the conservative one T-534
// pinned (a PowerShell-tagged line can carry a POSIX payload, so sh -c
// with a backtick span around crontab -e keeps its deny); the tick reading
// is what PowerShell
// runs, and without it two backticks on one line hid everything between
// them: `git commit `<nl>--no-verify `<nl>-m x` (line continuations) and
// `git commit --no`-verify -m "a`tb"` both lost their --no-verify into a
// "substitution". The reading is charged against the expansion budget like
// any other; an exhausted budget marks the line Unanalyzed (fail CLOSED).
func appendPSTickReading(raw string, st parseState, out []Command) []Command {
	if !st.afford(1) {
		marked := false
		for i := range out {
			if out[i].Depth == st.depth && out[i].Unanalyzed == "" {
				out[i].Unanalyzed = unanalyzedExpansionBudget
				marked = true
			}
		}
		if !marked {
			text := strings.TrimSpace(raw)
			out = append(out, Command{Argv: []string{text}, Raw: text, Dialect: DialectPowerShell, Depth: st.depth, Unanalyzed: unanalyzedExpansionBudget})
		}
		return out
	}
	alt := st
	alt.psTicks = true
	return append(out, parseDepth(raw, DialectPowerShell, alt)...)
}

// markSubstitutionLimit records that a command substitution on this
// line was stripped but never analysed, so R-157 denies.
//
// The reason goes on the units the line produced — they are the
// commands the substitution's value would have flowed into. A line
// that is NOTHING but a substitution (`$(crontab -e)`) produces no
// unit at all, so a synthetic one carries the reason instead; without
// it the fail-closed signal would have nowhere to live and the drop
// would be silent again.
//
// The synthetic unit gets a ONE-WORD Argv, never an empty one:
// Command.Argv is non-empty for every unit this parser emits, and the
// first version of this path broke that invariant — seven matchers
// sliced Argv[1:] raw and the whole evaluation PANICKED (measured
// while adding this path; the raw slices are Args() now). Base stays
// empty on purpose: the text is not a command word and must not
// canonicalize into one.
func markSubstitutionLimit(raw string, dialect Dialect, st parseState, out *[]Command) {
	if len(*out) == 0 {
		text := strings.TrimSpace(raw)
		if text == "" {
			text = "$()"
		}
		*out = append(*out, Command{
			Argv:       []string{text},
			Raw:        text,
			Dialect:    dialect,
			Depth:      st.depth,
			Unanalyzed: unanalyzedNestingLimit,
		})
		return
	}
	for i := range *out {
		if (*out)[i].Depth == st.depth && (*out)[i].Unanalyzed == "" {
			(*out)[i].Unanalyzed = unanalyzedNestingLimit
		}
	}
}

// processUnit turns one lexed unit into a Command (plus any nested
// Commands its payloads unwrap into) and appends them to out.
func processUnit(u unit, dialect Dialect, st parseState, out *[]Command) {
	words := stripLeadingKeywords(u.words, dialect)
	if len(words) == 0 {
		return
	}
	chdir := wrapperChdir(words, dialect)
	stripped, wrappers, sudo := stripWrappers(words, dialect)
	if len(stripped) == 0 {
		// A bare wrapper ("sudo" with nothing after it) — keep the
		// original words so the unit is still visible.
		stripped, wrappers, sudo = words, nil, false
	}
	raw := strings.Join(u.words, " ")
	// stripAssignments and stripWrappers only drop leading words, so the
	// argv is a suffix of the unit's words and its literal offsets are
	// the same suffix of u.lits.
	var argvLits, argvQB [][]int
	if len(u.lits) == len(u.words) && len(stripped) <= len(u.lits) {
		argvLits = u.lits[len(u.lits)-len(stripped):]
	}
	if len(u.qbr) == len(u.words) && len(stripped) <= len(u.qbr) {
		argvQB = u.qbr[len(u.qbr)-len(stripped):]
	}
	cmd := Command{
		Base:             canonicalBase(stripped[0], dialect),
		Argv:             stripped,
		ArgvLiterals:     argvLits,
		argvQuotedBraces: argvQB,
		Raw:              raw,
		Dialect:          dialect,
		Depth:            st.depth,
		Sudo:             sudo,
		Wrappers:         wrappers,
		Pipeline:         u.pipeline,
		RedirectTargets:  u.redirects,
		Heredoc:          u.heredoc,
		Env:              unitEnv(u.words, len(stripped)),
		seq:              st.cur,
		seqPos:           st.curPos,
		chdir:            chdir,
	}
	nested := analyzeNested(&cmd, st)
	// PowerShell script blocks passed as arguments are code too
	// (psblock.go, T-388); additive to whatever analyzeNested unwrapped.
	nested = append(nested, unwrapScriptBlocks(&cmd, st)...)
	*out = append(*out, cmd)
	*out = append(*out, nested...)
}

// leadingKeywords are the reserved words that may stand in COMMAND
// position in front of the command they introduce, per dialect. Before
// this table a unit beginning with one of them took the keyword as its
// Base, so `{ rm -rf /; }`, `if x; then rm -rf /; fi`, `while x; do rm
// -rf /; done` and `! rm -rf /` matched no rule at all (found while
// building the pass-2 M2-01 corpus). Only words that are followed by a
// COMMAND are listed: `for`, `case`, `select` and `function` introduce a
// name or a word list, and terminators (`fi`, `done`, `esac`, `}`) end a
// unit without starting one, so neither kind is stripped. The cmd dialect
// is absent on purpose: its `if` and `for` take conditions and variables
// before the command, and its parenthesised blocks already split into
// units at the lexer.
var leadingKeywords = map[Dialect]map[string]bool{
	DialectPosix: setOf("{", "!", "if", "then", "elif", "else", "while", "until", "do"),
	DialectPowerShell: setOf("{", "if", "elseif", "else", "while", "do", "until", "try",
		"finally", "begin", "process", "end"),
}

// stripLeadingKeywords drops leading environment assignments and
// leading reserved words (leadingKeywords) until the unit's real command
// word is first, in any order (`if FOO=1 rm ...`, `! { rm ...`).
func stripLeadingKeywords(words []string, dialect Dialect) []string {
	kw := leadingKeywords[dialect]
	if dialect == "" {
		kw = leadingKeywords[DialectPosix]
	}
	for {
		words = stripAssignments(words)
		if len(words) == 0 || !kw[strings.ToLower(words[0])] {
			return words
		}
		words = words[1:]
	}
}

// stripAssignments drops leading VAR=value environment assignments
// (`FOO=1 cmd ...` — POSIX prefix assignments).
func stripAssignments(words []string) []string {
	i := 0
	for i < len(words) && isEnvAssign(words[i]) {
		i++
	}
	return words[i:]
}

// unitEnv returns the environment assignments among the words in front of
// a unit's command word: the unit's words minus its argv, which is always a
// suffix of them (argvLen words long). Leading keywords and wrapper words
// are not assignments and are skipped, so prefix assignments and `env`
// wrapper operands are both kept, in order.
func unitEnv(words []string, argvLen int) []string {
	if argvLen > len(words) {
		return nil
	}
	var env []string
	for _, w := range words[:len(words)-argvLen] {
		if isEnvAssign(w) {
			env = append(env, w)
		}
	}
	return env
}

// isEnvAssign reports whether w is an environment-assignment word
// (NAME=value with a valid identifier name).
func isEnvAssign(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := w[i]
		if !(c == '_' || isASCIILetter(c) || (i > 0 && c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// wrapperSpec describes how one wrapper command consumes its own
// arguments before the wrapped command begins.
type wrapperSpec struct {
	// argFlags are wrapper flags that consume a following value
	// ("sudo -u root").
	argFlags map[string]bool
	// leadingOperand marks wrappers whose first positional is their
	// own operand, not the wrapped command ("timeout 5 cmd").
	leadingOperand bool
	// assignments marks wrappers that consume VAR=value operands
	// ("env FOO=1 cmd").
	assignments bool
}

// posixWrappers is the table of wrappers stripped before matching
// (spec §4.3). sudo/doas additionally set Command.Sudo. eval/exec are
// handled separately: exec strips like a wrapper; eval re-parses its
// arguments as a command line (see analyzeNested).
var posixWrappers = map[string]wrapperSpec{
	"sudo": {argFlags: setOf("-u", "-g", "-p", "-C", "-D", "-R", "-T", "-h", "--user", "--group")},
	"doas": {argFlags: setOf("-u")},
	// gsudo is the widely-installed third-party sudo for Windows and
	// wraps its command exactly like sudo does. It is listed in BOTH
	// dialect tables for the reason cmdWrappers documents: a Windows
	// command line can arrive tagged with any dialect, and a wrapper
	// that strips under one dialect and not another is the asymmetry
	// H5 was.
	"gsudo":   {argFlags: setOf("-u", "--user", "-i", "--integrity")},
	"env":     {assignments: true, argFlags: setOf("-u", "-S", "-C", "-P", "--unset", "--split-string", "--chdir")},
	"timeout": {leadingOperand: true, argFlags: setOf("-k", "-s", "--kill-after", "--signal")},
	"nice":    {argFlags: setOf("-n", "--adjustment")},
	"nohup":   {},
	"time":    {},
	"stdbuf":  {argFlags: setOf("-i", "-o", "-e")},
	"command": {},
	"builtin": {},
	"exec":    {},
	"xargs": {argFlags: setOf("-I", "-n", "-P", "-d", "-a", "-E", "-s", "-L", "-i",
		"--max-args", "--max-procs", "--delimiter", "--arg-file", "--max-chars", "--max-lines", "--replace")},
}

// cmdWrappers is the cmd-dialect wrapper table. cmd.exe has no
// wrapper convention of its own, but Windows 11 (24H2) ships
// `sudo.exe`, and a Windows client can deliver `sudo systemctl enable
// …` (or a WSL-bound line) tagged with the cmd dialect. Before this
// table existed, that command's base was `sudo` and R-155's
// systemctl arm never saw it — it denied under posix and PowerShell
// and ALLOWED under cmd, a dialect asymmetry with no defensible
// reading (measured 2026-07-27; docs/security.md H5).
//
// ONLY the privilege wrappers are listed. posixWrappers must NOT be
// reused wholesale here: cmd's `timeout` is a SLEEP, not a wrapper,
// and `start` is a launcher with its own syntax (launcher.go).
var cmdWrappers = map[string]wrapperSpec{
	"sudo":  {argFlags: setOf("-u", "--user")},
	"doas":  {argFlags: setOf("-u")},
	"gsudo": {argFlags: setOf("-u", "--user", "-i", "--integrity")},
}

// privilegeWrappers are the wrappers that set Command.Sudo — the
// privilege-escalation fact that survives wrapper stripping. Derived
// from one place so the two dialect tables cannot disagree about
// which of their rows escalate.
var privilegeWrappers = map[string]bool{"sudo": true, "doas": true, "gsudo": true}

// stripWrappers iteratively removes leading wrapper commands,
// returning the remaining argv, the stripped wrapper names in order,
// and whether a privilege-escalation wrapper (sudo/doas) was present.
func stripWrappers(words []string, dialect Dialect) (rest, wrappers []string, sudo bool) {
	table := posixWrappers
	if dialect == DialectCmd {
		table = cmdWrappers
	}
	for len(words) > 0 {
		base := canonicalBase(words[0], dialect)
		spec, ok := table[base]
		if !ok {
			break
		}
		wrappers = append(wrappers, base)
		if privilegeWrappers[base] {
			sudo = true
		}
		words = consumeWrapperArgs(words[1:], spec)
	}
	return words, wrappers, sudo
}

// consumeWrapperArgs skips a wrapper's own flags/operands and returns
// the argv tail where the wrapped command begins.
func consumeWrapperArgs(rest []string, spec wrapperSpec) []string {
	tookOperand := false
	for len(rest) > 0 {
		w := rest[0]
		switch {
		case len(w) > 1 && w[0] == '-':
			name, hasEq := w, false
			if i := strings.IndexByte(w, '='); i >= 0 {
				name, hasEq = w[:i], true
			}
			if spec.argFlags[name] && !hasEq && len(rest) > 1 {
				rest = rest[2:]
			} else {
				rest = rest[1:]
			}
		case spec.assignments && isEnvAssign(w):
			rest = rest[1:]
		case spec.leadingOperand && !tookOperand:
			tookOperand = true
			rest = rest[1:]
		default:
			return rest
		}
	}
	return rest
}

// canonicalBase derives Command.Base from a command word: directory
// prefix stripped, lowercased, known executable extensions stripped,
// PowerShell aliases resolved within that dialect.
func canonicalBase(word string, dialect Dialect) string {
	b := word
	if i := strings.LastIndexAny(b, `/\`); i >= 0 {
		b = b[i+1:]
	}
	b = strings.ToLower(b)
	for _, ext := range [...]string{".exe", ".com", ".bat", ".cmd"} {
		b = strings.TrimSuffix(b, ext)
	}
	if dialect == DialectPowerShell {
		if canon, ok := psAliases[b]; ok {
			return canon
		}
	}
	return b
}

// posixShellBases are the shells whose `-c` payloads unwrap
// recursively as POSIX command lines.
var posixShellBases = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true, "fish": true,
}

// interpreterSpec describes an interpreter whose one-liner payload is
// extracted opaquely (never parsed as shell — gap F1: we expose the
// payload, we do not pretend to understand it). Since T-317 the
// inline-script operand extractor (inlinescript.go) reads the same
// table, so this is the ONE owner of "how does this interpreter take
// a program on its command line".
type interpreterSpec struct {
	// flags are the exact one-liner flags whose value (the next token,
	// or the "--flag=VALUE" embedded form) is program text.
	flags []string
	// cluster lists the short-flag letters that may END a combined
	// cluster and still take the next token as the program
	// (`perl -lne`, `ruby -ne`, `python -Ic`).
	cluster string
	// sub is a subcommand whose first operand is program text
	// (`deno eval CODE`).
	sub string
	// stdin reports the interpreter runs a program read from standard
	// input (`python3 - <<EOF`, `echo CODE | node`).
	stdin bool
	kind  string
}

// interpreters maps interpreter bases to their one-liner flags. A
// versioned base (python3.12, php8.2) resolves through
// interpreterFor.
var interpreters = map[string]interpreterSpec{
	"python":    {flags: []string{"-c"}, cluster: "c", stdin: true, kind: "python"},
	"python2":   {flags: []string{"-c"}, cluster: "c", stdin: true, kind: "python"},
	"python3":   {flags: []string{"-c"}, cluster: "c", stdin: true, kind: "python"},
	"py":        {flags: []string{"-c"}, cluster: "c", stdin: true, kind: "python"},
	"node":      {flags: []string{"-e", "--eval", "-p", "--print"}, stdin: true, kind: "node"},
	"nodejs":    {flags: []string{"-e", "--eval", "-p", "--print"}, stdin: true, kind: "node"},
	"perl":      {flags: []string{"-e", "-E"}, cluster: "eE", stdin: true, kind: "perl"},
	"ruby":      {flags: []string{"-e"}, cluster: "e", stdin: true, kind: "ruby"},
	"php":       {flags: []string{"-r"}, stdin: true, kind: "php"},
	"deno":      {sub: "eval", kind: "deno"},
	"bun":       {flags: []string{"-e", "--eval", "-p", "--print"}, kind: "bun"},
	"osascript": {flags: []string{"-e"}, stdin: true, kind: "applescript"},
}

// analyzeNested inspects a freshly-built Command for nested code:
// LAUNCHER wrappers (Start-Process / wsl / cmd's START — see
// launcher.go), shell `-c` payloads (recursively parsed up to
// maxUnwrapDepth), PowerShell -Command/-EncodedCommand and `cmd /c`
// payloads (parsed under their own dialect), eval re-parsing, and
// interpreter one-liners (kept opaque on Payload). It may set
// Payload/PayloadKind on cmd and returns the unwrapped nested
// Commands.
func analyzeNested(cmd *Command, st parseState) []Command {
	// Launchers are checked first; no launcher base collides with a
	// shell, interpreter or `-c`-carrying base below.
	if spec, ok := launcherFor(cmd); ok {
		return unwrapLauncher(cmd, spec, st)
	}
	switch {
	case posixShellBases[cmd.Base]:
		payload, ok := dashCPayload(cmd.Argv)
		if !ok {
			return nil
		}
		return unwrapPayload(cmd, payload, DialectPosix, "shell", st)
	case cmd.Base == "eval":
		if len(cmd.Argv) < 2 {
			return nil
		}
		return unwrapPayload(cmd, strings.Join(cmd.Argv[1:], " "), cmd.Dialect, "shell", st)
	case cmd.Base == "invoke-expression" || cmd.Base == "iex":
		// PowerShell's eval. `iex` canonicalizes to
		// `invoke-expression` only in the PowerShell dialect, so the
		// raw alias is matched too — the same dialect-agnostic
		// reasoning launcher.go applies to `start` (a Windows command
		// line can arrive tagged with any dialect).
		payload, ok := psExpressionPayload(cmd.Argv)
		if !ok {
			return nil
		}
		return unwrapPayload(cmd, payload, DialectPowerShell, "powershell", st)
	case cmd.Base == "powershell" || cmd.Base == "pwsh":
		payload, ok := psCommandPayload(cmd.Argv)
		if !ok {
			return nil
		}
		return unwrapPayload(cmd, payload, DialectPowerShell, "powershell", st)
	case cmd.Base == "cmd":
		payload, ok := cmdSlashCPayload(cmd.Argv)
		if !ok {
			return nil
		}
		return unwrapPayload(cmd, payload, DialectCmd, "cmd", st)
	default:
		if spec, ok := interpreterFor(cmd.Base); ok {
			if code := inlineCode(cmd, spec); len(code) > 0 {
				cmd.Payload, cmd.PayloadKind = strings.Join(code, "\n"), spec.kind
			}
		}
		return nil
	}
}

// unwrapPayload either recursively parses a nested payload under the
// given dialect or — at the depth limit — records it opaquely on the
// wrapper Command.
func unwrapPayload(cmd *Command, payload string, dialect Dialect, kind string, st parseState) []Command {
	if st.depth >= maxUnwrapDepth {
		// FAIL CLOSED. Recording the text on Payload is a RECORD, not
		// a defence — no rule reads Payload (see its field comment),
		// so before Unanalyzed existed a wrapper chain one level past
		// the limit simply ALLOWED. Both are set: the text for the
		// operator, the reason for R-157.
		cmd.Payload, cmd.PayloadKind = payload, kind
		cmd.Unanalyzed = unanalyzedNestingLimit
		return nil
	}
	if !st.afford(1) {
		cmd.Unanalyzed = unanalyzedExpansionBudget
		cmd.Payload, cmd.PayloadKind = payload, kind
		return nil
	}
	return parseDepth(payload, dialect, st.deeper())
}

// dashCPayload finds a POSIX shell's -c payload, accepting combined
// flag clusters ("-lc", "-xec"). It stops at the first operand (a
// script file we cannot read — pure package) or a "--" terminator.
func dashCPayload(argv []string) (string, bool) {
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		if t == "--" || !strings.HasPrefix(t, "-") {
			return "", false
		}
		if strings.HasPrefix(t, "--") {
			continue
		}
		if strings.ContainsRune(t[1:], 'c') && i+1 < len(argv) {
			return argv[i+1], true
		}
	}
	return "", false
}

// extractHeredocs scans a POSIX command line for heredoc
// redirections (<<DELIM, <<-DELIM, quoted delimiters), removes each
// body and its terminator line from the returned string, and replaces
// the redirection with an internal marker word that buildUnits maps
// back to the body. Quoted regions are respected. Limitations
// (documented, pinned by tests): one heredoc per line; an
// unterminated heredoc consumes the rest of the input as its body.
func extractHeredocs(s string) (string, []string) {
	if !strings.Contains(s, "<<") {
		return s, nil
	}
	var out strings.Builder
	var bodies []string
	skips := map[int]int{} // newline index → resume index past the body
	inS, inD := false, false
	i := 0
	for i < len(s) {
		c := s[i]
		if to, ok := skips[i]; ok && c == '\n' {
			out.WriteByte('\n')
			i = to
			continue
		}
		switch {
		case inS:
			out.WriteByte(c)
			if c == '\'' {
				inS = false
			}
			i++
		case inD:
			if c == '\\' && i+1 < len(s) {
				out.WriteByte(c)
				out.WriteByte(s[i+1])
				i += 2
				continue
			}
			out.WriteByte(c)
			if c == '"' {
				inD = false
			}
			i++
		case c == '\'':
			inS = true
			out.WriteByte(c)
			i++
		case c == '"':
			inD = true
			out.WriteByte(c)
			i++
		case c == '\\':
			out.WriteByte(c)
			if i+1 < len(s) {
				out.WriteByte(s[i+1])
				i += 2
			} else {
				i++
			}
		case c == '<' && i+1 < len(s) && s[i+1] == '<' && (i+2 >= len(s) || s[i+2] != '<'):
			adv, ok := scanHeredoc(s, i, &bodies, skips, &out)
			if !ok {
				out.WriteString("<<")
				i += 2
				continue
			}
			i = adv
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String(), bodies
}

// scanHeredoc parses one heredoc redirection starting at s[i] ("<<"),
// records its body and skip range, writes the marker word, and
// returns the index to resume lexing at. ok is false when the text
// after "<<" is not a valid heredoc introducer.
func scanHeredoc(s string, i int, bodies *[]string, skips map[int]int, out *strings.Builder) (int, bool) {
	j := i + 2
	if j < len(s) && s[j] == '-' {
		j++
	}
	var q byte
	if j < len(s) && (s[j] == '\'' || s[j] == '"') {
		q = s[j]
		j++
	}
	st := j
	for j < len(s) && isWordChar(s[j]) {
		j++
	}
	delim := s[st:j]
	if q != 0 {
		if j < len(s) && s[j] == q {
			j++
		} else {
			delim = ""
		}
	}
	if delim == "" {
		return 0, false
	}
	marker := " \x00hd" + strconv.Itoa(len(*bodies)) + "\x00 "
	nl := strings.IndexByte(s[j:], '\n')
	if nl < 0 {
		// Declared but no body present in this input.
		*bodies = append(*bodies, "")
		out.WriteString(marker)
		return j, true
	}
	newlineAt := j + nl
	if _, exists := skips[newlineAt]; exists {
		// Second heredoc on one line — unsupported, treat literally.
		return 0, false
	}
	bodyStart := newlineAt + 1
	bodyLen, total := findHeredocEnd(s[bodyStart:], delim)
	*bodies = append(*bodies, s[bodyStart:bodyStart+bodyLen])
	skips[newlineAt] = bodyStart + total
	out.WriteString(marker)
	return j, true
}

// findHeredocEnd locates the terminator line within body text,
// returning the body length (up to the terminator line) and the total
// length consumed (past the terminator line). Leading tabs on the
// terminator are tolerated (<<- semantics). An unterminated heredoc
// returns the whole text as body.
func findHeredocEnd(text, delim string) (bodyLen, total int) {
	off := 0
	for off <= len(text) {
		end := strings.IndexByte(text[off:], '\n')
		var line string
		var next int
		if end < 0 {
			line, next = text[off:], len(text)
		} else {
			line, next = text[off:off+end], off+end+1
		}
		if line == delim || strings.TrimLeft(line, "\t") == delim {
			return off, next
		}
		if end < 0 {
			break
		}
		off = next
	}
	return len(text), len(text)
}

// isWordChar reports whether c is a heredoc-delimiter word character.
func isWordChar(c byte) bool {
	return c == '_' || isASCIILetter(c) || (c >= '0' && c <= '9')
}

// heredocIndex recognizes the internal heredoc marker words emitted
// by scanHeredoc.
func heredocIndex(w string) (int, bool) {
	if !strings.HasPrefix(w, "\x00hd") || !strings.HasSuffix(w, "\x00") || len(w) < 5 {
		return 0, false
	}
	n, err := strconv.Atoi(w[3 : len(w)-1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// ptoken is one lexer output token: a word, or a separator/redirect
// operator.
type ptoken struct {
	text string
	op   bool
	// lit lists the byte offsets in text of the '$', '%' and '`'
	// characters read from a single-quoted or escaped region (literal,
	// not an expansion). Command.ArgvLiterals carries it.
	lit []int
	// qbr lists the byte offsets in text of the '{' and '}' characters
	// read from a quoted (single or double) or escaped region: string
	// text, never a script-block delimiter (psblock.go, T-525). It is a
	// separate list from lit because a double-quoted '$' still expands
	// while a double-quoted brace is plain text.
	qbr []int
}

// lexSpec parametrizes lexLine per dialect.
type lexSpec struct {
	// escape is the dialect's escape character (POSIX '\\',
	// PowerShell '`', cmd '^'); 0 disables escaping.
	escape byte
	// singleQuote enables '...'-style literal quoting.
	singleQuote bool
	// semiSep treats ';' as a command separator (POSIX,
	// PowerShell; cmd uses '&').
	semiSep bool
	// stopParse honors PowerShell's --% stop-parsing token.
	stopParse bool
	// dquoteEscapeSet, when non-empty, restricts which characters
	// the escape char escapes INSIDE double quotes (POSIX: only
	// \" \\ \$ \` — otherwise the backslash is literal).
	dquoteEscapeSet string
	// psSyntax enables three PowerShell token rules (PSRULES lane): a
	// here-string (@'...'@, @"..."@) is one quoted word, a comment (# to
	// the end of the line, <# ... #>) at the start of a token is not
	// lexed, and an escape before a newline is a line continuation
	// (whitespace), not an escaped newline character.
	psSyntax bool
}

// Per-dialect lexer parameters.
var (
	posixLexSpec = lexSpec{escape: '\\', singleQuote: true, semiSep: true, dquoteEscapeSet: "\"\\$`"}
	psLexSpec    = lexSpec{escape: '`', singleQuote: true, semiSep: true, stopParse: true, psSyntax: true}
	cmdLexSpec   = lexSpec{escape: '^', singleQuote: false, semiSep: false}
)

// lexLine tokenizes one command line under the dialect spec into
// words and operator tokens. Operators emitted: ";" (unit separator —
// also used for newlines and "&"), "&&" and "||" (unit separators that
// carry their list semantics), "(" and ")" (unquoted parens, unit
// separators), "|" (pipe), ">" (output redirect whose target is the
// next word), ">fd" (fd-duplication redirect, no target word), "<"
// (input redirect, target dropped by buildUnits), and the zero-width
// opSubMark.
func lexLine(s string, spec lexSpec) []ptoken {
	lx := &lexer{src: s, spec: spec}
	lx.run()
	return lx.toks
}

// lexer carries lexLine's scanning state.
type lexer struct {
	src   string
	spec  lexSpec
	toks  []ptoken
	cur   strings.Builder
	has   bool
	inS   bool
	inD   bool
	digit bool // current word is all digits so far (fd-prefix detection)
	i     int
	// lits collects the current word's literal-character offsets
	// (ptoken.lit).
	lits []int
	// qbr collects the current word's quoted-brace offsets (ptoken.qbr).
	qbr []int
}

// flush emits the current word (if any) as a token, honoring the
// PowerShell stop-parsing token.
func (lx *lexer) flush() {
	if !lx.has && lx.cur.Len() == 0 {
		return
	}
	w := lx.cur.String()
	lits, qbr := lx.lits, lx.qbr
	lx.cur.Reset()
	lx.lits, lx.qbr = nil, nil
	lx.has = false
	lx.digit = false
	if lx.spec.stopParse && w == "--%" {
		// Everything after --% is literal words.
		rest := lx.src[lx.i:]
		if strings.IndexByte(rest, subMarker) >= 0 {
			lx.toks = append(lx.toks, ptoken{text: opSubMark, op: true})
			rest = strings.ReplaceAll(rest, string(rune(subMarker)), "")
		}
		for _, f := range strings.Fields(rest) {
			lx.toks = append(lx.toks, ptoken{text: f})
		}
		lx.i = len(lx.src)
		return
	}
	lx.toks = append(lx.toks, ptoken{text: w, lit: lits, qbr: qbr})
}

// opSubMark is the zero-width operator token the lexer emits for a
// subMarker byte. It does NOT flush the current word: buildUnits only
// sets the current unit's hadSub flag.
const opSubMark = "\x01sub"

// writeLit appends one byte read from a single-quoted or escaped region,
// recording an expansion-capable character as literal (ptoken.lit).
func (lx *lexer) writeLit(c byte) {
	if c == subMarker {
		lx.toks = append(lx.toks, ptoken{text: opSubMark, op: true})
		return
	}
	if c == '$' || c == '%' || c == '`' {
		lx.lits = append(lx.lits, lx.cur.Len())
	}
	lx.writeQuoted(c)
}

// writeQuoted appends one byte read from any quoted or escaped region,
// recording a brace as string text (ptoken.qbr).
func (lx *lexer) writeQuoted(c byte) {
	if c == '{' || c == '}' {
		lx.qbr = append(lx.qbr, lx.cur.Len())
	}
	lx.write(c)
}

// write appends one byte to the current word (a subMarker becomes the
// zero-width opSubMark token instead, see writeLit).
func (lx *lexer) write(c byte) {
	if c == subMarker {
		lx.toks = append(lx.toks, ptoken{text: opSubMark, op: true})
		return
	}
	if lx.cur.Len() == 0 {
		lx.digit = c >= '0' && c <= '9'
	} else if lx.digit {
		lx.digit = c >= '0' && c <= '9'
	}
	lx.cur.WriteByte(c)
	lx.has = true
}

// op flushes the current word and emits an operator token.
func (lx *lexer) op(text string) {
	lx.flush()
	lx.toks = append(lx.toks, ptoken{text: text, op: true})
}

// run is the scanning loop.
func (lx *lexer) run() {
	s, spec := lx.src, lx.spec
	for lx.i < len(s) {
		c := s[lx.i]
		switch {
		case lx.inS:
			if c == '\'' {
				lx.inS = false
			} else {
				lx.writeLit(c)
			}
			lx.i++
		case lx.inD:
			lx.scanDouble(c)
		case spec.psSyntax && lx.psToken(c):
			// consumed: a here-string (one quoted word) or a comment
		case spec.singleQuote && c == '\'':
			lx.inS, lx.has = true, true
			lx.i++
		case c == '"':
			lx.inD, lx.has = true, true
			lx.i++
		case spec.escape != 0 && c == spec.escape:
			lx.scanEscape()
		case c == ' ' || c == '\t' || c == '\r':
			lx.flush()
			lx.i++
		case c == '\n' || (spec.semiSep && c == ';'):
			lx.op(";")
			lx.i++
		case c == '&':
			lx.scanAmp()
		case c == '|':
			if lx.i+1 < len(s) && s[lx.i+1] == '|' {
				lx.op("||")
				lx.i += 2
			} else {
				lx.op("|")
				lx.i++
			}
		case c == '>':
			lx.scanRedirect()
		case c == '<':
			lx.op("<")
			lx.i++
		case c == '(' && lx.cur.Len() == 0:
			// A subshell/group opener at word start acts as a unit
			// separator; inside a word ("$(...)"), it is literal
			// and handled by extractSubstitutions. It is its own
			// operator so cwdtrack.go can scope a POSIX subshell's
			// directory changes; buildUnits treats it as a separator.
			lx.op("(")
			lx.i++
		case c == ')' && !strings.Contains(lx.cur.String(), "("):
			// A closer is a separator unless it closes a
			// substitution opened within the current word
			// ("$(pwd)") — then it is literal.
			lx.op(")")
			lx.i++
		default:
			lx.write(c)
			lx.i++
		}
	}
	lx.flush()
}

// scanEscape handles the dialect's escape character outside quotes: the
// next byte is literal, except that under psSyntax an escape before the end
// of the line is a line continuation, which joins the next line to this
// one and separates words like any whitespace.
func (lx *lexer) scanEscape() {
	s := lx.src
	if n := psLineContinuation(s, lx.i); lx.spec.psSyntax && n > 0 {
		lx.flush()
		lx.i += n
		return
	}
	if lx.i+1 < len(s) {
		lx.writeLit(s[lx.i+1])
		lx.i += 2
		return
	}
	lx.i++
}

// scanDouble handles one byte inside double quotes.
func (lx *lexer) scanDouble(c byte) {
	s, spec := lx.src, lx.spec
	if c == '"' {
		lx.inD = false
		lx.i++
		return
	}
	if spec.escape != 0 && c == spec.escape && lx.i+1 < len(s) {
		n := s[lx.i+1]
		if spec.dquoteEscapeSet == "" || strings.IndexByte(spec.dquoteEscapeSet, n) >= 0 {
			lx.writeLit(n)
			lx.i += 2
			return
		}
	}
	lx.writeQuoted(c)
	lx.i++
}

// scanAmp handles '&': "&&" separator, "&>" redirect, bare "&"
// separator (background / cmd separator / PS call operator — all
// reduce to a unit boundary; a leading PS call operator simply
// flushes an empty unit, which is a no-op).
func (lx *lexer) scanAmp() {
	s := lx.src
	switch {
	case lx.i+1 < len(s) && s[lx.i+1] == '&':
		lx.op("&&")
		lx.i += 2
	case lx.i+1 < len(s) && s[lx.i+1] == '>':
		lx.i += 2
		lx.op(">")
	default:
		lx.op(";")
		lx.i++
	}
}

// scanRedirect handles '>': ">>", ">", and fd-duplication forms
// (">&2"), dropping a pure-digit fd prefix ("2>") from the pending
// word.
func (lx *lexer) scanRedirect() {
	s := lx.src
	if lx.digit && lx.cur.Len() > 0 {
		// "2>"-style fd prefix: the digits are not a word.
		lx.cur.Reset()
		lx.lits, lx.qbr = nil, nil
		lx.has = false
		lx.digit = false
	}
	lx.i++
	if lx.i < len(s) && s[lx.i] == '>' {
		lx.i++
	}
	if lx.i < len(s) && s[lx.i] == '&' {
		lx.i++
		for lx.i < len(s) && s[lx.i] >= '0' && s[lx.i] <= '9' {
			lx.i++
		}
		lx.op(">fd")
		return
	}
	lx.op(">")
}

// buildUnits groups lexer tokens into units, wiring redirect targets,
// heredoc bodies and pipeline membership.
func buildUnits(toks []ptoken, bodies []string) []unit {
	var units []unit
	var cur unit
	pipeNext := false
	redirNext := false
	dropNext := false
	// The list operator and parens seen since the last emitted unit
	// belong to the NEXT unit; a flush that emits nothing keeps them.
	nextSep, nextOpens, nextCloses := sepSeq, 0, 0
	flush := func() {
		if len(cur.words) > 0 || cur.heredoc != "" || len(cur.redirects) > 0 {
			cur.pipeline = cur.pipeline || pipeNext
			cur.sep, cur.opens, cur.closes = nextSep, nextOpens, nextCloses
			units = append(units, cur)
			nextSep, nextOpens, nextCloses = sepSeq, 0, 0
		}
		cur = unit{}
		redirNext, dropNext = false, false
	}
	for _, t := range toks {
		if t.op {
			switch t.text {
			case opSubMark:
				cur.hadSub = true
			case ";", "&&", "||":
				flush()
				pipeNext = false
				nextSep = listSep(t.text)
			case "(":
				flush()
				pipeNext = false
				nextOpens++
			case ")":
				flush()
				pipeNext = false
				nextCloses++
			case "|":
				cur.pipeline = true
				flush()
				pipeNext = true
				nextSep = sepPipe
			case ">":
				redirNext = true
			case ">fd":
				// fd duplication — no target word follows.
			case "<":
				dropNext = true
			}
			continue
		}
		if n, ok := heredocIndex(t.text); ok {
			if n < len(bodies) {
				body := bodies[n]
				if strings.IndexByte(body, subMarker) >= 0 {
					cur.hadSub = true
					body = strings.ReplaceAll(body, string(rune(subMarker)), "")
				}
				cur.heredoc += body
			}
			continue
		}
		switch {
		case redirNext:
			cur.redirects = append(cur.redirects, t.text)
			redirNext = false
		case dropNext:
			dropNext = false // input-redirect source: dropped (no rule consumes it)
		default:
			cur.words = append(cur.words, t.text)
			cur.lits = append(cur.lits, t.lit)
			cur.qbr = append(cur.qbr, t.qbr)
		}
	}
	flush()
	return units
}

// stripSubstitutions removes command substitutions — "$( ... )"
// (nesting-aware) and backtick spans — outside single-quoted regions
// and returns the cleaned line plus the extracted inner texts. POSIX
// expands substitutions inside double quotes, so those are included.
// The caller parses each extracted text as additional command units;
// the substituted-away value itself is statically unknowable, so the
// cleaned line simply omits it.
func stripSubstitutions(s string) (string, []string) {
	return stripSubstitutionsMarked(s, false)
}

// subMarker is the byte stripSubstitutionsMarked leaves where a
// substitution was. The lexer never writes it into a word: it becomes a
// zero-width token that sets unit.hadSub, so every rule sees exactly the
// words it saw before the marker existed. A 0x01 byte in the input is
// read the same way (no real command line carries one). It is not NUL,
// which extractHeredocs already uses for its own marker words.
const subMarker = '\x01'

// stripSubstitutionsMarked is stripSubstitutions, optionally leaving
// subMarker in place of each removed substitution so the lexer can tell
// which unit lost one.
func stripSubstitutionsMarked(s string, mark bool) (string, []string) {
	return stripSubstitutionsFor(s, mark, false)
}

// stripSubstitutionsFor is stripSubstitutionsMarked with the two
// PowerShell escape facts parseDepth documents when psEscape is set
// (T-534): a backtick before a brace escapes it (both bytes copied
// through, never a span delimiter), and a backslash before a dollar is an
// ordinary character (the dollar is read next, so a `$( )` after it is
// stripped). Every other byte is read exactly as without psEscape.
func stripSubstitutionsFor(s string, mark, psEscape bool) (string, []string) {
	out, subs, _ := stripSubstitutionsOpts(s, stripOpts{mark: mark, psEscape: psEscape})
	return out, subs
}

// stripSubstitutionsOpts is the substitution pass under explicit options
// (stripOpts). tickSpan reports that a backtick span was removed as a
// substitution, which PowerShell would have read as escapes instead
// (parseDepth then adds the PowerShell tick reading).
//
// TWO QUOTE FACTS ADDED IN THE PSRULES LANE, both of which can only make
// the pass strip MORE: an apostrophe inside double quotes is text, not the
// start of a single-quoted region (`"it's $(crontab -e)"` used to hide its
// substitution from every dialect), and under psEscape a here-string body
// (psHereStringAt) is read with apostrophes as text (psHereBody).
func stripSubstitutionsOpts(s string, o stripOpts) (string, []string, bool) {
	if !strings.ContainsAny(s, "`$") {
		return s, nil, false
	}
	st := &stripScan{s: s, o: o}
	inS, inD := false, false
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case inS:
			st.out.WriteByte(c)
			inS = c != '\''
			i++
		case o.psEscape && !inD && c == '@':
			i = st.hereString(i)
		case c == '\'' && !inD && !o.noSingle:
			inS = true
			st.out.WriteByte(c)
			i++
		case c == '"':
			inD = !inD
			st.out.WriteByte(c)
			i++
		case o.psEscape && c == '\\' && i+1 < len(s) && s[i+1] == '$':
			st.out.WriteByte(c)
			i++
		case st.escapesNext(i):
			i = st.copyEscape(i)
		case c == '`':
			i = st.tickSpanAt(i)
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			i = st.dollarParen(i)
		default:
			st.out.WriteByte(c)
			i++
		}
	}
	return st.out.String(), st.subs, st.tickSpan
}

// stripScan is the output side of one substitution pass
// (stripSubstitutionsOpts): each method consumes one construct starting at
// s[i] and returns the index after it.
type stripScan struct {
	s        string
	o        stripOpts
	out      strings.Builder
	subs     []string
	tickSpan bool
}

// mark leaves subMarker where a substitution was removed (stripOpts.mark).
func (st *stripScan) mark() {
	if st.o.mark {
		st.out.WriteByte(subMarker)
	}
}

// hereString copies a PowerShell here-string, its body run through
// psHereBody; a '@' that does not open one is copied as text.
func (st *stripScan) hereString(i int) int {
	s := st.s
	_, bs, be, next, ok := psHereStringAt(s, i)
	if !ok {
		st.out.WriteByte(s[i])
		return i + 1
	}
	body, bsubs, bt := psHereBody(s[bs:be], st.o)
	st.out.WriteString(s[i:bs])
	st.out.WriteString(body)
	st.out.WriteString(s[be:next])
	st.subs = append(st.subs, bsubs...)
	st.tickSpan = st.tickSpan || bt
	return next
}

// escapesNext reports an escape at s[i] whose next byte is copied as is: a
// backslash, or under psEscape a backtick before a brace, or any backtick
// in the PowerShell tick reading (stripOpts.psTicks).
func (st *stripScan) escapesNext(i int) bool {
	s := st.s
	if s[i] == '\\' {
		return true
	}
	if !st.o.psEscape || s[i] != '`' {
		return false
	}
	return st.o.psTicks || (i+1 < len(s) && (s[i+1] == '{' || s[i+1] == '}'))
}

// copyEscape copies an escape and the byte after it.
func (st *stripScan) copyEscape(i int) int {
	st.out.WriteByte(st.s[i])
	if i+1 < len(st.s) {
		st.out.WriteByte(st.s[i+1])
		return i + 2
	}
	return i + 1
}

// tickSpanAt removes a POSIX backtick substitution; an unclosed backtick
// is copied as text.
func (st *stripScan) tickSpanAt(i int) int {
	s := st.s
	j := strings.IndexByte(s[i+1:], '`')
	if j < 0 {
		st.out.WriteByte(s[i])
		return i + 1
	}
	st.subs = append(st.subs, s[i+1:i+1+j])
	st.tickSpan = true
	st.mark()
	return i + 1 + j + 1
}

// dollarParen removes a $( ) substitution (nested parentheses balanced); an
// unbalanced one is copied as text from its '$'.
func (st *stripScan) dollarParen(i int) int {
	s := st.s
	depth := 1
	j := i + 2
	for j < len(s) && depth > 0 {
		switch s[j] {
		case '(':
			depth++
		case ')':
			depth--
		}
		j++
	}
	if depth != 0 {
		st.out.WriteByte(s[i])
		return i + 1
	}
	st.subs = append(st.subs, s[i+2:j-1])
	st.mark()
	return j
}
