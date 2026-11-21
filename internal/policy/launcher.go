package policy

import "strings"

// Launcher wrappers — commands whose JOB is to start ANOTHER program,
// with that program (and its arguments) recoverable from the
// launcher's own argv.
//
// WHY THIS FILE EXISTS. R-155 (persistence installs: crontab,
// `schtasks /Create`, Run-key writes, `systemctl enable`) matched on
// Command.Base. `Start-Process schtasks.exe -ArgumentList
// '/Create',…` parses as base `start-process` with `schtasks.exe` in a
// POSITIONAL slot, so nothing fired and the command was ALLOWED in
// ModeEnforce, in all three dialects. Same for `wsl.exe -- schtasks
// /Create …` and cmd's `start schtasks /Create …`. Measured
// 2026-07-27 against the real engine; see docs/security.md H5.
//
// THE DESIGN RULE, and the reason this is a parse-layer file rather
// than an R-155 special case: a launcher is resolved into the inner
// command ONCE, here, and the inner command is then handed to the
// ordinary matcher pipeline as a first-class Command. R-155 keeps
// exactly one implementation of "what persistence looks like"
// (CLAUDE.md rule 4: one owner per piece of state), and EVERY other
// rule — destructive, exfil, taint — gets the same coverage for free.
// A wrapper-shaped special case inside one matcher would have to be
// written again for the next rule, and the §W4.6 record is that
// wrapper shapes are exactly what the R-155 bypasses used.
//
// Resolution is table-driven (CLAUDE.md rule 5): one row per launcher,
// each row a resolver from the launcher's argv to the launched argv.
// Nothing here decides anything about policy.

// THE NEVER-SUPPRESS RULE (docs/security.md H5, ROUND 2).
//
// The paragraph above says "ambiguity resolves toward analyzing more,
// never guessing". The first version of this file violated that in
// exactly ONE place and shipped a critical bypass there: a boolean
// (`bound`) decided that because SOME argv token resolved as a
// Start-Process parameter, the cmd-START readings were not worth
// generating. That single suppression made
//
//	start powershell -c "schtasks /Create /TN evil /TR C:\evil.exe"
//	start /b crontab -e
//	start sh -c "crontab -e"
//
// ALLOW in ModeEnforce in all three dialects, while the `-Command`,
// `-enc` and dash-free spellings of the same lines denied. Adding an
// argument to a denied command made it allowed — the signature of a
// reading being deleted rather than a rule being missed.
//
// So: a resolver NEVER chooses between readings. Every reading the
// argv admits is emitted, deduped, and analysed. That covers three
// distinct guesses this file used to make silently, each now a
// generated alternative instead:
//
//   - WHICH GRAMMAR the word names — cmd.exe's START builtin or the
//     Start-Process cmdlet. Both, always.
//   - WHETHER A PARAMETER TOKEN IS THE LAUNCHER'S. `-c` prefixes
//     -Credential, `-e` prefixes -Environment/-ErrorAction — but they
//     are also how `powershell` and `crontab` spell their OWN flags.
//     Reading them as the launcher's DELETES the launched program's
//     arguments (psCollectValue eats the next token), which is how
//     `-c "<payload>"` vanished above.
//   - WHERE A LEXED VALUE ENDS. psCollectValue re-joins comma-run
//     tokens; a directory literally named `C:\temp,` therefore ate the
//     program that followed it, and `Start-Process -WorkingDirectory
//     'C:\temp,' schtasks.exe -ArgumentList …` ALLOWED.
//
// A reading that names an argument rather than a program matches no
// rule and costs a little analysis. A suppressed reading costs a
// bypass. When even the readings run out — no candidate, the depth
// limit, the fan-out bound, the expansion budget — the unit is marked
// Command.Unanalyzed and R-157 denies. Nothing here returns "nothing
// to see" for a wrapper it could not read.

// launchResult is what a launcher row's resolver returns.
type launchResult struct {
	// candidates is EVERY argv the launched command could plausibly
	// be (program first), before dedup. See the never-suppress rule
	// above: a resolver adds readings, it never picks between them.
	candidates [][]string
	// named reports that the invocation NAMED something to launch.
	//
	// `named` with an EMPTY candidate list is a PARSE FAILURE on a
	// known-dangerous wrapper, and it is recorded as such
	// (Command.Unanalyzed → R-157) instead of the old silent
	// `return nil`. It is distinct from "there was nothing to
	// launch" — an interactive `wsl`, `wsl -l -v`, `start` with only
	// switches — which is not a failure and must not deny.
	named bool
}

// launcherSpec is one row of the launcher table.
type launcherSpec struct {
	// name is the wrapper name recorded on the inner Command's
	// Wrappers, so a rule (and the R-155 ETW carve-out) can tell a
	// launched command from a directly-typed one.
	name string
	// resolve maps the launcher's own argv to every argv the launched
	// command could plausibly be. See launchResult and the
	// never-suppress rule above.
	resolve func(argv []string) launchResult
	// inner is the dialect the launched command runs under. Empty
	// inherits the launcher's own dialect.
	inner Dialect
	// reparse marks a launcher whose launched command is a SHELL LINE a
	// remote shell will parse, not an argv the local lexer already split
	// correctly (ssh). When set, unwrapLauncher re-joins each candidate
	// with spaces and runs it back through parseDepth under `inner`, one
	// level deeper, so the remote `cmd a && cmd b | cmd c` splits into its
	// own units exactly as a directly-typed line would — honouring the
	// depth, fan-out and expansion limits, and Unanalyzed, like every
	// other path.
	reparse bool
}

// launchers is the launcher table, keyed by canonical base.
//
// `saps` and `start` are listed alongside `start-process` because
// psAliases only fires in the PowerShell dialect, and an event may
// carry a Windows command line under a POSIX/cmd dialect tag —
// matching it there errs toward analyzing more, the same way
// canonicalBase's unconditional lowercasing does. All three share one
// resolver, which covers BOTH things the word `start` can name (the
// cmdlet and cmd.exe's builtin); see startProcessCandidates.
// `runas` is Windows' own privilege launcher and is here rather than
// in the wrapper tables because its command is ONE quoted operand
// (`runas /user:admin "crontab -e"`), not an argv tail. Adding
// sudo/doas to cmdWrappers closed a dialect asymmetry; leaving out
// their native Windows peer left the same hole under a different
// spelling — `runas /user:admin "crontab -e"` ALLOWED in all three
// dialects (docs/security.md H5 round 2).
//
// docker/podman/nerdctl/docker-compose, kubectl/oc and ssh join the table
// for the same reason the Windows launchers did: each RUNS another command
// whose argv (or remote shell line) is recoverable from its own, and a
// dangerous command behind `docker exec`, `kubectl exec -- ` or `ssh host`
// otherwise reached the matchers as the wrapper's positional and matched
// nothing. The container runtimes run the inner command under POSIX (a Linux
// container is the overwhelming case and the safe default); ssh's remote
// command is a SHELL LINE the remote shell re-parses, so it is reparse=true.
var launchers = map[string]launcherSpec{
	"start-process":  {name: "start-process", resolve: startProcessCandidates},
	"saps":           {name: "start-process", resolve: startProcessCandidates},
	"start":          {name: "start-process", resolve: startProcessCandidates},
	"wsl":            {name: "wsl", resolve: wslInnerArgv, inner: DialectPosix},
	"runas":          {name: "runas", resolve: runasCandidates},
	"docker":         {name: "docker exec", resolve: dockerExecResolver, inner: DialectPosix},
	"podman":         {name: "docker exec", resolve: dockerExecResolver, inner: DialectPosix},
	"nerdctl":        {name: "docker exec", resolve: dockerExecResolver, inner: DialectPosix},
	"docker-compose": {name: "docker exec", resolve: composeExecResolver, inner: DialectPosix},
	"kubectl":        {name: "kubectl exec", resolve: kubectlExecCandidates, inner: DialectPosix},
	"oc":             {name: "kubectl exec", resolve: kubectlExecCandidates, inner: DialectPosix},
	"ssh":            {name: "ssh", resolve: sshRemoteCommand, inner: DialectPosix, reparse: true},
}

// launcherWrapperNames is the set of names launchers records on
// Command.Wrappers, derived from the table so the two can never drift.
var launcherWrapperNames = func() map[string]bool {
	m := make(map[string]bool, len(launchers))
	for _, spec := range launchers {
		m[spec.name] = true
	}
	return m
}()

// viaLauncher reports whether the unit was reached by unwrapping a
// launcher wrapper rather than being invoked directly.
func viaLauncher(cmd *Command) bool {
	if cmd == nil {
		return false
	}
	for _, w := range cmd.Wrappers {
		if launcherWrapperNames[w] {
			return true
		}
	}
	return false
}

// launcherFor returns the launcher row for a parsed unit.
func launcherFor(cmd *Command) (launcherSpec, bool) {
	if len(cmd.Argv) < 2 {
		return launcherSpec{}, false
	}
	spec, ok := launchers[cmd.Base]
	return spec, ok
}

// unwrapLauncher resolves a launcher unit into the launched
// command(s) and parses each as a nested unit.
//
// EVERY exit that does not analyse the launched command marks
// cmd.Unanalyzed, so R-157 denies. Before that existed, all four of
// these paths returned nil and the wrapper analysed as an ordinary
// command that matched nothing — a launcher we could not read was
// SAFER than one we could:
//
//   - no candidate although the invocation named a target;
//   - past maxUnwrapDepth (`wsl -- ` ×5 denied, ×6 ALLOWED — the
//     "recorded on Payload rather than dropped" comment described a
//     field no rule reads);
//   - more readings than maxLauncherCandidates;
//   - the shared expansion budget exhausted.
func unwrapLauncher(cmd *Command, spec launcherSpec, st parseState) []Command {
	res := spec.resolve(cmd.Argv)
	candidates := dedupCandidates(res.candidates)
	if len(candidates) == 0 {
		if res.named {
			cmd.Unanalyzed = unanalyzedLauncherTarget
		}
		return nil
	}
	if st.depth >= maxUnwrapDepth {
		cmd.Payload, cmd.PayloadKind = strings.Join(candidates[0], " "), "shell"
		cmd.Unanalyzed = unanalyzedNestingLimit
		return nil
	}
	if len(candidates) > maxLauncherCandidates {
		cmd.Unanalyzed = unanalyzedLauncherFanOut
		candidates = candidates[:maxLauncherCandidates]
	}
	if !st.afford(len(candidates)) {
		cmd.Unanalyzed = unanalyzedExpansionBudget
		return nil
	}
	dialect := spec.inner
	if dialect == "" {
		dialect = cmd.Dialect
	}
	var out []Command
	for _, inner := range candidates {
		if spec.reparse {
			// The launched "command" is a remote shell line (ssh): the
			// remote shell, not the local lexer, splits it, so re-join and
			// re-parse it as a command line one level deeper. parseDepth
			// honours maxUnwrapDepth, the expansion budget and Unanalyzed
			// itself, exactly like every other nested-payload path.
			out = append(out, parseDepth(strings.Join(inner, " "), dialect, st.deeper())...)
			continue
		}
		processUnit(unit{words: inner}, dialect, st.deeper(), &out)
	}
	for i := range out {
		out[i].Wrappers = append([]string{spec.name}, out[i].Wrappers...)
		out[i].Sudo = out[i].Sudo || cmd.Sudo
	}
	return out
}

// dedupCandidates normalizes, then drops empty and repeated candidate
// argvs, so an unambiguous launcher costs exactly one nested unit. It
// is the single funnel EVERY resolver's readings pass through, which
// is why the normalization lives here rather than in each resolver.
//
// NORMALIZATION = strip surviving literal quoting from every token.
// A candidate becomes a first-class Command, so it must reach the
// matchers spelled the way the SAME command typed directly would be;
// otherwise a wrapper changes a verdict through nothing but a lexer
// artifact. That is not hypothetical:
//
//	Start-Process crontab -ArgumentList '-l'
//
// denied R-155 under the CMD dialect while `crontab -l` allowed. The
// cmd lexer does not treat `'` as a quote (correctly — cmd.exe does
// not either), so the cmd-START reading of this PowerShell line
// carried the token `'-l'`, safeCrontabList looked for `-l`, missed,
// and a read-only listing became a critical deny. The Start-Process
// reading of the same line was already correct because
// psSplitArguments trims — so the defect was that ONE reading
// normalized and the others did not.
//
// Trimming is monotonic in the safe direction for everything else: an
// unquoted token matches MORE path and flag patterns, not fewer. The
// one class it can relax is a safe-pattern that only matches unquoted
// (`crontab '-l'`) — and there the trimmed reading is the one that
// agrees with the directly-typed verdict, which is the property being
// defended. The R-155 ETW carve-out does not rely on this: it refuses
// launcher-wrapped units outright (viaLauncher).
// EMPTINESS IS CHECKED AFTER NORMALIZATION, NOT BEFORE. A candidate
// whose PROGRAM word normalizes to "" is not a reading at all — it is
// a unit whose Base is the empty string, which matches every rule
// exactly never. Skipping past leading empty words recovers the real
// program; a candidate with nothing left is dropped, and if that
// leaves the launcher with NO reading, unwrapLauncher's `named` path
// marks it Unanalyzed and R-157 denies. Both halves matter, and the
// missing check was live:
//
//	wsl '' crontab -e
//
// ALLOWED in ModeEnforce in all three dialects — wslInnerArgv reads
// the empty first operand as the command, so the launched unit's Base
// was "" and R-155 never saw crontab (measured 2026-07-27,
// docs/security.md H5 round 4). The same shape reaches the START
// readings under the cmd dialect, where `”` is not quoting and
// normalizeCandidate is the first thing to empty it.
func dedupCandidates(in [][]string) [][]string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, c := range in {
		if len(c) == 0 {
			continue
		}
		c = normalizeCandidate(c)
		for len(c) > 0 && c[0] == "" {
			c = c[1:]
		}
		if len(c) == 0 {
			continue
		}
		k := strings.Join(c, "\x00")
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}

// normalizeCandidate strips literal quoting from a candidate argv's
// tokens, mirroring what psSplitArguments already does to the
// Start-Process reading. It allocates only when a token changes.
func normalizeCandidate(c []string) []string {
	out := c
	for i, t := range c {
		trimmed := strings.Trim(t, `'"`)
		if trimmed == t {
			continue
		}
		if &out[0] == &c[0] {
			out = append([]string(nil), c...)
		}
		out[i] = trimmed
	}
	return out
}

// --- PowerShell Start-Process ------------------------------------------

// psParamRole marks the two Start-Process parameters whose values this
// resolver actually needs. Every other parameter is in the table only
// so that its VALUE is not mistaken for a positional.
type psParamRole int

// psParamRole values.
const (
	psRoleOther psParamRole = iota
	psRoleFilePath
	psRoleArgumentList
)

// psParam is one row of a cmdlet's parameter table.
type psParam struct {
	// name is the lower-cased parameter name (or documented alias).
	name string
	// canon is the canonical parameter this row spells, when the row
	// is an ALIAS. Empty means the row is its own canonical name.
	//
	// It exists so the ambiguity rule can tell "two spellings of ONE
	// parameter" (-Args and -ArgumentList, which `-arg` prefixes
	// both of) from "two DIFFERENT parameters" (-Environment and
	// -ErrorAction, which `-e` prefixes both of). PowerShell binds
	// the first and refuses the second.
	canon string
	// valued marks a parameter that consumes a value; the rest are
	// switches.
	valued bool
	// role marks the parameters this resolver reads.
	role psParamRole
}

// canonName returns the canonical parameter a row spells.
func (p psParam) canonName() string {
	if p.canon != "" {
		return p.canon
	}
	return p.name
}

// psStartProcessParams is Start-Process's parameter set plus the
// common parameters that take a value.
//
// EVERY parameter matters even when its value is uninteresting,
// because a valued parameter's value must not be counted as a
// positional: `Start-Process -WorkingDirectory C:\x schtasks.exe`
// binds `C:\x` to -WorkingDirectory, so the FilePath is `schtasks.exe`
// — a table missing -WorkingDirectory would resolve the program to
// `C:\x` and lose the persistence install.
//
// `-Args` is listed as a row of its own: it is a real alias of
// -ArgumentList and is NOT a prefix of it ("args" vs "argu"), so
// prefix matching alone would never find it.
var psStartProcessParams = []psParam{
	{name: "filepath", valued: true, role: psRoleFilePath},
	{name: "argumentlist", valued: true, role: psRoleArgumentList},
	{name: "args", canon: "argumentlist", valued: true, role: psRoleArgumentList},
	{name: "credential", valued: true},
	{name: "environment", valued: true},
	{name: "redirectstandarderror", valued: true},
	{name: "redirectstandardinput", valued: true},
	{name: "redirectstandardoutput", valued: true},
	{name: "verb", valued: true},
	{name: "windowstyle", valued: true},
	{name: "workingdirectory", valued: true},
	{name: "loaduserprofile"},
	{name: "nonewwindow"},
	{name: "passthru"},
	{name: "usenewenvironment"},
	{name: "wait"},
	// Common parameters (they bind on every cmdlet).
	{name: "erroraction", valued: true},
	{name: "errorvariable", valued: true},
	{name: "informationaction", valued: true},
	{name: "informationvariable", valued: true},
	{name: "outbuffer", valued: true},
	{name: "outvariable", valued: true},
	{name: "pipelinevariable", valued: true},
	{name: "progressaction", valued: true},
	{name: "warningaction", valued: true},
	{name: "warningvariable", valued: true},
	{name: "debug"},
	{name: "verbose"},
	// ShouldProcess parameters: Start-Process declares
	// SupportsShouldProcess, so both bind on it.
	{name: "confirm"},
	{name: "whatif"},
}

// psResolveParam binds a parameter TOKEN to a table row, and it is the
// reason nothing in this file ever compares a parameter name with `==`:
//
//	an EXACT (case-insensitive) name wins outright — this is what
//	  keeps `-Verb` from being ambiguous with `-Verbose`; then
//	the token must be a prefix of ONE parameter. `-fi` and `-Ver`
//	  name one each. `-arg` prefixes both -ArgumentList and its alias
//	  -Args, which are the SAME parameter (psParam.canon), so it
//	  binds. `-e` prefixes -Environment, -ErrorAction and
//	  -ErrorVariable — three DIFFERENT parameters — so it binds to
//	  nothing.
//
// THE AMBIGUITY RULE IS PowerShell's, THE CONSEQUENCE IS NOT.
// PowerShell REFUSES to run a command carrying an ambiguous
// abbreviation; this resolver only refuses to BIND one. The two are
// not the same thing and the difference is deliberate, because the
// tempting shortcut — "PowerShell would reject this line, so allow it"
// — would be a bypass generator: this table is a SUBSET of the real
// parameter set (Start-Process's own parameters plus the common ones),
// so any parameter it does not know would read as ambiguous, and
// spelling a real parameter we happen to be missing would become a way
// to buy an allow. An unbound token instead flows into the
// never-suppress cross-product: psBindModes generates BOTH the reading
// where it swallows the next token and the reading where it does not,
// and both are analysed. `Start-Process -e Stop schtasks.exe
// -ArgumentList '/Create'` therefore still denies — correctly, on the
// reading where `schtasks.exe` is the program.
//
// The previous rule bound to whichever row appeared FIRST whenever the
// candidates merely agreed on valued-ness and role, while its comment
// claimed to bind the way PowerShell binds. That claim was false (an
// independent review measured it, docs/security.md H5 round 4); the
// behaviour is now the stricter one and the comment says what it does.
//
// Guessing is what the modes exist to avoid: guessing "switch" hides a
// program (`-w C:\x schtasks.exe` would resolve FilePath to `C:\x`) and
// guessing "valued" hides a different one — see startProcessCandidates.
func psResolveParam(name string, params []psParam) psBinding {
	name = strings.ToLower(name)
	if name == "" {
		return psBinding{}
	}
	var match psParam
	found := false
	for _, p := range params {
		if p.name == name {
			return psBinding{param: p, bound: true, exact: true}
		}
		if !strings.HasPrefix(p.name, name) {
			continue
		}
		if found {
			if match.canonName() != p.canonName() {
				return psBinding{} // ambiguous: binds to nothing
			}
			continue // another spelling of the SAME parameter
		}
		match, found = p, true
	}
	if !found {
		return psBinding{}
	}
	return psBinding{param: match, bound: true}
}

// psBinding is the outcome of binding one parameter token.
type psBinding struct {
	// param is the row the token bound to; meaningless when !bound.
	param psParam
	// bound reports that the token names a table row.
	bound bool
	// exact reports that the token spelled the parameter's FULL name
	// (or a documented alias) rather than an abbreviation.
	//
	// This distinction is load-bearing, not cosmetic. `-c` is an
	// unambiguous abbreviation of -Credential to PowerShell's own
	// binder, so the first version of this file let it swallow the
	// next token — and `start powershell -c "<persistence>"` lost its
	// entire payload and ALLOWED. An ABBREVIATION is the LAUNCHED
	// program's flag every bit as plausibly as it is the launcher's,
	// so it is never allowed to delete a token in every reading; a
	// full name is the launcher's by construction. See
	// psBindMode.looseValues.
	exact bool
}

// psParamToken splits a PowerShell parameter token into its name and,
// for the `-Name:Value` colon spelling, its inline value. It reports
// ok=false for anything that is not parameter-shaped (a positional, a
// bare "-", a negative number).
func psParamToken(t string) (name, value string, inline, ok bool) {
	if len(t) < 2 || t[0] != '-' {
		return "", "", false, false
	}
	body := t[1:]
	if body[0] >= '0' && body[0] <= '9' {
		return "", "", false, false // a negative number, not a parameter
	}
	if j := strings.IndexByte(body, ':'); j >= 0 {
		return body[:j], body[j+1:], true, true
	}
	return body, "", false, true
}

// psCollectValue returns a parameter's value tokens starting at
// argv[i], plus the index of the last token consumed.
//
// A PowerShell array literal written with spaces after its commas
// (`-ArgumentList '/Create', '/TN', 'evil'`) reaches us as SEVERAL
// lexer tokens, because the lexer splits on whitespace and drops the
// quotes. They are re-joined while a comma sits on either side of the
// seam — the only evidence of the array that survives lexing.
//
// That re-join is a GUESS about where the value ends, and join=false
// is the reading in which it was not made. It matters because a
// trailing comma is legal in an NTFS directory name and
// attacker-creatable: `Start-Process -WorkingDirectory 'C:\temp,'
// schtasks.exe -ArgumentList '/Create',…` joined `C:\temp,` with
// `schtasks.exe`, leaving no positional at all, so the resolver
// produced NO candidate and the line ALLOWED. Both readings are
// emitted (see psBindModes).
func psCollectValue(argv []string, i int, join bool) ([]string, int) {
	if i >= len(argv) {
		return nil, i - 1
	}
	vals := []string{argv[i]}
	for join && i+1 < len(argv) && (strings.HasSuffix(argv[i], ",") || strings.HasPrefix(argv[i+1], ",")) {
		i++
		vals = append(vals, argv[i])
	}
	return vals, i
}

// psSplitArguments turns collected -ArgumentList value tokens into the
// launched program's argument vector.
//
// DOCUMENTED APPROXIMATION, in the spirit of the rest of this package:
// splitting happens on commas AND whitespace. PowerShell's own rule is
// that a single string element is handed to the child process as a
// whole command-line fragment which the child then re-splits, so
// `-ArgumentList '/Create /TN evil'` and `-ArgumentList
// '/Create','/TN','evil'` reach schtasks identically. Splitting both
// gives one argv shape for the matchers. The cost is that a quoted
// path containing a space becomes two tokens; no R-155 arm depends on
// a path staying whole (the ETW carve-out does, and it deliberately
// refuses launcher-wrapped units outright — see
// safeObserverETWTaskRegistration).
//
// Array-literal syntax (`@( … )`) is peeled off each element. An
// element that is a VARIABLE (`$args`, `$e`) is kept verbatim: its
// value is statically unknowable, the same documented approximation
// ParseCommand already makes for `rm -rf $(pwd)`.
func psSplitArguments(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, part := range strings.FieldsFunc(v, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		}) {
			part = strings.TrimPrefix(part, "@(")
			part = strings.TrimPrefix(part, "(")
			part = strings.TrimSuffix(part, ")")
			part = strings.Trim(part, `'"`)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// startProcessCandidates resolves the `start` family — the
// `Start-Process` cmdlet, its aliases `saps` / `start`, and cmd.exe's
// unrelated `START` builtin, which shares the word.
//
// It returns every interpretation the argv could carry, because the
// word alone does not settle which launcher was meant: in the
// PowerShell dialect canonicalBase has ALREADY rewritten `start` to
// `start-process`, so by the time we get here a genuine `start /b
// schtasks …` is indistinguishable from the cmdlet.
//
// It emits, ALWAYS and without a discriminator:
//
//   - every Start-Process CMDLET reading the argv's ambiguities admit
//     (psBindModes), and
//   - both cmd-START operand readings (cmdStartCandidates).
//
// The deleted discriminator is the H5 round-2 bypass. It read: a
// token that binds to a Start-Process parameter settles the line as
// the cmdlet, so the cmd-START readings are not generated. `-c` binds
// -Credential and `-e` binds the agreeing -Environment /
// -ErrorAction / -ErrorVariable set, so `start powershell -c "…"` and
// `start powershell -e <base64>` "settled" as the cmdlet — and the
// surviving cmdlet reading then ate the payload as that parameter's
// value. `-a -c -d -e -f -i -l -n -o -r -u` and longer prefixes all
// did it. The same suppression turned `/`-switches into positionals
// with no cmd reading left to correct them, so `start /b crontab -e`
// resolved its program to `/b`. See the never-suppress rule above.
func startProcessCandidates(argv []string) launchResult {
	var out [][]string
	for _, m := range psBindModes(argv) {
		resolved, at := psStartProcessArgv(argv, m)
		out = append(out, resolved)
		if at > 0 {
			// THE TAIL-VERBATIM READING. Once a mode has located the
			// program token, everything after it in the ORIGINAL argv
			// is emitted untouched, alongside the reconstruction.
			//
			// It exists because reconstruction necessarily rewrites:
			// it re-groups -ArgumentList arrays, whitespace-splits a
			// single-string element the way PowerShell's child would,
			// and drops the parameters it decided were the
			// launcher's. Each of those is right for some line and
			// destructive for another, and the destructive cases are
			// not reachable by any GLOBAL flag because two tokens in
			// one line can need opposite answers: in `Start-Process
			// -w C:\x powershell -enc <b64>` the unbound `-w` must
			// swallow its value for `powershell` to be the program,
			// while the unbound `-enc` must NOT, or the payload is
			// deleted. One flag cannot say both. The verbatim tail
			// sidesteps the question entirely — it alters nothing —
			// and the reconstruction stays for the cases only it can
			// read (`schtasks.exe '/Create /TN evil'` needs the
			// whitespace split).
			out = append(out, argv[at:])
		}
	}
	out = append(out, cmdStartCandidates(argv)...)
	return launchResult{candidates: out, named: startNamesTarget(argv)}
}

// startNamesTarget reports whether the invocation carries anything
// that could name a launched program, so that resolving to NOTHING is
// distinguishable from there being nothing to resolve. `start`, `start
// /b` and `start /d C:\x` name nothing and open a shell; anything else
// named a target, and failing to recover it is a parse failure that
// must deny rather than pass silently.
func startNamesTarget(argv []string) bool {
	for i := 1; i < len(argv); i++ {
		if t := argv[i]; t != "" && t[0] != '/' {
			return true
		}
	}
	return false
}

// psBindMode selects how psStartProcessArgv resolves the places the
// cmdlet grammar is genuinely ambiguous AFTER lexing. Every field is
// a guess this file is not allowed to make on its own: a mode with
// the flag set and a mode with it clear are both generated whenever
// the argv actually contains the ambiguity, and both are analysed.
type psBindMode struct {
	// unknownValued reads a parameter token that binds to NO table
	// row (`-w`: -Wait is a switch but -WindowStyle and
	// -WorkingDirectory are valued; or a parameter this table does
	// not know) as one that swallows the next token. Read as a
	// switch instead, `-w C:\x schtasks.exe` resolves FilePath to
	// `C:\x` and hides the program; read as valued, a launched
	// program's own flag eats its own argument.
	unknownValued bool
	// looseValues lets a PREFIX-matched valued parameter swallow its
	// value. False is the reading in which only an EXACT name does —
	// so `-c`, `-e` and friends stay with the launched program
	// instead of deleting its arguments.
	looseValues bool
	// joinCommaRuns re-joins a comma-separated value run
	// (psCollectValue). False is the reading in which a value is
	// exactly one token.
	joinCommaRuns bool
}

// psBindModes returns the readings to generate for one argv: the FULL
// CROSS-PRODUCT of the ambiguities the argv actually contains.
//
// It is a cross-product and not one-flip-at-a-time because the
// property test found the combination hole immediately: `Start-Process
// -w C:\x sh -c "<payload>"` needs unknownValued (so the unbindable
// `-w` swallows `C:\x` and `sh` becomes the program) AND
// looseValues=false (so `-c` stays with `sh` instead of binding
// -Credential) — no single flip reaches it, and every host spelling in
// that family ALLOWED while each flip was generated on its own.
// Flipping one guess at a time is just a smaller enumeration.
//
// Gating on ambiguities that are PRESENT is what keeps this cheap: an
// unambiguous line still costs exactly one cmdlet reading, which is
// every benign Start-Process the suite pins. The cost of a crafted
// line is bounded twice over — maxLauncherCandidates per unit and the
// shared expansion budget across the parse — and both fail CLOSED.
func psBindModes(argv []string) []psBindMode {
	base := psBindMode{looseValues: true, joinCommaRuns: true}
	var unknown, abbreviated, commas bool
	for i := 1; i < len(argv); i++ {
		if strings.HasSuffix(argv[i], ",") || strings.HasPrefix(argv[i], ",") {
			commas = true
		}
		name, _, _, ok := psParamToken(argv[i])
		if !ok {
			continue
		}
		switch b := psResolveParam(name, psStartProcessParams); {
		case !b.bound:
			unknown = true
		case b.param.valued && !b.exact:
			abbreviated = true
		}
	}
	var flips []func(*psBindMode)
	if unknown {
		flips = append(flips, func(m *psBindMode) { m.unknownValued = true })
	}
	if abbreviated {
		flips = append(flips, func(m *psBindMode) { m.looseValues = false })
	}
	if commas {
		flips = append(flips, func(m *psBindMode) { m.joinCommaRuns = false })
	}
	modes := []psBindMode{base}
	for _, flip := range flips {
		next := make([]psBindMode, 0, len(modes)*2)
		for _, m := range modes {
			alt := m
			flip(&alt)
			next = append(next, m, alt)
		}
		modes = next
	}
	return modes
}

// psStartProcessArgv resolves the `Start-Process` CMDLET reading of an
// argv into the argv of the program it launches, under one binding
// mode.
//
// Both binding forms are honored, because both are how the cmdlet is
// really used: the named parameters (-FilePath / -ArgumentList, in any
// legal abbreviation or the `-Name:Value` spelling) and the POSITIONAL
// ones (`Start-Process <FilePath> <ArgumentList>` — positions 0 and 1).
//
// A parameter token this mode decides is NOT the launcher's is KEPT
// as an argument of the launched program rather than dropped. It has
// to be: dropping it is a deletion by another name, and it is what
// stopped `Start-Process -Verb RunAs powershell -c "crontab -e"` from
// ever reaching powershell's own -Command parsing.
func psStartProcessArgv(argv []string, m psBindMode) ([]string, int) {
	type tok struct {
		text string
		// at is the token's index in the original argv, so the caller
		// can emit the verbatim tail that begins at the program.
		at int
		// positional marks a token that is not parameter-shaped, so
		// only it may be taken as the FilePath. A kept flag keeps its
		// place in the tail but can never BE the program.
		positional bool
	}
	var (
		filePath string
		fileAt   = -1
		listArgs []string
		tail     []tok
	)
	for i := 1; i < len(argv); i++ {
		name, inlineValue, inline, ok := psParamToken(argv[i])
		if !ok {
			tail = append(tail, tok{text: argv[i], at: i, positional: true})
			continue
		}
		b := psResolveParam(name, psStartProcessParams)
		if !b.bound {
			if m.unknownValued && !inline {
				_, i = psCollectValue(argv, i+1, m.joinCommaRuns)
				continue
			}
			tail = append(tail, tok{text: argv[i], at: i})
			continue
		}
		// A token the launcher does not own EXACTLY belongs to the
		// launched program and is KEPT, never dropped. An abbreviated
		// SWITCH is unconditional here because it consumes nothing,
		// so no mode has to choose: dropping it silently deleted a
		// flag from the launched argv, and `start crontab -l` denied
		// R-155 as a bare `crontab` because `-l` prefixes
		// -LoadUserProfile. A read-only listing became a critical
		// deny through nothing but a parameter abbreviation.
		if !b.exact && !(b.param.valued && m.looseValues) {
			tail = append(tail, tok{text: argv[i], at: i})
			continue
		}
		if !b.param.valued {
			continue
		}
		var vals []string
		if inline {
			vals = []string{inlineValue}
		} else {
			vals, i = psCollectValue(argv, i+1, m.joinCommaRuns)
		}
		switch b.param.role {
		case psRoleFilePath:
			if filePath == "" && len(vals) > 0 {
				filePath, fileAt = strings.Trim(vals[0], `'"`), i
			}
		case psRoleArgumentList:
			listArgs = append(listArgs, psSplitArguments(vals)...)
		case psRoleOther:
		}
	}
	// An EMPTY positional is skipped when picking the program: it is
	// what `start "" schtasks …`'s placeholder title lexes to, and
	// taking it as the FilePath would resolve the program to nothing.
	if filePath == "" {
		for i, t := range tail {
			v := strings.Trim(t.text, `'"`)
			if !t.positional || v == "" {
				continue
			}
			filePath, fileAt = v, t.at
			tail = append(tail[:i:i], tail[i+1:]...)
			break
		}
	}
	if filePath == "" {
		return nil, -1
	}
	// EVERY remaining tail token joins the argument list, in argv
	// order, including when -ArgumentList was also named.
	// Start-Process binds at most two positionals, so a third has no
	// legal meaning — but the cmd lexer does not treat `'` as a quote
	// (correctly: cmd.exe does not either), so a single-quoted
	// PowerShell array delivered under the cmd dialect spills its tail
	// into positional slots. Folding them back in errs toward
	// analyzing MORE; dropping them lost `Start-Process cmd.exe
	// -ArgumentList '/c','schtasks /Create …'` under exactly that
	// dialect.
	texts := make([]string, 0, len(tail))
	for _, t := range tail {
		texts = append(texts, t.text)
	}
	out := make([]string, 0, 1+len(listArgs)+len(texts))
	out = append(out, filePath)
	out = append(out, listArgs...)
	out = append(out, psSplitArguments(texts)...)
	return out, fileAt
}

// --- cmd.exe START -----------------------------------------------------

// cmdStartValuedFlags are the START switches that consume a following
// token, so it is not mistaken for the program.
var cmdStartValuedFlags = map[string]bool{"/d": true, "/node": true, "/affinity": true, "/machine": true}

// cmdStartCandidates resolves cmd.exe's `START` builtin — `start
// ["title"] [/switches] program [args…]`.
//
// START treats a QUOTED first operand as the WINDOW TITLE, and our
// lexers strip quotes, so after lexing `start "My Task" schtasks
// /Create …` and `start schtasks /Create …` are the same token
// sequence. Rather than guess — guessing "the first operand is the
// program" is what let `start "x" schtasks /Create` through — BOTH
// readings are returned: the run starting at the first operand and the
// run starting at the second. At most one of them is a real program;
// the other names an argument and matches nothing.
func cmdStartCandidates(argv []string) [][]string {
	var out [][]string
	for i := 1; i < len(argv) && len(out) < 2; i++ {
		t := argv[i]
		if t == "" {
			continue // the `""` placeholder title
		}
		if t[0] == '/' {
			if cmdStartValuedFlags[strings.ToLower(t)] {
				i++
			}
			continue
		}
		out = append(out, argv[i:])
	}
	return out
}

// --- wsl.exe -----------------------------------------------------------

// wslValuedFlags are the wsl.exe options that consume a following
// token. Without them `wsl -d Ubuntu crontab evil` would resolve its
// command to `Ubuntu`.
var wslValuedFlags = map[string]bool{
	"-d": true, "--distribution": true,
	"--distribution-id": true,
	"-u":                true, "--user": true,
	"--cd": true, "--shell-type": true,
}

// wslExecFlags are the wsl.exe options after which the REST of the
// argv is the command, exactly like `--`.
var wslExecFlags = map[string]bool{"-e": true, "--exec": true, "--": true}

// wslInnerArgv resolves `wsl.exe [options] [--] <command> [args…]`
// into the Linux command it runs. The inner command is parsed under
// the POSIX dialect (the launched process is a Linux one), which is
// the launcher row's `inner` field.
//
// wsl's own grammar is unambiguous, so exactly one candidate is ever
// produced and `named` coincides with having produced it: every
// no-candidate path here is a wsl invocation that names NO command —
// an interactive `wsl`, `wsl -l -v`, a dangling `--exec` — rather
// than one we failed to read. Those must not deny, which is why
// launchResult separates the two facts instead of treating "no
// candidate" as dangerous everywhere.
func wslInnerArgv(argv []string) launchResult {
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		if t == "" || t[0] != '-' {
			return launchResult{candidates: [][]string{argv[i:]}, named: true}
		}
		low := strings.ToLower(t)
		if wslExecFlags[low] {
			if i+1 < len(argv) {
				return launchResult{candidates: [][]string{argv[i+1:]}, named: true}
			}
			return launchResult{}
		}
		if strings.ContainsRune(low, '=') {
			continue // --distribution=Ubuntu: the value is inline
		}
		if wslValuedFlags[low] && i+1 < len(argv) {
			i++
		}
	}
	return launchResult{}
}

// --- runas.exe ---------------------------------------------------------

// runasCandidates resolves Windows' `runas [/switches] "<command
// line>"` into the command it elevates.
//
// Every runas option is `/name` or `/name:value` (/user:, /noprofile,
// /profile, /env, /netonly, /savecred, /smartcard, /trustlevel:,
// /showtrustlevels) — there are no space-separated values to consume,
// so the first operand begins the command line.
//
// That command line is ONE quoted operand, which the lexers deliver as
// a single token with its spaces intact, so it is re-split on
// whitespace here. That is the same documented approximation
// psSplitArguments makes, with the same cost (a quoted path
// containing a space becomes two tokens) and the same reason: the
// matchers need an argv, and no R-155 arm depends on a path staying
// whole.
func runasCandidates(argv []string) launchResult {
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		if t == "" || t[0] == '/' {
			continue
		}
		words := strings.Fields(strings.Join(argv[i:], " "))
		return launchResult{candidates: [][]string{words}, named: true}
	}
	return launchResult{}
}

// --- container exec (docker / podman / nerdctl / docker-compose) -------

// dockerExecValuedFlags are the `docker exec` / `docker compose exec` options
// that consume a FOLLOWING token, so a launched program's own operand is not
// mistaken for one (SH-2, SA-6): -u/-w/-e and their long spellings, --env-file,
// --detach-keys (docker), --preserve-fds / --preserve-fd (podman) and --index
// (compose). A missing valued flag shifts the operand, which is exactly the
// SH-2 bypass.
var dockerExecValuedFlags = map[string]bool{
	"-u": true, "--user": true,
	"-w": true, "--workdir": true,
	"-e": true, "--env": true, "--env-file": true,
	"--detach-keys":  true,
	"--preserve-fds": true, "--preserve-fd": true,
	"--index": true,
}

// dockerExecSwitchFlags are the `docker exec` options that consume NOTHING,
// so a short cluster made only of them (`-it`, `-ti`) is a switch too
// (shortSwitchCluster). An exec flag that is neither valued nor a known
// switch is UNKNOWN: both readings are emitted (containerExecInner), never
// guessed, per launcher.go's never-suppress rule.
var dockerExecSwitchFlags = map[string]bool{
	"-i": true, "-t": true, "-d": true,
	"--interactive": true, "--tty": true, "--detach": true, "--privileged": true,
}

// dockerExecNoOperandFlags are the `podman exec` options after which there is
// NO container operand — the command begins immediately (SA-6: `-l` /
// `--latest` run in the most-recent container).
var dockerExecNoOperandFlags = map[string]bool{"-l": true, "--latest": true}

// globalFlagTable is one tool's GLOBAL option set (the options it accepts
// BEFORE its subcommand), split by whether an option consumes the following
// token (SH-1). Short options are matched CASE-SENSITIVELY (docker's `-H` is
// --host and its `-h` is --help); long options are matched lower-cased.
//
// BOTH halves must be right, because either mistake hides `exec`: a switch
// listed as valued swallows the subcommand word (`--remote exec` would read
// `exec` as a value), and a valued option listed as a switch leaves its
// value standing in the subcommand slot. So a row is added only when it is
// grounded in the tool's own help; anything else stays UNKNOWN and fails
// closed (skipGlobalFlags → ambiguousExec → R-157).
type globalFlagTable struct {
	valued   map[string]bool
	switches map[string]bool
}

// dockerGlobalFlags is the docker / podman / nerdctl global option set.
// Grounded against `docker --help` (Docker Desktop, 2026-11-08): valued
// --config, -c/--context, -H/--host, -l/--log-level, --tlscacert, --tlscert,
// --tlskey; switches -D/--debug, --tls, --tlsverify, -v/--version (and the
// -h/--help every cobra CLI has). podman's -r/--remote and nerdctl's
// --debug-full / --insecure-registry are switches per those tools' docs (not
// installed here, so not checked against a live binary). One table serves all
// three because none of these rows disagrees between them.
var dockerGlobalFlags = globalFlagTable{
	valued: setOf("--config", "-c", "--context", "-H", "--host", "-l", "--log-level",
		"--tlscacert", "--tlscert", "--tlskey"),
	switches: setOf("-D", "--debug", "--tls", "--tlsverify", "-v", "--version", "-h", "--help",
		"-r", "--remote", "--debug-full", "--insecure-registry"),
}

// composeGlobalFlags is the compose global option set (after the `compose`
// word, or on the `docker-compose` binary). Grounded against `docker compose
// --help` / `docker-compose --help` (compose v2): valued --ansi, --env-file,
// -f/--file, --parallel, --profile, --progress, --project-directory,
// -p/--project-name; switches --all-resources, --compatibility, --dry-run.
// --verbose is compose v1's switch (absent from the v2 help) and -h/--help is
// cobra's.
var composeGlobalFlags = globalFlagTable{
	valued: setOf("--ansi", "--env-file", "-f", "--file", "--parallel", "--profile",
		"--progress", "--project-directory", "-p", "--project-name"),
	switches: setOf("--all-resources", "--compatibility", "--dry-run", "--verbose", "-h", "--help"),
}

// dockerExecResolver / composeExecResolver select the global-flag region a
// base starts in: a bare `docker` / `podman` / `nerdctl` has docker globals
// then optionally the `container` / `compose` grouping word, while the
// `docker-compose` binary is already inside compose.
func dockerExecResolver(argv []string) launchResult  { return containerExecCandidates(argv, false) }
func composeExecResolver(argv []string) launchResult { return containerExecCandidates(argv, true) }

// containerExecCandidates resolves `docker exec`, `docker container exec`,
// `docker [globals] compose [globals] exec <svc>`, `docker-compose exec <svc>`
// (and the podman / nerdctl spellings) into the command run inside the
// container.
//
// `docker run image cmd` is deliberately NOT handled: it starts a NEW
// container from an image, not a command in a running one, and the image's
// own entrypoint muddies what "the command" even is — out of scope by the
// brief. A non-exec docker invocation therefore names nothing and denies
// nothing (named=false). A bare `docker exec -it ctr` with no command is the
// same: it opens an interactive shell, which names no command to analyse.
//
// SH-1: a GLOBAL option before the subcommand is skipped (skipGlobalFlags).
// An UNKNOWN global dashed token before a recognisable `exec` could be a
// valued flag whose value is the subcommand, so `exec` cannot be located and
// the unit fails closed (ambiguousExec → Unanalyzed → R-157).
func containerExecCandidates(argv []string, composeBinary bool) launchResult {
	i := 1
	compose := composeBinary
	if !composeBinary {
		var ambiguous bool
		if i, ambiguous = skipGlobalFlags(argv, i, dockerGlobalFlags); ambiguous {
			return ambiguousExec(argv, i)
		}
		if i < len(argv) {
			switch strings.ToLower(argv[i]) {
			case "container":
				i++
			case "compose":
				i++
				compose = true
			}
		}
	}
	if compose {
		var ambiguous bool
		if i, ambiguous = skipGlobalFlags(argv, i, composeGlobalFlags); ambiguous {
			return ambiguousExec(argv, i)
		}
	}
	if i >= len(argv) || strings.ToLower(argv[i]) != "exec" {
		return launchResult{} // not an exec: nothing to launch
	}
	i++ // past `exec`
	candidates := containerExecInner(argv, i, dockerExecValuedFlags, dockerExecSwitchFlags, dockerExecNoOperandFlags)
	if len(candidates) == 0 {
		// Flags only, or a container with no command (interactive shell):
		// nothing to analyse, and nothing dangerous to miss.
		return launchResult{}
	}
	return launchResult{candidates: candidates, named: true}
}

// skipGlobalFlags skips a tool's GLOBAL options (before its subcommand)
// starting at i, using the tool's globalFlagTable (SH-1). Per token:
//
//   - a non-dashed token is the subcommand: stop;
//   - `--` ends the option region;
//   - `--flag=value` / `-f=value` carries its value inline and can never hide
//     the subcommand, so it is skipped whether or not the table knows it;
//   - a known valued option consumes the following token;
//   - a known switch consumes nothing;
//   - a short valued option with its value ATTACHED (`-v6`, `-nprod`, the
//     pflag/getopt form) is self-contained;
//   - anything else is UNKNOWN: it could be a valued option whose value is
//     the subcommand, so ambiguous=true and the caller fails closed when an
//     `exec` follows.
func skipGlobalFlags(argv []string, i int, tbl globalFlagTable) (int, bool) {
	for i < len(argv) {
		t := argv[i]
		if t == "" || t[0] != '-' {
			return i, false
		}
		if t == "--" {
			return i + 1, false
		}
		if strings.IndexByte(t, '=') >= 0 {
			i++ // inline value: cannot shift the subcommand
			continue
		}
		key := globalFlagKey(t)
		switch {
		case tbl.valued[key]:
			i += 2 // option + its value token
		case tbl.switches[key]:
			i++
		case len(t) > 2 && t[1] != '-' && tbl.valued[t[:2]]:
			i++ // short option with its value attached (`-v6`)
		default:
			return i, true // unknown: fail closed if exec follows
		}
	}
	return i, false
}

// globalFlagKey is the lookup spelling of an option token: a long option
// (`--Context`) lower-cased, a short one (`-H` vs `-h`) exactly as typed,
// because short options are case-sensitive in every CLI these tables cover.
func globalFlagKey(t string) string {
	if strings.HasPrefix(t, "--") {
		return strings.ToLower(t)
	}
	return t
}

// ambiguousExec is the SH-1 fail-closed arm: when the global-flag region
// could not be resolved, the unit is Unanalyzed (→ R-157) only if a
// recognisable `exec` still appears — otherwise the line is not a container
// exec at all and must not deny.
func ambiguousExec(argv []string, i int) launchResult {
	for j := i; j < len(argv); j++ {
		if strings.ToLower(argv[j]) == "exec" {
			return launchResult{named: true} // exec present but uncovered: deny
		}
	}
	return launchResult{} // no exec: not a container exec, nothing to launch
}

// containerExecInner resolves the region AFTER `exec` into every argv the
// launched command could be (SH-2, SA-6). It walks the exec-flag region and:
//
//   - a valued flag consumes its following token;
//   - a known switch (or a short cluster of them) consumes nothing;
//   - a no-operand flag (`-l` / `--latest`) means the command begins right
//     after the flags, with NO container operand;
//   - an UNKNOWN dashed token forks BOTH readings — the switch reading and
//     the valued reading — because a missing valued flag shifts the operand
//     (the never-suppress rule); dedup and maxLauncherCandidates bound it.
//
// A reading that reaches no command contributes nothing (an interactive
// `exec`); when none do, the caller treats it as "no command to analyse".
func containerExecInner(argv []string, start int, valued, switches, noOperand map[string]bool) [][]string {
	type frame struct {
		i      int
		latest bool
	}
	var out [][]string
	seen := make(map[int]bool)
	stack := []frame{{start, false}}
	for len(stack) > 0 && len(out) <= maxLauncherCandidates {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		j, latest := f.i, f.latest
		for j < len(argv) {
			t := argv[j]
			if t == "" || t[0] != '-' {
				break // the container operand, or (with --latest) the command
			}
			if t == "--" {
				j++
				break
			}
			low := strings.ToLower(t)
			if eq := strings.IndexByte(low, '='); eq >= 0 {
				j++ // `--flag=value`: self-contained
				continue
			}
			switch {
			case noOperand[low]:
				latest = true
				j++
			case valued[low]:
				j += 2
			case switches[low] || shortSwitchCluster(low, switches):
				j++
			default:
				// Unknown dashed: emit both readings. The valued reading
				// skips this flag AND the next token; the switch reading
				// skips only this flag.
				stack = append(stack, frame{j + 2, latest})
				j++
			}
		}
		cmdStart := j
		if !latest {
			cmdStart = j + 1 // skip the container / pod operand
		}
		if cmdStart < len(argv) && !seen[cmdStart] {
			seen[cmdStart] = true
			out = append(out, argv[cmdStart:])
		}
	}
	return out
}

// shortSwitchCluster reports whether a single-dash token is a cluster made
// ENTIRELY of known switch letters (`-it`, `-ti`), so it consumes nothing.
func shortSwitchCluster(low string, switches map[string]bool) bool {
	if len(low) < 2 || low[0] != '-' || low[1] == '-' {
		return false
	}
	for k := 1; k < len(low); k++ {
		if !switches["-"+string(low[k])] {
			return false
		}
	}
	return true
}

// --- kubectl / oc exec -------------------------------------------------

// kubectlExecValuedFlags are the `kubectl exec` options (AFTER `exec`) that
// consume a following token: -n/-c and their long spellings, --context, and
// --pod-running-timeout (SH-2 — its legacy no-`--` form otherwise reads the
// timeout value as the pod and the pod as the command).
var kubectlExecValuedFlags = map[string]bool{
	"-n": true, "--namespace": true,
	"-c": true, "--container": true,
	"--context": true, "--pod-running-timeout": true,
}

// kubectlExecSwitchFlags are the `kubectl exec` options that consume nothing;
// an exec flag that is neither valued nor a known switch is UNKNOWN and forks
// both readings (containerExecInner).
var kubectlExecSwitchFlags = map[string]bool{
	"-i": true, "-t": true,
	"--stdin": true, "--tty": true, "-q": true, "--quiet": true,
}

// kubectlGlobalFlags is the kubectl / oc global option set (before `exec`).
// Grounded against `kubectl options` (Docker Desktop's kubectl, 2026-11-08):
// every non-boolean option there is valued — note -v/--v (the log level,
// `-v 6` / `-v=6`) is VALUED here, unlike docker's -v/--version switch — and
// the four booleans are switches (pflag booleans never consume a following
// token; `--insecure-skip-tls-verify=false` uses the inline form). -h/--help
// is cobra's. oc is not installed here; it shares kubectl's global set.
var kubectlGlobalFlags = globalFlagTable{
	valued: setOf("--as", "--as-group", "--as-uid", "--cache-dir", "--certificate-authority",
		"--client-certificate", "--client-key", "--cluster", "--context", "--kubeconfig", "--kuberc",
		"--log-flush-frequency", "-n", "--namespace", "--password", "--profile", "--profile-output",
		"--request-timeout", "-s", "--server", "--tls-server-name", "--token", "--user", "--username",
		"-v", "--v", "--vmodule"),
	switches: setOf("--disable-compression", "--insecure-skip-tls-verify", "--match-server-version",
		"--warnings-as-errors", "-h", "--help"),
}

// kubectlExecCandidates resolves `kubectl [globals] exec [flags] <pod> -- <cmd…>`
// and the legacy `kubectl exec [flags] <pod> <cmd…>` form without the `--`
// terminator (oc shares the grammar). GLOBAL options before `exec` are
// skipped (SH-1); an unknown one fails closed (ambiguousExec). When a `--` is
// present everything after it is the command verbatim; otherwise exec's own
// flags are resolved (both readings for an unknown, SH-2), the first
// positional is the pod and the rest is the command.
func kubectlExecCandidates(argv []string) launchResult {
	i := 1
	var ambiguous bool
	if i, ambiguous = skipGlobalFlags(argv, i, kubectlGlobalFlags); ambiguous {
		return ambiguousExec(argv, i)
	}
	if i >= len(argv) || strings.ToLower(argv[i]) != "exec" {
		return launchResult{}
	}
	i++ // past `exec`
	// A `--` terminator: the remote command is everything after it.
	for j := i; j < len(argv); j++ {
		if argv[j] == "--" {
			if j+1 < len(argv) {
				return launchResult{candidates: [][]string{argv[j+1:]}, named: true}
			}
			return launchResult{} // `--` with nothing after it
		}
	}
	// Legacy form: skip exec's own flags (kubectl has no --latest), then the
	// pod operand; the rest is the command.
	candidates := containerExecInner(argv, i, kubectlExecValuedFlags, kubectlExecSwitchFlags, nil)
	if len(candidates) == 0 {
		return launchResult{} // no command: an interactive/attach shell
	}
	return launchResult{candidates: candidates, named: true}
}

// --- ssh ---------------------------------------------------------------

// sshValuedFlags are the ssh options that take a value (the brief's set).
// ssh uses getopt single-dash options only, so the value may be attached
// (`-p22`) or the next token (`-p 22`); the rest are switches. A valued flag
// ends an option cluster.
var sshValuedFlags = map[byte]bool{
	'p': true, 'l': true, 'i': true, 'o': true, 'F': true, 'J': true,
	'L': true, 'R': true, 'D': true, 'b': true, 'c': true, 'E': true,
	'e': true, 'I': true, 'm': true, 'O': true, 'Q': true, 'S': true,
	'W': true, 'w': true, 'B': true, 'P': true,
}

// sshRemoteCommand resolves `ssh [options] destination [options] [command…]`
// into the remote command line it runs. ssh joins the trailing args with
// spaces and hands them to the REMOTE shell, so the launcher row is
// reparse=true and the joined candidate is re-parsed as a POSIX command line.
//
// SA-5: OpenSSH keeps reading options AFTER the destination (`ssh host -t cmd`,
// `ssh host -o BatchMode=yes cmd`) unless a `--` has ended them, so the option
// scan runs again past the destination — honouring `--`. A bare interactive
// `ssh host` (no command) names nothing and must not deny; so does `ssh` with
// only options. Only a destination FOLLOWED by a command produces a candidate.
func sshRemoteCommand(argv []string) launchResult {
	i, ended := skipSSHFlagsTracked(argv, 1)
	if i >= len(argv) {
		return launchResult{} // no destination
	}
	i++ // the destination operand (user@host / host)
	if !ended {
		// Options are re-read after the destination until `--` or the command.
		i, _ = skipSSHFlagsTracked(argv, i)
	}
	if i >= len(argv) {
		return launchResult{} // interactive login: no remote command
	}
	return launchResult{candidates: [][]string{argv[i:]}, named: true}
}

// skipSSHFlags advances past ssh's own options starting at i and returns the
// next index. It is the host-resolution entry used by the network rules;
// sshRemoteCommand wants the extra `--`-ended fact, so both share one
// implementation (skipSSHFlagsTracked).
func skipSSHFlags(argv []string, i int) int {
	next, _ := skipSSHFlagsTracked(argv, i)
	return next
}

// skipSSHFlagsTracked advances past ssh's own options starting at i, returning
// the next index and whether a `--` ended the options (OpenSSH then stops
// reading options, so sshRemoteCommand must not re-scan past the destination).
// A token is an option cluster of single letters; the first valued letter in a
// cluster takes the remainder of the token as its value, or the next token
// when the letter ends the cluster (getopt).
func skipSSHFlagsTracked(argv []string, i int) (next int, endedByDashDash bool) {
	for i < len(argv) {
		t := argv[i]
		if len(t) < 2 || t[0] != '-' {
			break
		}
		if t == "--" {
			return i + 1, true
		}
		consumesNext := false
		for k := 1; k < len(t); k++ {
			if sshValuedFlags[t[k]] {
				// Attached value (`-p22`) stays in this token; a bare
				// valued letter at the cluster's end takes the next token.
				consumesNext = k == len(t)-1
				break
			}
		}
		i++
		if consumesNext && i < len(argv) {
			i++
		}
	}
	return i, false
}
