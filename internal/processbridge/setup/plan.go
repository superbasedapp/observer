package setup

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/processobs/bridge"
)

// TaskName is the Windows Scheduled Task that runs the ELEVATED
// ETW capturer (`observer process-bridge --etw --connect …`).
//
// FROZEN LITERAL. The name is the contract between this setup surface, the
// operator's own `schtasks /Query`, and every diagnostic that reports whether
// the elevated feed is installed. Renaming it silently orphans a task the
// operator already created — a rename would need a migration, not an edit.
const TaskName = "SuperBasedObserverETW"

// Outcome is what the setup step concluded. It exists so the
// decision (pure, table-tested) is separable from the printing.
type Outcome int

const (
	// OutcomeSkip prints NOTHING: either the ETW listener is not
	// enabled, or this host has no schtasks.exe (a plain Linux/macOS box).
	// Silence is the honest output — there is no Windows task to talk about.
	OutcomeSkip Outcome = iota
	// OutcomePresent means `schtasks /Query` found the task. Report
	// and stop: no reconfiguration, no duplicate.
	OutcomePresent
	// OutcomeManual means the task is absent and we emit the exact
	// elevated command for the operator to run once.
	OutcomeManual
	// OutcomeUnknown means the probe itself failed for a reason
	// other than "not found" — we say so, and still emit the command with an
	// explicit "if it is absent" caveat rather than guessing either way.
	OutcomeUnknown
	// OutcomeBlocked means the command cannot be composed with
	// everything resolved (no Windows observer.exe, no distro name, …). We
	// name the exact missing dependency instead of printing a placeholder.
	OutcomeBlocked
)

// Probe is the tri-state result of `schtasks /Query /TN …`.
// "Unknown" is a first-class state on purpose: an access error or a broken
// interop shell must not be reported as "the task does not exist".
type Probe int

const (
	// ProbeUnknown — the probe failed for a reason other than
	// "not found", or was never run.
	//
	// IT IS THE ZERO VALUE ON PURPOSE. Absent is the state that makes the step
	// emit a `/Create` command, so a forgotten assignment must NOT land there:
	// the safe default for "nobody told us" is "we do not know", which prints
	// the same command under an explicit "run it only if the task is absent"
	// caveat. Do not reorder these to put Absent first.
	ProbeUnknown Probe = iota
	// ProbeAbsent — schtasks answered "cannot find".
	ProbeAbsent
	// ProbePresent — schtasks exited 0 (the task exists).
	ProbePresent
)

// Inputs is everything the planner needs, already resolved by
// the caller. Keeping it a plain struct is what makes PlanTask
// pure: no exec, no filesystem, no environment.
type Inputs struct {
	// Enabled reports whether the elevated ETW feed can actually RUN on this
	// daemon: the conjunction of BOTH switches, ProcessEnabled AND ETWEnabled.
	//
	// It is a conjunction rather than a mirror of [observer.process.etw] alone
	// because the master switch gates the whole subsystem — with it off,
	// runProcessObserver returns before any backend or accept listener is
	// constructed, so a task registered against it would reconnect forever
	// against nothing. Everything the planner decides ("is there a feed to set
	// up?") is a question about the conjunction; only the operator-facing
	// WORDING needs to know which of the two is off, which is what the two
	// fields below are for.
	Enabled bool
	// ProcessEnabled mirrors [observer.process].enabled — the master switch
	// for the whole process-observability subsystem.
	ProcessEnabled bool
	// ETWEnabled mirrors [observer.process.etw].enabled — the accept listener
	// the elevated Windows capturer dials into.
	ETWEnabled bool
	// SchtasksPath is the resolved schtasks.exe, or "" when it is not on PATH
	// (i.e. not a Windows host and not WSL with interop).
	SchtasksPath string
	// Probe is the result of the read-only `schtasks /Query /TN <name>`.
	Probe Probe
	// ProbeErr carries the reason when Probe is Unknown.
	ProbeErr string
	// WindowsObserver is the Windows-side observer.exe as the DAEMON sees it
	// (a /mnt/… path under WSL, a native path on Windows); "" = unresolved.
	WindowsObserver string
	// WindowsObserverHint is the path the operator CONFIGURED for that binary
	// (config key first, then the env var), verbatim and untranslated. It is
	// carried separately because bridge.ResolveWindowsObserver collapses "you
	// configured nothing" and "what you configured does not exist" into the
	// same ("", false) — and those two need OPPOSITE advice. "" = neither the
	// config key nor the env var was set.
	WindowsObserverHint string
	// WindowsObserverHintSource names where WindowsObserverHint came from, so
	// the blocked message points at the key the operator actually set rather
	// than at the pair of them.
	WindowsObserverHintSource string
	// ListenAddr is [observer.process.etw].listen_addr as configured.
	ListenAddr string
	// TokenPath is the daemon-side path of the shared token file.
	TokenPath string
	// Distro is $WSL_DISTRO_NAME, needed to build the \\wsl.localhost UNC
	// path for a WSL-native token file. "" when unknown.
	Distro string
	// WindowsUser is the current Windows login name (crossmount.WindowsUserName),
	// used only for the "which account must own the task" note. "" = unknown.
	WindowsUser string
	// HostIsWindows is true when the daemon itself runs on Windows, where
	// every path is already Windows-shaped and no translation applies.
	HostIsWindows bool
}

// Plan is the planner's verdict: what to say, and the exact
// command to say it with.
type Plan struct {
	// Outcome selects the message shape.
	Outcome Outcome
	// Command is the fully-resolved elevated schtasks line (Manual/Unknown).
	Command string
	// SchtasksArgs is EXACTLY the tail of Command — everything after
	// `schtasks.exe ` — carried separately so the dashboard's elevation broker
	// can hand those same bytes to a child process without re-deriving (and
	// therefore without re-deciding) the quoting.
	//
	// It exists because the /TR quoting is measured, not obvious (see
	// TaskCommand), and a second builder would be a second owner of it. One
	// string, one owner: the copyable command an operator pastes and the argv
	// the broker spawns are the same bytes by construction.
	//
	// Empty in every outcome that has no command (Skip / Present / Blocked).
	SchtasksArgs string
	// Reason names the exact missing dependency (Blocked) or the probe
	// failure (Unknown). Never vague — it is what the operator must fix.
	Reason string
	// CmdShellOnly marks a Command that parses in cmd.exe but NOT in
	// PowerShell (a token path containing a space forces the escaped form).
	// The printer must then name the shell instead of saying "either".
	CmdShellOnly bool
	// Notes are per-plan caveats (account ownership, UNC readability).
	Notes []string
}

// PlanTask decides what `observer init` should tell the operator
// about the elevated ETW Scheduled Task. Pure: every input is resolved by the
// caller, so the whole decision table is unit-testable without ever touching a
// real schtasks.exe.
//
// It NEVER attempts to create the task. That is not a stylistic choice: the
// WSL interop token is Medium Mandatory Level with BUILTIN\Administrators
// present "for deny only", and `schtasks /Create /SC ONLOGON` — with or
// without /RL HIGHEST — is refused with "Access is denied" (measured
// 2026-07-26 on the reference host). Elevation cannot be self-granted from
// WSL, so the only honest surface is an exact, copy-paste-ready command.
func PlanTask(in Inputs) Plan {
	// Gate 1: the feed is opt-in, and "on" means BOTH switches (Inputs.Enabled
	// is their conjunction). Nothing to say when it is off — with ONE
	// exception, below, where silence would hide a config that reads as
	// enabled and does nothing.
	// Gate 2: no schtasks.exe ⇒ no Windows Scheduled Tasks on this host at
	// all. A pure Linux/macOS box is a CLEAN SILENT SKIP, not a warning:
	// there is no missing dependency, the feature simply does not apply.
	if !in.Enabled || in.SchtasksPath == "" {
		p := Plan{Outcome: OutcomeSkip}
		if in.ETWEnabled && !in.ProcessEnabled {
			// The operator switched the ETW feed ON and the master switch is
			// OFF. That combination LOOKS enabled and captures nothing: the
			// subsystem that builds the accept listener is never started, so
			// an elevated capturer would reconnect forever against nothing.
			// Same call as selectProcessBackend's `backend = "etw"` warning —
			// a config that asks for a feed it cannot get is told so.
			p.Reason = "[observer.process.etw].enabled is true but [observer.process].enabled is false, " +
				"so the whole process-capture subsystem - the listener an elevated capturer dials into " +
				"included - is never started. Set [observer.process].enabled = true as well."
		}
		return p
	}
	// Idempotence: an existing task is reported and left completely alone —
	// no reconfiguration, no second task, no /F overwrite.
	if in.Probe == ProbePresent {
		return Plan{Outcome: OutcomePresent}
	}

	// The binary did not resolve at all. Two DIFFERENT operator actions hide
	// behind that one empty string, so we say which: telling someone to set a
	// key they already set is a dead end, and the honest-disabled-copy rule is
	// that the message names the exact missing dependency.
	if strings.TrimSpace(in.WindowsObserver) == "" {
		return Plan{
			Outcome: OutcomeBlocked,
			Reason:  unresolvedBinaryReason(in.WindowsObserverHint, in.WindowsObserverHintSource),
		}
	}
	exe, err := WindowsPath(in.WindowsObserver, in.Distro, in.HostIsWindows)
	if err != nil {
		return Plan{
			Outcome: OutcomeBlocked,
			Reason: fmt.Sprintf("the Windows observer.exe resolved to %q, which is not reachable from Windows (%v) — "+
				"set [observer.process].windows_binary_path (or $OBSERVER_WINDOWS_BINARY) "+
				"to a Windows-side observer.exe and re-run", in.WindowsObserver, err),
		}
	}
	token, err := WindowsPath(in.TokenPath, in.Distro, in.HostIsWindows)
	if err != nil {
		return Plan{
			Outcome: OutcomeBlocked,
			Reason: fmt.Sprintf("the shared-token file path is not reachable from Windows (%v) — "+
				"set [observer.process.etw].token_path to a path the elevated task can open", err),
		}
	}

	addr := ConnectAddr(in.ListenAddr)
	// LAST GATE BEFORE COMPOSITION. Everything above resolved values; this
	// checks that the three of them can be placed in the /TR action string
	// without changing its meaning. A value that cannot is BLOCKED with the
	// offending character named — never quietly emitted, because the failure
	// mode of the alternative is a task that runs the wrong program (or an
	// elevated schtasks that sees an argument nobody wrote). See
	// validateActionValue.
	for _, v := range []struct {
		what, value string
		addrLike    bool
	}{
		{"the Windows observer.exe path", exe, false},
		{"the shared-token file path", token, false},
		{"the capturer connect address ([observer.process.etw].listen_addr)", addr, true},
	} {
		if err := validateActionValue(v.value, v.addrLike); err != nil {
			return Plan{
				Outcome: OutcomeBlocked,
				Reason: fmt.Sprintf("%s (%q) %v, so no elevated command could be composed from it - "+
					"point it at a path without that character and re-run", v.what, v.value, err),
			}
		}
	}

	args, cmdOnly := TaskArgs(exe, addr, token)
	plan := Plan{
		Outcome:      OutcomeManual,
		Command:      SchtasksExe + " " + args,
		SchtasksArgs: args,
		CmdShellOnly: cmdOnly,
	}
	// Only an EXPLICIT Absent authorises the unhedged "the task is not
	// registered" wording. Everything else — Unknown, or a value nobody set —
	// gets the hedged form, which is why Unknown is the zero value of the
	// tri-state: the default must be "we do not know", never "it is missing".
	if in.Probe != ProbeAbsent {
		plan.Outcome = OutcomeUnknown
		plan.Reason = in.ProbeErr
		if strings.TrimSpace(plan.Reason) == "" {
			plan.Reason = "the read-only /Query probe did not run"
		}
	}
	plan.Notes = append(TaskNotes(token, in.WindowsUser), composedCommandNotes(args)...)
	return plan
}

// validateActionValue reports why a resolved value cannot be placed in the /TR
// action string without changing what that string MEANS.
//
// The composed line has three nested grammars — PowerShell's parser (or
// cmd.exe's, when pasted), schtasks' own argv parsing, and the action string
// schtasks stores for Task Scheduler — and the quoting in TaskArgs is measured
// against all three. That quoting is safe for every character EXCEPT the ones
// below, which do not merely look odd: they end a quoted region early. The
// honest answer for them is a refusal that names the character, not a command
// that mis-parses on the operator's machine minutes later under elevation.
//
// It is deliberately a SHORT closed list of characters that BREAK the grammar,
// not an allow-list of "normal" paths: a Linux-side path (which is what the WSL
// daemon resolves before translating) may legally contain almost anything, and
// refusing a working install for tidiness would be the worse error.
//
// addrLike additionally forbids whitespace: the connect address is emitted BARE
// (it is never quoted — a host:port has no reason to be), so a space in it
// would split one argument into two. ConnectAddr echoes an unparseable
// listen_addr back verbatim, which is exactly how a stray space gets here.
func validateActionValue(v string, addrLike bool) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("is empty")
	}
	if strings.Contains(v, `"`) {
		// Illegal in a Windows file name to begin with, so this can only be a
		// WSL-side path or a hand-set config value — and it would terminate
		// the /TR value early, handing everything after it to schtasks as
		// further arguments.
		return errors.New(`contains a double quote, which would end the /TR value early and turn the rest ` +
			`of the path into arguments to schtasks itself`)
	}
	if strings.HasSuffix(v, `\`) {
		// A trailing backslash lands immediately before the closing quote of
		// the escaped (cmd.exe) form, where the C runtime reads the pair as an
		// escaped backslash and the quote stops closing anything.
		return errors.New(`ends with a backslash, which escapes the quote that closes it ` +
			`(neither a program nor the token file is a directory)`)
	}
	for _, r := range v {
		// Tab is allowed: TaskArgs already treats it as space-like and quotes
		// around it, and it survives the quoted forms. Every other control
		// character would break the single-line command outright.
		if r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains the control character %q, which cannot survive a single-line command", r)
		}
	}
	if addrLike && strings.ContainsAny(v, " \t") {
		return errors.New("contains whitespace; it is emitted unquoted, so it would split into two arguments " +
			"(set [observer.process.etw].listen_addr to a plain host:port)")
	}
	return nil
}

// schtasksTaskRunLimit is the documented ceiling on the /TR value: Microsoft's
// `schtasks create` reference states "The path name must not exceed 262
// characters". Community reports read the cap as covering the whole /TR string
// (program plus arguments) rather than the path alone.
//
// WHICH READING IS RIGHT HAS NOT BEEN MEASURED HERE, and that is why exceeding
// it produces a NOTE and not a refusal: blocking a setup that might work fine
// on the operator's build would be inventing a limit, while staying silent
// would leave them staring at a schtasks error with no idea it is a length
// problem. The note names the documented number and what to shorten.
const schtasksTaskRunLimit = 262

// composedCommandNotes returns the caveats that are properties of the COMPOSED
// command rather than of the host — the two things about the emitted line an
// operator cannot see by reading it.
func composedCommandNotes(args string) []string {
	var notes []string
	if action, ok := taskRunValue(args); ok && len(action) > schtasksTaskRunLimit {
		notes = append(notes, fmt.Sprintf(
			"the /TR value is %d characters. Microsoft documents a %d-character ceiling on it, so schtasks may\n"+
				"    refuse this line with an invalid-argument error. If it does, shorten it: point\n"+
				"    [observer.process.etw].token_path at a shorter path, or put observer.exe somewhere shorter\n"+
				"    and set [observer.process].windows_binary_path to it.",
			len(action), schtasksTaskRunLimit,
		))
	}
	if strings.Contains(args, "%") {
		notes = append(notes,
			"a path in this command contains a %. Pasting it into COMMAND PROMPT expands %…% as an\n"+
				"    environment variable before schtasks ever sees it, so use the dashboard button or\n"+
				"    PowerShell. Whether Task Scheduler ALSO expands the stored action when it runs has not\n"+
				"    been measured here - read the stored action back and check it says what you expect:\n"+
				"    schtasks.exe /Query /TN \""+TaskName+"\" /V /FO LIST")
	}
	return notes
}

// taskRunValue extracts the /TR value out of a composed argument tail, so the
// length note measures the thing the limit applies to rather than the whole
// line. ok=false when the tail is not the shape TaskArgs produces.
func taskRunValue(args string) (string, bool) {
	const marker = `/TR "`
	i := strings.Index(args, marker)
	if i < 0 {
		return "", false
	}
	rest := args[i+len(marker):]
	if !strings.HasSuffix(rest, `"`) {
		return "", false
	}
	return strings.TrimSuffix(rest, `"`), true
}

// unresolvedBinaryReason explains WHY there is no Windows
// observer.exe, in the operator's own terms.
//
// bridge.ResolveWindowsObserver returns ("", false) both when nothing was
// configured and when the configured path does not exist — and the fix for
// those is not the same. Reporting "empty path" for a path the operator
// explicitly set sends them to re-set the very key they already set (measured
// on the reference host with a nonexistent windows_binary_path). So the
// configured-but-missing branch NAMES the path it tried.
func unresolvedBinaryReason(hint, source string) string {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		return "no Windows observer.exe is configured, and none was found next to the daemon " +
			"binary or under ./bin - set [observer.process].windows_binary_path " +
			"(or $OBSERVER_WINDOWS_BINARY) to the Windows-side observer.exe and re-run"
	}
	if source == "" {
		source = "[observer.process].windows_binary_path"
	}
	return fmt.Sprintf("the Windows observer.exe configured in %s (%q) does not exist - "+
		"point it at a Windows-side observer.exe this daemon can read "+
		"(a /mnt/… or C:\\… path) and re-run", source, hint)
}

// TaskArgs renders the ARGUMENT TAIL of the elevated `schtasks /Create` line —
// everything TaskCommand puts after `schtasks.exe `.
//
// It is the SINGLE OWNER of the quoting documented below. TaskCommand is a
// one-line wrapper over it, and the dashboard's elevation broker
// (ElevatedRegisterArgv) hands this exact string to a child process. That is
// what keeps the two surfaces byte-identical: the line an operator pastes into
// an elevated shell and the line the broker gives schtasks.exe come from one
// call, so the measured /TR quoting cannot drift between them.
//
// TRIGGER CHOICE — /SC ONLOGON + /RL HIGHEST:
//   - ONLOGON, because the capturer is a long-lived daemon-shaped process that
//     must be running before the AI tools it observes are; it retries its
//     connection forever, so starting before the WSL daemon is harmless.
//   - /RL HIGHEST, because ETW session control (StartTraceW) ALWAYS requires
//     elevation — a non-elevated capturer gets ERROR_ACCESS_DENIED and falls
//     back to poll-only capture. A Task Scheduler task launched at HIGHEST
//     runs with the account's full token and shows NO UAC consent dialog,
//     which a Startup-folder shortcut cannot do.
//
// NO /RU, deliberately: schtasks creates the task in the context of the
// account that runs it, which under an elevated shell is the operator's own
// account — and it MUST be their own account, because the token file is
// commonly read over \\wsl.localhost, a per-user share that SYSTEM cannot
// reach. Passing /RU for another account also drags in /RP. The account the
// task must belong to is named in the notes instead.
//
// NO /F, deliberately: this command is only ever emitted when the task is
// ABSENT, and without /F schtasks refuses to clobber a task that appeared in
// the meantime. Updating an existing task is an explicit `/F` the operator
// types themselves.
//
// QUOTING — SINGLE quotes around the program path, and the reason is measured
// (2026-07-26, with a deliberately spaced C:\Program Files\… path):
//
//	/TR "\"<prog>\" args"   cmd.exe: OK   PowerShell: ERROR (Invalid argument/option - 'C:\Program')
//	/TR "'<prog>' args"     cmd.exe: OK   PowerShell: OK      ← what we emit
//	/TR "<prog> args"       stores an UNQUOTED program → Task Scheduler runs C:\Program
//
// schtasks itself normalizes the single-quoted program into the correct
// double-quoted stored action, so the "spaced path is one token" requirement is
// still satisfied. An elevated shell is as likely to be PowerShell (Windows
// Terminal's "Run as administrator") as cmd.exe, and this is the only form that
// parses in both — do NOT "fix" it back to backslash escapes.
//
// THE ONE PATH THE SINGLE-QUOTED FORM CANNOT CARRY is one containing a single
// quote — `C:\Users\O'Brien\observer.exe` is an ordinary, legal Windows path.
// Wrapping it in single quotes ends the quoted program at the apostrophe, and
// schtasks stores a program that is a PREFIX of the real one: a task that runs
// the wrong thing, silently, with no error at registration time. Such a path
// therefore falls back to the same `\"…\"` escaped form the spaced token path
// uses (cmdOnly=true) — correct in cmd.exe and in the broker, at the cost of
// the PowerShell paste. See quoteTaskProgram.
//
// The --token-file value carries no inner quotes for the same reason: the only
// form that survives both shells is a bare path, and bare is correct for every
// path without a space. cmdOnly=true is returned when the token path DOES
// contain a space, where correctness forces the cmd.exe-only escaped form and
// the caller must say so rather than hand a PowerShell user a broken line. An
// apostrophe needs nothing there — the token is an ARGUMENT, where a quote is
// not the grouping character schtasks looks at.
//
// Values that no form in this grammar can carry are refused upstream by
// validateActionValue rather than mangled here.
func TaskArgs(exe, addr, tokenPath string) (args string, cmdOnly bool) {
	prog, cmdOnly := quoteTaskProgram(exe)
	token := tokenPath
	if strings.ContainsAny(tokenPath, " \t") {
		token, cmdOnly = `\"`+tokenPath+`\"`, true
	}
	action := fmt.Sprintf(`%s process-bridge --etw --connect %s --token-file %s`, prog, addr, token)
	return fmt.Sprintf(`/Create /TN "%s" /SC ONLOGON /RL HIGHEST /TR "%s"`, TaskName, action), cmdOnly
}

// quoteTaskProgram wraps the program path so schtasks stores it as ONE token.
//
// Single quotes are the measured default (see TaskArgs) and are what every
// ordinary path gets. An apostrophe in the path defeats them, so that case —
// and only that case — takes the `\"` escaped form, which the C runtime that
// parses schtasks' own command line reads as a real double quote. Returns
// cmdOnly=true there, because that form is what PowerShell rejects.
//
// The broker path is unaffected either way: it hands the string to a child
// process without a shell in between, and BOTH forms were measured to arrive
// byte-identical (ElevatedRegisterArgv).
func quoteTaskProgram(exe string) (quoted string, cmdOnly bool) {
	if strings.Contains(exe, "'") {
		return `\"` + exe + `\"`, true
	}
	return "'" + exe + "'", false
}

// SchtasksExe is the program TaskCommand names and ElevatedRegisterArgv
// launches. Bare, not absolute: it is resolved on the WINDOWS PATH (System32),
// and the daemon composing it is commonly a Linux process for which no Windows
// absolute path is knowable.
const SchtasksExe = "schtasks.exe"

// TaskCommand renders the full copy-paste-ready elevated `schtasks /Create`
// line. It is TaskArgs prefixed with the program name and nothing else — see
// TaskArgs for the measured quoting rules, which live there because the
// elevation broker needs the tail without the program.
func TaskCommand(exe, addr, tokenPath string) (cmd string, cmdOnly bool) {
	args, cmdOnly := TaskArgs(exe, addr, tokenPath)
	return SchtasksExe + " " + args, cmdOnly
}

// PowerShellExe is the interpreter the elevation broker spawns. Windows
// PowerShell 5.1 ships in every supported Windows and is reachable from WSL
// through interop, so it needs no install and no version gate.
const PowerShellExe = "powershell.exe"

// ElevatedRegisterArgv returns the COMPLETE argv the dashboard's elevation
// broker spawns to register the Scheduled Task through a Windows UAC consent
// prompt. schtasksArgs must come from TaskArgs (carried on Plan.SchtasksArgs) —
// this function never composes a schtasks line of its own.
//
// WHY A BROKER EXISTS AT ALL. §W4.1 measured that `schtasks /Create` is
// Access-denied from WSL's interop token (Medium Mandatory Level,
// BUILTIN\Administrators present "for deny only"), which is why PlanTask never
// creates the task. What that measurement rules out is taking elevation
// SILENTLY; it does not rule out asking for it. Measured on the reference host
// 2026-07-27: a `Start-Process -Verb RunAs` from that same WSL token yields
// `Mandatory Label\High Mandatory Level` once the operator approves the prompt,
// and `schtasks /Create /SC ONLOGON /RL HIGHEST` under it exits 0. This is the
// exact analogue of `sudo tailscale set --operator` — a consent step Observer
// cannot take for the user, only put in front of them.
//
// UAC IS NOT SUPPRESSED AND CANNOT BE. No flag, manifest or argument skips the
// consent dialog for a medium-integrity caller; the dialog IS the security
// boundary. The script therefore treats a dismissed prompt as a first-class
// outcome: Start-Process throws, the catch prints what Windows actually said,
// and the process exits non-zero — so the card falls back to the copyable
// command instead of spinning. On a headless host with no interactive desktop
// session the same path is taken (nothing can approve the prompt), which is
// why the failure text points at the manual command rather than retrying.
//
// WHY THE ARGS ARE ONE STRING, NOT AN ARRAY. PowerShell's
// `Start-Process -ArgumentList` joins an array with single spaces and adds NO
// quoting, so an array would silently destroy the /TR grouping that the whole
// §W4.2 measurement is about. A single string is assigned verbatim to the
// child's command line. Measured 2026-07-27 end to end (WSL exec → interop →
// PowerShell 5.1 → child process): the child receives the argument string
// BYTE-IDENTICAL, for the single-quoted form AND for the cmd-shell-only `\"`
// form TaskArgs emits when the token path contains a space. No shell parses
// the string on the way, so cmdOnly does not apply to this path — it is a
// statement about pasting into a shell, which the broker never does.
func ElevatedRegisterArgv(schtasksArgs string) []string {
	return []string{PowerShellExe, "-NoProfile", "-NonInteractive", "-Command", elevateScript(schtasksArgs)}
}

// elevateScript renders the PowerShell program ElevatedRegisterArgv runs.
//
// Statements are NEWLINE-separated, not `;`-separated: a `;` between `try {}`
// and `catch {}` is a PowerShell parse error ("The Try statement is missing its
// Catch or Finally block") — measured 2026-07-27, and the reason this is a
// []string joined with "\n" rather than a one-liner.
//
// -PassThru rather than -RedirectStandardOutput, because an elevated child
// cannot share this PTY's console (that would breach the integrity boundary)
// and PowerShell refuses -Verb together with -RedirectStandard*. So the broker
// reports the child's EXIT CODE and prints its own verdict lines into the PTY
// the operator is watching, rather than pretending to relay output it cannot
// see.
func elevateScript(schtasksArgs string) string {
	verify := `schtasks.exe /Query /TN "` + TaskName + `"`
	lines := []string{
		// Stop on the first error so a failed Start-Process reaches the catch
		// instead of falling through to the success line.
		"$ErrorActionPreference = 'Stop'",
		"Write-Output " + psQuote("superbased: registering the elevated ETW capturer task "+TaskName+"."),
		"Write-Output " + psQuote("superbased: Windows will now show a User Account Control prompt. It must be "+
			"approved ON THIS MACHINE - approve it to continue, or dismiss it to cancel."),
		"try { $p = Start-Process -FilePath " + psQuote(SchtasksExe) +
			" -Verb RunAs -Wait -PassThru -ArgumentList " + psQuote(schtasksArgs) + " }",
		"catch {",
		"  Write-Output ('superbased: the elevated helper did not start - ' + $_.Exception.Message)",
		"  Write-Output " + psQuote("superbased: nothing was registered. If you dismissed the prompt, close this "+
			"terminal and press the button again - or run the command yourself from an elevated Windows shell."),
		"  exit 3",
		"}",
		"if ($null -eq $p) {",
		"  Write-Output " + psQuote("superbased: the elevated helper reported no process, so nothing can be said "+
			"about whether the task was registered. Check with: "+verify),
		"  exit 3",
		"}",
		"if ($p.ExitCode -ne 0) {",
		"  Write-Output ('superbased: schtasks exited ' + $p.ExitCode + ' - the task was NOT registered.')",
		"  Write-Output " + psQuote("superbased: schtasks refuses to overwrite an existing task without /F, so "+
			"this is also what an already-registered task looks like. Check with: "+verify),
		"  exit $p.ExitCode",
		"}",
		"Write-Output " + psQuote("superbased: registered. The capturer starts at your next logon; to start it now "+
			"without logging out, run (elevated): schtasks.exe /Run /TN \""+TaskName+"\""),
		"exit 0",
	}
	return strings.Join(lines, "\n")
}

// psQuote renders s as a PowerShell single-quoted string literal. Single quotes
// are PowerShell's VERBATIM form — no variable expansion, no backtick escapes —
// so a path full of backslashes and a /TR value full of double quotes both
// survive unchanged. The only character needing an escape is the single quote
// itself, which is doubled.
//
// This is quoting for the PowerShell PARSER only; it never alters the bytes the
// child process receives. Those are TaskArgs' output, verbatim.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// TaskNotes builds the caveats that belong with the command: who
// must own the task, and the one thing about it we cannot verify from here.
func TaskNotes(tokenPath, windowsUser string) []string {
	var notes []string
	if strings.HasPrefix(tokenPath, `\\wsl.localhost\`) || strings.HasPrefix(tokenPath, `\\wsl$\`) {
		// Measured 2026-07-26: a 0600 WSL-native file IS readable over
		// \\wsl.localhost from a NON-elevated Windows shell (the 9p server
		// runs as root inside the distro, so the mode bits do not apply).
		// What cannot be verified from inside WSL is the ELEVATED read — so
		// we hand the operator the one-line check instead of asserting it.
		//
		// The check is `dir`, NOT `type`/`Get-Content`. The failure mode being
		// probed is "can this elevated session reach the per-user
		// \\wsl.localhost share at all", which `dir` answers — and `dir` is
		// the same word in cmd.exe (builtin) and PowerShell (alias for
		// Get-ChildItem), so it keeps the both-shells promise the emitted
		// /Create line makes. Printing the file's CONTENTS would put the
		// shared secret in console scrollback — and this product captures
		// shell-output excerpts from observed shells into its own DB, so the
		// readability check would be the leak. Same reason there is no
		// --token flag (see processBridgeTokenEnv). Do not "improve" this
		// back into a `type`.
		notes = append(notes, fmt.Sprintf(
			"the token lives on the WSL filesystem; in the SAME elevated prompt, check it is reachable first\n"+
				"    (this lists the file - it deliberately never prints the token, which is a shared secret):\n    dir \"%s\"", tokenPath,
		))
	}
	if windowsUser != "" {
		notes = append(notes, fmt.Sprintf(
			"the task must belong to %s (the account that owns this WSL distro). If you elevate with a\n"+
				"    different admin account, add /RU \"%s\" - schtasks will then ask for that account's password.",
			windowsUser, windowsUser,
		))
	}
	notes = append(notes,
		"the capturer re-reads the token on every connect attempt, so a task that fires at logon\n"+
			"    before WSL is up recovers on its own - no ordering requirement between the two.")
	return notes
}

// ConnectAddr turns the daemon's LISTEN address into the address
// the Windows capturer must DIAL. A wildcard or empty bind is not something
// the operator can type into --connect, so it resolves to loopback: WSL2's
// localhostForwarding is exactly what makes Windows→127.0.0.1 reach the
// guest's listener.
func ConnectAddr(listenAddr string) string {
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		return bridge.DefaultListenAddr
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return listenAddr // unparseable: echo it back rather than invent one
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// WindowsPath converts a path the DAEMON sees into the form
// an elevated Windows process can open:
//
//   - on a Windows host, unchanged;
//   - /mnt/<drive>/… → <DRIVE>:\… (the file already lives on Windows);
//   - any other absolute path is WSL-native → \\wsl.localhost\<distro>\…
//
// The distro name comes from $WSL_DISTRO_NAME. Without it the UNC path cannot
// be composed, and that is an error rather than a guess — a wrong distro in a
// copy-paste command is worse than a named missing dependency.
func WindowsPath(p, distro string, hostIsWindows bool) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errors.New("empty path")
	}
	if hostIsWindows {
		return p, nil
	}
	if w, ok := mntPathToWindows(p); ok {
		return w, nil
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%q is not an absolute path", p)
	}
	if distro == "" {
		return "", errors.New("$WSL_DISTRO_NAME is not set, so the \\\\wsl.localhost path cannot be composed")
	}
	return `\\wsl.localhost\` + distro + strings.ReplaceAll(p, "/", `\`), nil
}

// mntPathToWindows converts /mnt/<drive>/x to <DRIVE>:\x. Returns ok=false for
// anything not under a /mnt drive mount. (A third local mirror of this 15-line
// conversion — browserhost and oscrypt each keep their own — because pulling
// cmd/observer into either package for it would be the bigger coupling.)
func mntPathToWindows(p string) (string, bool) {
	const prefix = "/mnt/"
	if !strings.HasPrefix(p, prefix) || len(p) < len(prefix)+1 {
		return "", false
	}
	drive := p[len(prefix)]
	if !((drive >= 'a' && drive <= 'z') || (drive >= 'A' && drive <= 'Z')) {
		return "", false
	}
	rest := p[len(prefix)+1:]
	if rest == "" {
		return strings.ToUpper(string(drive)) + `:\`, true
	}
	if rest[0] != '/' {
		return "", false // "/mnt/cfoo" is a directory named cfoo, not drive C
	}
	return strings.ToUpper(string(drive)) + ":" + strings.ReplaceAll(rest, "/", `\`), true
}
