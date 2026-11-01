package policy

import (
	"encoding/base64"
	"strings"
	"unicode/utf16"
)

// PowerShell / cmd.exe dialect specifics. These live in the pure
// package (no build tags): a Linux daemon can receive Windows-client
// commands through the WSL bridge and must evaluate them identically
// to a Windows-native daemon (Windows-first arc requirement).
//
// Documented approximations, pinned by tests in psparse_test.go:
//   - Parameter matching is case-insensitive prefix matching against
//     the parameter set we model, with per-parameter minimum prefix
//     lengths chosen to mirror real-world disambiguation ("-fo" for
//     -Force because "-f" is ambiguous with -Filter; "-r" for
//     -Recurse because no other Remove-Item parameter starts with r).
//   - PowerShell here-strings (@'...'@, @"..."@) lex as ONE quoted word
//     (psyntax.go); they are not captured as payload blocks, so a
//     here-string later run with Invoke-Expression through a variable is
//     not analysed.
//   - `powershell -Command` re-joins the remaining argv with single
//     spaces before re-lexing; original intra-argument quoting is not
//     reconstructed.

// psAliases resolves common PowerShell aliases to canonical cmdlet
// names so rule matchers see ONE base per operation regardless of how
// it was spelled. Applied only in the PowerShell dialect (a POSIX
// `rm` must stay `rm`).
var psAliases = map[string]string{
	// Remove-Item family — the rm -rf equivalents.
	"rm": "remove-item", "del": "remove-item", "erase": "remove-item",
	"rd": "remove-item", "ri": "remove-item", "rmdir": "remove-item",
	// Item manipulation.
	"ni": "new-item", "md": "new-item", "mkdir": "new-item",
	"cp": "copy-item", "copy": "copy-item", "cpi": "copy-item",
	"mv": "move-item", "move": "move-item", "mi": "move-item",
	// Content.
	"gc": "get-content", "cat": "get-content", "type": "get-content",
	"sc": "set-content", "ac": "add-content",
	// Web / execution (exfil-rule groundwork, R-17x lands post-G1).
	"iex": "invoke-expression",
	"irm": "invoke-restmethod",
	"iwr": "invoke-webrequest", "curl": "invoke-webrequest", "wget": "invoke-webrequest",
	// Registry / process (persistence vectors).
	"sp": "set-itemproperty", "saps": "start-process", "start": "start-process",
}

// psParamMatches reports whether token is the PowerShell parameter
// `full` under prefix matching: a leading '-', then a
// case-insensitive prefix of full at least minLen characters long.
func psParamMatches(token, full string, minLen int) bool {
	if len(token) < 1+minLen || token[0] != '-' {
		return false
	}
	name := strings.ToLower(token[1:])
	if len(name) > len(full) {
		return false
	}
	return strings.HasPrefix(full, name)
}

// psHasParam reports whether any argv token matches the PowerShell
// parameter under psParamMatches rules.
func psHasParam(c *Command, full string, minLen int) bool {
	for i := 1; i < len(c.Argv); i++ {
		if psParamMatches(c.Argv[i], full, minLen) {
			return true
		}
	}
	return false
}

// psHostKind classifies what a powershell.exe / pwsh.exe HOST
// parameter does with the argv that follows it — the only thing this
// package needs to know about the host grammar.
type psHostKind int

// psHostKind values.
const (
	// psHostSwitch consumes nothing.
	psHostSwitch psHostKind = iota
	// psHostValued consumes the next token as an uninteresting
	// value. It is in the table ONLY so that value can never be
	// mistaken for a payload parameter or for -File.
	psHostValued
	// psHostCommandText takes the REST of the argv as command text
	// (-Command, -CommandWithArgs).
	psHostCommandText
	// psHostEncoded takes the next token as base64 UTF-16LE command
	// text (-EncodedCommand).
	psHostEncoded
	// psHostScriptFile names a SCRIPT to run (-File). Everything
	// after it is the script's own argv, so scanning STOPS there.
	psHostScriptFile
)

// psHostParam is one row of the powershell.exe / pwsh.exe HOST
// parameter table — the argv grammar of the EXECUTABLE, which is a
// hand-written prefix matcher in PowerShell's own
// CommandLineParameterParser and is NOT the cmdlet parameter binder
// modelled by psResolveParam.
type psHostParam struct {
	// name is the canonical lower-cased parameter name.
	name string
	// minLen is the shortest legal abbreviation, mirroring the
	// "shortest unambiguous prefix" argument PowerShell's own parser
	// passes to MatchSwitch.
	minLen int
	// aliases are documented spellings that are NOT prefixes of name
	// ("cwa", "ec", "ep", "wd"), which prefix matching alone can
	// never find.
	aliases []string
	// kind is what the parameter does with the argv after it.
	kind psHostKind
}

// psHostParams is the WHOLE documented host-parameter vocabulary of
// pwsh 7 and powershell.exe 5.1, not just the rows that carry a
// payload.
//
// WHY THE WHOLE VOCABULARY AND NOT JUST THE PAYLOAD ROWS. §W4.6
// records that every previous round of this seam shipped a bypass
// because a table enumerated the shapes its author had thought of.
// This table therefore lists every parameter, and each non-payload row
// earns its place twice over:
//
//   - a VALUED row stops its value being read as a payload parameter.
//     `pwsh -ConfigurationName -File s.ps1` must not stop scanning at
//     a `-File` that is really -ConfigurationName's value.
//   - a SWITCH row stops the token AFTER it being skipped as a value
//     it does not take. Guessing "valued" on a switch deletes the very
//     next token, and the next token is where `-Command` lives.
//
// THE ROWS THAT CARRY EXECUTABLE TEXT are exactly three: -Command,
// -CommandWithArgs and -EncodedCommand. -CommandWithArgs (alias
// -cwa, pwsh 7.4+) was MISSING, and `pwsh -CommandWithArgs "schtasks
// /Create …"` therefore ALLOWED in ModeEnforce in all three dialects
// while the -Command spelling of the same line denied — measured
// 2026-07-27, docs/security.md H5 round 4. Its real grammar is
// `<string> [<args…>]` (the tail becomes $args rather than more
// command text); it is modelled as psHostCommandText, i.e. the whole
// tail is analysed, which is a SUPERSET of what pwsh executes and so
// errs toward analysing more.
//
// -EncodedArguments (-ea) is deliberately psHostValued: it encodes
// ARGUMENTS for an -EncodedCommand, never command text of its own.
// -File is psHostScriptFile: a script this pure package cannot read
// (gap F1), and — the point of the row — a terminator.
var psHostParams = []psHostParam{
	// --- executable text ---
	{name: "command", minLen: 1, kind: psHostCommandText},
	{name: "commandwithargs", minLen: 1, aliases: []string{"cwa"}, kind: psHostCommandText},
	{name: "encodedcommand", minLen: 1, aliases: []string{"ec"}, kind: psHostEncoded},
	// --- script file: STOPS the scan ---
	{name: "file", minLen: 1, kind: psHostScriptFile},
	// --- valued: their value must not be read as anything else ---
	{name: "encodedarguments", minLen: 8, aliases: []string{"ea"}, kind: psHostValued},
	{name: "executionpolicy", minLen: 2, aliases: []string{"ep"}, kind: psHostValued},
	{name: "inputformat", minLen: 3, aliases: []string{"if"}, kind: psHostValued},
	{name: "outputformat", minLen: 1, aliases: []string{"of"}, kind: psHostValued},
	{name: "windowstyle", minLen: 1, kind: psHostValued},
	{name: "workingdirectory", minLen: 2, aliases: []string{"wd"}, kind: psHostValued},
	{name: "configurationname", minLen: 6, kind: psHostValued},
	{name: "configurationfile", minLen: 7, kind: psHostValued},
	{name: "custompipename", minLen: 3, kind: psHostValued},
	{name: "settingsfile", minLen: 8, kind: psHostValued},
	{name: "psconsolefile", minLen: 3, kind: psHostValued}, // powershell.exe 5.1 only
	// --- switches: they consume NOTHING, and saying otherwise would
	// delete the token after them ---
	{name: "noexit", minLen: 3, kind: psHostSwitch},
	{name: "nologo", minLen: 3, kind: psHostSwitch},
	{name: "noninteractive", minLen: 4, kind: psHostSwitch},
	{name: "noprofile", minLen: 3, kind: psHostSwitch},
	{name: "noprofileloadtime", minLen: 11, kind: psHostSwitch},
	{name: "interactive", minLen: 1, kind: psHostSwitch},
	{name: "login", minLen: 1, kind: psHostSwitch},
	{name: "version", minLen: 1, kind: psHostSwitch},
	{name: "help", minLen: 1, kind: psHostSwitch},
	{name: "mta", minLen: 3, kind: psHostSwitch},
	{name: "sta", minLen: 3, kind: psHostSwitch},
	{name: "servermode", minLen: 1, kind: psHostSwitch},
	{name: "socketservermode", minLen: 2, kind: psHostSwitch},
	{name: "sshservermode", minLen: 4, kind: psHostSwitch},
	{name: "namedpipeservermode", minLen: 3, kind: psHostSwitch},
}

// psHostParamAliases indexes psHostParams by documented non-prefix
// alias, derived from the table so the two can never drift.
//
// `-ec` is the alias that mattered first: a documented alias of
// -EncodedCommand ("ec" is not a prefix of "encodedcommand", which
// continues "en…"), so `powershell -ec <base64>` carried an
// unwrappable payload and ALLOWED in ModeEnforce (docs/security.md
// H6). `-cwa` was the same class one round later.
var psHostParamAliases = func() map[string]psHostParam {
	m := make(map[string]psHostParam)
	for _, p := range psHostParams {
		for _, a := range p.aliases {
			m[a] = p
		}
	}
	return m
}()

// psResolveHostParam binds one argv token to a host-parameter row:
// documented alias first, then prefix matching at the row's minimum
// length. NEVER compare a parameter token with `==`: `-Com`, `-C`,
// `-Enc` and `-E` are all legal spellings.
//
// A token matching SEVERAL rows binds to the first that agrees with
// every other match about its kind, and to nothing otherwise — an
// abbreviation whose meaning we cannot pin must not be allowed to
// consume a token or to terminate the scan.
func psResolveHostParam(token string) (psHostParam, bool) {
	if len(token) < 2 || token[0] != '-' {
		return psHostParam{}, false
	}
	name := strings.ToLower(token[1:])
	if p, ok := psHostParamAliases[name]; ok {
		return p, true
	}
	var match psHostParam
	found := false
	for _, p := range psHostParams {
		if p.name == name {
			return p, true // an exact name wins outright
		}
		if !psParamMatches(token, p.name, p.minLen) {
			continue
		}
		if found {
			if match.kind != p.kind {
				return psHostParam{}, false
			}
			continue
		}
		match, found = p, true
	}
	return match, found
}

// psCommandPayload extracts the command text a powershell/pwsh
// invocation executes, walking the argv the way the HOST parser does.
//
// Three rows carry executable text (-Command, -CommandWithArgs,
// -EncodedCommand); -File STOPS the walk because everything after it
// is the SCRIPT's argv, not the host's. That termination is what
// stopped `pwsh -File .\analyze.ps1 -Command "schtasks /Create"` from
// denying a command pwsh never runs (docs/security.md H5 round 4) —
// the classifier used to keep scanning and read the script's own
// -Command argument as host command text.
//
// A VALUED parameter's value is skipped, so it cannot be misread as
// -File or as a payload parameter — but the skip REFUSES to swallow a
// token that itself names a payload parameter. That asymmetry is
// deliberate: a mistake in this table's valued-ness must never be able
// to delete a `-Command`, which is the one direction that fails open.
func psCommandPayload(argv []string) (string, bool) {
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		if !strings.HasPrefix(t, "-") {
			continue
		}
		p, ok := psResolveHostParam(t)
		if !ok {
			continue // unknown parameter: keep looking, never skip a token
		}
		switch p.kind {
		case psHostCommandText:
			if i+1 < len(argv) {
				return strings.Join(argv[i+1:], " "), true
			}
		case psHostEncoded:
			if i+1 < len(argv) {
				if dec, ok := decodeEncodedPS(argv[i+1]); ok {
					return dec, true
				}
			}
			return "", false
		case psHostScriptFile:
			// Everything after -File belongs to the script. A script's
			// argv cannot be statically unwrapped and must not be
			// misread as host command text.
			return "", false
		case psHostValued:
			if i+1 < len(argv) && !psCarriesCommandText(argv[i+1]) {
				i++
			}
		case psHostSwitch:
		}
	}
	return "", false
}

// psCarriesCommandText reports whether a token names a host parameter
// that carries executable text, so a valued parameter's value-skip
// can refuse to swallow it.
func psCarriesCommandText(token string) bool {
	p, ok := psResolveHostParam(token)
	return ok && (p.kind == psHostCommandText || p.kind == psHostEncoded)
}

// decodeEncodedPS decodes a -EncodedCommand value: standard base64
// wrapping UTF-16LE text (the only encoding PowerShell accepts).
//
// Whitespace is stripped first because .NET's
// Convert.FromBase64String — which is what PowerShell actually calls —
// IGNORES whitespace inside the base64, while Go's decoder rejects it.
// `powershell -e "<b64 with spaces>"` is one quoted argv token that
// PowerShell decodes and we did not (found in the round-4 vocabulary
// audit, 2026-07-27). A leading BOM in the decoded UTF-16 is dropped
// for the same reason: it would otherwise glue itself to the first
// word and change its Base.
func decodeEncodedPS(b64 string) (string, bool) {
	b64 = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, b64)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return "", false
		}
	}
	if len(raw) < 2 || len(raw)%2 != 0 {
		return "", false
	}
	u16 := make([]uint16, len(raw)/2)
	for i := range u16 {
		u16[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return strings.TrimPrefix(string(utf16.Decode(u16)), "\ufeff"), true
}

// cmdSlashCPayload extracts the payload of a `cmd /c ...` (or /k, or
// /r) invocation: everything after the switch, re-joined, parsed
// under the cmd dialect.
//
// `/r` is cmd.exe's SYNONYM for `/c` — it runs the command and
// terminates, identically. It is absent from `cmd /?` but real, and
// while only `/c` and `/k` were matched here `cmd /r crontab -e`
// ALLOWED in every dialect while `cmd /c crontab -e` denied
// (docs/security.md H5 round 2).
var cmdRunSwitches = map[string]bool{"/c": true, "/k": true, "/r": true}

// cmdSlashCPayload extracts a `cmd` run-switch payload.
func cmdSlashCPayload(argv []string) (string, bool) {
	for i := 1; i < len(argv); i++ {
		t := strings.ToLower(argv[i])
		if cmdRunSwitches[t] && i+1 < len(argv) {
			return strings.Join(argv[i+1:], " "), true
		}
	}
	return "", false
}

// psExpressionPayload returns the PowerShell command line an
// Invoke-Expression / iex unit evaluates: the -Command parameter's
// value where the parameter is named, otherwise the whole operand
// tail (the cmdlet takes it positionally).
func psExpressionPayload(argv []string) (string, bool) {
	if len(argv) < 2 {
		return "", false
	}
	if psParamMatches(argv[1], "command", 1) {
		if len(argv) < 3 {
			return "", false
		}
		return strings.Join(argv[2:], " "), true
	}
	return strings.Join(argv[1:], " "), true
}

// cmdHasFlag reports whether the cmd-dialect unit carries the given
// slash flag (case-insensitive), accepting both spaced ("/s /q") and
// run-together ("/s/q") forms.
func cmdHasFlag(c *Command, letter string) bool {
	for i := 1; i < len(c.Argv); i++ {
		t := c.Argv[i]
		if len(t) < 2 || t[0] != '/' {
			continue
		}
		for _, part := range strings.Split(t[1:], "/") {
			if strings.EqualFold(part, letter) {
				return true
			}
		}
	}
	return false
}
