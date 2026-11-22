package policy

import "strings"

// UNKNOWN COMMAND PREFIX FALLBACK (FR-SEC-7, review 2026-11-22; operator
// ruling 2026-11-22: build it).
//
// The wrapper table (posixWrappers) strips the exec prefixes the guard
// knows, so every rule sees the command they run. It will always lag: one
// careful pass measured 27 prefixes and value flags behind which a
// recursive delete of the home directory matched no rule. This fallback is
// the backstop for the next one.
//
// A unit whose Base is a command the guard does not know (no row of
// fallbackKnownSources claims it) is re-judged from each later word that
// starts a catastrophic command (fallbackTriggers: a delete command, a disk
// or device command, an interpreter), with that row's own rule matcher. A
// hit is an ASK, never a deny and never an allow: the guard cannot tell
// whether the prefix runs its arguments, so it asks. The row lives under
// R-102, the ask tier for "might be catastrophic, cannot tell" (the M2-01
// calibration), so an org override raising R-101 or R-142 to deny does not
// turn it into a block.
//
// Every decision here is a table: which bases are known, which words start
// a re-judged unit, and which matcher judges it.

// fallbackKnownSource is one reason a Base counts as a command the guard
// knows.
type fallbackKnownSource struct {
	name  string
	known func(base string) bool
}

// fallbackKnownSources is walked top-down; a base any row claims is never
// re-judged.
var fallbackKnownSources = []fallbackKnownSource{
	{"exec-prefix wrapper (stripped, or parsed as a shell line)", func(b string) bool {
		_, posix := posixWrappers[b]
		_, cmd := cmdWrappers[b]
		return posix || cmd
	}},
	{"delete command (judged by R-101 directly)", func(b string) bool { return fallbackTriggerBases[b] }},
	{"command a rule keys on", func(b string) bool { return ruleKeyedBases[b] }},
	// R-142 keys on the whole mkfs family by prefix (mkfs.ext4, mkfs.vfat).
	{"filesystem creation (mkfs*)", func(b string) bool { return strings.HasPrefix(b, "mkfs") }},
	{"interpreter", func(b string) bool { _, ok := interpreterFor(b); return ok }},
	{"non-executing command", func(b string) bool { return nonExecutingBases[b] }},
}

// fallbackTriggerBases are the delete commands R-101 and R-102 key on
// (deleteShape), canonical names in every dialect.
var fallbackTriggerBases = setOf("rm", "rmdir", "rd", "del", "erase", "remove-item")

// fallbackDeviceBases are the device commands R-142 keys on by name
// (matchDiskDevice), with the mkfs family matched by prefix. cmd's
// `format` is left out on purpose: it is an ordinary word after many
// unknown programs (`make format`, `just format`), and R-142 reads it as a
// volume format in the cmd dialect, so it would ask about every one of them.
var fallbackDeviceBases = setOf("dd", "diskpart", "format-volume", "clear-disk")

// fallbackTrigger is one kind of word that starts a re-judged unit, and the
// rule row that judges it: the rule id, its matcher, the safe pattern the
// row carries (nil when it has none), and how the reason names the hit.
type fallbackTrigger struct {
	name    string
	trigger func(base string) bool
	id      string
	match   MatchCmdFn
	safe    SafeFn
	what    string
}

// fallbackTriggers are walked for every later word of an unknown command,
// top-down; the first row whose trigger names the word and whose matcher
// hits the unit from that word on decides. Each matcher is the rule's own:
// R-101's shell row for a delete, R-102's substituted-operand row for a
// delete of a computed target (NF-2), R-142 for a device command, R-101's
// inline-script row for an interpreter one-liner (guard-parser lane,
// 2026-11-22: the device and interpreter rows close the guard-review
// report's "Residuals of the fallback").
var fallbackTriggers = []fallbackTrigger{
	{
		name: "delete command", trigger: func(b string) bool { return fallbackTriggerBases[b] },
		id: "R-101", match: matchDeleteCatastrophic, safe: safeDeleteAllowlisted, what: "delete",
	},
	{
		name: "delete of a substituted target", trigger: func(b string) bool { return fallbackTriggerBases[b] },
		id: "R-102", match: matchDeleteSubstitutedOperand, what: "delete of a computed target",
	},
	{
		name: "disk or device command", trigger: func(b string) bool { return fallbackDeviceBases[b] || strings.HasPrefix(b, "mkfs") },
		id: "R-142", match: matchDiskDevice, what: "disk or device operation",
	},
	{
		name: "interpreter one-liner", trigger: func(b string) bool { _, ok := interpreterFor(b); return ok },
		id: "R-101", match: matchInlineDeleteCatastrophic, what: "inline delete",
	},
}

// nonExecutingBases are commands that take words such as `rm -rf ~` as data
// (text to print or search for, a name to look up, a git path), never as a
// command to run. Kept small on purpose: a false ask it would hide is a
// question for the operator, not a row to add quietly.
var nonExecutingBases = setOf(
	"echo", "printf", "grep", "egrep", "fgrep", "rg", "git", "man", "which", "type", "apropos", "whatis",
	"whereis", "history", "help", "info",
	// PowerShell and cmd spellings of the same.
	"write-output", "write-host", "get-help", "get-command", "select-string", "findstr", "where",
)

// ruleKeyedBases is every base some rule switches on or looks up in its
// own table: a command the guard understands, whose arguments those rules
// judge. Built from the rule tables themselves, plus the bases rules compare
// against literally.
var ruleKeyedBases = func() map[string]bool {
	out := setOf(
		// The literal `Base ==` / `Base !=` comparisons and `switch
		// cmd.Base` cases in the rule files (rules_*.go, security*.go,
		// gitcommit.go, launcher.go), as of 2026-11-22.
		"aws", "az", "clear-disk", "cloudflared", "cmd", "code", "cp", "crontab", "curl",
		"dbus-update-activation-environment", "dd", "declare", "diskpart", "docker", "docker-compose", "eval",
		"export", "filter", "find", "format", "format-volume", "function", "gcloud", "gh", "git", "helm", "iex",
		"invoke-expression", "kubectl", "launchctl", "mkfifo", "new-itemproperty", "npm", "observer",
		"powershell", "pulumi", "pwsh", "reg", "schtasks", "set", "set-itemproperty", "setenv", "setx",
		"socat", "systemctl", "terraform", "tofu", "typeset", "chmod", "chown", "invoke-restmethod",
		"invoke-webrequest", "pnpm", "yarn", "twine", "cargo", "gem",
	)
	add := func(keys []string) {
		for _, k := range keys {
			out[k] = true
		}
	}
	add(keysOf(destBases))
	add(keysOf(dnsLookupBases))
	add(keysOf(inPlaceEditorMode))
	add(keysOf(interpreterEvalFlags))
	add(keysOf(launchers))
	add(keysOf(multicallBases))
	add(keysOf(ncExecBases))
	add(keysOf(networkCommandBases))
	add(keysOf(packageRunners))
	add(keysOf(packageScriptRunners))
	add(keysOf(pipeInterpreterBases))
	add(keysOf(psEnvItemCmdlets))
	add(keysOf(psProfileWriters))
	add(keysOf(remoteFetchBases))
	add(keysOf(scannerBases))
	add(keysOf(stepClassifiers))
	add(keysOf(tunnelSpecs))
	add(keysOf(valueFlags))
	add(keysOf(writeBases))
	add(keysOf(posixHostSpecs))
	add(keysOf(netPSSpecs))
	add(keysOf(urlHostBases))
	add(keysOf(firstPositionalHostBases))
	add(keysOf(scriptFeederBases))
	add(keysOf(posixShellBases))
	add(keysOf(evalBases))
	add(keysOf(sourceEvaluatorBases))
	add(keysOf(stagingDirChangeBases))
	add(keysOf(declarationBases))
	add(keysOf(dbCLIIndex))
	return out
}()

// keysOf returns a map's keys (unordered).
func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// fallbackSkip are the units the fallback never re-judges, walked
// top-down: a command the guard knows, and a PowerShell unit whose script
// block arguments were already parsed into nested units (psblock.go), so
// its words are code that was judged, or text the block quotes.
var fallbackSkip = []struct {
	name string
	skip func(c *Command) bool
}{
	{"command the guard knows", func(c *Command) bool { return fallbackKnown(c.Base) }},
	{"script block parsed into nested units", func(c *Command) bool { return c.scriptBlock }},
}

// fallbackKnown reports whether base is a command the guard knows
// (fallbackKnownSources).
func fallbackKnown(base string) bool {
	if base == "" {
		return true
	}
	for _, src := range fallbackKnownSources {
		if src.known(base) {
			return true
		}
	}
	return false
}

// fallbackApplies reports whether cmd is a unit the fallback re-judges: a
// unit no fallbackSkip row names.
func fallbackApplies(cmd *Command) bool {
	if cmd == nil {
		return false
	}
	for _, s := range fallbackSkip {
		if s.skip(cmd) {
			return false
		}
	}
	return true
}

// unknownPrefixUnit returns the unit to re-judge behind cmd's unknown
// prefix from word k on: cmd's argv from k, with that word's canonical base
// as its Base and every other fact of cmd (dialect, directory sequence,
// environment, heredoc, pipeline position) kept.
func unknownPrefixUnit(cmd *Command, k int) Command {
	sub := *cmd
	sub.Base = canonicalBase(cmd.Argv[k], cmd.Dialect)
	sub.Argv = cmd.Argv[k:]
	sub.ArgvLiterals = suffixIfParallel(cmd.ArgvLiterals, len(cmd.Argv), k)
	sub.argvQuotedBraces = suffixIfParallel(cmd.argvQuotedBraces, len(cmd.Argv), k)
	sub.lostArgs = nil
	for _, i := range cmd.lostArgs {
		if i > k {
			sub.lostArgs = append(sub.lostArgs, i-k)
		}
	}
	sub.Wrappers = append(append([]string(nil), cmd.Wrappers...), cmd.Base)
	return sub
}

// suffixIfParallel slices a per-word slice that runs parallel to an argv
// of n words from index k; nil when it does not run parallel (unknown).
func suffixIfParallel(s [][]int, n, k int) [][]int {
	if len(s) != n {
		return nil
	}
	return s[k:]
}

// matchDeleteBehindUnknownPrefix is the R-102 fallback row: a unit whose
// Base is a command the guard does not know, and whose argv from some later
// trigger word is a catastrophic command by that trigger's own rule
// (fallbackTriggers). The detail names the unknown prefix.
func matchDeleteBehindUnknownPrefix(ctx *MatchContext, cmd *Command) (bool, string) {
	if !fallbackApplies(cmd) {
		return false, ""
	}
	for k := 1; k < len(cmd.Argv); k++ {
		base := canonicalBase(cmd.Argv[k], cmd.Dialect)
		for _, r := range fallbackTriggers {
			if !r.trigger(base) {
				continue
			}
			sub := unknownPrefixUnit(cmd, k)
			hit, why := r.match(ctx, &sub)
			if !hit || (r.safe != nil && r.safe(ctx, &sub)) {
				continue
			}
			prefix := strings.TrimSpace(cmd.Argv[0])
			return true, "`" + excerpt(prefix) + "` is not a command the guard knows, and the words after it are a " +
				r.id + " " + r.what + " (" + why + ")"
		}
	}
	return false, ""
}
