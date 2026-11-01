package hook

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Equivalent-hook keep (T-725). `observer start` auto-registration used to
// REWRITE an existing observer hook whenever its command was not byte-equal
// to the one the running binary would write: a different install path, a
// renamed binary (observer.135) or an explicit `--config` naming the
// default config file each counted as drift, so every daemon relaunch from
// a differently placed binary rewrote the user's Claude Code settings.json
// (D-528, D-541). With Options.KeepEquivalentHooks set, a registrar asks
// keepEquivalentHook before it drops an existing observer entry: an entry
// that is still EQUIVALENT is left exactly as it is, and only a missing or
// broken entry is rewritten. Every rewrite is reported in
// RegistrationResult.Rewrites with the rule that forced it.

// hookInvocation is a parsed observer hook command: what the entry would
// execute, independent of quoting and of which observer install wrote it.
type hookInvocation struct {
	// bridge is true for the `wsl.exe -d <distro> --` cross-OS shape.
	bridge bool
	// distro is the WSL distribution a bridge entry names.
	distro string
	// envPrefix is true when the command starts with `KEY=VALUE`
	// assignments (the legacy `MSYS_NO_PATHCONV=1` bridge form).
	envPrefix bool
	// exitTrailer is true when the command ends with the portable
	// bridge's `; exit $LASTEXITCODE` (bridgeExitTrailer).
	exitTrailer bool
	// binary is the executable the entry runs (inside the bridge, if any).
	binary string
	// tool and event are the `hook <tool> <event>` arguments.
	tool, event string
	// config is the `--config` value; empty when the entry has none.
	config string
	// extra holds any argument observer does not write itself.
	extra []string
}

// parseObserverHookCommand parses cmd into a hookInvocation. ok is false
// when cmd is not a `<bin> hook <tool> <event> [--config <path>]` command in
// either the native or the bridge shape.
func parseObserverHookCommand(cmd string) (hookInvocation, bool) {
	body, trailer := trimBridgeExitTrailer(cmd)
	inv, ok := parseHookTokens(splitCommandTokens(body))
	// Same retry isObserverAnyHookEntry makes: an unquoted Windows path
	// collapses under the POSIX tokenizer's backslash rule. It is also
	// taken when the first parse succeeded but only because the tokenizer
	// ate the separators of an unquoted C:\... binary path (a hook written
	// by hand or by an older build on native Windows): that token read as
	// "C:Users...observer", not an observer binary, so an equivalent hook
	// was rewritten by binary-not-observer (Windows 11 Pro live run, PT-02).
	if strings.Contains(body, `\`) {
		if slashed, sok := parseHookTokens(splitCommandTokens(strings.ReplaceAll(body, `\`, "/"))); sok && (!ok || driveLetterPath(slashed.binary)) {
			inv, ok = slashed, true
		}
	}
	if !ok {
		return hookInvocation{}, false
	}
	inv.exitTrailer = trailer
	return inv, true
}

func parseHookTokens(toks []string) (hookInvocation, bool) {
	var inv hookInvocation
	for len(toks) > 0 && strings.Contains(toks[0], "=") && !strings.ContainsAny(toks[0], `/\`) {
		inv.envPrefix = true
		toks = toks[1:]
	}
	if len(toks) == 0 {
		return inv, false
	}
	if strings.ToLower(strings.TrimSuffix(commandBaseName(toks[0]), ".exe")) == "wsl" {
		inv.bridge = true
		for i := 1; i < len(toks); i++ {
			if toks[i] == "-d" && i+1 < len(toks) {
				inv.distro = toks[i+1]
			}
		}
	}
	toks = stripHookCommandPrefix(toks)
	if len(toks) < 4 || toks[1] != "hook" {
		return inv, false
	}
	inv.binary, inv.tool, inv.event = toks[0], toks[2], toks[3]
	rest := toks[4:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == "--config" && i+1 < len(rest) && inv.config == "" {
			inv.config = rest[i+1]
			i++
			continue
		}
		inv.extra = append(inv.extra, rest[i])
	}
	if inv.bridge {
		// Inside WSL `//x` and `/x` are the same file; the doubled slash
		// only exists to get past Git Bash (msysLiteralPath).
		inv.binary = unMSYSLiteralPath(inv.binary)
		inv.config = unMSYSLiteralPath(inv.config)
	}
	return inv, true
}

// hookEquivalenceEnv is what the rules may consult beyond the two parsed
// commands: whether a binary still runs and what an absent --config means.
type hookEquivalenceEnv struct {
	// binaryWorks reports whether the entry's binary exists and can run.
	binaryWorks func(path string) bool
	// defaultConfig is the config file a hook without --config reads.
	defaultConfig string
}

// hookEquivalenceRule is one row of the equivalence table: rewrite reports
// whether this rule forces a rewrite of the existing entry.
type hookEquivalenceRule struct {
	name    string
	reason  string
	rewrite func(have, want hookInvocation, env hookEquivalenceEnv) bool
}

// hookEquivalenceRules is walked top-down; the first row whose rewrite
// returns true decides "rewrite" with its reason. No row firing means the
// existing entry is equivalent and stays byte-identical. A binary-path or
// binary-name difference is deliberately NOT a row, and neither is a
// --config that only spells out the default config file.
var hookEquivalenceRules = []hookEquivalenceRule{
	{
		name:   "shape",
		reason: "the entry's shape differs (native command vs wsl.exe bridge, or another WSL distro)",
		rewrite: func(have, want hookInvocation, _ hookEquivalenceEnv) bool {
			return have.bridge != want.bridge || (want.bridge && have.distro != want.distro)
		},
	},
	{
		// AP-119: the legacy `MSYS_NO_PATHCONV=1 wsl.exe ...` bridge runs
		// under Git Bash only, so an entry in a different shell form than
		// the one observer writes now is rewritten even though it runs the
		// same binary.
		name:   "bridge-form",
		reason: "the bridge entry is in an older shell form (the MSYS_NO_PATHCONV=1 prefix or the exit-code trailer differs)",
		rewrite: func(have, want hookInvocation, _ hookEquivalenceEnv) bool {
			return want.bridge && (have.envPrefix != want.envPrefix || have.exitTrailer != want.exitTrailer)
		},
	},
	{
		name:   "tool-event",
		reason: "the entry names another hook tool or event",
		rewrite: func(have, want hookInvocation, _ hookEquivalenceEnv) bool {
			return have.tool != want.tool || have.event != want.event
		},
	},
	{
		name:   "extra-args",
		reason: "the entry carries arguments observer does not write",
		rewrite: func(have, _ hookInvocation, _ hookEquivalenceEnv) bool {
			return len(have.extra) > 0
		},
	},
	{
		// T-847: a binary-path difference is kept (T-725), but only for an
		// observer binary. `/bin/true hook claude-code pre-tool` parses as an
		// observer hook command, its binary runs, and before this row it was
		// KEPT as equivalent, so a developer could disable a gate with a
		// command that always allows and `observer start` would bless it.
		name:   foreignBinaryRule,
		reason: foreignBinaryReason,
		rewrite: func(have, want hookInvocation, _ hookEquivalenceEnv) bool {
			return !observerBinaryJudged(have.binary, want.binary)
		},
	},
	{
		name:   "binary-broken",
		reason: "the entry's observer binary is missing or not executable",
		rewrite: func(have, _ hookInvocation, env hookEquivalenceEnv) bool {
			return env.binaryWorks == nil || !env.binaryWorks(have.binary)
		},
	},
	{
		name:   "config",
		reason: "the entry reads a different config file",
		rewrite: func(have, want hookInvocation, env hookEquivalenceEnv) bool {
			return effectiveHookConfig(have.config, env.defaultConfig) != effectiveHookConfig(want.config, env.defaultConfig)
		},
	},
}

// effectiveHookConfig normalizes a --config value: absent means the default
// config file; separators are compared forward-slashed and cleaned.
func effectiveHookConfig(cfg, def string) string {
	if cfg == "" {
		cfg = def
	}
	if cfg == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(strings.ReplaceAll(cfg, `\`, "/")))
}

// decideHookEquivalence walks hookEquivalenceRules for an existing command
// against the one the registrar would write. keep is true when the
// existing entry is equivalent; otherwise reason names the first rule that
// forced the rewrite. An existing command that does not parse is never kept.
func decideHookEquivalence(haveCmd, wantCmd string, env hookEquivalenceEnv) (keep bool, rule, reason string) {
	have, ok := parseObserverHookCommand(haveCmd)
	if !ok {
		return false, "unparsed", "the existing entry could not be parsed as an observer hook command"
	}
	want, ok := parseObserverHookCommand(wantCmd)
	if !ok {
		return false, "unparsed", "the command observer would write could not be parsed"
	}
	for _, r := range hookEquivalenceRules {
		if r.rewrite(have, want, env) {
			return false, r.name, r.reason
		}
	}
	return true, "", ""
}

// hookBinaryWorks is the production binaryWorks: a regular file that, off
// Windows, carries an execute bit.
func hookBinaryWorks(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return fi.Mode().Perm()&0o111 != 0
}

// equivalenceEnv is the registry's hookEquivalenceEnv: the hook process
// runs as this user (natively, or inside WSL for a bridge entry), so an
// absent --config reads <home>/.observer/config.toml.
func (r *Registry) equivalenceEnv() hookEquivalenceEnv {
	works := r.opts.binaryWorks
	if works == nil {
		works = hookBinaryWorks
	}
	return hookEquivalenceEnv{
		binaryWorks:   works,
		defaultConfig: filepath.Join(r.opts.HomeDir, ".observer", "config.toml"),
	}
}

// Rewrite records one existing observer hook entry a registrar replaced,
// and the equivalence rule that forced it.
type Rewrite struct {
	Event  string
	Rule   string
	Reason string
	From   string
	To     string
}

// keepOrRewrite is the one call a registrar makes when it found an existing
// observer entry whose command is not byte-equal to want. It returns true
// when the entry must stay (KeepEquivalentHooks set and the entry is
// equivalent); otherwise it records the rewrite on res and returns false.
func (r *Registry) keepOrRewrite(res *RegistrationResult, event, have, want string) bool {
	if r.opts.KeepEquivalentHooks {
		keep, rule, reason := decideHookEquivalence(have, want, r.equivalenceEnv())
		if keep {
			res.KeptEquivalent = append(res.KeptEquivalent, event)
			return true
		}
		res.Rewrites = append(res.Rewrites, Rewrite{Event: event, Rule: rule, Reason: reason, From: have, To: want})
		return false
	}
	res.Rewrites = append(res.Rewrites, Rewrite{Event: event, Rule: "refresh", Reason: "the command differs from the one this binary writes", From: have, To: want})
	return false
}

// driveLetterPath reports whether p starts with a Windows drive ("C:/" or
// "C:\\").
func driveLetterPath(p string) bool {
	if len(p) < 3 || p[1] != ':' || (p[2] != '/' && p[2] != '\\') {
		return false
	}
	c := p[0] | 0x20
	return c >= 'a' && c <= 'z'
}
