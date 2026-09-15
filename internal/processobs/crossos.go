package processobs

import (
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// CrossOSWindow is the default tolerance between a session's start and the
// Windows AI-tool root process's observed start (spec §5.5). The root launches
// when the session begins and the poll backend observes it within an interval,
// so the gap is small; the window stays modest so two sequential sessions in
// the same project don't cross-attribute (a tie is broken by nearest start).
const CrossOSWindow = 2 * time.Minute

// crossOSBackSkew tolerates a root process observed BEFORE its session row's
// timestamp. This is not just clock skew: a tool launches its root process when
// the session opens, but the session row's started_at comes from the first
// LOGGED event (e.g. the first user prompt), which can land tens of seconds
// later — so the root legitimately predates the session timestamp. Set wide
// enough to cover that launch-to-first-event latency; cross-session bleed is
// bounded by the nearest-session tie-break (a process anchors to the session
// whose start is closest), and the subtree climb (climbToSessionRoot) then
// inherits children that themselves fall outside the window.
//
// Sized to match CrossOSWindow (the forward tolerance) so the anchor window is
// symmetric: live Windows-side capture showed real launch-to-first-prompt gaps
// of ~45s (a CLI started, then the operator typed the first prompt), which the
// previous 30s skew dropped on the floor. 2 min comfortably covers the
// realistic gap. For WSL-native tools the robust fix is still a same-OS
// SessionStart-hook pid seed (pidbridge); the Windows cross-OS case CANNOT use
// that (the hook runs in WSL, can't see the Windows pid), so this back-skew is
// the only lever there — hence sized for the observed worst case, not the
// median.
const crossOSBackSkew = 2 * time.Minute

// DefaultCrossOSToolBasenames maps a session tool to the Windows executable
// basenames its root process may present (spec §5.5). cwd==project_root + the
// time window are the strong discriminators; this set only guards an anchor
// against a non-AI process that happens to share the project cwd in the
// window. Matched case-insensitively; injectable so operators/tests extend it.
// An entry ending in "*" is a case-insensitive PREFIX pattern (see
// basenameMatches) — used for codex-command-runner-<ver>.exe, the version-
// stamped command-execution worker the Codex desktop app spawns in the project
// cwd (alongside node_repl.exe). An unknown tool (no entry) yields no anchor —
// cross-OS never guesses.
var DefaultCrossOSToolBasenames = map[string][]string{
	"claude-code": {"claude.exe", "claude", "node.exe", "node"},
	"codex":       {"codex.exe", "codex", "node.exe", "node", "node_repl.exe", "codex-command-runner-*"},
	"cursor":      {"cursor.exe", "cursor"},
	"copilot":     {"copilot.exe", "node.exe", "node"},
	"copilot-cli": {"copilot.exe", "copilot", "node.exe", "node"}, // @github/copilot CLI (binary `copilot`)
	"cline":       {"node.exe", "node"},
	"cline-cli":   {"cline.exe", "cline", "node.exe", "node"},
	"roo-code":    {"node.exe", "node"}, // VS Code extension (Roo Cline fork) — runs in the node extension host
	// zoo-code (2026-09-03): ZooCode, the community continuation of Roo
	// Code — the SAME VS Code extension shape (parsed by the cline
	// adapter's clineExtensions table), so it runs in the same node
	// extension host as roo-code.
	"zoo-code":        {"node.exe", "node"},
	"opencode":        {"opencode.exe", "opencode", "bun.exe", "bun", "node.exe", "node"},
	"kilo-code":       {"node.exe", "node"},
	"kilo-code-cli":   {"kilo.exe", "kilo", "node.exe", "node"},
	"hermes":          {"python.exe", "python", "node.exe", "node"},
	"openclaw":        {"openclaw.exe", "openclaw", "node.exe", "node"},
	"pi":              {"pi.exe", "pi", "node.exe", "node"},         // ~/.pi terminal agent
	"gemini-cli":      {"gemini.exe", "gemini", "node.exe", "node"}, // @google/gemini-cli (binary `gemini`)
	"antigravity-cli": {"antigravity.exe", "antigravity", "agy.exe", "agy", "node.exe", "node"},
	// Google Antigravity IDE (VS Code fork) — the agent worker is agy.exe /
	// language_server alongside the electron node host (internal/adapter/antigravity).
	"antigravity": {"antigravity.exe", "antigravity", "agy.exe", "agy", "node.exe", "node"},
	// Anthropic Claude Cowork desktop — layered on the Claude Code CLI, so the
	// inner worker presents as claude/node under the desktop app.
	"cowork": {"claude.exe", "claude", "cowork.exe", "cowork", "node.exe", "node"},
	// 2026-07 adapter wave. Runtimes grounded in live installs (2026-07-09):
	// a native compiled binary (ELF/Rust/Go) takes ONLY its own name — adding
	// node/python would risk false-anchoring a stray interpreter that merely
	// shares the project cwd; node-shim and python-launched tools also carry
	// their interpreter (the tool's own long-running child may present as it).
	"qwen-code": {"qwen.exe", "qwen", "node.exe", "node"},   // npm @qwen-code/qwen-code — node shim (cli-entry.js)
	"kiro-cli":  {"kiro-cli.exe", "kiro-cli"},               // AWS Kiro CLI (rebranded Amazon Q) — native binary
	"crush":     {"crush.exe", "crush", "node.exe", "node"}, // Charm Crush — npm shim (run-crush.js) execs the Go binary
	"kimi-code": {"kimi.exe", "kimi"},                       // Moonshot kimi-code (binary `kimi`) — native ELF (bun-compiled)
	"grok":      {"grok.exe", "grok", "grok-*"},             // xAI Grok — native ELF; live installs ship version-stamped artifacts (grok-1.0.0-linux-x86_64, observed 2026-08-21), so the prefix pattern is required
	// Grok Bot DESKTOP (distinct from "grok" above) — an Electron app
	// installed at "C:\Program Files\Grok Bot\Grok Bot.exe" (grounded on a
	// live 0.28.0 install, 2026-08-28). Its local-exec daemon and renderer
	// are .cjs bundles run by that SAME executable, not separate binaries,
	// so the one basename covers every child. Matched case-insensitively;
	// no bare "grok" spelling, which would collide with the grok CLI.
	"grokbot": {"grok bot.exe"},
	// AWS Kiro Crew — the DESKTOP app is the only local process on the
	// grounding box: "C:\Program Files\KiroCrew\KiroCrew.exe" (live
	// install, 2026-09-03; matched case-insensitively). The vendor also
	// documents a `kirocrew` CLI (`kirocrew telemetry status`), which was
	// NOT on PATH there — its spelling is carried on the strength of the
	// vendor's own command syntax, not a live probe. Note Crew ORCHESTRATES
	// kiro-cli, so a Crew run's actual agent process presents as
	// kiro-cli.exe and is attributed under "kiro-cli" above; that is
	// correct — kiro-cli owns those sessions (see
	// internal/adapter/kirocrew/doc.go "Ownership").
	"kiro-crew": {"kirocrew.exe", "kirocrew"},
	"devin":     {"devin.exe", "devin"},                         // Cognition Devin CLI (binary `devin`) — native binary
	"aider":     {"aider.exe", "aider", "python.exe", "python"}, // pip aider-chat — python console-script entry
	"qoder":     {"qoder.exe", "qoder", "node.exe", "node"},     // Alibaba Qoder CLI — CC-shaped node-family (no local install to probe)
	"goose":     {"goose.exe", "goose"},                         // Block goose (binary `goose`) — native Rust ELF
	// 2026-07-29 wave. Same runtime rule as above: a natively compiled
	// binary takes ONLY its own name; an npm-shim CLI also carries node.
	"droid": {"droid.exe", "droid"}, // Factory AI droid — distributed as its own binary, not an npm/python shim
	// Open Interpreter is the OpenAI Codex CLI Rust codebase rebuilt under
	// a different product name — a native binary, so no node/python.
	"open-interpreter": {"interpreter.exe", "interpreter"},
	// Command Code is an npm package whose bin entries all load the same
	// node bundle, so node belongs here (the cline-cli/copilot-cli/crush
	// precedent). It installs FOUR bin aliases — `commandcode`,
	// `command-code`, `cmd`, `cmdc` — but only the two unambiguous
	// spellings are matched: `cmd`/`cmd.exe` is the Windows command
	// prompt and `cmdc` is generic enough to collide, and a false anchor
	// here misattributes an unrelated process to a session (cwd + the
	// time window are the only other discriminators).
	"command-code": {"command-code.exe", "command-code", "commandcode.exe", "commandcode", "node.exe", "node"},
	// Meta Muse Code (2026-08-06): Linux/macOS only — the launcher platform
	// table has no Windows build, so no .exe names exist to ground. The
	// `muse` shell launcher execs a versioned native Rust ELF
	// (muse-bin-<version>), hence the glob (codex-command-runner-* precedent);
	// native binary rule: no node/python.
	"muse": {"muse", "muse-bin-*"},
	// Prime Intellect Prime Agent (2026-08-06): npm package `prime-agent`
	// whose bin entry loads the same node bundle on every platform (the
	// command-code/cline-cli/crush precedent), so node belongs here —
	// Windows gets a .cmd shim, the real process is node.
	"prime-agent": {"prime-agent.exe", "prime-agent", "node.exe", "node"},
	// DeepSeek Harness (`@deepseek-ai/dsh`): an npm bin loading a node bundle
	// (the command-code/prime-agent precedent), so node belongs here; the
	// branded `dsh` name anchors when present.
	"deepseek": {"dsh.exe", "dsh", "node.exe", "node"},
	// JetBrains Junie (2026-08-17): the `junie` launcher is a managed bash
	// shim that execs a native versioned binary ALSO named `junie`
	// (~/.local/share/junie/versions/<v>/junie) — no node/JVM name is exposed
	// at the process level, so the branded basename is the whole entry (the
	// muse native-binary precedent); Windows gets junie.exe.
	"junie": {"junie.exe", "junie"},
	// zcode (Z.AI, 2026-08-18): npm package `zcode-app-cli`, binary `zcode`
	// — an OpenCode fork but its own npm bin entry (the command-code/
	// prime-agent precedent), so node belongs here alongside the branded
	// name.
	"zcode": {"zcode.exe", "zcode", "node.exe", "node"},
	// Mistral Code (2026-08-18): CLI binary `vibe`, installed as a uv-tool
	// Python console script (requires Python 3.12+) — the aider precedent,
	// so python belongs here alongside the branded name.
	"mistral-code": {"vibe.exe", "vibe", "python.exe", "python"},
	// Freebuff / CodebuffAI (2026-08-18): npm `freebuff`, but the installed
	// entry point is itself a compiled ELF/exe binary (docs/freebuff-
	// adapter.md's off-limits note: "the `freebuff` ELF/exe binary") — the
	// kimi-code/goose native-binary precedent, so no node/python.
	"freebuff": {"freebuff.exe", "freebuff"},
	// Poolside (2026-09-05): the JetBrains-bundled ACP agent binary is
	// `pool-windows-amd64.exe` (grounded live under
	// <JetBrains vendor root>/acp-agents/poolside/<ver>/), spawned as its
	// own child process by the IDE. The bare `pool` stem is a documented
	// guess for the unverified macOS/Linux binary naming (no build was
	// available to ground on the grounding host).
	"poolside": {"pool-windows-amd64.exe", "pool"},
	// Zed (2026-09-06): the built-in agent runs INSIDE the Zed editor's
	// own process — there is no separate agent worker binary — so the
	// editor's own executable is both the root process and, when a
	// project is open, the process presenting in the project cwd (the
	// same shape as "cursor" above).
	"zed": {"zed.exe", "zed"},
}

// DefaultCrossOSToolLaunchers maps a session tool to the branded IDE/desktop
// process basenames that, when found as an ANCESTOR of a project-cwd process,
// identify that process's subtree as belonging to the tool (spec §5.5, the
// "inverse-of-codex" shape). The Codex DESKTOP app proved the worker-in-project
// pattern from the OTHER direction: its branded WORKER (codex-command-runner-*)
// runs IN the project cwd, so it anchors directly via DefaultCrossOSToolBasenames.
// The IDEs are inverted — a branded process runs from the INSTALL dir
// (Cursor.exe, OpenCode.exe, Codex.exe, Antigravity.exe, or VS Code's Code.exe)
// and spawns GENERIC workers (git/go/gopls/node/sh/powershell) that DO run in
// the project cwd. Those generic names can't go in DefaultCrossOSToolBasenames
// (a manual `git` in the project would false-anchor); instead a project-cwd
// process anchors when one of its ancestors is the tool's branded launcher
// here — the parent identity is the disambiguator (e.g. a git under OpenCode.exe
// vs the same git under Codex.exe in one shared project dir). Matched
// case-insensitively, prefix-pattern aware (basenameMatches). The VS Code family
// (copilot/cline/roo-code/zoo-code/kilo-code) shares Code.exe, so within VS Code
// the worker's cwd==project_root is what selects the session; only two VS Code AI
// tools open on the SAME project in the SAME window is genuinely ambiguous (a
// rare corner, resolved by nearest-start, medium confidence either way).
var DefaultCrossOSToolLaunchers = map[string][]string{
	"cursor":          {"cursor.exe", "cursor"},
	"opencode":        {"opencode.exe", "opencode"},
	"codex":           {"codex.exe", "codex"},
	"antigravity-cli": {"antigravity.exe", "agy.exe", "agy"},
	"antigravity":     {"antigravity.exe", "agy.exe", "agy"},
	"copilot":         {"code.exe"},
	"cline":           {"code.exe"},
	"roo-code":        {"code.exe"},
	// zoo-code (2026-09-03): same VS Code-family shape as roo-code —
	// see the DefaultCrossOSToolBasenames entry above.
	"zoo-code":  {"code.exe"},
	"kilo-code": {"code.exe"},
}

// DefaultRefreshLauncherBasenames are the DISTINCTIVE AI-tool launcher exe
// basenames the poll backend uses to decide which SURVIVOR subtrees get a live
// metrics-refresh event each poll (item 3 — "refresh non-token subtrees"). It
// deliberately EXCLUDES the generic interpreter names (node/python/bun) that
// DefaultCrossOSToolBasenames also accepts: at the capturer there is no
// cwd==project_root discriminator (that lives downstream in the daemon), so
// refreshing every node/python subtree would flood the cross-OS NDJSON wire —
// the exact volume the token-bounded refresh was built to avoid. Branded
// launchers are safe to match on name alone. Matched case-insensitively.
//
// Consequence (documented limitation): a tool that runs ONLY as a generic
// interpreter with no branded launcher process (Copilot, the in-IDE Cline/Kilo
// extensions, Hermes-as-python, Codex when it presents purely as node) keeps
// exec-time + accurate at-exit metrics rather than LIVE refresh of its
// long-running children. The precise fix is a daemon→capturer attributed-pid
// feedback channel (deferred, same class as the ETW reverse-channel).
//
// THE SCRIPT-WRAPPER SHAPE (grounded on a live install, 2026-08-27). Several
// tools install a launcher that is NOT a binary at all but a script, so the
// process the OS execs — and therefore the exe basename this map is matched
// against — is the INTERPRETER, never the tool's name. No row can be added for
// these, because the row would have to say "bash" or "python" or "node" and
// that is exactly the generic match the wire-volume rule forbids:
//
//	hermes   → ~/.local/bin/hermes is a bash script; the worker is python
//	           (this is the Hermes-as-python limitation named above, now with
//	           its cause: the wrapper, not the adapter)
//	vibe     → ~/.local/bin/vibe is a python script (mistral-code)
//	zcode    → an npm-installed node script
//	freebuff → an npm-installed node script
//
// A row was NOT invented for any of them: the registry's honesty rule is that
// a zero value means "no grounded capability", never a fabricated one. They
// keep cross-OS attribution via DefaultCrossOSToolBasenames plus exec-time and
// at-exit metrics; only LIVE refresh is skipped.
//
// muse is the one script-wrapper tool that IS reachable, and only through the
// prefix rule below — see DefaultRefreshLauncherPrefixes.
//
// The `observer` wrapper that roots every dashboard-launched subtree is also
// deliberately absent. Adding it would collide head-on with
// Options.ExcludeOwnBasenames, which exists to keep the daemon's own binary
// from being captured and mis-joined to whatever session shares its cwd. The
// principled fix for that subtree is the launch_seeds.run_id binding (task
// 9f), which identifies the child directly instead of guessing from its name.
var DefaultRefreshLauncherBasenames = map[string]bool{
	"claude.exe":   true, // claude-code (also EV/tokened on Windows; covers Linux-native + non-EV)
	"claude":       true,
	"codex.exe":    true,
	"codex":        true,
	"cursor.exe":   true,
	"cursor":       true,
	"cline.exe":    true, // cline-cli
	"cline":        true,
	"kilo.exe":     true, // kilo-code-cli
	"kilo":         true,
	"opencode.exe": true,
	"opencode":     true,
	"gemini.exe":   true, // gemini-cli
	"gemini":       true,
	"copilot.exe":  true, // copilot / copilot-cli (distinctive enough; not a generic interpreter)
	"copilot":      true,
	"openclaw.exe": true, // openclaw
	"openclaw":     true,
	"agy.exe":      true, // antigravity agent worker
	"agy":          true,
	// 2026-07 adapter wave — the DISTINCTIVE native-binary launcher names only.
	// These match the tool's own compiled binary (ELF/Rust/Go/bun-compiled) and
	// are safe on name alone; the generic interpreters those tools may ALSO
	// spawn (node/python/bun — see DefaultCrossOSToolBasenames) are deliberately
	// excluded here for the same wire-volume reason as above (no cwd guard at
	// the capturer). Without these rows the whole wave was silently downgraded
	// to the fragile cwd-anchor rule (audit 2026-07-15 root-cause #4).
	"qwen.exe":     true, // qwen-code (npm shim binary `qwen`)
	"qwen":         true,
	"kiro-cli.exe": true, // kiro-cli (AWS Kiro CLI native binary)
	"kiro-cli":     true,
	"crush.exe":    true, // crush (Charm Crush — Go binary)
	"crush":        true,
	"kimi.exe":     true, // kimi-code (Moonshot — bun-compiled ELF)
	"kimi":         true,
	"grok.exe":     true, // grok (xAI Grok — native ELF)
	"grok":         true,
	"devin.exe":    true, // devin (Cognition Devin CLI — native binary)
	"devin":        true,
	"aider.exe":    true, // aider (aider-chat — native-binary form only; see NOTE)
	"aider":        true,
	"qoder.exe":    true, // qoder (Alibaba Qoder CLI)
	"qoder":        true,
	"goose.exe":    true, // goose (Block goose — native Rust ELF)
	"goose":        true,
	// 2026-07-29 wave — distinctive branded launcher names only, same
	// rule as above (the generic node/node.exe that command-code's npm
	// shim also presents is deliberately NOT added: no cwd guard here).
	"droid.exe":        true, // droid (Factory AI — own binary)
	"droid":            true,
	"interpreter.exe":  true, // open-interpreter (rebadged Codex CLI Rust binary)
	"interpreter":      true,
	"command-code.exe": true, // command-code (npm bin alias; `cmd`/`cmdc` excluded as ambiguous)
	"command-code":     true,
	"commandcode.exe":  true,
	"commandcode":      true,
	// prime-agent (2026-08-06): npm bin alias, distinctive enough to match on
	// name alone (unlike `pi`, excluded below) — the generic node/node.exe the
	// shim also presents is deliberately not added, same rule as command-code.
	"prime-agent.exe": true,
	"prime-agent":     true,
	// NOTE: roo-code (node-only, no branded launcher), pi (`pi` too short/
	// generic to match on name alone without the cwd guard), and cowork (claude
	// launcher already covered) are intentionally NOT added here — they still
	// get cross-OS attribution via DefaultCrossOSToolBasenames + exec/at-exit
	// metrics; only the LIVE refresh of long-running children is skipped (the
	// documented generic-interpreter limitation above). Likewise the generic
	// interpreter names (node/node.exe/python/python.exe/bun) that the wave
	// tools' npm/python shims present are NEVER added — matching them on name
	// alone (no cwd discriminator here) would false-anchor a stray interpreter
	// and flood the cross-OS wire. aider's python-shim console-script form is
	// therefore uncovered BY DESIGN; only its native-binary form is matched.
	//
	// Likewise the script-wrapper tools (hermes / vibe / zcode / freebuff) get
	// no row at all — see the SCRIPT-WRAPPER SHAPE note above for why a row
	// for them is unrepresentable rather than merely missing.
}

// DefaultRefreshLauncherPrefixes are lowercased exe-basename PREFIXES that
// identify a distinctive AI-tool launcher whose binary carries a VERSION in
// its own filename, so no exact name can ever match it across upgrades.
//
// It is a separate, deliberately tiny list consulted only AFTER
// DefaultRefreshLauncherBasenames misses, so exact-match semantics are
// unchanged for every other tool: nothing that matched before matches
// differently now, and a prefix can only ever ADD a match. That ordering is
// the whole reason this is a second list instead of a rewrite of the first.
//
// WHY NOT THE "name*" CONVENTION basenameMatches uses. DefaultCrossOSToolBasenames
// encodes the same idea as a trailing "*" inside its per-tool SLICE, which it
// can afford because that slice is scanned linearly anyway. This list's
// companion is a MAP, looked up once per observed process on the poll backend's
// hot path; a "*"-suffixed key is unreachable by map lookup, so honouring it
// would mean scanning all ~60 entries on every miss — that is, on every
// non-AI process on the box. Same semantics, different data structure, so the
// prefixes live beside the map rather than inside it.
//
// A prefix earns a place here only when it is (a) grounded on a live install
// and (b) distinctive enough to be safe with no cwd discriminator — the same
// bar every exact row must clear. A short or generic prefix would match far
// more than its tool and flood the cross-OS wire, which is the failure this
// list is one careless entry away from.
//
// Grounded 2026-08-27 on a live install:
//
//	muse-bin- → Meta's Muse Code CLI installs ~/.local/bin/muse as a BASH
//	            SCRIPT (so the exec'd basename is "bash" — unmatchable, see
//	            the SCRIPT-WRAPPER SHAPE note) beside the real binary, which
//	            is version-stamped: "muse-bin-0.2.1-R1215.1". The version tail
//	            moves on every upgrade; the prefix does not.
var DefaultRefreshLauncherPrefixes = []string{
	"muse-bin-",
}

// matchesLauncherPrefix reports whether an already-lowercased basename starts
// with one of DefaultRefreshLauncherPrefixes.
func matchesLauncherPrefix(lowerBase string) bool {
	for _, p := range DefaultRefreshLauncherPrefixes {
		if strings.HasPrefix(lowerBase, p) {
			return true
		}
	}
	return false
}

// IsAIToolLauncher reports whether an executable path's basename is a
// DISTINCTIVE AI-tool launcher. The poll backend calls it to extend live
// metrics refresh to medium-attributed (non-env-token) AI subtrees on both the
// cross-OS bridge and native Linux.
//
// It is the SINGLE seam over both matching rules (CLAUDE.md rule 4): the exact
// DefaultRefreshLauncherBasenames map first, then — only on a miss — the
// version-stamped DefaultRefreshLauncherPrefixes. Every caller in the tree
// goes through this function rather than indexing the map itself, which is why
// the prefix rule reaches all of them without a second decision point that
// could drift.
func IsAIToolLauncher(exePath string) bool {
	base := strings.ToLower(basename(exePath))
	if DefaultRefreshLauncherBasenames[base] {
		return true
	}
	return matchesLauncherPrefix(base)
}

// CrossOSSessionRef is a session a Windows process tree may belong to (§5.5).
// ProjectRoot is the session's project root_path in whatever shape its adapter
// recorded it — Windows-shaped (C:\…) for a Windows tool reached through the
// wsl.exe hook bridge, or WSL-shaped (/mnt/d/…) for a native-Linux tool.
// pathsEqual folds both shapes to the daemon's native form before comparing, so
// a Windows-captured process cwd and a WSL session root match when they name
// the same directory (cwd-attribution scoping B2).
type CrossOSSessionRef struct {
	SessionID   string
	Tool        string
	ProjectID   int64
	ProjectRoot string
	StartedAt   time.Time
}

// CrossOSProcRef is the minimal persisted process-run projection the cross-OS
// correlator reads. Source/Confidence are the run's CURRENT attribution so the
// pass never overrides a higher-confidence one and stays idempotent.
type CrossOSProcRef struct {
	ProcessKey       string
	ParentProcessKey string
	ExeBasename      string
	CWD              string
	StartedAt        time.Time
	Source           AttributionSource
	Confidence       Confidence
}

// CrossOSAttribution assigns one process (by key) to a session, source
// cross_os_correlation, confidence medium.
type CrossOSAttribution struct {
	ProcessKey string
	SessionID  string
	Tool       string
	ProjectID  int64
	Source     AttributionSource
	Confidence Confidence
}

// CorrelateCrossOS implements the §5.5 deferred cross-OS pass with the same
// anchor+subtree machinery as CorrelateActions. A process is an ANCHOR for a
// session when its exe basename is in that tool's set, its cwd equals the
// session's project root, and it started within `window` of the session; the
// session attribution then propagates DOWN that process's subtree (via
// parent_process_key) until another anchor, never crossing into a run already
// attributed at HIGH confidence (those are authoritative — bridge/inherited/
// adapter_pid). Only the ROOT must match by cwd/time; children are reached by
// inheritance regardless of their own cwd/start (§9.2.2).
//
// Pure: the store loads sessions+runs and applies the returned attributions.
// window <= 0 uses CrossOSWindow; basenames nil uses DefaultCrossOSToolBasenames.
// Idempotent — a run already cross-OS-attributed re-emits identically and the
// store UPDATE is confidence-guarded.
func CorrelateCrossOS(sessions []CrossOSSessionRef, runs []CrossOSProcRef, basenames map[string][]string, window time.Duration) []CrossOSAttribution {
	if window <= 0 {
		window = CrossOSWindow
	}
	if basenames == nil {
		basenames = DefaultCrossOSToolBasenames
	}
	launchers := DefaultCrossOSToolLaunchers

	byKey := make(map[string]*CrossOSProcRef, len(runs))
	children := make(map[string][]string)
	for i := range runs {
		r := &runs[i]
		byKey[r.ProcessKey] = r
		if r.ParentProcessKey != "" {
			children[r.ParentProcessKey] = append(children[r.ParentProcessKey], r.ProcessKey)
		}
	}

	// Anchors: each eligible run matched to its best (nearest-in-time) session.
	anchors := make(map[string]CrossOSSessionRef)
	for i := range runs {
		r := &runs[i]
		if r.Confidence == ConfHigh {
			continue // authoritative — never re-anchored
		}
		if s, ok := bestSession(r, sessions, basenames, launchers, byKey, window); ok {
			anchors[r.ProcessKey] = s
		}
	}

	// Climb each anchor to the session's true ROOT (see climbToSessionRoot). A
	// tool (codex et al.) launches its root process a few seconds BEFORE the
	// session file logs its first event, so the root itself falls outside
	// bestSession's back-skew and only a later CHILD anchors directly. Without
	// the climb, the root's other children (e.g. a python the session ran) are
	// siblings of that child — not descendants — and never inherit. Re-homing
	// the anchor to the root makes the whole subtree attributable.
	if len(anchors) > 0 {
		climbed := make(map[string]CrossOSSessionRef, len(anchors))
		for anchorKey, sess := range anchors {
			root := climbToSessionRoot(anchorKey, byKey, basenames[sess.Tool], sess.ProjectRoot)
			// If two anchors climb to one root, keep the session whose start is
			// nearest the root's start — deterministic regardless of map order.
			if existing, ok := climbed[root]; ok {
				if rootRun := byKey[root]; rootRun != nil &&
					absDuration(existing.StartedAt.Sub(rootRun.StartedAt)) <= absDuration(sess.StartedAt.Sub(rootRun.StartedAt)) {
					continue
				}
			}
			climbed[root] = sess
		}
		anchors = climbed
	}

	out := make([]CrossOSAttribution, 0, len(anchors))
	assigned := make(map[string]bool)
	for anchorKey, sess := range anchors {
		// DFS the anchor's subtree, assigning the session to non-authoritative
		// nodes and stopping at any OTHER anchor (that subtree owns itself).
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
			if r == nil || r.Confidence == ConfHigh {
				continue // never override an authoritative attribution
			}
			assigned[k] = true
			out = append(out, CrossOSAttribution{
				ProcessKey: k,
				SessionID:  sess.SessionID,
				Tool:       sess.Tool,
				ProjectID:  sess.ProjectID,
				Source:     AttrCrossOSCorrelation,
				Confidence: ConfMedium,
			})
			stack = append(stack, children[k]...)
		}
	}
	return out
}

// bestSession picks the session a process anchors to. The process must run in
// the session's project root and within the window, AND be identifiable as the
// tool's: either its own exe basename is in the tool's worker set (the direct
// case — codex-command-runner et al.) OR one of its ancestors is the tool's
// branded launcher (the IDE case — a generic git/go/node worker under
// Cursor.exe/OpenCode.exe/Code.exe…, see DefaultCrossOSToolLaunchers). Ties
// break by closeness in time. ok=false when nothing matches.
func bestSession(r *CrossOSProcRef, sessions []CrossOSSessionRef, basenames, launchers map[string][]string, byKey map[string]*CrossOSProcRef, window time.Duration) (CrossOSSessionRef, bool) {
	var best CrossOSSessionRef
	found := false
	var bestAbs time.Duration
	for _, s := range sessions {
		// cwd + time are the strong discriminators; require them first.
		if !pathsEqual(r.CWD, s.ProjectRoot) {
			continue
		}
		delta := r.StartedAt.Sub(s.StartedAt)
		if delta < -crossOSBackSkew || delta > window {
			continue
		}
		// Identity: own basename in the worker set, or a branded-launcher
		// ancestor. Without one of these a process merely sharing the project
		// cwd (e.g. a manual `git`) must NOT anchor.
		if !basenameMatches(r.ExeBasename, basenames[s.Tool]) &&
			!hasLauncherAncestor(r, byKey, launchers[s.Tool]) {
			continue
		}
		abs := delta
		if abs < 0 {
			abs = -abs
		}
		if !found || abs < bestAbs {
			best, bestAbs, found = s, abs, true
		}
	}
	return best, found
}

// hasLauncherAncestor reports whether any ancestor of r (walking parent links
// via byKey) has an exe basename in launcherSet — i.e. r's subtree was spawned
// by the tool's branded IDE/desktop process. Bounded by a hop cap so a cyclic
// or pathological parent chain can never spin. r itself is NOT considered (a
// launcher running in its own install dir is not a project-cwd worker).
func hasLauncherAncestor(r *CrossOSProcRef, byKey map[string]*CrossOSProcRef, launcherSet []string) bool {
	if len(launcherSet) == 0 {
		return false
	}
	const maxHops = 64
	key := r.ParentProcessKey
	for hops := 0; hops < maxHops && key != ""; hops++ {
		p := byKey[key]
		if p == nil {
			return false
		}
		if basenameMatches(p.ExeBasename, launcherSet) {
			return true
		}
		key = p.ParentProcessKey
	}
	return false
}

// climbToSessionRoot walks up from an anchored process to the topmost ancestor
// that is STILL an eligible process for the session's tool AND shares its
// project-root cwd — the session's true root process. It stops at the first
// ancestor that is missing, high-confidence (authoritative, owns itself), a
// different tool/basename, or a different cwd, so it never climbs into a shared
// launcher (the bash/shell that started the tool) or a long-lived app-server.
// Returns the input key when there is nothing eligible to climb to.
func climbToSessionRoot(start string, byKey map[string]*CrossOSProcRef, set []string, projectRoot string) string {
	root := start
	for {
		r := byKey[root]
		if r == nil || r.ParentProcessKey == "" {
			return root
		}
		parent := byKey[r.ParentProcessKey]
		if parent == nil || parent.Confidence == ConfHigh {
			return root
		}
		if !basenameMatches(parent.ExeBasename, set) || !pathsEqual(parent.CWD, projectRoot) {
			return root
		}
		root = parent.ProcessKey
	}
}

// isASCIILetter reports whether b is an ASCII a-z/A-Z (a drive letter).
func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// absDuration returns the absolute value of d.
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// basenameMatches reports whether an exe basename is in the tool's allowed set
// (case-insensitive, Windows filesystem semantics). An entry ending in "*" is a
// case-insensitive PREFIX pattern — needed for the version-stamped workers the
// Codex desktop app spawns (codex-command-runner-<ver>.exe), where an exact
// name can't be pinned across upgrades. Everything else is an exact match.
func basenameMatches(base string, set []string) bool {
	if base == "" || len(set) == 0 {
		return false
	}
	for _, b := range set {
		if prefix, ok := strings.CutSuffix(b, "*"); ok {
			if prefix != "" && len(base) >= len(prefix) && strings.EqualFold(base[:len(prefix)], prefix) {
				return true
			}
			continue
		}
		if strings.EqualFold(base, b) {
			return true
		}
	}
	return false
}

// pathsEqual compares two paths after normalizing separators, trailing
// separators, and case (Windows paths are case-insensitive). Two empty paths
// never match — an unknown cwd must not anchor.
func pathsEqual(a, b string) bool {
	na, nb := normalizePath(a), normalizePath(b)
	return na != "" && na == nb
}

func normalizePath(p string) string {
	// Canonicalize across the OS boundary FIRST. A Windows-shaped path
	// (D:\proj, C:/proj, file://, \\wsl$\…, the Git-Bash /c/… form) and a
	// WSL-shaped path (/mnt/d/proj) can name the same directory but compared
	// verbatim never match — barrier B2 in the cwd-attribution scoping. On the
	// daemon's OS, TranslateForeignPath (pathnorm.Normalize) folds a foreign
	// drive-letter path to the native /mnt/<drive>/… form; on a WSL daemon that
	// makes a Windows-captured process cwd (D:\…) comparable to a WSL session
	// root (/mnt/d/…). It is applied to BOTH sides of pathsEqual so equality is
	// preserved regardless of which form each side arrived in, and its
	// never-fail contract returns unrecognised input unchanged. The subsequent
	// separator/trailing/case folding then makes the original Windows-only
	// matches (C:\proj == C:/proj == c:\proj\) hold on every host.
	// VS Code records a project root as a URI fsPath — `/c:/programsx/proj` (a
	// leading slash before the drive letter). TranslateForeignPath folds the
	// `c:/…` / `C:\…` / `/c/…` forms but not this one, so a Cursor/VS Code session
	// root would never match a captured `C:\…` worker cwd. Strip the spurious
	// leading slash so the drive-letter fold below applies.
	if len(p) >= 3 && p[0] == '/' && isASCIILetter(p[1]) && p[2] == ':' {
		p = p[1:]
	}
	p = crossmount.TranslateForeignPath(p)
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.TrimRight(p, "/")
	return strings.ToLower(p)
}
