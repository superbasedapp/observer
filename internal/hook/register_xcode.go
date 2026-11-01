package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
)

// # Xcode agent homes (surface-gap FU-145, S-2)
//
// Xcode 26.3+ runs its bundled Claude Agent with CLAUDE_CONFIG_DIR set to
// ~/Library/Developer/Xcode/CodingAssistant/ClaudeAgentConfig and its Codex
// with CODEX_HOME set to .../CodingAssistant/codex (MAC-1 read, 2026-10-28:
// Xcode 26.6 on macOS 26.2). Neither reads ~/.claude or ~/.codex, so the
// native writers never gate them (a Bash call carrying the deny marker ran
// through with Observer's ~/.claude hooks in place).
//
// claude-code-xcode writes Observer's Claude Code hooks into
// ClaudeAgentConfig/settings.json through the native settings writer
// (registerClaudeCodeAt); codex-xcode writes hooks.json, the config.toml
// [features] hooks switch and the hook trust records into
// CodingAssistant/codex through the native Codex writer (registerCodexAt).
// Same entry shapes and the same `observer hook claude-code|codex <event>`
// commands as the native targets, so isObserverClaudeEntry and
// isObserverCodexEntryNative own them, and Unregister removes exactly them.
//
// Both homes resolve through the catalogued agentconfig rows
// (claude-code/xcode-agent-home, codex/xcode-agent-home) with the package's
// one artifact-path helper, so the path is never a literal here. A target is
// detected, and written, only when its folder already exists as a real
// directory (Xcode created it): Observer never creates an Xcode home, and a
// symlinked home is refused rather than followed out of the Library tree.
//
// Both writers were built switched off (DEC-12) behind WriterKindHostHooks
// rows and are now ON: LCR-89 and LCR-90 passed on the macOS VM on
// 2026-10-28 with these writers' own output (Xcode 26.6, Mac round 5b).
// Xcode's Claude ran the settings.json hooks and blocked a deny-marker Bash
// call, and Xcode kept settings.json byte for byte. Xcode's Codex ran
// hooks.json and blocked the probe with no trust prompt; Xcode rewrites
// config.toml at every session start (its own keys and tables, often above
// Observer's lines) and keeps [features] hooks = true and the [hooks.state]
// trust records, so the Codex line edit must work on a file Xcode rewrote.
// With no project open Xcode runs Codex with cwd ~/Library/Autosave
// Information. A future recheck is one integration row again: the gate
// below still reads that list.
//
// gemini-cli-xcode (FU-160) writes Observer's Gemini CLI hooks into the
// settings.json of the home Xcode 26.6 gives its bundled Gemini CLI
// (CodingAssistant/gemini/.gemini, catalogued gemini-cli/xcode-agent-home;
// Mac round 5b found settings.json, GEMINI.md, projects.json, history/ and
// tmp/ there, and a shell call ran with no Observer hook). It goes through
// the native Gemini settings writer (registerGenericSettingsHooks) with the
// native `observer hook gemini-cli <event>` commands, so
// isObserverAnyHookEntry owns its entries and Unregister removes exactly
// them. That settings.json is Xcode's own file, whose contents Observer has
// not seen, so the target writes it under the D-268 credential-file rules
// whatever the base row says (hostOwnedFile): only the hooks member is
// spliced in, the checksum is the hooks-subtree digest, errors never quote
// the file, and an Unregister that leaves no hook removes the member it
// added. It is switched OFF (DEC-12) on LCR-91's result (MAC-6, 2026-10-30,
// FU-195): Xcode 26.6 kept Observer's hooks in that settings.json through its
// own launch rewrite and ran BeforeAgent, but never BeforeTool for its
// run_shell_command, so the tool gate cannot block there
// (integration.LiveGate.Finding). Another seam (Xcode's own tool approval,
// an MCP route) is a follow-up, not this writer.

// xcodeHostTarget is one Xcode agent-home target.
type xcodeHostTarget struct {
	// target is the Registry target and the RegistrationResult.Tool label.
	target string
	// tool is the registry row whose WriterKindHostHooks gates the writer.
	tool string
	// artifact is the catalogued directory row of the home.
	artifact string
	// hostOwnedFile puts the target's file under the D-268 credential-file
	// rules even when the base row does not declare them: the file is the
	// host's own, written before Observer and never read by a person here
	// (gemini-cli-xcode; hooksShareCredentialFile).
	hostOwnedFile bool
}

// xcodeHostTargets is the table of Xcode agent-home targets.
var xcodeHostTargets = []xcodeHostTarget{
	{target: "claude-code-xcode", tool: "claude-code", artifact: "claude-code/xcode-agent-home"},
	{target: "codex-xcode", tool: "codex", artifact: "codex/xcode-agent-home"},
	{target: "gemini-cli-xcode", tool: "gemini-cli", artifact: "gemini-cli/xcode-agent-home", hostOwnedFile: true},
}

// xcodeTargetFor returns the Xcode target row named target. Its tool is the
// registry row the target writes for, so the credential-file rules
// (hooksShareCredentialFile) and every other capability lookup answer for
// the base tool's file shape.
func xcodeTargetFor(target string) (xcodeHostTarget, bool) {
	for _, t := range xcodeHostTargets {
		if t.target == target {
			return t, true
		}
	}
	return xcodeHostTarget{}, false
}

// XcodeTargetBase returns the native tool an Xcode agent-home target
// ("claude-code-xcode") registers for, false for any other target. The
// callers (observer start, init, the dashboard, uninstall, the hook doctor)
// resolve the target's capability through it (FU-145); whether the target
// is switched on is LiveCheckGate's answer, and whether its home exists on
// this machine is Installed's.
func XcodeTargetBase(target string) (string, bool) {
	t, ok := xcodeTargetFor(target)
	return t.tool, ok
}

// XcodeTargetsFor returns the Xcode agent-home targets that register for the
// native tool base, in table order (gated ones included; LiveCheckGate says
// which are switched off).
func XcodeTargetsFor(base string) []string {
	var out []string
	for _, t := range xcodeHostTargets {
		if t.tool == base {
			out = append(out, t.target)
		}
	}
	return out
}

// xcodeTargetGateRows feeds the Xcode targets into the live-check gate from
// integration's rowless gated writers, so the gate is one list: deleting the
// integration row switches the target on.
func xcodeTargetGateRows() []liveGateRow {
	var out []liveGateRow
	for _, t := range xcodeHostTargets {
		gates := integration.RowlessWriterGates(t.tool, integration.WriterKindHostHooks)
		if !gates.Waiting() {
			continue
		}
		row := liveGateRow{target: t.target}
		for _, g := range gates {
			row.liveChecks = append(row.liveChecks, string(g))
		}
		out = append(out, row)
	}
	return out
}

// xcodeHomeState is what xcodeHomeDir found at an Xcode home.
type xcodeHomeState int

const (
	// xcodeHomeAbsent: no such directory (or no Xcode on this OS).
	xcodeHomeAbsent xcodeHomeState = iota
	// xcodeHomeLinked: the path is a symbolic link, refused.
	xcodeHomeLinked
	// xcodeHomeReady: a real directory.
	xcodeHomeReady
)

// xcodeHomeDir resolves the home of artifact and says what is there. err
// is a resolution refusal on macOS (a relocation the tool would read
// relative); on any other OS the catalogue names no Xcode home and the
// state is absent with no error.
func (r *Registry) xcodeHomeDir(artifact string) (string, xcodeHomeState, error) {
	dir, err := r.artifactDir(artifact)
	if err != nil {
		if r.hostGOOS() != "darwin" {
			return "", xcodeHomeAbsent, nil
		}
		return "", xcodeHomeAbsent, err
	}
	fi, err := os.Lstat(dir)
	switch {
	case err != nil:
		return dir, xcodeHomeAbsent, nil
	case fi.Mode()&os.ModeSymlink != 0:
		return dir, xcodeHomeLinked, nil
	case fi.IsDir():
		return dir, xcodeHomeReady, nil
	}
	return dir, xcodeHomeAbsent, nil
}

// installedXcodeTargets lists the Xcode targets whose home exists; a gated
// one (none today) only when includeGated is set (InstalledLiveGated).
func (r *Registry) installedXcodeTargets(includeGated bool) []string {
	var out []string
	for _, t := range xcodeHostTargets {
		if _, gated := LiveCheckGate(t.target); gated && !includeGated {
			continue
		}
		if _, st, _ := r.xcodeHomeDir(t.artifact); st == xcodeHomeReady {
			out = append(out, t.target)
		}
	}
	return out
}

// xcodeHomeOrSkip resolves t's home for a registration: the directory, or a
// result to return as it is (a refusal, or the not-applicable skip of a
// machine with no such Xcode home or a symlinked one).
func (r *Registry) xcodeHomeOrSkip(t xcodeHostTarget) (string, *RegistrationResult) {
	dir, st, err := r.xcodeHomeDir(t.artifact)
	if err != nil {
		return "", &RegistrationResult{Tool: t.target, DryRun: r.opts.DryRun, Error: err}
	}
	skip := func(reason string) *RegistrationResult {
		return &RegistrationResult{Tool: t.target, DryRun: r.opts.DryRun, Skipped: true, SkipKind: SkipNotApplicable, SkipReason: reason}
	}
	switch st {
	case xcodeHomeLinked:
		return "", skip(fmt.Sprintf("refused: %s is a symbolic link, which Observer does not follow out of Xcode's tree", dir))
	case xcodeHomeAbsent:
		if dir == "" {
			return "", skip("Xcode agent homes exist on macOS only")
		}
		return "", skip(fmt.Sprintf("no Xcode agent home at %s (Observer writes there only when Xcode created it)", dir))
	}
	return dir, nil
}

// registerClaudeCodeXcode writes claude-code-xcode.
func (r *Registry) registerClaudeCodeXcode() RegistrationResult {
	dir, skip := r.xcodeHomeOrSkip(xcodeHostTargets[0])
	if skip != nil {
		return *skip
	}
	return r.registerClaudeCodeAt("claude-code-xcode", dir, "hook.registerClaudeCodeXcode")
}

// unregisterClaudeCodeXcode removes claude-code-xcode's entries.
func (r *Registry) unregisterClaudeCodeXcode() UnregistrationResult {
	dir, st, err := r.xcodeHomeDir(xcodeHostTargets[0].artifact)
	if err != nil || st != xcodeHomeReady {
		return UnregistrationResult{Tool: "claude-code-xcode", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterClaudeCodeAt("claude-code-xcode", dir, "hook.unregisterClaudeCodeXcode")
}

// registerCodexXcode writes codex-xcode: the native Codex writer at the
// Xcode home (Xcode's Codex runs on macOS, so the POSIX quoting applies and
// trust is keyed by the hooks.json path it loads, as for the native target).
func (r *Registry) registerCodexXcode() RegistrationResult {
	dir, skip := r.xcodeHomeOrSkip(xcodeHostTargets[1])
	if skip != nil {
		return *skip
	}
	return r.registerCodexAt(codexHookTarget{
		tool:      "codex-xcode",
		dir:       dir,
		quote:     codexCmdQuoteIfNeeded,
		errPrefix: "hook.registerCodexXcode",
		matchMine: isObserverCodexEntryNative,
		trustKey:  nativeCodexTrustKey,
	})
}

// unregisterCodexXcode removes codex-xcode's entries and the trust records
// Observer wrote for them.
func (r *Registry) unregisterCodexXcode() UnregistrationResult {
	dir, st, err := r.xcodeHomeDir(xcodeHostTargets[1].artifact)
	if err != nil || st != xcodeHomeReady {
		return UnregistrationResult{Tool: "codex-xcode", DryRun: r.opts.DryRun, Skipped: true}
	}
	res := r.unregisterCodexAt("codex-xcode", dir, "hook.unregisterCodexXcode", nativeCodexTrustKey)
	if res.Error == nil && !r.opts.DryRun {
		r.removeLoneCodexSwitch(filepath.Join(dir, "config.toml"))
	}
	return res
}

// xcodeGeminiTarget is the native Gemini settings writer's target at the
// Xcode Gemini home dir: the base tool's commands and events, the
// gemini-cli-xcode label, and the host-file rules (hostTarget).
func xcodeGeminiTarget(dir, errPrefix string) genericSettingsHookTarget {
	return genericSettingsHookTarget{
		tool: "gemini-cli", resultTool: "gemini-cli-xcode", hostTarget: "gemini-cli-xcode",
		dir: dir, event: "BeforeAgent", errPrefix: errPrefix,
	}
}

// registerGeminiCLIXcode writes gemini-cli-xcode (refused on LCR-91's
// finding by Register before this runs).
func (r *Registry) registerGeminiCLIXcode() RegistrationResult {
	t, _ := xcodeTargetFor("gemini-cli-xcode")
	dir, skip := r.xcodeHomeOrSkip(t)
	if skip != nil {
		return *skip
	}
	return r.registerGenericSettingsHooks(xcodeGeminiTarget(dir, "hook.registerGeminiCLIXcode"))
}

// unregisterGeminiCLIXcode removes gemini-cli-xcode's entries (never gated).
func (r *Registry) unregisterGeminiCLIXcode() UnregistrationResult {
	t, _ := xcodeTargetFor("gemini-cli-xcode")
	dir, st, err := r.xcodeHomeDir(t.artifact)
	if err != nil || st != xcodeHomeReady {
		return UnregistrationResult{Tool: t.target, DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterGenericSettingsHooks(xcodeGeminiTarget(dir, "hook.unregisterGeminiCLIXcode"))
}

// removeLoneCodexSwitch deletes the Xcode Codex home's config.toml when all
// that is left in it is Observer's own [features] hooks switch (Xcode's
// Codex ships no config.toml, so the writer created it; audit item 10). Any
// other byte (a comment, another key, a table with content) keeps the
// file. A failed removal leaves the file as it is (the unregister itself
// succeeded) and is not an error.
func (r *Registry) removeLoneCodexSwitch(path string) {
	unlock, err := r.lockSettings(path)
	if err != nil {
		return
	}
	defer unlock()
	raw, err := regularfile.Read(path, 1<<20)
	if err != nil || !onlyObserverCodexSwitch(raw) {
		return
	}
	// FU-212: the bytes judged Observer's are compared again just before
	// the delete, so a file the user changed in between is kept.
	_ = removeEmptyConfigFile(path, raw)
}

// onlyObserverCodexSwitch reports whether a config.toml holds nothing but
// "[features]" / "hooks = true" and the empty trust tables the trust
// removal may leave.
func onlyObserverCodexSwitch(raw []byte) bool {
	allowed := map[string]bool{"[features]": true, "hooks = true": true, "[hooks]": true, "[hooks.state]": true}
	seen := false
	for _, line := range strings.Split(string(raw), "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		if !allowed[l] {
			return false
		}
		seen = seen || l == "hooks = true"
	}
	return seen
}
