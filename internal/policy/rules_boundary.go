package policy

import (
	"net/netip"
	"strings"
)

// Boundary & sensitive-path rules R-150…R-161 (spec §5.2). Path rules
// generally come in row pairs/quads per public ID (approved deviation
// 3): file-access rows match the resolved Event path; shell rows scan
// command units for path-shaped tokens, classified read vs write.
// Every row is pinned in rules_boundary_test.go, including the
// Windows shapes (%APPDATA%, PowerShell profiles, Run keys) — a
// Windows-first-arc requirement.

// actionIsWrite reports whether the models-taxonomy action verb
// mutates the target. The literals mirror internal/models (not
// imported — purity); unknown/empty verbs classify as reads, the
// less-alarming direction.
func actionIsWrite(actionType string) bool {
	switch actionType {
	case "write_file", "edit_file":
		return true
	default:
		return false
	}
}

// isWriteEvent reports whether the event as a whole is a write:
// write-verb file accesses, and config-change events by definition.
func isWriteEvent(ev *Event) bool {
	return ev.Kind == KindConfigChange || actionIsWrite(ev.ActionType)
}

// pathPattern is one row of a path-rule table: a glob (matched
// case-insensitively — conservative: correct on case-insensitive
// filesystems, negligible-FP on case-sensitive ones since legit
// different-case twins of ~/.ssh etc. don't occur) plus the
// human-readable description used in verdict reasons.
type pathPattern struct {
	glob string
	desc string
}

// sensitivePathPatterns is the R-152 sensitive set (spec §5.2):
// credential stores, browser profiles, OS keychains, wallet dirs —
// in "~/"-anchored form plus absolute Windows fallbacks for
// cross-flavor events whose home is unknown.
var sensitivePathPatterns = []pathPattern{
	{"~/.ssh/**", "SSH key material"},
	{"~/.aws/**", "AWS credentials"},
	{"~/.gnupg/**", "GnuPG keyring"},
	{"~/.kube/config", "Kubernetes credentials"},
	{"~/.netrc", "netrc credentials"},
	{"~/_netrc", "netrc credentials"},
	{"~/.npmrc", "npm auth configuration"},
	{"~/.docker/config.json", "Docker registry auth"},
	{"~/.config/gcloud/**", "gcloud credentials"},
	{"~/.azure/**", "Azure credentials"},
	{"~/.mozilla/firefox/**", "browser profile"},
	{"~/.config/google-chrome/**", "browser profile"},
	{"~/.config/chromium/**", "browser profile"},
	{"~/library/application support/google/chrome/**", "browser profile"},
	{"~/appdata/roaming/mozilla/firefox/**", "browser profile"},
	{"~/appdata/local/google/chrome/user data/**", "browser profile"},
	{"?:/users/*/.ssh/**", "SSH key material"},
	{"?:/users/*/.aws/**", "AWS credentials"},
	{"?:/users/*/appdata/roaming/mozilla/firefox/**", "browser profile"},
	{"?:/users/*/appdata/local/google/chrome/user data/**", "browser profile"},
	{"~/library/keychains/**", "macOS keychain"},
	{"~/.local/share/keyrings/**", "GNOME keyring"},
	{"~/appdata/roaming/microsoft/protect/**", "Windows DPAPI store"},
	{"?:/users/*/appdata/roaming/microsoft/protect/**", "Windows DPAPI store"},
	{"~/.bitcoin/**", "cryptocurrency wallet"},
	{"~/.electrum/**", "cryptocurrency wallet"},
	{"~/.ethereum/**", "cryptocurrency wallet"},
}

// secretFileBasenames is the R-153 secret-file set, matched against
// the target's basename.
var secretFileBasenames = []string{
	".env", ".env.*", "*.pem", "*.key",
	"id_rsa*", "id_ed25519*", "id_ecdsa*", "credentials*.json",
}

// secretExampleBasenames are the placeholder variants R-153 must NOT
// fire on (.env.example committed to repos — the classic FP).
var secretExampleBasenames = []string{"*.example", "*.sample", "*.template", "*.dist"}

// shellProfilePatterns is the R-154 persistence surface: shell rc /
// profile files across POSIX shells and both PowerShell generations
// (including OneDrive-redirected Documents).
var shellProfilePatterns = []pathPattern{
	{"~/.bashrc", "bash rc file"},
	{"~/.bash_profile", "bash profile"},
	{"~/.bash_login", "bash login file"},
	{"~/.profile", "shell profile"},
	{"~/.zshrc", "zsh rc file"},
	{"~/.zprofile", "zsh profile"},
	{"~/.zshenv", "zsh env file"},
	{"~/.zlogin", "zsh login file"},
	{"~/.config/fish/config.fish", "fish config"},
	{"~/documents/powershell/*profile*.ps1", "PowerShell profile"},
	{"~/documents/windowspowershell/*profile*.ps1", "PowerShell profile"},
	{"~/onedrive/documents/powershell/*profile*.ps1", "PowerShell profile"},
	{"~/onedrive/documents/windowspowershell/*profile*.ps1", "PowerShell profile"},
	{"?:/users/*/documents/powershell/*profile*.ps1", "PowerShell profile"},
	{"?:/users/*/documents/windowspowershell/*profile*.ps1", "PowerShell profile"},
}

// persistencePathPatterns is the R-155 path surface: cron, systemd
// user units, LaunchAgents/Daemons, XDG autostart, Windows Startup
// folders.
var persistencePathPatterns = []pathPattern{
	{"/etc/crontab", "system crontab"},
	{"/etc/cron*/**", "system cron directory"},
	{"/var/spool/cron/**", "user crontab spool"},
	{"~/.config/systemd/user/**", "systemd user unit"},
	{"/etc/systemd/**", "systemd unit"},
	{"~/library/launchagents/**", "LaunchAgent"},
	{"/library/launchagents/**", "system LaunchAgent"},
	{"/library/launchdaemons/**", "LaunchDaemon"},
	{"~/.config/autostart/**", "XDG autostart entry"},
	{"~/appdata/roaming/microsoft/windows/start menu/programs/startup/**", "Windows Startup folder"},
	{"?:/users/*/appdata/roaming/microsoft/windows/start menu/programs/startup/**", "Windows Startup folder"},
	{"?:/programdata/microsoft/windows/start menu/programs/startup/**", "Windows Startup folder"},
}

// gitHooksPatterns is the R-156 surface: in-repo git hooks, a
// persistence vector that executes on the next git operation.
var gitHooksPatterns = []pathPattern{
	{"**/.git/hooks/**", "git hook"},
}

// observerConfigPatterns is the R-160 surface: observer's own
// configuration plus the client hook-bearing config files an agent
// could edit to unhook us (gap F4 — tamper-EVIDENT, with self-heal at
// observer start). Project-level .claude/settings.local.json is
// deliberately ABSENT: the host tool itself writes it on every
// permission grant; flagging it would be constant noise and denying
// it would break the host tool (revisit with the G6 conformance
// matrix).
// The `~/.observer/**` glob already covers the dashboard-authored
// trusted per-project layer dir (~/.observer/guard-project-policies/),
// so an agent write there is denied with no new matcher — that coverage
// is what lets the trusted layer safely carry weaken/disable semantics
// (guard-rule-management-ui plan §3.4).
var observerConfigPatterns = []pathPattern{
	{"~/.observer/**", "observer configuration"},
	{"?:/users/*/.observer/**", "observer configuration"},
	{"~/.claude/settings.json", "Claude Code hook settings"},
	{"**/.claude/settings.json", "project Claude Code hook settings"},
	{"~/.codex/config.toml", "Codex configuration"},
}

// clientConfigDirPatterns is the R-150 exclusion set: the AI clients'
// own config/state dirs, which their tools touch routinely and
// legitimately from any project (spec §5.2 "the client's own config
// dir").
var clientConfigDirPatterns = []string{
	"~/.claude/**", "~/.codex/**", "~/.cursor/**", "~/.observer/**",
	"~/.gemini/**", "~/.config/opencode/**", "~/.local/share/opencode/**",
	"~/.cline/**", "~/.copilot/**",
}

// boundaryRules returns the §5.2 table. Path rules use the shared
// faPathMatch/shPathMatch constructors so matching and write/read
// classification stay in ONE place.
func boundaryRules() []Rule {
	fa := []EventKind{KindFileAccess}
	faCfg := []EventKind{KindFileAccess, KindConfigChange}
	shell := []EventKind{KindShellExec}
	boundarySafe := []SafeFn{safePathAllowlisted, safeClientConfigPath}
	return []Rule{
		{
			ID: "R-150", Category: CategoryBoundary, Severity: SeverityWarn,
			AppliesTo: fa, Match: matchOutsideProject(false),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			SafePat: boundarySafe,
			Doc:     "file read outside the project root",
			Advice:  "Reads outside the project are recorded; add a [guard.boundary] allow_paths entry if this location is routine.",
		},
		{
			ID: "R-150", Category: CategoryBoundary, Severity: SeverityWarn,
			AppliesTo: fa, Match: matchOutsideProject(true),
			Observe: DecisionFlag, Enforce: DecisionAsk,
			SafePat: boundarySafe,
			Doc:     "file write outside the project root",
			Advice:  "Write inside the project, or add a [guard.boundary] allow_paths entry for this location.",
		},
		{
			ID: "R-151", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: fa, Match: matchCrossProjectWrite,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "write into a DIFFERENT observed project's root (cross-project bleed)",
			Advice: "Open that project in its own session instead of writing across project boundaries.",
		},
		{
			ID: "R-152", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: fa, Match: faPathMatch(sensitivePathPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "write to a sensitive credential/profile location",
			Advice: "Credential stores are off-limits to agents; have the operator make this change.",
		},
		{
			ID: "R-152", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: fa, Match: faPathMatch(sensitivePathPatterns, false),
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "read of a sensitive credential/profile location",
			Advice: "If a credential is genuinely needed, ask the operator to provide it explicitly.",
		},
		{
			ID: "R-152", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: shPathMatch(sensitivePathPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "shell command writing to a sensitive credential/profile location",
			Advice: "Credential stores are off-limits to agents; have the operator make this change.",
		},
		{
			ID: "R-152", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: shPathMatch(sensitivePathPatterns, false),
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "shell command reading a sensitive credential/profile location",
			Advice: "If a credential is genuinely needed, ask the operator to provide it explicitly.",
		},
		{
			ID: "R-153", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: fa, Match: matchSecretFileReadFA,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			SafePat: []SafeFn{safeSecretExampleFile},
			Doc:     "read of a secret-bearing file (.env / key material / credentials)",
			Advice:  "Use a placeholder (.env.example) or have the operator supply the value.",
		},
		{
			ID: "R-153", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchSecretFileReadShell,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "shell command reading a secret-bearing file (.env / key material / credentials)",
			Advice: "Use a placeholder (.env.example) or have the operator supply the value.",
		},
		{
			ID: "R-154", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: faCfg, Match: faPathMatch(shellProfilePatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "write to a shell rc/profile file (persistence vector)",
			Advice: "Profile changes outlive the session; have the operator apply them.",
		},
		{
			ID: "R-154", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: shPathMatch(shellProfilePatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "shell command writing to a shell rc/profile file (persistence vector)",
			Advice: "Profile changes outlive the session; have the operator apply them.",
		},
		{
			ID: "R-155", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: faCfg, Match: faPathMatch(persistencePathPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "write to an autostart/persistence location (cron, systemd, LaunchAgents, Startup)",
			Advice: "Persistent scheduling needs the operator; agents must not install autostart entries.",
		},
		{
			ID: "R-155", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: shPathMatch(persistencePathPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "shell command writing to an autostart/persistence location",
			Advice: "Persistent scheduling needs the operator; agents must not install autostart entries.",
		},
		{
			ID: "R-155", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchPersistenceCommand,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			SafePat: []SafeFn{safeCrontabList, safeObserverETWTaskRegistration},
			Doc:     "persistence-installing command (crontab / schtasks /create / Run registry key / systemctl enable)",
			Advice:  "Persistent scheduling needs the operator; agents must not install autostart entries.",
		},
		{
			ID: "R-156", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: faCfg, Match: faPathMatch(gitHooksPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "write to .git/hooks (in-repo persistence vector)",
			Advice: "Git hooks execute on the next git operation; review the hook body before allowing.",
		},
		{
			ID: "R-156", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: shPathMatch(gitHooksPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "shell command writing to .git/hooks (in-repo persistence vector)",
			Advice: "Git hooks execute on the next git operation; review the hook body before allowing.",
		},
		{
			ID: "R-157", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchUnanalyzedWrapper,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "wrapper whose inner command could not be analysed (fail-closed)",
			Advice: "Run the inner command directly, or reduce the wrapper nesting, so it can be evaluated on its own terms.",
		},
		{
			ID: "R-160", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: faCfg, Match: faPathMatch(observerConfigPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent modifying observer/guard/hook configuration",
			Advice: "Guard and hook configuration is operator-owned (F4); ask the operator to change it.",
		},
		{
			ID: "R-160", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: shPathMatch(observerConfigPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "shell command modifying observer/guard/hook configuration",
			Advice: "Guard and hook configuration is operator-owned (F4); ask the operator to change it.",
		},
		{
			ID: "R-161", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: faCfg, Match: matchProjectPolicyWriteFA,
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "agent modifying the project guard policy file",
			Advice: "Project policy edits are recorded; this in-repo file is escalate-only (§4.6 drops any loosening it attempts). Dashboard-managed project relaxations live in the R-160-protected daemon-local trusted layer, which the agent cannot write.",
		},
		{
			ID: "R-161", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchProjectPolicyWriteShell,
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "shell command modifying the project guard policy file",
			Advice: "Project policy edits are recorded; this in-repo file is escalate-only (§4.6 drops any loosening it attempts). Dashboard-managed project relaxations live in the R-160-protected daemon-local trusted layer, which the agent cannot write.",
		},
	}
}

// --- shared path matching ---------------------------------------------

// homeRelative rewrites an absolute path under home into its
// "~/"-anchored form for pattern matching. ok is false when p is not
// under home (or home is unknown).
func homeRelative(p, home string) (string, bool) {
	np, nh := normPath(p), normPath(home)
	if nh == "" || !isUnder(np, nh) {
		return "", false
	}
	if len(np) <= len(nh) {
		return "~", true
	}
	return "~/" + np[len(nh)+1:], true
}

// pathPatternMatch matches a resolved path against a pattern table,
// trying both the absolute form and (when under home) the
// "~/"-anchored form. Unexpanded literal "~/..." paths (empty-home
// degradation) match the "~" patterns directly.
func pathPatternMatch(p, home string, pats []pathPattern) (string, bool) {
	if p == "" {
		return "", false
	}
	forms := []string{p}
	if rel, ok := homeRelative(p, home); ok {
		forms = append(forms, rel)
	}
	for _, pat := range pats {
		for _, f := range forms {
			if matchGlob(pat.glob, f, true) {
				return pat.desc, true
			}
		}
	}
	return "", false
}

// faPathMatch builds a file-access matcher over a pattern table for
// the given write/read direction.
func faPathMatch(pats []pathPattern, wantWrite bool) MatchFn {
	return func(ctx *MatchContext) (bool, string) {
		if isWriteEvent(ctx.Event) != wantWrite {
			return false, ""
		}
		desc, ok := pathPatternMatch(ctx.Path, ctx.Cfg.Home, pats)
		if !ok {
			return false, ""
		}
		return true, desc + " (" + ctx.Event.Target + ")"
	}
}

// shPathMatch builds a command-unit matcher over a pattern table:
// every path-candidate token resolves and matches against the table,
// then classifies as write or read access within the unit.
func shPathMatch(pats []pathPattern, wantWrite bool) MatchCmdFn {
	return func(ctx *MatchContext, cmd *Command) (bool, string) {
		for _, t := range unitPathTokens(cmd) {
			rp := resolveOrLiteral(ctx, t)
			desc, ok := pathPatternMatch(rp, ctx.Cfg.Home, pats)
			if !ok {
				continue
			}
			if classifyWrite(cmd, t) == wantWrite {
				return true, desc + " (" + t + ")"
			}
		}
		return false, ""
	}
}

// writeBases are command bases whose pathish operands are written
// regardless of position.
var writeBases = map[string]bool{
	"tee": true, "truncate": true, "install": true,
	"set-content": true, "add-content": true, "out-file": true, "new-item": true,
}

// destBases are copy/move-style commands whose LAST pathish operand
// is the written destination.
var destBases = map[string]bool{
	"cp": true, "mv": true, "rsync": true, "scp": true,
	"copy-item": true, "move-item": true,
}

// classifyWrite classifies one path token's access direction within a
// unit (documented approximation, pinned by tests): redirect targets
// are writes; writeBases write all operands; copy/move write their
// last operand; sed -i writes in place; delete commands write
// (destroy) their targets; everything else reads.
func classifyWrite(cmd *Command, tok string) bool {
	for _, r := range cmd.RedirectTargets {
		if r == tok {
			return true
		}
	}
	if writeBases[cmd.Base] {
		return true
	}
	if _, isDelete := deleteShape(cmd); isDelete {
		return true
	}
	if cmd.Base == "sed" && (cmd.HasShortFlag('i') || cmd.HasLongFlag("--in-place")) {
		return true
	}
	if destBases[cmd.Base] {
		pathish := unitPathTokens(cmd)
		return len(pathish) >= 2 && pathish[len(pathish)-1] == tok
	}
	return false
}

// --- R-150 / R-151 ----------------------------------------------------

// matchOutsideProject builds the R-150 matcher for the given
// direction. No project root (or a cross-flavor path the boundary
// didn't translate) means no hit — unknown is not a violation.
func matchOutsideProject(wantWrite bool) MatchFn {
	return func(ctx *MatchContext) (bool, string) {
		if isWriteEvent(ctx.Event) != wantWrite {
			return false, ""
		}
		p, pr := ctx.Path, ctx.Event.ProjectRoot
		if p == "" || pr == "" || !comparableFlavors(p, pr) || isUnder(p, pr) {
			return false, ""
		}
		return true, "path " + ctx.Event.Target + " is outside the project root"
	}
}

// matchCrossProjectWrite implements R-151: a write landing inside a
// DIFFERENT observed project's root — detectable only because the
// daemon knows every project root it watches.
func matchCrossProjectWrite(ctx *MatchContext) (bool, string) {
	if !isWriteEvent(ctx.Event) || ctx.Path == "" {
		return false, ""
	}
	cur := ctx.Event.ProjectRoot
	if cur != "" && isUnder(ctx.Path, cur) {
		return false, "" // inside the current project: never cross-bleed
	}
	for _, root := range ctx.Cfg.KnownProjectRoots {
		if root == "" || (cur != "" && pathsEqual(root, cur)) {
			continue
		}
		if isUnder(ctx.Path, root) {
			return true, "write into observed project " + root
		}
	}
	return false, ""
}

// safePathAllowlisted exempts file-access paths under
// [guard.boundary].allow_paths (both absolute and "~/"-anchored
// forms, via matchAllowPaths).
func safePathAllowlisted(ctx *MatchContext, _ *Command) bool {
	return matchAllowPaths(ctx, ctx.Path)
}

// safeClientConfigPath exempts the AI clients' own config/state dirs
// (touched routinely from any project — R-150's catalog exclusion).
func safeClientConfigPath(ctx *MatchContext, _ *Command) bool {
	if ctx.Path == "" {
		return false
	}
	rel, ok := homeRelative(ctx.Path, ctx.Cfg.Home)
	if !ok {
		rel = ctx.Path // unexpanded "~/..." literals match directly
	}
	return matchAnyGlob(clientConfigDirPatterns, rel, true)
}

// --- R-153 -------------------------------------------------------------

// secretBasename reports whether name matches the R-153 secret-file
// set.
func secretBasename(name string) bool {
	if name == "" {
		return false
	}
	return matchAnyGlob(secretFileBasenames, name, true)
}

// exampleBasename reports whether name is a placeholder variant
// (.env.example etc.).
func exampleBasename(name string) bool {
	return matchAnyGlob(secretExampleBasenames, name, true)
}

// matchSecretFileReadFA implements the R-153 file-access row.
func matchSecretFileReadFA(ctx *MatchContext) (bool, string) {
	if isWriteEvent(ctx.Event) {
		return false, ""
	}
	if !secretBasename(baseName(ctx.Path)) {
		return false, ""
	}
	return true, "secret file " + ctx.Event.Target
}

// matchSecretFileReadShell implements the R-153 shell row. Unlike the
// generic path rules it scans ALL positionals, not just pathish ones:
// the canonical `cat .env` carries a bare dotfile token, and the
// secret-basename glob itself is the precision filter. The
// example-file exclusion is token-level here (a unit can touch both a
// real and a placeholder file), unlike the file-access row where it
// is a rule-level safe pattern.
func matchSecretFileReadShell(ctx *MatchContext, cmd *Command) (bool, string) {
	for _, t := range append(cmd.Positionals(), cmd.RedirectTargets...) {
		name := baseName(resolveOrLiteral(ctx, t))
		if !secretBasename(name) || exampleBasename(name) {
			continue
		}
		if !classifyWrite(cmd, t) {
			return true, "secret file " + t
		}
	}
	return false, ""
}

// safeSecretExampleFile exempts placeholder files on the R-153
// file-access row.
func safeSecretExampleFile(ctx *MatchContext, _ *Command) bool {
	return exampleBasename(baseName(ctx.Path))
}

// --- R-155 command shapes ----------------------------------------------

// runKeyToken reports whether a token references the Windows
// CurrentVersion\Run registry persistence keys.
func runKeyToken(t string) bool {
	low := strings.ToLower(strings.ReplaceAll(t, "/", `\`))
	return strings.Contains(low, `\currentversion\run`)
}

// matchPersistenceCommand implements the R-155 command row:
// crontab installs, schtasks /create, Run-key registry writes, and
// systemctl enable. (launchctl load is deliberately absent — routine
// for dev services; the LaunchAgents PATH row catches actual
// persistence writes.) Exactly one narrow exemption exists, applied by
// the engine BEFORE this matcher: safeObserverETWTaskRegistration.
func matchPersistenceCommand(_ *MatchContext, cmd *Command) (bool, string) {
	switch cmd.Base {
	case "crontab":
		return true, "crontab modification"
	case "schtasks":
		if cmdHasFlag(cmd, "create") {
			return true, "schtasks /create scheduled task"
		}
	case "reg":
		if cmd.Sub() == "add" {
			for _, a := range cmd.Args() {
				if runKeyToken(a) {
					return true, "Run registry key write"
				}
			}
		}
	case "set-itemproperty", "new-itemproperty":
		for _, a := range cmd.Args() {
			if runKeyToken(a) {
				return true, "Run registry key write"
			}
		}
	case "systemctl":
		for _, p := range cmd.Positionals() {
			if p == "enable" {
				return true, "systemctl enable (persistent unit)"
			}
		}
	}
	return false, ""
}

// safeCrontabList exempts the read-only `crontab -l` listing.
func safeCrontabList(_ *MatchContext, cmd *Command) bool {
	return cmd != nil && cmd.Base == "crontab" && cmd.HasShortFlag('l')
}

// --- R-157 -------------------------------------------------------------

// matchUnanalyzedWrapper implements R-157: a unit that WRAPS a command
// the parser could not analyse.
//
// This rule exists because every limit in shellparse/launcher used to
// fail OPEN, which made an unreadable wrapper strictly SAFER for an
// attacker than a readable one. All four paths were measured
// (docs/security.md H5 round 2):
//
//   - `wsl -- ` nested FIVE deep denies; SIX ALLOWED. The parser set
//     Command.Payload at the limit with a comment saying the payload
//     was "recorded rather than dropped" — but no rule, matcher or
//     compiled user rule reads Payload, so the preservation preserved
//     nothing.
//   - a launcher that NAMED a target no reading could recover
//     returned nil and the wrapper matched no rule.
//   - the candidate fan-out bound and the expansion budget, added with
//     this rule, would have been two more of the same.
//
// The unit's own Raw is the detail: the operator needs to see the
// line that could not be read, and the inner command is by definition
// not available.
func matchUnanalyzedWrapper(_ *MatchContext, cmd *Command) (bool, string) {
	if cmd == nil || cmd.Unanalyzed == "" {
		return false, ""
	}
	return true, cmd.Unanalyzed + " (" + clampDetail(cmd.Raw) + ")"
}

// clampDetail bounds a raw command line quoted into a verdict Reason.
func clampDetail(s string) string {
	const max = 120
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// observerETWTaskName is the FROZEN Scheduled Task name observer's own
// Windows-ETW capturer registration uses. It is a literal, not a
// pattern: the carve-out below must recognize exactly ONE task, so a
// future reader cannot widen it into "tasks whose name starts with
// SuperBased" without editing this constant deliberately.
const observerETWTaskName = "SuperBasedObserverETW"

// observerETWProgramBase is the file name of the program the ETW task
// must run — observer's own binary — after the directory and an
// OPTIONAL `.exe` suffix are stripped and the result is lowercased.
const observerETWProgramBase = "observer"

// observerETWSubcommand is the observer subcommand the ETW task's
// action must invoke immediately after the binary.
const observerETWSubcommand = "process-bridge"

// etwSpace is the whitespace set this carve-out uses everywhere: the
// action tokenizer, and the "a program token has no whitespace"
// invariant that the tokenizer establishes. It is spelled out rather
// than deferred to unicode.IsSpace so that "whitespace-free" means
// exactly ONE thing in every part of the predicate.
const etwSpace = " \t\n\v\f\r"

// --- R-155 ETW carve-out: the schtasks argv ----------------------------

// etwAllowedSchtasksFlags is the CLOSED set of schtasks flags the
// carve-out tolerates. It is exactly the flags observer's own emitted
// command uses (`/Create /TN /SC /RL /TR`) plus the two an operator is
// documented to add by hand: `/F` (re-register over an existing task)
// and `/RU` (run the task as a named account).
//
// Everything else denies. The flags that make this matter are the ones
// that change WHAT or WHERE the registration is:
//
//	/S /U /P   — create the task on ANOTHER MACHINE, as another user
//	/XML       — take the whole task definition from a file, which puts
//	             the real program outside anything /TR can vouch for
//	/RP        — a password on the command line
//
// Failing closed on an unrecognized flag costs nothing: the operator can
// always run the command themselves.
var etwAllowedSchtasksFlags = map[string]bool{
	"create": true,
	"tn":     true,
	"tr":     true,
	"sc":     true,
	"rl":     true,
	"f":      true,
	"ru":     true,
}

// etwValuedSchtasksFlags are the allow-listed flags that consume the
// FOLLOWING argv token as their value in the two-token form.
var etwValuedSchtasksFlags = map[string]bool{
	"tn": true, "tr": true, "sc": true, "rl": true, "ru": true,
}

// etwSchtasksFlags is a parsed schtasks argv: lower-cased flag name →
// its value ("" for a boolean flag).
type etwSchtasksFlags map[string]string

// value returns the flag's value with any surrounding quotes trimmed —
// the shape a WHOLE-value comparison (like /TN) wants. The lexer strips
// quotes for us in every dialect, but a value that arrived pre-quoted
// from an argv-delivering boundary must not silently fail to compare.
//
// /TR deliberately does NOT go through this: an action's own quoting is
// semantically load-bearing (it is what delimits the program token from
// its arguments), so etwActionTokens reads the RAW value.
func (f etwSchtasksFlags) value(name string) (string, bool) {
	v, ok := f[name]
	if !ok {
		return "", false
	}
	return strings.Trim(v, `"'`), true
}

// etwParseSchtasksArgv resolves a schtasks argv into flag→value in ONE
// pass, or reports ok=false when the argv is not a shape this carve-out
// positively recognizes.
//
// ONE PASS IS THE SECURITY PROPERTY, not a tidiness preference. The
// previous implementation had two walks with DIFFERENT notions of what
// a flag is: the /TR lookup scanned every token including flag VALUES,
// while the allow-list walk skipped a valued flag's value. A decoy
// `/TR:` hidden inside another flag's value was therefore read as the
// action, while the real `/TR` token was consumed and never inspected —
// `schtasks /Create /TN <ours> /SC "/TR:'C:\o\observer.exe'
// process-bridge" /TR "C:\evil\payload.exe"` was exempted. Reading a
// single map built by a single walk removes the disagreement by
// construction; do NOT reintroduce a second scan over cmd.Argv.
//
// Both real argv shapes are handled: the two-token form (`/TN name`)
// and the single-token colon form (`/TN:name`). `=` is deliberately NOT
// a separator — measured 2026-07-26 against real schtasks, `/TN:x` is
// accepted and `/TN=x` is rejected outright ("ERROR: Invalid
// argument/option"). Accepting a separator the tool itself refuses is
// dead surface on a security predicate: it can only ever widen what is
// exempted, against a command that could never execute.
//
// Three shapes fail closed that a permissive parser would wave through:
//
//   - A DUPLICATE flag. `/TR <ours> /TR <evil>` would otherwise be
//     first-wins here while schtasks itself takes neither (it rejects
//     duplicates — re-measured read-only 2026-07-26, both the two-token
//     and the colon form). We do not rely on that: a security property
//     must not depend on another tool's input validation.
//   - A valued flag whose value ITSELF starts with `/`. That is the
//     `/RL /XML:C:\evil\task.xml` shape, where a rejected flag hides in
//     an allowed flag's value slot. No legitimate value of /TN /TR /SC
//     /RL /RU begins with a slash (they are task names, Windows program
//     paths, ONLOGON, HIGHEST and account names), so refusing one costs
//     nothing real.
//   - A VALUED flag glued into a concatenated run (`/Create/TR`). Glued
//     flags are honored for booleans only (`/Create/F`); a glued valued
//     flag has nowhere to put its value.
func etwParseSchtasksArgv(cmd *Command) (etwSchtasksFlags, bool) {
	if cmd == nil {
		return nil, false
	}
	out := etwSchtasksFlags{}
	set := func(name, value string) bool {
		name = strings.ToLower(name)
		if !etwAllowedSchtasksFlags[name] {
			return false
		}
		if _, dup := out[name]; dup {
			return false
		}
		out[name] = value
		return true
	}
	for i := 1; i < len(cmd.Argv); i++ {
		t := cmd.Argv[i]
		if len(t) < 2 || t[0] != '/' {
			return nil, false // stray token: not a flag, and not a value we consumed
		}
		body := t[1:]
		if j := strings.IndexByte(body, ':'); j >= 0 {
			if !set(body[:j], body[j+1:]) {
				return nil, false
			}
			continue
		}
		if parts := strings.Split(body, "/"); len(parts) > 1 {
			for _, p := range parts {
				if etwValuedSchtasksFlags[strings.ToLower(p)] || !set(p, "") {
					return nil, false
				}
			}
			continue
		}
		if !etwValuedSchtasksFlags[strings.ToLower(body)] {
			if !set(body, "") {
				return nil, false
			}
			continue
		}
		if i+1 >= len(cmd.Argv) || strings.HasPrefix(cmd.Argv[i+1], "/") {
			return nil, false
		}
		if !set(body, cmd.Argv[i+1]) {
			return nil, false
		}
		i++ // the value is consumed, never re-examined as a flag
	}
	return out, true
}

// --- R-155 ETW carve-out: the /TR action -------------------------------

// etwActionToken is one token of a schtasks /TR action plus the single
// fact the program decision depends on: whether the token came out of a
// BALANCED QUOTE PAIR (`'…'`, `"…"`, `\"…\"`) rather than out of
// whitespace splitting.
type etwActionToken struct {
	text   string
	quoted bool
}

// etwActionTokens splits a schtasks /TR action into tokens, or reports
// ok=false for anything it does not positively recognize (an unclosed
// quote, or a closing quote not followed by whitespace).
//
// It is the whole reason this carve-out can make a claim about the
// PROGRAM at all. The quotings it honors are every one the emitter has
// shipped, plus what each dialect's lexer leaves of them:
//
//	'<tok>'        the current emitter form (parses in cmd AND PS)
//	"<tok>"        the earlier \"…\" form after POSIX lexing
//	\"<tok>\"      the same form delivered verbatim (argv boundary)
//	<tok>          unquoted — a whitespace-delimited run
//
// An unquoted token therefore CANNOT contain whitespace: that is a
// structural property of this function, and it is what closes the
// C1-bis bypass class (see etwActionProgram).
func etwActionTokens(action string) ([]etwActionToken, bool) {
	s := etwUnwrapWholeValue(strings.TrimSpace(action))
	var out []etwActionToken
	for i := 0; i < len(s); {
		if strings.IndexByte(etwSpace, s[i]) >= 0 {
			i++
			continue
		}
		var tok etwActionToken
		switch {
		case strings.HasPrefix(s[i:], `\"`):
			j := strings.Index(s[i+2:], `\"`)
			if j < 0 {
				return nil, false
			}
			tok = etwActionToken{text: s[i+2 : i+2+j], quoted: true}
			i += 2 + j + 2
		case s[i] == '\'' || s[i] == '"':
			j := strings.IndexByte(s[i+1:], s[i])
			if j < 0 {
				return nil, false
			}
			tok = etwActionToken{text: s[i+1 : i+1+j], quoted: true}
			i += 1 + j + 1
		default:
			j := strings.IndexAny(s[i:], etwSpace)
			if j < 0 {
				j = len(s) - i
			}
			tok = etwActionToken{text: s[i : i+j]}
			i += j
		}
		// A closing quote must END the token. `'a'b` is not something
		// we understand, and guessing at it is how a parser starts
		// admitting shapes nobody enumerated.
		if i < len(s) && strings.IndexByte(etwSpace, s[i]) < 0 {
			return nil, false
		}
		out = append(out, tok)
	}
	return out, true
}

// etwUnwrapWholeValue removes ONE layer of quoting that wraps an entire
// /TR value, as an argv-delivering boundary can hand us. It only fires
// when the quote character appears nowhere else, so the emitter's own
// `'<prog>' … --token-file '<path>'` (which also starts and ends with a
// single quote) is left alone — stripping that layer would erase the
// program delimiter.
func etwUnwrapWholeValue(s string) string {
	if len(s) < 2 {
		return s
	}
	q := s[0]
	if (q != '"' && q != '\'') || s[len(s)-1] != q {
		return s
	}
	if strings.IndexByte(s[1:len(s)-1], q) >= 0 {
		return s
	}
	return strings.TrimSpace(s[1 : len(s)-1])
}

// etwActionProgram returns the program Task Scheduler would actually
// launch for a tokenized action.
//
// THE ONE INVARIANT — a resolved program NEVER contains whitespace
// unless it came out of a balanced quote pair that wraps the whole
// token. Two independent reviews broke this carve-out by violating it,
// the second time (C1-bis) like this: the `\<prog>\` branch searched
// for "the first backslash that ends a word" and scanned ACROSS SPACES
// to find it, so
//
//	/TR "\Windows\System32\cmd.exe /c C:\Users\Public\payload.exe C:\x\observer\ process-bridge"
//
// resolved to a "program" of `Windows\System32\cmd.exe /c
// C:\Users\Public\payload.exe C:\x\observer` — arguments and all —
// whose LAST path segment is `observer`, so the identity check passed.
// On Windows a leading `\` is a drive-relative path, so that action
// really launches cmd.exe with an attacker's payload as its arguments,
// elevated, at every logon, under observer's own task name.
//
// The `\<prog>\` shape is real (it is what cmd/PowerShell lexing leaves
// of the emitter's abandoned `\"<prog>\"` form: the `"` is consumed and
// the `\` stays glued on), so it is still honored — but ONLY as an
// unwrap of a single whitespace-free token whose LAST BYTE is the
// closing backslash. There is no scanning. A `\`-delimited program is
// the one "quote" whose delimiter is also the path separator, so a
// SPACED path in that form is genuinely ambiguous and is refused; it is
// also unreachable, because the `\"…\"` spaced form does not survive
// cmd/PowerShell lexing as a single /TR value in the first place (see
// TestR155_ETWCarveOut_EscapedSpacedPathIsDialectSplit).
//
// A UNC path (`\\host\share\…`) is left alone: the leading pair is not
// a lexed quote, and stripping it would make `\\evil\observer\` — a
// DIRECTORY, not a program — resolve to base `observer`.
//
// The explicit whitespace check at the end is belt-and-braces: it is
// unreachable while etwActionTokens keeps unquoted tokens
// whitespace-free, and it is deliberately kept so that a future change
// to the tokenizer fails closed instead of silently reopening C1-bis.
func etwActionProgram(toks []etwActionToken) (string, bool) {
	if len(toks) == 0 {
		return "", false
	}
	p := toks[0]
	text := p.text
	if !p.quoted && len(text) > 2 && text[0] == '\\' && text[1] != '\\' && text[len(text)-1] == '\\' {
		text = text[1 : len(text)-1]
	}
	if text == "" {
		return "", false
	}
	if !p.quoted && strings.ContainsAny(text, etwSpace) {
		return "", false
	}
	if !etwSpacedProgramUnambiguous(text) {
		return "", false
	}
	return text, true
}

// etwExecExtensions are the suffixes that make a path plausibly
// launchable. They are used ONLY to detect an ambiguous spaced program
// (etwSpacedProgramUnambiguous); the identity check is stricter still
// and accepts `.exe` or nothing (etwProgramIsObserver).
var etwExecExtensions = [...]string{".exe", ".com", ".bat", ".cmd", ".ps1", ".scr", ".vbs", ".js", ".jse", ".wsf", ".msi", ".pif"}

// etwSpacedProgramUnambiguous refuses a QUOTED program whose
// space-boundary prefix could itself name an executable — e.g.
// `'C:\evil\payload.exe C:\x\observer'`, which passes the identity
// check on its last segment.
//
// The concern is the CreateProcess / Task Scheduler unquoted-path
// search: a program string containing spaces whose quoting is lost
// resolves to a PREFIX of itself (`C:\evil\payload.exe`), with the rest
// becoming arguments. That is the same class of confusion as C1-bis,
// arriving through a balanced quote pair instead of a backslash.
//
// It does NOT reject spaced programs as such: the emitter legitimately
// emits `'C:\Program Files\SuperBased\observer.exe'`, whose only
// space-boundary prefix (`C:\Program`) carries no executable
// extension.
//
// RESIDUAL, stated rather than papered over: a spaced program whose
// prefix is EXTENSIONLESS (`'C:\evil\payload C:\x\observer'`) is not
// caught, because rejecting it would require rejecting `C:\Program`
// too. It is not reachable as an execution: a quoted program in a
// stored Exec action is taken literally, so it must be a file with
// that exact spaced name — and an attacker who can create that file
// can create `observer.exe`, which is the residual this carve-out
// already accepts. If the quoting is instead lost, the action arrives
// here as the UNQUOTED spaced form, which is refused outright.
func etwSpacedProgramUnambiguous(prog string) bool {
	for i := 0; i < len(prog); i++ {
		if strings.IndexByte(etwSpace, prog[i]) < 0 {
			continue
		}
		low := strings.ToLower(prog[:i])
		for _, ext := range etwExecExtensions {
			if strings.HasSuffix(low, ext) {
				return false
			}
		}
	}
	return true
}

// etwProgramIsObserver reports whether a resolved program path names
// observer's own binary: file name `observer`, with extension `.exe` or
// none at all.
//
// THE EXTENSION IS PART OF THE CHECK. canonicalBase — which this
// deliberately does NOT use — also strips `.com`, `.bat` and `.cmd`, so
// `C:\Users\Public\observer.bat process-bridge` satisfied a name-based
// identity claim. A `.bat` is a plain text file of arbitrary shell: one
// Write call, no PE to build, no compiler. Accepting only `.exe` (or no
// extension, which is how the binary is named on the WSL side) keeps
// the residual risk at the level the doc comment on
// safeObserverETWTaskRegistration actually claims.
//
// It takes NO dialect. The predecessor hardcoded
// canonicalBase(…, DialectCmd) inside a dialect-agnostic predicate,
// which was harmless (no PowerShell alias is named `observer`) but was
// a source-identity assumption in a place that must not have one. File
// names are compared case-insensitively because that is a property of
// the Windows filesystem this action runs on, not of the shell that
// delivered the string.
func etwProgramIsObserver(prog string) bool {
	base := prog
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	base = strings.ToLower(base)
	base = strings.TrimSuffix(base, ".exe")
	if strings.ContainsRune(base, '.') {
		return false // any other extension: .bat/.cmd/.com/.ps1/…
	}
	return base == observerETWProgramBase
}

// etwCapturerBoolFlags / etwCapturerValueFlags are the CLOSED set of
// arguments `observer process-bridge` may carry inside an exempted
// registration — exactly the ones the emitter renders. Names are
// matched case-sensitively because cobra matches them that way: a
// spelling cobra would reject cannot be a command we exempt.
var (
	etwCapturerBoolFlags  = map[string]bool{"--etw": true}
	etwCapturerValueFlags = map[string]bool{"--connect": true, "--token-file": true}
)

// etwCapturerArgsAllowed reports whether every argument AFTER
// `process-bridge` is one observer itself emits.
//
// Closing this was M5: the exemption is for a PERSISTENT, ELEVATED,
// at-logon task, and `observer process-bridge` takes `--connect
// <host:port>` (any address) and `--token-file <path>` (any path),
// with the handshake writing that file's contents to that remote. An
// unconstrained argument list therefore authorised installing a task
// that streams the host's process table to an arbitrary endpoint and
// ships an arbitrary readable file as its "token". An unknown flag now
// denies, and `--connect` must name a loopback address — which the
// emitted command always does, because the capturer's whole job is to
// dial the daemon on this machine.
//
// Both `--flag value` and `--flag=value` are accepted (cobra accepts
// both). A duplicate flag denies, for the same reason a duplicate
// schtasks flag does: we do not want the verdict to depend on whether
// the consumer is first-wins or last-wins.
func etwCapturerArgsAllowed(toks []etwActionToken) bool {
	seen := map[string]bool{}
	for i := 0; i < len(toks); i++ {
		name, value, hasValue := toks[i].text, "", false
		if j := strings.IndexByte(name, '='); j >= 0 {
			name, value, hasValue = name[:j], name[j+1:], true
		}
		switch {
		case etwCapturerBoolFlags[name]:
			if hasValue {
				return false
			}
		case etwCapturerValueFlags[name]:
			if !hasValue {
				if i+1 >= len(toks) {
					return false
				}
				i++
				value = toks[i].text
			}
			if value == "" || strings.HasPrefix(value, "-") {
				return false
			}
			if name == "--connect" && !etwLoopbackDialTarget(value) {
				return false
			}
		default:
			return false
		}
		if seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

// etwLoopbackDialTarget reports whether v is an address on THIS
// machine: `localhost`, 127.0.0.0/8, or ::1, with or without a port.
//
// processBridgeConnectAddr composes exactly such a value (it rewrites a
// wildcard bind to 127.0.0.1 precisely because WSL2 localhostForwarding
// is what makes Windows→127.0.0.1 reach the guest's listener), so the
// emitted command always satisfies this. The ONE emitter shape it does
// not is a `listen_addr` too malformed for net.SplitHostPort, which the
// emitter echoes back verbatim — a command that could not work anyway.
func etwLoopbackDialTarget(v string) bool {
	host := v
	switch {
	case strings.HasPrefix(v, "["):
		j := strings.IndexByte(v, ']')
		if j < 0 {
			return false
		}
		host = v[1:j]
		if rest := v[j+1:]; rest != "" && !etwPortSuffix(rest) {
			return false
		}
	default:
		// Exactly one colon is host:port; two or more is a bare IPv6
		// literal, which carries its own colons and no port.
		if j := strings.IndexByte(v, ':'); j >= 0 && strings.LastIndexByte(v, ':') == j {
			if !etwPortSuffix(v[j:]) {
				return false
			}
			host = v[:j]
		}
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// etwPortSuffix reports whether s is ":" followed by at least one digit
// and nothing else.
func etwPortSuffix(s string) bool {
	if len(s) < 2 || s[0] != ':' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// etwActionRunsObserverCapturer reports whether a schtasks /TR action
// is EXACTLY the shape observer's own capturer registration emits:
//
//	<prog> process-bridge [--etw] [--connect <loopback>] [--token-file <path>]
//
// where <prog> is a program token (quoted, or whitespace-free) whose
// file name is `observer` with extension `.exe` or none.
//
// The question it asks is deliberately NOT "does an observer capturer
// appear somewhere in this attacker-controlled string?" — that question
// has now been answered wrongly twice, once by adjacency scanning and
// once by a permissive program parser. It asks "is this the command
// observer itself prints?", and fails closed on everything else. The
// cost of a false deny is nil: the operator can always run the command
// themselves.
func etwActionRunsObserverCapturer(action string) bool {
	toks, ok := etwActionTokens(action)
	if !ok || len(toks) < 2 {
		return false
	}
	prog, ok := etwActionProgram(toks)
	if !ok || !etwProgramIsObserver(prog) {
		return false
	}
	if toks[1].text != observerETWSubcommand {
		return false
	}
	return etwCapturerArgsAllowed(toks[2:])
}

// safeObserverETWTaskRegistration exempts ONE command from R-155: the
// registration of observer's OWN elevated Windows-ETW capturer task
// (`observer init` documents it, and an agent helping the operator run
// it would otherwise hit a critical hard deny with no scoped escape —
// the only alternative being to disable R-155 entirely, which would
// also stop flagging genuine crontab / Run-key / systemd persistence).
//
// WHAT IT ENFORCES, exactly — all of it, or the command denies:
//
//	the base is `schtasks`; and
//	every argv token is an allow-listed flag (/Create /TN /TR /SC /RL
//	  /F /RU) or the value of one, no duplicates, no value that is
//	  itself flag-shaped (etwParseSchtasksArgv); and
//	/Create is present; and
//	/TN equals "SuperBasedObserverETW" (case-insensitively, as
//	  schtasks compares task names); and
//	/TR parses (etwActionTokens) into: a program token that is either
//	  quoted or whitespace-free, none of whose space-boundary prefixes
//	  carries an executable extension, and whose file name is
//	  `observer` with extension `.exe` or none; then the literal
//	  `process-bridge` (case-sensitively, as cobra matches it); then
//	  only observer's own capturer flags (--etw, --connect <loopback>,
//	  --token-file <path>, in either the space or `=` spelling), each
//	  at most once, with no positional and nothing unrecognized.
//
// The argv allow-list is what makes /TN and /TR mean anything: those
// two describe the task, and say nothing about WHERE it is created or
// WHOSE definition it uses. Without the allow-list, `/S <host> /U
// <user> /P <pass>` extended the exemption to creating the task on
// another machine, and `/XML <file>` to taking the task definition —
// program included — from a file.
//
// ACCEPTED RESIDUAL RISKS, stated plainly because the previous two
// versions of this comment claimed more than the code enforced:
//
//   - Identity is POSITIONAL, NOT CRYPTOGRAPHIC. An attacker who can
//     write a file named `observer.exe` (or an extensionless `observer`)
//     anywhere on disk, and can get an agent to run a schtasks line, can
//     have that file installed as an elevated at-logon Scheduled Task —
//     it must merely be invoked with `process-bridge` first and none of
//     observer's other flags. No name-based check can do better, and
//     pinning an install path would fail closed on most machines (npm,
//     scoop and the VSIX all put the binary somewhere different) while
//     an attacker who can name a file `observer.exe` can also place it
//     on any path we would pin. `.bat`/`.cmd`/`.com`/`.ps1` are NOT
//     accepted, so this costs an attacker a real executable rather than
//     one Write of arbitrary shell text.
//   - The task is REAL persistence. Even when the program genuinely is
//     observer, the exempted command installs something that runs
//     elevated at every logon. That is the point of the feature; it is
//     exempted because observer's own `init` prints this exact line.
//   - `--token-file` may name ANY path. It is constrained to being a
//     single token and to not looking like a flag, nothing more —
//     observer's own token path is operator-configured, so there is no
//     literal to pin. Combined with the loopback `--connect`, whatever
//     that file contains only ever goes to a listener on this machine.
//   - ONE emitter shape is denied, and it is a lexer limitation rather
//     than a policy decision: when the operator's TOKEN PATH contains a
//     space, processBridgeTaskCommand escapes it as `\"…\"` and marks
//     the line cmd.exe-only. Our cmd/PowerShell lexer does not model
//     MSVCRT's `\"` unescaping, so it splits that /TR value and leaves
//     a stray argv token, which this predicate refuses (admitting an
//     unexplained stray token is exactly what the /XML and /S bypasses
//     needed). The same line IS allowed when the event carries the
//     POSIX dialect. Pinned in
//     TestR155_ETWCarveOut_EveryEmitterShape; the fix belongs in
//     shellparse.go's cmd lexer, not here.
//
// Everything else about R-155 is untouched: crontab, `crontab -e`,
// systemctl enable, Run-key writes and the persistence-PATH rows all
// still deny, and this predicate returns false for any base that is not
// schtasks.
func safeObserverETWTaskRegistration(_ *MatchContext, cmd *Command) bool {
	if cmd == nil || cmd.Base != "schtasks" {
		return false
	}
	// A LAUNCHER-wrapped registration is a different shape from the
	// one `observer init` prints, and the exemption is deliberately
	// NOT widened to it (etw-dashboard plan §E4: "prefer not to widen
	// it"). `Start-Process schtasks … -Verb RunAs` additionally
	// ELEVATES, and psSplitArguments' comma/whitespace splitting means
	// a wrapped /TR value no longer round-trips as one token — the
	// program-delimiting quoting this predicate depends on is gone.
	// Fail closed: the operator can always run the line themselves.
	if viaLauncher(cmd) {
		return false
	}
	flags, ok := etwParseSchtasksArgv(cmd)
	if !ok {
		return false
	}
	if _, ok := flags["create"]; !ok {
		return false
	}
	name, ok := flags.value("tn")
	if !ok || !strings.EqualFold(name, observerETWTaskName) {
		return false
	}
	action, ok := flags["tr"]
	return ok && etwActionRunsObserverCapturer(action)
}

// --- R-161 -------------------------------------------------------------

// projectPolicyPath reports whether p is a PROJECT guard policy file
// (<project>/.observer/guard-policy.toml) as opposed to the
// user-level ~/.observer one, which is R-160's territory.
func projectPolicyPath(p, home string) bool {
	if p == "" || !matchGlob("**/.observer/guard-policy.toml", p, true) {
		return false
	}
	if home != "" && isUnder(p, normPath(home)+"/.observer") {
		return false
	}
	return true
}

// matchProjectPolicyWriteFA implements the R-161 file-access row.
func matchProjectPolicyWriteFA(ctx *MatchContext) (bool, string) {
	if !isWriteEvent(ctx.Event) || !projectPolicyPath(ctx.Path, ctx.Cfg.Home) {
		return false, ""
	}
	return true, "project guard policy " + ctx.Event.Target
}

// matchProjectPolicyWriteShell implements the R-161 shell row.
func matchProjectPolicyWriteShell(ctx *MatchContext, cmd *Command) (bool, string) {
	for _, t := range unitPathTokens(cmd) {
		rp := resolveOrLiteral(ctx, t)
		if projectPolicyPath(rp, ctx.Cfg.Home) && classifyWrite(cmd, t) {
			return true, "project guard policy " + t
		}
	}
	return false, ""
}
