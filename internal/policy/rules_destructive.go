package policy

import (
	"regexp"
	"strings"
)

// Destructive-action rules R-101…R-142 (spec §5.1) as ordered table
// rows, plus the shared command-analysis helpers they and the
// boundary rules build on. Every row's hit / safe-pattern / near-miss
// behavior is pinned in rules_destructive_test.go.

// destructiveRules returns the §5.1 table. Severity and the
// observe→enforce decision pair transcribe the catalog exactly.
func destructiveRules() []Rule {
	shell := []EventKind{KindShellExec}
	return []Rule{
		{
			ID: "R-101", Category: CategoryDestructive, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchDeleteCatastrophic,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			SafePat: []SafeFn{safeDeleteAllowlisted},
			Doc:     "recursive delete targeting a filesystem root, the home directory, a root-depth wildcard, or a path outside the project",
			Advice:  "Delete inside the project root or a temp directory, or ask the operator to allow R-101 for this target.",
		},
		{
			// T-317 follow-up: the same classification for a recursive
			// delete CALL inside interpreter program text
			// (`shutil.rmtree('/')`, `fs.rmSync(p, {recursive: true})`,
			// `[IO.Directory]::Delete(p, $true)`); see inlinedelete.go.
			// allow_paths is applied inside the matcher, to the
			// outside-the-project arm only, as the shell row's safe
			// pattern does.
			ID: "R-101", Category: CategoryDestructive, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchInlineDeleteCatastrophic,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "interpreter one-liner or inline script recursively deleting a filesystem root, the home directory, a root-depth wildcard, or a path outside the project",
			Advice: "Delete inside the project root or a temp directory, or ask the operator to allow R-101 for this target.",
		},
		{
			// T-525, operator ruling D-338: the ASK row of R-101. A
			// recursive delete whose target is the bare pipeline variable
			// (`$_`, `$PSItem`) of the PowerShell script block it sits in
			// (`Get-ChildItem build | % { Remove-Item $_ -Recurse -Force }`)
			// deletes whatever the pipeline hands the block, which the
			// guard cannot see; the same bare variable outside a block
			// stays the DENY row's unexpanded-variable arm (psblock.go).
			ID: "R-101", Category: CategoryDestructive, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchDeletePipelineItem,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "recursive delete of the pipeline item ($_) inside a PowerShell script block, whose target the guard cannot check",
			Advice: "Confirm what the pipeline feeds the block, or delete explicit paths inside the project.",
		},
		{
			ID: "R-102", Category: CategoryDestructive, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchDeleteVCS,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			SafePat: []SafeFn{safeUnitPathsAllowlisted},
			Doc:     "recursive delete inside the project targeting the VCS directory or the project root itself",
			Advice:  "Target a specific subdirectory; .git removal destroys history irrecoverably.",
		},
		{
			// Pass-2 M2-01 calibration (orchestrator decision 2026-10-05):
			// the "might be catastrophic, cannot tell" tier of a recursive
			// delete. A row of R-102 (the ask tier, which no starter org
			// bundle raises to deny) rather than of R-101, so an org
			// override of R-101 to deny does not turn every unresolved
			// `cd $X && rm -rf build` back into a hard block.
			ID: "R-102", Category: CategoryDestructive, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchDeleteUnresolved,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "recursive delete after a directory change in the same command that the guard cannot resolve, or that is outside the project only if an earlier directory change fails",
			Advice: "Use an explicit path, or chain directory changes with && so a failed cd stops the line; confirm if the target is intended.",
		},
		{
			ID: "R-103", Category: CategoryDestructive, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchMassDelete,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			SafePat: []SafeFn{safeUnitPathsAllowlisted},
			Doc:     "mass-deletion chain (find -delete / xargs rm)",
			Advice:  "Prefer an explicit file list, or scope the find expression and re-run.",
		},
		{
			ID: "R-104", Category: CategoryDestructive, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchGitDiscard,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			SafePat: []SafeFn{safeGitDryRun},
			Doc:     "git command that discards uncommitted work (reset --hard / checkout -- / clean -f)",
			Advice:  "Stash first (git stash push -u), or run git clean -n to preview.",
		},
		{
			ID: "R-110", Category: CategoryDestructive, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchForcePush,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			SafePat: []SafeFn{safeForceWithLease},
			Doc:     "force push to a protected branch",
			Advice:  "Use --force-with-lease, or ask the operator to allow R-110 for this project.",
		},
		{
			ID: "R-111", Category: CategoryDestructive, Severity: SeverityWarn,
			AppliesTo: shell, MatchCmd: matchProtectedDeletion,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "deletion of a protected branch or tag",
			Advice: "Confirm the ref is disposable; protected patterns are Protected branches (Observer dashboard Settings > Guard, Boundary; [guard.boundary]).",
		},
		{
			ID: "R-120", Category: CategoryDestructive, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchDangerousSQL,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "destructive SQL through a database CLI (DROP/TRUNCATE/DELETE without WHERE)",
			Advice: "Add a WHERE clause or run against a scratch database; take a backup first.",
		},
		{
			ID: "R-130", Category: CategoryDestructive, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchCloudDestroy,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "cloud-infrastructure or container-volume destruction command",
			Advice: "Run a plan/dry-run variant first and have a human review the target scope.",
		},
		{
			ID: "R-140", Category: CategoryDestructive, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchPackagePublish,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "package registry publish/yank",
			Advice: "Publishing is public and hard to retract; confirm version and registry.",
		},
		{
			ID: "R-141", Category: CategoryDestructive, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchBulkPermChange,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "bulk permission/ownership change (chmod -R 777 / chown -R outside project)",
			Advice: "Scope the change to specific files and use least-privilege modes.",
		},
		{
			ID: "R-142", Category: CategoryDestructive, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchDiskDevice,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "disk/device-level operation (mkfs / dd to a device / diskpart / format)",
			Advice: "Device operations are unrecoverable; this needs an operator, not an agent.",
		},
	}
}

// --- shared helpers -------------------------------------------------

// resolveOrLiteral resolves a path token like resolvePath, falling
// back to the home-expanded literal form when no cwd/project anchor
// exists (so "~/x" and "/abs" still analyze in anchor-less events).
func resolveOrLiteral(ctx *MatchContext, t string) string {
	ev := ctx.Event
	if rp := resolvePath(t, ctx.Cfg.Home, ev.Cwd, ev.ProjectRoot); rp != "" {
		return rp
	}
	return normPath(expandHome(t, ctx.Cfg.Home))
}

// hasWrapper reports whether the named wrapper was stripped from the
// unit.
func hasWrapper(cmd *Command, name string) bool {
	for _, w := range cmd.Wrappers {
		if w == name {
			return true
		}
	}
	return false
}

// unitPathTokens returns the unit's path-candidate tokens: pathish
// positionals plus all redirect targets (redirect targets are
// definitionally paths even when bare words).
func unitPathTokens(cmd *Command) []string {
	var out []string
	for _, p := range cmd.Positionals() {
		if looksPathish(p) {
			out = append(out, p)
		}
	}
	out = append(out, cmd.RedirectTargets...)
	return out
}

// positionalsSkipping is Command.Positionals with the given set of
// value-taking flags in place of the per-base valueFlags row, for the rules
// that own their CLI's flag knowledge (the database CLI table, the R-130
// sub-table): a listed flag's separate value is not an operand, an
// "=VALUE" form carries its own, and "--" ends option scanning.
func positionalsSkipping(cmd *Command, valued map[string]bool) []string {
	_, pos := walkOptions(cmd, optSpec{valued: valued})
	return pos
}

// excerpt bounds a detail string for verdict reasons (Don'ts: bounded
// excerpts only, never full content).
func excerpt(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

// --- safe patterns ---------------------------------------------------

// matchAllowPaths reports whether a resolved path falls under
// [guard.boundary].allow_paths, matching both the absolute and the
// "~/"-anchored form (the config's default patterns are "~/"-anchored
// while resolved paths are absolute).
func matchAllowPaths(ctx *MatchContext, p string) bool {
	if p == "" {
		return false
	}
	if matchAnyGlob(ctx.Cfg.AllowPaths, p, true) {
		return true
	}
	if rel, ok := homeRelative(p, ctx.Cfg.Home); ok {
		return matchAnyGlob(ctx.Cfg.AllowPaths, rel, true)
	}
	return false
}

// safeUnitPathsAllowlisted exempts a unit whose path candidates ALL
// resolve under [guard.boundary].allow_paths (e.g. `rm -rf
// /tmp/build`). A unit with no path candidates is NOT safe — safety
// must be demonstrated, not absent. Each candidate must be allowlisted
// from EVERY directory the unit can run in (cwdtrack.go), and a unit that
// can run in an unknown directory, or after an unmodelled evaluation, is
// never safe: `cd /home/u/proj && rm -rf .git` with the event's cwd under
// /tmp must not be judged as /tmp/.../.git.
func safeUnitPathsAllowlisted(ctx *MatchContext, cmd *Command) bool {
	if cmd == nil {
		return false
	}
	cand := unitPathTokens(cmd)
	if len(cand) == 0 {
		return false
	}
	for _, a := range unitAnchors(ctx, cmd) {
		if a.unknown || a.opaque {
			return false
		}
		for _, t := range cand {
			p := resolveAt(ctx, t, a)
			if sub, unknown, through := throughSameCmdLinks(p, a.links); through {
				if unknown {
					return false
				}
				p = sub
			}
			if !matchAllowPaths(ctx, p) {
				return false
			}
		}
	}
	return true
}

// safeGitDryRun exempts git invocations carrying a dry-run flag
// (`git clean -n` previews instead of deleting).
func safeGitDryRun(_ *MatchContext, cmd *Command) bool {
	return cmd != nil && cmd.Base == "git" &&
		(cmd.HasShortFlag('n') || cmd.HasLongFlag("--dry-run"))
}

// safeForceWithLease exempts the safe force-push variant (the
// catalog's canonical safe pattern for R-110).
func safeForceWithLease(_ *MatchContext, cmd *Command) bool {
	return cmd != nil && cmd.HasLongFlag("--force-with-lease", "--force-if-includes")
}

// --- delete-shape analysis (R-101/R-102) ------------------------------

// deleteShape recognizes filesystem-delete commands across dialects
// and reports whether the invocation is recursive. ok is false for
// non-delete bases.
func deleteShape(cmd *Command) (recursive, ok bool) {
	switch cmd.Base {
	case "rm":
		return cmd.HasShortFlag('r', 'R') || cmd.HasLongFlag("--recursive"), true
	case "remove-item":
		// PowerShell: -Recurse prefix-matched at ≥1 ("-r") — no
		// other Remove-Item parameter starts with r.
		return psHasParam(cmd, "recurse", 1), true
	case "rd", "rmdir":
		if cmd.Dialect == DialectCmd {
			return cmdHasFlag(cmd, "s"), true
		}
		return false, true // POSIX rmdir only removes empty dirs
	case "del", "erase":
		if cmd.Dialect == DialectCmd {
			return cmdHasFlag(cmd, "s"), true
		}
		return false, false
	default:
		return false, false
	}
}

// matchDeleteCatastrophic implements R-101: recursive delete whose
// target is a filesystem root, the home directory, a root-depth
// wildcard, or resolves outside the project root. Each operand is
// judged from every directory the unit can run in (cwdtrack.go, pass-2
// review M2-01). When that is more than the event's own directory the
// rule's safe pattern stands aside and allow_paths clears the
// outside-the-project arms here, per anchor, as the inline-delete row
// always has.
func matchDeleteCatastrophic(ctx *MatchContext, cmd *Command) (bool, string) {
	return matchShellDeleteTier(ctx, cmd, tierDeny)
}

// matchDeleteUnresolved is R-102's second row (pass-2 M2-01 calibration,
// orchestrator decision 2026-10-05): a recursive delete the guard cannot
// show is catastrophic, because an earlier step of the same line moved to
// a directory it cannot resolve (a variable, a substitution, an inherited
// previous directory, `popd` past this line's stack, an eval, a state
// overflow), or because only the failure branch of a `;`-chained `cd` /
// `pushd` puts the target outside the project. Those ASK; a target that
// resolves to a root, the home directory or a root-depth wildcard in ANY
// reachable state stays R-101's DENY (the engine keeps the strictest
// verdict). It covers the shell delete operands and the inline-script
// delete calls alike.
func matchDeleteUnresolved(ctx *MatchContext, cmd *Command) (bool, string) {
	if hit, why := matchShellDeleteTier(ctx, cmd, tierAsk); hit {
		return true, why
	}
	return matchInlineDeleteTier(ctx, cmd, tierAsk)
}

// matchDeletePipelineItem is R-101's ASK row (T-525, D-338): a recursive
// delete whose target is the bare pipeline variable of the script block
// the unit sits in.
func matchDeletePipelineItem(ctx *MatchContext, cmd *Command) (bool, string) {
	return matchShellDeleteTier(ctx, cmd, tierItem)
}

// matchShellDeleteTier reports the first shell delete operand whose
// classification from some anchor is exactly tier.
func matchShellDeleteTier(ctx *MatchContext, cmd *Command, tier deleteTier) (bool, string) {
	recursive, ok := deleteShape(cmd)
	if !ok || !recursive {
		return false, ""
	}
	anchors := unitAnchors(ctx, cmd)
	allow := !plainOnly(anchors)
	for _, op := range cmd.positionalOperands() {
		for _, a := range anchors {
			if t, why := dangerousDeleteTarget(ctx, op, cmd.Dialect, a, allow); t == tier {
				return true, anchorReason(a, why)
			}
		}
	}
	return false, ""
}

// anchorReason tells the operator that a hit was judged from a directory
// an earlier step of the command moved to, not the event's own one.
func anchorReason(a deleteAnchor, why string) string {
	if a.plain || len(a.links) > 0 || a.unknown || a.opaque || strings.Contains(why, "this command") ||
		strings.Contains(why, "confirm before") {
		return why
	}
	return why + " (from the directory an earlier step of this command changed to)"
}

// deleteTier is how one delete target classifies from one anchor.
type deleteTier uint8

// deleteTier values.
const (
	tierNone deleteTier = iota
	// tierDeny: R-101. The target IS a root, the home directory, a
	// root-depth wildcard, or resolves outside the project, in a state the
	// guard resolved.
	tierDeny
	// tierAsk: R-102's unresolved-directory row. The guard cannot tell
	// whether the delete is catastrophic.
	tierAsk
	// tierItem: R-101's ASK row. The target is the bare pipeline variable
	// of the script block the unit sits in (T-525, D-338).
	tierItem
)

// confirmTail ends every tierAsk reason.
const confirmTail = "; confirm before a recursive delete"

// dangerousDeleteTarget classifies one delete target from one anchor.
// Resolution is lexical (pure package): home references expand,
// relatives anchor on the anchor's directory (the event's Cwd/ProjectRoot
// for the plain anchor), and an unresolvable relative is judged by its
// literal form only. allow lets [guard.boundary].allow_paths clear the
// outside-the-project arms (never the catastrophic ones).
//
// Order matters: a catastrophic path is DENY even on a failure branch or
// after an evaluated step; only what the guard cannot resolve is ASK.
func dangerousDeleteTarget(ctx *MatchContext, op operand, d Dialect, a deleteAnchor, allow bool) (deleteTier, string) {
	raw := op.text
	if strings.TrimSpace(raw) == "" || strings.HasPrefix(raw, "-") {
		return tierNone, ""
	}
	if op.item {
		return tierItem, "target " + raw + " is the pipeline item of the script block, which the guard cannot check" + confirmTail
	}
	if a.unknown && relativeDeleteTarget(ctx, op, d) {
		return tierAsk, "target " + raw + " is relative to " + quoteStep(a.unknownVia, "a directory change") +
			", which could not be resolved" + confirmTail
	}
	ev := ctx.Event
	rp, cand := deleteTargetPathsAt(ctx, raw, a)
	if why := catastrophicDeleteTarget(ctx, op, d, cand, a); why != "" {
		return tierDeny, why
	}
	if t, why := sameCmdLinkHazard(ctx, op, d, a, cand, allow); t != tierNone {
		return t, why
	}
	if a.opaque {
		return tierAsk, "target " + raw + " follows " + quoteStep(a.opaqueVia, "a step") +
			", which the guard cannot follow" + confirmTail
	}
	if allow && matchAllowPaths(ctx, rp) {
		return tierNone, ""
	}
	if ev.AltDialect != "" && d != ev.AltDialect && isDriveRelative(expandHome(raw, ctx.Cfg.Home)) {
		// An unstated Windows shell is read twice (Event.AltDialect): the
		// posix reading eats the backslashes of `d:\repo\build` and leaves
		// the drive-relative `d:repobuild`, which normPath roots at the
		// drive and would call outside the project. The other reading
		// judges the real path, so this one does not (surface-gap FU-101).
		// An event read once keeps the drive-rooted best effort.
		return tierNone, ""
	}
	outside := ""
	root := deleteProjectRoot(ev)
	if root != "" && rp != "" && comparableFlavors(rp, root) && !isUnder(rp, root) {
		outside = "target " + raw + " resolves outside the project root"
	} else if real := resolveLinks(ctx, rp); real != "" && root != "" && comparableFlavors(real, root) {
		rootReal := resolveLinks(ctx, normPath(root))
		if rootReal == "" {
			rootReal = root
		}
		if !isUnder(real, rootReal) && !isUnder(real, root) {
			outside = "target " + raw + " resolves outside the project root through a symlink"
		}
	}
	if outside == "" && root == "" {
		outside = homeChildWithoutRoot(ctx, raw, rp, cand)
	}
	if outside == "" {
		return tierNone, ""
	}
	if a.failPath && !a.plain {
		return tierAsk, outside + " only if " + quoteStep(a.failVia, "an earlier directory change") +
			" fails and the line carries on" + confirmTail
	}
	return tierDeny, outside
}

// deleteProjectRoot is the root the destructive rules' outside-the-project
// arms judge against: R-101's recursive-delete arms (D-MU10), R-102's
// `.git` / project-root delete and R-141's `chown -R` arm (surface-gap
// FU-101). It is the event's own ProjectRoot, else the git checkout the
// hook found around its cwd (Event.RepoRoot). "" means no root is known,
// which those arms treat as unknown, never as outside.
func deleteProjectRoot(ev *Event) string {
	if ev.ProjectRoot != "" {
		return ev.ProjectRoot
	}
	return ev.RepoRoot
}

// homeChildWithoutRoot is R-101's arm for an event whose project root is
// unknown (D-MU10): with no root there is no outside-the-project check, so
// a recursive delete of a folder directly in the home directory
// (~/Desktop, $HOME/Documents, /Users/<u>/Downloads) is refused, the way
// the home directory itself always is. The target is judged as resolved
// and, through Config.ResolveLinks, where it really points, against the
// home as written and as resolved. A deeper path is left to the other
// rules: without a root nothing says it is outside a project.
func homeChildWithoutRoot(ctx *MatchContext, raw, rp, cand string) string {
	home := normPath(ctx.Cfg.Home)
	if home == "" {
		return ""
	}
	homes := []string{home}
	if hr := resolveLinks(ctx, home); hr != "" {
		homes = append(homes, hr)
	}
	paths := []string{rp, cand}
	if real := resolveLinks(ctx, cand); real != "" {
		paths = append(paths, real)
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		for _, h := range homes {
			if !comparableFlavors(p, h) || pathsEqual(p, h) {
				continue
			}
			if parent := parentDir(p); parent != "" && pathsEqual(parent, h) {
				return "target " + raw + " is a folder directly in the home directory, and the project root is unknown"
			}
		}
	}
	return ""
}

// quoteStep renders the step that left a directory unresolved, or the
// fallback when none was recorded. A step already rendered with its own
// quoting and note (cwdtrack.go) is used as is.
func quoteStep(step, fallback string) string {
	switch {
	case strings.TrimSpace(step) == "":
		return fallback
	case strings.HasPrefix(step, "`"):
		return step
	}
	return "`" + excerpt(step) + "`"
}

// resolveLinks applies the injected symlink resolver to a normalized path:
// "" when there is no resolver, no path, or the resolution changes
// nothing.
func resolveLinks(ctx *MatchContext, p string) string {
	if ctx.Cfg.ResolveLinks == nil || p == "" || !isAbsPath(p) {
		return ""
	}
	real := ctx.Cfg.ResolveLinks(p)
	if real == "" {
		return ""
	}
	real = normPath(real)
	if pathsEqual(real, p) {
		return ""
	}
	return real
}

// deleteTargetPathsAt resolves one delete target from an anchor: rp is
// the anchored resolution ("" when a relative cannot be anchored) and
// cand is rp, or the home-expanded literal when rp is empty. For the
// plain anchor (cwd = Event.Cwd, else Event.ProjectRoot) this is the
// same resolution the rules always used.
func deleteTargetPathsAt(ctx *MatchContext, raw string, a deleteAnchor) (rp, cand string) {
	home := ctx.Cfg.Home
	rp = resolvePath(raw, home, a.cwd, "")
	cand = rp
	if cand == "" {
		cand = normPath(expandHome(raw, home))
	}
	return rp, cand
}

// relativeDeleteTarget reports whether op names a path relative to the
// working directory, as written or with its unexpanded variables empty.
func relativeDeleteTarget(ctx *MatchContext, op operand, d Dialect) bool {
	rel := func(s string) bool {
		p := expandHome(s, ctx.Cfg.Home)
		return strings.TrimSpace(p) != "" && !isAbsPath(p) && !strings.HasPrefix(p, "~")
	}
	if rel(op.text) {
		return true
	}
	spans := shellExpansions(op.text, op.lit, d)
	return len(spans) > 0 && rel(withoutSpans(op.text, spans))
}

// sameCmdLinkHazard is the same-command link arm (pass-2 review M2-01):
// a target that goes through a link created earlier in the same line is
// judged at the link's target, which Config.ResolveLinks cannot see
// because the link does not exist yet. A catastrophic or outside-project
// link target is DENY; a link whose target could not be resolved is ASK.
func sameCmdLinkHazard(ctx *MatchContext, op operand, d Dialect, a deleteAnchor, cand string, allow bool) (deleteTier, string) {
	raw := op.text
	if len(a.links) == 0 {
		return tierNone, ""
	}
	type probe struct{ path, via string }
	probes := []probe{{cand, ""}}
	if spans := shellExpansions(raw, op.lit, d); len(spans) > 0 {
		if empty := withoutSpans(raw, spans); strings.TrimSpace(empty) != "" {
			_, ec := deleteTargetPathsAt(ctx, empty, a)
			probes = append(probes, probe{ec, " (with its unexpanded variable empty)"})
		}
	}
	home := ctx.Cfg.Home
	homeReal := resolveLinks(ctx, normPath(home))
	root := deleteProjectRoot(ctx.Event)
	var unresolved string
	for _, pr := range probes {
		sub, unknown, through := throughSameCmdLinks(pr.path, a.links)
		if !through {
			continue
		}
		via := pr.via + " through a link created earlier in this command"
		if unknown {
			if unresolved == "" {
				unresolved = "target " + raw + " goes through " + quoteStep(unknownLinkVia(pr.path, a.links), "a link created earlier in this command") +
					", whose target could not be resolved" + confirmTail
			}
			continue
		}
		if why := catastrophicPath(raw, sub, via, home, homeReal); why != "" {
			return tierDeny, why
		}
		if real := resolveLinks(ctx, sub); real != "" {
			if why := catastrophicPath(raw, real, via, home, homeReal); why != "" {
				return tierDeny, why
			}
		}
		if root != "" && comparableFlavors(sub, root) && !isUnder(sub, root) && !(allow && matchAllowPaths(ctx, sub)) {
			return tierDeny, "target " + raw + " resolves outside the project root" + via
		}
	}
	if unresolved != "" {
		return tierAsk, unresolved
	}
	return tierNone, ""
}

// catastrophicDeleteTarget returns R-101's reason when cand is a
// filesystem root, the home directory or a root-depth wildcard, and ""
// otherwise. These arms hold wherever the path sits: no allow_paths
// entry can make deleting the home directory safe.
//
// Two arms close bypasses the literal check could not see (Sol A2-04, as
// narrowed): a target carrying an unexpanded shell expansion is judged as
// if every expansion were EMPTY, the value an unset or mistyped variable
// gives, and is catastrophic when that lands on a root, the home directory
// or a root-depth wildcard (a bare `$VAR`, `$VAR/`, `$VAR/*`, `$VAR/.`,
// `$VAR/..`, `/$VAR`, `$HOME/$X`); `$VAR/<named subpath>` goes through the
// normal rules. And a target whose existing prefix is a symlink is also
// judged by where it resolves (Config.ResolveLinks), against the home
// directory as written and as resolved.
func catastrophicDeleteTarget(ctx *MatchContext, op operand, d Dialect, cand string, a deleteAnchor) string {
	raw := op.text
	home := ctx.Cfg.Home
	if spans := shellExpansions(raw, op.lit, d); len(spans) > 0 {
		empty := withoutSpans(raw, spans)
		if strings.TrimSpace(empty) == "" {
			return "target " + raw + " is only an unexpanded shell variable, so its real target cannot be checked"
		}
		_, ec := deleteTargetPathsAt(ctx, empty, a)
		if why := catastrophicPath(raw, ec, " (with its unexpanded variable empty)", home); why != "" {
			return why
		}
	}
	if why := catastrophicPath(raw, cand, "", home); why != "" {
		return why
	}
	if real := resolveLinks(ctx, cand); real != "" {
		homeReal := resolveLinks(ctx, normPath(home))
		return catastrophicPath(raw, real, " through a symlink", home, homeReal)
	}
	return ""
}

// catastrophicPath is the literal R-101 classification of one normalized
// path against the home spellings in homes ("" entries ignored); via is
// appended to the reason ("" for the literal path).
func catastrophicPath(raw, p, via string, homes ...string) string {
	switch {
	case isFilesystemRoot(p):
		return "target " + raw + via + " is a filesystem root"
	case p == "~" || matchesHome(p, homes):
		return "target " + raw + via + " is the home directory"
	case isRootDepthGlob(p, "") || rootDepthUnderHome(p, homes):
		return "target " + raw + via + " is a root-depth wildcard"
	default:
		return ""
	}
}

func matchesHome(p string, homes []string) bool {
	for _, h := range homes {
		if h != "" && pathsEqual(p, h) {
			return true
		}
	}
	return false
}

func rootDepthUnderHome(p string, homes []string) bool {
	for _, h := range homes {
		if h != "" && isRootDepthGlob(p, h) {
			return true
		}
	}
	return false
}

// safeDeleteAllowlisted is R-101's safe pattern. The allow_paths
// exemption clears only the outside-the-project arm: a unit that
// targets a filesystem root, the home directory or a root-depth
// wildcard is never safe, even when that path sits under an allowlisted
// location. A home directory under /tmp (CI runners, sandboxes,
// throwaway test homes) otherwise matched the default "/tmp/**" entry
// and turned `rm -rf ~` into an exempt temp-dir delete.
//
// A unit that can run anywhere but the event's own directory (an earlier
// `cd`, a same-command link, a chdir wrapper) is never exempt here: the
// matcher then judges every anchor and applies allow_paths per anchor.
func safeDeleteAllowlisted(ctx *MatchContext, cmd *Command) bool {
	if cmd == nil {
		return false
	}
	anchors := unitAnchors(ctx, cmd)
	if !plainOnly(anchors) {
		return false
	}
	for _, op := range cmd.positionalOperands() {
		raw := op.text
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(raw, "-") {
			continue
		}
		if _, cand := deleteTargetPathsAt(ctx, raw, anchors[0]); catastrophicDeleteTarget(ctx, op, cmd.Dialect, cand, anchors[0]) != "" {
			return false
		}
	}
	return safeUnitPathsAllowlisted(ctx, cmd)
}

// matchDeleteVCS implements R-102: recursive delete inside the
// project that targets the .git directory or the project root
// itself. (The spec's ">N entries" half needs filesystem counting —
// I/O this pure package cannot do; deferred with a doc note, see
// PROGRESS.)
func matchDeleteVCS(ctx *MatchContext, cmd *Command) (bool, string) {
	recursive, ok := deleteShape(cmd)
	if !ok || !recursive {
		return false, ""
	}
	pr := deleteProjectRoot(ctx.Event)
	if pr == "" {
		return false, ""
	}
	anchors := unitAnchors(ctx, cmd)
	for _, t := range cmd.Positionals() {
		for _, a := range anchors {
			if a.unknown || a.opaque {
				continue // R-101 owns a delete it cannot place
			}
			rp := resolveAt(ctx, t, a)
			if sub, unknown, through := throughSameCmdLinks(rp, a.links); through && !unknown {
				rp = sub
			}
			if rp == "" || !isUnder(rp, pr) {
				continue
			}
			if hasComponent(rp, ".git") {
				return true, "target " + t + " includes the .git directory"
			}
			if pathsEqual(rp, pr) {
				return true, "target " + t + " is the project root itself"
			}
		}
	}
	return false, ""
}

// matchMassDelete implements R-103: `find ... -delete`, `find -exec
// rm`, and xargs-fed rm chains.
func matchMassDelete(_ *MatchContext, cmd *Command) (bool, string) {
	if cmd.Base == "find" {
		if cmd.HasLongFlag("-delete") {
			return true, "find -delete mass deletion"
		}
		for i := 1; i < len(cmd.Argv)-1; i++ {
			a := cmd.Argv[i]
			if (a == "-exec" || a == "-execdir") && canonicalBase(cmd.Argv[i+1], cmd.Dialect) == "rm" {
				return true, "find -exec rm mass deletion"
			}
		}
		return false, ""
	}
	if cmd.Base == "rm" && hasWrapper(cmd, "xargs") {
		return true, "rm fed by xargs"
	}
	return false, ""
}

// --- git rules (R-104/R-110/R-111) ------------------------------------

// matchGitDiscard implements R-104: work-discarding git forms.
func matchGitDiscard(_ *MatchContext, cmd *Command) (bool, string) {
	if cmd.Base != "git" {
		return false, ""
	}
	switch cmd.Sub() {
	case "reset":
		if cmd.HasLongFlag("--hard") {
			return true, "git reset --hard discards uncommitted changes"
		}
	case "checkout":
		for _, a := range cmd.Args() {
			if a == "--" {
				return true, "git checkout -- discards working-tree changes"
			}
		}
	case "clean":
		if cmd.HasShortFlag('f') || cmd.HasLongFlag("--force") {
			return true, "git clean -f deletes untracked files"
		}
	}
	return false, ""
}

// refDst extracts the destination branch from a push refspec
// ("main", "+src:dst", "HEAD:main", "refs/heads/main").
func refDst(ref string) string {
	ref = strings.TrimPrefix(ref, "+")
	if i := strings.LastIndexByte(ref, ':'); i >= 0 {
		ref = ref[i+1:]
	}
	return strings.TrimPrefix(ref, "refs/heads/")
}

// protectedBranch reports whether name matches a configured protected
// pattern.
func protectedBranch(ctx *MatchContext, name string) bool {
	return name != "" && matchAnyGlob(ctx.Cfg.ProtectedBranches, name, false)
}

// matchForcePush implements R-110. With no refspec on the command
// line the current branch is unknown to a pure evaluator, so the rule
// hits conservatively (documented; the safe pattern and near-miss
// behavior are pinned by tests).
func matchForcePush(ctx *MatchContext, cmd *Command) (bool, string) {
	if cmd.Base != "git" || cmd.Sub() != "push" {
		return false, ""
	}
	if !cmd.HasShortFlag('f') && !cmd.HasLongFlag("--force") {
		return false, ""
	}
	pos := cmd.Positionals() // ["push", remote?, refspecs...]
	if len(pos) < 3 {
		return true, "force push with no refspec (target branch unknown, assumed protected)"
	}
	for _, ref := range pos[2:] {
		if b := refDst(ref); protectedBranch(ctx, b) {
			return true, "force push to protected branch " + b
		}
	}
	return false, ""
}

// matchProtectedDeletion implements R-111: branch -D / tag -d /
// push --delete (and ":ref" push refspecs) against protected
// patterns.
func matchProtectedDeletion(ctx *MatchContext, cmd *Command) (bool, string) {
	if cmd.Base != "git" {
		return false, ""
	}
	pos := cmd.Positionals()
	switch cmd.Sub() {
	case "branch":
		if cmd.HasShortFlag('D') || (cmd.HasLongFlag("--delete") && cmd.HasLongFlag("--force")) {
			for _, b := range pos[1:] {
				if protectedBranch(ctx, b) {
					return true, "deleting protected branch " + b
				}
			}
		}
	case "tag":
		if cmd.HasShortFlag('d') || cmd.HasLongFlag("--delete") {
			for _, t := range pos[1:] {
				if protectedBranch(ctx, t) {
					return true, "deleting protected tag " + t
				}
			}
		}
	case "push":
		for _, ref := range pos[1:] {
			deleting := cmd.HasLongFlag("--delete") || strings.HasPrefix(ref, ":")
			if !deleting {
				continue
			}
			if b := refDst(ref); protectedBranch(ctx, b) {
				return true, "push-deleting protected ref " + b
			}
		}
	}
	return false, ""
}

// --- SQL (R-120) -------------------------------------------------------

// R-120's matcher (matchDangerousSQL) lives in rules_database.go with the
// database CLI table it shares with R-121 to R-126.

// --- cloud / publish / perms / device (R-130/R-140/R-141/R-142) -------

// cloudDestroyChecks is the R-130 sub-table: one check per provider
// CLI shape (table-driven per Module rule 5; each entry pinned by its
// own test case).
var cloudDestroyChecks = []func(*Command) (bool, string){
	checkTerraformDestroy,
	checkAWSDestroy,
	checkGcloudDelete,
	checkKubectlDelete,
	checkHelmUninstall,
	checkPulumiDestroy,
	checkCDKDestroy,
	checkAzGroupDelete,
	checkDockerSystemPrune,
	checkDockerVolumeRemove,
	checkComposeDownVolumes,
}

// matchCloudDestroy implements R-130 by walking the provider
// sub-table.
func matchCloudDestroy(_ *MatchContext, cmd *Command) (bool, string) {
	for _, check := range cloudDestroyChecks {
		if hit, why := check(cmd); hit {
			return true, why
		}
	}
	return false, ""
}

// checkTerraformDestroy: `terraform destroy` (any) and `terraform
// apply -auto-approve` (unattended apply).
func checkTerraformDestroy(cmd *Command) (bool, string) {
	if cmd.Base != "terraform" && cmd.Base != "tofu" {
		return false, ""
	}
	switch cmd.Sub() {
	case "destroy":
		return true, "terraform destroy"
	case "apply":
		if cmd.HasLongFlag("-auto-approve", "--auto-approve") {
			return true, "terraform apply -auto-approve (unattended)"
		}
	}
	return false, ""
}

// checkAWSDestroy: `aws s3 rm --recursive` and `aws ec2
// terminate-instances`.
func checkAWSDestroy(cmd *Command) (bool, string) {
	if cmd.Base != "aws" {
		return false, ""
	}
	pos := cmd.Positionals()
	if len(pos) >= 2 && pos[0] == "s3" && pos[1] == "rm" && cmd.HasLongFlag("--recursive") {
		return true, "aws s3 rm --recursive"
	}
	if len(pos) >= 2 && pos[0] == "ec2" && pos[1] == "terminate-instances" {
		return true, "aws ec2 terminate-instances"
	}
	return false, ""
}

// checkGcloudDelete: any gcloud command with a delete verb.
func checkGcloudDelete(cmd *Command) (bool, string) {
	if cmd.Base != "gcloud" {
		return false, ""
	}
	for _, p := range cmd.Positionals() {
		if p == "delete" {
			return true, "gcloud ... delete"
		}
	}
	return false, ""
}

// checkKubectlDelete: kubectl delete with --all/--all-namespaces or a
// namespace-wide target.
func checkKubectlDelete(cmd *Command) (bool, string) {
	if cmd.Base != "kubectl" || cmd.Sub() != "delete" {
		return false, ""
	}
	if cmd.HasLongFlag("--all", "--all-namespaces") || cmd.HasShortFlag('A') {
		return true, "kubectl delete --all"
	}
	pos := cmd.Positionals()
	if len(pos) >= 2 && (pos[1] == "namespace" || pos[1] == "ns") {
		return true, "kubectl delete namespace"
	}
	return false, ""
}

// checkHelmUninstall: helm uninstall (and its legacy delete alias).
func checkHelmUninstall(cmd *Command) (bool, string) {
	if cmd.Base != "helm" {
		return false, ""
	}
	if s := cmd.Sub(); s == "uninstall" || s == "delete" {
		return true, "helm " + s
	}
	return false, ""
}

// Value-taking flags of the R-130 CLIs that have no valueFlags row, so
// their verbs read at the right operand position (positionalsSkipping).
var (
	pulumiValued = setOf("-s", "--stack", "-C", "--cwd", "--color", "-m", "--message", "--config-file",
		"-t", "--target", "-p", "--parallel", "--exclude", "--secrets-provider")
	cdkValued = setOf("-a", "--app", "--profile", "-c", "--context", "-r", "--role-arn", "-o", "--output",
		"--toolkit-stack-name", "--plugin", "--ca-bundle-path", "-p", "--package")
	azValued = setOf("-n", "--name", "-g", "--resource-group", "--subscription", "-o", "--output", "--query")
	// dockerValued covers the docker globals and the compose flags that come
	// before a compose verb.
	dockerValued = setOf("-H", "--host", "-c", "--context", "--config", "-l", "--log-level",
		"-f", "--file", "-p", "--project-name", "--project-directory", "--env-file", "--profile",
		"--ansi", "--progress", "--filter", "-t", "--timeout", "--rmi")
)

// checkPulumiDestroy: `pulumi destroy` and its `pulumi down` alias.
func checkPulumiDestroy(cmd *Command) (bool, string) {
	if cmd.Base != "pulumi" {
		return false, ""
	}
	if pos := positionalsSkipping(cmd, pulumiValued); len(pos) > 0 && (pos[0] == "destroy" || pos[0] == "down") {
		return true, "pulumi " + pos[0]
	}
	return false, ""
}

// cdkWords are the command words that run the AWS CDK CLI.
var cdkWords = setOf("cdk", "aws-cdk")

// checkCDKDestroy: `cdk destroy`, also through a package runner (`npx cdk
// destroy`, `npx aws-cdk destroy`).
func checkCDKDestroy(cmd *Command) (bool, string) {
	words := append([]string{cmd.Base}, positionalsSkipping(cmd, cdkValued)...)
	for i := 0; i+1 < len(words); i++ {
		if !cdkWords[canonicalBase(words[i], cmd.Dialect)] || (i > 0 && !isCommandRunner(cmd.Base)) {
			continue
		}
		if words[i+1] == "destroy" {
			return true, "cdk destroy"
		}
	}
	return false, ""
}

// checkAzGroupDelete: `az group delete` (a resource group and everything
// in it).
func checkAzGroupDelete(cmd *Command) (bool, string) {
	if cmd.Base != "az" {
		return false, ""
	}
	if pos := positionalsSkipping(cmd, azValued); len(pos) >= 2 && pos[0] == "group" && pos[1] == "delete" {
		return true, "az group delete"
	}
	return false, ""
}

// checkDockerSystemPrune: `docker system prune -a` (every unused image,
// not only dangling ones).
func checkDockerSystemPrune(cmd *Command) (bool, string) {
	if cmd.Base != "docker" {
		return false, ""
	}
	pos := positionalsSkipping(cmd, dockerValued)
	if len(pos) >= 2 && pos[0] == "system" && pos[1] == "prune" && (cmd.HasShortFlag('a') || cmd.HasLongFlag("--all")) {
		return true, "docker system prune --all"
	}
	return false, ""
}

// checkDockerVolumeRemove: `docker volume rm` / `remove` / `prune` (volume
// data is not recoverable).
func checkDockerVolumeRemove(cmd *Command) (bool, string) {
	if cmd.Base != "docker" {
		return false, ""
	}
	pos := positionalsSkipping(cmd, dockerValued)
	if len(pos) >= 2 && pos[0] == "volume" && (pos[1] == "rm" || pos[1] == "remove" || pos[1] == "prune") {
		return true, "docker volume " + pos[1]
	}
	return false, ""
}

// checkComposeDownVolumes: `docker compose down -v` and `docker-compose
// down --volumes` (the project's named volumes go with the containers).
func checkComposeDownVolumes(cmd *Command) (bool, string) {
	pos := positionalsSkipping(cmd, dockerValued)
	down := (cmd.Base == "docker" && len(pos) >= 2 && pos[0] == "compose" && pos[1] == "down") ||
		(cmd.Base == "docker-compose" && len(pos) >= 1 && pos[0] == "down")
	if down && (cmd.HasShortFlag('v') || cmd.HasLongFlag("--volumes")) {
		return true, "compose down --volumes"
	}
	return false, ""
}

// matchPackagePublish implements R-140: registry publish and yank
// operations across the package managers in the catalog.
func matchPackagePublish(_ *MatchContext, cmd *Command) (bool, string) {
	sub := cmd.Sub()
	switch cmd.Base {
	case "npm", "yarn", "pnpm":
		if sub == "publish" || sub == "unpublish" {
			return true, cmd.Base + " " + sub
		}
	case "twine":
		if sub == "upload" {
			return true, "twine upload (PyPI publish)"
		}
	case "cargo":
		if sub == "publish" || sub == "yank" {
			return true, "cargo " + sub
		}
	case "gem":
		if sub == "push" || sub == "yank" {
			return true, "gem " + sub
		}
	}
	return false, ""
}

// reMode777 recognizes the world-writable numeric modes.
var reMode777 = regexp.MustCompile(`^0?[0-7]?777$`)

// matchBulkPermChange implements R-141: chmod -R 777 anywhere, and
// chown -R with a target outside the project root.
func matchBulkPermChange(ctx *MatchContext, cmd *Command) (bool, string) {
	recursive := cmd.HasShortFlag('R') || cmd.HasLongFlag("--recursive")
	if !recursive {
		return false, ""
	}
	pos := cmd.Positionals()
	switch cmd.Base {
	case "chmod":
		for _, p := range pos {
			if reMode777.MatchString(p) || p == "a+rwx" || p == "a=rwx" {
				return true, "chmod -R " + p
			}
		}
	case "chown":
		if len(pos) < 2 {
			return false, ""
		}
		anchors := unitAnchors(ctx, cmd)
		root := deleteProjectRoot(ctx.Event)
		for _, t := range pos[1:] { // pos[0] is the owner spec
			for _, a := range anchors {
				if a.unknown || a.opaque {
					continue
				}
				rp := resolveAt(ctx, t, a)
				if rp == "" || root == "" {
					continue
				}
				if comparableFlavors(rp, root) && !isUnder(rp, root) {
					return true, "chown -R outside project: " + t
				}
			}
		}
	}
	return false, ""
}

// matchDiskDevice implements R-142: mkfs*, dd writing to a device,
// diskpart, cmd-dialect format, and the PowerShell volume cmdlets.
// A POSIX-dialect bare `format` is deliberately NOT matched (too
// collision-prone with project scripts); the cmd dialect and
// Format-Volume cover the real Windows shapes.
func matchDiskDevice(_ *MatchContext, cmd *Command) (bool, string) {
	switch {
	case strings.HasPrefix(cmd.Base, "mkfs"):
		return true, cmd.Base + " filesystem creation"
	case cmd.Base == "diskpart":
		return true, "diskpart disk partitioning"
	case cmd.Base == "format" && cmd.Dialect == DialectCmd:
		return true, "format volume"
	case cmd.Base == "format-volume" || cmd.Base == "clear-disk":
		return true, cmd.Base + " volume operation"
	case cmd.Base == "dd":
		for _, a := range cmd.Args() {
			la := strings.ToLower(a)
			if strings.HasPrefix(la, "of=/dev/") || strings.HasPrefix(la, `of=\\.\`) {
				return true, "dd writing to device " + a
			}
		}
	}
	return false, ""
}
