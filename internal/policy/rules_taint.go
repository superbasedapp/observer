package policy

import "strings"

// Taint / dataflow rules T-501…T-505 (spec §4.5, §5.6) — the
// differentiator: deterministic source→sink sequencing over the
// normalized event stream. Each rule consults the per-session
// TaintState snapshot the guard composition layer stamps onto the
// Event (this package never tracks cross-event state itself — §17.4
// one-owner: TaintState is owned by guard.Guard; rules read the
// snapshot only). A mark present in the snapshot is by definition
// still live — decay (turn-window expiry, compaction reset) happens
// at the owner before the snapshot is taken.
//
// Decision mapping from the §5.6 catalog single-decision shorthand:
// the named decision is the ENFORCE-mode column; observe mode flags
// (observe never blocks/asks — D2). T-503/T-505 are flag in both.

// Taint source classes (TaintMark.Source vocabulary, spec §4.5).
// Stable strings — they persist in guard_events.taint_origin prefixes
// and appear in user-rule matchers (taint_source).
const (
	// TaintSourceWebFetch marks web fetch/search tool results.
	TaintSourceWebFetch = "web_fetch"
	// TaintSourceMCPUnpinned marks MCP tool results from servers
	// without an approved pin (until G10 lands pinning, EVERY server
	// is unpinned — true to spec §4.5, refined by guard_pins later).
	TaintSourceMCPUnpinned = "mcp_unpinned"
	// TaintSourceExternalFile marks reads of files modified outside
	// the session (freshness classifier's change detection).
	TaintSourceExternalFile = "external_file"
	// TaintSourceAttachment marks paste-shaped user attachments
	// (proxy-side detection, G9).
	TaintSourceAttachment = "attachment"
	// TaintSourceSecretsRead marks that the session read a
	// secrets-bearing file (verdict-driven: R-152 read / R-153 hits).
	// NOT an untrusted-content source — it grades sensitivity, and
	// only T-504 consumes it.
	TaintSourceSecretsRead = "secrets_read"
)

// untrustedTaintSource reports whether the source class carries
// UNTRUSTED CONTENT (the T-501/502/503 precondition). secrets_read is
// deliberately excluded — reading a secret doesn't make the session's
// instructions untrusted, it makes its egress sensitive (T-504).
func untrustedTaintSource(source string) bool {
	switch source {
	case TaintSourceWebFetch, TaintSourceMCPUnpinned,
		TaintSourceExternalFile, TaintSourceAttachment:
		return true
	default:
		return false
	}
}

// firstUntrustedMark returns the first untrusted-content mark in the
// snapshot, if any — the detail string names its origin.
func firstUntrustedMark(t TaintState) (TaintMark, bool) {
	for _, m := range t.Marks {
		if untrustedTaintSource(m.Source) {
			return m, true
		}
	}
	return TaintMark{}, false
}

// taintRules assembles the T-5xx table rows in catalog order.
func taintRules() []Rule {
	return []Rule{
		{
			ID: "T-501", Category: CategoryTaint, Severity: SeverityHigh,
			AppliesTo: []EventKind{KindShellExec},
			Match:     matchTaintImperativeShell,
			Observe:   DecisionFlag, Enforce: DecisionAsk,
			Doc:    "shell command while the session carries untrusted content with instruction-like patterns",
			Advice: "Review the fetched/tool-result content for injected instructions before re-running; if intended, approve this rule for the session.",
		},
		{
			ID: "T-502", Category: CategoryTaint, Severity: SeverityHigh,
			AppliesTo: []EventKind{KindFileAccess, KindConfigChange},
			Match:     matchTaintOutsideWrite,
			// Same allowlist exemptions as R-150: temp dirs, toolchain
			// caches and the client's own config dir are routine even
			// in a tainted session.
			SafePat: []SafeFn{safePathAllowlisted, safeClientConfigPath},
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "out-of-project write while the session carries untrusted content",
			Advice: "Verify the write target was requested by you, not by fetched content; if this location is routine, add it to Allowed paths (Observer dashboard Settings > Guard, Boundary; [guard.boundary].allow_paths).",
		},
		{
			ID: "T-503", Category: CategoryTaint, Severity: SeverityWarn,
			AppliesTo: []EventKind{KindShellExec},
			MatchCmd:  matchTaintGitPush,
			Observe:   DecisionFlag, Enforce: DecisionFlag,
			Doc:    "git push while the session carries untrusted content",
			Advice: "Review the pushed commits for content originating from fetched/tool-result data.",
		},
		{
			ID: "T-504", Category: CategoryTaint, Severity: SeverityCritical,
			AppliesTo: []EventKind{KindShellExec},
			MatchCmd:  matchTaintSecretsToNetwork,
			Observe:   DecisionFlag, Enforce: DecisionDeny,
			Doc:    "network-touching command after the session read a secrets-bearing file",
			Advice: "If this egress is intended, approve T-504 for this session; otherwise check the command for credential exfiltration.",
		},
		{
			ID: "T-505", Category: CategoryTaint, Severity: SeverityWarn,
			AppliesTo: []EventKind{KindMCPCall},
			Match:     matchTaintCrossServerMCP,
			Observe:   DecisionFlag, Enforce: DecisionFlag,
			Doc:    "MCP call to a different server after consuming an unpinned server's result (cross-server toxic-flow shape)",
			Advice: "Pin and approve your MCP servers (Approve on the Observer dashboard Security > MCP, or `observer guard mcp approve`) so cross-server flows between trusted servers stay quiet.",
		},
	}
}

// matchTaintImperativeShell implements T-501: any live untrusted mark
// whose content carried imperative-instruction patterns (the
// Imperative bit is set by the proxy-side injection heuristics, §8.4;
// watcher-path marks never set it — content is not inspected
// post-hoc) makes the next shell execution suspect.
func matchTaintImperativeShell(ctx *MatchContext) (bool, string) {
	for _, m := range ctx.Event.Taint.Marks {
		if m.Imperative && untrustedTaintSource(m.Source) {
			return true, "untrusted content from " + m.Origin + " contained instruction-like patterns"
		}
	}
	return false, ""
}

// matchTaintOutsideWrite implements T-502: an out-of-project write
// (R-150's write-direction predicate, reused) while ANY untrusted
// mark is live.
func matchTaintOutsideWrite(ctx *MatchContext) (bool, string) {
	m, tainted := firstUntrustedMark(ctx.Event.Taint)
	if !tainted {
		return false, ""
	}
	hit, _ := matchOutsideProject(true)(ctx)
	if !hit {
		return false, ""
	}
	return true, "write to " + ctx.Event.Target + " while carrying untrusted content from " + m.Origin
}

// matchTaintGitPush implements T-503: any `git push` unit while an
// untrusted mark is live. Unlike R-110 this fires on EVERY push form
// (force or not) — the signal is provenance, not destructiveness.
func matchTaintGitPush(ctx *MatchContext, cmd *Command) (bool, string) {
	m, tainted := firstUntrustedMark(ctx.Event.Taint)
	if !tainted || cmd.Base != "git" {
		return false, ""
	}
	pos := cmd.Positionals()
	if len(pos) == 0 || pos[0] != "push" {
		return false, ""
	}
	return true, "git push while carrying untrusted content from " + m.Origin
}

// networkCommandBases is the network-touching command table T-504
// consults (canonical Base forms — PowerShell aliases iwr/irm/curl/
// wget already resolve to the invoke-* cmdlet names in psparse).
// Table-driven per Module rule 5; extend here, not in the matcher.
var networkCommandBases = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"ssh": true, "scp": true, "sftp": true, "rsync": true, "ftp": true,
	"telnet": true, "socat": true,
	"invoke-webrequest": true, "invoke-restmethod": true,
}

// matchTaintSecretsToNetwork implements T-504: a network-touching
// command unit while a secrets_read mark is live. The mark is set by
// the guard layer when an R-152 (read) / R-153 verdict fired earlier
// in the window — verdict-driven marking, so the secret-file
// vocabulary stays in one place (rules_boundary.go).
func matchTaintSecretsToNetwork(ctx *MatchContext, cmd *Command) (bool, string) {
	if !networkCommandBases[cmd.Base] {
		return false, ""
	}
	for _, m := range ctx.Event.Taint.Marks {
		if m.Source == TaintSourceSecretsRead {
			return true, cmd.Base + " after reading " + m.Origin
		}
	}
	return false, ""
}

// matchTaintCrossServerMCP implements T-505 (the Snyk "toxic flows"
// shape): the session consumed a result from unpinned server A and is
// now calling server B. Same-server follow-ups stay quiet.
func matchTaintCrossServerMCP(ctx *MatchContext) (bool, string) {
	cur := MCPServerFromTarget(ctx.Event.Target)
	if cur == "" {
		return false, ""
	}
	for _, m := range ctx.Event.Taint.Marks {
		if m.Source == TaintSourceMCPUnpinned && m.Origin != "" && m.Origin != cur {
			return true, "call to MCP server " + cur + " after consuming a result from unpinned server " + m.Origin
		}
	}
	return false, ""
}

// MCPServerFromTarget extracts the server name from a normalized MCP
// call target. Approximation, documented: adapters normalize MCP tool
// names in two common shapes — the Claude Code "mcp__server__tool"
// form and a "server/tool" form. A bare tool name (no separator)
// yields "" (unknown server → T-505 cannot evaluate, never a hit).
// Exported because the guard layer uses the same extraction when it
// records the mcp_unpinned mark's origin — both sides of the
// comparison must agree on the parse.
//
// NOT DELEGATED to internal/tooltax (the taxonomy plan's §1 single MCP
// identity owner) on purpose: TestPackageImports_Bounded pins
// internal/policy at ZERO observer imports (guard spec §17.1, "the
// strongest form of the invariant"), which a tooltax import would
// break. The bodies here stay a deliberate local copy; equivalence with
// the owner is pinned from the other side by
// internal/tooltax/mcp_test.go::TestPolicyParsersMatchTooltax, which
// also records the ONE tolerated divergence (tooltax drops the
// zero-corpus-row "server/tool" shape; this copy keeps it).
func MCPServerFromTarget(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if rest, ok := strings.CutPrefix(t, "mcp__"); ok {
		if i := strings.Index(rest, "__"); i > 0 {
			return rest[:i]
		}
		return rest
	}
	if i := strings.IndexAny(t, "/:"); i > 0 {
		return t[:i]
	}
	return ""
}

// MCPToolFromTarget extracts the bare TOOL name from a normalized MCP
// call target — the companion of MCPServerFromTarget, parsing the
// same two shapes ("mcp__server__tool", "server/tool"). A target with
// no tool half yields "". Exported for the same reason: the guard
// layer's §9.3 poisoning heuristics key tool-name collisions off the
// bare name, and both sides must agree on the parse.
//
// Not delegated to internal/tooltax for the same §17.1 reason as
// MCPServerFromTarget above.
func MCPToolFromTarget(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if rest, ok := strings.CutPrefix(t, "mcp__"); ok {
		if i := strings.Index(rest, "__"); i > 0 {
			return rest[i+2:]
		}
		return ""
	}
	if i := strings.IndexAny(t, "/:"); i > 0 && i+1 < len(t) {
		return t[i+1:]
	}
	return ""
}
