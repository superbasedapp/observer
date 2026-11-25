package config

import "time"

// This file holds the config types of [intelligence], [advisor], [predict],
// [guidance] and [projects].

// AdvisorConfig gates the suggestions engine (docs/advisor.md; plan
// docs/plans/suggestions-engine-implementation-plan-2026-06-10.md).
// "§15.7" is the engine's long-standing informal handle used across
// docs/plans — the numbered spec itself only goes to §15.6, so this
// comment cites the operator doc instead of a section that doesn't exist.
// Default-ON: read-layer only, local, zero LLM cost. Same partial-merge
// invariant as CacheTrackConfig — an install with no [advisor] section
// must get Enabled=true from Default(), never a zero-valued false.
type AdvisorConfig struct {
	// Enabled gates the /api/suggestions endpoint, the dashboard tab's
	// data, and `observer advise`.
	Enabled bool `toml:"enabled"`
	// WindowDays is the default evidence window. Default 14.
	WindowDays int `toml:"window_days"`
	// MinConfidence hides suggestions below this floor. Default 0.5.
	MinConfidence float64 `toml:"min_confidence"`
	// MinSavingsUSD hides cost suggestions claiming less than this
	// (calibration T7). Default 1.0.
	MinSavingsUSD float64 `toml:"min_savings_usd"`
	// SessionDigest, when true, lets the Claude Code session-start hook
	// inject a ≤400-token advisory digest (top suggestions) as
	// additionalContext. Default OFF until proven quiet (plan Phase 3).
	// The hook only point-reads the advisor_digest snapshot — it never
	// computes (P1).
	SessionDigest bool `toml:"session_digest"`
	// DigestRefreshMinutes is the daemon's advisor_digest refresh
	// cadence. Default 30.
	DigestRefreshMinutes int `toml:"digest_refresh_minutes"`
}

// PredictConfig is the [predict] surface — the Next-Message Cost &
// Limit Predictor (docs/cost-predictor.md). Default-ON, same partial-
// merge invariant as CacheTrackConfig: an install with no [predict]
// section gets Enabled=true (NOT a zero-valued false) because Load()
// starts from Default() and unmarshals TOML on top. LOCAL-ONLY — never
// distributed to an org server.
type PredictConfig struct {
	// Enabled gates the predictor. The cost estimate is pure read-side
	// math (no cost when unused); when false the proxy also skips
	// limit-snapshot capture and the dashboard/CLI surfaces stay empty.
	Enabled bool `toml:"enabled"`
	// YoungSessionMessages is the §0 T-ladder threshold: at/above this
	// many observed user messages the session's own turns-per-message
	// distribution is trusted; below it the cross-session prior wins.
	// Default 3.
	YoungSessionMessages int `toml:"young_session_messages"`
	// DefaultTurnsPerMessage is the tier-3 fallback fan-out when neither
	// the session nor a prior yields turns-per-message. Default 12.
	DefaultTurnsPerMessage int `toml:"default_turns_per_message"`
	// PriorWindowDays bounds the recency of sessions feeding the
	// cross-session T prior. Default 30. 0 = no bound.
	PriorWindowDays int `toml:"prior_window_days"`
}

// GuidanceConfig is the [guidance] surface — the agent-guidance-file
// inventory (CLAUDE.md / AGENTS.md / .cursor/rules / skills / commands /
// subagent definitions and their per-tool equivalents). LOCAL-ONLY: the
// scan records file NAMES, sizes, hashes and frontmatter metadata, never
// file bodies (CLAUDE.md "no content in the DB" rule — a body is read on
// demand through the capped, symlink-safe fsview reader instead).
//
// Default-ON, with the CacheTrack partial-merge rule: an install whose
// config.toml has no [guidance] section MUST get Enabled=true from
// Default(), not a zero-valued false, and a section that sets only
// rescan_minutes must keep Enabled=true.
type GuidanceConfig struct {
	// Enabled gates the daemon-lifetime scan loop, the CLI's implicit
	// scan, and the dashboard/MCP read surfaces. When false nothing is
	// scanned and the surfaces report the disabled state honestly.
	Enabled bool `toml:"enabled"`
	// RescanMinutes is the interval between whole-estate rescans (every
	// known project root). Default 15. <= 0 disables the periodic tick —
	// the one-shot scan at daemon start still runs.
	RescanMinutes int `toml:"rescan_minutes"`
	// MaxFileBytes caps how much of a guidance file the scanner reads to
	// hash it and parse its frontmatter. Default 524288 (512KB). A larger
	// file is still inventoried; only its parse is bounded.
	MaxFileBytes int64 `toml:"max_file_bytes"`
	// MaxDepth bounds directory recursion below a guidance root (e.g.
	// `.claude/skills/<name>/SKILL.md`). Default 4.
	MaxDepth int `toml:"max_depth"`
	// IncludeUserScope also inventories the operator's HOME-scoped
	// guidance (`~/.claude/CLAUDE.md`, `~/.claude/skills/…`) alongside the
	// project-scoped files. Default true — a user-scope skill changes the
	// agent's behaviour in this project just as much as a project one.
	IncludeUserScope bool `toml:"include_user_scope"`
	// MaxRootsPerPass caps how many project roots one pass walks. Roots
	// are ordered most-recently-active first, so the cap drops the
	// dormant tail; the tail is not starved, because each pass rotates
	// its start offset. Default 50. <= 0 means the seeded default.
	//
	// It was 200 (a compile-time constant) until a live machine with 404
	// recorded roots — most of them slow DrvFs mounts — turned a start-up
	// pass into four CPU-minutes.
	MaxRootsPerPass int `toml:"max_roots_per_pass"`
	// RootTimeoutSeconds bounds ONE root's walk. A root that overruns is
	// reported incomplete and NOT persisted — a partial inventory would
	// tombstone guidance files that are still there — and is retried on
	// the next pass. Default 20. <= 0 means the seeded default; there is
	// deliberately no "unbounded" setting, because an unbounded root is
	// exactly the failure this bounds.
	RootTimeoutSeconds int `toml:"root_timeout_seconds"`
	// RootTimeoutMaxSeconds is the ADAPTIVE CEILING for a root's walk. A
	// root that overruns RootTimeoutSeconds is granted a larger budget on
	// its next pass (doubling per consecutive overrun) up to this ceiling,
	// so a legitimately slow-but-real root — e.g. a large repo on a slow
	// DrvFs mount — is given the time to finish and finally persist, rather
	// than overrunning the same fixed budget forever and never landing its
	// inventory. Default 180. <= 0 means the seeded default; a positive
	// value below RootTimeoutSeconds is refused by Validate (the ceiling can
	// never be below the base). 180s gives real headroom over the ~106s a
	// live DrvFs walk took while still bounding a runaway.
	RootTimeoutMaxSeconds int `toml:"root_timeout_max_seconds"`
	// PassTimeoutMinutes bounds a WHOLE pass. Roots not reached inside it
	// are simply picked up next tick. Default 10. <= 0 means the seeded
	// default.
	PassTimeoutMinutes int `toml:"pass_timeout_minutes"`
	// StartupDelaySeconds delays the first pass after the daemon starts,
	// so a restart is not immediately CPU-heavy while the proxy, watcher
	// and dashboard are coming up. Default 90. <= 0 runs the first pass
	// immediately.
	StartupDelaySeconds int `toml:"startup_delay_seconds"`
	// FirstScanPollSeconds is how often the daemon looks for project roots
	// that have NEVER been scanned and inventories just those, so a brand
	// new project does not wait up to RescanMinutes for its first (and
	// only informative) inventory. Default 60. 0 disables the poll
	// entirely; the periodic pass still covers the root eventually.
	//
	// It is deliberately NOT a per-session trigger: a scan is filesystem
	// work, and firing one every time a session starts in an
	// already-inventoried project would be the same unbounded cost the
	// per-root/per-pass budgets exist to prevent. Never-scanned is the one
	// state where waiting a quarter of an hour shows the operator nothing.
	FirstScanPollSeconds int `toml:"first_scan_poll_seconds"`
}

// ProjectsConfig is the [projects] surface — the Projects-page spend/ROI/
// commit-alignment arc (docs/plans/projects-page-roi-and-commit-alignment-
// plan-2026-09-21.md §2/§3.2). LOCAL-ONLY: every knob here governs the
// node's own read-only git-commit scanner (internal/commitscan) and the
// pure attribution/ROI math (internal/projectroi); nothing is distributed
// to an org server.
//
// Same partial-merge invariant as GuidanceConfig/CacheTrackConfig: an
// install with no [projects] section — or one that sets only, say,
// commit_link_window_days — gets the Default() seed for every other
// field, NOT the zero value, because Load() starts from Default() and
// unmarshals TOML on top.
type ProjectsConfig struct {
	// CommitScan gates the daemon-lifetime read-only `git log` scanner
	// (plan R2). Default TRUE — commit capture is local, passive, and
	// network-free, the same posture as Guidance/CacheTrack/Predict.
	// Disabling it leaves the Projects page's commit ledger and every ROI
	// proxy that depends on it honestly empty (capture:"never_scanned").
	CommitScan bool `toml:"commit_scan"`
	// CommitScanIntervalSeconds is the tick period between scanner passes
	// over every active project root. Default 120.
	CommitScanIntervalSeconds int `toml:"commit_scan_interval_seconds"`
	// CommitLinkWindowDays bounds how long after a prompt a later commit
	// may still "carry" the files it touched (plan R4.4's attribution
	// rule) — also sizes the reachability-revalidation lookback
	// (internal/commitscan's LinkWindow). Default 14.
	CommitLinkWindowDays int `toml:"commit_link_window_days"`
	// ActiveProjectDays bounds which projects the scanner considers
	// ACTIVE (a session started within this many days) and therefore
	// worth polling (plan R2). Default 30.
	ActiveProjectDays int `toml:"active_project_days"`
	// AlignmentJudge gates the §3.6 "J" alignment-grading tier (W5a):
	// "off" (default) leaves prompt-to-commit grading to the always-on
	// local heuristic (internal/projectroi) only; "obs_judge" reuses the
	// SAME judge endpoint/model the operator already configured under
	// [observability.judge] (or its [observability.eval] override) —
	// which MAY be a remote/hosted judge, in which case
	// cmd/observer/alignment_wire.go applies the same egress scrub
	// (secret redaction + payload cap) the eval/admission judge adapters
	// already apply to a non-loopback judge. No other value is
	// recognized; an unrecognized value is treated as "off".
	AlignmentJudge string `toml:"alignment_judge"`
	// SkillHistory gates the Projects-page Skills history capture
	// (S10-SKILLS): the Claude Code hook snapshots of every SKILL.md at
	// SessionStart / PostToolUse(Skill), and the read-only git step that
	// runs after each successful commit scan (reflog, skill-directory
	// trees, working-tree status). Default TRUE - local, passive and
	// network-free, the same posture as CommitScan. Disabling it stops
	// new capture; already-captured history still renders.
	SkillHistory bool `toml:"skill_history"`
	// SkillHistorySkewSeconds is how close a HEAD move may be to a
	// session's start before the Skills tab refuses to say which commit
	// HEAD was on ("head moved near start", both candidates shown).
	// Covers clock skew between the AI tool's clock and the repository's
	// (e.g. a Windows tool and a WSL daemon). Default 120.
	SkillHistorySkewSeconds int `toml:"skill_history_skew_seconds"`
	// QualityMetrics gates the Projects page's quality metrics
	// (docs/projects-page.md "Quality metrics", plan item 8 M3L-2 and
	// M3L-4): line coverage read from the coverage report files a
	// project's own test runs already wrote at their default locations
	// (read under a byte cap, never through a symbolic link; only the
	// numbers are stored), duplication rolled up from the codeintel
	// near-clone index, complexity rolled up from the per-function
	// cyclomatic complexity code intelligence counts at index time (both
	// need [codeintel].enabled; counting is a second tree-sitter query
	// pass, so the indexer runs it only while this is on, and turning it
	// on re-parses each indexed file once at the next index pass), and one
	// daily trend point per active project (internal/codequalitysvc).
	// Default FALSE, opt-in as plan 14.13's editions table rules for item
	// 8 (it is local, passive, read-only and network-free; Observer never
	// runs a project's tests). False makes the Quality tab say "off",
	// records no points and stops counting; stored history and counted
	// figures stay.
	QualityMetrics bool `toml:"quality_metrics"`
}

// IntelligenceConfig groups intelligence-layer settings.
//
// MonthlyBudgetUSD is the user's self-set spend cap for the calendar
// month — surfaced on the Analysis dashboard as a progress tile. Zero
// disables budget tracking. Stored in `intelligence.monthly_budget_usd`.
// The Settings page (PR 2 of the dashboard refresh) writes this from the
// UI; until then users can edit `config.toml` directly.
//
// ProjectBudgetsUSD maps a project root path (exactly as the projects
// table records it) to a monthly advisory budget for that project.
// Absent / zero = no per-project budget. ADVISORY ONLY — budget state
// renders banners and tiles; nothing ever gates proxy traffic (P1).
// Stored in `[intelligence.project_budgets_usd]`; edited from the Cost
// page's Budget card or `observer config set
// intelligence.project_budgets_usd.<root> <usd>`.
type IntelligenceConfig struct {
	Pricing           PricingConfig         `toml:"pricing"`
	APIKeyEnv         string                `toml:"api_key_env"`
	SummaryModel      string                `toml:"summary_model"`
	MonthlyBudgetUSD  float64               `toml:"monthly_budget_usd"`
	ProjectBudgetsUSD map[string]float64    `toml:"project_budgets_usd"`
	MCP               IntelligenceMCPConfig `toml:"mcp"`
	// OrgEnrichment opts this node into pulling Cloud Intelligence enrichment
	// from the ORG server it is enrolled with, instead of the hosted personal
	// plane (org-served-cloud-intelligence plan §2.1, W3). Read-only here; the
	// managed-node RAISE of this key is a govern authority (W5) under the
	// enterprise posture (an extract.intel grant on a managed enrolment), so
	// this is the node-authored default and, on an individual node, the
	// "never server-forced" floor. Default false:
	// a node that never sets it makes no org-intelligence request at all.
	OrgEnrichment bool `toml:"org_enrichment"`
	// Scoring tunes the daemon's automatic session quality scoring
	// (spec §15.2, internal/intelligence/scoring.AutoScorer).
	Scoring IntelligenceScoringConfig `toml:"scoring"`
}

// IntelligenceScoringConfig tunes the daemon-lifetime session quality scorer
// (spec §15.2). Default-ON with the partial-merge rule: Default() seeds Auto
// true, so an install whose config.toml has no [intelligence.scoring] block
// inherits it. Local, read-only over actions/token_usage/cache_events, zero
// LLM cost, writes only the sessions score columns. Zero / negative numeric
// values fall back to the built-in defaults (see the accessor methods), so a
// half-written block never disables scoring by accident.
type IntelligenceScoringConfig struct {
	// Auto runs the scorer inside `observer start`. false leaves scoring to
	// the manual `observer score` CLI.
	Auto bool `toml:"auto"`
	// IntervalMinutes is the pause between scoring passes (default 5).
	IntervalMinutes int `toml:"interval_minutes"`
	// IdleMinutes is how long a session must be quiet before it is scored
	// (default 30) - the stand-in for "session ended", which most tools
	// never record.
	IdleMinutes int `toml:"idle_minutes"`
	// MaxPerPass bounds the sessions scored in one pass (default 200), so a
	// large never-scored history is worked off gradually.
	MaxPerPass int `toml:"max_per_pass"`
}

// Interval returns the pass interval, defaulting to 5 minutes.
func (c IntelligenceScoringConfig) Interval() time.Duration {
	if c.IntervalMinutes <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(c.IntervalMinutes) * time.Minute
}

// Idle returns the idle threshold, defaulting to 30 minutes.
func (c IntelligenceScoringConfig) Idle() time.Duration {
	if c.IdleMinutes <= 0 {
		return 30 * time.Minute
	}
	return time.Duration(c.IdleMinutes) * time.Minute
}

// PassLimit returns the per-pass cap, defaulting to 200.
func (c IntelligenceScoringConfig) PassLimit() int {
	if c.MaxPerPass <= 0 {
		return 200
	}
	return c.MaxPerPass
}

// IntelligenceMCPConfig groups settings for the V7-12 retrieval-surface
// MCP tools and their shared audit log. Top-level switch is per-tool
// (each subtype carries its own Enabled flag) — there is no global
// `[intelligence.mcp].enabled` knob because operators should be able
// to disable individual tools without losing audit visibility.
//
// Features is the V7-16 allow-list for the four V7-12 retrieval tools
// (`get_file`, `get_symbols`, `get_relations`, `retrieve_stashed`).
// Scope is deliberately V7-12-only — the 13 built-in observability
// tools (check_*, get_action_details, get_cost_summary,
// get_failure_context, get_file_history, get_last_test_result,
// get_project_patterns, get_redundancy_report,
// get_session_recovery_context, get_session_summary,
// list_actions_around, search_past_outputs) are NOT filtered. See
// D-3 in docs/plans/v1.7.11-stash-retrieval-correctness-plan-2026-05-31.md
// for the trade-off discussion.
//
// Precedence: per-tool `enabled = false` ALWAYS wins. Features filter
// cannot re-enable a per-tool-disabled tool. Empty Features (the
// default) = no filter, per-tool flags decide alone.
type IntelligenceMCPConfig struct {
	Features        []string                             `toml:"features"`
	GetFile         IntelligenceMCPGetFileConfig         `toml:"get_file"`
	GetSymbols      IntelligenceMCPGetSymbolsConfig      `toml:"get_symbols"`
	GetRelations    IntelligenceMCPGetRelationsConfig    `toml:"get_relations"`
	RetrieveStashed IntelligenceMCPRetrieveStashedConfig `toml:"retrieve_stashed"`
	Audit           IntelligenceMCPAuditConfig           `toml:"audit"`
}

// IntelligenceMCPGetFileConfig tunes the v1.7.8 get_file MCP tool.
//
// AllowExtensions empty disables the allow-list (operator escape
// hatch for binary-mostly workloads); see V7-13 Gap 4 in
// docs/v4-codex-compression-recipe-and-issues.md.
//
// DenyPaths supports a small glob syntax: `*`, `?`, `<dir>/**`.
// Patterns using unsupported syntax (`[abc]`, `{a,b}`, escapes) are
// silently dead; [Load] emits a warning per unsupported pattern at
// startup so operators notice.
//
// MaxResponseKB caps individual response bytes. Truncated responses
// carry `truncated: true` so the agent knows to retry tighter.
type IntelligenceMCPGetFileConfig struct {
	Enabled         bool     `toml:"enabled"`
	AllowExtensions []string `toml:"allow_extensions"`
	DenyPaths       []string `toml:"deny_paths"`
	MaxResponseKB   int      `toml:"max_response_kb"`
}

// IntelligenceMCPGetSymbolsConfig tunes the v1.7.9 get_symbols MCP
// tool (V7-12 retrieval surface, second of four).
//
// Path-safety knobs (allow/deny lists, max response size) live on
// [IntelligenceMCPGetFileConfig] and are SHARED — one place to keep
// in sync; both tools resolve files the same way and operators
// shouldn't have to author two extension allow-lists. If a future
// release surfaces a divergence (e.g. get_symbols wants binary file
// extensions get_file shouldn't allow), this struct grows its own
// AllowExtensions/DenyPaths fields and the resolver prefers them
// over GetFile's.
//
// MaxCallers and MaxCallees cap the per-symbol callers/callees list
// returned by `include_relations: true`. The accompanying
// `callers_count` / `callees_count` fields report the unlimited
// totals so the agent sees `callers_count: 47, callers: [...top 20...]`
// without being misled.
type IntelligenceMCPGetSymbolsConfig struct {
	Enabled    bool `toml:"enabled"`
	MaxCallers int  `toml:"max_callers"`
	MaxCallees int  `toml:"max_callees"`
}

// IntelligenceMCPGetRelationsConfig tunes the v1.7.10 get_relations
// MCP tool (V7-12 retrieval surface, third of four).
//
// Path-safety knobs (allow/deny lists, max response KB) live on
// [IntelligenceMCPGetFileConfig] and are SHARED across all three
// retrieval tools — one place for operators to keep in sync.
//
// MaxDepth caps BFS recursion depth; MaxResults caps the per-call
// reachable-node count. Lower these on very large codebases where
// a worst-case BFS could otherwise visit thousands of nodes per call.
// Larger values are bounded only by SQLite recursive-CTE cost; the
// MCP layer truncates at MaxResults regardless.
type IntelligenceMCPGetRelationsConfig struct {
	Enabled    bool `toml:"enabled"`
	MaxDepth   int  `toml:"max_depth"`
	MaxResults int  `toml:"max_results"`
}

// IntelligenceMCPRetrieveStashedConfig tunes the v1.7.11
// retrieve_stashed MCP tool extension (V7-12 retrieval surface,
// fourth of four).
//
// Enabled gates registration. When the stash itself is enabled
// (`[compression.conversation.stash].enabled = true`) AND this flag is
// true, the tool is registered. Setting this to false lets operators
// keep proxy-side stash compression active while denying the agent
// the retrieval surface (e.g., security/audit scenarios where the
// proxy and the MCP server have asymmetric trust).
//
// MaxShasPerCall caps the array-form sha input per request. Defaults
// to 25 (matches get_symbols's per-call batch cap). Set higher only
// if your agent reliably emits larger batches AND your audit budget
// can absorb the per-sha row volume.
type IntelligenceMCPRetrieveStashedConfig struct {
	Enabled        bool `toml:"enabled"`
	MaxShasPerCall int  `toml:"max_shas_per_call"`
}

// IntelligenceMCPAuditConfig controls the V7-14 audit log. When
// Enabled, every V7-12 MCP call (success or denial) writes one row
// into mcp_audit. Operators can `SELECT ... FROM mcp_audit` for
// "what was denied?" / "what is the agent reading?" forensics until
// the operator CLI lands (deferred to v1.8.x).
//
// Default true: the table is local-only, the volume budget is small,
// and the forensic value is high. Privacy-conscious operators opt
// out with one TOML line.
type IntelligenceMCPAuditConfig struct {
	Enabled bool `toml:"enabled"`
}

// UnsupportedDenyPatterns returns the subset of [DenyPaths] that use
// glob syntax outside the supported `*`, `?`, `<dir>/**` subset
// (e.g. character classes `[a-z]`, brace alternation `{a,b}`, or
// escape sequences `\x`). The patterns are NOT removed from the
// config — they're inert at match time. Callers (notably
// `observer serve`) emit one warning line per returned pattern at
// startup so operators notice silently-dead deny rules.
func (g IntelligenceMCPGetFileConfig) UnsupportedDenyPatterns() []string {
	var bad []string
	for _, p := range g.DenyPaths {
		if hasUnsupportedDenyGlob(p) {
			bad = append(bad, p)
		}
	}
	return bad
}

// hasUnsupportedDenyGlob mirrors internal/mcp/pathsafety.go's
// hasUnsupportedGlobSyntax. Duplicated here (5 lines) so config
// doesn't import mcp — config sits beneath mcp in the dependency
// graph. Keep both in sync; the test
// [TestIntelligenceMCPGetFileConfig_UnsupportedDenyPatterns] pins
// the contract.
func hasUnsupportedDenyGlob(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '[', ']', '{', '}', '\\':
			return true
		}
	}
	return false
}
