package policy

// This file is the security pillar's type contract inside the guard core
// (security pillar plan docs/plans/security-pillar-plan-2026-10-19.md,
// sections 4.3, 4.5 and 4.7; joint roadmap section 12, lane sec-a). It
// holds types and constants only.
//
// They live here, and not in a pillar package, because core code consults
// them in every build, including one compiled with sbo_omit_security
// (section 4.3 "What stays in core"): the guard engine evaluates Event
// values that carry Event.Security, the hook context seam
// (internal/hookctx) fills it, the org wire rows spell findings with these
// vocabularies, and this package imports zero observer packages, so it is
// the one owner every other layer can share. With the security module
// inactive Event.Security stays nil and nothing here does anything.

// KindAgentLaunch is the launch chokepoint's event (section 4.7 item 4):
// an agent about to start in a project, through `observer <tool>`, New
// Terminal or a shell-wrap shim. Target is the project root; the repository
// trust verdict rides in Event.Security. It exists so "refuse to launch an
// agent in an untrusted repository" is a guard rule (S-701 to S-705), not
// pillar code.
const KindAgentLaunch EventKind = "agent_launch"

// CategoryCodeSecurity is the guard rule category of the pillar's S-7xx
// rules (section 4.7 item 5). Secret rules keep CategorySecrets, so
// existing category filters and per-category overrides keep working.
const CategoryCodeSecurity Category = "code_security"

// SourcePackSecurity is the Rule.Source value of the pillar's S-7xx rows,
// passed in Config.ExtraRules by the cmd layer (section 4.7 item 1). The
// guard layering treats it like a built-in for trust purposes: user
// overrides and the org bundle may tune it, the project layer may only
// escalate it.
const SourcePackSecurity = "pack:security"

// SecurityRuleIDPrefix is the guard rule id prefix the pillar owns
// (section 4.7 item 5: S-701 to S-799). Engine rule ids (an Opengrep
// rule, a custom driver's) are finding rule ids only, never guard ids.
const SecurityRuleIDPrefix = "S-7"

// SinkGitCommit is the policy-file sink beside git_push (section 4.7 item
// 4): an agent action that records a commit. It maps to KindShellExec and
// KindMCPCall, and the classifier tables in this package decide it.
const SinkGitCommit = "git_commit"

// FindingCategory is the closed finding category vocabulary (section 4.5).
type FindingCategory string

// The FindingCategory values (section 4.5).
const (
	FindingAgentConfig          FindingCategory = "agent_config"
	FindingRepoTrust            FindingCategory = "repo_trust"
	FindingSecret               FindingCategory = "secret"
	FindingMaliciousPackage     FindingCategory = "malicious_package"
	FindingVulnerableDependency FindingCategory = "vulnerable_dependency"
	FindingHallucinatedPackage  FindingCategory = "hallucinated_package"
	FindingCodeVuln             FindingCategory = "code_vuln"
	FindingIaC                  FindingCategory = "iac"
	FindingCIConfig             FindingCategory = "ci_config"
	FindingSecurityRegression   FindingCategory = "security_regression"
	FindingTestTampering        FindingCategory = "test_tampering"
	FindingScopeDrift           FindingCategory = "scope_drift"
	FindingGitBypass            FindingCategory = "git_bypass"
	FindingProvenance           FindingCategory = "provenance"
)

// FindingCategories returns the closed category vocabulary in plan order.
func FindingCategories() []FindingCategory {
	return []FindingCategory{
		FindingAgentConfig, FindingRepoTrust, FindingSecret, FindingMaliciousPackage,
		FindingVulnerableDependency, FindingHallucinatedPackage, FindingCodeVuln, FindingIaC,
		FindingCIConfig, FindingSecurityRegression, FindingTestTampering, FindingScopeDrift,
		FindingGitBypass, FindingProvenance,
	}
}

// FindingSeverity is the closed finding severity vocabulary (section 4.5).
// It is distinct from the guard rule Severity: a finding's severity is the
// engine's grading of the issue, a rule's severity grades the rule.
type FindingSeverity string

// The FindingSeverity values, weakest first.
const (
	FindingSeverityInfo     FindingSeverity = "info"
	FindingSeverityLow      FindingSeverity = "low"
	FindingSeverityMedium   FindingSeverity = "medium"
	FindingSeverityHigh     FindingSeverity = "high"
	FindingSeverityCritical FindingSeverity = "critical"
)

// FindingSeverities returns the closed severity vocabulary, weakest first.
func FindingSeverities() []FindingSeverity {
	return []FindingSeverity{
		FindingSeverityInfo, FindingSeverityLow, FindingSeverityMedium,
		FindingSeverityHigh, FindingSeverityCritical,
	}
}

// FindingConfidence is the closed confidence vocabulary (section 4.5,
// principle PR7).
type FindingConfidence string

// The FindingConfidence values, weakest first.
const (
	FindingConfidenceLow    FindingConfidence = "low"
	FindingConfidenceMedium FindingConfidence = "medium"
	FindingConfidenceHigh   FindingConfidence = "high"
)

// FindingConfidences returns the closed confidence vocabulary, weakest
// first.
func FindingConfidences() []FindingConfidence {
	return []FindingConfidence{FindingConfidenceLow, FindingConfidenceMedium, FindingConfidenceHigh}
}

// FindingScope is where a finding (or a driver run) was produced (section
// 4.5; the driver Target.Scope of section 4.4 uses the same vocabulary).
type FindingScope string

// The FindingScope values (section 4.5).
const (
	FindingScopePreWrite  FindingScope = "pre_write"
	FindingScopePostWrite FindingScope = "post_write"
	FindingScopeStaged    FindingScope = "staged"
	FindingScopeDiff      FindingScope = "diff"
	FindingScopeCommit    FindingScope = "commit"
	FindingScopePush      FindingScope = "push"
	FindingScopeScheduled FindingScope = "scheduled"
	FindingScopeCI        FindingScope = "ci"
	FindingScopeManual    FindingScope = "manual"
	FindingScopePrelaunch FindingScope = "prelaunch"
)

// FindingScopes returns the closed scope vocabulary in plan order.
func FindingScopes() []FindingScope {
	return []FindingScope{
		FindingScopePreWrite, FindingScopePostWrite, FindingScopeStaged, FindingScopeDiff, FindingScopeCommit,
		FindingScopePush, FindingScopeScheduled, FindingScopeCI, FindingScopeManual, FindingScopePrelaunch,
	}
}

// FindingBaseline is the baseline judgement of a finding (section 4.5.2).
type FindingBaseline string

// The FindingBaseline values (section 4.5.2).
const (
	// FindingBaselineNew: not reported against the approved baseline commit.
	FindingBaselineNew FindingBaseline = "new"
	// FindingBaselinePreExisting: the same rule pack reports the same local key
	// against the approved baseline commit's tree. Never for a secret or a
	// malicious package.
	FindingBaselinePreExisting FindingBaseline = "pre_existing"
	// FindingBaselineUntrusted: no trusted baseline exists yet (first activation,
	// a deleted database, a new identity). Flags but does not block on an
	// individual node; treated like new under a managed floor.
	FindingBaselineUntrusted FindingBaseline = "untrusted_baseline"
	// FindingBaselineUnknown: not judged.
	FindingBaselineUnknown FindingBaseline = "unknown"
)

// FindingBaselines returns the closed baseline vocabulary.
func FindingBaselines() []FindingBaseline {
	return []FindingBaseline{FindingBaselineNew, FindingBaselinePreExisting, FindingBaselineUntrusted, FindingBaselineUnknown}
}

// FindingStatus is a finding's lifecycle status (section 4.5).
type FindingStatus string

// The FindingStatus values (section 4.5).
const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusNotReproduced FindingStatus = "not_reproduced"
	FindingStatusFixedVerified FindingStatus = "fixed_verified"
	FindingStatusSuppressed    FindingStatus = "suppressed"
	FindingStatusAcceptedRisk  FindingStatus = "accepted_risk"
	FindingStatusFalsePositive FindingStatus = "false_positive"
)

// FindingStatuses returns the closed status vocabulary.
func FindingStatuses() []FindingStatus {
	return []FindingStatus{
		FindingStatusOpen, FindingStatusNotReproduced, FindingStatusFixedVerified,
		FindingStatusSuppressed, FindingStatusAcceptedRisk, FindingStatusFalsePositive,
	}
}

// FindingAttribution is the inferred attribution class of a finding
// (section 4.5): an inference from a temporal and path-hash association,
// never proof of who wrote a line, and a class, never a person.
type FindingAttribution string

// The FindingAttribution values (section 4.5).
const (
	FindingAttributionAI      FindingAttribution = "ai"
	FindingAttributionHuman   FindingAttribution = "human"
	FindingAttributionMixed   FindingAttribution = "mixed"
	FindingAttributionUnknown FindingAttribution = "unknown"
)

// FindingAttributions returns the closed attribution vocabulary.
func FindingAttributions() []FindingAttribution {
	return []FindingAttribution{FindingAttributionAI, FindingAttributionHuman, FindingAttributionMixed, FindingAttributionUnknown}
}

// SecurityPosture is one of the five project states the hook derives from
// the signed posture sidecar and the dirty marker (section 4.8). The
// commit-gate rules S-791 to S-794 decide on it.
type SecurityPosture string

// The SecurityPosture values (section 4.8).
const (
	// SecurityPostureAbsent: the module is inactive, or no pillar child is in the
	// active pack set. No pillar rule is composed.
	SecurityPostureAbsent SecurityPosture = "absent"
	// SecurityPostureUnknown: the posture file is missing, does not verify, has
	// expired, was rolled back below the seen mark, is over its cap, names
	// other policy or bundle versions, or has overflowed. Never treated as
	// clean (principle PR14).
	SecurityPostureUnknown SecurityPosture = "unknown"
	// SecurityPostureDirty: agent activity since the last clean quick scan has not
	// been scanned.
	SecurityPostureDirty SecurityPosture = "dirty"
	// SecurityPostureBlocking: open, new (or untrusted_baseline under a managed
	// floor), high-confidence blocking findings; Security.Blocking is n.
	SecurityPostureBlocking SecurityPosture = "blocking"
	// SecurityPostureClean: nothing known and nothing unscanned.
	SecurityPostureClean SecurityPosture = "clean"
)

// SecurityPostures returns the closed posture vocabulary.
func SecurityPostures() []SecurityPosture {
	return []SecurityPosture{SecurityPostureAbsent, SecurityPostureUnknown, SecurityPostureDirty, SecurityPostureBlocking, SecurityPostureClean}
}

// TrustVerdict is the repository trust check's verdict (section 5.1).
type TrustVerdict string

// The TrustVerdict values (section 5.1).
const (
	// TrustNotChecked: no trust check ran for this event (the zero value).
	TrustNotChecked TrustVerdict = ""
	// TrustClean: nothing on the fixed path table is risky.
	TrustClean TrustVerdict = "clean"
	// TrustFlagged: risky but accepted, or a reason that only words a
	// warning.
	TrustFlagged TrustVerdict = "flagged"
	// TrustUntrusted: a command the repository makes the agent run whose
	// exact digest is not accepted, or a redirect of the agent's API.
	TrustUntrusted TrustVerdict = "untrusted"
	// TrustUnknown: the check could not run to completion.
	TrustUnknown TrustVerdict = "unknown"
)

// InstallVerdict is the install-time package check's verdict (section
// 5.4).
type InstallVerdict string

// The InstallVerdict values (section 5.4).
const (
	// InstallNotChecked: no install was checked for this event.
	InstallNotChecked InstallVerdict = ""
	// InstallKnownGood: the names are on the popular list and not listed
	// as malicious.
	InstallKnownGood InstallVerdict = "known_good"
	// InstallMalicious: listed by an authenticated source (S-741, the only
	// deny-eligible verdict).
	InstallMalicious InstallVerdict = "malicious"
	// InstallNearMiss: one edit away from a popular name (S-742).
	InstallNearMiss InstallVerdict = "near_miss"
	// InstallListedVersion: some versions of the package are listed as
	// malicious, and the install does not pin a version known to be
	// outside them (an unpinned install, or a listing by version range).
	// It flags (S-749); only a listing that covers the version installed
	// is malicious (S-741).
	InstallListedVersion InstallVerdict = "listed_version"
	// InstallTooNew: published too recently (S-743).
	InstallTooNew InstallVerdict = "too_new"
	// InstallUnknownName: not known to the offline index (S-744).
	InstallUnknownName InstallVerdict = "unknown"
	// InstallOnlineUnknown: the online check did not answer in time; the
	// offline verdict stands (S-748). Never relaxes.
	InstallOnlineUnknown InstallVerdict = "online_unknown"
)

// InstallSource says where an install verdict came from (section 5.4).
type InstallSource string

// The InstallSource values.
const (
	InstallSourceNone    InstallSource = ""
	InstallSourceOffline InstallSource = "offline"
	InstallSourceOnline  InstallSource = "online"
)

// InstallChecksMax caps Security.Installs.
const InstallChecksMax = 64

// InstallNameMax caps InstallCheck.Name (and NearMiss) in bytes.
const InstallNameMax = 128

// InstallCheck is one package's install-time check (section 5.4): the
// ecosystem, the name as it was checked (capped, charset-filtered by the
// producer; it reaches deny text only quoted), the pinned version, the
// verdict and where it came from. It never carries a path or a registry
// URL.
type InstallCheck struct {
	Ecosystem string
	Name      string
	Version   string
	Verdict   InstallVerdict
	Source    InstallSource
	// Private reports a name the classifier kept off every online source
	// (a private scope or registry): it is checked offline only and never
	// called a near miss.
	Private bool
	// NearMiss is the popular name a near_miss verdict is one edit from.
	NearMiss string
	// Reason is the closed reason code (internal/secfeed).
	Reason string
	// Action is the node's [security.deps] action for this check's verdict
	// (lane LEFT-SEC): "" or InstallActionDefault keeps the rule's own
	// decision; InstallActionAsk and InstallActionDeny raise S-744 (an
	// unknown package) and S-748 (an unanswered online check). Stamped by
	// the hook's install provider from the daemon's settings file.
	Action string
}

// The InstallCheck.Action values (the [security.deps] unknown-package
// pickers).
const (
	InstallActionDefault = "default"
	InstallActionAsk     = "ask"
	InstallActionDeny    = "deny"
)

// InstallVerdictRank orders install verdicts by how strongly they decide,
// for picking an event's summary verdict: malicious, near_miss,
// listed_version, online_unknown, unknown, too_new, known_good, not
// checked.
func InstallVerdictRank(v InstallVerdict) int {
	switch v {
	case InstallMalicious:
		return 8
	case InstallNearMiss:
		return 6
	case InstallListedVersion:
		return 5
	case InstallOnlineUnknown:
		return 4
	case InstallUnknownName:
		return 3
	case InstallTooNew:
		return 2
	case InstallKnownGood:
		return 1
	}
	return 0
}

// QuickScanVerdict is the commit quick scan's answer (section 4.8). The
// zero value means no quick scan ran for this event.
type QuickScanVerdict string

// The QuickScanVerdict values (section 4.8).
const (
	QuickScanNone QuickScanVerdict = ""
	// QuickScanClean: the diff the commit would record is clean.
	QuickScanClean QuickScanVerdict = "clean"
	// QuickScanBlocking: the scan found a blocking finding.
	QuickScanBlocking QuickScanVerdict = "blocking"
	// QuickScanUnknown: over budget, daemon busy, git unavailable, the
	// scanner failed or the transport failed.
	QuickScanUnknown QuickScanVerdict = "unknown"
)

// SecurityHitPathMax caps SecurityHit.Path in bytes (section 4.5.3: a
// path is at most 512 bytes).
const SecurityHitPathMax = 512

// SecurityHit is one in-hook detector hit (section 4.7 item 2): what kind
// of finding, how bad, how sure, which rule and a capped location. It
// never carries the matched value.
type SecurityHit struct {
	Category   FindingCategory
	Severity   FindingSeverity
	Confidence FindingConfidence
	Baseline   FindingBaseline
	// RuleID is the detector's finding rule id, not a guard rule id.
	RuleID string
	// Path is the project-relative path, at most SecurityHitPathMax bytes;
	// "" when the hit has no file (a command line).
	Path string
	// Line is 1-based; 0 when unknown.
	Line int
}

// ProjectMatch is the project audience match of section 7.11: the org
// projects the signed mapping resolved for this project root and the
// assignment epoch it was resolved under. Reserved by Phase A, filled by
// Phase P [JSP-10]; empty until then.
type ProjectMatch struct {
	OrgProjectIDs []string
	Epoch         uint64
}

// HeldCommit is one unpushed commit that holds a blocking finding open
// (lane sec-gate4): its full id and the remotes whose remote-tracking refs
// already have it.
type HeldCommit struct {
	Commit  string
	Remotes []string
}

// Security is Event.Security, the security pillar's facts about one event
// (section 4.7 item 2). Plain enums, counts and hits; nil when the module
// is inactive. One shared function, the hook context seam
// (internal/hookctx, roadmap F0-3), fills it; the pillar's Match closures
// read it; the guard core never imports the pillar.
type Security struct {
	// Posture is the project's commit-gate state (section 4.8). The zero
	// value means the provider gave no state; rules treat it as unknown.
	Posture SecurityPosture
	// Blocking is n of blocking(n): the open blocking findings the posture
	// lists. Overflow reports that the list was capped.
	Blocking int
	Overflow bool
	// BlockingHistoryOnly is how many of Blocking an unpushed commit alone
	// holds open (no file holds them any more; lane sec-gate3 audit
	// finding 2): the push gate (S-792) counts them, the commit gate
	// (S-791) does not, since another commit adds nothing to what the push
	// sends of them.
	BlockingHistoryOnly int
	// BlockingHistoryCapped is how many of BlockingHistoryOnly are held only
	// by commits a reflog entry past a [security.scanning] reflog cap
	// reaches (lane LEFT-SEC): no longer held for a deny, so when every
	// history-only finding is capped the push gate asks (S-792's capped
	// row) instead of denying, never allows. Zero unless a cap is set.
	BlockingHistoryCapped int
	// BlockingHistoryOnlyOn counts, per remote, the BlockingHistoryOnly
	// findings every holding commit of which that remote's tracking refs
	// already have (lane sec-gate4 milestone 1a): a push to that remote
	// sends nothing new of them, so S-792 does not count them for it. A
	// remote that is not a key has none.
	BlockingHistoryOnlyOn map[string]int
	// HeldCommits are the unpushed commits behind BlockingHistoryOnly (a
	// bounded list), each with the remotes that already have it, for the
	// push gate's wording and the pre-push hook.
	HeldCommits []HeldCommit
	// DefaultPushRemote is the remote a plain `git push` goes to, as the
	// daemon resolved and signed it for every checked-out branch of the
	// repository (lane sec-gate4 audit finding 5; "" when it could not, or
	// the branches disagree). S-792 reads a plain push as a push to it.
	DefaultPushRemote string
	// Packs is the active pack set the posture was signed under: the
	// pillar children that are active (component ids such as
	// "security.secrets"), so the hook needs no component state.
	Packs []string
	// Hits are the in-hook detector hits for this event (a proposed write,
	// a command line). ScanIncomplete reports that a detector reached its
	// deadline: the content is left to the post-write seam and the commit
	// gate, never treated as clean.
	Hits           []SecurityHit
	ScanIncomplete bool
	// QuickScan is the commit quick scan's answer at a git_commit or
	// git_push sink; QuickScanNone elsewhere.
	QuickScan QuickScanVerdict
	// Trust and TrustReasons are the repository trust verdict and its
	// reason codes (section 5.1), at agent_launch and session start.
	Trust        TrustVerdict
	TrustReasons []string
	// Install and InstallSource are the install-time package verdict and
	// where it came from (section 5.4): the strongest of Installs.
	Install       InstallVerdict
	InstallSource InstallSource
	// Installs are the per-package checks behind Install, one per package
	// the command or manifest edit names (capped at InstallChecksMax), so
	// one install naming a near-miss and an unanswered name fires both
	// rules. InstallCustomRegistry reports a registry or index flag or
	// variable (S-745); InstallManifest that the checks come from a
	// manifest edit, not an install command (S-747).
	Installs              []InstallCheck
	InstallCustomRegistry bool
	InstallManifest       bool
	// Project is the project audience match (section 7.11).
	Project ProjectMatch
	// DaemonStopped reports that the hook found the daemon not refreshing
	// its signed guard posture (older than the freshness window: stopped,
	// suspended or wedged). It changes no decision; the commit gate's
	// verdict text then says the state is unknown because the daemon is
	// stopped and how to start it (lane sec-gate2, decision log P-021).
	DaemonStopped bool
	// CommitGateFloor is the org floor require.commit_gate in force for the
	// project (lane SEC-P4 decision 9), signed into its posture by the
	// daemon: CommitGateFloorQuickScan makes S-791 to S-794 take the
	// section 4.8 decision table's managed-floor cells; "" is the node's own
	// commit gate. Only a managed node holding the security.scanning floor
	// ever has it set.
	CommitGateFloor string
}

// CommitGateFloorQuickScan is the commit gate floor that takes the managed
// floor column (require.commit_gate = "quick_scan").
const CommitGateFloorQuickScan = "quick_scan"

// GitWriteForm is one row kind of the git_commit classifier (section 4.7
// item 4): the parsed intent of a command or MCP call that records a
// commit or rewrites history. The classifier decides on the parsed intent
// (the git subcommand and its flags), never on one exact string, so a
// rewording reaches the same rule.
type GitWriteForm string

// The GitWriteForm values (section 4.7 item 4, revisions 2.4 and 2.5
// [JSP-6]).
const (
	// GitWriteCommit is `git commit`.
	GitWriteCommit GitWriteForm = "commit"
	// GitWriteCommitTree is `git commit-tree` (plumbing).
	GitWriteCommitTree GitWriteForm = "commit_tree"
	// GitWriteUpdateRef is `git update-ref` (plumbing; with commit-tree it
	// records a commit without porcelain).
	GitWriteUpdateRef GitWriteForm = "update_ref"
	// GitWriteMerge is `git merge` (runs pre-merge-commit, not pre-commit).
	GitWriteMerge GitWriteForm = "merge"
	// GitWriteCherryPick is `git cherry-pick`.
	GitWriteCherryPick GitWriteForm = "cherry_pick"
	// GitWriteAm is `git am`.
	GitWriteAm GitWriteForm = "am"
	// GitWriteRebase is `git rebase`, including `--exec`.
	GitWriteRebase GitWriteForm = "rebase"
	// GitWriteRevert is `git revert`.
	GitWriteRevert GitWriteForm = "revert"
	// GitWriteStash is `git stash` (flag only: it records a commit object
	// but not on a branch).
	GitWriteStash GitWriteForm = "stash"
	// GitWriteGHPRMerge is `gh pr merge`.
	GitWriteGHPRMerge GitWriteForm = "gh_pr_merge"
	// GitWriteGHAPIWrite is a `gh api` content-write route.
	GitWriteGHAPIWrite GitWriteForm = "gh_api_write"
	// GitWriteMCP is a known commit-capable MCP tool, matched by name.
	GitWriteMCP GitWriteForm = "mcp"
)

// GitWriteForms returns the closed classifier vocabulary.
func GitWriteForms() []GitWriteForm {
	return []GitWriteForm{
		GitWriteCommit, GitWriteCommitTree, GitWriteUpdateRef, GitWriteMerge,
		GitWriteCherryPick, GitWriteAm, GitWriteRebase, GitWriteRevert, GitWriteStash,
		GitWriteGHPRMerge, GitWriteGHAPIWrite, GitWriteMCP,
	}
}

// GitWrite is one classified git write in an event: its form plus the
// flags the quick scan needs (section 4.8: the plain form, `-a`,
// pathspecs, `--amend`). A push is the git_push sink and is recorded with
// Push set so the quick-scan request can say so.
type GitWrite struct {
	Form GitWriteForm
	// Push reports a git push riding in the same event (a chained
	// command); the push itself is the git_push sink.
	Push bool
	// All is `commit -a` / `--all`.
	All bool
	// Amend is `commit --amend`.
	Amend bool
	// Exec is `rebase --exec` / `-x`: the rebase runs a command per commit.
	Exec bool
	// FlagOnly marks a form that is flagged, never gated (git stash).
	FlagOnly bool
	// Pathspecs are the explicit paths a commit names, bounded.
	Pathspecs []string
	// Dir is the `-C <dir>` or `--git-dir` the command named, "" when none.
	Dir string
	// PushOperands are a push's operands (the repository, then the
	// refspecs), bounded; the quick scan reads what they send.
	PushOperands []string
	// PushOpaque marks a push option that changes what is sent in a way
	// the quick scan does not model (--all, --mirror, --tags, --delete,
	// --repo and the like).
	PushOpaque bool
	// PushRedirect marks a push whose destination the command line may
	// have changed (lane sec-gate4 audit finding 3): a `-c` or
	// `--config-env` naming a remote, url, branch or include key, a
	// GIT_CONFIG_* or GIT_DIR assignment, or an earlier unit on the same
	// line that switches the branch or rewires a remote. Its target is
	// unknown (PushTargetFor).
	PushRedirect bool
}
