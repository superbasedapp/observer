package orgcontract

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// securityrows.go is the security pillar's org wire (security plan 7.4, lane
// SEC-E2): three rows a node composes through the SecurityOrgProviders seam
// (internal/store/orgpush.go) and the org server re-normalizes at ingest
// (internal/orgserver/secorg).
//
// The wire is TAG-DRIVEN (plan 7.4 revision 2.4, spike JSP-1). Every field of
// every security wire row, and of every struct nested in one, carries a class
// tag:
//
//   - wire:"always" ships whenever the share level allows the row at all;
//   - wire:"raw" ships only under ShareOptions.shipsRawContent().
//
// StripSecurityRaw is the ONE strip: it reads the tags and zeroes every raw
// field unless raw content ships. CheckSecurityWireTags refuses an untagged
// field, an unknown class and an embedded struct, so a new field cannot be
// added unclassified (pinned by a reflective test over SecurityWireRowTypes).
// The plan's "never" column (a secret value, file contents, raw snippets
// beyond the redacted window, engine message text, prompt text) has NO field
// here at all; a test walks the row types for those names.
//
// Optional both directions (the compat invariant): an old node sends none of
// the envelope keys, an old server ignores them.

// The two wire classes.
const (
	SecurityWireAlways = "always"
	SecurityWireRaw    = "raw"
)

// The share levels of the security wire ([org_client.share].security on an
// individual node, finding_share of the managed pull on a managed node).
const (
	SecurityShareOff      = "off"
	SecuritySharePosture  = "posture"
	SecurityShareFindings = "findings"
)

// SecurityShareLevels is the closed share-level vocabulary.
var SecurityShareLevels = []string{SecurityShareOff, SecuritySharePosture, SecurityShareFindings}

// SecurityFindingRow is one finding as one node sees it (security plan 4.5 and
// 7.4). A re-push of the same finding carries the same FindingRef, so the
// server updates its copy and never duplicates it; OrgKey (or, without it,
// the project identity, the rule and the evidence hash) folds two nodes'
// copies into one org finding.
type SecurityFindingRow struct {
	// OrgID / UserEmail are the agent-stamped attribution; the server
	// overwrites both with the authenticated pusher's.
	OrgID     string `json:"org_id,omitempty" wire:"always"`
	UserEmail string `json:"user_email,omitempty" wire:"always"`
	// FindingRef is an opaque per-node handle of the finding (a domain
	// separated digest of the node-local id, never the id itself): the key a
	// re-push updates.
	FindingRef string `json:"finding_ref" wire:"always"`
	// OrgKey is the org dedupe key (plan 4.5.1), present only when the node
	// holds the org dedupe key from the managed pull.
	OrgKey string `json:"org_key,omitempty" wire:"always"`

	RuleID          string `json:"rule_id" wire:"always"`
	RuleVersion     string `json:"rule_version,omitempty" wire:"always"`
	RulePack        string `json:"rule_pack,omitempty" wire:"always"`
	RulePackVersion string `json:"rule_pack_version,omitempty" wire:"always"`
	Driver          string `json:"driver,omitempty" wire:"always"`
	DriverVersion   string `json:"driver_version,omitempty" wire:"always"`
	EngineDigest    string `json:"engine_digest,omitempty" wire:"always"`
	DatabaseEpoch   string `json:"database_epoch,omitempty" wire:"always"`

	Category   string   `json:"category" wire:"always"`
	Severity   string   `json:"severity" wire:"always"`
	Confidence string   `json:"confidence,omitempty" wire:"always"`
	CWE        []string `json:"cwe,omitempty" wire:"always"`
	OWASP      []string `json:"owasp,omitempty" wire:"always"`
	ATLAS      []string `json:"atlas,omitempty" wire:"always"`
	Scope      string   `json:"scope,omitempty" wire:"always"`

	ProjectIdentityHash string `json:"project_identity_hash,omitempty" wire:"always"`
	OrgProjectID        string `json:"org_project_id,omitempty" wire:"always"`
	EvidenceHash        string `json:"evidence_hash,omitempty" wire:"always"`

	// Baseline is the judgement; the reference's kind and versions ship
	// always, the reference itself (a commit sha or a CI result id) only
	// under raw content, like CommitSHA.
	Baseline              string `json:"baseline,omitempty" wire:"always"`
	BaselineRefKind       string `json:"baseline_ref_kind,omitempty" wire:"always"`
	BaselinePackVersion   string `json:"baseline_pack_version,omitempty" wire:"always"`
	BaselinePolicyVersion string `json:"baseline_policy_version,omitempty" wire:"always"`
	BaselineRef           string `json:"baseline_ref,omitempty" wire:"raw"`

	Attribution           string `json:"attribution,omitempty" wire:"always"`
	AttributionMethod     string `json:"attribution_method,omitempty" wire:"always"`
	AttributionConfidence string `json:"attribution_confidence,omitempty" wire:"always"`

	// Lineage ids already ship as metadata on other rows (plan 7.12 governs
	// the drill-down from here to a member).
	SessionID      string `json:"session_id,omitempty" wire:"always"`
	ActionID       string `json:"action_id,omitempty" wire:"always"`
	PromptActionID string `json:"prompt_action_id,omitempty" wire:"always"`
	Tool           string `json:"tool,omitempty" wire:"always"`
	ToolVersion    string `json:"tool_version,omitempty" wire:"always"`
	Model          string `json:"model,omitempty" wire:"always"`
	Surface        string `json:"surface,omitempty" wire:"always"`

	// Tainted and the taint origin CLASS ship always; the node keeps no
	// origin detail today (agent migration 177 has no column for it).
	Tainted          bool   `json:"tainted,omitempty" wire:"always"`
	TaintOriginClass string `json:"taint_origin_class,omitempty" wire:"always"`

	Status    string `json:"status" wire:"always"`
	FirstSeen string `json:"first_seen" wire:"always"`
	LastSeen  string `json:"last_seen" wire:"always"`
	ClosedAt  string `json:"closed_at,omitempty" wire:"always"`

	// Fix observations are facts only (plan 5.11), booleans and an exit code.
	FixRuleNoLongerFires    bool `json:"fix_rule_no_longer_fires,omitempty" wire:"always"`
	FixNoNewFindingInRegion bool `json:"fix_no_new_finding_in_region,omitempty" wire:"always"`
	FixTestCommandObserved  bool `json:"fix_test_command_observed,omitempty" wire:"always"`
	FixTestExitCode         int  `json:"fix_test_exit_code,omitempty" wire:"always"`
	FixTestFilesEdited      bool `json:"fix_test_files_edited,omitempty" wire:"always"`

	ExceptionID string   `json:"exception_id,omitempty" wire:"always"`
	VerdictIDs  []string `json:"verdict_ids,omitempty" wire:"always"`
	Landed      bool     `json:"landed,omitempty" wire:"always"`

	// Only under raw content: where the finding sits, the redacted evidence
	// window and the commit.
	RelPath          string   `json:"rel_path,omitempty" wire:"raw"`
	StartLine        int      `json:"start_line,omitempty" wire:"raw"`
	EndLine          int      `json:"end_line,omitempty" wire:"raw"`
	PathAliases      []string `json:"path_aliases,omitempty" wire:"raw"`
	EvidenceRedacted string   `json:"evidence_redacted,omitempty" wire:"raw"`
	CommitSHA        string   `json:"commit_sha,omitempty" wire:"raw"`
	PatchFP          string   `json:"patch_fp,omitempty" wire:"raw"`
}

// SecurityPostureRow is a node's security posture for one UTC day (security
// plan 7.4): closed enums and counts only, the BudgetPostureRow pattern. It
// never carries a path, a project, a rule id, a finding or a name. The
// server keeps one row per (pusher, day), replaced by each push.
type SecurityPostureRow struct {
	OrgID     string `json:"org_id,omitempty" wire:"always"`
	UserEmail string `json:"user_email,omitempty" wire:"always"`
	// Day is the UTC date (YYYY-MM-DD) the posture was composed on.
	Day string `json:"day" wire:"always"`
	// ShareLevel is the level the node is pushing at (posture or findings).
	ShareLevel string `json:"share_level" wire:"always"`
	// Findings counts the node's findings by category, severity and status.
	Findings []SecurityPostureCount `json:"findings,omitempty" wire:"always"`
	// Projects is how many projects hold at least one finding.
	Projects int64 `json:"projects,omitempty" wire:"always"`
	// Detectors are the security component ids active on the node.
	Detectors []string `json:"detectors,omitempty" wire:"always"`
	// Drivers are the scanner drivers that ran, with their versions.
	Drivers []SecurityDriverVersion `json:"drivers,omitempty" wire:"always"`
	// ScanFreshness buckets the age of the newest scan run.
	ScanFreshness string `json:"scan_freshness,omitempty" wire:"always"`
	// ScanOutcomes counts the day's scan runs by outcome.
	ScanOutcomes []SecurityOutcomeCount `json:"scan_outcomes,omitempty" wire:"always"`
	// OnlineChecks is the online package check state: on or off.
	OnlineChecks string `json:"online_checks,omitempty" wire:"always"`
	// CommitGate counts the day's commit-gate verdicts (S-791 to S-794) by
	// rule and decision.
	CommitGate []SecurityGateCount `json:"commit_gate,omitempty" wire:"always"`
	// FloorKeys are the in-force security.scanning floor keys and what each
	// does on this node: applied, not_applicable with a reason, or refused
	// (the E1 evaluation, as closed enums).
	FloorKeys []SecurityFloorKeyState `json:"floor_keys,omitempty" wire:"always"`
	// The four facts below were added by lane SEC-H2 (security plan 7.4's
	// table). Each is optional on the wire both ways: an older server
	// ignores the keys, and a newer server reads a fact as "not reported"
	// unless Reported names it, so an older node's row never reads as zero.
	// DatabaseAges buckets the age of each advisory or content database the
	// node holds (SecurityDatabaseKinds, SecurityDatabaseAgeBuckets).
	DatabaseAges []SecurityDatabaseAge `json:"database_ages,omitempty" wire:"always"`
	// PlatformGaps names each active scanner driver whose support on this
	// node's platform is short of supported.
	PlatformGaps []SecurityPlatformGap `json:"platform_gaps,omitempty" wire:"always"`
	// TrustVerdicts counts the day's repository trust verdicts at agent
	// launch that were not clean (a clean verdict raises no event).
	TrustVerdicts []SecurityVerdictCount `json:"trust_verdicts,omitempty" wire:"always"`
	// GateOutcomes counts the day's commit-gate outcomes: asked, denied,
	// waited (the gate waited for the quick scan and it did not come back
	// clean, S-793) and unknown (S-794).
	GateOutcomes []SecurityGateOutcome `json:"gate_outcomes,omitempty" wire:"always"`
	// Reported names which of the four facts above the node composed
	// (SecurityPostureFacts), so an empty list reads as "none" and a fact a
	// node did not compose reads as "not reported".
	Reported []string `json:"reported,omitempty" wire:"always"`
}

// SecurityDatabaseAge is one database and its age bucket.
type SecurityDatabaseAge struct {
	Kind   string `json:"kind" wire:"always"`
	Bucket string `json:"bucket" wire:"always"`
}

// SecurityPlatformGap is one driver short of supported on the node's
// platform.
type SecurityPlatformGap struct {
	Driver  string `json:"driver" wire:"always"`
	Support string `json:"support" wire:"always"`
}

// SecurityVerdictCount is one trust verdict and its count.
type SecurityVerdictCount struct {
	Verdict string `json:"verdict" wire:"always"`
	Count   int64  `json:"count" wire:"always"`
}

// SecurityGateOutcome is one commit-gate outcome and its event count.
type SecurityGateOutcome struct {
	Outcome string `json:"outcome" wire:"always"`
	Events  int64  `json:"events" wire:"always"`
}

// SecurityPostureCount is one (category, severity, status) bucket.
type SecurityPostureCount struct {
	Category string `json:"category" wire:"always"`
	Severity string `json:"severity" wire:"always"`
	Status   string `json:"status" wire:"always"`
	Count    int64  `json:"count" wire:"always"`
}

// SecurityDriverVersion is one driver and the version it last ran as.
type SecurityDriverVersion struct {
	Driver  string `json:"driver" wire:"always"`
	Version string `json:"version,omitempty" wire:"always"`
}

// SecurityOutcomeCount is one scan outcome and its run count.
type SecurityOutcomeCount struct {
	Outcome string `json:"outcome" wire:"always"`
	Runs    int64  `json:"runs" wire:"always"`
}

// SecurityGateCount is one commit-gate rule and decision with its count.
type SecurityGateCount struct {
	Rule     string `json:"rule" wire:"always"`
	Decision string `json:"decision" wire:"always"`
	Events   int64  `json:"events" wire:"always"`
}

// SecurityFloorKeyState is one floor key's state on the node.
type SecurityFloorKeyState struct {
	Key    string `json:"key" wire:"always"`
	State  string `json:"state" wire:"always"`
	Reason string `json:"reason,omitempty" wire:"always"`
}

// AIChangeRecordRow is the per-commit AI change record summary (security plan
// 5.9, 7.4 and 7.10). The row is defined now so the wire, the server table
// and the canaries exist; nothing produces it yet (phase F2 builds the
// producer). Never prompt text.
type AIChangeRecordRow struct {
	OrgID     string `json:"org_id,omitempty" wire:"always"`
	UserEmail string `json:"user_email,omitempty" wire:"always"`
	// CommitIdentityHash is the hash of the commit's identity; the key a
	// re-push updates.
	CommitIdentityHash string `json:"commit_identity_hash" wire:"always"`
	PatchFPHash        string `json:"patch_fp_hash,omitempty" wire:"always"`
	RecordDigest       string `json:"record_digest,omitempty" wire:"always"`
	KeyID              string `json:"key_id,omitempty" wire:"always"`
	AttestationLevel   string `json:"attestation_level,omitempty" wire:"always"`
	Files              int64  `json:"files,omitempty" wire:"always"`
	AILines            int64  `json:"ai_lines,omitempty" wire:"always"`
	HumanLines         int64  `json:"human_lines,omitempty" wire:"always"`
	UnknownLines       int64  `json:"unknown_lines,omitempty" wire:"always"`
	HumanCapture       string `json:"human_capture,omitempty" wire:"always"`
	// Sessions, models, tools and scanner pack versions the record names.
	Sessions     []string `json:"sessions,omitempty" wire:"always"`
	Models       []string `json:"models,omitempty" wire:"always"`
	Tools        []string `json:"tools,omitempty" wire:"always"`
	Scanners     []string `json:"scanners,omitempty" wire:"always"`
	PackVersions []string `json:"pack_versions,omitempty" wire:"always"`
	// FindingsOpen / FindingsBlocking summarize the findings in the change.
	FindingsOpen     int64    `json:"findings_open,omitempty" wire:"always"`
	FindingsBlocking int64    `json:"findings_blocking,omitempty" wire:"always"`
	ExceptionIDs     []string `json:"exception_ids,omitempty" wire:"always"`
	CommittedAt      string   `json:"committed_at,omitempty" wire:"always"`
	// Only under raw content: the commit sha and the file paths.
	CommitSHA string   `json:"commit_sha,omitempty" wire:"raw"`
	Paths     []string `json:"paths,omitempty" wire:"raw"`
	// Envelope is the record's signed DSSE envelope (one JSON line, at most
	// MaxChangeEnvelopeBytes; lane SEC-F2B), so the org can check the
	// signature and the binding before it countersigns. Only under raw
	// content, like the commit sha it binds; a server that predates it
	// ignores it, and without it the org countersigns the digest alone.
	Envelope string `json:"envelope,omitempty" wire:"raw"`
}

// SecurityWireRowTypes lists every top-level security wire row type, for the
// reflective tag test and the canary scan.
func SecurityWireRowTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(SecurityFindingRow{}),
		reflect.TypeOf(SecurityPostureRow{}),
		reflect.TypeOf(AIChangeRecordRow{}),
	}
}

// CheckSecurityWireTags reports the first field of t (or of a struct nested
// in it) that has no wire class, an unknown class, or is embedded. A nil
// error means every field is classified.
func CheckSecurityWireTags(t reflect.Type) error {
	return checkWireTags(t, t.Name())
}

func checkWireTags(t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		where := path + "." + f.Name
		if f.Anonymous {
			return fmt.Errorf("orgcontract: %s is an embedded struct; security wire rows name every field", where)
		}
		switch f.Tag.Get("wire") {
		case SecurityWireAlways:
			if err := checkWireTags(f.Type, where); err != nil {
				return err
			}
		case SecurityWireRaw:
		default:
			return fmt.Errorf("orgcontract: %s has no wire class (want wire:%q or wire:%q)", where, SecurityWireAlways, SecurityWireRaw)
		}
	}
	return nil
}

// StripSecurityRaw zeroes every wire:"raw" field of row (a pointer to a
// security wire row) unless raw is true, recursing into always-class nested
// structs. It refuses a row with an unclassified field.
func StripSecurityRaw(row any, raw bool) error {
	v := reflect.ValueOf(row)
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("orgcontract.StripSecurityRaw: want a non-nil pointer to a struct, got %T", row)
	}
	if err := CheckSecurityWireTags(v.Elem().Type()); err != nil {
		return err
	}
	stripValue(v.Elem(), raw)
	return nil
}

func stripValue(v reflect.Value, raw bool) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			stripValue(v.Elem(), raw)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			stripValue(v.Index(i), raw)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if f.Tag.Get("wire") == SecurityWireRaw {
				if !raw {
					v.Field(i).Set(reflect.Zero(f.Type))
				}
				continue
			}
			stripValue(v.Field(i), raw)
		}
	}
}

// The closed finding vocabularies, spelled here because orgcontract imports
// nothing of the node's policy layer; an external test pins each one to
// internal/policy.
var (
	SecurityFindingCategories = []string{
		"agent_config", "repo_trust", "secret", "malicious_package", "vulnerable_dependency",
		"hallucinated_package", "code_vuln", "iac", "ci_config", "security_regression",
		"test_tampering", "scope_drift", "git_bypass", "provenance",
	}
	SecurityFindingSeverities   = []string{"info", "low", "medium", "high", "critical"}
	SecurityFindingConfidences  = []string{"low", "medium", "high"}
	SecurityFindingScopes       = []string{"pre_write", "post_write", "staged", "diff", "commit", "push", "scheduled", "ci", "manual", "prelaunch"}
	SecurityFindingBaselines    = []string{"new", "pre_existing", "untrusted_baseline", "unknown"}
	SecurityFindingStatuses     = []string{"open", "not_reproduced", "fixed_verified", "suppressed", "accepted_risk", "false_positive"}
	SecurityFindingAttributions = []string{"ai", "human", "mixed", "unknown"}
	SecurityBaselineRefKinds    = []string{"commit", "ci_result"}
	SecurityScanOutcomes        = []string{"clean", "findings", "unknown", "not_scanned", "failed"}
	SecurityScanFreshness       = []string{"under_1h", "under_1d", "under_7d", "over_7d", "never"}
	SecurityOnlineCheckStates   = []string{"on", "off"}
	SecurityGateRules           = []string{"S-791", "S-792", "S-793", "S-794"}
	SecurityGateDecisions       = []string{"allow", "flag", "ask", "deny"}
	SecurityFloorStates         = []string{"applied", "not_applicable", "refused"}
	SecurityFloorReasons        = []string{"component_absent", "individual_node", "not_built", "module_inactive", "managed_node_uses_org_mirror"}
	SecurityAttestationLevels   = []string{"none", "local", "ci_verified", "countersigned"}
	SecurityHumanCaptures       = []string{"none", "partial", "full"}
	// The lane SEC-H2 posture facts' vocabularies.
	SecurityDatabaseKinds      = []string{"malicious_packages", "popular_names", "osv_export", "agent_cve_table"}
	SecurityDatabaseAgeBuckets = []string{"under_1d", "under_7d", "over_7d", "never"}
	SecurityPlatformSupports   = []string{"unsupported", "untested"}
	SecurityTrustVerdicts      = []string{"flagged", "untrusted"}
	SecurityGateOutcomes       = []string{"asked", "denied", "waited", "unknown"}
	// SecurityPostureFacts are the facts a posture row's Reported names.
	SecurityPostureFacts = []string{"database_ages", "platform_gaps", "trust_verdicts", "gate_outcomes"}
)

// Caps (plan 4.5 and 7.4): every string on the wire is bounded again here,
// on the node before it sends and on the server before it stores.
const (
	maxSecIDLen       = 128
	maxSecVersionLen  = 64
	maxSecPathLen     = 512
	maxSecEvidence    = 240
	maxSecListLen     = 16
	maxSecRowsPerPush = 2000
)

var (
	// secIDShape is a rule id, driver, pack, method, tool or model name: a
	// short token of letters, digits and the punctuation ids use.
	secIDShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`)
	// secHexShape is a hex digest or a finding handle.
	secHexShape = regexp.MustCompile(`^(sha256:)?[0-9a-f]{8,128}$`)
	// secOpaqueShape is a lineage id (session, action, exception, verdict).
	secOpaqueShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	// secRefShape is a CWE, OWASP or ATLAS reference id.
	secRefShape = regexp.MustCompile(`^[A-Z][A-Za-z0-9.:-]{0,31}$`)
	// secFloorKeyShape is a floor body key ("require.commit_gate",
	// "sections.deps", "require.components:security.deps").
	secFloorKeyShape = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,95}$`)
	// secDayShape is a UTC date.
	secDayShape = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// MaxSecurityRowsPerPush bounds each security slice of one envelope.
const MaxSecurityRowsPerPush = maxSecRowsPerPush

func secClosed(v string, vocab []string) string {
	if slices.Contains(vocab, v) {
		return v
	}
	return ""
}

func secShaped(v string, re *regexp.Regexp, max int) string {
	if v == "" || len(v) > max || !re.MatchString(v) {
		return ""
	}
	return v
}

func secTimestamp(v string) string {
	if v == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func secList(in []string, re *regexp.Regexp, max int) []string {
	var out []string
	for _, s := range in {
		if len(out) == maxSecListLen {
			break
		}
		if s = secShaped(s, re, max); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// SecurityRelPathOK reports whether p is a project-relative path the wire
// may carry: valid UTF-8, at most maxSecPathLen bytes, forward slashes only,
// no leading slash, drive letter, ".." segment, backslash, control character
// (C0, DEL or C1) or invisible format character (the bidi embeddings,
// overrides and isolates, zero-width characters, the byte order mark: the
// Unicode Cf class), so a path cannot render differently from what it is.
func SecurityRelPathOK(p string) bool {
	if p == "" || len(p) > maxSecPathLen || !utf8.ValidString(p) {
		return false
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || (len(p) > 1 && p[1] == ':') {
		return false
	}
	for _, r := range p {
		if secInvisible(r) {
			return false
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "" {
			return false
		}
	}
	return true
}

func secPath(p string) string {
	if SecurityRelPathOK(p) {
		return p
	}
	return ""
}

// secInvisible reports a control character (C0, DEL, C1) or an invisible
// format character (Unicode Cf: bidi controls, zero-width characters, the
// byte order mark), which the wire never carries in a path or an excerpt.
func secInvisible(r rune) bool {
	return unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r)
}

// secEvidence bounds a redacted evidence window: valid UTF-8, at most
// maxSecEvidence runes, a control character other than the tab turned into a
// space and every invisible format character removed (lane SEC-E2 audit
// finding 10), on the node before it sends and on the server before it
// stores.
func secEvidence(s string) string {
	if !utf8.ValidString(s) {
		return ""
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxSecEvidence {
			break
		}
		switch {
		case r == '\t':
		case unicode.Is(unicode.Cf, r):
			continue
		case unicode.Is(unicode.Cc, r):
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

func secCount(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

// NormalizeSecurityFinding bounds every field of r to its shape or closed
// vocabulary. ok=false drops the row: it has no finding handle, no rule id,
// or a category, severity or status outside the vocabulary. Called by the
// node before it sends and by the server before it stores (the
// managed_integrity.go precedent); the server additionally re-scrubs the
// evidence (internal/orgserver/secorg).
func NormalizeSecurityFinding(r SecurityFindingRow) (SecurityFindingRow, bool) {
	out := SecurityFindingRow{
		OrgID: r.OrgID, UserEmail: r.UserEmail,
		FindingRef:            secShaped(r.FindingRef, secHexShape, maxSecIDLen),
		OrgKey:                secShaped(r.OrgKey, secHexShape, maxSecIDLen),
		RuleID:                secShaped(r.RuleID, secIDShape, maxSecIDLen),
		RuleVersion:           secShaped(r.RuleVersion, secIDShape, maxSecVersionLen),
		RulePack:              secShaped(r.RulePack, secIDShape, maxSecIDLen),
		RulePackVersion:       secShaped(r.RulePackVersion, secIDShape, maxSecVersionLen),
		Driver:                secShaped(r.Driver, secIDShape, maxSecIDLen),
		DriverVersion:         secShaped(r.DriverVersion, secIDShape, maxSecVersionLen),
		EngineDigest:          secShaped(r.EngineDigest, secHexShape, maxSecIDLen),
		DatabaseEpoch:         secShaped(r.DatabaseEpoch, secIDShape, maxSecVersionLen),
		Category:              secClosed(r.Category, SecurityFindingCategories),
		Severity:              secClosed(r.Severity, SecurityFindingSeverities),
		Confidence:            secClosed(r.Confidence, SecurityFindingConfidences),
		CWE:                   secList(r.CWE, secRefShape, 32),
		OWASP:                 secList(r.OWASP, secRefShape, 32),
		ATLAS:                 secList(r.ATLAS, secRefShape, 32),
		Scope:                 secClosed(r.Scope, SecurityFindingScopes),
		ProjectIdentityHash:   secShaped(r.ProjectIdentityHash, secHexShape, maxSecIDLen),
		OrgProjectID:          secShaped(r.OrgProjectID, secOpaqueShape, maxSecIDLen),
		EvidenceHash:          secShaped(r.EvidenceHash, secHexShape, maxSecIDLen),
		Baseline:              secClosed(r.Baseline, SecurityFindingBaselines),
		BaselineRefKind:       secClosed(r.BaselineRefKind, SecurityBaselineRefKinds),
		BaselinePackVersion:   secShaped(r.BaselinePackVersion, secIDShape, maxSecVersionLen),
		BaselinePolicyVersion: secShaped(r.BaselinePolicyVersion, secIDShape, maxSecVersionLen),
		BaselineRef:           secShaped(r.BaselineRef, secOpaqueShape, maxSecIDLen),
		Attribution:           secClosed(r.Attribution, SecurityFindingAttributions),
		AttributionMethod:     secShaped(r.AttributionMethod, secIDShape, maxSecIDLen),
		AttributionConfidence: secClosed(r.AttributionConfidence, SecurityFindingConfidences),
		SessionID:             secShaped(r.SessionID, secOpaqueShape, maxSecIDLen),
		ActionID:              secShaped(r.ActionID, secOpaqueShape, maxSecIDLen),
		PromptActionID:        secShaped(r.PromptActionID, secOpaqueShape, maxSecIDLen),
		Tool:                  secShaped(r.Tool, secIDShape, maxSecIDLen),
		ToolVersion:           secShaped(r.ToolVersion, secIDShape, maxSecVersionLen),
		Model:                 secShaped(r.Model, secIDShape, maxSecIDLen),
		Surface:               secShaped(r.Surface, secIDShape, maxSecIDLen),
		Tainted:               r.Tainted,
		TaintOriginClass:      secShaped(r.TaintOriginClass, secIDShape, 64),
		Status:                secClosed(r.Status, SecurityFindingStatuses),
		FirstSeen:             secTimestamp(r.FirstSeen),
		LastSeen:              secTimestamp(r.LastSeen),
		ClosedAt:              secTimestamp(r.ClosedAt),

		FixRuleNoLongerFires:    r.FixRuleNoLongerFires,
		FixNoNewFindingInRegion: r.FixNoNewFindingInRegion,
		FixTestCommandObserved:  r.FixTestCommandObserved,
		FixTestExitCode:         max(min(r.FixTestExitCode, 255), -1),
		FixTestFilesEdited:      r.FixTestFilesEdited,
		ExceptionID:             secShaped(r.ExceptionID, secOpaqueShape, maxSecIDLen),
		VerdictIDs:              secList(r.VerdictIDs, secOpaqueShape, maxSecIDLen),
		Landed:                  r.Landed,

		RelPath:          secPath(r.RelPath),
		StartLine:        max(r.StartLine, 0),
		EndLine:          max(r.EndLine, 0),
		EvidenceRedacted: secEvidence(r.EvidenceRedacted),
		CommitSHA:        secShaped(r.CommitSHA, secHexShape, 64),
		PatchFP:          secShaped(r.PatchFP, secHexShape, maxSecIDLen),
	}
	for _, a := range r.PathAliases {
		if len(out.PathAliases) == 8 {
			break
		}
		if a = secPath(a); a != "" && !slices.Contains(out.PathAliases, a) {
			out.PathAliases = append(out.PathAliases, a)
		}
	}
	if out.FindingRef == "" || out.RuleID == "" || out.Category == "" || out.Severity == "" || out.Status == "" || out.LastSeen == "" {
		return out, false
	}
	if out.FirstSeen == "" {
		out.FirstSeen = out.LastSeen
	}
	return out, true
}

// NormalizeSecurityPosture bounds a posture row. ok=false drops it (no day,
// or a share level outside the vocabulary).
func NormalizeSecurityPosture(r SecurityPostureRow) (SecurityPostureRow, bool) {
	out := SecurityPostureRow{
		OrgID: r.OrgID, UserEmail: r.UserEmail,
		Day:           r.Day,
		ShareLevel:    secClosed(r.ShareLevel, []string{SecuritySharePosture, SecurityShareFindings}),
		Projects:      secCount(r.Projects),
		ScanFreshness: secClosed(r.ScanFreshness, SecurityScanFreshness),
		OnlineChecks:  secClosed(r.OnlineChecks, SecurityOnlineCheckStates),
	}
	if !secDayShape.MatchString(out.Day) {
		return out, false
	}
	if _, err := time.Parse("2006-01-02", out.Day); err != nil || out.ShareLevel == "" {
		return out, false
	}
	for _, c := range r.Findings {
		if len(out.Findings) == 512 {
			break
		}
		c = SecurityPostureCount{
			Category: secClosed(c.Category, SecurityFindingCategories), Severity: secClosed(c.Severity, SecurityFindingSeverities),
			Status: secClosed(c.Status, SecurityFindingStatuses), Count: secCount(c.Count),
		}
		if c.Category != "" && c.Severity != "" && c.Status != "" {
			out.Findings = append(out.Findings, c)
		}
	}
	out.Detectors = secList(r.Detectors, secIDShape, 64)
	for _, d := range r.Drivers {
		if len(out.Drivers) == maxSecListLen {
			break
		}
		d = SecurityDriverVersion{Driver: secShaped(d.Driver, secIDShape, 64), Version: secShaped(d.Version, secIDShape, maxSecVersionLen)}
		if d.Driver != "" {
			out.Drivers = append(out.Drivers, d)
		}
	}
	for _, o := range r.ScanOutcomes {
		if o.Outcome = secClosed(o.Outcome, SecurityScanOutcomes); o.Outcome != "" && len(out.ScanOutcomes) < len(SecurityScanOutcomes) {
			out.ScanOutcomes = append(out.ScanOutcomes, SecurityOutcomeCount{Outcome: o.Outcome, Runs: secCount(o.Runs)})
		}
	}
	for _, g := range r.CommitGate {
		g = SecurityGateCount{Rule: secClosed(g.Rule, SecurityGateRules), Decision: secClosed(g.Decision, SecurityGateDecisions), Events: secCount(g.Events)}
		if g.Rule != "" && g.Decision != "" && len(out.CommitGate) < 16 {
			out.CommitGate = append(out.CommitGate, g)
		}
	}
	for _, k := range r.FloorKeys {
		if len(out.FloorKeys) == 64 {
			break
		}
		k = SecurityFloorKeyState{Key: secShaped(k.Key, secFloorKeyShape, 96), State: secClosed(k.State, SecurityFloorStates), Reason: secClosed(k.Reason, SecurityFloorReasons)}
		if k.Key != "" && k.State != "" {
			out.FloorKeys = append(out.FloorKeys, k)
		}
	}
	normalizePostureFacts(r, &out)
	return out, true
}

// normalizePostureFacts bounds the lane SEC-H2 facts: closed vocabularies,
// one entry per key, and Reported limited to the four fact names.
func normalizePostureFacts(r SecurityPostureRow, out *SecurityPostureRow) {
	seen := map[string]bool{}
	for _, d := range r.DatabaseAges {
		d = SecurityDatabaseAge{Kind: secClosed(d.Kind, SecurityDatabaseKinds), Bucket: secClosed(d.Bucket, SecurityDatabaseAgeBuckets)}
		if d.Kind != "" && d.Bucket != "" && !seen["db:"+d.Kind] {
			seen["db:"+d.Kind] = true
			out.DatabaseAges = append(out.DatabaseAges, d)
		}
	}
	for _, g := range r.PlatformGaps {
		g = SecurityPlatformGap{Driver: secShaped(g.Driver, secIDShape, 64), Support: secClosed(g.Support, SecurityPlatformSupports)}
		if g.Driver != "" && g.Support != "" && !seen["gap:"+g.Driver] && len(out.PlatformGaps) < maxSecListLen {
			seen["gap:"+g.Driver] = true
			out.PlatformGaps = append(out.PlatformGaps, g)
		}
	}
	for _, v := range r.TrustVerdicts {
		v = SecurityVerdictCount{Verdict: secClosed(v.Verdict, SecurityTrustVerdicts), Count: secCount(v.Count)}
		if v.Verdict != "" && !seen["trust:"+v.Verdict] {
			seen["trust:"+v.Verdict] = true
			out.TrustVerdicts = append(out.TrustVerdicts, v)
		}
	}
	for _, g := range r.GateOutcomes {
		g = SecurityGateOutcome{Outcome: secClosed(g.Outcome, SecurityGateOutcomes), Events: secCount(g.Events)}
		if g.Outcome != "" && !seen["gate:"+g.Outcome] {
			seen["gate:"+g.Outcome] = true
			out.GateOutcomes = append(out.GateOutcomes, g)
		}
	}
	for _, f := range r.Reported {
		if f = secClosed(f, SecurityPostureFacts); f != "" && !seen["rep:"+f] {
			seen["rep:"+f] = true
			out.Reported = append(out.Reported, f)
		}
	}
}

// NormalizeAIChangeRecord bounds a change record row. ok=false drops it (no
// commit identity hash).
func NormalizeAIChangeRecord(r AIChangeRecordRow) (AIChangeRecordRow, bool) {
	out := AIChangeRecordRow{
		OrgID: r.OrgID, UserEmail: r.UserEmail,
		CommitIdentityHash: secShaped(r.CommitIdentityHash, secHexShape, maxSecIDLen),
		PatchFPHash:        secShaped(r.PatchFPHash, secHexShape, maxSecIDLen),
		RecordDigest:       secShaped(r.RecordDigest, secHexShape, maxSecIDLen),
		KeyID:              secShaped(r.KeyID, secOpaqueShape, maxSecIDLen),
		AttestationLevel:   secClosed(r.AttestationLevel, SecurityAttestationLevels),
		Files:              secCount(r.Files),
		AILines:            secCount(r.AILines),
		HumanLines:         secCount(r.HumanLines),
		UnknownLines:       secCount(r.UnknownLines),
		HumanCapture:       secClosed(r.HumanCapture, SecurityHumanCaptures),
		Sessions:           secList(r.Sessions, secOpaqueShape, maxSecIDLen),
		Models:             secList(r.Models, secIDShape, maxSecIDLen),
		Tools:              secList(r.Tools, secIDShape, maxSecIDLen),
		Scanners:           secList(r.Scanners, secIDShape, maxSecIDLen),
		PackVersions:       secList(r.PackVersions, secIDShape, maxSecVersionLen),
		FindingsOpen:       secCount(r.FindingsOpen),
		FindingsBlocking:   secCount(r.FindingsBlocking),
		ExceptionIDs:       secList(r.ExceptionIDs, secOpaqueShape, maxSecIDLen),
		CommittedAt:        secTimestamp(r.CommittedAt),
		CommitSHA:          secShaped(r.CommitSHA, secHexShape, 64),
		Envelope:           NormalizeChangeEnvelope(r.Envelope),
	}
	for _, p := range r.Paths {
		if len(out.Paths) == 256 {
			break
		}
		if p = secPath(p); p != "" && !slices.Contains(out.Paths, p) {
			out.Paths = append(out.Paths, p)
		}
	}
	return out, out.CommitIdentityHash != ""
}
