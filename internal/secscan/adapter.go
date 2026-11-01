package secscan

import (
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
)

// SeveritySource names where an adapter reads a result's severity
// (revision 2.4 [JSP-12]: each template names its severity source
// explicitly).
type SeveritySource string

// The SeveritySource values.
const (
	// SeverityFromLevel reads the result's SARIF level, else its rule's
	// default level.
	SeverityFromLevel SeveritySource = "level"
	// SeverityFromRuleLevel reads only the rule's default level (Opengrep
	// puts severity on the rule, not the result [JSP-8]).
	SeverityFromRuleLevel SeveritySource = "rule_level"
	// SeverityFromSecuritySeverity reads the rule's numeric
	// security-severity property (GitHub's convention).
	SeverityFromSecuritySeverity SeveritySource = "security_severity"
	// SeverityFromResultProperty reads a named result property.
	SeverityFromResultProperty SeveritySource = "result_property"
	// SeverityFixed uses the row's fixed severity.
	SeverityFixed SeveritySource = "fixed"
)

// AdapterRow is one driver's semantic adapter as data (section 4.5.3):
// how the engine's levels and properties map onto the finding model. The
// pure function Adapt walks it.
type AdapterRow struct {
	Name string
	// Category is the category every result of the engine carries.
	Category secfinding.Category
	// SeverityFrom, SeverityProperty and LevelMap map the engine's levels
	// (lowercased) onto a severity; an unmapped level reads as Default.
	SeverityFrom     SeveritySource
	SeverityProperty string
	LevelMap         map[string]secfinding.Severity
	Default          secfinding.Severity
	// Confidence is the confidence the engine's results carry.
	Confidence secfinding.Confidence
	// Fingerprint is the result fingerprint key that is location-free
	// (Opengrep's matchBasedId/v1); "" when the engine has none.
	Fingerprint string
	// MaxResults caps the results kept per run; 0 means sarif.MaxResults.
	MaxResults int
}

// sarifLevels is the common SARIF level mapping.
var sarifLevels = map[string]secfinding.Severity{
	"error": policy.FindingSeverityHigh, "warning": policy.FindingSeverityMedium,
	"note": policy.FindingSeverityLow, "none": policy.FindingSeverityInfo,
}

// adapterTable is the semantic adapter table, one row per planned engine
// (section 4.4) plus the generic import and the strictest custom default.
var adapterTable = map[string]AdapterRow{
	"opengrep": {
		Name: "opengrep", Category: policy.FindingCodeVuln, SeverityFrom: SeverityFromRuleLevel,
		LevelMap: sarifLevels, Default: policy.FindingSeverityMedium, Confidence: policy.FindingConfidenceMedium,
		Fingerprint: "matchBasedId/v1",
	},
	"osv": {
		Name: "osv", Category: policy.FindingVulnerableDependency, SeverityFrom: SeverityFromSecuritySeverity,
		LevelMap: sarifLevels, Default: policy.FindingSeverityMedium, Confidence: policy.FindingConfidenceHigh,
	},
	"gitleaks": {
		Name: "gitleaks", Category: policy.FindingSecret, SeverityFrom: SeverityFixed,
		Default: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceMedium,
	},
	"trivy": {
		Name: "trivy", Category: policy.FindingVulnerableDependency, SeverityFrom: SeverityFromSecuritySeverity,
		LevelMap: sarifLevels, Default: policy.FindingSeverityMedium, Confidence: policy.FindingConfidenceHigh,
	},
	// trivy-config is `trivy config` (misconfiguration only, lane
	// GATES-SEC): every result is an iac finding, its severity from the
	// rule's security-severity, else the result level (seciac.SeverityTable).
	"trivy-config": {
		Name: "trivy-config", Category: policy.FindingIaC, SeverityFrom: SeverityFromSecuritySeverity,
		LevelMap: sarifLevels, Default: policy.FindingSeverityMedium, Confidence: policy.FindingConfidenceMedium,
	},
	"kics": {
		Name: "kics", Category: policy.FindingIaC, SeverityFrom: SeverityFromLevel,
		LevelMap: sarifLevels, Default: policy.FindingSeverityMedium, Confidence: policy.FindingConfidenceMedium,
	},
	"actionlint": {
		Name: "actionlint", Category: policy.FindingCIConfig, SeverityFrom: SeverityFixed,
		Default: policy.FindingSeverityLow, Confidence: policy.FindingConfidenceMedium,
	},
	// sarif-import takes the strictest default too (lane sec-g5, section
	// 4.5.3 "In"): the producing tool is the developer's, run outside
	// Observer, so its levels never map above medium and every result is
	// low confidence (flag only).
	"sarif-import": {
		Name: "sarif-import", Category: policy.FindingCodeVuln, SeverityFrom: SeverityFromLevel,
		LevelMap: map[string]secfinding.Severity{
			"error": policy.FindingSeverityMedium, "warning": policy.FindingSeverityLow,
			"note": policy.FindingSeverityInfo, "none": policy.FindingSeverityInfo,
		},
		Default: policy.FindingSeverityInfo, Confidence: policy.FindingConfidenceLow, MaxResults: 1000,
	},
	// custom is the strictest default (section 8.6): every result is low
	// confidence, capped hard, its levels mapped but never above medium.
	"custom": {
		Name: "custom", Category: policy.FindingCodeVuln, SeverityFrom: SeverityFromLevel,
		LevelMap: map[string]secfinding.Severity{
			"error": policy.FindingSeverityMedium, "warning": policy.FindingSeverityLow,
			"note": policy.FindingSeverityInfo, "none": policy.FindingSeverityInfo,
		},
		Default: policy.FindingSeverityInfo, Confidence: policy.FindingConfidenceLow, MaxResults: 1000,
	},
}

// Adapter returns the named semantic adapter row.
func Adapter(name string) (AdapterRow, bool) {
	r, ok := adapterTable[name]
	return r, ok
}

// AdapterNames returns every adapter name.
func AdapterNames() []string {
	out := make([]string, 0, len(adapterTable))
	for n := range adapterTable {
		out = append(out, n)
	}
	return out
}

// AdaptOptions are the per-run inputs of Adapt.
type AdaptOptions struct {
	ProjectRoot     string
	ProjectRootHash string
	Scope           secfinding.Scope
	Engine          EngineIdentity
	// RulePrefix is the stable rules directory, in the dotted form the
	// engine embeds in its rule ids (Opengrep [JSP-8]); it is stripped.
	RulePrefix string
	// SelfTestPassed: the driver's self-test passed for its current
	// digests and versions. Without it, zero results is unknown, never
	// clean (revision 2.4 [JSP-12]).
	SelfTestPassed bool
	// UnknownMarker: an unknown-marking stderr pattern appeared.
	UnknownMarker bool
}

// maxRuleIDBytes and the rule id charset (section 4.5.3: a rule-id
// charset and length limit).
const maxRuleIDBytes = 128

func validRuleID(id string) bool {
	if id == "" || len(id) > maxRuleIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == ':', c == '/':
		default:
			return false
		}
	}
	return true
}

// Adapt maps one decoded SARIF run onto findings through an adapter row.
// Engine messages and rule descriptions never reach the finding: its
// message is templated from the row, the rule id and the engine name
// (section 9 T8; SARIF messages are content-bearing, Bandit quotes the
// password it found). A result whose location or rule id is refused is
// dropped and counted in the coverage.
func Adapt(row AdapterRow, run sarif.Run, o AdaptOptions) ([]secfinding.Finding, Coverage) {
	limit := row.MaxResults
	if limit <= 0 || limit > sarif.MaxResults {
		limit = sarif.MaxResults
	}
	cov := Coverage{Truncated: run.Dropped > 0 || run.RulesDropped > 0}
	rules := map[string]sarif.Rule{}
	for _, r := range run.Tool.Rules {
		rules[r.ID] = r
	}
	var out []secfinding.Finding
	files := map[string]bool{}
	for _, res := range run.Results {
		if len(out) >= limit {
			cov.Truncated = true
			break
		}
		rawID := res.RuleID
		var rule sarif.Rule
		if rawID == "" && res.RuleIndex >= 0 && res.RuleIndex < len(run.Tool.Rules) {
			rule = run.Tool.Rules[res.RuleIndex]
			rawID = rule.ID
		} else {
			rule = rules[rawID]
		}
		id := rawID
		if o.RulePrefix != "" {
			id = strings.TrimPrefix(strings.TrimPrefix(id, o.RulePrefix), ".")
		}
		if !validRuleID(id) {
			cov.Skipped = append(cov.Skipped, Skip{Reason: "bad_rule_id"})
			continue
		}
		f := secfinding.Finding{
			Rule:     secfinding.Rule{ID: id},
			Engine:   secfinding.Engine{Driver: row.Name, DriverVersion: o.Engine.Version, EngineDigest: o.Engine.Digest, DatabaseEpoch: o.Engine.DatabaseEpoch},
			Category: row.Category, Severity: adaptSeverity(row, res, rule), Confidence: row.Confidence,
			Scope: o.Scope, Project: secfinding.Project{RootHash: o.ProjectRootHash},
			Message:  "Reported by " + row.Name + " rule " + id,
			Baseline: policy.FindingBaselineUnknown, Status: policy.FindingStatusOpen,
		}
		if len(res.Locations) > 0 {
			l := res.Locations[0]
			rel, why := NormalizeLocation(l.URI, o.ProjectRoot)
			if why != LocOK {
				cov.Skipped = append(cov.Skipped, Skip{Reason: string(why)})
				continue
			}
			f.Location = secfinding.Location{RelPath: rel, StartLine: l.StartLine, EndLine: l.EndLine}
			files[rel] = true
		}
		f.LocalKey = secfinding.LocalKey(o.ProjectRootHash, id, adaptIdentity(row, res, f.Location.RelPath))
		out = append(out, secfinding.Normalize(f))
	}
	cov.FilesScanned = len(files)
	switch {
	case len(out) > 0:
		cov.Outcome = OutcomeFindings
	case o.SelfTestPassed && !o.UnknownMarker && len(cov.Skipped) == 0 && !cov.Truncated:
		cov.Outcome = OutcomeClean
	default:
		cov.Outcome = OutcomeUnknown
		cov.Reason = "no_self_test"
		if o.UnknownMarker {
			cov.Reason = "unknown_marker"
		} else if len(cov.Skipped) > 0 || cov.Truncated {
			cov.Reason = "results_refused"
		}
	}
	return out, cov
}

// adaptIdentity is the location-free identity of a result: the engine's
// own location-free fingerprint when the row names one; otherwise the
// result's partial fingerprints; otherwise, honestly degraded, the
// relative path without the line (a line move keeps the key, a rename
// does not, because no matched text is decoded).
func adaptIdentity(row AdapterRow, res sarif.Result, rel string) secfinding.MatchIdentity {
	if row.Fingerprint != "" {
		if v := res.Fingerprints[row.Fingerprint]; v != "" {
			return secfinding.EngineIdentity(v)
		}
	}
	if len(res.PartialFingerprints) > 0 {
		keys := make([]string, 0, len(res.PartialFingerprints))
		for k := range res.PartialFingerprints {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			b.WriteString(k + "=" + res.PartialFingerprints[k] + ";")
		}
		return secfinding.EngineIdentity(b.String())
	}
	return secfinding.TextIdentity("path:" + rel)
}

func adaptSeverity(row AdapterRow, res sarif.Result, rule sarif.Rule) secfinding.Severity {
	level := ""
	switch row.SeverityFrom {
	case SeverityFixed:
		return row.Default
	case SeverityFromRuleLevel:
		level = rule.DefaultLevel
	case SeverityFromLevel:
		level = res.Level
		if level == "" {
			level = rule.DefaultLevel
		}
	case SeverityFromResultProperty:
		level = res.Properties[row.SeverityProperty]
	case SeverityFromSecuritySeverity:
		if s, ok := scoreSeverity(rule.SecuritySeverity); ok {
			return s
		}
		if s, ok := scoreSeverity(res.Properties["security-severity"]); ok {
			return s
		}
		level = res.Level
	}
	if s, ok := row.LevelMap[strings.ToLower(level)]; ok {
		return s
	}
	return row.Default
}

// scoreSeverity maps a CVSS-style score onto a severity (GitHub's bands).
func scoreSeverity(v string) (secfinding.Severity, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || f < 0 || f > 10 {
		return "", false
	}
	switch {
	case f >= 9:
		return policy.FindingSeverityCritical, true
	case f >= 7:
		return policy.FindingSeverityHigh, true
	case f >= 4:
		return policy.FindingSeverityMedium, true
	case f > 0:
		return policy.FindingSeverityLow, true
	}
	return policy.FindingSeverityInfo, true
}
