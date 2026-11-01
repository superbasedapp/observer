package seccustom

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// MaxResults caps the findings one custom run keeps (the strictest
// default adapter, section 8.6).
const MaxResults = 1000

// maxLine bounds a reported line number.
const maxLine = 10_000_000

// rootBaseIDs are the uriBaseId values read as the project root. Any other
// base id is refused: the file's own originalUriBaseIds are never read
// (they could redirect a location anywhere).
var rootBaseIDs = []string{"%SRCROOT%", "SRCROOT", "PROJECTROOT"}

// AdaptInput is one run's strict adapter input.
type AdaptInput struct {
	Record          Record
	ProjectRoot     string
	ProjectRootHash string
	Scope           secfinding.Scope
	// BlockingAllowed reports, per rule id, whether a finding may count
	// toward blocking (OrgDecision.BlockingRule). nil means flag-only.
	BlockingAllowed func(ruleID string) bool
}

// Refusal is one result the adapter refused and why (a closed reason).
type Refusal struct {
	Index  int
	Reason string
}

// Adapted is the strict adapter's answer.
type Adapted struct {
	Findings  []secfinding.Finding
	Refused   []Refusal
	Truncated bool
	Files     int
}

// Adapt maps a decoded SARIF log onto findings under the strictest rules
// (sections 4.5.3 and 8.6, as amended by revision 2.4 [JSP-8, JSP-12]):
//
//   - severity and confidence only through the manifest's closed maps; a
//     value they do not name refuses the finding, never a guess;
//   - a location must be project-relative, or a file: URI with an empty or
//     localhost host whose path lies under the project root (Bandit's
//     file:/// for an absolute target, a Windows file:///C:/... too): that
//     absolute prefix is stripped so no local path is kept; a bare
//     absolute path, a remote URI, a foreign uriBaseId, a backslash, a
//     query or fragment, a ".." segment or a control character refuses it;
//   - region.snippet is never decoded (the decoder has no field for it),
//     and the engine's message never reaches the finding: the message is
//     templated from the driver name and the rule id (Bandit quotes the
//     password it found in its message);
//   - findings are flag-only: confidence is capped at medium and the
//     baseline left unknown, so none can block, unless BlockingAllowed
//     names the rule (an org-approved manifest run isolated on a managed
//     node, OrgDecision).
func Adapt(in AdaptInput, log *sarif.Log) Adapted {
	var out Adapted
	if log == nil {
		return out
	}
	m := in.Record.Manifest
	files := map[string]bool{}
	occur := map[string]int{}
	idx := 0
	for _, run := range log.Runs {
		out.Truncated = out.Truncated || run.Dropped > 0 || run.RulesDropped > 0
		rules := map[string]sarif.Rule{}
		for _, r := range run.Tool.Rules {
			rules[r.ID] = r
		}
		for _, res := range run.Results {
			if len(out.Findings) >= MaxResults {
				out.Truncated = true
				return out
			}
			f, why := adaptOne(in, m, res, run.Tool.Rules, rules, occur)
			if why != "" {
				out.Refused = append(out.Refused, Refusal{Index: idx, Reason: why})
			} else {
				out.Findings = append(out.Findings, f)
				files[f.Location.RelPath] = true
			}
			idx++
		}
	}
	out.Files = len(files)
	return out
}

func adaptOne(in AdaptInput, m Manifest, res sarif.Result, ruleList []sarif.Rule, rules map[string]sarif.Rule, occur map[string]int) (secfinding.Finding, string) {
	id := res.RuleID
	var rule sarif.Rule
	if id == "" && res.RuleIndex >= 0 && res.RuleIndex < len(ruleList) {
		rule = ruleList[res.RuleIndex]
		id = rule.ID
	} else {
		rule = rules[id]
	}
	if !ruleIDRE.MatchString(id) {
		return secfinding.Finding{}, "bad_rule_id"
	}
	if len(res.Locations) == 0 {
		return secfinding.Finding{}, "no_location"
	}
	l := res.Locations[0]
	rel, why := StrictLocation(l.URI, l.URIBaseID, in.ProjectRoot)
	if why != "" {
		return secfinding.Finding{}, why
	}
	sl, el := l.StartLine, l.EndLine
	if el == 0 {
		el = sl
	}
	if sl < 0 || sl > maxLine || el < sl || el > maxLine {
		return secfinding.Finding{}, "line_out_of_range"
	}
	sev, ok := severityOf(m.Severity, res, rule)
	if !ok {
		return secfinding.Finding{}, "unmapped_severity"
	}
	conf, ok := confidenceOf(m.Confidence, res)
	if !ok {
		return secfinding.Finding{}, "unmapped_confidence"
	}
	blocking := in.BlockingAllowed != nil && in.BlockingAllowed(id)
	baseline := policy.FindingBaselineUnknown
	if blocking {
		// No baseline comparison runs for a custom driver: an eligible
		// finding is untrusted_baseline, which only a managed floor counts.
		baseline = policy.FindingBaselineUntrusted
	} else if conf == policy.FindingConfidenceHigh {
		conf = policy.FindingConfidenceMedium
	}
	occKey := id + "\x00" + rel
	n := occur[occKey]
	occur[occKey] = n + 1
	f := secfinding.Finding{
		Rule:     secfinding.Rule{ID: id, Pack: in.Record.Driver()},
		Engine:   secfinding.Engine{Driver: in.Record.Driver(), DriverVersion: m.Version, EngineDigest: m.ExecutableSHA256},
		Category: secfinding.Category(m.Category), Severity: sev, Confidence: conf,
		Scope: in.Scope, Project: secfinding.Project{RootHash: in.ProjectRootHash},
		Location: secfinding.Location{RelPath: rel, StartLine: sl, EndLine: el},
		Message:  fmt.Sprintf("Reported by the custom scanner %s, rule %s", m.Name, id),
		Baseline: baseline, Status: policy.FindingStatusOpen,
	}
	f.LocalKey = secfinding.LocalKey(in.ProjectRootHash, id, identity(res, rel, n))
	return secfinding.Normalize(f), ""
}

// identity is the location-free identity: the result's partial
// fingerprints when it carries them, otherwise (honestly degraded) the
// relative path and the occurrence of the rule in that file, without the
// line, so a line move keeps the key.
func identity(res sarif.Result, rel string, n int) secfinding.MatchIdentity {
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
	return secfinding.TextIdentity(fmt.Sprintf("path:%s#%d", rel, n))
}

func severityOf(s SeverityMap, res sarif.Result, rule sarif.Rule) (secfinding.Severity, bool) {
	var raw string
	switch s.Source {
	case SeverityLevel:
		raw = res.Level
		if raw == "" {
			raw = "warning" // the SARIF default
		}
	case SeverityRuleLevel:
		raw = rule.DefaultLevel
		if raw == "" {
			raw = "warning"
		}
	case SeverityRuleTag:
		for _, t := range rule.Tags {
			if _, ok := s.Levels[t]; ok {
				raw = t
				break
			}
		}
	case SeverityResultProperty:
		raw = res.Properties[s.Property]
	}
	v, ok := s.Levels[raw]
	return v, ok && raw != ""
}

func confidenceOf(c ConfidenceMap, res sarif.Result) (secfinding.Confidence, bool) {
	if c.Source == ConfidenceFixed {
		return c.Fixed, c.Fixed != ""
	}
	raw := res.Properties[c.Property]
	v, ok := c.Levels[raw]
	return v, ok && raw != ""
}

// StrictLocation is the custom driver's location rule: it returns the
// project-relative path, or the closed reason it was refused.
func StrictLocation(uri, baseID, root string) (string, string) {
	switch {
	case uri == "":
		return "", "empty_uri"
	case len(uri) > 1024:
		return "", "uri_too_long"
	case strings.ContainsRune(uri, '\\'):
		return "", "backslash"
	case strings.ContainsAny(uri, "?#"):
		return "", "query_or_fragment"
	case hasControl(uri):
		return "", "control_character"
	}
	file := strings.HasPrefix(strings.ToLower(uri), "file:")
	if baseID != "" && (file || !slices.Contains(rootBaseIDs, baseID)) {
		return "", "foreign_base_id"
	}
	if !file {
		if i := strings.Index(uri, ":"); i > 0 && !strings.Contains(uri[:i], "/") {
			return "", "remote_uri"
		}
		if strings.HasPrefix(uri, "/") {
			return "", "absolute_without_scheme"
		}
	}
	rel, why := secscan.NormalizeLocation(uri, root)
	if why != secscan.LocOK {
		return "", string(why)
	}
	if hasControl(rel) {
		return "", "control_character"
	}
	return rel, ""
}
