package secfeedback

import (
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
)

// Line limits (security pillar plan section 6.1, the access-grants
// convention).
const (
	// MaxLineBytes caps one feedback line.
	MaxLineBytes = 200
	// MaxLines caps the lines one reply carries.
	MaxLines = 3
	// MaxRuleIDBytes caps the rendered rule id.
	MaxRuleIDBytes = 48
	// minHintBytes is the shortest cut fix hint worth keeping.
	minHintBytes = 24
	// minLocationBytes is the shortest cut location worth keeping.
	minLocationBytes = 12
)

// HumanLine is the one sentence addressed to the developer: an exception is
// the human's decision, never the agent's (R-165 covers an agent that tries).
const HumanLine = "Only the developer can grant an exception."

// Finding is the rule data one line is built from. It deliberately has no
// field for a message, a description, evidence or a snippet (T8).
type Finding struct {
	// RuleID is the finding's rule id ("secret.github_pat"); rendered
	// through a safe character set, and only when RuleNamed.
	RuleID string
	// RuleNamed is set by the caller only when RuleID was checked against
	// Observer's compiled rule tables or a verified pack (lane sec-polish,
	// audit finding F5). Otherwise the line names the finding by its
	// category alone: an engine's or a pack's own id could spell an
	// instruction such as IGNORE_PREVIOUS_INSTRUCTIONS.
	RuleNamed bool
	// Category is the finding category; it picks the "what" phrase and the
	// fix hint when the rule id names no detector type.
	Category policy.FindingCategory
	// Severity orders the lines.
	Severity policy.FindingSeverity
	// Confidence is rendered in words.
	Confidence policy.FindingConfidence
	// Path is project-relative; repository-controlled, so it is
	// sanitized, cut to 80 characters and written only as the quoted
	// value of the line's last field, after all of the template's own
	// text, so a path that spells words reads as data.
	Path string
	// Line is the 1-based line (0: unknown).
	Line int
}

// categoryWords is what a finding of each category is, in Observer's own
// words.
var categoryWords = map[policy.FindingCategory]string{
	policy.FindingAgentConfig:          "an agent configuration change",
	policy.FindingRepoTrust:            "an untrusted repository setting",
	policy.FindingSecret:               "a secret",
	policy.FindingMaliciousPackage:     "a known malicious package",
	policy.FindingVulnerableDependency: "a vulnerable dependency",
	policy.FindingHallucinatedPackage:  "a package that may not exist",
	policy.FindingCodeVuln:             "a code vulnerability",
	policy.FindingIaC:                  "an infrastructure configuration issue",
	policy.FindingCIConfig:             "a CI configuration issue",
	policy.FindingSecurityRegression:   "a security regression",
	policy.FindingTestTampering:        "a weakened test",
	policy.FindingScopeDrift:           "a change outside the task's scope",
	policy.FindingGitBypass:            "a git hook bypass",
	policy.FindingProvenance:           "a provenance gap",
}

// categoryHints is the fix hint of each category, in Observer's own words.
var categoryHints = map[policy.FindingCategory]string{
	policy.FindingAgentConfig:          "Review the change before the agent relies on it.",
	policy.FindingRepoTrust:            "Review the setting before you trust this repository.",
	policy.FindingSecret:               "Move the value to an environment variable, then rotate it.", //nolint:gosec // G101: advice wording, not a credential
	policy.FindingMaliciousPackage:     "Remove the package and check where it came from.",
	policy.FindingVulnerableDependency: "Upgrade to a fixed version.",
	policy.FindingHallucinatedPackage:  "Check the package name before you install it.",
	policy.FindingCodeVuln:             "Fix the pattern at this line.",
	policy.FindingIaC:                  "Fix the setting at this line.",
	policy.FindingCIConfig:             "Fix the workflow at this line.",
	policy.FindingSecurityRegression:   "Restore the check that was removed.",
	policy.FindingTestTampering:        "Restore the test instead of changing it to pass.",
	policy.FindingScopeDrift:           "Keep the change to the files the task needs.",
	policy.FindingGitBypass:            "Commit without skipping the hooks.",
	policy.FindingProvenance:           "Record where this change came from.",
}

// confidenceWords renders the confidence.
var confidenceWords = map[policy.FindingConfidence]string{
	policy.FindingConfidenceHigh:   "high confidence",
	policy.FindingConfidenceMedium: "medium confidence",
	policy.FindingConfidenceLow:    "low confidence",
}

// severityRank orders the lines: the most severe first.
var severityRank = map[policy.FindingSeverity]int{
	policy.FindingSeverityCritical: 5,
	policy.FindingSeverityHigh:     4,
	policy.FindingSeverityMedium:   3,
	policy.FindingSeverityLow:      2,
	policy.FindingSeverityInfo:     1,
}

// secretRulePrefix is the prefix of a secret finding's rule id; the rest is
// the detector type.
const secretRulePrefix = secdetect.SecretRulePrefix

// what returns the phrase for what f found: the detector type's own words
// for a named secret rule, else the category's.
func what(f Finding) string {
	if t, ok := strings.CutPrefix(f.RuleID, secretRulePrefix); ok && f.RuleNamed && f.Category == policy.FindingSecret {
		return secdetect.TypeWords(t)
	}
	if w := categoryWords[f.Category]; w != "" {
		return w
	}
	return "a security finding"
}

// LocationLabel opens the line's last field, the location: everything
// before it is the template's own text.
const LocationLabel = " File: "

// Line renders one feedback line from f: at most MaxLineBytes, printable
// ASCII only. All of the template's own text comes first: what was found,
// the confidence, the rule (named only when f.RuleNamed), the fix hint and
// the human sentence; the location is last, as the quoted value of
// LocationLabel. The fix hint is cut, or left out, first when the line
// would run over; then the location is cut from its start.
func Line(f Finding) string {
	var b strings.Builder
	b.WriteString("observer: found ")
	b.WriteString(what(f))
	if c := confidenceWords[f.Confidence]; c != "" {
		b.WriteString(" (" + c + ")")
	}
	if id := safeRuleID(f.RuleID); f.RuleNamed && id != "" {
		b.WriteString(" by rule " + id)
	}
	b.WriteString(".")
	head := b.String()
	tail := " " + HumanLine
	data := location(f, MaxLineBytes-len(head)-len(tail))
	room := MaxLineBytes - len(head) - len(tail) - len(data)
	if hint := categoryHints[f.Category]; hint != "" && room > minHintBytes {
		if len(hint)+1 <= room {
			head += " " + hint
		} else {
			head += " " + cutWords(hint, room-1)
		}
	}
	line := head + tail + data
	if len(line) > MaxLineBytes {
		line = head + tail
	}
	if len(line) > MaxLineBytes {
		line = line[:MaxLineBytes-3] + "..."
	}
	return line
}

// location renders f's location field in at most room bytes: the label,
// the sanitized path quoted (cut from its start when it does not fit) and
// the line number; "" when there is no path or no room for a useful one.
func location(f Finding, room int) string {
	loc := secdetect.SanitizeLocation(f.Path)
	if loc == "" {
		return ""
	}
	num := ""
	if f.Line > 0 {
		num = ":" + strconv.Itoa(f.Line)
	}
	fit := room - len(LocationLabel) - len(`""`) - len(num)
	if fit < minLocationBytes {
		return ""
	}
	if len(loc) > fit {
		loc = "..." + loc[len(loc)-(fit-3):]
	}
	return LocationLabel + strconv.Quote(loc) + num
}

// Lines renders at most MaxLines lines, the most severe first (then by rule
// id, path and line, so the order is stable), one per distinct finding.
func Lines(fs []Finding) []string {
	sorted := append([]Finding(nil), fs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	var out []string
	seen := map[string]bool{}
	for _, f := range sorted {
		if len(out) == MaxLines {
			break
		}
		l := Line(f)
		if seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

// safeRuleID keeps a rule id to [A-Za-z0-9._/-], at most MaxRuleIDBytes
// ("" when nothing is left). Only a named rule (Finding.RuleNamed) is ever
// rendered.
func safeRuleID(id string) string {
	var b strings.Builder
	for i := 0; i < len(id) && b.Len() < MaxRuleIDBytes; i++ {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '/' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// cutWords cuts s to at most n bytes at a word boundary, ending in "...".
func cutWords(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return ""
	}
	cut := s[:n-3]
	if i := strings.LastIndexByte(cut, ' '); i > 0 {
		cut = cut[:i]
	}
	return strings.TrimRight(cut, " ,.") + "..."
}
