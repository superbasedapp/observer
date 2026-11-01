package secfinding

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Clip returns s without control characters, cut to at most max bytes on
// a rune boundary. Every string a finding keeps goes through it (section
// 4.5.3: a hostile engine can carry huge strings and control characters).
func Clip(s string, max int) string {
	if max <= 0 {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || (unicode.IsControl(r) && r != ' ') {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// clipRunes cuts s to at most n characters.
func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// Normalize returns f with every string capped and cleaned, the path
// aliases bounded, and every vocabulary field outside its closed set
// replaced by its honest unknown value (or the weakest, for severity and
// confidence). It is the last step of every semantic adapter.
func Normalize(f Finding) Finding {
	f.Location.RelPath = Clip(f.Location.RelPath, MaxPath)
	if len(f.Location.PathAliases) > MaxPathAliases {
		f.Location.PathAliases = f.Location.PathAliases[:MaxPathAliases]
	}
	for i, a := range f.Location.PathAliases {
		f.Location.PathAliases[i] = Clip(a, MaxPath)
	}
	if f.Location.StartLine < 0 {
		f.Location.StartLine = 0
	}
	if f.Location.EndLine < f.Location.StartLine {
		f.Location.EndLine = f.Location.StartLine
	}
	f.Rule.ID = Clip(f.Rule.ID, MaxRuleID)
	f.EvidenceRedacted = clipRunes(Clip(f.EvidenceRedacted, 4*MaxEvidence), MaxEvidence)
	if f.EvidenceRedacted != "" && f.EvidenceHash == "" {
		f.EvidenceHash = EvidenceHash(f.EvidenceRedacted)
	}
	f.Message = Clip(f.Message, MaxMessage)
	f.FixHint = Clip(f.FixHint, MaxMessage)
	if !slices.Contains(policy.FindingCategories(), f.Category) {
		f.Category = ""
	}
	if !slices.Contains(policy.FindingSeverities(), f.Severity) {
		f.Severity = policy.FindingSeverityInfo
	}
	if !slices.Contains(policy.FindingConfidences(), f.Confidence) {
		f.Confidence = policy.FindingConfidenceLow
	}
	if !slices.Contains(policy.FindingBaselines(), f.Baseline) {
		f.Baseline = policy.FindingBaselineUnknown
	}
	if !slices.Contains(policy.FindingStatuses(), f.Status) {
		f.Status = policy.FindingStatusOpen
	}
	if !slices.Contains(policy.FindingAttributions(), f.Attribution.Class) {
		f.Attribution.Class = policy.FindingAttributionUnknown
	}
	return f
}

// NeverPreExisting reports the categories that are never pre_existing
// (section 4.5.2 item 4): a secret is a live credential and a malicious
// package is malware whatever their age.
func NeverPreExisting(c Category) bool {
	return c == policy.FindingSecret || c == policy.FindingMaliciousPackage
}
