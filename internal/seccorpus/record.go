package seccorpus

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// Finding is one candidate finding of the corpus run: where a rule fired.
// It carries no source text.
type Finding struct {
	// Repo is the repository URL (https).
	Repo string `json:"repo"`
	// Commit is the full commit id the repository was scanned at.
	Commit string `json:"commit"`
	// Path is repository-relative, with forward slashes.
	Path string `json:"path"`
	// Line is the 1-based line the rule reported.
	Line int `json:"line"`
	// Rule is the observer-code rule id.
	Rule string `json:"rule"`
}

// Key identifies a finding across files.
func (f Finding) Key() string {
	return fmt.Sprintf("%s@%s:%s:%d:%s", f.Repo, f.Commit, f.Path, f.Line, f.Rule)
}

// Validate checks that a finding is plain data: an https URL, a hex commit,
// a clean relative path, a positive line and a rule id.
func (f Finding) Validate() error {
	switch {
	case !strings.HasPrefix(f.Repo, "https://") || strings.ContainsAny(f.Repo, " \t\r\n\"") || len(f.Repo) > 200:
		return fmt.Errorf("repo %q is not an https URL", f.Repo)
	case !hexCommit(f.Commit):
		return fmt.Errorf("commit %q is not a 40 or 64 digit hex id", f.Commit)
	case f.Path == "" || len(f.Path) > 400 || strings.ContainsAny(f.Path, "\\\t\r\n") ||
		path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path || f.Path == ".." || strings.HasPrefix(f.Path, "../"):
		return fmt.Errorf("path %q is not a clean relative path", f.Path)
	case f.Line < 1:
		return fmt.Errorf("line %d", f.Line)
	case !ruleID(f.Rule):
		return fmt.Errorf("rule %q", f.Rule)
	}
	return nil
}

func hexCommit(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func ruleID(s string) bool {
	if s == "" || len(s) > 96 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// Verdict is one reviewer's label of one finding.
type Verdict string

// The Verdict values.
const (
	TruePositive  Verdict = "true_positive"
	FalsePositive Verdict = "false_positive"
)

// Reason is a fixed reason code beside a verdict (no free text, so a label
// file never carries source text).
type Reason string

// Reasons maps each reason code to the verdict it belongs to: the table a
// reviewer picks from.
var Reasons = map[Reason]Verdict{
	"input_reaches_sink":       TruePositive,
	"unsafe_by_construction":   TruePositive,
	"unsafe_setting":           TruePositive,
	"constant_or_internal":     FalsePositive,
	"sanitized_or_allowlisted": FalsePositive,
	"not_the_weakness":         FalsePositive,
	"wrong_match":              FalsePositive,
	"deliberate_test_or_demo":  FalsePositive,
}

// Reviewer ids. The two reviewers never see each other's labels.
const (
	ReviewerA = "a"
	ReviewerB = "b"
)

// LabelRecord is one reviewer's label of one finding.
type LabelRecord struct {
	Finding
	Reviewer string  `json:"reviewer"`
	Verdict  Verdict `json:"verdict"`
	Reason   Reason  `json:"reason"`
}

// Validate checks a label record.
func (l LabelRecord) Validate() error {
	if err := l.Finding.Validate(); err != nil {
		return err
	}
	if l.Reviewer != ReviewerA && l.Reviewer != ReviewerB {
		return fmt.Errorf("reviewer %q (want a or b)", l.Reviewer)
	}
	want, ok := Reasons[l.Reason]
	switch {
	case l.Verdict != TruePositive && l.Verdict != FalsePositive:
		return fmt.Errorf("verdict %q", l.Verdict)
	case !ok:
		return fmt.Errorf("reason %q is not in the table", l.Reason)
	case want != l.Verdict:
		return fmt.Errorf("reason %q belongs to %s, not %s", l.Reason, want, l.Verdict)
	}
	return nil
}

// ErrIncomplete is returned when a candidate finding lacks a label.
var ErrIncomplete = errors.New("seccorpus: a candidate finding has no label")
