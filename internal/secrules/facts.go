package secrules

import (
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
)

// PreWriteSecurity is the in-hook pre-write scan the hook context seam runs
// for a write event (security plan section 4.7 item 3.1): the added text
// of the event's proposed edits (policy.Event.Edits, filled from the
// write_content_pre payload) under the fixed in-hook limits, as the hits
// and the scan_incomplete flag the seam stamps into Event.Security. An
// event without edits yields nothing. The cap is applied before an edit is
// copied: at most secdetect.HookMaxBytes of edit text is ever copied, so a
// multi-megabyte edit costs no more than a small one (the scanner applies
// the same cap and reports what it did not read as scan_incomplete).
func PreWriteSecurity(ev *policy.Event) (hits []policy.SecurityHit, incomplete bool) {
	if ev == nil || len(ev.Edits) == 0 {
		return nil, false
	}
	var b strings.Builder
	truncated := false
	for _, e := range ev.Edits {
		if e.New == "" {
			continue
		}
		room := secdetect.HookMaxBytes + 1 - b.Len()
		if room <= 0 {
			truncated = true
			break
		}
		text := e.New
		if len(text) > room {
			text, truncated = text[:room], true
		}
		b.WriteString(text)
		if !strings.HasSuffix(text, "\n") {
			b.WriteByte('\n')
		}
	}
	rel := relTarget(ev)
	r := secdetect.ScanHook(b.String(), rel)
	for _, h := range r.Hits {
		hits = append(hits, securityHit(h, rel))
	}
	return hits, truncated || r.Status == secdetect.StatusIncomplete
}

// securityHit maps a detector hit onto the contract's hit.
func securityHit(h secdetect.Hit, rel string) policy.SecurityHit {
	conf, sev := policy.FindingConfidenceLow, policy.FindingSeverityMedium
	if h.Blocking() {
		conf, sev = policy.FindingConfidenceHigh, policy.FindingSeverityHigh
	}
	if len(rel) > policy.SecurityHitPathMax {
		rel = rel[:policy.SecurityHitPathMax]
	}
	return policy.SecurityHit{
		Category: policy.FindingSecret, Severity: sev, Confidence: conf, Baseline: policy.FindingBaselineNew,
		RuleID: secretRulePrefix + h.Type, Path: rel, Line: h.Line,
	}
}

// secretRulePrefix prefixes a detector type into a finding rule id
// ("secret.aws_access_key"); finding rule ids are never guard ids.
const secretRulePrefix = "secret."

// relTarget is the write's path relative to the project root when it is
// under it (slash-separated), else the target as given.
func relTarget(ev *policy.Event) string {
	t := ev.Target
	if ev.ProjectRoot != "" && filepath.IsAbs(t) {
		if r, err := filepath.Rel(ev.ProjectRoot, t); err == nil && !strings.HasPrefix(r, "..") {
			t = r
		}
	}
	return filepath.ToSlash(t)
}
