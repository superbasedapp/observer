package export

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Period is the evidence-pack reporting window: half-open [Start, End).
type Period struct {
	// Label is the operator's --period argument, echoed for the record.
	Label string `json:"label"`
	// Start / End bound the window (UTC).
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ParsePeriod parses the `observer guard report --period` argument.
// Accepted forms, table-tested:
//
//   - a Go duration ("168h", "720h") — the window [now-d, now);
//   - "YYYY-MM" — that UTC calendar month;
//   - "YYYY-MM-DD" — that UTC calendar day.
//
// now is injected so the cmd layer owns the clock (purity contract).
func ParsePeriod(s string, now time.Time) (Period, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Period{}, fmt.Errorf("export.ParsePeriod: empty period (use a duration like 720h, a month like 2026-05, or a day like 2026-05-01)")
	}
	if t, err := time.Parse("2006-01", s); err == nil {
		return Period{Label: s, Start: t.UTC(), End: t.UTC().AddDate(0, 1, 0)}, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return Period{Label: s, Start: t.UTC(), End: t.UTC().AddDate(0, 0, 1)}, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return Period{}, fmt.Errorf("export.ParsePeriod: %q is not a duration, YYYY-MM month, or YYYY-MM-DD day", s)
	}
	if d <= 0 {
		return Period{}, fmt.Errorf("export.ParsePeriod: duration must be positive")
	}
	now = now.UTC()
	return Period{Label: s, Start: now.Add(-d), End: now}, nil
}

// PolicyStateEntry is one guard_policy_state load-log row in
// export-facing form (§14.4 policy-change log).
type PolicyStateEntry struct {
	Layer       string    `json:"layer"`
	Path        string    `json:"path"`
	Version     string    `json:"version,omitempty"`
	ContentHash string    `json:"content_hash"`
	Signature   string    `json:"signature,omitempty"`
	LoadedAt    time.Time `json:"loaded_at"`
}

// VerdictStats is the period's guard_events aggregate.
type VerdictStats struct {
	Total      int            `json:"total"`
	Enforced   int            `json:"enforced"`
	ByDecision map[string]int `json:"by_decision,omitempty"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
	ByCategory map[string]int `json:"by_category,omitempty"`
}

// ChainResult is the audit-chain verification outcome (§10.4) — the
// export-facing mirror of the store's walk report.
type ChainResult struct {
	Checked           int    `json:"checked"`
	OK                bool   `json:"ok"`
	FirstDivergenceID int64  `json:"first_divergence_id,omitempty"`
	Detail            string `json:"detail,omitempty"`
}

// CoverageRow is one adapter×channel row of the §6.5 conformance
// matrix in export-facing form.
type CoverageRow struct {
	Client       string `json:"client"`
	Channel      string `json:"channel"`
	PreExecution bool   `json:"pre_execution"`
	CanBlock     bool   `json:"can_block"`
	CanAsk       bool   `json:"can_ask"`
	Notes        string `json:"notes,omitempty"`
}

// ApprovalEntry is one active guard_approvals grant — the §14.4
// reviewable exception register.
type ApprovalEntry struct {
	ID              int64     `json:"id"`
	TS              time.Time `json:"ts"`
	RuleID          string    `json:"rule_id"`
	Scope           string    `json:"scope"`
	SessionID       string    `json:"session_id,omitempty"`
	ProjectRootHash string    `json:"project_root_hash,omitempty"`
	GrantedBy       string    `json:"granted_by,omitempty"`
	// ExpiresAt zero means the grant does not expire.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// ReportInput is everything BuildReport composes — read by the cmd
// layer from the existing store/guard accessors, never re-derived
// here.
type ReportInput struct {
	// GeneratedAt stamps the report (injected clock).
	GeneratedAt time.Time
	// Period is the reporting window.
	Period Period
	// GuardEnabled / Mode / ObserverVersion describe the install at
	// report time.
	GuardEnabled    bool
	Mode            string
	ObserverVersion string
	// PolicyLog is the FULL guard_policy_state load log in id order
	// (append-only, negligible volume — a row per policy change).
	// Effective-at and in-period views are computed from it.
	PolicyLog []PolicyStateEntry
	// Stats aggregates guard_events over the period.
	Stats VerdictStats
	// Chain is the full-chain verification result.
	Chain ChainResult
	// Coverage is the §6.5 conformance matrix.
	Coverage []CoverageRow
	// ActiveApprovals are the non-expired grants at report time.
	ActiveApprovals []ApprovalEntry
}

// Report is the assembled §14.4 evidence pack. The struct is the
// --json wire shape; RenderText is the human form.
type Report struct {
	GeneratedAt     time.Time `json:"generated_at"`
	Period          Period    `json:"period"`
	GuardEnabled    bool      `json:"guard_enabled"`
	Mode            string    `json:"mode"`
	ObserverVersion string    `json:"observer_version,omitempty"`
	// PolicyAtStart / PolicyAtEnd are the effective policy sources as
	// of the period boundaries: the latest load per (layer, path) at
	// or before each instant. The load log records LOADS — a policy
	// file removed mid-period stays listed until a later load
	// supersedes its (layer, path) (documented approximation).
	PolicyAtStart []PolicyStateEntry `json:"policy_at_start"`
	PolicyAtEnd   []PolicyStateEntry `json:"policy_at_end"`
	// PolicyChanges are the loads recorded inside the period — the
	// who/when/what change log (§14.4).
	PolicyChanges   []PolicyStateEntry `json:"policy_changes"`
	Stats           VerdictStats       `json:"verdict_stats"`
	Chain           ChainResult        `json:"audit_chain"`
	Coverage        []CoverageRow      `json:"coverage_matrix"`
	ActiveApprovals []ApprovalEntry    `json:"active_approvals"`
}

// BuildReport assembles the evidence pack from its inputs. Pure: the
// only computation here is the policy-log time slicing; everything
// else passes through.
func BuildReport(in ReportInput) Report {
	return Report{
		GeneratedAt:     in.GeneratedAt.UTC(),
		Period:          in.Period,
		GuardEnabled:    in.GuardEnabled,
		Mode:            in.Mode,
		ObserverVersion: in.ObserverVersion,
		PolicyAtStart:   policyEffectiveAt(in.PolicyLog, in.Period.Start),
		PolicyAtEnd:     policyEffectiveAt(in.PolicyLog, in.Period.End),
		PolicyChanges:   policyChangesWithin(in.PolicyLog, in.Period),
		Stats:           in.Stats,
		Chain:           in.Chain,
		Coverage:        in.Coverage,
		ActiveApprovals: in.ActiveApprovals,
	}
}

// policyEffectiveAt computes the latest load per (layer, path) at or
// before t. The log is walked in order, so a later row for the same
// (layer, path) supersedes an earlier one (id order == load order).
// Results sort by (layer, path) for deterministic rendering.
func policyEffectiveAt(log []PolicyStateEntry, t time.Time) []PolicyStateEntry {
	latest := map[string]PolicyStateEntry{}
	for _, e := range log {
		if e.LoadedAt.After(t) {
			continue
		}
		latest[e.Layer+"\x00"+e.Path] = e
	}
	out := make([]PolicyStateEntry, 0, len(latest))
	for _, e := range latest {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Layer != out[j].Layer {
			return out[i].Layer < out[j].Layer
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// policyChangesWithin selects the loads inside the half-open period,
// preserving log (load) order.
func policyChangesWithin(log []PolicyStateEntry, p Period) []PolicyStateEntry {
	var out []PolicyStateEntry
	for _, e := range log {
		if !e.LoadedAt.Before(p.Start) && e.LoadedAt.Before(p.End) {
			out = append(out, e)
		}
	}
	return out
}

// RenderText renders the human evidence pack. Sections mirror the
// §14.4 list: policy state, change log, verdict statistics, chain
// verification, coverage matrix, exception register.
func RenderText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Guard evidence pack - period %s (%s - %s)\n",
		r.Period.Label, stamp(r.Period.Start), stamp(r.Period.End))
	fmt.Fprintf(&b, "Generated %s · observer %s · guard %s mode %s\n",
		stamp(r.GeneratedAt), orDash(r.ObserverVersion), onOff(r.GuardEnabled), orDash(r.Mode))

	b.WriteString("\n== Effective policy at period start ==\n")
	writePolicyEntries(&b, r.PolicyAtStart)
	b.WriteString("\n== Effective policy at period end ==\n")
	writePolicyEntries(&b, r.PolicyAtEnd)

	b.WriteString("\n== Policy changes in period ==\n")
	if len(r.PolicyChanges) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, e := range r.PolicyChanges {
		fmt.Fprintf(&b, "  %s  %-7s %s", stamp(e.LoadedAt), e.Layer, e.Path)
		if e.Version != "" {
			fmt.Fprintf(&b, " (version %s)", e.Version)
		}
		fmt.Fprintf(&b, " sha256 %.12s…\n", e.ContentHash)
	}

	b.WriteString("\n== Verdict statistics ==\n")
	fmt.Fprintf(&b, "  total %d, enforced %d\n", r.Stats.Total, r.Stats.Enforced)
	for _, line := range []struct {
		label string
		m     map[string]int
	}{
		{"by decision", r.Stats.ByDecision},
		{"by severity", r.Stats.BySeverity},
		{"by category", r.Stats.ByCategory},
	} {
		if len(line.m) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %-12s %s\n", line.label+":", countsLine(line.m))
	}

	b.WriteString("\n== Audit-chain verification ==\n")
	if r.Chain.OK {
		fmt.Fprintf(&b, "  OK - %d row(s) verified (tamper-evident, not tamper-proof)\n", r.Chain.Checked)
	} else {
		fmt.Fprintf(&b, "  BROKEN at id %d (%d row(s) walked) — %s\n",
			r.Chain.FirstDivergenceID, r.Chain.Checked, r.Chain.Detail)
	}

	b.WriteString("\n== Coverage matrix (§6.5) ==\n")
	for _, c := range r.Coverage {
		caps := make([]string, 0, 3)
		if c.PreExecution {
			caps = append(caps, "pre-exec")
		}
		if c.CanBlock {
			caps = append(caps, "block")
		}
		if c.CanAsk {
			caps = append(caps, "ask")
		}
		capsStr := "observe-only"
		if len(caps) > 0 {
			capsStr = strings.Join(caps, "+")
		}
		fmt.Fprintf(&b, "  %-14s %-26s %s\n", c.Client, c.Channel, capsStr)
	}

	b.WriteString("\n== Exception register (active approvals) ==\n")
	if len(r.ActiveApprovals) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, a := range r.ActiveApprovals {
		expiry := "no expiry"
		if !a.ExpiresAt.IsZero() {
			expiry = "expires " + stamp(a.ExpiresAt)
		}
		fmt.Fprintf(&b, "  #%d %s scope=%s granted_by=%s %s (granted %s)\n",
			a.ID, a.RuleID, a.Scope, orDash(a.GrantedBy), expiry, stamp(a.TS))
	}
	return b.String()
}

// writePolicyEntries renders one effective-policy section.
func writePolicyEntries(b *strings.Builder, entries []PolicyStateEntry) {
	if len(entries) == 0 {
		b.WriteString("  (no policy sources recorded)\n")
		return
	}
	for _, e := range entries {
		fmt.Fprintf(b, "  %-7s %s", e.Layer, e.Path)
		if e.Version != "" {
			fmt.Fprintf(b, " (version %s)", e.Version)
		}
		fmt.Fprintf(b, " sha256 %.12s… loaded %s\n", e.ContentHash, stamp(e.LoadedAt))
	}
}

// stamp renders a UTC second-resolution timestamp for the text form.
func stamp(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05Z")
}

// orDash substitutes "-" for an empty value in the text form.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// onOff renders a bool as on/off.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// countsLine renders a count map as "k=v k=v" sorted by key.
func countsLine(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, m[k])
	}
	return strings.Join(parts, " ")
}
