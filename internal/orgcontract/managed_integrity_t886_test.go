package orgcontract

import (
	"fmt"
	"testing"
	"time"
)

// TestRepeatActIsANewOccurrence pins T-886 (guard tamper re-test 2026-10-17
// residual 1): a node reports a hook repair for 24 hours, so before the act
// time travelled with the item, a second repair of the same hook inside that
// day hid inside the first and raised no integrity_change. The act time now
// identifies the occurrence; standing items and an unchanged act stay quiet.
func TestRepeatActIsANewOccurrence(t *testing.T) {
	t0 := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	repaired := func(at time.Time) CaptureRiskItem {
		it := CaptureRiskItem{Risk: CaptureRiskHookRepaired, Tool: "cline-cli", File: "~/.cline/plugins/guard.js", Events: []string{"PreToolUse"}}
		if !at.IsZero() {
			it.At = at.Format(time.RFC3339)
		}
		return it
	}
	changed := func(at string) CaptureRiskItem {
		return CaptureRiskItem{Risk: CaptureRiskHookConfigChanged, Tool: "claude-code", File: "~/.claude/settings.json", At: at}
	}
	mismatch := CaptureRiskItem{Risk: CaptureRiskHookBinaryMismatch, Tool: "codex", File: "~/.codex/hooks.json"}

	type report struct {
		at      time.Duration
		items   []CaptureRiskItem
		first   bool
		wantNew []string // OccurrenceKeys newly raised by this report
		// wantChanges is how many changes the window holds after the report
		// (-1: do not check).
		wantChanges int
	}
	scenarios := []struct {
		name    string
		reports []report
	}{
		{"a repeat repair inside the day re-raises", []report{
			{at: 0, items: []CaptureRiskItem{mismatch}, first: true, wantChanges: 0},
			{
				at: time.Hour, items: []CaptureRiskItem{mismatch, repaired(t0.Add(50 * time.Minute))},
				wantNew: []string{repaired(t0.Add(50 * time.Minute)).OccurrenceKey()}, wantChanges: 1,
			},
			{at: 2 * time.Hour, items: []CaptureRiskItem{mismatch, repaired(t0.Add(50 * time.Minute))}, wantChanges: 1},
			// Neutralised and repaired again 7 hours later: the item is the
			// same Key, but a new act. It replaces the stored change, so the
			// reason names the hook once.
			{
				at: 8 * time.Hour, items: []CaptureRiskItem{mismatch, repaired(t0.Add(7*time.Hour + 18*time.Minute))},
				wantNew: []string{repaired(t0.Add(7*time.Hour + 18*time.Minute)).OccurrenceKey()}, wantChanges: 1,
			},
			{at: 9 * time.Hour, items: []CaptureRiskItem{mismatch, repaired(t0.Add(7*time.Hour + 18*time.Minute))}, wantChanges: 1},
		}},
		{"standing items stay quiet whatever time they carry", []report{
			{at: 0, items: []CaptureRiskItem{mismatch, changed("")}, first: true, wantChanges: 0},
			{at: time.Hour, items: []CaptureRiskItem{mismatch, changed("2026-10-17T10:30:00Z")}, wantChanges: 0},
			{at: 2 * time.Hour, items: []CaptureRiskItem{mismatch, changed("2026-10-17T11:30:00Z")}, wantChanges: 0},
		}},
		{"restoring a user's own bytes after a repair is no new act", []report{
			{at: 0, items: []CaptureRiskItem{repaired(t0.Add(-10 * time.Minute))}, first: true, wantChanges: 0},
			// The user puts their original file back: the registry digest no
			// longer matches (a standing hook_config_changed, new here), and
			// the repair record is unchanged, so no second hook_repaired.
			{
				at: time.Hour, items: []CaptureRiskItem{repaired(t0.Add(-10 * time.Minute)), changed("")},
				wantNew: []string{changed("").OccurrenceKey()}, wantChanges: 1,
			},
			{at: 2 * time.Hour, items: []CaptureRiskItem{repaired(t0.Add(-10 * time.Minute)), changed("")}, wantChanges: 1},
		}},
		{"an upgrade from an undated item is not a new event", []report{
			{at: 0, items: []CaptureRiskItem{repaired(time.Time{})}, first: true, wantChanges: 0},
			{at: time.Hour, items: []CaptureRiskItem{repaired(t0.Add(-10 * time.Minute))}, wantChanges: 0},
			{
				at: 2 * time.Hour, items: []CaptureRiskItem{repaired(t0.Add(90 * time.Minute))},
				wantNew: []string{repaired(t0.Add(90 * time.Minute)).OccurrenceKey()}, wantChanges: 1,
			},
		}},
		{"an older node without act times keeps the Key-only reading", []report{
			{at: 0, items: []CaptureRiskItem{mismatch}, first: true, wantChanges: 0},
			{
				at: time.Hour, items: []CaptureRiskItem{mismatch, repaired(time.Time{})},
				wantNew: []string{repaired(time.Time{}).Key()}, wantChanges: 1,
			},
			{at: 2 * time.Hour, items: []CaptureRiskItem{mismatch, repaired(time.Time{})}, wantChanges: 1},
		}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			var prior ManagedIntegrityDetail
			for i, r := range sc.reports {
				now := t0.Add(r.at)
				items := NormalizeCaptureRiskItems(r.items)
				var labels []string
				seen := map[string]bool{}
				for _, it := range items {
					if !seen[it.Risk] {
						seen[it.Risk] = true
						labels = append(labels, it.Risk)
					}
				}
				changes := DeriveCaptureRiskChanges(prior, !r.first, labels, items, now)
				stamp := now.Format(time.RFC3339)
				var got []string
				for _, c := range changes {
					if c.FirstSeen == stamp {
						got = append(got, c.OccurrenceKey())
					}
				}
				if fmt.Sprint(sortedCopy(got)) != fmt.Sprint(sortedCopy(r.wantNew)) {
					t.Fatalf("report %d: new %v, want %v", i, got, r.wantNew)
				}
				if r.wantChanges >= 0 && len(changes) != r.wantChanges {
					t.Fatalf("report %d: %d changes in the window (%+v), want %d", i, len(changes), changes, r.wantChanges)
				}
				prior = ManagedIntegrityDetail{
					CaptureCheckVersion: ManagedCaptureCheckVersion,
					CaptureRisks:        labels,
					CaptureRiskItems:    items,
					RecentChanges:       changes,
					KnownRisks:          MergeKnownCaptureRisks(prior.KnownRisks, labels, items, now),
				}
			}
		})
	}
}

// TestNormalizeRiskAt pins the act time's content floor: kept (in UTC, to
// the second) on an act label, blanked on a standing label and on anything
// that does not parse.
func TestNormalizeRiskAt(t *testing.T) {
	cases := []struct {
		risk, at, want string
	}{
		{CaptureRiskHookRepaired, "2026-10-17T19:18:40+02:00", "2026-10-17T17:18:40Z"},
		{CaptureRiskHookRepaired, "2026-10-17T17:18:40.123456Z", "2026-10-17T17:18:40Z"},
		{CaptureRiskHookRepaired, "yesterday", ""},
		{CaptureRiskHookRepaired, "", ""},
		{CaptureRiskHookConfigChanged, "2026-10-17T17:18:40Z", ""},
		{CaptureRiskHookBinaryMismatch, "2026-10-17T17:18:40Z", ""},
	}
	for _, tc := range cases {
		items := NormalizeCaptureRiskItems([]CaptureRiskItem{{Risk: tc.risk, Tool: "pi", At: tc.at}})
		if len(items) != 1 || items[0].At != tc.want {
			t.Errorf("%s %q: got %+v, want At %q", tc.risk, tc.at, items, tc.want)
		}
	}
	if k := (CaptureRiskItem{Risk: CaptureRiskHookConfigChanged, Tool: "pi", At: "2026-10-17T17:18:40Z"}).OccurrenceKey(); k != "hook_config_changed|pi|" {
		t.Errorf("a standing item's occurrence key carries its time: %q", k)
	}
	known := MergeKnownCaptureRisks(nil, nil, []CaptureRiskItem{{Risk: CaptureRiskHookRepaired, Tool: "pi", At: "2026-10-17T17:18:40Z"}}, time.Date(2026, 10, 17, 18, 0, 0, 0, time.UTC))
	if len(known) != 1 || known[0].At != "" {
		t.Errorf("the known-risk memory kept an act time: %+v", known)
	}
}
