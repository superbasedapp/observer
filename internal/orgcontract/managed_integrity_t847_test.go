package orgcontract

import (
	"strings"
	"testing"
	"time"
)

// TestValidRiskFileLabel pins the content floor of a located risk's file
// label: a closed root, conservative characters, no traversal, bounded.
func TestValidRiskFileLabel(t *testing.T) {
	cases := []struct {
		label string
		ok    bool
	}{
		{"~/.cursor/hooks.json", true},
		{"~win/.claude/settings.json", true},
		{"?/agents/superbased-observer.json", true},
		{"~/.config/poolside/settings.yaml", true},
		{"", false},
		{"/home/alice/.cursor/hooks.json", false},
		{"C:/Users/alice/.cursor/hooks.json", false},
		{"~/../etc/passwd", false},
		{"~/./x", false},
		{"~//x", false},
		{"~/x;rm -rf", false},
		{"~/" + strings.Repeat("a", 200), false},
	}
	for _, tc := range cases {
		if got := ValidRiskFileLabel(tc.label); got != tc.ok {
			t.Errorf("ValidRiskFileLabel(%q) = %v, want %v", tc.label, got, tc.ok)
		}
	}
}

// TestNormalizeCaptureRiskItems pins that an unknown risk is dropped, an
// invalid tool, file or event is blanked, duplicates collapse and the list is
// bounded.
func TestNormalizeCaptureRiskItems(t *testing.T) {
	in := []CaptureRiskItem{
		{Risk: "not_a_risk", Tool: "cursor", File: "~/.cursor/hooks.json"},
		{Risk: CaptureRiskHookConfigMissing, Tool: "Cursor!", File: "/home/alice/.cursor/hooks.json", Events: []string{"pre tool", "PreToolUse"}},
		{Risk: CaptureRiskHookRepaired, Tool: "claude-code", File: "~/.claude/settings.json", Events: []string{"PreToolUse"}},
		{Risk: CaptureRiskHookRepaired, Tool: "claude-code", File: "~/.claude/settings.json", Events: []string{"Stop"}},
	}
	got := NormalizeCaptureRiskItems(in)
	if len(got) != 2 {
		t.Fatalf("got %+v, want 2 items", got)
	}
	for _, it := range got {
		if it.Risk == CaptureRiskHookConfigMissing {
			if it.Tool != "" || it.File != "" || len(it.Events) != 1 || it.Events[0] != "PreToolUse" {
				t.Errorf("invalid fields not blanked: %+v", it)
			}
		}
	}
	many := make([]CaptureRiskItem, 0, 40)
	for i := 0; i < 40; i++ {
		many = append(many, CaptureRiskItem{Risk: CaptureRiskHookConfigChanged, Tool: "t" + strings.Repeat("x", i%40+1)})
	}
	if n := len(NormalizeCaptureRiskItems(many)); n != maxCaptureRiskItems {
		t.Errorf("bounded to %d, want %d", n, maxCaptureRiskItems)
	}
}

// TestDeriveCaptureRiskChanges is the server's per-event derivation, one row
// per rule.
func TestDeriveCaptureRiskChanges(t *testing.T) {
	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	stamp := now.Format(time.RFC3339)
	cursor := CaptureRiskItem{Risk: CaptureRiskHookConfigMissing, Tool: "cursor", File: "~/.cursor/hooks.json"}
	codex := CaptureRiskItem{Risk: CaptureRiskHookConfigMissing, Tool: "codex", File: "~/.codex/hooks.json"}
	claude := CaptureRiskItem{Risk: CaptureRiskHookConfigChanged, Tool: "claude-code", File: "~/.claude/settings.json"}
	cases := []struct {
		name     string
		prior    ManagedIntegrityDetail
		hadPrior bool
		labels   []string
		items    []CaptureRiskItem
		want     []string
	}{
		{name: "first report yields no change", items: []CaptureRiskItem{cursor}, labels: []string{cursor.Risk}},
		{
			name:     "a new file under an existing label is new (audit c2)",
			prior:    ManagedIntegrityDetail{CaptureRisks: []string{cursor.Risk}, CaptureRiskItems: []CaptureRiskItem{cursor}},
			hadPrior: true, labels: []string{cursor.Risk}, items: []CaptureRiskItem{cursor, codex},
			want: []string{codex.Key()},
		},
		{
			name:     "an unchanged report yields nothing",
			prior:    ManagedIntegrityDetail{CaptureRisks: []string{cursor.Risk}, CaptureRiskItems: []CaptureRiskItem{cursor}},
			hadPrior: true, labels: []string{cursor.Risk}, items: []CaptureRiskItem{cursor},
		},
		{
			name:     "a prior without located items compares by label (no upgrade storm)",
			prior:    ManagedIntegrityDetail{CaptureRisks: []string{claude.Risk}},
			hadPrior: true, labels: []string{claude.Risk, cursor.Risk}, items: []CaptureRiskItem{claude, cursor},
			want: []string{cursor.Key()},
		},
		{
			name:     "a new bare label from an older node is new",
			prior:    ManagedIntegrityDetail{CaptureRisks: []string{claude.Risk}},
			hadPrior: true, labels: []string{claude.Risk, CaptureRiskCodexHookUntrusted},
			want: []string{CaptureRiskItem{Risk: CaptureRiskCodexHookUntrusted}.Key()},
		},
		{
			name: "prior changes carry inside the window and expire outside it",
			prior: ManagedIntegrityDetail{RecentChanges: []CaptureRiskChange{
				{CaptureRiskItem: cursor, FirstSeen: now.Add(-time.Hour).Format(time.RFC3339)},
				{CaptureRiskItem: codex, FirstSeen: now.Add(-25 * time.Hour).Format(time.RFC3339)},
			}},
			hadPrior: true,
			want:     []string{cursor.Key()},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveCaptureRiskChanges(tc.prior, tc.hadPrior, tc.labels, tc.items, now)
			var keys []string
			for _, c := range got {
				keys = append(keys, c.Key())
				if c.Key() != cursor.Key() && c.FirstSeen != stamp {
					t.Errorf("new change %s stamped %s, want %s", c.Key(), c.FirstSeen, stamp)
				}
			}
			if strings.Join(keys, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("changes = %v, want %v", keys, tc.want)
			}
		})
	}
}

// TestCaptureRiskItemString pins the reason rendering fleethealth relies on.
func TestCaptureRiskItemString(t *testing.T) {
	it := CaptureRiskItem{Risk: CaptureRiskHookRepaired, Tool: "cursor", File: "~/.cursor/hooks.json", Events: []string{"preToolUse", "stop"}}
	if got, want := it.String(), "hook_repaired (cursor ~/.cursor/hooks.json: preToolUse,stop)"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if got := (CaptureRiskItem{Risk: CaptureRiskCodexHookUntrusted}).String(); got != CaptureRiskCodexHookUntrusted {
		t.Fatalf("bare String() = %q", got)
	}
}
