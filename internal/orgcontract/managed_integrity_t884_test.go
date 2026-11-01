package orgcontract

import (
	"encoding/json"
	"testing"
	"time"
)

// TestCaptureRiskItemKeptCopy pins T-884: the copy a managed hook repair kept
// rides the hook_repaired item under the same content floor as File, is not
// part of the item's identity, and is rendered in the finding reason.
func TestCaptureRiskItemKeptCopy(t *testing.T) {
	const copyLabel = "~/.pi/agent/extensions/superbased-observer.ts.displaced-20261017T171840.123456789Z"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"home-relative label kept", copyLabel, copyLabel},
		{"absolute path dropped", "/home/dev/.pi/x.ts.displaced-20261017T171840.123456789Z", ""},
		{"traversal dropped", "~/../etc/passwd", ""},
		{"empty stays empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			it := CaptureRiskItem{Risk: CaptureRiskHookRepaired, Tool: "pi", File: "~/.pi/agent/extensions/superbased-observer.ts", KeptCopy: tc.in}
			out := NormalizeCaptureRiskItems([]CaptureRiskItem{it})
			if len(out) != 1 || out[0].KeptCopy != tc.want {
				t.Fatalf("normalized = %+v, want kept_copy %q", out, tc.want)
			}
		})
	}

	// Act-only, like At (T-886): a standing label never carries a copy, and
	// the known-risk memory drops it.
	standing := CaptureRiskItem{Risk: CaptureRiskHookBinaryMismatch, Tool: "pi", File: "~/x.ts", KeptCopy: copyLabel}
	if out := NormalizeCaptureRiskItems([]CaptureRiskItem{standing}); len(out) != 1 || out[0].KeptCopy != "" {
		t.Fatalf("standing label kept a copy: %+v", out)
	}
	repaired := CaptureRiskItem{Risk: CaptureRiskHookRepaired, Tool: "pi", File: "~/x.ts", At: "2026-10-17T17:18:40Z", KeptCopy: copyLabel}
	for _, k := range MergeKnownCaptureRisks(nil, nil, []CaptureRiskItem{repaired}, time.Date(2026, 10, 17, 18, 0, 0, 0, time.UTC)) {
		if k.KeptCopy != "" || k.At != "" {
			t.Fatalf("known-risk memory kept act fields: %+v", k)
		}
	}

	a := CaptureRiskItem{Risk: CaptureRiskHookRepaired, Tool: "pi", File: "~/x.ts"}
	b := a
	b.KeptCopy = "~/x.ts.displaced-20261017T171840.123456789Z"
	if a.Key() != b.Key() {
		t.Fatalf("kept_copy changed the item identity: %q vs %q", a.Key(), b.Key())
	}
	b.Events = []string{"tool.execute.before"}
	if got, want := b.String(), "hook_repaired (pi ~/x.ts: tool.execute.before; previous bytes kept at ~/x.ts.displaced-20261017T171840.123456789Z)"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}

	// Compat both ways: an older node's item (no field) decodes to an empty
	// copy, and the field is omitted when empty.
	var old CaptureRiskItem
	if err := json.Unmarshal([]byte(`{"risk":"hook_repaired","tool":"pi","file":"~/x.ts"}`), &old); err != nil || old.KeptCopy != "" {
		t.Fatalf("older item = %+v (%v)", old, err)
	}
	raw, _ := json.Marshal(a)
	if string(raw) != `{"risk":"hook_repaired","tool":"pi","file":"~/x.ts"}` {
		t.Fatalf("item without a copy encodes as %s", raw)
	}
}
