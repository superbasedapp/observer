package dashboard

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestClampDetailValueCutsOnARune pins lane cli-2 fixes-3, audit L2: a
// long value is cut on a rune boundary, so the card never shows half a
// character.
func TestClampDetailValueCutsOnARune(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    string
	}{
		{"ascii", strings.Repeat("a", maxDetailValue+20)},
		{"two-byte rune across the cut", strings.Repeat("a", maxDetailValue-1) + "ééé"},
		{"three-byte runes", strings.Repeat("€", maxDetailValue)},
		{"four-byte runes", strings.Repeat("\U0001F600", maxDetailValue)},
	} {
		got := clampDetailValue(tc.v)
		if !utf8.ValidString(got) {
			t.Errorf("%s: cut value is not valid UTF-8: %q", tc.name, got[len(got)-50:])
		}
		shown, _, ok := strings.Cut(got, "... (cut;")
		if !ok || len(shown) > maxDetailValue || !strings.HasPrefix(tc.v, shown) {
			t.Errorf("%s: shown %d bytes, want at most %d and a prefix of the value", tc.name, len(shown), maxDetailValue)
		}
	}
	if v := "short é"; clampDetailValue(v) != v {
		t.Errorf("a short value was changed")
	}
}

// TestListMemberSaysHowManyItemsWereCut: a long list (arena candidates)
// shows its items whole while they fit and says how many it cut, flagged.
func TestListMemberSaysHowManyItemsWereCut(t *testing.T) {
	row, _ := launchRouteFor("/api/arena/runs")
	var items []string
	for i := range 40 {
		items = append(items, fmt.Sprintf(`{"tool":"codex","model":"model-%02d"}`, i))
	}
	body := `{"prompt":"p","candidates":[` + strings.Join(items, ",") + `]}`
	var cand *struct {
		Value string
		Warn  bool
	}
	for _, d := range heldDetails(row, "/api/arena/runs", []byte(body)) {
		if d.Label == "candidates" {
			cand = &struct {
				Value string
				Warn  bool
			}{d.Value, d.Warn}
		}
	}
	if cand == nil {
		t.Fatal("no candidates detail")
	}
	shown := strings.Count(cand.Value, `"tool":"codex"`)
	want := fmt.Sprintf("(%d of 40 items cut; the confirm sends all 40)", 40-shown)
	if shown == 0 || shown == 40 || !strings.Contains(cand.Value, want) || !cand.Warn {
		t.Fatalf("candidates detail = %q (warn %v), want %q", cand.Value, cand.Warn, want)
	}
	if !strings.Contains(cand.Value, items[shown-1]) {
		t.Fatalf("the last shown item is not whole: %q", cand.Value)
	}

	// A first item that alone is too long is shown cut and counted cut.
	long := `{"prompt":"` + strings.Repeat("é", maxDetailValue) + `"}`
	v, cut := clampListValue([]string{long, `{"tool":"x"}`})
	if !cut || !utf8.ValidString(v) || !strings.Contains(v, "(2 of 2 items cut; the confirm sends all 2)") {
		t.Fatalf("one long item = %q %v", v, cut)
	}
	// A list that fits is shown whole and not flagged.
	if v, cut := clampListValue([]string{`"a"`, `"b"`}); cut || v != `["a","b"]` {
		t.Fatalf("a short list = %q %v", v, cut)
	}
}
