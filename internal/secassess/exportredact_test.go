package secassess

import (
	"strings"
	"testing"
)

// exMarked is a checked threat model whose text holds n markers of a hidden
// secret, as a copy redacted when it was stored does.
func exMarked(t *testing.T, n int) Result {
	t.Helper()
	res := exTM(t, nil)
	if got := CountRedactionMarkers(res); got != 0 {
		t.Fatalf("the baseline already holds %d markers", got)
	}
	var parts []string
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			parts = append(parts, "key [REDACTED]")
		} else {
			parts = append(parts, "key [REDACTED:aws_key]")
		}
	}
	res.TM.Threats = []Threat{{Title: strings.Join(parts, " and ") + " in a header"}}
	return res
}

// TestCountRedactionMarkers: both marker spellings count, once each, in the
// strings the display pass walks, and the value is left as it was.
func TestCountRedactionMarkers(t *testing.T) {
	tests := []struct {
		name string
		n    int
	}{{"none", 0}, {"one", 1}, {"two spellings", 2}, {"several", 7}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := exMarked(t, tc.n)
			before := res.TM.Threats[0].Title
			if got := CountRedactionMarkers(res); got != tc.n {
				t.Errorf("markers = %d, want %d", got, tc.n)
			}
			if res.TM.Threats[0].Title != before {
				t.Error("counting changed the value")
			}
		})
	}
	if got := CountRedactionMarkers(struct{ A string }{"x [REDACTED] y [REDACTED]"}); got != 2 {
		t.Errorf("a plain struct: %d, want 2", got)
	}
}

// TestRedactionSentenceNamesWhatIsInTheText: the statement about hiding is
// never "nothing hidden" beside a text full of markers (UX-13 of the e2e
// review: 16 and 19 markers in the files, "found none to hide" and hidden 0).
// One row per case of redactionRows, with and without markers in the stored copy.
func TestRedactionSentenceNamesWhatIsInTheText(t *testing.T) {
	const holds = "The text below holds "
	tests := []struct {
		name   string
		on     bool
		now    int
		marked int
		want   []string
	}{
		{"on, nothing hidden now, none in the text", true, 0, 0, []string{"Observer found none to hide in the text below.", "!" + holds}},
		{"on, nothing hidden now, markers from storage", true, 0, 16, []string{"hiding them again found nothing more to hide", holds + "16 markers where a secret was hidden", "including any hidden when the copy was stored.", "!Observer found none to hide"}},
		{"on, one marker from storage", true, 0, 1, []string{holds + "1 marker where a secret was hidden", "!1 markers"}},
		{"on, hidden now and markers", true, 2, 5, []string{"hidden in 2 places of the text below.", holds + "5 markers"}},
		{"on, hidden now, no markers counted", true, 2, 0, []string{"hidden in 2 places of the text below.", "!" + holds}},
		{"off, none in the text", false, 0, 0, []string{"Hiding recognised secrets was off, so the text below is as stored", "!" + holds, "!were hidden in"}},
		{"off, markers from storage", false, 0, 19, []string{"Hiding recognised secrets was off, so the text below is as stored", holds + "19 markers where a secret was hidden", "!were hidden in", "!none to hide"}},
		{"off with a stale count", false, 9, 3, []string{"was off", holds + "3 markers", "!were hidden in"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := exMeta(ThreatModel)
			m.RedactionOn, m.Hidden = tc.on, tc.now
			got := redactionSentence(m, tc.marked)
			exHas(t, got, tc.want...)
		})
	}
}

// TestExportsCountTheMarkersTheTextHolds: the Markdown and the JSON both
// count the markers of the text they carry, whatever the display pass hid.
func TestExportsCountTheMarkersTheTextHolds(t *testing.T) {
	res := exMarked(t, 4)
	meta := exMeta(ThreatModel)
	meta.RedactionOn, meta.Hidden = true, 0
	md := RenderMarkdown(meta, res)
	exHas(t, md, "The text below holds 4 markers where a secret was hidden", "!Observer found none to hide")
	b, err := RenderExportJSON(meta, res)
	if err != nil {
		t.Fatal(err)
	}
	doc := exDecode(t, b)
	if doc.Redaction != (ExportRedaction{On: true, Hidden: 0, Markers: 4}) {
		t.Errorf("redaction = %+v, want the 4 markers counted beside hidden 0", doc.Redaction)
	}
	if !strings.Contains(doc.Note, "redaction.markers") || !strings.Contains(doc.Note, "when the copy was stored") {
		t.Errorf("the note does not explain the two counts: %q", doc.Note)
	}
	// Nothing in the text, nothing counted.
	plain, err := RenderExportJSON(meta, exTM(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := exDecode(t, plain).Redaction.Markers; got != 0 {
		t.Errorf("markers = %d for a text with none", got)
	}
}
