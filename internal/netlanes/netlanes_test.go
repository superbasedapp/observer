package netlanes

import (
	"strings"
	"testing"
)

func TestLanesWellFormed(t *testing.T) {
	known := map[Default]bool{DefaultOn: true, DefaultYourTraffic: true, DefaultAfterAccept: true, DefaultWhenYouAct: true, DefaultOff: true}
	seen := map[string]bool{}
	for _, l := range Lanes {
		if l.ID == "" || seen[l.ID] {
			t.Errorf("lane id %q empty or repeated", l.ID)
		}
		seen[l.ID] = true
		for name, v := range map[string]string{"Name": l.Name, "Sends": l.Sends, "To": l.To, "When": l.When, "TurnOff": l.TurnOff} {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: %s is empty", l.ID, name)
			}
			if strings.Contains(v, "—") {
				t.Errorf("%s: %s has an em-dash", l.ID, name)
			}
		}
		if !known[l.Default] {
			t.Errorf("%s: default %q is not in the closed set", l.ID, l.Default)
		}
		if len(l.EgressIDs) == 0 {
			t.Errorf("%s names no egress lane", l.ID)
		}
	}
	// The lanes the README must name (Getting started v2).
	for _, id := range []string{"package-lists", "package-checks", "osv-database", "package-lookup", "sign-in", "community", "connect-push", "plans-limits", "tls-prewarm"} {
		if !seen[id] {
			t.Errorf("no %s lane", id)
		}
	}
}

func TestMarkdownTable(t *testing.T) {
	md := Markdown()
	lines := strings.Split(strings.TrimSpace(md), "\n")
	if len(lines) != len(Lanes)+2 {
		t.Fatalf("got %d lines, want %d", len(lines), len(Lanes)+2)
	}
	for i, line := range lines {
		if got := strings.Count(strings.ReplaceAll(line, `\|`, ""), "|"); got != 7 {
			t.Errorf("line %d has %d separators: %q", i, got, line)
		}
	}
	if mdCell("a|b\nc") != `a\|b c` {
		t.Errorf("mdCell = %q", mdCell("a|b\nc"))
	}
}
