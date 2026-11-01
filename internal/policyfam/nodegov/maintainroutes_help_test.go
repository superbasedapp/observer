package nodegov

import (
	"strings"
	"testing"
)

// TestMaintainRoutesHelpIsServed: the admin console's note on what turning
// proxy.maintain_routes off costs travels in the served vocabulary, on that
// row only, with no em or en dash (operator copy rule; the hyphen in
// "pre-send" is part of a word, not a dash).
func TestMaintainRoutesHelpIsServed(t *testing.T) {
	found := false
	for _, k := range Vocabulary().PinnableKeys {
		if k.Key != "proxy.maintain_routes" {
			// Other rows may carry their own note (the sandbox list
			// operators, lane SBX-P1B); it must match the table and carry no
			// dash either.
			if row, ok := LookupPinnableKey(k.Key); !ok || k.Help != row.Help {
				t.Errorf("%s serves a help note it was not given", k.Key)
			}
			if strings.ContainsAny(k.Help, "\u2014\u2013") {
				t.Errorf("%s: the note contains a dash: %q", k.Key, k.Help)
			}
			continue
		}
		found = true
		if k.Help != MaintainRoutesOffHelp {
			t.Fatalf("help = %q, want MaintainRoutesOffHelp", k.Help)
		}
	}
	if !found {
		t.Fatal("proxy.maintain_routes is not in the served vocabulary")
	}
	if strings.ContainsAny(MaintainRoutesOffHelp, "\u2014\u2013") {
		t.Fatalf("the note contains a dash: %q", MaintainRoutesOffHelp)
	}
}
