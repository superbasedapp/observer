package sandboxvocab

import (
	"strings"
	"testing"
)

// TestOrgDailyBoxMinutesPhrase: the phrase carries the number and says
// whose quantity it is (per member, every machine), never "today's".
func TestOrgDailyBoxMinutesPhrase(t *testing.T) {
	got := OrgDailyBoxMinutesPhrase(480)
	for _, want := range []string{"480 box-minutes a day", "per member", "all of the member's machines"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "today") {
		t.Fatalf("%q reads as a remaining amount", got)
	}
}
