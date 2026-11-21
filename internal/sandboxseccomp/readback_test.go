package sandboxseccomp

import (
	"strings"
	"testing"
)

func TestParseStatus(t *testing.T) {
	t.Parallel()
	got := ParseStatus("Name:\tx\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t3\n")
	if got != (Status{Mode: "2", Filters: 3, HasFilters: true}) {
		t.Fatalf("got %+v", got)
	}
	if got := ParseStatus("Seccomp:\t0\n"); got != (Status{Mode: "0"}) {
		t.Fatalf("old kernel: got %+v", got)
	}
	if got := ParseStatus("Seccomp_filters:\tx\n"); got.HasFilters {
		t.Fatalf("a bad count parsed: %+v", got)
	}
}

// TestReadBackRows: one case per row of the read-back table, plus the
// matches.
func TestReadBackRows(t *testing.T) {
	t.Parallel()
	none := Status{Mode: "0", HasFilters: true}
	oldNone := Status{Mode: "0"}
	for _, c := range []struct {
		name        string
		self, child Status
		want        string
	}{
		{"child unfiltered", none, Status{Mode: "0", HasFilters: true}, StateNotFiltered},
		{"child strict mode", none, Status{Mode: "1", HasFilters: true}, StateNotFiltered},
		{"child line missing", none, Status{}, StateNotFiltered},
		{"mode 2 with zero filters", none, Status{Mode: "2", HasFilters: true}, StateNotFiltered},
		{"helper filtered, no counter", Status{Mode: "2"}, Status{Mode: "2"}, StateUnmeasurable},
		{"helper filtered, child no counter", Status{Mode: "2", Filters: 1, HasFilters: true}, Status{Mode: "2"}, StateUnmeasurable},
		{"only the inherited filter", Status{Mode: "2", Filters: 1, HasFilters: true}, Status{Mode: "2", Filters: 1, HasFilters: true}, StateOnlyInherited},
		{"match", none, Status{Mode: "2", Filters: 1, HasFilters: true}, ""},
		{"match, old kernel", oldNone, Status{Mode: "2"}, ""},
		{"match over an inherited filter", Status{Mode: "2", Filters: 1, HasFilters: true}, Status{Mode: "2", Filters: 2, HasFilters: true}, ""},
	} {
		err := ReadBack(c.self, c.child)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.HasPrefix(err.Error(), c.want+":")):
			t.Errorf("%s: got %v, want %s", c.name, err, c.want)
		}
	}
}

// TestPreflightRows: one case per row of the pre-launch table, plus the
// states the read-back can still measure.
func TestPreflightRows(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		self Status
		want string
	}{
		{"helper filtered, no counter", Status{Mode: "2"}, StateUnmeasurable},
		{"helper unfiltered, no counter", Status{Mode: "0"}, ""},
		{"helper unfiltered, line missing", Status{}, ""},
		{"helper filtered, counter", Status{Mode: "2", Filters: 1, HasFilters: true}, ""},
		{"helper unfiltered, counter", Status{Mode: "0", HasFilters: true}, ""},
	} {
		err := Preflight(c.self)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.HasPrefix(err.Error(), c.want+":")):
			t.Errorf("%s: got %v, want %s", c.name, err, c.want)
		}
	}
}

// TestPreflightCoversReadBackUnmeasurable: every self state the read-back
// would call unmeasurable against a child on the same kernel is refused by
// Preflight first, so a started agent is never killed for it.
func TestPreflightCoversReadBackUnmeasurable(t *testing.T) {
	t.Parallel()
	for _, self := range []Status{{Mode: "2"}, {Mode: "2", Filters: 1, HasFilters: true}, {Mode: "0"}, {Mode: "0", HasFilters: true}} {
		// A child on the same kernel has the counter exactly when self does.
		child := Status{Mode: "2", Filters: self.Filters + 1, HasFilters: self.HasFilters}
		err := ReadBack(self, child)
		if err != nil && strings.HasPrefix(err.Error(), StateUnmeasurable+":") && Preflight(self) == nil {
			t.Errorf("self %+v: the read-back says unmeasurable but Preflight let it launch", self)
		}
	}
}
