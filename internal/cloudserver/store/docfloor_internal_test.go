package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// TestDecideFloorRows is one case per floorRules row (W16-D6), plus the
// boundaries: a floor is raised only when the record is strictly above both
// the stored maximum and the current floor, so it never lowers.
func TestDecideFloorRows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                  string
		record, stored, floor int64
		want                  FloorAction
	}{
		{"database ahead of the record", 10, 20, 0, FloorDatabaseAhead},
		{"database equal to the record", 10, 10, 0, FloorDatabaseAhead},
		{"floor already past the record", 10, 5, 12, FloorAlreadyRaised},
		{"floor equal to the record (a repeated run)", 10, 5, 10, FloorAlreadyRaised},
		{"record ahead of both", 10, 5, 7, FloorRaise},
		{"record ahead of an empty stream", 10, 0, 0, FloorRaise},
	}
	if got, want := len(floorRules), 3; got != want {
		t.Fatalf("floorRules has %d rows; this test covers %d", got, want)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := decideFloor(c.record, c.stored, c.floor); got != c.want {
				t.Fatalf("decideFloor(%d, %d, %d) = %s, want %s", c.record, c.stored, c.floor, got, c.want)
			}
		})
	}
}

// TestCheckRaiseInput: every input rule refuses before any SQL, and the
// accepted entries come back in lock order.
func TestCheckRaiseInput(t *testing.T) {
	t.Parallel()
	const orgA = "aaaaaaaa-0000-4000-8000-000000000001"
	const orgB = "bbbbbbbb-0000-4000-8000-000000000002"
	sha := strings.Repeat("ab", 32)
	ok := RaiseDocumentFloorsInput{RecordSHA256: sha, Operator: "ops", Entries: []DocumentFloorEntry{
		{Kind: platformcontract.KindEntitlements, Scope: orgB, Version: 2},
		{Kind: platformcontract.KindAvailability, Scope: platformcontract.AvailabilityScope, Version: 1},
		{Kind: platformcontract.KindEntitlements, Scope: orgA, Version: 3},
	}}
	got, err := checkRaiseInput(ok)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Kind != platformcontract.KindAvailability || got[1].Scope != orgA || got[2].Scope != orgB {
		t.Fatalf("entries not in lock order: %+v", got)
	}
	bad := map[string]func(*RaiseDocumentFloorsInput){
		"digest not hex":     func(in *RaiseDocumentFloorsInput) { in.RecordSHA256 = strings.Repeat("z", 64) },
		"digest uppercase":   func(in *RaiseDocumentFloorsInput) { in.RecordSHA256 = strings.Repeat("AB", 32) },
		"no operator":        func(in *RaiseDocumentFloorsInput) { in.Operator = "" },
		"operator spaces":    func(in *RaiseDocumentFloorsInput) { in.Operator = "a b" },
		"no entries":         func(in *RaiseDocumentFloorsInput) { in.Entries = nil },
		"unknown kind":       func(in *RaiseDocumentFloorsInput) { in.Entries[0].Kind = "invoices" },
		"availability scope": func(in *RaiseDocumentFloorsInput) { in.Entries[1].Scope = orgA },
		"zero version":       func(in *RaiseDocumentFloorsInput) { in.Entries[0].Version = 0 },
		"repeated stream":    func(in *RaiseDocumentFloorsInput) { in.Entries[2].Scope = orgB },
	}
	for name, mutate := range bad {
		in := ok
		in.Entries = append([]DocumentFloorEntry(nil), ok.Entries...)
		mutate(&in)
		if _, err := checkRaiseInput(in); !errors.Is(err, ErrDocumentFloorInput) {
			t.Errorf("%s: err = %v, want ErrDocumentFloorInput", name, err)
		}
	}
}
