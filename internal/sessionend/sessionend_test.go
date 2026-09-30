package sessionend

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// One case per rule-table row, in order, plus the boundary cases.
func TestEndedAt(t *testing.T) {
	const (
		t1 = "2026-09-27T11:13:10Z"
		t2 = "2026-09-27T11:13:44.952Z"
		t3 = "2026-09-27T11:20:00Z"
	)
	for _, tc := range []struct {
		name   string
		f      Facts
		want   string
		wantOK bool
	}{
		{"no_close_leaves_stored_value", Facts{LastReopen: t1}, "", false},
		{"reopen_after_close_is_live", Facts{LastClose: t2, LastReopen: t3}, "", true},
		{"close_after_reopen_ends", Facts{LastClose: t2, LastReopen: t1}, t2, true},
		{"close_only_ends", Facts{LastClose: t2}, t2, true},
		{"same_instant_stays_closed", Facts{LastClose: t2, LastReopen: t2}, t2, true},
		{"unparseable_close_is_absent", Facts{LastClose: "garbage", LastReopen: t1}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := EndedAt(tc.f)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("EndedAt(%+v) = %q,%v want %q,%v", tc.f, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestRoles(t *testing.T) {
	if RoleOf(models.ActionSessionEnd) != RoleClose || RoleOf(models.ActionUserPrompt) != RoleReopen ||
		RoleOf(models.ActionSessionStart) != RoleReopen || RoleOf(models.ActionTurnAborted) != RoleNone {
		t.Fatal("role table drifted")
	}
	if got := ActionTypes(RoleClose); len(got) != 1 || got[0] != models.ActionSessionEnd {
		t.Fatalf("closers = %v", got)
	}
	if got := ActionTypes(RoleReopen); len(got) != 2 {
		t.Fatalf("reopeners = %v", got)
	}
}
