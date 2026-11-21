package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// fakeEnroller records the one EnrolStaff call runStaffEnrol makes.
type fakeEnroller struct {
	calls int
	got   store.EnrolStaffInput
}

func (f *fakeEnroller) EnrolStaff(_ context.Context, in store.EnrolStaffInput) (store.StaffEnrolment, error) {
	f.calls++
	f.got = in
	id := in.StaffID
	if id == "" {
		id = "11111111-2222-4333-8444-555555555555"
	}
	return store.StaffEnrolment{
		Staff:     store.StaffUser{StaffID: id, DisplayName: "Ops One", Role: staffauth.RoleAdmin},
		RawCode:   "one-time-code-abc",
		ExpiresAt: in.Now.Add(30 * time.Minute),
	}, nil
}

func TestRunStaffEnrol(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		flags staffEnrolFlags
		ok    bool
	}{
		{"new admin", staffEnrolFlags{displayName: "Ops One", role: "admin", reason: "first staff member"}, true},
		{"existing member", staffEnrolFlags{staffID: "11111111-2222-4333-8444-555555555555", reason: "lost key"}, true},
		{"no name", staffEnrolFlags{role: "admin", reason: "r"}, false},
		{"unknown role", staffEnrolFlags{displayName: "A", role: "root", reason: "r"}, false},
		{"no reason", staffEnrolFlags{displayName: "A", role: "ops"}, false},
		{"staff id with a role", staffEnrolFlags{staffID: "x", role: "ops", reason: "r"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeEnroller{}
			var out bytes.Buffer
			err := runStaffEnrol(context.Background(), f, c.flags, now, &out)
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
			if !c.ok {
				if f.calls != 0 {
					t.Fatal("an invalid enrolment reached the store")
				}
				return
			}
			if f.calls != 1 {
				t.Fatalf("EnrolStaff calls = %d", f.calls)
			}
			// The code is printed exactly once.
			if n := strings.Count(out.String(), "one-time-code-abc"); n != 1 {
				t.Fatalf("code printed %d times:\n%s", n, out.String())
			}
		})
	}
}
