// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"testing"
)

// TestOrgDaemonCredentialReports pins the per-daemon round trip: a daemon's
// new view replaces its own previous one and leaves another daemon's alone.
func TestOrgDaemonCredentialReports(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if got, err := s.LoadOrgDaemonCredentialReports(ctx); err != nil || len(got) != 0 {
		t.Fatalf("empty: %+v err=%v", got, err)
	}
	a := OrgDaemonCredentialReport{PID: 40, Enrolled: false, Backend: "keychain", Reason: "no bearer", At: "2026-10-28T10:00:00Z"}
	b := OrgDaemonCredentialReport{PID: 7, Enrolled: true, Backend: "file", At: "2026-10-28T10:01:00Z"}
	for _, r := range []OrgDaemonCredentialReport{a, b} {
		if err := s.SaveOrgDaemonCredentialReport(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	a2 := a
	a2.Enrolled, a2.Reason, a2.At = true, "", "2026-10-28T10:02:00Z"
	if err := s.SaveOrgDaemonCredentialReport(ctx, a2); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadOrgDaemonCredentialReports(ctx)
	if err != nil || len(got) != 2 || got[0] != b || got[1] != a2 {
		t.Fatalf("got %+v err=%v", got, err)
	}
}
