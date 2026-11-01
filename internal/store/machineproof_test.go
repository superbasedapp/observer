// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"testing"
)

// TestOrgMachineProofReport pins the round trip and the contract the doctor
// reads with its own SQL: the key and the JSON field names.
func TestOrgMachineProofReport(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if _, ok, err := s.LoadOrgMachineProofReport(ctx); err != nil || ok {
		t.Fatalf("empty: ok=%v err=%v", ok, err)
	}
	want := OrgMachineProofReport{Available: false, Reason: "no Windows logon session", At: "2026-10-28T10:00:00Z"}
	if err := s.SaveOrgMachineProofReport(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LoadOrgMachineProofReport(ctx)
	if err != nil || !ok || got != want {
		t.Fatalf("got %+v ok=%v err=%v", got, ok, err)
	}
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = 'org_machine_proof'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != `{"available":false,"reason":"no Windows logon session","at":"2026-10-28T10:00:00Z"}` {
		t.Fatalf("stored JSON = %s", raw)
	}
}
