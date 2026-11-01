// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// machineproof.go persists the daemon's machine-proof outcome (WINNODE item 4)
// so `observer doctor`, `observer org status` and the dashboard's enrolment
// page say what the DAEMON sees. Those run in other processes, and on Windows
// a CLI over SSH has no logon session of its own, so its own view of the
// Windows credential store says nothing about the daemon's. One node-local
// schema_meta key, the orgsnapoversize.go precedent; it never ships.

// OrgMachineProofKey is the schema_meta key holding the JSON report. The
// doctor reads it directly (internal/diag keeps its own SQL), so the key and
// the JSON field names are a contract, pinned by TestOrgMachineProofReport.
const OrgMachineProofKey = "org_machine_proof"

// OrgMachineProofReport is the daemon's last machine-proof outcome.
type OrgMachineProofReport struct {
	// Available is true when the daemon signed its requests with its
	// machine key.
	Available bool `json:"available"`
	// Reason names why the proof is unavailable ("" when available).
	Reason string `json:"reason,omitempty"`
	// At is when the outcome last changed (RFC 3339).
	At string `json:"at"`
}

// SaveOrgMachineProofReport records r. Best effort for the caller: a failed
// write only leaves the previous report.
func (s *Store) SaveOrgMachineProofReport(ctx context.Context, r OrgMachineProofReport) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("store.SaveOrgMachineProofReport: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		OrgMachineProofKey, string(raw)); err != nil {
		return fmt.Errorf("store.SaveOrgMachineProofReport: %w", err)
	}
	return nil
}

// LoadOrgMachineProofReport returns the persisted report; ok is false when
// the daemon never recorded one (an individual enrolment, or no request that
// names the machine yet).
func (s *Store) LoadOrgMachineProofReport(ctx context.Context) (OrgMachineProofReport, bool, error) {
	v, err := s.readMeta(ctx, OrgMachineProofKey)
	if err != nil {
		return OrgMachineProofReport{}, false, fmt.Errorf("store.LoadOrgMachineProofReport: %w", err)
	}
	if v == "" {
		return OrgMachineProofReport{}, false, nil
	}
	var r OrgMachineProofReport
	if err := json.Unmarshal([]byte(v), &r); err != nil {
		return OrgMachineProofReport{}, false, fmt.Errorf("store.LoadOrgMachineProofReport: %w", err)
	}
	return r, true, nil
}
