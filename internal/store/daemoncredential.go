// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// daemoncredential.go persists, per daemon, what the daemon last saw of its
// own org credential (WINNODE2, issue 1b). On Windows the credential store
// depends on the logon context, so the CLI's own view (over SSH, the 0600
// file store) says nothing about a daemon started at the developer's sign-in
// (Credential Manager). `observer org push-status`, `observer org status`
// and the dashboard's enrolment page read this report to say when the
// RUNNING daemon cannot push. One node-local schema_meta key, the
// machineproof.go precedent; it never ships.

// OrgDaemonCredentialKey is the schema_meta key holding the JSON reports.
const OrgDaemonCredentialKey = "org_daemon_credential" //nolint:gosec // G101: a schema_meta key name, not a credential

// maxDaemonCredentialReports bounds the stored reports; readers keep only
// the live daemons' ones anyway.
const maxDaemonCredentialReports = 8

// OrgDaemonCredentialReport is one daemon's last view of its org credential.
type OrgDaemonCredentialReport struct {
	// PID is the daemon's process id (its lock file names it).
	PID int `json:"pid"`
	// StartedAt is when the daemon started (RFC 3339), so a report from an
	// earlier daemon that reused the pid is told apart.
	StartedAt string `json:"started_at,omitempty"`
	// Enrolled is true when the daemon read an enrolment record, the bearer
	// and the agent signing key at its last push cycle.
	Enrolled bool `json:"enrolled"`
	// Backend is the credential store the daemon opened.
	Backend string `json:"backend,omitempty"`
	// Reason says why the daemon is not enrolled ("" when Enrolled).
	Reason string `json:"reason,omitempty"`
	// At is when the view last changed (RFC 3339).
	At string `json:"at"`
}

// SaveOrgDaemonCredentialReport records r, replacing the same daemon's
// previous report. Best effort for the caller: a failed write only leaves
// the previous report.
func (s *Store) SaveOrgDaemonCredentialReport(ctx context.Context, r OrgDaemonCredentialReport) error {
	all, err := s.LoadOrgDaemonCredentialReports(ctx)
	if err != nil {
		all = nil
	}
	out := []OrgDaemonCredentialReport{r}
	for _, prev := range all {
		if prev.PID != r.PID {
			out = append(out, prev)
		}
	}
	if len(out) > maxDaemonCredentialReports {
		out = out[:maxDaemonCredentialReports]
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	raw, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("store.SaveOrgDaemonCredentialReport: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		OrgDaemonCredentialKey, string(raw)); err != nil {
		return fmt.Errorf("store.SaveOrgDaemonCredentialReport: %w", err)
	}
	return nil
}

// LoadOrgDaemonCredentialReports returns every stored report, by pid. The
// caller keeps the ones whose daemon is still running.
func (s *Store) LoadOrgDaemonCredentialReports(ctx context.Context) ([]OrgDaemonCredentialReport, error) {
	v, err := s.readMeta(ctx, OrgDaemonCredentialKey)
	if err != nil {
		return nil, fmt.Errorf("store.LoadOrgDaemonCredentialReports: %w", err)
	}
	if v == "" {
		return nil, nil
	}
	var out []OrgDaemonCredentialReport
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return nil, fmt.Errorf("store.LoadOrgDaemonCredentialReports: %w", err)
	}
	return out, nil
}
