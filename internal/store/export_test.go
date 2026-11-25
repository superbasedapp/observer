package store

// Test-only accessors and SubjectTool shorthands. Production code reaches the
// same state through the generic methods (FinishInstallRecord,
// FinishUninstallRecord, SetInstallRecordStatus, ListSandboxEgressRefusals)
// or does not need it at all, so these live here and are compiled only into
// this package's tests. The security-tagged one is in
// secfindings_export_test.go.

import "context"

// CountAPITurns returns the total number of rows in api_turns.
func (s *Store) CountAPITurns(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_turns`).Scan(&n)
	return n, err
}

// OrgSnapshotGateStats returns the per-family skip / recompute tallies since
// process start.
func (s *Store) OrgSnapshotGateStats() (skipped, recomputed map[string]int64) {
	return s.snap.counters()
}

// OrgSnapshotOversizedRows returns, per snapshot family, how many distinct
// rows since process start were larger than the whole snapshot budget
// ([org_client] max_push_bytes minus the envelope reserve) and so could not
// ship. Each is also logged once as a warning.
func (s *Store) OrgSnapshotOversizedRows() map[string]int64 {
	return s.snap.oversizedCounts()
}

// FinishToolInstall settles an in-flight AI-tool INSTALL: CAS from `from` to
// f.Status, stamping the exit code, finish time and the post-install
// resolution. ok=false when the row was not in `from` (already settled).
func (s *Store) FinishToolInstall(ctx context.Context, id int64, from string, f ToolInstallFinish) (bool, error) {
	return s.FinishInstallRecord(ctx, SubjectTool, id, from, f)
}

// FinishToolUninstall settles an in-flight AI-tool UNINSTALL: CAS from
// `from` to f.Status with the uninstall exit code, finish time and the
// post-uninstall resolution (a binary still found means another install
// shadows it).
func (s *Store) FinishToolUninstall(ctx context.Context, id int64, from string, f ToolInstallFinish) (bool, error) {
	return s.FinishUninstallRecord(ctx, SubjectTool, id, from, f)
}

// SetToolInstallStatus is the bare CAS used for the orphan sweep of an
// AI-tool record (an in-flight row no live process tracks).
func (s *Store) SetToolInstallStatus(ctx context.Context, id int64, from, to string) (bool, error) {
	return s.SetInstallRecordStatus(ctx, SubjectTool, id, from, to)
}

// ListSandboxEgressRefusalsByProject returns a page of the refusals of runs
// attributed to projectRoot, newest first.
func (s *Store) ListSandboxEgressRefusalsByProject(ctx context.Context, projectRoot string, before int64, limit int) ([]SandboxEgressRefusal, error) {
	return s.ListSandboxEgressRefusals(ctx, SandboxEgressRefusalQuery{ProjectRoot: projectRoot, Before: before, Limit: limit})
}
