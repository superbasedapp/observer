//go:build !sbo_omit_security

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/projectroi"
)

// secchange_facts.go gathers what a change record says about one commit
// from the node's attribution (security plan 7.10 "What it is"): the
// commit ownership fold (LoadCommitOwnership, the same composition the
// Projects page and the org wire use), the human lines from file_changes,
// the guard verdicts and taint on the record's sessions, the security
// findings and scans of the change, the exceptions in force, and a
// sandbox run's evidence when a session ran in one. Every read is
// read-only; nothing here writes. Never prompt text.

// ChangeFileFacts is one changed file of the commit.
type ChangeFileFacts struct {
	PathHash string
	RelPath  string
	// Added is the commit's added lines for the file (numstat).
	Added int
	// AI is the AI code lines the attribution carried into this commit;
	// Human the editor-reported human lines in the window.
	AI    int
	Human int
}

// ChangeEvidence is a sandbox run's evidence reference.
type ChangeEvidence struct {
	RunID          string
	Digest         string
	IsolationClass string
	CaptureLevel   string
	KeyCustody     string
	Verification   string
}

// ChangeFacts is everything a change record says about one commit.
type ChangeFacts struct {
	ProjectID    int64
	CommitID     int64
	SHA          string
	CommittedAt  time.Time
	PatchFP      string
	PatchFPState string
	Files        []ChangeFileFacts
	Sessions     []string
	Tools        []string
	Models       []string
	ToolVersions []string
	PromptIDs    []string
	HumanCapture string
	GuardEvents  int64
	GuardDenies  int64
	GuardAsks    int64
	// GuardApprovedAsks counts the asks and denies a person's approval or
	// an org grant turned into a flag (guard_events.degraded_from
	// "approved" or "org_grant", lane SEC-F2B).
	GuardApprovedAsks int64
	Taint             int64
	Scanners          []string
	Packs             []string
	FindingsOpen      int64
	// FindingsBlocking counts the open high and critical findings.
	FindingsBlocking int64
	Exceptions       []string
	Evidence         *ChangeEvidence
}

// ChangeFactsSkip says why a commit gets no record.
type ChangeFactsSkip string

// The ChangeFactsSkip values (empty: the commit gets a record).
const (
	ChangeSkipUnknownCommit ChangeFactsSkip = "unknown_commit"
	ChangeSkipNotOwned      ChangeFactsSkip = "no_ai_attribution"
)

// minEvidenceConfidence is the terminal-run correlation floor a session
// must reach before a record names the run's evidence (termrun's own
// MinLinkConfidence, kept as a number so this file imports no termrun).
const minEvidenceConfidence = 0.5

// LoadChangeFacts gathers one commit's facts. skip is non-empty when the
// commit gets no record: it is not in the ledger, or the attribution ties
// no AI session to it (a merge, an unreachable or foreign-author commit,
// or one with no AI edits; projectroi.Ownership's gates decide).
func (s *Store) LoadChangeFacts(ctx context.Context, projectID int64, rootHash, sha string, linkWindow time.Duration) (ChangeFacts, ChangeFactsSkip, error) {
	f := ChangeFacts{ProjectID: projectID, SHA: sha}
	var committed string
	var fp sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id, committed_at, patch_fp, patch_fp_state FROM project_commits WHERE project_id = ? AND sha = ?`, projectID, sha).
		Scan(&f.CommitID, &committed, &fp, &f.PatchFPState)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ChangeSkipUnknownCommit, nil
	}
	if err != nil {
		return f, "", fmt.Errorf("store.LoadChangeFacts: %w", err)
	}
	f.CommittedAt, f.PatchFP = parseCommitTime(committed), fp.String
	if linkWindow <= 0 {
		linkWindow = projectroi.DefaultLinkWindow
	}
	own, err := s.LoadCommitOwnership(ctx, projectID, f.CommittedAt.Add(-linkWindow), f.CommittedAt.Add(time.Minute), linkWindow, OwnershipCaps{})
	if err != nil {
		return f, "", fmt.Errorf("store.LoadChangeFacts: %w", err)
	}
	o, ok := own.Ownership[f.CommitID]
	if !ok || len(o.Contributors) == 0 {
		return f, ChangeSkipNotOwned, nil
	}
	if err := s.changeFiles(ctx, &f, own.Linkage); err != nil {
		return f, "", err
	}
	for _, c := range o.Contributors {
		f.Sessions = append(f.Sessions, c.SessionID)
		for _, id := range c.PromptActionIDs {
			f.PromptIDs = append(f.PromptIDs, strconv.FormatInt(id, 10))
		}
	}
	steps := []func(context.Context, *ChangeFacts, string) error{
		s.changeSessions, s.changeHuman, s.changeGuard, s.changeFindings, s.changeEvidence,
	}
	for _, step := range steps {
		if err := step(ctx, &f, rootHash); err != nil {
			return f, "", fmt.Errorf("store.LoadChangeFacts: %w", err)
		}
	}
	return f, "", nil
}

// changeFiles fills the commit's files and the AI lines the linkage
// carried into it.
func (s *Store) changeFiles(ctx context.Context, f *ChangeFacts, l projectroi.Linkage) error {
	files, err := s.loadCommitFilesByIDs(ctx, []int64{f.CommitID})
	if err != nil {
		return fmt.Errorf("store.LoadChangeFacts: %w", err)
	}
	ai := map[string]int{}
	for _, ch := range l.Chains {
		for _, cf := range ch.Files {
			if cf.CommitID == f.CommitID {
				ai[cf.PathHash] += cf.Added + cf.Modified
			}
		}
	}
	for _, r := range files {
		f.Files = append(f.Files, ChangeFileFacts{PathHash: r.PathHash, RelPath: r.RelPath, Added: r.Added, AI: ai[r.PathHash]})
	}
	return nil
}

func changeArgs(ss []string) []any {
	out := make([]any, len(ss))
	for i, v := range ss {
		out[i] = v
	}
	return out
}

// changeSessions fills the agents, models and tool versions.
func (s *Store) changeSessions(ctx context.Context, f *ChangeFacts, _ string) error {
	//nolint:gosec // G202: only a placeholder list is concatenated.
	rows, err := s.db.QueryContext(ctx, `SELECT tool, COALESCE(model, ''), COALESCE(tool_version, '') FROM sessions WHERE id IN (`+placeholders(len(f.Sessions))+`)`, changeArgs(f.Sessions)...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tool, model, ver string
		if err := rows.Scan(&tool, &model, &ver); err != nil {
			return err
		}
		f.Tools = append(f.Tools, tool)
		if model != "" {
			f.Models = append(f.Models, model)
		}
		if ver != "" {
			f.ToolVersions = append(f.ToolVersions, tool+"@"+ver)
		}
	}
	return rows.Err()
}

// changeHuman adds the editor-reported human lines on the commit's files
// in the link window before the commit, and the window's human capture
// state (none means unmeasured, never zero).
func (s *Store) changeHuman(ctx context.Context, f *ChangeFacts, _ string) error {
	since := f.CommittedAt.Add(-projectroi.DefaultLinkWindow)
	_, _, hc, err := s.LoadProjectLOCTotals(ctx, f.ProjectID, since, f.CommittedAt.Add(time.Minute))
	if err != nil {
		return err
	}
	f.HumanCapture = hc
	if len(f.Files) == 0 {
		return nil
	}
	hashes := make([]string, len(f.Files))
	for i, x := range f.Files {
		hashes[i] = x.PathHash
	}
	args := append([]any{f.ProjectID, since.UTC().Format(time.RFC3339), f.CommittedAt.UTC().Add(time.Minute).Format(time.RFC3339)}, changeArgs(hashes)...)
	//nolint:gosec // G202: only a placeholder list is concatenated.
	rows, err := s.db.QueryContext(ctx, `SELECT file_path_hash, COALESCE(SUM(added_code + modified_code), 0) FROM file_changes
		WHERE project_id = ? AND actor = 'human' AND saved_at >= ? AND saved_at < ? AND file_path_hash IN (`+placeholders(len(hashes))+`)
		GROUP BY file_path_hash`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	human := map[string]int{}
	for rows.Next() {
		var h string
		var n int
		if err := rows.Scan(&h, &n); err != nil {
			return err
		}
		human[h] = n
	}
	for i := range f.Files {
		f.Files[i].Human = human[f.Files[i].PathHash]
	}
	return rows.Err()
}

// changeGuard counts the guard verdicts and taint events on the sessions.
func (s *Store) changeGuard(ctx context.Context, f *ChangeFacts, _ string) error {
	//nolint:gosec // G202: only a placeholder list is concatenated.
	return s.db.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'ask' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN category = 'taint' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN degraded_from IN ('approved', 'org_grant') THEN 1 ELSE 0 END), 0)
		FROM guard_events WHERE session_id IN (`+placeholders(len(f.Sessions))+`)`, changeArgs(f.Sessions)...).
		Scan(&f.GuardEvents, &f.GuardDenies, &f.GuardAsks, &f.Taint, &f.GuardApprovedAsks)
}

// changeFindings fills the findings of the change (recorded on the commit,
// or seen added in it), the scanners and packs that ran on the project in
// the window, and the exceptions in force.
func (s *Store) changeFindings(ctx context.Context, f *ChangeFacts, rootHash string) error {
	err := s.db.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'open' AND severity IN ('high', 'critical') THEN 1 ELSE 0 END), 0)
		FROM sec_findings WHERE project_root_hash = ? AND (commit_sha = ? OR id IN (SELECT finding_id FROM sec_finding_commits WHERE commit_sha = ?))`,
		rootHash, f.SHA, f.SHA).Scan(&f.FindingsOpen, &f.FindingsBlocking)
	if err != nil {
		return err
	}
	since := f.CommittedAt.Add(-projectroi.DefaultLinkWindow).UTC().Format(time.RFC3339)
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT driver FROM sec_scan_runs WHERE project_root_hash = ? AND started_at >= ? ORDER BY driver LIMIT 64`, rootHash, since)
	if err != nil {
		return err
	}
	if err := changeCollect(rows, &f.Scanners); err != nil {
		return err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT DISTINCT rule_pack || '@' || rule_pack_version FROM sec_findings
		WHERE project_root_hash = ? AND rule_pack != '' AND rule_pack_version != '' ORDER BY 1 LIMIT 64`, rootHash)
	if err != nil {
		return err
	}
	if err := changeCollect(rows, &f.Packs); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	rows, err = s.db.QueryContext(ctx, `SELECT 'exc-' || id FROM sec_finding_exceptions
		WHERE project_root_hash = ? AND ended_at = '' AND (expires_at = '' OR expires_at > ?) ORDER BY id LIMIT 64`, rootHash, now)
	if err != nil {
		return err
	}
	return changeCollect(rows, &f.Exceptions)
}

func changeCollect(rows *sql.Rows, dst *[]string) error {
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return err
		}
		*dst = append(*dst, v)
	}
	return rows.Err()
}

// changeEvidence names the evidence envelope of a sandboxed terminal run
// one of the record's sessions ran in (roadmap F0-13). No run, or a run
// without isolation, leaves the record without evidence, complete and
// valid.
func (s *Store) changeEvidence(ctx context.Context, f *ChangeFacts, _ string) error {
	args := append([]any{minEvidenceConfidence}, changeArgs(f.Sessions)...)
	//nolint:gosec // G202: only a placeholder list is concatenated.
	rows, err := s.db.QueryContext(ctx, `SELECT r.run_id, r.evidence_digest, r.isolation_class, r.capture_level, r.key_custody, r.verification
		FROM terminal_run_session c JOIN terminal_run r ON r.run_id = c.run_id
		WHERE c.confidence >= ? AND c.session_id IN (`+placeholders(len(f.Sessions))+`)
		  AND r.evidence_digest != '' AND r.isolation_class NOT IN ('', 'none')
		ORDER BY r.run_id LIMIT 1`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		var e ChangeEvidence
		if err := rows.Scan(&e.RunID, &e.Digest, &e.IsolationClass, &e.CaptureLevel, &e.KeyCustody, &e.Verification); err != nil {
			return err
		}
		f.Evidence = &e
	}
	sort.Strings(f.Sessions)
	return rows.Err()
}

// BoxCommit is a commit a sandbox box returned (commitscan.Root.BoxRef):
// it is not in the commit ledger, so its files come from the scan itself.
type BoxCommit struct {
	SHA         string
	CommittedAt time.Time
	Files       []ChangeFileFacts
}

// maxBoxSessions bounds the sessions a box record names.
const maxBoxSessions = 64

// LoadBoxChangeFacts gathers the facts of a commit a sandbox run returned
// (lane SEC-F2B; security plan 7.10 revision 2.3 M7): the run's sessions
// come from the terminal-run correlation (confidence at least
// minEvidenceConfidence), a file's AI lines are the AI lines those
// sessions wrote to it (file_changes, never more than the commit added),
// and the rest is read as LoadChangeFacts reads it. skip is
// ChangeSkipNotOwned when no session is tied to the run.
func (s *Store) LoadBoxChangeFacts(ctx context.Context, projectID int64, rootHash, runID string, c BoxCommit) (ChangeFacts, ChangeFactsSkip, error) {
	f := ChangeFacts{ProjectID: projectID, SHA: c.SHA, CommittedAt: c.CommittedAt, Files: append([]ChangeFileFacts(nil), c.Files...)}
	if runID == "" {
		return f, ChangeSkipNotOwned, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT session_id FROM terminal_run_session
		WHERE run_id = ? AND confidence >= ? AND session_id != '' ORDER BY session_id LIMIT ?`, runID, minEvidenceConfidence, maxBoxSessions)
	if err != nil {
		return f, "", fmt.Errorf("store.LoadBoxChangeFacts: %w", err)
	}
	if err := changeCollect(rows, &f.Sessions); err != nil {
		return f, "", fmt.Errorf("store.LoadBoxChangeFacts: %w", err)
	}
	if len(f.Sessions) == 0 {
		return f, ChangeSkipNotOwned, nil
	}
	if err := s.boxAILines(ctx, &f); err != nil {
		return f, "", fmt.Errorf("store.LoadBoxChangeFacts: %w", err)
	}
	steps := []func(context.Context, *ChangeFacts, string) error{
		s.changeSessions, s.changeHuman, s.changeGuard, s.changeFindings, s.changeEvidence,
	}
	for _, step := range steps {
		if err := step(ctx, &f, rootHash); err != nil {
			return f, "", fmt.Errorf("store.LoadBoxChangeFacts: %w", err)
		}
	}
	return f, "", nil
}

// boxAILines fills each file's AI lines from the run sessions' AI edits.
func (s *Store) boxAILines(ctx context.Context, f *ChangeFacts) error {
	if len(f.Files) == 0 {
		return nil
	}
	hashes := make([]string, len(f.Files))
	for i, x := range f.Files {
		hashes[i] = x.PathHash
	}
	args := append(changeArgs(f.Sessions), changeArgs(hashes)...)
	//nolint:gosec // G202: only placeholder lists are concatenated.
	rows, err := s.db.QueryContext(ctx, `SELECT file_path_hash, COALESCE(SUM(added_code + modified_code), 0) FROM file_changes
		WHERE actor = 'ai' AND session_id IN (`+placeholders(len(f.Sessions))+`) AND file_path_hash IN (`+placeholders(len(hashes))+`)
		GROUP BY file_path_hash`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	ai := map[string]int{}
	for rows.Next() {
		var h string
		var n int
		if err := rows.Scan(&h, &n); err != nil {
			return err
		}
		ai[h] = n
	}
	for i := range f.Files {
		f.Files[i].AI = min(ai[f.Files[i].PathHash], f.Files[i].Added)
	}
	return rows.Err()
}
