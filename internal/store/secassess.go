package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// secassess.go is the store seam of the agent-run security assessments module
// (docs/plans/security-assessments-module-plan-2026-11-13.md sections 13.5 to
// 13.8): the guard-approval rows a run owns, the covering-approval lookup the
// guard names in a verdict, the per-run count of verdicts a relaxation changed
// and the lifecycle audit rows on the guard-events chain. It adds no table and
// no migration. guard_approvals and guard_events keep their one writer each:
// the approval rows are written here only through the conditional statements
// below (never GrantGuardApproval, which is grant-or-extend), and the audit
// rows go through insertGuardEventsTx, the chain owner.

// SecAssessEventRuleID is the rule_id of the lifecycle audit rows. Like
// GuardApprovalAuditRuleID it is a marker row: event_kind 'audit', decision
// 'allow', never a verdict, and excluded from verdict counts.
const SecAssessEventRuleID = "sec_assessment"

// SecAssessToolPrefix is the prefix of the audit rows' tool column; the phase
// follows ("assessment.launch"). The tool column ships on every node, so the
// phase is visible to the org whatever the content-sharing setting is.
const SecAssessToolPrefix = "assessment."

// CreateApprovalIfAbsent inserts the approval row only when its key (rule,
// scope, session, project hash) holds no row at all, expired or not, with ONE
// statement (no read-then-write race), and appends the same guard_approval
// audit event GrantGuardApproval does in the same transaction. When the key is
// taken it changes nothing and reports created=false, so a developer's own
// row, or another run's, is never extended or overwritten.
func (s *Store) CreateApprovalIfAbsent(ctx context.Context, a GuardApprovalRow) (id int64, created bool, err error) {
	if a.RuleID == "" || a.Scope == "" || a.GrantedBy == "" || a.ExpiresAt.IsZero() {
		return 0, false, errors.New("store.CreateApprovalIfAbsent: rule_id, scope, granted_by and expires_at required")
	}
	if a.TS.IsZero() {
		a.TS = time.Now().UTC()
	}
	expires := timestamp(a.ExpiresAt)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("store.CreateApprovalIfAbsent: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO guard_approvals (ts, rule_id, scope, session_id, project_root_hash, granted_by, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (rule_id, scope, session_id, project_root_hash) DO NOTHING`,
		timestamp(a.TS), a.RuleID, a.Scope, a.SessionID, a.ProjectRootHash, a.GrantedBy, expires)
	if err != nil {
		return 0, false, fmt.Errorf("store.CreateApprovalIfAbsent: insert: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, false, nil
	}
	if id, err = res.LastInsertId(); err != nil {
		return 0, false, fmt.Errorf("store.CreateApprovalIfAbsent: last id: %w", err)
	}
	if err := insertGuardEventsTx(ctx, tx, []GuardEventRow{approvalAudit{op: "create", id: id, grant: a, newExpires: expires}.row()}); err != nil {
		return 0, false, fmt.Errorf("store.CreateApprovalIfAbsent: audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("store.CreateApprovalIfAbsent: commit: %w", err)
	}
	return id, true, nil
}

// RenewOwnedApproval moves the expiry of the approval row id from was to now,
// only while the row is still the one the caller created: the same id, the
// same grantor and the same expiry the caller last wrote. A row the developer
// extended, revoked or replaced matches nothing and is left alone
// (renewed=false).
func (s *Store) RenewOwnedApproval(ctx context.Context, id int64, grantedBy string, was, now time.Time) (renewed bool, err error) {
	if id <= 0 || grantedBy == "" {
		return false, errors.New("store.RenewOwnedApproval: id and granted_by required")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE guard_approvals SET expires_at = ? WHERE id = ? AND granted_by = ? AND expires_at = ?`,
		timestamp(now), id, grantedBy, timestamp(was))
	if err != nil {
		return false, fmt.Errorf("store.RenewOwnedApproval: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// DeleteOwnedApproval removes the approval row id only while it is still the
// one the caller created (the same id, grantor and last-written expiry), and
// returns whether a row was removed. It is the only delete a run makes.
func (s *Store) DeleteOwnedApproval(ctx context.Context, id int64, grantedBy string, expires time.Time) (deleted bool, err error) {
	if id <= 0 || grantedBy == "" {
		return false, errors.New("store.DeleteOwnedApproval: id and granted_by required")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM guard_approvals WHERE id = ? AND granted_by = ? AND expires_at = ?`,
		id, grantedBy, timestamp(expires))
	if err != nil {
		return false, fmt.Errorf("store.DeleteOwnedApproval: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ActiveApprovalOnKey returns the non-expired approval row on exactly this key
// (rule, scope, session id, project hash), if any. The module reads it to tell
// a row another run holds from the developer's own before it launches.
func (s *Store) ActiveApprovalOnKey(ctx context.Context, ruleID, scope, sessionID, projectRootHash string, now time.Time) (GuardApprovalRow, bool, error) {
	var r GuardApprovalRow
	var ts, expires string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, ts, rule_id, scope, session_id, project_root_hash, granted_by, expires_at
		  FROM guard_approvals
		 WHERE rule_id = ? AND scope = ? AND session_id = ? AND project_root_hash = ?
		   AND (expires_at = '' OR expires_at > ?)`,
		ruleID, scope, sessionID, projectRootHash, timestamp(now)).
		Scan(&r.ID, &ts, &r.RuleID, &r.Scope, &r.SessionID, &r.ProjectRootHash, &r.GrantedBy, &expires)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return GuardApprovalRow{}, false, nil
	case err != nil:
		return GuardApprovalRow{}, false, fmt.Errorf("store.ActiveApprovalOnKey: %w", err)
	}
	r.TS = parseStamp(ts)
	if expires != "" {
		r.ExpiresAt = parseStamp(expires)
	}
	return r, true, nil
}

// ApprovalCover is the covering approval ApprovalCoverFor found.
type ApprovalCover struct {
	Found     bool
	ID        int64
	GrantedBy string
}

// ApprovalCoverFor is ApprovalActiveFor with the covering row: the same
// scope semantics ('global' always, 'session' on a non-empty equal session id,
// 'project' on a non-empty equal project hash; 'once' is ignored) in the same
// single read, answered with the row's id and grantor. When several rows cover,
// the narrowest scope wins (session, then project, then global), then the
// lowest id, so a verdict names exactly one approval.
func (s *Store) ApprovalCoverFor(ctx context.Context, ruleID, sessionID, projectRootHash string, now time.Time) (ApprovalCover, error) {
	const q = `
		SELECT id, granted_by FROM guard_approvals
		WHERE rule_id = ?
		  AND (expires_at = '' OR expires_at > ?)
		  AND (
		        scope = 'global'
		     OR (scope = 'session' AND session_id != '' AND session_id = ?)
		     OR (scope = 'project' AND project_root_hash != '' AND project_root_hash = ?)
		  )
		ORDER BY CASE scope WHEN 'session' THEN 0 WHEN 'project' THEN 1 ELSE 2 END, id
		LIMIT 1`
	var c ApprovalCover
	err := s.db.QueryRowContext(ctx, q, ruleID, timestamp(now), sessionID, projectRootHash).Scan(&c.ID, &c.GrantedBy)
	switch {
	case err == nil:
		c.Found = true
		return c, nil
	case errors.Is(err, sql.ErrNoRows):
		return ApprovalCover{}, nil
	default:
		return ApprovalCover{}, fmt.Errorf("store.ApprovalCoverFor: %w", err)
	}
}

// RelaxedVerdicts is the count of verdicts a run's relaxations changed.
type RelaxedVerdicts struct {
	// Exact counts verdicts a local approval of the run lifted: the verdict's
	// reason names the run's grantor (guard.approvedNote).
	Exact int
	// Approx counts verdicts an org grant changed on the rules the run
	// relaxed, in the run's sessions, while the run lived. An org grant is
	// named by id, not by run, so this is every such verdict, not only the
	// run's own.
	Approx int
}

// CountRelaxedVerdicts counts what a run's relaxations changed between since
// and until (zero until is open): exact for a local approval (the cover note
// carries the run's grantor), approximate for an org grant. sessions and
// ruleIDs may be empty, which counts nothing for that half.
func (s *Store) CountRelaxedVerdicts(ctx context.Context, grantedBy string, sessions, ruleIDs []string, since, until time.Time) (RelaxedVerdicts, error) {
	var out RelaxedVerdicts
	if len(ruleIDs) == 0 {
		return out, nil
	}
	rules, ruleArgs := inClause(ruleIDs)
	window := ` AND ts >= ?`
	args := []any{timestamp(since)}
	if !until.IsZero() {
		window += ` AND ts <= ?`
		args = append(args, timestamp(until))
	}
	if grantedBy != "" {
		q := `SELECT COUNT(*) FROM guard_events WHERE event_kind != 'audit' AND degraded_from = 'approved'
		       AND rule_id IN (` + rules + `) AND instr(reason, ?) > 0` + window
		a := append(append([]any(nil), ruleArgs...), "("+grantedBy+") covers")
		a = append(a, args...)
		if err := s.db.QueryRowContext(ctx, q, a...).Scan(&out.Exact); err != nil { //nolint:gosec // G202: q is fixed text plus a placeholder list of the rule ids
			return RelaxedVerdicts{}, fmt.Errorf("store.CountRelaxedVerdicts: exact: %w", err)
		}
	}
	if len(sessions) > 0 {
		sess, sessArgs := inClause(sessions)
		q := `SELECT COUNT(*) FROM guard_events WHERE event_kind != 'audit' AND degraded_from IN ('org_grant', 'org_grant_soften')
		       AND rule_id IN (` + rules + `) AND session_id IN (` + sess + `)` + window
		a := append(append(append([]any(nil), ruleArgs...), sessArgs...), args...)
		if err := s.db.QueryRowContext(ctx, q, a...).Scan(&out.Approx); err != nil { //nolint:gosec // G202: q is fixed text plus placeholder lists
			return RelaxedVerdicts{}, fmt.Errorf("store.CountRelaxedVerdicts: org: %w", err)
		}
	}
	return out, nil
}

// inClause returns "?,?,?" and the args for a list.
func inClause(vals []string) (string, []any) {
	ph := make([]string, len(vals))
	args := make([]any, len(vals))
	for i, v := range vals {
		ph[i], args[i] = "?", v
	}
	return strings.Join(ph, ","), args
}

// SecAssessEvent is one lifecycle audit row of an assessment run.
type SecAssessEvent struct {
	TS time.Time
	// Phase is the closed phase: held, launch, end, import, validated or cancel.
	Phase string
	// SessionID is the run's bound session when known ("" otherwise).
	SessionID string
	// ProjectRootHash is the project's root hash (the row's target_hash).
	ProjectRootHash string
	// Detail is the content-free line the row's reason carries (ids, rule ids,
	// counts, enum words); the push strips it unless the node shares raw
	// content, and a managed node does.
	Detail string
}

// SecAssessDetailMax is the most bytes of a Detail one audit row keeps; the
// rest is cut. The launch row's line carries every effective
// [security.assessments] value and each relaxation, which is what sets the
// size (a dashboard test measures its worst case against this, with the
// longest value of every key). A line past it loses its tail, which is where
// the relaxations are, so the cap is sized to the worst case, not the usual one.
const SecAssessDetailMax = 1280

// secAssessReasonMaxRunes is the most runes the stored Reason of an audit row
// keeps: the Detail plus the words before it ("security assessment validated: "
// is the longest, 31 runes). The guard store cuts every other row's Reason at
// guardMaxReasonRunes (1024), which counts those words and would take the
// launch line's tail; this rule's rows are given the room their cap promises
// (guardReasonMaxRunes), and nothing else's.
const secAssessReasonMaxRunes = SecAssessDetailMax + 32

// secAssessPhases is the closed phase vocabulary.
var secAssessPhases = map[string]bool{"held": true, "launch": true, "end": true, "import": true, "validated": true, "cancel": true}

// RecordSecAssessEvent appends one lifecycle audit row to the guard-events
// chain: event_kind 'audit', rule_id 'sec_assessment', category 'posture',
// severity 'info', decision 'allow', tool 'assessment.<phase>' (which ships on
// every node), target_hash the project root hash. Nothing the agent wrote and
// no path is carried.
func (s *Store) RecordSecAssessEvent(ctx context.Context, e SecAssessEvent) error {
	if !secAssessPhases[e.Phase] {
		return fmt.Errorf("store.RecordSecAssessEvent: unknown phase %q", e.Phase)
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	detail := e.Detail
	if len(detail) > SecAssessDetailMax {
		detail = detail[:SecAssessDetailMax]
	}
	_, err := s.InsertGuardEvents(ctx, []GuardEventRow{{
		TS:         e.TS,
		SessionID:  e.SessionID,
		Tool:       SecAssessToolPrefix + e.Phase,
		EventKind:  "audit",
		RuleID:     SecAssessEventRuleID,
		Category:   "posture",
		Severity:   "info",
		Decision:   "allow",
		Source:     "observer",
		Reason:     "security assessment " + e.Phase + ": " + detail,
		TargetHash: e.ProjectRootHash,
	}})
	if err != nil {
		return fmt.Errorf("store.RecordSecAssessEvent: %w", err)
	}
	return nil
}
