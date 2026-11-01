//go:build !sbo_omit_security

package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// The security pillar's findings store (agent migration 177; security
// pillar plan section 4.6). ONE OWNER: sec_findings, sec_finding_events,
// sec_scan_runs and sec_baselines are written exclusively here, and
// internal/secsvc is the only caller that writes findings. NODE-LOCAL:
// every sec_* table is in the privacy sentinel. A feature-owned file: it
// leaves the binary with sbo_omit_security (the tables stay, empty).

// Finding event kinds (the CHECK constraint of migration 177).
const (
	SecEventSeen              = "seen"
	SecEventClosed            = "closed"
	SecEventReopened          = "reopened"
	SecEventSuppressed        = "suppressed"
	SecEventExceptionExpired  = "exception_expired"
	SecEventVerdictReferenced = "verdict_referenced"
	SecEventBaselineSet       = "baseline_set"
	SecEventBaselineReset     = "baseline_reset"
	// SecEventFeedbackSent: the finding's feedback line was put into the
	// agent's post-tool reply (migration 189, lane sec-h); the detail is
	// the session id.
	SecEventFeedbackSent = "feedback_sent"
)

// ErrSecFindingNotFound reports an unknown finding id.
var ErrSecFindingNotFound = errors.New("store: security finding not found")

const secTime = time.RFC3339Nano

// crockford is the ULID alphabet.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newSecFindingID returns a node-local ULID: 48 bits of milliseconds and
// 80 random bits, Crockford base32.
func newSecFindingID(now time.Time) (string, error) {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], uint64(now.UnixMilli())<<16)
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("store.newSecFindingID: %w", err)
	}
	var out [26]byte
	// 128 bits into 26 five-bit groups (the top group holds 3 bits).
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:]), nil
}

func jsonOrEmpty(v any, empty bool) string {
	if empty {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// closedStatuses are the statuses a rescan that sees the finding again
// reopens.
var closedStatuses = map[policy.FindingStatus]bool{
	policy.FindingStatusNotReproduced: true, policy.FindingStatusFixedVerified: true,
}

// UpsertSecFinding records one sighting of a finding: a new local key is
// inserted (a seen event), a known one has its location, grading and
// last_seen refreshed, and a finding that had been closed as fixed or not
// reproduced is reopened (a reopened event). A suppressed, accepted or
// false-positive finding keeps its status. A finding from box work
// (Lineage.RunID set) writes no file sighting and leaves an existing host
// finding of the same identity as it is, adding only its commit row. It
// returns the finding id and whether the row is new. f must be normalized
// (secfinding.Normalize).
func (s *Store) UpsertSecFinding(ctx context.Context, f secfinding.Finding, now time.Time) (string, bool, error) {
	if f.Project.RootHash == "" || f.LocalKey == "" || f.Rule.ID == "" {
		return "", false, errors.New("store.UpsertSecFinding: a finding needs a project, a local key and a rule id")
	}
	ts := now.UTC().Format(secTime)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, fmt.Errorf("store.UpsertSecFinding: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Box work (a commit a sandbox box made: Lineage.RunID is set; lane
	// sec-box audit finding 1) is history, never the developer's own tree:
	// it writes the commit row that holds the push, but no file sighting,
	// and it never moves, re-grades or reopens a host finding (run_id '')
	// of the same identity. So a secret that lives only on a box ref gates
	// the push that would send it, not the developer's own commits.
	box := f.Lineage.RunID != ""
	var id, status, rowRun string
	err = tx.QueryRowContext(ctx, `SELECT id, status, run_id FROM sec_findings WHERE project_root_hash = ? AND local_key = ?`,
		f.Project.RootHash, f.LocalKey).Scan(&id, &status, &rowRun)
	created := false
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if id, err = newSecFindingID(now); err != nil {
			return "", false, err
		}
		if f.Status == "" {
			f.Status = policy.FindingStatusOpen
		}
		if f.FirstSeen.IsZero() {
			f.FirstSeen = now
		}
		if err := insertSecFinding(ctx, tx, id, f, ts); err != nil {
			return "", false, err
		}
		created = true
		if err := appendSecEvent(ctx, tx, id, f.Project.RootHash, SecEventSeen, "", ts); err != nil {
			return "", false, err
		}
	case err != nil:
		return "", false, fmt.Errorf("store.UpsertSecFinding: %w", err)
	case box && rowRun == "":
		// A host finding keeps its path, lines, grading and status; the box
		// commit only adds its commit row below.
	default:
		reopen := closedStatuses[policy.FindingStatus(status)]
		if _, err := tx.ExecContext(ctx, `UPDATE sec_findings SET
			rel_path = ?, start_line = ?, end_line = ?, path_aliases_json = ?, severity = ?, confidence = ?,
			scope = ?, engine_digest = ?, driver_version = ?, database_epoch = ?, last_seen = ?,
			status = CASE WHEN ? THEN 'open' ELSE status END,
			closed_at = CASE WHEN ? THEN '' ELSE closed_at END,
			org_key = CASE WHEN ? <> '' THEN ? ELSE org_key END
			WHERE id = ?`,
			f.Location.RelPath, f.Location.StartLine, f.Location.EndLine, jsonOrEmpty(f.Location.PathAliases, len(f.Location.PathAliases) == 0),
			string(f.Severity), string(f.Confidence), string(f.Scope), f.Engine.EngineDigest, f.Engine.DriverVersion,
			f.Engine.DatabaseEpoch, ts, reopen, reopen, f.OrgKey, f.OrgKey, id); err != nil {
			return "", false, fmt.Errorf("store.UpsertSecFinding: %w", err)
		}
		if reopen {
			if err := appendSecEvent(ctx, tx, id, f.Project.RootHash, SecEventReopened, "", ts); err != nil {
				return "", false, err
			}
		}
	}
	if f.Location.RelPath != "" && !box {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sec_finding_sightings (finding_id, rel_path, last_seen) VALUES (?,?,?)
			ON CONFLICT(finding_id, rel_path) DO UPDATE SET last_seen = excluded.last_seen`, id, f.Location.RelPath, ts); err != nil {
			return "", false, fmt.Errorf("store.UpsertSecFinding: sighting: %w", err)
		}
	}
	held := secCommitHeld(string(f.Category), string(f.Confidence))
	if !held {
		// A flag-only, non-secret finding is never held by a commit (lane
		// SEC-P4 decision 13, ruling P-165): drop any row an earlier build
		// wrote.
		if _, err := tx.ExecContext(ctx, `DELETE FROM sec_finding_commits WHERE finding_id = ?`, id); err != nil {
			return "", false, fmt.Errorf("store.UpsertSecFinding: commit: %w", err)
		}
	}
	if held && f.Scope == policy.FindingScopeCommit && IsCommitSHA(f.Commit.SHA) {
		// The commit that holds it is history the next push sends: the
		// finding stays open until that commit is pushed or gone (lane
		// sec-gate3, migration 185).
		if _, err := tx.ExecContext(ctx, `INSERT INTO sec_finding_commits (finding_id, commit_sha, last_seen) VALUES (?,?,?)
			ON CONFLICT(finding_id, commit_sha) DO UPDATE SET last_seen = excluded.last_seen`, id, strings.ToLower(f.Commit.SHA), ts); err != nil {
			return "", false, fmt.Errorf("store.UpsertSecFinding: commit: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("store.UpsertSecFinding: %w", err)
	}
	return id, created, nil
}

// IsCommitSHA reports whether s is a full commit id (40 or 64 hex
// characters), the only form a history row stores and the daemon passes
// to git.
func IsCommitSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// SecPushedNote is the fixed note a finding whose secret reached a remote
// carries (lane sec-gate4 milestone 1b, decision log P-039): it stays open
// with this note instead of closing as not reproduced, because removing
// the secret from the tree or the history does not take it back from the
// remote. ListSecFindings puts it ahead of the finding's fix hint.
const SecPushedNote = "already pushed: rotate the secret"

// SecClosedPackChanged is the closed-event detail of a not_reproduced close
// whose run had another rule pack version than the one the finding was
// recorded under (SecGoneQuery.PackVersion): the pack change (a retired or a
// narrowed rule) may be what closed it, so the close is no evidence of a fix
// and the finding is never eligible for fixed_verified (lane sec-g5 audit
// finding 5).
const SecClosedPackChanged = "not_reproduced:pack_changed"

// secPushedHint is the fix hint a finding is read with: SecPushedNote
// first when its secret reached a remote (reached is reached_remote_at),
// so every surface that lists or shows findings carries it.
func secPushedHint(reached, hint string) string {
	switch {
	case reached == "":
		return hint
	case hint == "":
		return SecPushedNote
	}
	return SecPushedNote + "; " + hint
}

// secCommitHoldRows is the commit hold's table (lane SEC-P4 decision 13,
// operator ruling P-165 on SECP-27), walked top-down, the first matching
// row deciding. A BLOCKING finding is held until proof of absence: a
// secret at any confidence, and any other finding that can block (high
// confidence: a code rule, a dependency finding), so an unpushed commit that
// holds one keeps the commit and push gates denying (S-792) after the tree
// is fixed. A FLAG-ONLY non-secret finding (below high confidence, it can
// never block, section 4.8) is never held: it closes on its own proof of
// absence. Only a secret carries SecPushedNote once pushed
// (secPushedNoted); a held non-secret finding is released by the push.
var secCommitHoldRows = []struct {
	name  string
	match func(category, confidence string) bool
	held  bool
}{
	{"secret", func(c, _ string) bool { return c == string(policy.FindingSecret) }, true},
	{"flag-only", func(_, conf string) bool { return conf != string(policy.FindingConfidenceHigh) }, false},
	{"blocking", func(string, string) bool { return true }, true},
}

// secPushedNoted reports whether a finding of this category is kept open
// with SecPushedNote once its commit reached a remote (ruling P-165:
// secrets only, because a pushed secret must be rotated; a pushed code or
// dependency finding closes on its own proof of absence).
func secPushedNoted(category string) bool { return category == string(policy.FindingSecret) }

// secCommitHeld reports whether the commit hold keeps a finding of this
// category and confidence open (secCommitHoldRows).
func secCommitHeld(category, confidence string) bool {
	for _, r := range secCommitHoldRows {
		if r.match(category, confidence) {
			return r.held
		}
	}
	return false
}

// secReachedNote is reached_remote_at as the fix hint reads it: empty for
// anything but a secret the commit hold keeps, so no non-secret finding
// shows SecPushedNote even when an earlier build stamped it (ruling P-165).
func secReachedNote(reached, category, confidence string) string {
	if !secCommitHeld(category, confidence) || !secPushedNoted(category) {
		return ""
	}
	return reached
}

// secQueryRower is the read half a transaction and the database share.
type secQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// secFindingKept reports whether a finding no file holds any more still
// stays open: an unpushed commit on record (sec_finding_commits) adds it,
// so the next push can still send it, or its secret already reached a
// remote (reached_remote_at), so it stays open with SecPushedNote until
// triage closes it (lane sec-gate4 milestone 1b). Such a finding never
// closes on a working-tree or later-commit proof of absence.
//
// A flag-only, non-secret finding (secCommitHeld false; lane SEC-P4
// decision 13, ruling P-165) is never kept, whatever an earlier build
// recorded; a blocking non-secret one is kept only while a commit row
// holds it, never by a reach (only a secret stays open once pushed).
func secFindingKept(ctx context.Context, q secQueryRower, id string) (bool, error) {
	var cat, conf string
	var reached, committed bool
	err := q.QueryRowContext(ctx, `SELECT f.category, f.confidence, f.reached_remote_at <> '',
		EXISTS (SELECT 1 FROM sec_finding_commits c WHERE c.finding_id = f.id)
		FROM sec_findings f WHERE f.id = ? AND (f.reached_remote_at <> ''
		OR EXISTS (SELECT 1 FROM sec_finding_commits c WHERE c.finding_id = f.id)) LIMIT 1`, id).Scan(&cat, &conf, &reached, &committed)
	switch {
	case err == nil:
		return secCommitHeld(cat, conf) && (committed || (reached && secPushedNoted(cat))), nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	}
	return false, fmt.Errorf("store.secFindingKept: %w", err)
}

// CloseSecFindingNotReproduced is the hold-aware close of one finding a
// run no longer reports (lane sec-gate4 milestone 1c): it moves an open
// finding to not_reproduced unless an unpushed commit still holds it or
// its secret already reached a remote (secFindingKept), in which case it
// stays open. It reports whether it closed the finding. The deps and the
// custom-driver close paths call it, so no close path skips the hold.
func (s *Store) CloseSecFindingNotReproduced(ctx context.Context, id string, now time.Time) (bool, error) {
	kept, err := secFindingKept(ctx, s.db, id)
	if err != nil {
		return false, err
	}
	if kept {
		return false, nil
	}
	if err := s.SetSecFindingStatus(ctx, id, policy.FindingStatusNotReproduced, "", now); err != nil {
		return false, err
	}
	return true, nil
}

// MarkSecFindingFixedVerified moves a finding that is already
// not_reproduced to fixed_verified on recorded evidence (security pillar
// plan section 5.11 (a), lane sec-g5): the caller has observed a
// test-class command after the last edit whose success the host reported
// and no test file edited, and detail says so ("observed test command",
// the class and what the host reported; never "tests passed"). It never
// closes a finding: a finding in any other status, or one whose close came
// from a run with another rule pack version (SecClosedPackChanged), is left
// alone and false is returned. The move, its observations in fix_json (what
// the org row's fix fields read, audit finding 4) and its closed event
// (detail "fixed_verified:" + detail) are one transaction.
func (s *Store) MarkSecFindingFixedVerified(ctx context.Context, id, detail string, obs secfinding.FixObservations, now time.Time) (bool, error) {
	fix, err := json.Marshal(obs)
	if err != nil {
		return false, fmt.Errorf("store.MarkSecFindingFixedVerified: %w", err)
	}
	ts := now.UTC().Format(secTime)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store.MarkSecFindingFixedVerified: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var root string
	err = tx.QueryRowContext(ctx, `SELECT project_root_hash FROM sec_findings WHERE id = ? AND status = ?`,
		id, string(policy.FindingStatusNotReproduced)).Scan(&root)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store.MarkSecFindingFixedVerified: %w", err)
	}
	var lastClose string
	err = tx.QueryRowContext(ctx, `SELECT detail FROM sec_finding_events WHERE finding_id = ? AND kind = ? ORDER BY id DESC LIMIT 1`,
		id, SecEventClosed).Scan(&lastClose)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("store.MarkSecFindingFixedVerified: %w", err)
	}
	if lastClose == SecClosedPackChanged {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sec_findings SET status = ?, fix_json = ? WHERE id = ? AND status = ?`,
		string(policy.FindingStatusFixedVerified), string(fix), id, string(policy.FindingStatusNotReproduced)); err != nil {
		return false, fmt.Errorf("store.MarkSecFindingFixedVerified: %w", err)
	}
	if err := appendSecEvent(ctx, tx, id, root, SecEventClosed, string(policy.FindingStatusFixedVerified)+":"+detail, ts); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store.MarkSecFindingFixedVerified: %w", err)
	}
	return true, nil
}

func insertSecFinding(ctx context.Context, tx *sql.Tx, id string, f secfinding.Finding, ts string) error {
	refs := jsonOrEmpty(f.References, len(f.References.CWE)+len(f.References.OWASP)+len(f.References.ATLAS) == 0)
	_, err := tx.ExecContext(ctx, `INSERT INTO sec_findings (
		id, project_root_hash, local_key, org_key, rel_path, start_line, end_line, path_aliases_json,
		rule_id, rule_version, rule_pack, rule_pack_version, driver, driver_version, engine_digest, database_epoch,
		category, severity, confidence, refs_json, scope, project_identity_hash, org_project_id,
		evidence_redacted, evidence_hash, message, fix_hint, baseline, baseline_ref_json,
		attribution, attribution_method, attribution_confidence, session_id, action_id, prompt_action_id,
		tool, tool_version, model, surface, taint_at_write, taint_origin_class, commit_sha, patch_fp, landed,
		status, first_seen, last_seen, exception_id, run_id)
		VALUES (?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?, ?,?,?,?,?,?, ?,?,?,?,?,?, ?,?,?,?,?,?,?,?,?, ?,?,?,?,?)`,
		id, f.Project.RootHash, f.LocalKey, f.OrgKey, f.Location.RelPath, f.Location.StartLine, f.Location.EndLine,
		jsonOrEmpty(f.Location.PathAliases, len(f.Location.PathAliases) == 0),
		f.Rule.ID, f.Rule.Version, f.Rule.Pack, f.Rule.PackVersion, f.Engine.Driver, f.Engine.DriverVersion, f.Engine.EngineDigest, f.Engine.DatabaseEpoch,
		string(f.Category), string(f.Severity), string(f.Confidence), refs, string(f.Scope), f.Project.IdentityHash, f.Project.OrgProjectID,
		f.EvidenceRedacted, f.EvidenceHash, f.Message, f.FixHint, string(f.Baseline), jsonOrEmpty(f.BaselineRef, f.BaselineRef == (secfinding.BaselineRef{})),
		string(f.Attribution.Class), f.Attribution.Method, string(f.Attribution.Confidence), f.Lineage.SessionID, f.Lineage.ActionID, f.Lineage.PromptActionID,
		f.Lineage.Tool, f.Lineage.ToolVersion, f.Lineage.Model, f.Lineage.Surface, f.TaintAtWrite.Tainted, f.TaintAtWrite.OriginClass,
		f.Commit.SHA, f.Commit.PatchFP, f.Commit.Landed,
		string(f.Status), f.FirstSeen.UTC().Format(secTime), ts, f.ExceptionID, f.Lineage.RunID)
	if err != nil {
		return fmt.Errorf("store.UpsertSecFinding: insert: %w", err)
	}
	return nil
}

func appendSecEvent(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, findingID, rootHash, kind, detail, ts string,
) error {
	if _, err := q.ExecContext(ctx, `INSERT INTO sec_finding_events (finding_id, project_root_hash, kind, detail, at) VALUES (?,?,?,?,?)`,
		findingID, rootHash, kind, detail, ts); err != nil {
		return fmt.Errorf("store.appendSecEvent: %w", err)
	}
	return nil
}

// AppendSecFindingEvent records one lifecycle event (finding id may be ""
// for a project-level event such as a baseline set).
func (s *Store) AppendSecFindingEvent(ctx context.Context, findingID, rootHash, kind, detail string, now time.Time) error {
	return appendSecEvent(ctx, s.db, findingID, rootHash, kind, detail, now.UTC().Format(secTime))
}

// SetSecFindingStatus moves a finding to status (closing it when status is
// not open) and records the event.
func (s *Store) SetSecFindingStatus(ctx context.Context, id string, status secfinding.Status, exceptionID string, now time.Time) error {
	ts := now.UTC().Format(secTime)
	closedAt := ts
	kind := SecEventClosed
	switch status {
	case policy.FindingStatusOpen:
		closedAt, kind = "", SecEventReopened
	case policy.FindingStatusSuppressed, policy.FindingStatusAcceptedRisk, policy.FindingStatusFalsePositive:
		kind = SecEventSuppressed
	}
	var root string
	if err := s.db.QueryRowContext(ctx, `SELECT project_root_hash FROM sec_findings WHERE id = ?`, id).Scan(&root); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSecFindingNotFound
		}
		return fmt.Errorf("store.SetSecFindingStatus: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE sec_findings SET status = ?, closed_at = ?, exception_id = ? WHERE id = ?`,
		string(status), closedAt, exceptionID, id); err != nil {
		return fmt.Errorf("store.SetSecFindingStatus: %w", err)
	}
	return appendSecEvent(ctx, s.db, id, root, kind, string(status), ts)
}

// SecSighting is one (finding key, file) pair: where a run saw a finding,
// or where it saw the finding's content removed.
type SecSighting struct {
	Key  string
	Path string
}

// SecGoneQuery names the open findings a completed scan run proved gone
// (lane SEC-GATEFIX milestone 2d; keyed by path and identity since lane
// sec-gate2): findings of one project, driver and rule pack sighted at a
// whole file the run read (Paths), or whose content the run saw removed
// from one file (Removed), except the sightings the run reported again
// (Keep). Each such sighting is dropped; a finding closes only when it has
// no sighting left, so a secret removed from one file stays open while
// another file still holds it.
type SecGoneQuery struct {
	ProjectRootHash string
	Driver          string
	RulePack        string
	Paths           []string
	Removed         []SecSighting
	Keep            []SecSighting
	// RulePrefixes, when set, limits the close to findings whose rule id
	// starts with one of them (a workflow check speaks for the ci.* rows
	// only, not for the diff observations sighted at the same file).
	RulePrefixes []string
	// PackVersion is the closing run's rule pack version
	// (secscan.EngineIdentity.RulePackVersion). A finding recorded under
	// another non-empty version closes with SecClosedPackChanged, which
	// MarkSecFindingFixedVerified refuses. Empty compares nothing.
	PackVersion string
}

// maxSecGone bounds the paths and removals one close names.
const maxSecGone = 256

// CloseGoneSecFindings drops every sighting q proves gone and moves each
// open finding left with no sighting to not_reproduced (a later sighting
// reopens it, UpsertSecFinding), recording a closed event for each. A
// finding that keeps another sighting stays open, its location moved to
// one it is still seen at. It returns how many it closed. A query with no
// project, driver or pack, or with neither paths nor removals, closes
// nothing.
func (s *Store) CloseGoneSecFindings(ctx context.Context, q SecGoneQuery, now time.Time) (int, error) {
	if q.ProjectRootHash == "" || q.Driver == "" || q.RulePack == "" || (len(q.Paths) == 0 && len(q.Removed) == 0) {
		return 0, nil
	}
	if len(q.Paths) > maxSecGone || len(q.Removed) > maxSecGone {
		return 0, errors.New("store.CloseGoneSecFindings: too many paths or removals")
	}
	keep := map[SecSighting]bool{}
	for _, k := range q.Keep {
		keep[k] = true
	}
	ts := now.UTC().Format(secTime)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.CloseGoneSecFindings: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	gone, err := goneSightings(ctx, tx, q)
	if err != nil {
		return 0, err
	}
	touched := map[string]bool{}
	var order []string
	for _, g := range gone {
		if keep[SecSighting{Key: g.key, Path: g.path}] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sec_finding_sightings WHERE finding_id = ? AND rel_path = ?`, g.id, g.path); err != nil {
			return 0, fmt.Errorf("store.CloseGoneSecFindings: %w", err)
		}
		if !touched[g.id] {
			touched[g.id] = true
			order = append(order, g.id)
		}
	}
	closed := 0
	for _, id := range order {
		var left string
		err := tx.QueryRowContext(ctx, `SELECT rel_path FROM sec_finding_sightings WHERE finding_id = ? ORDER BY last_seen DESC, rel_path LIMIT 1`, id).Scan(&left)
		switch {
		case err == nil:
			// Still seen elsewhere: open, located where it still is.
			if _, err := tx.ExecContext(ctx, `UPDATE sec_findings SET rel_path = ? WHERE id = ? AND rel_path <> ?`, left, id, left); err != nil {
				return 0, fmt.Errorf("store.CloseGoneSecFindings: %w", err)
			}
			continue
		case !errors.Is(err, sql.ErrNoRows):
			return 0, fmt.Errorf("store.CloseGoneSecFindings: %w", err)
		}
		// No file holds it any more, but a commit that adds it is not yet
		// pushed (it stays open, so the next push is still gated, lane
		// sec-gate3), or it already reached a remote (it stays open with
		// SecPushedNote, lane sec-gate4).
		kept, err := secFindingKept(ctx, tx, id)
		if err != nil {
			return 0, err
		}
		if kept {
			continue
		}
		closeDetail := string(policy.FindingStatusNotReproduced)
		if q.PackVersion != "" {
			var recorded string
			if err := tx.QueryRowContext(ctx, `SELECT rule_pack_version FROM sec_findings WHERE id = ?`, id).Scan(&recorded); err != nil {
				return 0, fmt.Errorf("store.CloseGoneSecFindings: %w", err)
			}
			if recorded != "" && recorded != q.PackVersion {
				closeDetail = SecClosedPackChanged
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE sec_findings SET status = ?, closed_at = ? WHERE id = ?`,
			string(policy.FindingStatusNotReproduced), ts, id); err != nil {
			return 0, fmt.Errorf("store.CloseGoneSecFindings: %w", err)
		}
		if err := appendSecEvent(ctx, tx, id, q.ProjectRootHash, SecEventClosed, closeDetail, ts); err != nil {
			return 0, err
		}
		closed++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.CloseGoneSecFindings: %w", err)
	}
	return closed, nil
}

// goneSighting is one open finding's sighting a query names.
type goneSighting struct{ id, key, path string }

// goneSightings lists the open findings' sightings q names: every sighting
// at one of q.Paths, and the sighting of each removal's key at its path. A
// finding stored with no sighting row is read at its own location.
func goneSightings(ctx context.Context, tx *sql.Tx, q SecGoneQuery) ([]goneSighting, error) {
	base := `SELECT f.id, f.local_key, f.rule_id, COALESCE(s.rel_path, f.rel_path) AS p FROM sec_findings f
		LEFT JOIN sec_finding_sightings s ON s.finding_id = f.id
		WHERE f.project_root_hash = ? AND f.status = ? AND f.driver = ? AND f.rule_pack = ?`
	var match []string
	args := []any{q.ProjectRootHash, string(policy.FindingStatusOpen), q.Driver, q.RulePack}
	if len(q.Paths) > 0 {
		match = append(match, `p IN (`+placeholders(len(q.Paths))+`)`)
		for _, p := range q.Paths {
			args = append(args, p)
		}
	}
	for _, r := range q.Removed {
		match = append(match, `(local_key = ? AND p = ?)`)
		args = append(args, r.Key, r.Path)
	}
	where := `(` + strings.Join(match, " OR ") + `)`
	if len(q.RulePrefixes) > 0 {
		var rules []string
		for _, pre := range q.RulePrefixes {
			rules = append(rules, `substr(rule_id, 1, ?) = ?`)
			args = append(args, len(pre), pre)
		}
		where += ` AND (` + strings.Join(rules, " OR ") + `)`
	}
	//nolint:gosec // G202: only fixed clauses and placeholder lists are concatenated; every value is a bound parameter.
	rows, err := tx.QueryContext(ctx, `SELECT id, local_key, p FROM (`+base+`) WHERE `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("store.CloseGoneSecFindings: %w", err)
	}
	defer rows.Close()
	var out []goneSighting
	for rows.Next() {
		var g goneSighting
		if err := rows.Scan(&g.id, &g.key, &g.path); err != nil {
			return nil, fmt.Errorf("store.CloseGoneSecFindings: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.CloseGoneSecFindings: %w", err)
	}
	return out, nil
}

// SecOpenSighting is one open finding's sighting, for the daemon's rescan
// of the files open findings sit in (lane sec-gate2: a human edit or an
// `rm` closes a finding).
type SecOpenSighting struct {
	ProjectRootHash string
	Path            string
	RulePack        string
	RuleID          string
}

// SecRescanClass is one kind of finding the rescan can answer: every rule
// of Pack, or only the rules whose id starts with one of RulePrefixes or
// equals one of RuleIDs.
type SecRescanClass struct {
	Pack         string
	RulePrefixes []string
	RuleIDs      []string
}

// SecRescanQuery selects the sightings one rescan pass reads (lane
// sec-gate3 milestone 1a). Only the classes the rescan can answer and only
// the projects whose root it knows are read, so rows it can never rescan
// cannot fill the page; the page starts after After and walks the rows in
// key order, so a file that stays unreadable is passed over on the next
// page instead of holding the head of the list.
type SecRescanQuery struct {
	Driver     string
	Classes    []SecRescanClass
	RootHashes []string
	// After is the last row of the previous page; the zero value starts at
	// the first row.
	After SecOpenSighting
	Limit int
}

// SecRescanSightings returns up to q.Limit open findings' sightings of
// q.Driver, one row per (project, path, pack, rule), in that key order,
// strictly after q.After. A query with no class or no root returns none.
func (s *Store) SecRescanSightings(ctx context.Context, q SecRescanQuery) ([]SecOpenSighting, error) {
	if len(q.Classes) == 0 || len(q.RootHashes) == 0 {
		return nil, nil
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 64
	}
	hashes, err := json.Marshal(q.RootHashes)
	if err != nil {
		return nil, fmt.Errorf("store.SecRescanSightings: %w", err)
	}
	args := []any{string(policy.FindingStatusOpen), q.Driver, string(hashes)}
	var classes []string
	for _, c := range q.Classes {
		if c.Pack == "" {
			continue
		}
		clause := `f.rule_pack = ?`
		args = append(args, c.Pack)
		var rules []string
		for _, pre := range c.RulePrefixes {
			rules = append(rules, `substr(f.rule_id, 1, ?) = ?`)
			args = append(args, len(pre), pre)
		}
		for _, id := range c.RuleIDs {
			rules = append(rules, `f.rule_id = ?`)
			args = append(args, id)
		}
		if len(rules) > 0 {
			clause += ` AND (` + strings.Join(rules, " OR ") + `)`
		}
		classes = append(classes, `(`+clause+`)`)
	}
	if len(classes) == 0 {
		return nil, nil
	}
	a := q.After
	args = append(args, a.ProjectRootHash, a.ProjectRootHash, a.Path, a.ProjectRootHash, a.Path, a.RulePack,
		a.ProjectRootHash, a.Path, a.RulePack, a.RuleID, limit)
	//nolint:gosec // G202: only fixed clauses are concatenated; every value is a bound parameter.
	rows, err := s.db.QueryContext(ctx, `SELECT h, p, k, r FROM (
		SELECT DISTINCT f.project_root_hash AS h, COALESCE(s.rel_path, f.rel_path) AS p, f.rule_pack AS k, f.rule_id AS r
		FROM sec_findings f LEFT JOIN sec_finding_sightings s ON s.finding_id = f.id
		WHERE f.status = ? AND f.driver = ?
			AND f.project_root_hash IN (SELECT value FROM json_each(?))
			AND (`+strings.Join(classes, " OR ")+`))
		WHERE p <> '' AND (h > ? OR (h = ? AND p > ?) OR (h = ? AND p = ? AND k > ?) OR (h = ? AND p = ? AND k = ? AND r > ?))
		ORDER BY h, p, k, r LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.SecRescanSightings: %w", err)
	}
	defer rows.Close()
	var out []SecOpenSighting
	for rows.Next() {
		var o SecOpenSighting
		if err := rows.Scan(&o.ProjectRootHash, &o.Path, &o.RulePack, &o.RuleID); err != nil {
			return nil, fmt.Errorf("store.SecRescanSightings: %w", err)
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SecRescanSightings: %w", err)
	}
	return out, nil
}

// SecFindingCommit is one (project, commit) pair some open finding is held
// open by (sec_finding_commits, lane sec-gate3 milestone 1b).
type SecFindingCommit struct {
	ProjectRootHash string
	CommitSHA       string
}

// SecHeldCommits returns up to limit distinct (project, commit) pairs that
// hold an open or suppressed finding, of the projects in rootHashes, in key
// order and strictly after after (the zero value starts at the first). A
// suppressed finding's commits are checked too, so a secret pushed while an
// exception suppresses its finding is still recorded as having reached a
// remote (markReached; GATE4 audit finding 10).
func (s *Store) SecHeldCommits(ctx context.Context, rootHashes []string, after SecFindingCommit, limit int) ([]SecFindingCommit, error) {
	if len(rootHashes) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 16
	}
	hashes, err := json.Marshal(rootHashes)
	if err != nil {
		return nil, fmt.Errorf("store.SecHeldCommits: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT f.project_root_hash, c.commit_sha
		FROM sec_finding_commits c JOIN sec_findings f ON f.id = c.finding_id
		WHERE f.status IN (?, ?) AND f.project_root_hash IN (SELECT value FROM json_each(?))
			AND (f.project_root_hash > ? OR (f.project_root_hash = ? AND c.commit_sha > ?))
		ORDER BY f.project_root_hash, c.commit_sha LIMIT ?`,
		string(policy.FindingStatusOpen), string(policy.FindingStatusSuppressed), string(hashes), after.ProjectRootHash, after.ProjectRootHash, after.CommitSHA, limit)
	if err != nil {
		return nil, fmt.Errorf("store.SecHeldCommits: %w", err)
	}
	defer rows.Close()
	var out []SecFindingCommit
	for rows.Next() {
		var c SecFindingCommit
		if err := rows.Scan(&c.ProjectRootHash, &c.CommitSHA); err != nil {
			return nil, fmt.Errorf("store.SecHeldCommits: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SecHeldCommits: %w", err)
	}
	return out, nil
}

// SecHistoryReasonPushed and SecHistoryReasonGone are the reasons the
// daemon drops a held commit: it reached a remote and no push can send it
// again (every configured remote has it, or no local branch, tag or HEAD
// holds it any more), or it no longer exists and never reached a remote.
const (
	SecHistoryReasonPushed = "pushed"
	SecHistoryReasonGone   = "gone"
)

// maxSecRemotes bounds the remotes one held commit records.
const maxSecRemotes = 16

// secRemotesJSON is the stored form of a remote list: sorted, deduplicated,
// bounded, "" when empty.
func secRemotesJSON(remotes []string) string {
	set := map[string]bool{}
	var out []string
	for _, r := range remotes {
		if r == "" || set[r] || len(out) >= maxSecRemotes {
			continue
		}
		set[r] = true
		out = append(out, r)
	}
	if len(out) == 0 {
		return ""
	}
	sort.Strings(out)
	b, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(b)
}

// secRemotesFrom reads a stored remote list (an unreadable one is empty:
// on no remote, which never releases a hold).
func secRemotesFrom(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if json.Unmarshal([]byte(s), &out) != nil {
		return nil
	}
	return out
}

// heldFindings lists the findings of a project one commit holds, with
// their status.
func heldFindings(ctx context.Context, tx *sql.Tx, c SecFindingCommit) ([]heldFinding, error) {
	rows, err := tx.QueryContext(ctx, `SELECT c.finding_id, f.status, f.reached_remote_at, f.category, f.confidence FROM sec_finding_commits c
		JOIN sec_findings f ON f.id = c.finding_id
		WHERE f.project_root_hash = ? AND c.commit_sha = ? ORDER BY c.finding_id`, c.ProjectRootHash, strings.ToLower(c.CommitSHA))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []heldFinding
	for rows.Next() {
		var h heldFinding
		var cat, conf string
		if err := rows.Scan(&h.id, &h.status, &h.reached, &cat, &conf); err != nil {
			return nil, err
		}
		h.held = secCommitHeld(cat, conf)
		h.noted = h.held && secPushedNoted(cat)
		out = append(out, h)
	}
	return out, rows.Err()
}

// heldFinding is one finding a held commit holds; held is false for a
// row an earlier build wrote for a flag-only finding (secCommitHeld);
// noted is true only for a held secret, the one kind stamped as reached
// (ruling P-165).
type heldFinding struct {
	id, status, reached string
	held, noted         bool
}

// markReached stamps reached_remote_at on an open or suppressed finding
// that has not reached a remote before, recording a seen event whose detail
// names the remotes ("pushed:<remote>,..."; the event kinds are closed by
// migration 177's CHECK, so the reach rides on a seen event). It reports
// whether it stamped. A suppressed finding is stamped too (GATE4 audit
// finding 10): a secret pushed while an exception suppresses it has still
// left the machine, so when the exception ends the finding stays open with
// SecPushedNote instead of closing as not reproduced.
func markReached(ctx context.Context, tx *sql.Tx, h heldFinding, rootHash string, remotes []string, ts string) (bool, error) {
	if !h.noted || !secReachable(h.status) || h.reached != "" {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sec_findings SET reached_remote_at = ? WHERE id = ? AND reached_remote_at = ''`, ts, h.id); err != nil {
		return false, err
	}
	detail := SecHistoryReasonPushed
	if len(remotes) > 0 {
		detail += ":" + strings.Join(secRemotesFrom(secRemotesJSON(remotes)), ",")
	}
	if err := appendSecEvent(ctx, tx, h.id, rootHash, SecEventSeen, detail, ts); err != nil {
		return false, err
	}
	return true, nil
}

// secReachable reports a status markReached stamps: open, or suppressed by
// an exception (still the developer's finding, only hidden for a while).
// A triage close (accepted risk, false positive, fixed) is left alone.
func secReachable(status string) bool {
	return status == string(policy.FindingStatusOpen) || status == string(policy.FindingStatusSuppressed)
}

// SetSecFindingCommitRemotes records which configured remotes already
// hold a commit that still holds findings open (lane sec-gate4 milestone
// 1a): the push gate counts the commit as pushed only for those remotes.
// When remotes is not empty, each open finding the commit holds is marked
// as having reached a remote (SecPushedNote). It returns how many rows it
// changed (a remote list that differs from the stored one, a finding
// newly marked), so the caller re-signs the posture only on a change.
func (s *Store) SetSecFindingCommitRemotes(ctx context.Context, c SecFindingCommit, remotes []string, now time.Time) (int, error) {
	if c.ProjectRootHash == "" || !IsCommitSHA(c.CommitSHA) {
		return 0, nil
	}
	ts := now.UTC().Format(secTime)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.SetSecFindingCommitRemotes: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	held, err := heldFindings(ctx, tx, c)
	if err != nil {
		return 0, fmt.Errorf("store.SetSecFindingCommitRemotes: %w", err)
	}
	stored := secRemotesJSON(remotes)
	marked := 0
	for _, h := range held {
		res, err := tx.ExecContext(ctx, `UPDATE sec_finding_commits SET remotes_json = ? WHERE finding_id = ? AND commit_sha = ? AND remotes_json <> ?`,
			stored, h.id, strings.ToLower(c.CommitSHA), stored)
		if err != nil {
			return 0, fmt.Errorf("store.SetSecFindingCommitRemotes: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			marked++
		}
		if stored == "" {
			continue
		}
		ok, err := markReached(ctx, tx, h, c.ProjectRootHash, remotes, ts)
		if err != nil {
			return 0, fmt.Errorf("store.SetSecFindingCommitRemotes: %w", err)
		}
		if ok {
			marked++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.SetSecFindingCommitRemotes: %w", err)
	}
	return marked, nil
}

// The SecFindingCommit reflog cap reasons (migration 193, lane LEFT-SEC):
// the only reflog entries reaching a held commit are older than
// [security.scanning].reflog_hold_max_age_days, or deeper in their ref's
// reflog than reflog_hold_max_entries.
const (
	SecReflogCapAge     = "reflog_cap_age"
	SecReflogCapEntries = "reflog_cap_entries"
)

// SetSecFindingCommitReflogCap records (cap one of the SecReflogCap*
// reasons) or clears (cap "") that a held commit is reached only past a
// reflog cap, on every finding of the project it holds. It returns how many
// rows changed, so the caller re-signs the posture only on a change. Any
// other cap value changes nothing.
func (s *Store) SetSecFindingCommitReflogCap(ctx context.Context, c SecFindingCommit, capReason string) (int, error) {
	if c.ProjectRootHash == "" || !IsCommitSHA(c.CommitSHA) || (capReason != "" && capReason != SecReflogCapAge && capReason != SecReflogCapEntries) {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `UPDATE sec_finding_commits SET reflog_cap = ?
		WHERE commit_sha = ? AND reflog_cap <> ? AND finding_id IN (SELECT id FROM sec_findings WHERE project_root_hash = ?)`,
		capReason, strings.ToLower(c.CommitSHA), capReason, c.ProjectRootHash)
	if err != nil {
		return 0, fmt.Errorf("store.SetSecFindingCommitReflogCap: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// DropSecFindingCommit removes one commit from the history of every
// finding of a project. reason SecHistoryReasonPushed (the commit reached
// a remote and no push can send it again) marks each open finding it held
// as having reached a remote: it stays open with SecPushedNote and stops
// blocking once nothing else holds it (lane sec-gate4 milestone 1b).
// remotes names the remotes that hold it, for the event. Any other reason
// (gone: rewritten away before it reached a remote) closes as
// not_reproduced each open finding left with no file sighting, no held
// commit and no earlier reach, recording a closed event with reason as
// detail. It returns how many it closed.
func (s *Store) DropSecFindingCommit(ctx context.Context, c SecFindingCommit, reason string, remotes []string, now time.Time) (int, error) {
	if c.ProjectRootHash == "" || !IsCommitSHA(c.CommitSHA) {
		return 0, nil
	}
	ts := now.UTC().Format(secTime)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.DropSecFindingCommit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	ids, err := heldFindings(ctx, tx, c)
	if err != nil {
		return 0, fmt.Errorf("store.DropSecFindingCommit: %w", err)
	}
	closed := 0
	for _, h := range ids {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sec_finding_commits WHERE finding_id = ? AND commit_sha = ?`, h.id, strings.ToLower(c.CommitSHA)); err != nil {
			return 0, fmt.Errorf("store.DropSecFindingCommit: %w", err)
		}
		if reason == SecHistoryReasonPushed {
			// Open or suppressed (markReached decides which it stamps).
			if _, err := markReached(ctx, tx, h, c.ProjectRootHash, remotes, ts); err != nil {
				return 0, fmt.Errorf("store.DropSecFindingCommit: %w", err)
			}
			continue
		}
		if h.status != string(policy.FindingStatusOpen) {
			continue
		}
		kept, err := secFindingKept(ctx, tx, h.id)
		if err != nil {
			return 0, err
		}
		var one int
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM sec_finding_sightings WHERE finding_id = ? LIMIT 1`, h.id).Scan(&one)
		sighted := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("store.DropSecFindingCommit: %w", err)
		}
		if kept || sighted {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE sec_findings SET status = ?, closed_at = ? WHERE id = ?`,
			string(policy.FindingStatusNotReproduced), ts, h.id); err != nil {
			return 0, fmt.Errorf("store.DropSecFindingCommit: %w", err)
		}
		if err := appendSecEvent(ctx, tx, h.id, c.ProjectRootHash, SecEventClosed, string(policy.FindingStatusNotReproduced)+":"+reason, ts); err != nil {
			return 0, err
		}
		closed++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.DropSecFindingCommit: %w", err)
	}
	return closed, nil
}

// SecFindingFilter selects findings for ListSecFindings.
type SecFindingFilter struct {
	ProjectRootHash string
	// Status "" is every status.
	Status secfinding.Status
	Limit  int
}

// ListSecFindings returns findings newest first (at most Limit, default
// 200, at most 1000), with the full lineage the SARIF export writes (the
// prompt action, tool version, surface, attribution method and confidence
// and the taint flag, lane sec-g5).
func (s *Store) ListSecFindings(ctx context.Context, f SecFindingFilter) ([]secfinding.Finding, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	var where []string
	var args []any
	if f.ProjectRootHash != "" {
		where, args = append(where, "project_root_hash = ?"), append(args, f.ProjectRootHash)
	}
	if f.Status != "" {
		where, args = append(where, "status = ?"), append(args, string(f.Status))
	}
	q := `SELECT id, project_root_hash, local_key, org_key, rel_path, start_line, end_line, rule_id, rule_pack,
		driver, driver_version, category, severity, confidence, scope, evidence_hash, message, fix_hint, baseline,
		attribution, COALESCE(session_id, ''), action_id, tool, model, status, first_seen, last_seen, closed_at, exception_id,
		reached_remote_at, prompt_action_id, tool_version, surface, attribution_method, attribution_confidence, taint_at_write
		FROM sec_findings`
	if len(where) > 0 {
		//nolint:gosec // G202: the clauses are fixed literals above; every value is a bound parameter.
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY last_seen DESC, id LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListSecFindings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []secfinding.Finding
	for rows.Next() {
		var x secfinding.Finding
		var cat, sev, conf, scope, base, attr, status, first, last, closed, reached, attrConf string
		if err := rows.Scan(&x.ID, &x.Project.RootHash, &x.LocalKey, &x.OrgKey, &x.Location.RelPath, &x.Location.StartLine,
			&x.Location.EndLine, &x.Rule.ID, &x.Rule.Pack, &x.Engine.Driver, &x.Engine.DriverVersion, &cat, &sev, &conf, &scope,
			&x.EvidenceHash, &x.Message, &x.FixHint, &base, &attr, &x.Lineage.SessionID, &x.Lineage.ActionID, &x.Lineage.Tool,
			&x.Lineage.Model, &status, &first, &last, &closed, &x.ExceptionID, &reached,
			&x.Lineage.PromptActionID, &x.Lineage.ToolVersion, &x.Lineage.Surface, &x.Attribution.Method, &attrConf,
			&x.TaintAtWrite.Tainted); err != nil {
			return nil, fmt.Errorf("store.ListSecFindings: %w", err)
		}
		x.Attribution.Confidence = secfinding.Confidence(attrConf)
		x.FixHint = secPushedHint(secReachedNote(reached, cat, conf), x.FixHint)
		x.Category, x.Severity, x.Confidence = secfinding.Category(cat), secfinding.Severity(sev), secfinding.Confidence(conf)
		x.Scope, x.Baseline, x.Status = secfinding.Scope(scope), secfinding.Baseline(base), secfinding.Status(status)
		x.Attribution.Class = secfinding.Attribution(attr)
		x.FirstSeen, _ = time.Parse(secTime, first)
		x.LastSeen, _ = time.Parse(secTime, last)
		x.ClosedAt, _ = time.Parse(secTime, closed)
		out = append(out, x)
	}
	return out, rows.Err()
}

// SecBlockingQuery says which open findings block (section 4.8): open,
// high confidence, at or above the minimum severities, and new (or
// untrusted_baseline too, under a managed floor).
type SecBlockingQuery struct {
	ProjectRootHash  string
	Severities       []secfinding.Severity
	IncludeUntrusted bool
	// HistoryOnly narrows the result to the findings an unpushed commit
	// alone holds open: a sec_finding_commits row and no file sighting
	// left (lane sec-gate3 audit finding 2).
	HistoryOnly bool
}

// secBlockingWhere is the WHERE clause and arguments SecBlockingKeys and
// SecHeldHistory share. A finding whose secret already reached a remote
// and that no file sighting and no held commit holds any more is open
// (SecPushedNote) but never blocking: the push it could gate already
// happened (lane sec-gate4 milestone 1b).
//
// Box work with no foothold on the host (lane LEFT-SEC): a finding with a
// run id (secfinding.Lineage.RunID) that no commit holds and no file of the
// developer's tree sights, such as one found in a hosted box's staged diff
// saved home but never applied, is shown and never blocks; the moment it is
// sighted in the tree or held by a commit it blocks like any other.
func secBlockingWhere(q SecBlockingQuery) (string, []any) {
	baselines := []any{string(policy.FindingBaselineNew)}
	if q.IncludeUntrusted {
		baselines = append(baselines, string(policy.FindingBaselineUntrusted))
	}
	args := []any{q.ProjectRootHash, string(policy.FindingStatusOpen), string(policy.FindingConfidenceHigh)}
	args = append(args, baselines...)
	for _, sv := range q.Severities {
		args = append(args, string(sv))
	}
	history := ""
	if q.HistoryOnly {
		history = ` AND EXISTS (SELECT 1 FROM sec_finding_commits c WHERE c.finding_id = sec_findings.id)
		AND NOT EXISTS (SELECT 1 FROM sec_finding_sightings s WHERE s.finding_id = sec_findings.id)`
	}
	where := `sec_findings.project_root_hash = ? AND sec_findings.status = ? AND sec_findings.confidence = ?
		AND sec_findings.baseline IN (` + placeholders(len(baselines)) + `) AND sec_findings.severity IN (` + placeholders(len(q.Severities)) + `)
		AND NOT (sec_findings.reached_remote_at <> ''
			AND NOT EXISTS (SELECT 1 FROM sec_finding_commits c WHERE c.finding_id = sec_findings.id)
			AND NOT EXISTS (SELECT 1 FROM sec_finding_sightings s WHERE s.finding_id = sec_findings.id))
		AND NOT (sec_findings.run_id <> ''
			AND NOT EXISTS (SELECT 1 FROM sec_finding_commits c WHERE c.finding_id = sec_findings.id)
			AND NOT EXISTS (SELECT 1 FROM sec_finding_sightings s WHERE s.finding_id = sec_findings.id))` + history
	return where, args
}

// SecBlockingKeys returns the local keys of the project's open blocking
// findings, sorted, at most limit (the caller sets overflow when limit is
// reached).
func (s *Store) SecBlockingKeys(ctx context.Context, q SecBlockingQuery, limit int) ([]string, error) {
	if len(q.Severities) == 0 {
		return nil, nil
	}
	where, args := secBlockingWhere(q)
	args = append(args, limit)
	//nolint:gosec // G202: only placeholder lists and fixed clauses are concatenated; every value is a bound parameter.
	rows, err := s.db.QueryContext(ctx, `SELECT local_key FROM sec_findings WHERE `+where+`
		ORDER BY local_key LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.SecBlockingKeys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, fmt.Errorf("store.SecBlockingKeys: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SecHeldRow is one (blocking finding, held commit) pair: the finding's
// local key, the commit and the remotes that already hold the commit.
type SecHeldRow struct {
	LocalKey  string
	CommitSHA string
	Remotes   []string
	// ReflogCap names the reflog cap past which the only reflog entries
	// reaching this commit lie ("" when it is held otherwise; migration
	// 193, lane LEFT-SEC).
	ReflogCap string
}

// SecHeldHistory returns, for the open blocking findings q selects (set
// q.HistoryOnly for the ones only an unpushed commit holds), every held
// commit of each, ordered by key and commit, at most limit rows (the
// caller treats a full page as capped). The posture reads it to say, per
// remote, which held findings that remote already has (lane sec-gate4
// milestone 1a).
func (s *Store) SecHeldHistory(ctx context.Context, q SecBlockingQuery, limit int) ([]SecHeldRow, error) {
	if len(q.Severities) == 0 {
		return nil, nil
	}
	where, args := secBlockingWhere(q)
	args = append(args, limit)
	//nolint:gosec // G202: only placeholder lists and fixed clauses are concatenated; every value is a bound parameter.
	rows, err := s.db.QueryContext(ctx, `SELECT sec_findings.local_key, hc.commit_sha, hc.remotes_json, hc.reflog_cap
		FROM sec_findings JOIN sec_finding_commits hc ON hc.finding_id = sec_findings.id WHERE `+where+`
		ORDER BY sec_findings.local_key, hc.commit_sha LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.SecHeldHistory: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []SecHeldRow
	for rows.Next() {
		var r SecHeldRow
		var remotes string
		if err := rows.Scan(&r.LocalKey, &r.CommitSHA, &remotes, &r.ReflogCap); err != nil {
			return nil, fmt.Errorf("store.SecHeldHistory: %w", err)
		}
		r.Remotes = secRemotesFrom(remotes)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SecCount is one cell of the open findings by category and severity.
type SecCount struct {
	Category secfinding.Category
	Severity secfinding.Severity
	N        int
}

// SecOpenCounts returns the project's open findings by category and
// severity.
func (s *Store) SecOpenCounts(ctx context.Context, rootHash string) ([]SecCount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT category, severity, COUNT(*) FROM sec_findings
		WHERE project_root_hash = ? AND status = 'open' GROUP BY category, severity ORDER BY category, severity`, rootHash)
	if err != nil {
		return nil, fmt.Errorf("store.SecOpenCounts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []SecCount
	for rows.Next() {
		var c SecCount
		var cat, sev string
		if err := rows.Scan(&cat, &sev, &c.N); err != nil {
			return nil, fmt.Errorf("store.SecOpenCounts: %w", err)
		}
		c.Category, c.Severity = secfinding.Category(cat), secfinding.Severity(sev)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SecScanRun is one driver run (sec_scan_runs).
type SecScanRun struct {
	ProjectRootHash string
	Driver          string
	Scope           secfinding.Scope
	Target          any
	Coverage        any
	Engine          any
	Outcome         string
	Findings        int
	StartedAt       time.Time
	Duration        time.Duration
}

// InsertSecScanRun records one driver run.
func (s *Store) InsertSecScanRun(ctx context.Context, r SecScanRun) error {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO sec_scan_runs
		(project_root_hash, driver, scope, target_json, coverage_json, engine_json, outcome, findings, started_at, duration_ms)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		r.ProjectRootHash, r.Driver, string(r.Scope), jsonOrEmpty(r.Target, r.Target == nil), jsonOrEmpty(r.Coverage, r.Coverage == nil),
		jsonOrEmpty(r.Engine, r.Engine == nil), r.Outcome, r.Findings, r.StartedAt.UTC().Format(secTime), r.Duration.Milliseconds()); err != nil {
		return fmt.Errorf("store.InsertSecScanRun: %w", err)
	}
	return nil
}

// SecRunReasonNotRun is the coverage reason of a scan run recorded for a
// run that never executed (a scheduled custom scanner run that failed
// before the scanner started: seccustomsvc's recordScheduledFailure). The
// row keeps the schedule's last-run time (SecLastDriverRun reads it), but
// it is not a scan: SecLastScan, SecLatestRunNotes and the org posture
// freshness and outcome counts leave it out (secScanRanSQL). An Opengrep
// run that stopped before the engine scanned anything is recorded the same
// way (cmd/observer recordCodeScan, opengrep.EngineRan), and SecLatestRun
// skips it too.
const SecRunReasonNotRun = "not_run"

// secScanRanSQL is the sec_scan_runs filter that leaves out a run that
// never executed (reason SecRunReasonNotRun, under the scheduled failure's
// "reason" key or secscan.Coverage's "Reason"). A row with no or invalid
// coverage JSON is kept.
const secScanRanSQL = ` AND NOT (json_valid(coverage_json) AND COALESCE(json_extract(coverage_json, '$.reason'), json_extract(coverage_json, '$.Reason'), '') = '` + SecRunReasonNotRun + `')`

// SecLastScan returns when the project's newest scan run of its working
// tree started (zero when none). A baseline rescan reads an older commit
// and a diff run reads only a change (SecDiffDriverPrefix), so neither is
// counted, and nor is a run that never executed (SecRunReasonNotRun).
func (s *Store) SecLastScan(ctx context.Context, rootHash string) (time.Time, error) {
	var ts sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(started_at) FROM sec_scan_runs WHERE project_root_hash = ? AND driver NOT LIKE ? AND driver NOT LIKE ?`+secScanRanSQL,
		rootHash, SecBaselineDriverPrefix+"%", SecDiffDriverPrefix+"%").Scan(&ts); err != nil {
		return time.Time{}, fmt.Errorf("store.SecLastScan: %w", err)
	}
	if !ts.Valid {
		return time.Time{}, nil
	}
	t, _ := time.Parse(secTime, ts.String)
	return t, nil
}

// SecLatestRunNotes returns the coverage notes of a driver's newest scan
// run on any project (nil when it has none, or the row carries no notes):
// the dashboard's Scanners card labels a driver whose last run was not
// isolated or ran an untested engine version (lane SEC-DEPS3 item 6). The
// notes are Observer's own fixed sentences (secscan.Coverage.Notes). A run
// that never executed (SecRunReasonNotRun) carries no notes and is skipped,
// so it does not hide an earlier run's.
func (s *Store) SecLatestRunNotes(ctx context.Context, driver string) ([]string, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT coverage_json FROM sec_scan_runs WHERE driver = ?`+secScanRanSQL+`
		ORDER BY started_at DESC, id DESC LIMIT 1`, driver).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("store.SecLatestRunNotes: %w", err)
	}
	var cov struct {
		Notes []string `json:"Notes"`
	}
	if raw == "" || json.Unmarshal([]byte(raw), &cov) != nil {
		return nil, nil
	}
	return cov.Notes, nil
}

// SecRunSummary is a driver's newest recorded run: when, its outcome and
// scope, and its coverage notes.
type SecRunSummary struct {
	StartedAt time.Time
	Outcome   string
	Scope     string
	Notes     []string
}

// SecLatestRun returns the driver's newest run of any project; ok is false
// when it has none. A run that never executed (SecRunReasonNotRun) is not a
// scan and is skipped, through the same filter as SecLastScan
// (secScanRanSQL; lane SEC-G2 audit finding 4).
func (s *Store) SecLatestRun(ctx context.Context, driver string) (SecRunSummary, bool, error) {
	var started, outcome, scope, raw string
	err := s.db.QueryRowContext(ctx, `SELECT started_at, outcome, scope, coverage_json FROM sec_scan_runs WHERE driver = ?`+secScanRanSQL+`
		ORDER BY started_at DESC, id DESC LIMIT 1`, driver).Scan(&started, &outcome, &scope, &raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return SecRunSummary{}, false, nil
	case err != nil:
		return SecRunSummary{}, false, fmt.Errorf("store.SecLatestRun: %w", err)
	}
	out := SecRunSummary{Outcome: outcome, Scope: scope}
	if t, err := time.Parse(secTime, started); err == nil {
		out.StartedAt = t
	}
	var cov struct {
		Notes []string `json:"Notes"`
	}
	if raw != "" && json.Unmarshal([]byte(raw), &cov) == nil {
		out.Notes = cov.Notes
	}
	return out, true, nil
}

// SecDiffDriverPrefix prefixes the driver of a run that read only a diff
// (a commit's or the staged changes), never the working tree: S-747 on the
// manifests a commit changes records under "diff:deps.s-747" (lane
// SEC-DEPS3 item 8). SecLastScan does not count such a run.
const SecDiffDriverPrefix = "diff:"

// SecBaselineDriverPrefix prefixes the driver of a baseline rescan's scan
// run ("baseline:<driver id>"): the run that read the baseline commit's
// tree under one rule pack and policy version (section 4.5.2 item 2).
const SecBaselineDriverPrefix = "baseline:"

// SecBaselineScan is the target of a baseline rescan's scan run: which
// baseline commit was read, under which versions.
type SecBaselineScan struct {
	Ref           string `json:"baseline_ref"`
	PackVersion   string `json:"pack_version"`
	PolicyVersion string `json:"policy_version"`
}

// SecBaselineScanned reports whether a complete baseline rescan (outcome
// clean or findings) of ref under the given versions is recorded for the
// project.
func (s *Store) SecBaselineScanned(ctx context.Context, rootHash string, b SecBaselineScan) (bool, error) {
	target := jsonOrEmpty(b, false)
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sec_scan_runs
		WHERE project_root_hash = ? AND driver LIKE ? AND target_json = ? AND outcome IN ('clean', 'findings')`,
		rootHash, SecBaselineDriverPrefix+"%", target).Scan(&n); err != nil {
		return false, fmt.Errorf("store.SecBaselineScanned: %w", err)
	}
	return n > 0, nil
}

// SetSecFindingBaseline relabels one finding's baseline (a baseline rescan,
// section 4.5.2 item 2) and records the baseline it was judged against.
func (s *Store) SetSecFindingBaseline(ctx context.Context, id string, b secfinding.Baseline, ref secfinding.BaselineRef) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sec_findings SET baseline = ?, baseline_ref_json = ? WHERE id = ?`,
		string(b), jsonOrEmpty(ref, ref == (secfinding.BaselineRef{})), id)
	if err != nil {
		return fmt.Errorf("store.SetSecFindingBaseline: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrSecFindingNotFound
	}
	return nil
}

// SecBaseline is one baseline row (section 4.5.2).
type SecBaseline struct {
	ProjectRootHash string
	// Kind is "commit", "ci_result" or "reset".
	Kind          string
	Ref           string
	Approver      string
	PackVersion   string
	PolicyVersion string
	CreatedAt     time.Time
}

// AddSecBaseline records a baseline set or reset and its audit event. A
// reset never relabels open findings by itself.
func (s *Store) AddSecBaseline(ctx context.Context, b SecBaseline) error {
	ts := b.CreatedAt.UTC().Format(secTime)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.AddSecBaseline: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO sec_baselines (project_root_hash, kind, ref, approver, pack_version, policy_version, created_at)
		VALUES (?,?,?,?,?,?,?)`, b.ProjectRootHash, b.Kind, b.Ref, b.Approver, b.PackVersion, b.PolicyVersion, ts); err != nil {
		return fmt.Errorf("store.AddSecBaseline: %w", err)
	}
	kind := SecEventBaselineSet
	if b.Kind == "reset" {
		kind = SecEventBaselineReset
	}
	if err := appendSecEvent(ctx, tx, "", b.ProjectRootHash, kind, b.Kind+":"+b.Ref, ts); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.AddSecBaseline: %w", err)
	}
	return nil
}

// LatestSecBaseline returns the project's newest baseline, false when none
// (or when the newest is a reset).
func (s *Store) LatestSecBaseline(ctx context.Context, rootHash string) (SecBaseline, bool, error) {
	var b SecBaseline
	var ts string
	err := s.db.QueryRowContext(ctx, `SELECT project_root_hash, kind, ref, approver, pack_version, policy_version, created_at
		FROM sec_baselines WHERE project_root_hash = ? ORDER BY id DESC LIMIT 1`, rootHash).
		Scan(&b.ProjectRootHash, &b.Kind, &b.Ref, &b.Approver, &b.PackVersion, &b.PolicyVersion, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return SecBaseline{}, false, nil
	}
	if err != nil {
		return SecBaseline{}, false, fmt.Errorf("store.LatestSecBaseline: %w", err)
	}
	b.CreatedAt, _ = time.Parse(secTime, ts)
	return b, b.Kind != "reset", nil
}

// SecProjects returns every project root hash the store holds findings or
// scan runs for, sorted.
func (s *Store) SecProjects(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT project_root_hash FROM sec_findings
		UNION SELECT project_root_hash FROM sec_scan_runs ORDER BY 1`)
	if err != nil {
		return nil, fmt.Errorf("store.SecProjects: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("store.SecProjects: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SecActiveProjectRoots returns the project roots active since the given
// time, sorted: a session of the project started or ended then or later,
// or the project was first recorded then or later. It is the set the
// security posture writer signs (security pillar plan section 4.8) and the
// set the scheduled scans walk. A root that is not a path
// (projectRootIsPath; FU-193's "Xcode (project unknown)") is left out:
// every consumer reads each root as a directory (audit finding 1 on the
// w14 hand-back).
func (s *Store) SecActiveProjectRoots(ctx context.Context, since time.Time) ([]string, error) {
	ts := timestamp(since)
	rows, err := s.db.QueryContext(ctx, `SELECT root_path FROM projects
		WHERE root_path <> '' AND (created_at >= ? OR id IN (
			SELECT project_id FROM sessions WHERE started_at >= ? OR ended_at >= ?))
		ORDER BY root_path`, ts, ts, ts)
	if err != nil {
		return nil, fmt.Errorf("store.SecActiveProjectRoots: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, fmt.Errorf("store.SecActiveProjectRoots: %w", err)
		}
		if !projectRootIsPath(r) {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PruneSecFindings deletes closed and suppressed findings closed before
// cutoff, scan runs that started before it, and lifecycle events recorded
// before it unless their finding is still open ([security.retention].days,
// section 4.6), together with the events of every finding it deleted. Open
// findings and their history are never deleted. It returns the findings
// removed.
func (s *Store) PruneSecFindings(ctx context.Context, cutoff time.Time) (int64, error) {
	return s.PruneSecFindingsScoped(ctx, cutoff, SecPruneScope{})
}

// SecPruneScope narrows a retention prune by project root hash (lane SEC-P4
// decision 10: a project whose org floor keeps findings longer than the
// node is pruned on its own). Only, when set, prunes those projects alone;
// Except leaves those projects out. The zero value prunes every project.
type SecPruneScope struct {
	Only   []string
	Except []string
}

// secPruneHashCap bounds the project hashes one scoped prune names.
const secPruneHashCap = 4096

// clause is the scope's SQL condition on project_root_hash and its args
// ("1=1" for the zero value).
func (sc SecPruneScope) clause() (string, []any, error) {
	list := sc.Only
	op := "IN"
	if len(list) == 0 {
		list, op = sc.Except, "NOT IN"
	}
	if len(list) == 0 {
		return "1=1", nil, nil
	}
	if len(list) > secPruneHashCap {
		return "", nil, fmt.Errorf("store.SecPruneScope: %d project hashes over the cap %d", len(list), secPruneHashCap)
	}
	args := make([]any, len(list))
	marks := make([]string, len(list))
	for i, h := range list {
		args[i], marks[i] = h, "?"
	}
	return "project_root_hash " + op + " (" + strings.Join(marks, ",") + ")", args, nil
}

// PruneSecFindingsScoped is PruneSecFindings over the projects scope names.
func (s *Store) PruneSecFindingsScoped(ctx context.Context, cutoff time.Time, scope SecPruneScope) (int64, error) {
	ts := cutoff.UTC().Format(secTime)
	where, scopeArgs, err := scope.clause()
	if err != nil {
		return 0, err
	}
	args := append([]any{ts}, scopeArgs...)
	//nolint:gosec // G202: where is scope.clause()'s fixed text with ? placeholders; every value is a bound parameter.
	res, err := s.db.ExecContext(ctx, `DELETE FROM sec_findings WHERE status <> 'open' AND closed_at <> '' AND closed_at < ? AND `+where, args...)
	if err != nil {
		return 0, fmt.Errorf("store.PruneSecFindings: %w", err)
	}
	n, _ := res.RowsAffected()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sec_finding_sightings WHERE finding_id NOT IN (SELECT id FROM sec_findings)`); err != nil {
		return n, fmt.Errorf("store.PruneSecFindings: sightings: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sec_finding_commits WHERE finding_id NOT IN (SELECT id FROM sec_findings)`); err != nil {
		return n, fmt.Errorf("store.PruneSecFindings: commits: %w", err)
	}
	//nolint:gosec // G202: where is scope.clause()'s fixed text with ? placeholders; every value is a bound parameter.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sec_scan_runs WHERE started_at < ? AND `+where, args...); err != nil {
		return n, fmt.Errorf("store.PruneSecFindings: runs: %w", err)
	}
	//nolint:gosec // G202: where is scope.clause()'s fixed text with ? placeholders; every value is a bound parameter.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sec_finding_events
		WHERE (finding_id <> '' AND finding_id NOT IN (SELECT id FROM sec_findings))
		   OR (at < ? AND (finding_id = '' OR finding_id NOT IN (SELECT id FROM sec_findings WHERE status = 'open')) AND `+where+`)`, args...); err != nil {
		return n, fmt.Errorf("store.PruneSecFindings: events: %w", err)
	}
	return n, nil
}

// SecLastDriverRun returns when the newest scan run of one driver over one
// project with one scope started (zero when none). The custom scanner
// schedule reads it so a daemon restart keeps each pair's last scheduled
// run instead of making every pair due at once. started_at is RFC3339Nano
// text, so MAX can misorder two runs within the same second; the schedule's
// interval is whole hours, so that never matters here.
func (s *Store) SecLastDriverRun(ctx context.Context, rootHash, driver string, scope secfinding.Scope) (time.Time, error) {
	var ts sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(started_at) FROM sec_scan_runs
		WHERE project_root_hash = ? AND driver = ? AND scope = ?`, rootHash, driver, string(scope)).Scan(&ts); err != nil {
		return time.Time{}, fmt.Errorf("store.SecLastDriverRun: %w", err)
	}
	if !ts.Valid {
		return time.Time{}, nil
	}
	t, err := time.Parse(secTime, ts.String)
	if err != nil {
		return time.Time{}, fmt.Errorf("store.SecLastDriverRun: parse %q: %w", ts.String, err)
	}
	return t, nil
}

// SecFeedbackQuery selects the findings TakeSecFeedback hands to the
// agent's post-tool reply (security pillar plan sections 5.11 (c) and 6.2
// step 2, lane sec-h).
type SecFeedbackQuery struct {
	// ProjectRootHash and SessionID scope the findings to the session's
	// own writes in its project; both are required.
	ProjectRootHash string
	SessionID       string
	// Limit caps the findings (default and maximum 3, the line cap).
	Limit int
	// Lease returns the findings without recording them: the caller holds
	// them under a short lease and records them with IDs only once the
	// hook acknowledged the reply that carried them (lane sec-polish,
	// audit finding F3), so a reply that never reached the agent loses no
	// line.
	Lease bool
	// Exclude leaves out these findings (the ones under the caller's
	// unexpired leases), so a line is never offered twice at once.
	Exclude []string
	// IDs, when not nil, restricts the take to these findings: the
	// acknowledgement of a leased offer. An empty, non-nil IDs takes none.
	IDs []string
}

// TakeSecFeedback returns the session's undelivered findings that are
// open, new (baseline new), high confidence and not excepted, the most
// severe first, and, unless q.Lease is set, records one feedback_sent
// event per finding in the same transaction, so each finding is handed
// out once. A finding closed, excepted or already sent since it was
// leased is neither returned nor recorded by the acknowledgement (q.IDs).
// It returns only rule data and the location: no message, evidence or
// fix-hint text (T8).
func (s *Store) TakeSecFeedback(ctx context.Context, q SecFeedbackQuery, now time.Time) ([]secfinding.Finding, error) {
	if q.ProjectRootHash == "" || q.SessionID == "" || (q.IDs != nil && len(q.IDs) == 0) {
		return nil, nil
	}
	limit := q.Limit
	if limit <= 0 || limit > 3 {
		limit = 3
	}
	args := []any{
		q.ProjectRootHash, q.SessionID, string(policy.FindingStatusOpen), string(policy.FindingBaselineNew),
		string(policy.FindingConfidenceHigh), SecEventFeedbackSent,
	}
	var only string
	if q.IDs != nil {
		only = " AND f.id IN (" + strings.TrimSuffix(strings.Repeat("?,", len(q.IDs)), ",") + ")"
		for _, id := range q.IDs {
			args = append(args, id)
		}
	}
	if len(q.Exclude) > 0 {
		only += " AND f.id NOT IN (" + strings.TrimSuffix(strings.Repeat("?,", len(q.Exclude)), ",") + ")"
		for _, id := range q.Exclude {
			args = append(args, id)
		}
	}
	args = append(args, limit)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store.TakeSecFeedback: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	//nolint:gosec // G202: the concatenated fragment is fixed SQL with ? placeholders; the ids bind as args
	rows, err := tx.QueryContext(ctx, `SELECT f.id, f.rule_id, f.rule_pack, f.category, f.severity, f.confidence, f.rel_path, f.start_line
		FROM sec_findings f
		WHERE f.project_root_hash = ? AND f.session_id = ? AND f.status = ? AND f.baseline = ? AND f.confidence = ?
			AND f.exception_id = ''
			AND NOT EXISTS (SELECT 1 FROM sec_finding_events e WHERE e.kind = ? AND e.finding_id = f.id)`+only+`
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
			f.first_seen, f.id
		LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.TakeSecFeedback: %w", err)
	}
	var out []secfinding.Finding
	for rows.Next() {
		var x secfinding.Finding
		var cat, sev, conf string
		if err := rows.Scan(&x.ID, &x.Rule.ID, &x.Rule.Pack, &cat, &sev, &conf, &x.Location.RelPath, &x.Location.StartLine); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.TakeSecFeedback: %w", err)
		}
		x.Category, x.Severity, x.Confidence = secfinding.Category(cat), secfinding.Severity(sev), secfinding.Confidence(conf)
		x.Project.RootHash, x.Lineage.SessionID = q.ProjectRootHash, q.SessionID
		out = append(out, x)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("store.TakeSecFeedback: %w", err)
	}
	_ = rows.Close()
	if q.Lease {
		return out, nil
	}
	ts := now.UTC().Format(secTime)
	for _, f := range out {
		if err := appendSecEvent(ctx, tx, f.ID, q.ProjectRootHash, SecEventFeedbackSent, q.SessionID, ts); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store.TakeSecFeedback: %w", err)
	}
	return out, nil
}

// SecFindingEvidence returns one finding's redacted evidence and the
// session it is attributed to (the explain flow, lane sec-h; the rule data
// comes from SecFindingByID). Read-only; ok is false for an unknown id.
func (s *Store) SecFindingEvidence(ctx context.Context, id string) (evidence, sessionID string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT evidence_redacted, COALESCE(session_id, '') FROM sec_findings WHERE id = ?`, id).
		Scan(&evidence, &sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("store.SecFindingEvidence: %w", err)
	}
	return evidence, sessionID, true, nil
}
