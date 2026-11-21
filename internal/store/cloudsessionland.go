package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/shiptoken"
)

// CloudSessionLandResult is what LandCloudSessionEnvelope did.
type CloudSessionLandResult struct {
	Ingest IngestResult
	// Stamped counts sessions whose execution location or vendor reference
	// this batch set (first-wins-unless-empty, SetSessionExecution).
	Stamped int
	// Projects counts the batch's sessions per project source.
	Projects map[shiptoken.ProjectSource]int
	// NotLanded counts admitted rows the node does not land, per family.
	NotLanded map[string]int
	// Tagged counts sessions this batch tagged sandbox-reported
	// (sessions.reported_via_token, agent migration 245, CA-D18).
	Tagged int
	// SkippedSessions counts, per shiptoken ownership reason, the envelope
	// sessions the batch may not write (ledger CLOUDSESS-8): a session the
	// node captured itself, or one another token created.
	SkippedSessions map[string]int
	// SkippedRows counts, per family, the rows dropped with those sessions.
	SkippedRows map[string]int
	// RowsRemaining is what is left of the token's volume cap
	// (shiptoken.NodeRowCap) after this batch.
	RowsRemaining int64
}

// ShipTokenVolumeExhaustedError refuses a batch that would take a node ship
// token past its volume cap (shiptoken.NodeRowCap). Nothing was landed.
type ShipTokenVolumeExhaustedError struct {
	Batch     int64
	Remaining int64
	Cap       int64
}

func (e ShipTokenVolumeExhaustedError) Error() string {
	return fmt.Sprintf("the batch's %d rows would take the ship token past its volume cap of %d rows (%d left)", e.Batch, e.Cap, e.Remaining)
}

// cloudSessionLandMu serializes node landings, so the ownership check, the
// volume check and the tag of a new session are one step against another
// batch in this process (the daemon is the node DB's only ingest writer of
// this route).
var cloudSessionLandMu sync.Mutex

// cloudSessionRowCap is the node ship token volume cap the landing applies:
// shiptoken.NodeRowCap, a variable only so a test can lower it.
var cloudSessionRowCap = shiptoken.NodeRowCap

// LandCloudSessionEnvelope lands an ADMITTED cloud-session envelope (the
// individual destination of Rail S, lane CA-B3) into the node's own tables:
// the ownership filter, the volume cap, the pure shiptoken.PlanNode mapping,
// then the ordinary Ingest, then the execution stamps through
// SetSessionExecution. Projects resolve by the remote rule (CA-D3) or the
// remote's hash, never by the sandbox's own filesystem root. Ingest is
// idempotent on source event ids, so a re-sent batch lands nothing twice.
// tokenID is the presenting ship token's public id: every session the batch
// creates is tagged sandbox-reported with it (decision CA-D18).
//
// Ownership (ledger CLOUDSESS-8): a session id the node already holds is
// writable only by the token that created it; a session the node captured
// itself, or one another token created, is skipped with its rows and counted
// in SkippedSessions / SkippedRows. Volume: the rows the token has landed
// (its tagged sessions' actions and token rows) plus this batch's landable
// rows must fit shiptoken.NodeRowCap, else ShipTokenVolumeExhaustedError and
// nothing lands.
func (s *Store) LandCloudSessionEnvelope(ctx context.Context, env orgcontract.PushEnvelope, tokenID string) (CloudSessionLandResult, error) {
	if !shiptoken.ValidID(tokenID) {
		return CloudSessionLandResult{}, errors.New("store.LandCloudSessionEnvelope: a ship token id is required")
	}
	cloudSessionLandMu.Lock()
	defer cloudSessionLandMu.Unlock()

	skippedSessions := map[string]int{}
	skip := map[string]bool{}
	for _, sid := range shiptoken.EnvelopeSessionIDs(env) {
		exists, via, err := s.sessionReportedVia(ctx, sid)
		if err != nil {
			return CloudSessionLandResult{}, fmt.Errorf("store.LandCloudSessionEnvelope: %w", err)
		}
		if reason := shiptoken.SessionOwnership(exists, via, tokenID); reason != "" {
			skip[sid] = true
			skippedSessions[reason]++
		}
	}
	env, skippedRows := shiptoken.WithoutSessions(env, skip)

	used, err := s.cloudSessionTokenRowsUsed(ctx, tokenID)
	if err != nil {
		return CloudSessionLandResult{}, fmt.Errorf("store.LandCloudSessionEnvelope: %w", err)
	}
	batch := int64(len(env.Actions) + len(env.TokenUsage))
	fits, remaining := shiptoken.NodeVolume(used, batch, cloudSessionRowCap)
	if !fits {
		return CloudSessionLandResult{}, ShipTokenVolumeExhaustedError{Batch: batch, Remaining: remaining, Cap: cloudSessionRowCap}
	}

	var lookupErr error
	lookup := shiptoken.ProjectLookup{
		ByRemote: func(raw string) (string, string, bool) {
			norm := git.NormalizeRemote(raw)
			if !hostedRemote(norm) {
				return "", "", false
			}
			p, ok, err := s.ProjectByRemote(ctx, norm)
			if err != nil {
				lookupErr = err
				return "", "", false
			}
			if ok {
				return p.RootPath, norm, true
			}
			return models.SyntheticCloudProjectRoot(norm), norm, true
		},
		ByRemoteHash: func(hash string) (string, string, bool) {
			root, remote, ok, err := s.projectByRemoteHash(ctx, hash)
			if err != nil {
				lookupErr = err
			}
			return root, remote, ok
		},
	}
	plan := shiptoken.PlanNode(env, lookup)
	if lookupErr != nil {
		return CloudSessionLandResult{}, fmt.Errorf("store.LandCloudSessionEnvelope: project lookup: %w", lookupErr)
	}
	res, err := s.Ingest(ctx, plan.Events, plan.Tokens, IngestOptions{})
	if err != nil {
		return CloudSessionLandResult{}, fmt.Errorf("store.LandCloudSessionEnvelope: %w", err)
	}
	out := CloudSessionLandResult{
		Ingest: res, Projects: plan.Projects, NotLanded: plan.NotLanded,
		SkippedSessions: skippedSessions, SkippedRows: skippedRows,
		RowsRemaining: remaining - int64(res.ActionsInserted+res.TokensInserted),
	}
	if out.RowsRemaining < 0 {
		out.RowsRemaining = 0
	}
	for _, ex := range plan.Executions {
		ok, err := s.SetSessionExecution(ctx, ex)
		if err != nil {
			return out, fmt.Errorf("store.LandCloudSessionEnvelope: %w", err)
		}
		if ok {
			out.Stamped++
		}
	}
	for _, sid := range plan.SessionIDs {
		ok, err := s.tagSessionReportedVia(ctx, sid, tokenID)
		if err != nil {
			return out, fmt.Errorf("store.LandCloudSessionEnvelope: %w", err)
		}
		if ok {
			out.Tagged++
		}
	}
	return out, nil
}

// tagSessionReportedVia stamps sessions.reported_via_token (agent migration
// 245) when it is still empty. The one writer of the column: first wins, a
// later batch under another token never re-tags, nothing clears it. The
// column is not in the org-push change trigger, so the stamp never
// re-pushes the session.
func (s *Store) tagSessionReportedVia(ctx context.Context, sessionID, tokenID string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE sessions SET reported_via_token = ?
 WHERE id = ? AND IFNULL(reported_via_token, '') = ''`, tokenID, sessionID)
	if err != nil {
		return false, fmt.Errorf("store.tagSessionReportedVia: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SessionReportedVia returns the ship token id a session was reported
// through ("" for a session this node captured itself).
func (s *Store) SessionReportedVia(ctx context.Context, sessionID string) (string, error) {
	_, via, err := s.sessionReportedVia(ctx, sessionID)
	return via, err
}

// sessionReportedVia reports whether the node holds a session, and the ship
// token id that created it ("" for a session the node captured itself).
func (s *Store) sessionReportedVia(ctx context.Context, sessionID string) (exists bool, via string, err error) {
	var v sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT reported_via_token FROM sessions WHERE id = ?`, sessionID).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("store.sessionReportedVia: %w", err)
	}
	return true, v.String, nil
}

// cloudSessionTokenRowsUsed counts the action and token rows a node ship
// token has landed: every row of the sessions it created. The ownership rule
// keeps a token's batches inside its own sessions, so this is exactly what
// the token wrote, counted from the rows themselves (no counter column to
// drift); a deduped re-send adds nothing.
func (s *Store) cloudSessionTokenRowsUsed(ctx context.Context, tokenID string) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `
SELECT (SELECT COUNT(*) FROM actions a JOIN sessions s ON s.id = a.session_id WHERE s.reported_via_token = ?)
     + (SELECT COUNT(*) FROM token_usage t JOIN sessions s ON s.id = t.session_id WHERE s.reported_via_token = ?)`,
		tokenID, tokenID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store.cloudSessionTokenRowsUsed: %w", err)
	}
	return n, nil
}

// projectByRemoteHash returns the root and remote of the project whose
// git_remote_hash matches: a local checkout before a synthetic cloud root,
// then the oldest.
func (s *Store) projectByRemoteHash(ctx context.Context, hash string) (string, string, bool, error) {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return "", "", false, nil
	}
	var root string
	var remote sql.NullString
	err := s.db.QueryRowContext(ctx, `
SELECT root_path, git_remote FROM projects
 WHERE git_remote_hash = ? AND root_path <> ''
 ORDER BY CASE WHEN root_path LIKE ? THEN 1 ELSE 0 END, id
 LIMIT 1`, hash, models.CloudProjectRootPrefix+"%").Scan(&root, &remote)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("store.projectByRemoteHash: %w", err)
	}
	return root, remote.String, true, nil
}
