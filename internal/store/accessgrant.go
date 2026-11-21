package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Org access-grant cache seam (agent migration 152; request-grants design
// §3.1/§4.1). ONE OWNER: org_access_grant_state, org_access_grants and
// access_request_outbox are written exclusively here. NODE-LOCAL: received
// state and a local queue, never pushed (privacy sentinel).
//
// The cache writer (SaveAccessGrants) is reachable only from the verified-200
// branch of orgclient.FetchAccessGrants, like SaveOrgPricing: a 404, an
// unsigned reply or a refused document never reaches it, and only a signed
// body with an empty grant list may empty the cache.

// AccessGrantState is the cached, VERIFIED grants document plus its receipt.
type AccessGrantState struct {
	OrgID          string
	Subject        string
	Version        int64
	Body           string
	BodyHash       string
	Signature      string
	ServerPubkey   string
	ServerNowNs    int64
	ReceivedAtNs   int64
	LastVerifiedNs int64
	HighWaterNs    int64
	MaxOfflineS    int64
	IssuedAt       string
}

// Receipt is the honour-table input this state yields.
func (s AccessGrantState) Receipt() accessgrant.Receipt {
	return accessgrant.Receipt{
		ServerNowNs: s.ServerNowNs, ReceivedAtNs: s.ReceivedAtNs, LastVerifiedNs: s.LastVerifiedNs,
		HighWaterNs: s.HighWaterNs, MaxOfflineS: s.MaxOfflineS,
	}
}

// GetAccessGrantState returns the cached state; ok=false when this node never
// verified a grants document (every solo install).
func (s *Store) GetAccessGrantState(ctx context.Context) (AccessGrantState, bool, error) {
	var st AccessGrantState
	err := s.db.QueryRowContext(ctx, `
		SELECT org_id, subject, version, body, body_hash, signature, server_pubkey,
		       server_now_ns, received_at_ns, last_verified_ns, high_water_ns, max_offline_s, issued_at
		  FROM org_access_grant_state WHERE id = 1`).
		Scan(&st.OrgID, &st.Subject, &st.Version, &st.Body, &st.BodyHash, &st.Signature, &st.ServerPubkey,
			&st.ServerNowNs, &st.ReceivedAtNs, &st.LastVerifiedNs, &st.HighWaterNs, &st.MaxOfflineS, &st.IssuedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AccessGrantState{}, false, nil
	}
	if err != nil {
		return AccessGrantState{}, false, fmt.Errorf("store.GetAccessGrantState: %w", err)
	}
	return st, true, nil
}

// SaveAccessGrants replaces the cache with a newly VERIFIED document, in one
// transaction: the state row, then the grant rows (a grant id still present
// keeps its local uses_used; a grant no longer listed is gone). The high-water
// mark never moves down.
func (s *Store) SaveAccessGrants(ctx context.Context, st AccessGrantState, grants []orgcontract.AccessGrantWire) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.SaveAccessGrants: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	uses := map[int64]int64{}
	rows, err := tx.QueryContext(ctx, `SELECT grant_id, uses_used FROM org_access_grants`)
	if err != nil {
		return fmt.Errorf("store.SaveAccessGrants: read uses: %w", err)
	}
	for rows.Next() {
		var id, n int64
		if err := rows.Scan(&id, &n); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store.SaveAccessGrants: scan uses: %w", err)
		}
		uses[id] = n
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("store.SaveAccessGrants: read uses: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO org_access_grant_state (id, org_id, subject, version, body, body_hash, signature, server_pubkey,
		       server_now_ns, received_at_ns, last_verified_ns, high_water_ns, max_offline_s, issued_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		  org_id = excluded.org_id, subject = excluded.subject, version = excluded.version,
		  body = excluded.body, body_hash = excluded.body_hash, signature = excluded.signature,
		  server_pubkey = excluded.server_pubkey, server_now_ns = excluded.server_now_ns,
		  received_at_ns = excluded.received_at_ns, last_verified_ns = excluded.last_verified_ns,
		  high_water_ns = MAX(org_access_grant_state.high_water_ns, excluded.high_water_ns),
		  max_offline_s = excluded.max_offline_s, issued_at = excluded.issued_at`,
		st.OrgID, st.Subject, st.Version, st.Body, st.BodyHash, st.Signature, st.ServerPubkey,
		st.ServerNowNs, st.ReceivedAtNs, st.LastVerifiedNs, st.HighWaterNs, st.MaxOfflineS, st.IssuedAt); err != nil {
		return fmt.Errorf("store.SaveAccessGrants: state: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM org_access_grants`); err != nil {
		return fmt.Errorf("store.SaveAccessGrants: clear: %w", err)
	}
	for _, g := range grants {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO org_access_grants (grant_id, type, effect, subject_kind, machine_identity, rule_id, lane,
			       command_class, operand_hash, project_root_hash, target, starts_at_ns, expires_at_ns, max_uses,
			       uses_used, request_id, doc_version)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			g.ID, g.Type, g.Effect, g.SubjectKind, g.MachineIdentity, g.RuleID, g.Lane,
			g.CommandClass, g.OperandHash, g.ProjectRootHash, g.Target, g.StartsAtNs, g.ExpiresAtNs, g.MaxUses,
			uses[g.ID], g.RequestID, st.Version); err != nil {
			return fmt.Errorf("store.SaveAccessGrants: grant %d: %w", g.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.SaveAccessGrants: commit: %w", err)
	}
	return nil
}

// TouchAccessGrantsVerified records a VERIFIED 200 whose document was not
// newer than the cache (the same version re-signed): the offline window
// restarts from now. Callers reach it only after the signature verified.
func (s *Store) TouchAccessGrantsVerified(ctx context.Context, version, verifiedNs int64) error {
	if _, err := s.db.ExecContext(ctx, `
		UPDATE org_access_grant_state
		   SET last_verified_ns = MAX(last_verified_ns, ?), high_water_ns = MAX(high_water_ns, ?)
		 WHERE id = 1 AND version = ?`, verifiedNs, verifiedNs, version); err != nil {
		return fmt.Errorf("store.TouchAccessGrantsVerified: %w", err)
	}
	return nil
}

// NoteAccessGrantClock advances the high-water mark to nowNs (never down), so
// a clock set back later is read as the highest time already seen (GRANT-3).
func (s *Store) NoteAccessGrantClock(ctx context.Context, nowNs int64) error {
	if _, err := s.db.ExecContext(ctx, `
		UPDATE org_access_grant_state SET high_water_ns = ? WHERE id = 1 AND high_water_ns < ?`, nowNs, nowNs); err != nil {
		return fmt.Errorf("store.NoteAccessGrantClock: %w", err)
	}
	return nil
}

// CachedAccessGrants returns the cached grants with their local use counts.
func (s *Store) CachedAccessGrants(ctx context.Context) ([]accessgrant.Cached, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT grant_id, type, effect, subject_kind, machine_identity, rule_id, lane, command_class,
		       operand_hash, project_root_hash, target, starts_at_ns, expires_at_ns, max_uses, uses_used, request_id
		  FROM org_access_grants ORDER BY grant_id`)
	if err != nil {
		return nil, fmt.Errorf("store.CachedAccessGrants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []accessgrant.Cached
	for rows.Next() {
		var c accessgrant.Cached
		g := &c.Grant
		if err := rows.Scan(&g.ID, &g.Type, &g.Effect, &g.SubjectKind, &g.MachineIdentity, &g.RuleID, &g.Lane,
			&g.CommandClass, &g.OperandHash, &g.ProjectRootHash, &g.Target, &g.StartsAtNs, &g.ExpiresAtNs,
			&g.MaxUses, &c.UsesUsed, &g.RequestID); err != nil {
			return nil, fmt.Errorf("store.CachedAccessGrants: scan: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ConsumeAccessGrantUse counts one local use of a grant against the cap
// the caller read from the SIGNED document (maxUses 0 = unlimited), never the
// row's own max_uses copy. One conditional UPDATE: two processes racing on
// the last use serialise on SQLite's write lock and only one row change
// happens. ok=false means nothing was counted (spent, or no such grant).
func (s *Store) ConsumeAccessGrantUse(ctx context.Context, grantID, maxUses int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE org_access_grants SET uses_used = uses_used + 1
		 WHERE grant_id = ? AND (? = 0 OR uses_used < ?)`, grantID, maxUses, maxUses)
	if err != nil {
		return false, fmt.Errorf("store.ConsumeAccessGrantUse: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// AccessGrantView is one cached grant as the node's surfaces show it.
type AccessGrantView struct {
	Grant    orgcontract.AccessGrantWire `json:"grant"`
	UsesUsed int64                       `json:"uses_used"`
	// Honoured is whether the node would act on it right now; Reason says why
	// not (accessgrant.Reason*).
	Honoured bool   `json:"honoured"`
	Reason   string `json:"reason,omitempty"`
	// CoveredBy is the id of another grant in force on this machine that
	// already gives everything this one gives (accessgrant.Redundant), 0
	// when there is none: the page says so, so two rows for one rule do not
	// read as two different exceptions.
	CoveredBy int64 `json:"covered_by,omitempty"`
}

// AccessGrantsView is the node's whole grant picture for one enrolment.
type AccessGrantsView struct {
	Version        int64             `json:"version"`
	LastVerifiedNs int64             `json:"last_verified_ns"`
	MaxOfflineS    int64             `json:"max_offline_s"`
	Grants         []AccessGrantView `json:"grants"`
	// Unverified is true when the cached document no longer verifies on
	// this node (signature, key, org or subject): none of its grants is in
	// force, and a surface must not say it was confirmed (review M4-09).
	Unverified bool `json:"unverified,omitempty"`
}

// clearAccessGrants drops the org's grants and the outbox (unenrolment): a
// departed org's grants never outlive the enrolment that received them.
func (s *Store) clearAccessGrants(ctx context.Context) error {
	for _, q := range []string{
		`DELETE FROM org_access_grants`,
		`DELETE FROM org_access_grant_state`,
		`DELETE FROM access_request_outbox`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("store.clearAccessGrants: %w", err)
		}
	}
	return nil
}

// OutboxRequest is one queued access request.
type OutboxRequest struct {
	ID          int64  `json:"id"`
	OrgID       string `json:"org_id"`
	RequestJSON string `json:"request_json"`
	CreatedAt   string `json:"created_at"`
	Attempts    int64  `json:"attempts"`
	LastError   string `json:"last_error,omitempty"`
	LastAttempt string `json:"last_attempt,omitempty"`
}

// MaxOutboxRequests bounds the queue (the server's own open-request cap is 20).
const MaxOutboxRequests = 20

// ErrOutboxFull is returned when the queue already holds MaxOutboxRequests.
var ErrOutboxFull = errors.New("store: access request outbox is full")

// EnqueueAccessRequest queues one request (the exact JSON the developer
// previewed) for the org it was raised against.
func (s *Store) EnqueueAccessRequest(ctx context.Context, orgID, requestJSON string, now time.Time) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_request_outbox`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store.EnqueueAccessRequest: %w", err)
	}
	if n >= MaxOutboxRequests {
		return 0, ErrOutboxFull
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO access_request_outbox (org_id, request_json, created_at) VALUES (?, ?, ?)`,
		orgID, requestJSON, timestamp(now))
	if err != nil {
		return 0, fmt.Errorf("store.EnqueueAccessRequest: %w", err)
	}
	return res.LastInsertId()
}

// ListAccessRequestOutbox returns the queue, oldest first.
func (s *Store) ListAccessRequestOutbox(ctx context.Context) ([]OutboxRequest, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, org_id, request_json, created_at, attempts, last_error, last_attempt
		  FROM access_request_outbox ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store.ListAccessRequestOutbox: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []OutboxRequest{}
	for rows.Next() {
		var r OutboxRequest
		if err := rows.Scan(&r.ID, &r.OrgID, &r.RequestJSON, &r.CreatedAt, &r.Attempts, &r.LastError, &r.LastAttempt); err != nil {
			return nil, fmt.Errorf("store.ListAccessRequestOutbox: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteOutboxRequest removes one queued request (sent, or cancelled by the
// developer before it was sent).
func (s *Store) DeleteOutboxRequest(ctx context.Context, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM access_request_outbox WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("store.DeleteOutboxRequest: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// NoteOutboxAttempt records a failed send.
func (s *Store) NoteOutboxAttempt(ctx context.Context, id int64, errText string, now time.Time) error {
	if len(errText) > 300 {
		errText = errText[:300]
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE access_request_outbox SET attempts = attempts + 1, last_error = ?, last_attempt = ? WHERE id = ?`,
		errText, timestamp(now), id); err != nil {
		return fmt.Errorf("store.NoteOutboxAttempt: %w", err)
	}
	return nil
}

// draftProject is a guard event's project as a request draft carries it.
type draftProject struct {
	hash, root string
}

// draftProjectRules picks the project a request drafted from a guard event
// is scoped on, an ordered table walked top down (GRANT-20):
//
//	| # | the guard_events row carries        | project                          |
//	|---|-------------------------------------|----------------------------------|
//	| 1 | project_root_hash (agent 253)       | the event's (hash + its root)    |
//	| 2 | no hash (pre-253, or none resolved) | the session's project            |
//
// Row 1 is the project the gate matched grants on for that call (the hook's
// cwd-derived root, the host-named root, or the session's project on the
// proxy lane), so the grant the request yields matches the next identical
// call. Row 2 keeps every older row drafting exactly as before. The event's
// root is never mixed with the session's: a row whose hash is set but whose
// root is not shows no root rather than a different project's.
var draftProjectRules = []struct {
	name  string
	match func(event, session draftProject) bool
	pick  func(event, session draftProject) draftProject
}{
	{"event", func(e, _ draftProject) bool { return e.hash != "" }, func(e, _ draftProject) draftProject { return e }},
	{"session", func(_, _ draftProject) bool { return true }, func(_, s draftProject) draftProject { return s }},
}

// resolveDraftProject walks draftProjectRules.
func resolveDraftProject(event, session draftProject) draftProject {
	for _, r := range draftProjectRules {
		if r.match(event, session) {
			return r.pick(event, session)
		}
	}
	return draftProject{}
}

// GuardEventRequestDraft reads one guard event and shapes it into a request draft.
// CommandClass is "<category>/<event_kind>" (design §3.2) and OperandHash is
// the event's target_hash, so an exact grant matches the same command again
// and nothing else. The project is the one the gate matched grants on for
// that call when the row recorded it, else the session's (resolveDraftProject).
func (s *Store) GuardEventRequestDraft(ctx context.Context, id int64) (orgcontract.AccessRequestCreate, bool, error) {
	var (
		ruleID, category, severity, decision, tool, eventKind, targetHash, excerpt string
		sessionID, branch                                                          string
		event, session                                                             draftProject
		enforced                                                                   int64
		ts                                                                         string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT ge.rule_id, COALESCE(ge.category,''), COALESCE(ge.severity,''), COALESCE(ge.decision,''),
		       COALESCE(ge.tool,''), COALESCE(ge.event_kind,''), COALESCE(ge.target_hash,''),
		       COALESCE(ge.target_excerpt,''), COALESCE(ge.session_id,''), COALESCE(ge.enforced,0), ge.ts,
		       COALESCE(ge.project_root_hash,''), COALESCE(ge.project_root,''),
		       COALESCE(p.root_path_hash,''), COALESCE(p.root_path,''), COALESCE(s.git_branch,'')
		  FROM guard_events ge
		  LEFT JOIN sessions s ON s.id = ge.session_id
		  LEFT JOIN projects p ON p.id = s.project_id
		 WHERE ge.id = ?`, id).
		Scan(&ruleID, &category, &severity, &decision, &tool, &eventKind, &targetHash, &excerpt,
			&sessionID, &enforced, &ts, &event.hash, &event.root, &session.hash, &session.root, &branch)
	if errors.Is(err, sql.ErrNoRows) {
		return orgcontract.AccessRequestCreate{}, false, nil
	}
	if err != nil {
		return orgcontract.AccessRequestCreate{}, false, fmt.Errorf("store.GuardEventRequestDraft: %w", err)
	}
	project := resolveDraftProject(event, session)
	projectHash, projectRoot := project.hash, project.root
	var hits int64
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM guard_events WHERE rule_id = ? AND ts >= ?`,
		ruleID, time.Now().UTC().Add(-7*24*time.Hour).Format(time.RFC3339)).Scan(&hits)
	class := ""
	if category != "" || eventKind != "" {
		class = category + "/" + eventKind
	}
	return orgcontract.AccessRequestCreate{
		RequestType: accessgrant.TypeGuardExemption,
		Payload: &orgcontract.AccessRequestPayload{
			RuleID: ruleID, Breadth: accessgrant.BreadthExact, OperandHash: targetHash,
			CommandClass: class, ProjectRootHash: projectHash,
		},
		Context: &orgcontract.AccessRequestContext{
			RuleID: ruleID, Category: category, Severity: severity, Decision: decision,
			Enforced: enforced != 0, Tool: tool, TargetHash: targetHash, ProjectRootHash: projectHash,
			SessionID: sessionID, EventID: id, Hits7d: hits,
			TargetExcerpt: excerpt, ProjectRoot: projectRoot, GitBranch: branch,
		},
		RequestedDurationS: int64(accessgrant.DefaultDuration / time.Second),
	}, true, nil
}

// GuardRuleRequestDraft shapes the request draft behind the guard's
// org-locked deny link, /requests?rule=R&session=S (request-grants G4). The
// vendor reply is written before the event is persisted, so the link names
// the rule and the session rather than an event id: the newest event for
// that rule in that session yields the exact draft GuardEventRequestDraft
// builds; with no such event (or no session) the draft is rule-wide and
// carries the session in its context only. It never borrows another
// session's event, whose operand would be someone else's command.
func (s *Store) GuardRuleRequestDraft(ctx context.Context, ruleID, sessionID string) (orgcontract.AccessRequestCreate, error) {
	if sessionID != "" {
		var id int64
		err := s.db.QueryRowContext(ctx, `
			SELECT id FROM guard_events WHERE rule_id = ? AND session_id = ?
			 ORDER BY ts DESC, id DESC LIMIT 1`, ruleID, sessionID).Scan(&id)
		switch {
		case err == nil:
			d, ok, derr := s.GuardEventRequestDraft(ctx, id)
			if derr != nil {
				return orgcontract.AccessRequestCreate{}, fmt.Errorf("store.GuardRuleRequestDraft: %w", derr)
			}
			if ok {
				return d, nil
			}
		case !errors.Is(err, sql.ErrNoRows):
			return orgcontract.AccessRequestCreate{}, fmt.Errorf("store.GuardRuleRequestDraft: %w", err)
		}
	}
	return orgcontract.AccessRequestCreate{
		RequestType:        accessgrant.TypeGuardExemption,
		Payload:            &orgcontract.AccessRequestPayload{RuleID: ruleID, Breadth: accessgrant.BreadthRule},
		Context:            &orgcontract.AccessRequestContext{RuleID: ruleID, SessionID: sessionID},
		RequestedDurationS: int64(accessgrant.DefaultDuration / time.Second),
	}, nil
}
