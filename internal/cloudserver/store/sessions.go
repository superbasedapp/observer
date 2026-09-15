package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// sessions.go is the portal Sessions read surface (W6c, closes D4): a paginated
// list of the account's enriched sessions and a per-session detail carrying
// every result, its provenance, its append-only revision history, and which
// result is the current head. It is READ-ONLY and RLS-scoped — every query runs
// under WithAccount, so a portal session can only ever see its own account.

// AccountSessionSummary is one row of the Sessions list.
type AccountSessionSummary struct {
	CloudSessionID string    `json:"cloud_session_id"`
	Tool           string    `json:"tool"`
	ModelFamily    string    `json:"model_family"`
	CreatedAt      time.Time `json:"created_at"`
	// ResultCount is how many enrichment results this session has (a
	// regeneration adds one; superseded ones still count as history).
	ResultCount int `json:"result_count"`
	// Edited is true when the developer has corrected any of this session's
	// results (at least one revision exists).
	Edited bool `json:"edited"`
	// EffectiveTitle is what the portal shows: the latest user title correction
	// on the current result if any, else the current result's AI title. Empty
	// when the current result is tombstoned (deleted).
	EffectiveTitle string `json:"effective_title"`
	// Tombstoned is true when the current result's body has been deleted.
	Tombstoned bool `json:"tombstoned"`
}

// SessionsPage is a page of AccountSessionSummary plus the keyset cursor to
// fetch the next (older) page. HasMore reports whether another page exists.
type SessionsPage struct {
	Sessions []AccountSessionSummary
	HasMore  bool
	// NextCreatedAt / NextCloudSessionID are the keyset of the LAST row, echoed
	// so the caller can build an opaque `after` cursor. Zero when the page is
	// empty.
	NextCreatedAt      time.Time
	NextCloudSessionID string
}

// ListAccountSessions returns one page of the account's enriched sessions,
// newest-first, keyset-paginated on (created_at DESC, cloud_session_id DESC) —
// a stable order because (account_id, cloud_session_id) is unique. A zero
// afterCreatedAt starts at the newest session; otherwise the page begins
// strictly before (afterCreatedAt, afterCloudSessionID).
//
// The "effective title" is computed server-side with two LATERAL lookups: the
// CURRENT result (the newest non-superseded result of the session, falling back
// to the newest overall) and, over that result, the newest revision that set a
// title. This is the "latest explicit user act wins" head rule (R6) reduced to
// exactly the one string the list needs; the full head is on the detail.
func (s *Store) ListAccountSessions(ctx context.Context, accountID string, limit int, afterCreatedAt time.Time, afterCloudSessionID string) (SessionsPage, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	var page SessionsPage
	// Fetch limit+1 to detect a further page without a second query.
	fetch := limit + 1
	// A zero afterCreatedAt ⇒ NULL ⇒ "start at the newest" (the $2 IS NULL arm).
	var afterTime *time.Time
	if !afterCreatedAt.IsZero() {
		afterTime = &afterCreatedAt
	}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT cs.cloud_session_id, cs.tool, cs.model_family, cs.created_at,
			        cur.result_count, cur.edited,
			        coalesce(rev.title, cur.ai_title, '') AS effective_title,
			        cur.tombstoned
			   FROM cloud_sessions cs
			   JOIN LATERAL (
			        SELECT count(*)                                        AS result_count,
			               bool_or(EXISTS (SELECT 1 FROM result_revisions x
			                                WHERE x.account_id = r.account_id AND x.result_id = r.id)) AS edited,
			               (array_agg(r.id ORDER BY r.superseded ASC, r.created_at DESC))[1]           AS head_id,
			               (array_agg(r.result->>'title' ORDER BY r.superseded ASC, r.created_at DESC))[1] AS ai_title,
			               (array_agg(r.result = $4::jsonb ORDER BY r.superseded ASC, r.created_at DESC))[1] AS tombstoned
			          FROM analysis_results r
			          JOIN analysis_jobs j ON j.account_id = r.account_id AND j.id = r.job_id
			         WHERE r.account_id = cs.account_id AND j.session_pk = cs.id
			   ) cur ON cur.result_count > 0
			   LEFT JOIN LATERAL (
			        SELECT rr.correction->>'title' AS title
			          FROM result_revisions rr
			         WHERE rr.account_id = cs.account_id AND rr.result_id = cur.head_id
			           AND rr.correction ? 'title'
			         ORDER BY rr.revision_seq DESC
			         LIMIT 1
			   ) rev ON true
			  WHERE cs.account_id = $1::uuid
			    AND ($2::timestamptz IS NULL
			         OR (cs.created_at, cs.cloud_session_id) < ($2::timestamptz, $3))
			  ORDER BY cs.created_at DESC, cs.cloud_session_id DESC
			  LIMIT $5`,
			accountID, afterTime, afterCloudSessionID, tombstoneResult, fetch)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var it AccountSessionSummary
			if e := rows.Scan(&it.CloudSessionID, &it.Tool, &it.ModelFamily, &it.CreatedAt,
				&it.ResultCount, &it.Edited, &it.EffectiveTitle, &it.Tombstoned); e != nil {
				return e
			}
			page.Sessions = append(page.Sessions, it)
		}
		return rows.Err()
	})
	if err != nil {
		return SessionsPage{}, fmt.Errorf("cloudserver/store.ListAccountSessions: %w", err)
	}
	if len(page.Sessions) > limit {
		page.HasMore = true
		page.Sessions = page.Sessions[:limit]
	}
	if n := len(page.Sessions); n > 0 {
		page.NextCreatedAt = page.Sessions[n-1].CreatedAt
		page.NextCloudSessionID = page.Sessions[n-1].CloudSessionID
	}
	return page, nil
}

// SessionResultDetail is one result within a session detail, with its provenance
// flags, ETag component, tombstone state, raw stored body, and revision history.
// The RAW body is returned; the API boundary normalizes it to safe bytes before
// serving (mirroring handleResults), so the store stays free of the cloudcontract
// dependency.
type SessionResultDetail struct {
	ResultID      string           `json:"result_id"`
	CreatedAt     time.Time        `json:"created_at"`
	AISource      bool             `json:"ai_source"`
	Superseded    bool             `json:"superseded"`
	SupersededBy  string           `json:"superseded_by,omitempty"`
	CorrectionSeq int64            `json:"correction_seq"`
	Tombstoned    bool             `json:"tombstoned"`
	Result        json.RawMessage  `json:"result"`
	Revisions     []ResultRevision `json:"revisions"`
}

// SessionDetail is the per-session detail: session meta, every result
// newest-first, and which result is the current head (the newest non-superseded
// result, else the newest overall).
type SessionDetail struct {
	CloudSessionID string                `json:"cloud_session_id"`
	Tool           string                `json:"tool"`
	ModelFamily    string                `json:"model_family"`
	CreatedAt      time.Time             `json:"created_at"`
	HeadResultID   string                `json:"head_result_id"`
	Results        []SessionResultDetail `json:"results"`
}

// GetAccountSession returns the detail for one of the account's sessions, or
// ErrNotFound when the pseudonym is unknown or has no results. Results are
// newest-first; each carries its full revision history (also newest-first). The
// head is the newest non-superseded result (the "current" enrichment).
func (s *Store) GetAccountSession(ctx context.Context, accountID, cloudSessionID string) (SessionDetail, error) {
	var det SessionDetail
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var sessionPK string
		if e := tx.QueryRow(ctx,
			`SELECT id::text, cloud_session_id, tool, model_family, created_at
			   FROM cloud_sessions
			  WHERE account_id = $1::uuid AND cloud_session_id = $2`,
			accountID, cloudSessionID).Scan(&sessionPK, &det.CloudSessionID, &det.Tool, &det.ModelFamily, &det.CreatedAt); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("load session: %w", e)
		}

		rows, e := tx.Query(ctx,
			`SELECT r.id::text, r.created_at, r.ai_source, r.superseded,
			        coalesce(r.superseded_by::text, ''), r.correction_seq,
			        (r.result = $3::jsonb) AS tombstoned, r.result
			   FROM analysis_results r
			   JOIN analysis_jobs j ON j.account_id = r.account_id AND j.id = r.job_id
			  WHERE r.account_id = $1::uuid AND j.session_pk = $2::uuid
			  ORDER BY r.superseded ASC, r.created_at DESC`,
			accountID, sessionPK, tombstoneResult)
		if e != nil {
			return fmt.Errorf("load results: %w", e)
		}
		var results []SessionResultDetail
		func() {
			defer rows.Close()
			for rows.Next() {
				var rd SessionResultDetail
				var raw []byte
				if e = rows.Scan(&rd.ResultID, &rd.CreatedAt, &rd.AISource, &rd.Superseded,
					&rd.SupersededBy, &rd.CorrectionSeq, &rd.Tombstoned, &raw); e != nil {
					return
				}
				rd.Result = json.RawMessage(raw)
				results = append(results, rd)
			}
			e = rows.Err()
		}()
		if e != nil {
			return fmt.Errorf("scan results: %w", e)
		}
		if len(results) == 0 {
			return ErrNotFound
		}

		// Attach each result's revision history and choose the head (the first
		// row is the newest non-superseded result thanks to the ORDER BY).
		for i := range results {
			revs, re := loadRevisionsTx(ctx, tx, accountID, results[i].ResultID)
			if re != nil {
				return re
			}
			results[i].Revisions = revs
		}
		det.Results = results
		det.HeadResultID = results[0].ResultID
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return SessionDetail{}, err
		}
		return SessionDetail{}, fmt.Errorf("cloudserver/store.GetAccountSession: %w", err)
	}
	return det, nil
}

// loadRevisionsTx reads a result's revisions newest-first inside an existing
// tenant transaction (shared by GetAccountSession).
func loadRevisionsTx(ctx context.Context, tx pgx.Tx, accountID, resultID string) ([]ResultRevision, error) {
	rows, err := tx.Query(ctx,
		`SELECT revision_seq, editor, source, correction, created_at
		   FROM result_revisions
		  WHERE account_id = $1::uuid AND result_id = $2::uuid
		  ORDER BY revision_seq DESC`,
		accountID, resultID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ResultRevision
	for rows.Next() {
		var rv ResultRevision
		var raw []byte
		if err := rows.Scan(&rv.RevisionSeq, &rv.Editor, &rv.Source, &raw, &rv.CreatedAt); err != nil {
			return nil, err
		}
		rv.Correction = json.RawMessage(raw)
		out = append(out, rv)
	}
	return out, rows.Err()
}
