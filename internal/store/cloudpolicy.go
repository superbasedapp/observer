package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// cloudpolicy.go is the store seam over migration 115's cloud_enrich_policy
// singleton (value-upgrade plan of record §W2) plus two small read helpers the
// enable/disable flow and the dashboard ledger need: cancelling queued
// per-session evidence on disable, finding the outbox item behind a receipt,
// and a content-free ledger read.
//
// Same discipline as cloudlocal.go: this file does NOT import
// internal/cloudcontract or internal/cloudevidence — the purpose vocabulary is
// duplicated as plain strings (cloudPurposeStructuralInsights already lives in
// structuralinsights.go; cloudPurposeContextEnrichment is added here), and it
// never imports internal/cloudclient/cloudpop/cloudcred (the zero-egress
// invariant). cloud_enrich_policy is NODE-LOCAL like every other cloud_*
// table and never enters the org-push wire.

// CloudEnrichLevel is the closed vocabulary for cloud_enrich_policy.level —
// which purpose (if any) the background enrichment path may mint per-session
// receipts under.
type CloudEnrichLevel string

const (
	// CloudEnrichOff means background enrichment mints nothing; per-session
	// enrichment still works through the existing explicit consent flow.
	CloudEnrichOff CloudEnrichLevel = "off"
	// CloudEnrichTitles authorizes the structural_activity_insights purpose
	// only: a structural summary and the first user prompt, nothing else.
	CloudEnrichTitles CloudEnrichLevel = "titles"
	// CloudEnrichExcerpts authorizes bounded_context_enrichment, which always
	// implies (and includes) the structural purpose too
	// (cmd/observer/cloud.go::cloudPurposeSet).
	CloudEnrichExcerpts CloudEnrichLevel = "excerpts"
)

// cloudPurposeContextEnrichment mirrors cloudcontract.PurposeContextEnrichment
// ("bounded_context_enrichment"). Duplicated as a plain string for the same
// reason cloudPurposeStructuralInsights is (structuralinsights.go): this seam
// deliberately does not depend on the contract package.
const cloudPurposeContextEnrichment = "bounded_context_enrichment"

// CloudEnrichPolicy is the developer's own standing intent for per-session
// enrichment: which level the background path may mint receipts under, and
// whether background enrichment runs at all. It is NOT a consent receipt — it
// binds nothing and authorizes no upload by itself; the consent-gated egress
// seam still demands a live receipt per upload regardless of what this says
// (migration 115's header).
type CloudEnrichPolicy struct {
	Level CloudEnrichLevel
	// EvidenceSettings is nil for a legacy policy using the original selector.
	EvidenceSettings *CloudEvidenceSettings
	// Generation changes on every recorded policy edit and fences background work.
	Generation int64
	// Background is whether the background enrichment path runs unattended at
	// this level. False means the developer enriches sessions themselves
	// (`observer cloud consent` / the dashboard's Enrich now button).
	Background bool
	// PolicyVersion is the provider-retention disclosure version
	// (cloudcontract.ProviderPosturePolicyVersion) that was shown when this
	// policy was last recorded.
	PolicyVersion string
	// Source names who recorded this policy (e.g. "cli", "dashboard").
	Source    string
	UpdatedAt time.Time
	// Since is WHEN this policy last transitioned from off to on (migration
	// 117). It is maintained entirely by SetCloudEnrichPolicy — a caller
	// never sets it directly, the same way a caller never picks UpdatedAt's
	// zero-means-now default. Zero means the policy is off, or has never
	// been turned on. cmd/observer/cloudautoenrich.go's background sweep
	// uses it to bound which sessions may be auto-enqueued: one started
	// before Since is never touched, so turning background enrichment on
	// never reaches back and uploads history.
	Since time.Time
}

// PurposeName maps a level to the consent purpose the background path mints
// receipts under: titles -> structural_activity_insights, excerpts ->
// bounded_context_enrichment, off -> ok=false (nothing is minted).
func (p CloudEnrichPolicy) PurposeName() (string, bool) {
	switch p.Level {
	case CloudEnrichTitles:
		return cloudPurposeStructuralInsights, true
	case CloudEnrichExcerpts:
		return cloudPurposeContextEnrichment, true
	default:
		return "", false
	}
}

// GetCloudEnrichPolicy loads the singleton row. ok=false means no row has ever
// been recorded (the developer has never run `observer cloud enable`).
func (s *Store) GetCloudEnrichPolicy(ctx context.Context) (CloudEnrichPolicy, bool, error) {
	var (
		p            CloudEnrichPolicy
		level        string
		background   int
		updatedAt    string
		since        string
		settingsJSON string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT level, background, policy_version, source, updated_at, since, generation, evidence_settings_json
		  FROM cloud_enrich_policy WHERE id = 1`).
		Scan(&level, &background, &p.PolicyVersion, &p.Source, &updatedAt, &since, &p.Generation, &settingsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudEnrichPolicy{}, false, nil
	}
	if err != nil {
		return CloudEnrichPolicy{}, false, fmt.Errorf("store.GetCloudEnrichPolicy: %w", err)
	}
	p.EvidenceSettings, err = ParseCloudEvidenceSettings(settingsJSON)
	if err != nil {
		return CloudEnrichPolicy{}, false, fmt.Errorf("store.GetCloudEnrichPolicy: %w", err)
	}
	p.Level = CloudEnrichLevel(level)
	p.Background = background != 0
	p.UpdatedAt = cloudParseTime(updatedAt)
	p.Since = cloudParseTime(since)
	return p, true, nil
}

// SetCloudEnrichPolicy upserts the singleton row (id=1). A zero UpdatedAt is
// stamped to time.Now().UTC(). Returns an error for any level outside the
// closed vocabulary.
//
// `since` (migration 117) is entirely OWNED here, never taken from p.Since —
// the caller (cmd/observer/cloudenable.go, the dashboard's cloud_policy.go)
// only ever passes Level/Background/PolicyVersion/Source. The rule: an
// off->on transition stamps `since` to now; staying on (a level or
// background tweak with the row already on) carries the existing `since`
// forward unchanged; going ->off clears it to "". The read-then-write runs
// inside one transaction so two concurrent `observer cloud enable` calls
// can't race the transition check.
func (s *Store) SetCloudEnrichPolicy(ctx context.Context, p CloudEnrichPolicy) error {
	switch p.Level {
	case CloudEnrichOff, CloudEnrichTitles, CloudEnrichExcerpts:
	default:
		return fmt.Errorf("store.SetCloudEnrichPolicy: unknown level %q", p.Level)
	}
	settingsJSON := ""
	if p.EvidenceSettings != nil {
		if err := p.EvidenceSettings.Validate(); err != nil {
			return err
		}
		effective := p.EvidenceSettings.ForLevel(p.Level)
		var err error
		settingsJSON, err = effective.JSON()
		if err != nil {
			return fmt.Errorf("store.SetCloudEnrichPolicy: %w", err)
		}
	}
	updatedAt := p.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	background := 0
	if p.Background {
		background = 1
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.SetCloudEnrichPolicy: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var since string
	if p.Level == CloudEnrichOff {
		since = ""
	} else {
		var curLevel, curSince sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT level, since FROM cloud_enrich_policy WHERE id = 1`).
			Scan(&curLevel, &curSince)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			since = cloudFormatTime(updatedAt)
		case err != nil:
			return fmt.Errorf("store.SetCloudEnrichPolicy: read prior: %w", err)
		case curLevel.String == string(CloudEnrichOff) || !curSince.Valid || curSince.String == "":
			// Transitioning off -> on (or a pre-117 row with no `since` yet).
			since = cloudFormatTime(updatedAt)
		default:
			// Staying on: carry the existing `since` forward unchanged.
			since = curSince.String
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_enrich_policy (id, level, background, policy_version, source, updated_at, since, generation, evidence_settings_json)
		VALUES (1, ?, ?, ?, ?, ?, ?, 1, ?)
		ON CONFLICT(id) DO UPDATE SET
			level          = excluded.level,
			background     = excluded.background,
			policy_version = excluded.policy_version,
			source         = excluded.source,
			updated_at     = excluded.updated_at,
			since          = excluded.since,
			generation     = cloud_enrich_policy.generation + 1,
            evidence_settings_json = excluded.evidence_settings_json`,
		string(p.Level), background, p.PolicyVersion, p.Source, cloudFormatTime(updatedAt), since, settingsJSON); err != nil {
		return fmt.Errorf("store.SetCloudEnrichPolicy: %w", err)
	}
	retired, err := retireCloudBackgroundReceiptsTx(ctx, tx, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("store.SetCloudEnrichPolicy: retire background receipts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.SetCloudEnrichPolicy: commit: %w", err)
	}
	_, err = s.AwaitCloudDispatchQuiescence(ctx, retired)
	return err
}

// CancelPendingCloudSessionEvidence invalidates every LIVE per-upload
// (CloudGrantPerUpload) consent receipt whose bound session_evidence outbox
// item is still `pending` or `failed_retryable`, and cancels those items. A
// standing receipt (the structural rail) is untouched here — revoking it is
// cloudRevokeStanding's job (cmd/observer). Sent/terminal outbox items are
// never touched: `observer cloud disable` never deletes anything already
// delivered. Returns the number of outbox items cancelled.
func (s *Store) CancelPendingCloudSessionEvidence(ctx context.Context) (int, error) {
	const pfx = "store.CancelPendingCloudSessionEvidence"
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT o.receipt_id
		  FROM cloud_outbox o
		  JOIN cloud_consent_receipts r ON r.id = o.receipt_id
		 WHERE o.kind = ?
		   AND o.state IN (?, ?)
		   AND r.invalidated_at IS NULL
		   AND r.grant_mode = ?`,
		string(CloudOutboxKindSessionEvidence), string(CloudOutboxPending), string(CloudOutboxFailedRetryable),
		string(CloudGrantPerUpload))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", pfx, err)
	}
	var receiptIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("%s: %w", pfx, err)
		}
		receiptIDs = append(receiptIDs, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("%s: %w", pfx, err)
	}
	_ = rows.Close()

	total := 0
	for _, rid := range receiptIDs {
		if err := s.InvalidateCloudConsentReceipt(ctx, rid); err != nil {
			return total, fmt.Errorf("%s: %w", pfx, err)
		}
		n, err := s.CancelCloudOutboxForReceipt(ctx, rid)
		if err != nil {
			return total, fmt.Errorf("%s: %w", pfx, err)
		}
		total += n
	}
	return total, nil
}

// FindCloudOutboxByReceipt returns the newest outbox item bound to a receipt,
// if any. A session-evidence receipt binds exactly one outbox item in
// practice; ok=false means none exists.
func (s *Store) FindCloudOutboxByReceipt(ctx context.Context, receiptID string) (CloudOutboxItem, bool, error) {
	if receiptID == "" {
		return CloudOutboxItem{}, false, errors.New("store.FindCloudOutboxByReceipt: receipt id is required")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, session_id, feature_set_json, evidence_content_digest, upload_digest,
		       receipt_id, state, retry_count, last_error, created_at, updated_at
		  FROM cloud_outbox WHERE receipt_id = ?
		 ORDER BY created_at DESC, id DESC
		 LIMIT 1`, receiptID)
	if err != nil {
		return CloudOutboxItem{}, false, fmt.Errorf("store.FindCloudOutboxByReceipt: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items, err := scanCloudOutboxRows(rows, "store.FindCloudOutboxByReceipt")
	if err != nil {
		return CloudOutboxItem{}, false, err
	}
	if len(items) == 0 {
		return CloudOutboxItem{}, false, nil
	}
	return items[0], true, nil
}

// -- Ledger -------------------------------------------------------------------

// CloudLedgerReceipt is one consent receipt on the "What we sent" ledger.
// Content-free: purposes, versions, timestamps only.
type CloudLedgerReceipt struct {
	EvidenceSettingsJSON string
	ID                   string
	Purpose              string
	GrantMode            string
	Endpoint             string
	CreatedAt            time.Time
	ReviewAt             *time.Time
	InvalidatedAt        *time.Time
	Live                 bool
}

// CloudLedgerItem is one outbox item bound to a ledger receipt.
type CloudLedgerItem struct {
	ID         string
	SessionID  string
	Kind       string
	State      string
	LastError  string
	RetryCount int
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// CloudLedgerResult is the current (non-superseded) enrichment result for a
// ledger entry's session, if any. Content-free: provenance and counts only —
// never the result body.
type CloudLedgerResult struct {
	ID         string
	SessionID  string
	ModelRoute string
	Tokens     int
	CostUSD    float64
	ReceivedAt time.Time
}

// CloudLedgerEntry is one row of the ledger: a receipt, the outbox items
// queued under it, and (for a session-evidence receipt) the current result
// for that session, if any.
type CloudLedgerEntry struct {
	Receipt CloudLedgerReceipt
	Items   []CloudLedgerItem
	Result  *CloudLedgerResult
}

// ListCloudLedger returns the newest `limit` consent receipts (newest first),
// each with its outbox items and — for a session-evidence receipt — the
// current (non-superseded) cloud_results row for that session, if any.
// CONTENT-FREE: never selects result_json, payload_bytes, or titles. The
// second return is the total receipt count (independent of limit).
func (s *Store) ListCloudLedger(ctx context.Context, limit int) ([]CloudLedgerEntry, int, error) {
	const pfx = "store.ListCloudLedger"
	if limit <= 0 {
		limit = 200
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cloud_consent_receipts`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", pfx, err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, purpose, grant_mode, endpoint, created_at, review_at, invalidated_at, evidence_settings_json
		  FROM cloud_consent_receipts
		 ORDER BY created_at DESC, id DESC
		 LIMIT ?`, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", pfx, err)
	}
	var entries []CloudLedgerEntry
	for rows.Next() {
		var (
			id, purpose, grantMode, endpoint, createdAt, settingsJSON string
			reviewAt, invalidatedAt                                   sql.NullString
		)
		if err := rows.Scan(&id, &purpose, &grantMode, &endpoint, &createdAt, &reviewAt, &invalidatedAt, &settingsJSON); err != nil {
			_ = rows.Close()
			return nil, 0, fmt.Errorf("%s: %w", pfx, err)
		}
		mode := grantMode
		if mode == "" {
			mode = string(CloudGrantPerUpload)
		}
		rec := CloudLedgerReceipt{
			EvidenceSettingsJSON: settingsJSON,
			ID:                   id,
			Purpose:              purpose,
			GrantMode:            mode,
			Endpoint:             endpoint,
			CreatedAt:            cloudParseTime(createdAt),
			Live:                 !invalidatedAt.Valid || invalidatedAt.String == "",
		}
		if reviewAt.Valid && reviewAt.String != "" {
			t := cloudParseTime(reviewAt.String)
			rec.ReviewAt = &t
		}
		if invalidatedAt.Valid && invalidatedAt.String != "" {
			t := cloudParseTime(invalidatedAt.String)
			rec.InvalidatedAt = &t
		}
		entries = append(entries, CloudLedgerEntry{Receipt: rec})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, 0, fmt.Errorf("%s: %w", pfx, err)
	}
	_ = rows.Close()

	for i := range entries {
		itemRows, err := s.db.QueryContext(ctx, `
			SELECT id, kind, session_id, feature_set_json, evidence_content_digest, upload_digest,
			       receipt_id, state, retry_count, last_error, created_at, updated_at
			  FROM cloud_outbox WHERE receipt_id = ?
			 ORDER BY created_at ASC, id ASC`, entries[i].Receipt.ID)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", pfx, err)
		}
		outboxItems, err := scanCloudOutboxRows(itemRows, pfx)
		_ = itemRows.Close()
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", pfx, err)
		}
		var sessionIDForResult string
		for _, oi := range outboxItems {
			entries[i].Items = append(entries[i].Items, CloudLedgerItem{
				ID:         oi.ID,
				SessionID:  oi.SessionID,
				Kind:       string(oi.Kind),
				State:      string(oi.State),
				LastError:  oi.LastError,
				RetryCount: oi.RetryCount,
				CreatedAt:  oi.CreatedAt,
				UpdatedAt:  oi.UpdatedAt,
			})
			if oi.Kind == CloudOutboxKindSessionEvidence && oi.SessionID != "" {
				sessionIDForResult = oi.SessionID
			}
		}
		if sessionIDForResult != "" {
			res, _, ok, rerr := s.GetCloudSessionResult(ctx, sessionIDForResult)
			if rerr == nil && ok {
				entries[i].Result = &CloudLedgerResult{
					ID:         res.ID,
					SessionID:  res.SessionID,
					ModelRoute: res.Provenance.ModelRoute,
					Tokens:     res.Provenance.Tokens,
					CostUSD:    res.Provenance.CostUSD,
					ReceivedAt: res.ReceivedAt,
				}
			}
		}
	}
	return entries, total, nil
}
