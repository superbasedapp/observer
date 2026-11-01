package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// intelconsent.go is the ONE store seam over the three node-local tables of
// the Cloud Intelligence parity consent model (agent migration 153; design
// docs/plans/cloud-intelligence-parity-design-2026-10-03.md section 3.7):
// org_intel_requirement (the verified signed requirement document),
// org_intel_consent (append-only consent events) and org_intel_receipts (the
// local org-plane audit). None of the three ever enters orgpush.go (their
// names are in the privacy sentinel's forbidden set).
//
// INV-13: no org document can create a consent row. The only writer of an
// 'accept' row is RecordOrgIntelConsent, which the interactive accept paths
// call after showing the developer the disclosure; the requirement fetch path
// only ever writes org_intel_requirement.

// OrgIntelRequirementRow is the cached, VERIFIED requirement document.
type OrgIntelRequirementRow struct {
	OrgID        string
	Version      int64
	Body         string
	BodyHash     string
	Signature    string
	ServerPubkey string
	ReceivedAt   time.Time
}

// Decoded returns the document's body. A body that does not decode (never
// expected: it verified before it was stored) yields ok=false.
func (r OrgIntelRequirementRow) Decoded() (orgcontract.IntelRequirementBody, bool) {
	b, err := orgcontract.DecodeIntelRequirementBody(r.Body)
	return b, err == nil
}

// UpsertOrgIntelRequirement replaces the single cached document. Callers MUST
// have verified it (orgcontract.VerifyIntelRequirement) first.
func (s *Store) UpsertOrgIntelRequirement(ctx context.Context, r OrgIntelRequirementRow) error {
	if r.OrgID == "" {
		return errors.New("store.UpsertOrgIntelRequirement: org id is required")
	}
	if r.ReceivedAt.IsZero() {
		r.ReceivedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO org_intel_requirement (id, org_id, version, body, body_hash, signature, server_pubkey, received_at)
VALUES (1, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  org_id = excluded.org_id, version = excluded.version, body = excluded.body,
  body_hash = excluded.body_hash, signature = excluded.signature,
  server_pubkey = excluded.server_pubkey, received_at = excluded.received_at`,
		r.OrgID, r.Version, r.Body, r.BodyHash, r.Signature, r.ServerPubkey, cloudFormatTime(r.ReceivedAt))
	if err != nil {
		return fmt.Errorf("store.UpsertOrgIntelRequirement: %w", err)
	}
	return nil
}

// GetOrgIntelRequirement returns the cached document (ok=false when none).
func (s *Store) GetOrgIntelRequirement(ctx context.Context) (OrgIntelRequirementRow, bool, error) {
	var (
		r        OrgIntelRequirementRow
		received string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT org_id, version, body, body_hash, signature, server_pubkey, received_at
  FROM org_intel_requirement WHERE id = 1`).
		Scan(&r.OrgID, &r.Version, &r.Body, &r.BodyHash, &r.Signature, &r.ServerPubkey, &received)
	if errors.Is(err, sql.ErrNoRows) {
		return OrgIntelRequirementRow{}, false, nil
	}
	if err != nil {
		return OrgIntelRequirementRow{}, false, fmt.Errorf("store.GetOrgIntelRequirement: %w", err)
	}
	if t, perr := time.Parse(time.RFC3339Nano, received); perr == nil {
		r.ReceivedAt = t
	}
	return r, true, nil
}

// Org-plane consent event kinds (the CHECK vocabulary of org_intel_consent).
const (
	OrgIntelConsentAccept   = "accept"
	OrgIntelConsentWithdraw = "withdraw"
	OrgIntelConsentLeave    = "leave"
)

// OrgIntelConsentEvent is one consent event.
type OrgIntelConsentEvent struct {
	ID                 int64     `json:"id"`
	OrgID              string    `json:"org_id"`
	Event              string    `json:"event"`
	RequirementVersion int64     `json:"requirement_version"`
	EvidenceLevel      string    `json:"evidence_level"`
	Purposes           []string  `json:"purposes"`
	DisclosureDigest   string    `json:"disclosure_digest"`
	ConsentMode        string    `json:"consent_mode"`
	Actor              string    `json:"actor"`
	CreatedAt          time.Time `json:"created_at"`
}

// RecordOrgIntelConsent appends one consent event. An 'accept' must carry an
// evidence level, at least one purpose and the disclosure digest of what was
// shown; the interactive accept paths are its only callers (INV-13).
func (s *Store) RecordOrgIntelConsent(ctx context.Context, ev OrgIntelConsentEvent) (OrgIntelConsentEvent, error) {
	if ev.OrgID == "" {
		return OrgIntelConsentEvent{}, errors.New("store.RecordOrgIntelConsent: org id is required")
	}
	switch ev.Event {
	case OrgIntelConsentAccept:
		if ev.EvidenceLevel == "" || len(ev.Purposes) == 0 || ev.DisclosureDigest == "" {
			return OrgIntelConsentEvent{}, errors.New("store.RecordOrgIntelConsent: an accept must record the level, the purposes and the disclosure digest it covers")
		}
	case OrgIntelConsentWithdraw, OrgIntelConsentLeave:
	default:
		return OrgIntelConsentEvent{}, fmt.Errorf("store.RecordOrgIntelConsent: unknown event %q", ev.Event)
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	purposes := ev.Purposes
	if purposes == nil {
		purposes = []string{}
	}
	raw, err := json.Marshal(purposes)
	if err != nil {
		return OrgIntelConsentEvent{}, fmt.Errorf("store.RecordOrgIntelConsent: %w", err)
	}
	// A withdraw or leave also cancels every submission still queued for the
	// org, in the SAME transaction (review C156-20): evidence built under the
	// consent that just ended must never leave, even if the withdrawal report
	// to the server fails.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OrgIntelConsentEvent{}, fmt.Errorf("store.RecordOrgIntelConsent: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
INSERT INTO org_intel_consent
  (org_id, event, requirement_version, evidence_level, purposes, disclosure_digest, consent_mode, actor, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.OrgID, ev.Event, ev.RequirementVersion, ev.EvidenceLevel, string(raw),
		ev.DisclosureDigest, ev.ConsentMode, ev.Actor, cloudFormatTime(ev.CreatedAt))
	if err != nil {
		return OrgIntelConsentEvent{}, fmt.Errorf("store.RecordOrgIntelConsent: %w", err)
	}
	ev.ID, _ = res.LastInsertId()
	if ev.Event == OrgIntelConsentWithdraw || ev.Event == OrgIntelConsentLeave {
		if _, err := cancelPendingOrgIntel(ctx, tx, ev.OrgID, OrgIntelOutboxReasonConsentWithdrawn, ev.CreatedAt); err != nil {
			return OrgIntelConsentEvent{}, fmt.Errorf("store.RecordOrgIntelConsent: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return OrgIntelConsentEvent{}, fmt.Errorf("store.RecordOrgIntelConsent: commit: %w", err)
	}
	return ev, nil
}

// OrgIntelConsentHistory returns an org's consent events, newest first (limit
// <= 0 means all).
func (s *Store) OrgIntelConsentHistory(ctx context.Context, orgID string, limit int) ([]OrgIntelConsentEvent, error) {
	q := `SELECT id, org_id, event, requirement_version, evidence_level, purposes,
	             disclosure_digest, consent_mode, actor, created_at
	        FROM org_intel_consent WHERE org_id = ? ORDER BY id DESC`
	args := []any{orgID}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.OrgIntelConsentHistory: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []OrgIntelConsentEvent
	for rows.Next() {
		var (
			ev       OrgIntelConsentEvent
			purposes string
			created  string
		)
		if err := rows.Scan(&ev.ID, &ev.OrgID, &ev.Event, &ev.RequirementVersion, &ev.EvidenceLevel,
			&purposes, &ev.DisclosureDigest, &ev.ConsentMode, &ev.Actor, &created); err != nil {
			return nil, fmt.Errorf("store.OrgIntelConsentHistory: scan: %w", err)
		}
		_ = json.Unmarshal([]byte(purposes), &ev.Purposes)
		if t, perr := time.Parse(time.RFC3339Nano, created); perr == nil {
			ev.CreatedAt = t
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ActiveOrgIntelConsent returns the org's CURRENT accepted consent: its latest
// event when that event is an accept (ok=false when the latest is a withdraw /
// leave, or there is none).
func (s *Store) ActiveOrgIntelConsent(ctx context.Context, orgID string) (OrgIntelConsentEvent, bool, error) {
	if orgID == "" {
		return OrgIntelConsentEvent{}, false, nil
	}
	h, err := s.OrgIntelConsentHistory(ctx, orgID, 1)
	if err != nil {
		return OrgIntelConsentEvent{}, false, err
	}
	if len(h) == 0 || h[0].Event != OrgIntelConsentAccept {
		return OrgIntelConsentEvent{}, false, nil
	}
	return h[0], true, nil
}

// Local org-plane receipt kinds (org_intel_receipts.kind).
const (
	// OrgIntelReceiptNoticeShown records that a managed developer was shown
	// the org-plane notice (design section 3.3: a notice, not a consent).
	OrgIntelReceiptNoticeShown = "managed_notice_shown"
	// OrgIntelReceiptSweepUnconsented records a T-155d sweep: cached results
	// pulled on an individual-tenancy enrolment without a covering consent
	// (before the INTEL-7 fix) were removed.
	OrgIntelReceiptSweepUnconsented = "cache_swept_unconsented"
	// OrgIntelReceiptClearedOnLeave records the result cache cleared when the
	// machine left the org.
	OrgIntelReceiptClearedOnLeave = "cache_cleared_on_leave"
	// OrgIntelReceiptReportRefused records a consent report the org server
	// refused (shown on the status page; the local consent is unchanged).
	OrgIntelReceiptReportRefused = "consent_report_refused"
)

// OrgIntelReceipt is one local audit row.
type OrgIntelReceipt struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	OrgID     string    `json:"org_id"`
	Count     int       `json:"count"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

// AppendOrgIntelReceipt writes one local audit row.
func (s *Store) AppendOrgIntelReceipt(ctx context.Context, r OrgIntelReceipt) error {
	return appendOrgIntelReceipt(ctx, s.db, r)
}

// appendOrgIntelReceipt writes one receipt through a *sql.DB or *sql.Tx
// (store.go's execer).
func appendOrgIntelReceipt(ctx context.Context, q execer, r OrgIntelReceipt) error {
	if r.Kind == "" {
		return errors.New("store.AppendOrgIntelReceipt: kind is required")
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	if _, err := q.ExecContext(ctx, `
INSERT INTO org_intel_receipts (kind, org_id, count, detail, created_at) VALUES (?, ?, ?, ?, ?)`,
		r.Kind, r.OrgID, r.Count, r.Detail, cloudFormatTime(r.CreatedAt)); err != nil {
		return fmt.Errorf("store.AppendOrgIntelReceipt: %w", err)
	}
	return nil
}

// OrgIntelReceipts returns the newest local receipts first (limit <= 0 = 50).
func (s *Store) OrgIntelReceipts(ctx context.Context, limit int) ([]OrgIntelReceipt, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, kind, org_id, count, detail, created_at FROM org_intel_receipts ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.OrgIntelReceipts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []OrgIntelReceipt
	for rows.Next() {
		var (
			r       OrgIntelReceipt
			created string
		)
		if err := rows.Scan(&r.ID, &r.Kind, &r.OrgID, &r.Count, &r.Detail, &created); err != nil {
			return nil, fmt.Errorf("store.OrgIntelReceipts: scan: %w", err)
		}
		if t, perr := time.Parse(time.RFC3339Nano, created); perr == nil {
			r.CreatedAt = t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SweepUnconsentedOrgIntelCache is the T-155d sweep. INDIVIDUAL-tenancy nodes
// may still hold org_intel_cache rows pulled before the INTEL-7 fix, when the
// org enriched them without an opt-in, and the server cannot clear them. On an
// individual-tenancy enrolment this removes every cached result the developer
// never consented to: all of them when there is no active consent, and those
// pulled before the active consent's acceptance otherwise. A MANAGED enrolment
// keeps its cache (the org is the controller there); a node its org switched
// to enterprise is managed too (P-205), which this store cannot verify, so
// its callers (orgclient's consent cycle, the withdraw action) skip the sweep
// for one. A sweep that removed
// anything writes one org_intel_receipts row (local audit) in the same
// transaction. Not enrolled is a no-op: DeleteEnrolment already cleared the
// cache. Returns how many rows were removed.
func (s *Store) SweepUnconsentedOrgIntelCache(ctx context.Context, now time.Time) (int, error) {
	enr, err := s.LoadEnrolment(ctx)
	if err != nil {
		return 0, fmt.Errorf("store.SweepUnconsentedOrgIntelCache: %w", err)
	}
	if enr == nil || enr.IsManaged() {
		return 0, nil
	}
	active, ok, err := s.ActiveOrgIntelConsent(ctx, enr.OrgID)
	if err != nil {
		return 0, fmt.Errorf("store.SweepUnconsentedOrgIntelCache: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.SweepUnconsentedOrgIntelCache: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var res sql.Result
	detail := "no_consent"
	if ok {
		detail = "before_consent"
		// julianday, not a string compare: RFC3339Nano trims trailing zeros, so
		// two instants in the same second do not sort lexicographically.
		res, err = tx.ExecContext(ctx, `DELETE FROM org_intel_cache WHERE julianday(fetched_at) < julianday(?)`, cloudFormatTime(active.CreatedAt))
	} else {
		res, err = tx.ExecContext(ctx, `DELETE FROM org_intel_cache`)
	}
	if err != nil {
		return 0, fmt.Errorf("store.SweepUnconsentedOrgIntelCache: delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		if err := appendOrgIntelReceipt(ctx, tx, OrgIntelReceipt{
			Kind: OrgIntelReceiptSweepUnconsented, OrgID: enr.OrgID, Count: int(n),
			Detail: "individual_tenancy:" + detail, CreatedAt: now,
		}); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.SweepUnconsentedOrgIntelCache: commit: %w", err)
	}
	return int(n), nil
}

// OrgIntelCacheCount reports how many sessions this machine holds org-served
// results for (Settings shows it as "Results on this machine"). It counts
// distinct sessions (ruling Q4): a re-enriched session, or one enriched under
// a second purpose, keeps a cached row per job, and those history rows mirror
// the org's spend ledger, never extra results. The leave receipt still counts
// rows (countOrgIntelCache), because that is what it deletes.
func (s *Store) OrgIntelCacheCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT session_id) FROM org_intel_cache`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store.OrgIntelCacheCount: %w", err)
	}
	return n, nil
}

// countOrgIntelCache counts the cached result rows (for the leave receipt).
func countOrgIntelCache(ctx context.Context, q querier) (int, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_intel_cache`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// leaveOrgIntel is DeleteEnrolment's org-plane cleanup: a 'leave' consent event
// when the departed org held an active consent, the requirement document
// dropped, and a local receipt when cached results were cleared.
func (s *Store) leaveOrgIntel(ctx context.Context, leaving *Enrolment, clearedCache int) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM org_intel_requirement`); err != nil {
		return fmt.Errorf("clear intel requirement: %w", err)
	}
	// The org-plane submission outbox (agent migration 154): queued evidence
	// for an org this machine no longer belongs to must never be sent, and the
	// ledger of what was sent goes with the enrolment (Q4).
	if _, err := s.db.ExecContext(ctx, `DELETE FROM org_intel_outbox`); err != nil {
		return fmt.Errorf("clear intel outbox: %w", err)
	}
	orgID := ""
	if leaving != nil {
		orgID = leaving.OrgID
	}
	if orgID != "" {
		if _, ok, err := s.ActiveOrgIntelConsent(ctx, orgID); err != nil {
			return err
		} else if ok {
			if _, err := s.RecordOrgIntelConsent(ctx, OrgIntelConsentEvent{
				OrgID: orgID, Event: OrgIntelConsentLeave, ConsentMode: "leave",
			}); err != nil {
				return err
			}
		}
	}
	if clearedCache > 0 {
		if err := s.AppendOrgIntelReceipt(ctx, OrgIntelReceipt{
			Kind: OrgIntelReceiptClearedOnLeave, OrgID: orgID, Count: clearedCache, Detail: "left_organization",
		}); err != nil {
			return err
		}
	}
	return nil
}
