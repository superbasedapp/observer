package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// export.go is the account data-export store surface (divergence-remediation
// plan §3 "W6d"; closes D11). It assembles the account's own data — exactly the
// objects the W6d matrix marks "in export" — into a cloudcontract.AccountExport,
// serializes it, encrypts it with the Store's evidence Encryptor, and persists
// it as an expiring export_artifacts row (migration 0020). The artifact is
// deleted at expiry (SweepExpiredExports) AND by the account-deletion pass
// (deletion.go purges export_artifacts alongside the enrichment cluster — an
// assembled export is itself account data).
//
// Every read and write runs under WithAccount, so RLS constrains the whole
// assembly and the download to the acting account's own rows: one account's
// export can never reach another's data.

// ExportArtifactTTL is how long an assembled export stays downloadable before
// the sweeper deletes it. Doc B §5.2 caps it at ≤7 days; this is that ceiling.
const ExportArtifactTTL = 7 * 24 * time.Hour

// ErrExportExpired is returned by GetExportArtifact when the artifact exists but
// is past expires_at (the caller should treat it as gone — a fresh export must
// be assembled).
var ErrExportExpired = errors.New("cloudserver/store: export artifact expired")

// ExportArtifactMeta is the content-free descriptor of a stored export (never
// the bytes). It is what the create path returns and what a listing shows.
type ExportArtifactMeta struct {
	ID        string    `json:"export_id"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateExportArtifact assembles the account's export document, encrypts it, and
// stores it as an artifact expiring at now+ExportArtifactTTL. It returns the
// artifact metadata (never the plaintext). The assembly and the insert run in
// ONE tenant transaction, so the artifact is a consistent snapshot. This is the
// DEVICE path (PoP is the strong factor — no browser step-up).
func (s *Store) CreateExportArtifact(ctx context.Context, accountID string, now time.Time) (ExportArtifactMeta, error) {
	return s.runExport(ctx, accountID, now, nil)
}

// CreateExportArtifactWithStepUp is the PORTAL WorkOS path: it consumes a
// one-use export step-up authorization in the SAME transaction as the assembly,
// so a failed assembly never burns the authorization and a consumed
// authorization can never drive a second export (mirrors the deletion path).
func (s *Store) CreateExportArtifactWithStepUp(ctx context.Context, accountID, sessionID, authzID string, now time.Time) (ExportArtifactMeta, error) {
	return s.runExport(ctx, accountID, now, &stepUp{sessionID: sessionID, authzID: authzID})
}

// runExport is the shared assembly driver. When su is set it consumes the
// step-up BEFORE assembling, inside the same tenant transaction.
func (s *Store) runExport(ctx context.Context, accountID string, now time.Time, su *stepUp) (ExportArtifactMeta, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var meta ExportArtifactMeta
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if su != nil {
			if e := consumeStepUpTx(ctx, tx, accountID, su.sessionID, StepUpActionExport, su.authzID, now); e != nil {
				return e // refused step-up: rolls back, no artifact written
			}
		}
		doc, e := assembleAccountExportTx(ctx, tx, accountID, now)
		if e != nil {
			return e
		}
		plaintext, e := doc.Bytes()
		if e != nil {
			return fmt.Errorf("serialize export: %w", e)
		}
		ct, e := s.enc.Seal(plaintext)
		if e != nil {
			return fmt.Errorf("encrypt export: %w", e)
		}
		meta.SizeBytes = int64(len(plaintext))
		meta.CreatedAt = now
		meta.ExpiresAt = now.Add(ExportArtifactTTL)
		return tx.QueryRow(
			ctx,
			`INSERT INTO export_artifacts (account_id, schema_version, ciphertext, size_bytes, created_at, expires_at)
			 VALUES ($1::uuid, $2, $3, $4, $5, $6)
			 RETURNING export_id::text`,
			accountID, cloudcontract.AccountExportSchemaVersion, ct, meta.SizeBytes, now, meta.ExpiresAt,
		).Scan(&meta.ID)
	})
	if err != nil {
		if errors.Is(err, ErrStepUpInvalid) {
			return ExportArtifactMeta{}, ErrStepUpInvalid
		}
		return ExportArtifactMeta{}, fmt.Errorf("cloudserver/store.CreateExportArtifact: %w", err)
	}
	return meta, nil
}

// GetExportArtifact loads and decrypts one of the account's export artifacts and
// stamps downloaded_at. It returns ErrNotFound when the id is unknown (or
// belongs to another account — RLS makes those indistinguishable, which is the
// correct non-disclosure) and ErrExportExpired when the artifact is past its
// TTL (the sweep may not have run yet, so the read enforces expiry too).
func (s *Store) GetExportArtifact(ctx context.Context, accountID, exportID string, now time.Time) ([]byte, ExportArtifactMeta, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var ct []byte
	var meta ExportArtifactMeta
	var expiresAt time.Time
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT ciphertext, size_bytes, created_at, expires_at
			   FROM export_artifacts
			  WHERE account_id = $1::uuid AND export_id = $2::uuid`,
			accountID, exportID).Scan(&ct, &meta.SizeBytes, &meta.CreatedAt, &expiresAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			if isInvalidUUIDErr(e) {
				return ErrNotFound // a malformed id is simply not found, not a server fault
			}
			return e
		}
		if !expiresAt.After(now) {
			return ErrExportExpired
		}
		// Best-effort download stamp inside the same tenant tx.
		if _, e := tx.Exec(ctx,
			`UPDATE export_artifacts SET downloaded_at = $3
			  WHERE account_id = $1::uuid AND export_id = $2::uuid AND downloaded_at IS NULL`,
			accountID, exportID, now); e != nil {
			return fmt.Errorf("stamp download: %w", e)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExportExpired) {
			return nil, ExportArtifactMeta{}, err
		}
		return nil, ExportArtifactMeta{}, fmt.Errorf("cloudserver/store.GetExportArtifact: %w", err)
	}
	pt, err := s.enc.Open(ct)
	if err != nil {
		return nil, ExportArtifactMeta{}, fmt.Errorf("cloudserver/store.GetExportArtifact: decrypt: %w", err)
	}
	meta.ID = exportID
	meta.ExpiresAt = expiresAt
	return pt, meta, nil
}

// ListExportArtifacts returns the account's live (unexpired) export artifacts,
// newest-first — the portal shows these so a developer can re-download a recent
// export instead of assembling another.
func (s *Store) ListExportArtifacts(ctx context.Context, accountID string, now time.Time) ([]ExportArtifactMeta, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var out []ExportArtifactMeta
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT export_id::text, size_bytes, created_at, expires_at
			   FROM export_artifacts
			  WHERE account_id = $1::uuid AND expires_at > $2
			  ORDER BY created_at DESC`,
			accountID, now)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var m ExportArtifactMeta
			if e := rows.Scan(&m.ID, &m.SizeBytes, &m.CreatedAt, &m.ExpiresAt); e != nil {
				return e
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListExportArtifacts: %w", err)
	}
	return out, nil
}

// SweepExpiredExports deletes every export artifact past its expires_at, ACROSS
// all tenants, through the SECURITY DEFINER sweep primitive (the only way to
// reach every tenant's rows). It never consults account state — an artifact
// expires purely by its own clock. Returns how many were deleted.
func (s *Store) SweepExpiredExports(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var deleted int
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sbci_sweep_expired_exports($1)`, now).Scan(&deleted)
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.SweepExpiredExports: %w", err)
	}
	return deleted, nil
}

// --- assembly --------------------------------------------------------------

// assembleAccountExportTx reads every "in export" object for the account inside
// the caller's tenant transaction and composes the AccountExport. It uses a
// small fixed number of bulk queries (never one-per-session), so its cost is
// independent of how many sessions the account has.
func assembleAccountExportTx(ctx context.Context, tx pgx.Tx, accountID string, now time.Time) (cloudcontract.AccountExport, error) {
	doc := cloudcontract.AccountExport{
		SchemaVersion: cloudcontract.AccountExportSchemaVersion,
		GeneratedAt:   now,
		AccountID:     accountID,
		Devices:       []cloudcontract.ExportDevice{},
		Consents:      cloudcontract.ExportConsents{Receipts: []cloudcontract.ExportConsentReceipt{}, Events: []cloudcontract.ExportConsentEvent{}},
		Usage: cloudcontract.ExportUsage{
			Entitlements: []cloudcontract.ExportEntitlement{},
			Cycles:       []cloudcontract.ExportUsageCycle{},
			Ledger:       []cloudcontract.ExportUsageLedgerEntry{},
		},
		Projects:   []cloudcontract.ExportProject{},
		Sessions:   []cloudcontract.ExportSession{},
		Jobs:       []cloudcontract.ExportJobSummary{},
		Structural: []cloudcontract.ExportStructuralDay{},
	}

	if e := exportDevicesTx(ctx, tx, accountID, &doc); e != nil {
		return cloudcontract.AccountExport{}, e
	}
	if e := exportConsentsTx(ctx, tx, accountID, &doc); e != nil {
		return cloudcontract.AccountExport{}, e
	}
	if e := exportUsageTx(ctx, tx, accountID, &doc); e != nil {
		return cloudcontract.AccountExport{}, e
	}
	if e := exportProjectsTx(ctx, tx, accountID, &doc); e != nil {
		return cloudcontract.AccountExport{}, e
	}
	if e := exportSessionsTx(ctx, tx, accountID, &doc); e != nil {
		return cloudcontract.AccountExport{}, e
	}
	if e := exportJobsTx(ctx, tx, accountID, &doc); e != nil {
		return cloudcontract.AccountExport{}, e
	}
	if e := exportStructuralTx(ctx, tx, accountID, &doc); e != nil {
		return cloudcontract.AccountExport{}, e
	}
	return doc, nil
}

func exportDevicesTx(ctx context.Context, tx pgx.Tx, accountID string, doc *cloudcontract.AccountExport) error {
	rows, err := tx.Query(ctx,
		`SELECT coalesce(label,''), created_at, revoked_at
		   FROM device_registrations WHERE account_id = $1::uuid ORDER BY created_at`,
		accountID)
	if err != nil {
		return fmt.Errorf("export devices: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d cloudcontract.ExportDevice
		var revoked *time.Time
		if err := rows.Scan(&d.Label, &d.CreatedAt, &revoked); err != nil {
			return fmt.Errorf("export devices scan: %w", err)
		}
		d.RevokedAt = revoked
		doc.Devices = append(doc.Devices, d)
	}
	return rows.Err()
}

func exportConsentsTx(ctx context.Context, tx pgx.Tx, accountID string, doc *cloudcontract.AccountExport) error {
	rrows, err := tx.Query(ctx,
		`SELECT purposes, field_classes, evidence_schema, scrubber_version, retention_policy,
		        endpoint, subprocessors, upload_digest, coalesce(evidence_content_digest,''),
		        generation, created_at, expires_at
		   FROM consent_receipts WHERE account_id = $1::uuid ORDER BY created_at`,
		accountID)
	if err != nil {
		return fmt.Errorf("export consent receipts: %w", err)
	}
	defer rrows.Close()
	for rrows.Next() {
		var r cloudcontract.ExportConsentReceipt
		var expiresAt *time.Time
		if err := rrows.Scan(&r.Purposes, &r.FieldClasses, &r.EvidenceSchema, &r.ScrubberVersion,
			&r.RetentionPolicy, &r.Endpoint, &r.Subprocessors, &r.UploadDigest, &r.EvidenceContentDigest,
			&r.Generation, &r.CreatedAt, &expiresAt); err != nil {
			return fmt.Errorf("export consent receipts scan: %w", err)
		}
		r.ExpiresAt = expiresAt
		nilToEmpty(&r.Purposes)
		nilToEmpty(&r.FieldClasses)
		nilToEmpty(&r.Subprocessors)
		doc.Consents.Receipts = append(doc.Consents.Receipts, r)
	}
	if err := rrows.Err(); err != nil {
		return err
	}
	erows, err := tx.Query(ctx,
		`SELECT event_type, purposes, generation, created_at
		   FROM consent_events WHERE account_id = $1::uuid ORDER BY created_at`,
		accountID)
	if err != nil {
		return fmt.Errorf("export consent events: %w", err)
	}
	defer erows.Close()
	for erows.Next() {
		var ev cloudcontract.ExportConsentEvent
		if err := erows.Scan(&ev.EventType, &ev.Purposes, &ev.Generation, &ev.CreatedAt); err != nil {
			return fmt.Errorf("export consent events scan: %w", err)
		}
		nilToEmpty(&ev.Purposes)
		doc.Consents.Events = append(doc.Consents.Events, ev)
	}
	return erows.Err()
}

func exportUsageTx(ctx context.Context, tx pgx.Tx, accountID string, doc *cloudcontract.AccountExport) error {
	ent, err := tx.Query(ctx,
		`SELECT feature, source, daily_cap, monthly_cap, concurrency_cap
		   FROM entitlements WHERE account_id = $1::uuid ORDER BY feature`,
		accountID)
	if err != nil {
		return fmt.Errorf("export entitlements: %w", err)
	}
	defer ent.Close()
	for ent.Next() {
		var e cloudcontract.ExportEntitlement
		if err := ent.Scan(&e.Feature, &e.Source, &e.DailyCap, &e.MonthlyCap, &e.ConcurrencyCap); err != nil {
			return fmt.Errorf("export entitlements scan: %w", err)
		}
		doc.Usage.Entitlements = append(doc.Usage.Entitlements, e)
	}
	if err := ent.Err(); err != nil {
		return err
	}
	cyc, err := tx.Query(ctx,
		`SELECT feature, cycle_kind, window_key, cap, used
		   FROM usage_cycles WHERE account_id = $1::uuid ORDER BY feature, window_key`,
		accountID)
	if err != nil {
		return fmt.Errorf("export usage cycles: %w", err)
	}
	defer cyc.Close()
	for cyc.Next() {
		var c cloudcontract.ExportUsageCycle
		if err := cyc.Scan(&c.Feature, &c.CycleKind, &c.WindowKey, &c.Cap, &c.Used); err != nil {
			return fmt.Errorf("export usage cycles scan: %w", err)
		}
		doc.Usage.Cycles = append(doc.Usage.Cycles, c)
	}
	if err := cyc.Err(); err != nil {
		return err
	}
	led, err := tx.Query(ctx,
		`SELECT event, user_units, internal_units,
		        coalesce(tokens_in, 0), coalesce(tokens_out, 0), created_at
		   FROM analysis_usage_ledger WHERE account_id = $1::uuid ORDER BY created_at`,
		accountID)
	if err != nil {
		return fmt.Errorf("export usage ledger: %w", err)
	}
	defer led.Close()
	for led.Next() {
		var l cloudcontract.ExportUsageLedgerEntry
		if err := led.Scan(&l.Event, &l.UserUnits, &l.InternalUnits, &l.TokensIn, &l.TokensOut, &l.CreatedAt); err != nil {
			return fmt.Errorf("export usage ledger scan: %w", err)
		}
		doc.Usage.Ledger = append(doc.Usage.Ledger, l)
	}
	return led.Err()
}

func exportProjectsTx(ctx context.Context, tx pgx.Tx, accountID string, doc *cloudcontract.AccountExport) error {
	rows, err := tx.Query(ctx,
		`SELECT cloud_project_id, created_at FROM cloud_projects WHERE account_id = $1::uuid ORDER BY created_at`,
		accountID)
	if err != nil {
		return fmt.Errorf("export projects: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p cloudcontract.ExportProject
		if err := rows.Scan(&p.CloudProjectID, &p.CreatedAt); err != nil {
			return fmt.Errorf("export projects scan: %w", err)
		}
		doc.Projects = append(doc.Projects, p)
	}
	return rows.Err()
}

// exportSessionsTx reads every session, then all results and all revisions in
// two bulk queries, and groups them in Go — no per-session round-trip.
func exportSessionsTx(ctx context.Context, tx pgx.Tx, accountID string, doc *cloudcontract.AccountExport) error {
	// 1. Sessions, keyed by pk so results can attach to them.
	type sess struct {
		pk  string
		out *cloudcontract.ExportSession
	}
	byPK := map[string]*sess{}
	srows, err := tx.Query(ctx,
		`SELECT id::text, cloud_session_id, tool, model_family, created_at
		   FROM cloud_sessions WHERE account_id = $1::uuid ORDER BY created_at`,
		accountID)
	if err != nil {
		return fmt.Errorf("export sessions: %w", err)
	}
	order := []string{}
	func() {
		defer srows.Close()
		for srows.Next() {
			var pk string
			var es cloudcontract.ExportSession
			es.Results = []cloudcontract.ExportResult{}
			if err = srows.Scan(&pk, &es.CloudSessionID, &es.Tool, &es.ModelFamily, &es.CreatedAt); err != nil {
				return
			}
			doc.Sessions = append(doc.Sessions, es)
			order = append(order, pk)
		}
		err = srows.Err()
	}()
	if err != nil {
		return fmt.Errorf("export sessions scan: %w", err)
	}
	for i := range doc.Sessions {
		byPK[order[i]] = &sess{pk: order[i], out: &doc.Sessions[i]}
	}

	// 2. All revisions, grouped by result_id.
	revByResult := map[string][]cloudcontract.ExportRevision{}
	rvrows, err := tx.Query(ctx,
		`SELECT result_id::text, revision_seq, editor, source, correction, created_at
		   FROM result_revisions WHERE account_id = $1::uuid ORDER BY result_id, revision_seq DESC`,
		accountID)
	if err != nil {
		return fmt.Errorf("export revisions: %w", err)
	}
	func() {
		defer rvrows.Close()
		for rvrows.Next() {
			var resultID string
			var rv cloudcontract.ExportRevision
			var raw []byte
			if err = rvrows.Scan(&resultID, &rv.RevisionSeq, &rv.Editor, &rv.Source, &raw, &rv.CreatedAt); err != nil {
				return
			}
			rv.Correction = json.RawMessage(raw)
			revByResult[resultID] = append(revByResult[resultID], rv)
		}
		err = rvrows.Err()
	}()
	if err != nil {
		return fmt.Errorf("export revisions scan: %w", err)
	}

	// 3. All results, attached to their session, newest-first, with revisions.
	rrows, err := tx.Query(ctx,
		`SELECT j.session_pk::text, r.id::text, r.created_at, r.ai_source, r.superseded,
		        (r.result = $2::jsonb) AS tombstoned, r.result
		   FROM analysis_results r
		   JOIN analysis_jobs j ON j.account_id = r.account_id AND j.id = r.job_id
		  WHERE r.account_id = $1::uuid
		  ORDER BY j.session_pk, r.superseded ASC, r.created_at DESC`,
		accountID, tombstoneResult)
	if err != nil {
		return fmt.Errorf("export results: %w", err)
	}
	func() {
		defer rrows.Close()
		for rrows.Next() {
			var sessionPK string
			var er cloudcontract.ExportResult
			var tombstoned bool
			var raw []byte
			if err = rrows.Scan(&sessionPK, &er.ResultID, &er.CreatedAt, &er.AISource, &er.Superseded, &tombstoned, &raw); err != nil {
				return
			}
			if !tombstoned {
				er.Result = json.RawMessage(raw)
			}
			er.Revisions = revByResult[er.ResultID]
			if er.Revisions == nil {
				er.Revisions = []cloudcontract.ExportRevision{}
			}
			if s := byPK[sessionPK]; s != nil {
				s.out.Results = append(s.out.Results, er)
			}
		}
		err = rrows.Err()
	}()
	if err != nil {
		return fmt.Errorf("export results scan: %w", err)
	}
	return nil
}

func exportJobsTx(ctx context.Context, tx pgx.Tx, accountID string, doc *cloudcontract.AccountExport) error {
	rows, err := tx.Query(ctx,
		`SELECT feature, state, created_at FROM analysis_jobs WHERE account_id = $1::uuid ORDER BY created_at`,
		accountID)
	if err != nil {
		return fmt.Errorf("export jobs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var j cloudcontract.ExportJobSummary
		if err := rows.Scan(&j.Feature, &j.State, &j.CreatedAt); err != nil {
			return fmt.Errorf("export jobs scan: %w", err)
		}
		doc.Jobs = append(doc.Jobs, j)
	}
	return rows.Err()
}

func exportStructuralTx(ctx context.Context, tx pgx.Tx, accountID string, doc *cloudcontract.AccountExport) error {
	rows, err := tx.Query(ctx,
		`SELECT period, device_count, session_count, action_count, tokens_in, tokens_out,
		        cost_usd, verification_coverage_band, outcome_evidence_band, computed_at
		   FROM structural_account_days WHERE account_id = $1::uuid ORDER BY period`,
		accountID)
	if err != nil {
		return fmt.Errorf("export structural: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d cloudcontract.ExportStructuralDay
		if err := rows.Scan(&d.Period, &d.DeviceCount, &d.SessionCount, &d.ActionCount,
			&d.TokensIn, &d.TokensOut, &d.CostUSD, &d.VerificationCoverageBand,
			&d.OutcomeEvidenceBand, &d.ComputedAt); err != nil {
			return fmt.Errorf("export structural scan: %w", err)
		}
		doc.Structural = append(doc.Structural, d)
	}
	return rows.Err()
}

// nilToEmpty replaces a nil slice with an empty one so the exported JSON carries
// [] not null for a text[] column that was empty/NULL.
func nilToEmpty(s *[]string) {
	if *s == nil {
		*s = []string{}
	}
}
