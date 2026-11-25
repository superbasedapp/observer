package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/personalmig"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// personalmig.go is the store seam of `observer-cloud migrate-personal`, the
// cloud half of stage E3 (managed-SaaS plan 06 9.4; plan 07 M9.3;
// docs/plans/managed-saas/individuals/inventory.md D-IND-4, D-IND-5,
// D-IND-6; docs/security.md IND-5). The decisions are the pure
// internal/cloudserver/personalmig package's; this file reads the facts it
// decides on and writes what it decided:
//
//   - the account walk (accounts is a system table, read in account_id order
//     so a rerun resumes anywhere), and one account's footprint and results,
//     read under the account's OWN context (WithAccount), so RLS still bounds
//     every tenant read to that account;
//   - the ledger (personal_migrations, cloud 0134, class S): every write
//     goes through writePersonalMigrationTx, which refuses a move the stage
//     machine does not allow and appends one security_audit_events row per
//     stage change in the same transaction;
//   - the personal org, found or provisioned through ProvisionOrg;
//   - the re-key (D-IND-6), in ONE transaction per account: the account's
//     live plus_beta subscription (org_id NULL) is bound to the personal org
//     and rewritten to personal_pro (personalmig.OrgPlanVersion), the account's Paddle-sourced plan
//     rows are closed, and the ledger moves to rekeyed. Later webhooks find
//     the bound row (boundSubscriptionOrgTx) and take the org branch, which
//     changes no account plan: one subscription, one row, one entitlement.
//     No Paddle API is called (the subscription and customer ids stay).
//
// No content is written anywhere: counts, ids and digests only.

// ErrPersonalMigrationStage is returned when a ledger write asks for a move
// the stage machine refuses (personalmig.CanMove).
var ErrPersonalMigrationStage = errors.New("cloudserver/store: personal migration stage move refused")

// personalMigrationReasonMax and personalMigrationErrorMax are the 0134
// bounds of skip_reason and last_error.
const (
	personalMigrationReasonMax = 500
	personalMigrationErrorMax  = 1000
)

// PersonalMigrationRow is one personal_migrations row.
type PersonalMigrationRow struct {
	AccountID             string
	OrgID                 string
	Stage                 personalmig.Stage
	SkipReason            string
	ResultsTotal          int
	ResultsExported       int
	ResultsSkipped        int
	RekeyedSubscriptionID string
	BundleSHA256          string
	// The tenant receipt's counts; nil until verify read a receipt.
	ReceiptInserted       *int
	ReceiptAlreadyPresent *int
	ReceiptPresent        *int
	LastError             string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// PersonalMigrationAccount is one account the migration walk visits.
type PersonalMigrationAccount struct {
	AccountID string
	Status    string
}

// ListPersonalMigrationAccounts returns up to limit accounts whose id is
// after after ("" from the start), in account_id order: the resumable walk
// the migration pages through.
func (s *Store) ListPersonalMigrationAccounts(ctx context.Context, after string, limit int) ([]PersonalMigrationAccount, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var cursor *string
	if after != "" {
		if !validOrgID(after) {
			return nil, fmt.Errorf("cloudserver/store.ListPersonalMigrationAccounts: cursor %q is not a uuid", after)
		}
		cursor = &after
	}
	var out []PersonalMigrationAccount
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT account_id::text, status FROM accounts
			  WHERE ($1::uuid IS NULL OR account_id > $1::uuid)
			  ORDER BY account_id LIMIT $2`, cursor, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a PersonalMigrationAccount
			if err := rows.Scan(&a.AccountID, &a.Status); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListPersonalMigrationAccounts: %w", err)
	}
	return out, nil
}

// PersonalMigrationFootprint reads what personalmig.Decide needs about one
// account, under the account's own context. ErrNotFound when the account
// does not exist.
func (s *Store) PersonalMigrationFootprint(ctx context.Context, accountID string, now time.Time) (personalmig.Footprint, error) {
	if !validOrgID(accountID) {
		return personalmig.Footprint{}, ErrNotFound
	}
	f := personalmig.Footprint{AccountID: accountID}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT status FROM accounts WHERE account_id=$1::uuid`, accountID).Scan(&f.AccountStatus)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return fmt.Errorf("read account: %w", e)
		}
		if e := tx.QueryRow(ctx,
			`SELECT (SELECT count(*) FROM analysis_results WHERE account_id=$1::uuid),
			        (SELECT count(*) FROM device_registrations WHERE account_id=$1::uuid)`,
			accountID).Scan(&f.Results, &f.Devices); e != nil {
			return fmt.Errorf("count footprint: %w", e)
		}
		org, ok, e := migPersonalOrgTx(ctx, tx, accountID)
		if e != nil {
			return e
		}
		if ok {
			f.Org = &org
		}
		subs, e := accountSubscriptionsTx(ctx, tx, accountID)
		if e != nil {
			return e
		}
		for _, sub := range subs {
			switch {
			case sub.OrgID == "":
				f.AccountSubscriptions = append(f.AccountSubscriptions, sub)
			case f.Org != nil && sub.OrgID == f.Org.OrgID:
				f.RekeyedSubscriptions = append(f.RekeyedSubscriptions, sub)
			}
		}
		e = tx.QueryRow(ctx,
			`SELECT p.name, ap.source
			   FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
			  WHERE ap.account_id = $1::uuid AND ap.effective_from <= $2
			    AND (ap.effective_until IS NULL OR ap.effective_until > $2)
			  ORDER BY ap.effective_from DESC LIMIT 1`, accountID, now).Scan(&f.PlanName, &f.PlanSource)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return fmt.Errorf("read account plan: %w", e)
		}
		sub, e := ownerSubjectTx(ctx, tx, accountID)
		if e != nil {
			return e
		}
		f.OwnerSubject = sub
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		return personalmig.Footprint{}, ErrNotFound
	}
	if err != nil {
		return personalmig.Footprint{}, fmt.Errorf("cloudserver/store.PersonalMigrationFootprint: %w", err)
	}
	return f, nil
}

// migPersonalOrgTx is personalOrgTx (personalorg.go, the one read of the
// caller's personal org) in the migration's shape. accountID must be the
// transaction's own account (WithAccount).
func migPersonalOrgTx(ctx context.Context, tx pgx.Tx, _ string) (personalmig.PersonalOrg, bool, error) {
	o, e := personalOrgTx(ctx, tx)
	if errors.Is(e, ErrNotFound) {
		return personalmig.PersonalOrg{}, false, nil
	}
	if e != nil {
		return personalmig.PersonalOrg{}, false, fmt.Errorf("read personal org: %w", e)
	}
	return personalmig.PersonalOrg{OrgID: o.OrgID, Slug: o.Slug, Status: string(o.Status)}, true, nil
}

// accountSubscriptionsTx reads every subscription the account pays for.
func accountSubscriptionsTx(ctx context.Context, tx pgx.Tx, accountID string) ([]personalmig.Subscription, error) {
	rows, err := tx.Query(ctx,
		`SELECT paddle_subscription_id, plan_name, plan_version, status, coalesce(org_id::text, '')
		   FROM paddle_subscriptions WHERE account_id = $1::uuid
		  ORDER BY created_at, paddle_subscription_id`, accountID)
	if err != nil {
		return nil, fmt.Errorf("read subscriptions: %w", err)
	}
	defer rows.Close()
	var out []personalmig.Subscription
	for rows.Next() {
		var s personalmig.Subscription
		if err := rows.Scan(&s.ID, &s.PlanName, &s.PlanVersion, &s.Status, &s.OrgID); err != nil {
			return nil, fmt.Errorf("read subscriptions: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ownerSubjectTx reads the account's WorkOS subject by the same rule as the
// OIDC issuer and the create_tenant owner (a workos link first, then the
// oldest), "" when it has none.
func ownerSubjectTx(ctx context.Context, tx pgx.Tx, accountID string) (string, error) {
	var sub string
	e := tx.QueryRow(ctx,
		`SELECT l.subject FROM identity_links l
		  WHERE l.account_id = $1::uuid
		  ORDER BY (l.provider = 'workos') DESC, l.created_at, l.id
		  LIMIT 1`, accountID).Scan(&sub)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", nil
	}
	if e != nil {
		return "", fmt.Errorf("read owner subject: %w", e)
	}
	return sub, nil
}

// PersonalMigrationResults reads every analysis result of the account with
// its corrections, in (created_at, id) order, for personalmig.BuildExport.
func (s *Store) PersonalMigrationResults(ctx context.Context, accountID string) ([]personalmig.ResultFacts, error) {
	if !validOrgID(accountID) {
		return nil, ErrNotFound
	}
	var out []personalmig.ResultFacts
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT r.id::text, r.kind, coalesce(cs.cloud_session_id, ''), r.created_at, r.superseded,
			        r.result = $2::jsonb, r.result::text
			   FROM analysis_results r
			   JOIN analysis_jobs j ON j.account_id = r.account_id AND j.id = r.job_id
			   LEFT JOIN cloud_sessions cs ON cs.account_id = j.account_id AND cs.id = j.session_pk
			  WHERE r.account_id = $1::uuid
			  ORDER BY r.created_at, r.id
			  LIMIT $3`, accountID, tombstoneResult, personalMigrationResultLimit+1)
		if err != nil {
			return fmt.Errorf("read results: %w", err)
		}
		index := map[string]int{}
		for rows.Next() {
			var r personalmig.ResultFacts
			var body string
			if err := rows.Scan(&r.ID, &r.Kind, &r.CloudSessionID, &r.CreatedAt, &r.Superseded, &r.Tombstoned, &body); err != nil {
				rows.Close()
				return fmt.Errorf("read results: %w", err)
			}
			r.Result = []byte(body)
			index[r.ID] = len(out)
			out = append(out, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("read results: %w", err)
		}
		if len(out) > personalMigrationResultLimit {
			return fmt.Errorf("account has more than %d results", personalMigrationResultLimit)
		}
		revs, err := tx.Query(ctx,
			`SELECT result_id::text, revision_seq, correction::text
			   FROM result_revisions WHERE account_id = $1::uuid
			  ORDER BY result_id, revision_seq`, accountID)
		if err != nil {
			return fmt.Errorf("read revisions: %w", err)
		}
		defer revs.Close()
		for revs.Next() {
			var rid, body string
			var seq int
			if err := revs.Scan(&rid, &seq, &body); err != nil {
				return fmt.Errorf("read revisions: %w", err)
			}
			if i, ok := index[rid]; ok {
				out[i].Revisions = append(out[i].Revisions, personalmig.Revision{Seq: seq, Correction: []byte(body)})
			}
		}
		return revs.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.PersonalMigrationResults: %w", err)
	}
	return out, nil
}

// personalMigrationResultLimit is the bundle bound (one bundle per account).
const personalMigrationResultLimit = 100000

// GetPersonalMigration returns the account's ledger row; found is false when
// it has none.
func (s *Store) GetPersonalMigration(ctx context.Context, accountID string) (PersonalMigrationRow, bool, error) {
	if !validOrgID(accountID) {
		return PersonalMigrationRow{}, false, nil
	}
	var row PersonalMigrationRow
	found := false
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		r, ok, e := readPersonalMigrationTx(ctx, tx, accountID, false)
		row, found = r, ok
		return e
	})
	if err != nil {
		return PersonalMigrationRow{}, false, fmt.Errorf("cloudserver/store.GetPersonalMigration: %w", err)
	}
	return row, found, nil
}

// ListPersonalMigrations returns every ledger row in account_id order.
func (s *Store) ListPersonalMigrations(ctx context.Context) ([]PersonalMigrationRow, error) {
	var out []PersonalMigrationRow
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+personalMigrationColumns+` FROM personal_migrations ORDER BY account_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanPersonalMigration(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListPersonalMigrations: %w", err)
	}
	return out, nil
}

const personalMigrationColumns = `account_id::text, coalesce(org_id::text, ''), stage, coalesce(skip_reason, ''),
	results_total, results_exported, results_skipped, coalesce(rekeyed_subscription_id, ''),
	coalesce(bundle_sha256, ''), receipt_inserted, receipt_already_present, receipt_present,
	coalesce(last_error, ''), created_at, updated_at`

func scanPersonalMigration(row pgx.Row) (PersonalMigrationRow, error) {
	var r PersonalMigrationRow
	var stage string
	err := row.Scan(&r.AccountID, &r.OrgID, &stage, &r.SkipReason,
		&r.ResultsTotal, &r.ResultsExported, &r.ResultsSkipped, &r.RekeyedSubscriptionID,
		&r.BundleSHA256, &r.ReceiptInserted, &r.ReceiptAlreadyPresent, &r.ReceiptPresent,
		&r.LastError, &r.CreatedAt, &r.UpdatedAt)
	r.Stage = personalmig.Stage(stage)
	return r, err
}

func readPersonalMigrationTx(ctx context.Context, tx pgx.Tx, accountID string, forUpdate bool) (PersonalMigrationRow, bool, error) {
	q := `SELECT ` + personalMigrationColumns + ` FROM personal_migrations WHERE account_id = $1::uuid`
	if forUpdate {
		q += ` FOR UPDATE`
	}
	r, err := scanPersonalMigration(tx.QueryRow(ctx, q, accountID))
	if errors.Is(err, pgx.ErrNoRows) {
		return PersonalMigrationRow{}, false, nil
	}
	if err != nil {
		return PersonalMigrationRow{}, false, fmt.Errorf("read ledger: %w", err)
	}
	return r, true, nil
}

// RecordPersonalMigration writes the account's ledger row as row (its
// stage, counts, receipt and error). It returns changed=true when the stage
// moved (and an audit row was written). A move the stage machine refuses is
// ErrPersonalMigrationStage and writes nothing.
func (s *Store) RecordPersonalMigration(ctx context.Context, row PersonalMigrationRow) (bool, error) {
	var changed bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		c, e := writePersonalMigrationTx(ctx, tx, row)
		changed = c
		return e
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.RecordPersonalMigration: %w", err)
	}
	return changed, nil
}

// RecordPersonalMigrationError notes a failed step on the account's ledger
// row without moving its stage, so the failure shows in status. It reports
// whether a row was there to note it on (an account fails before its first
// row only when the ledger itself cannot be written).
func (s *Store) RecordPersonalMigrationError(ctx context.Context, accountID, msg string) (bool, error) {
	msg = boundText(msg, personalMigrationErrorMax)
	if msg == "" {
		msg = "error"
	}
	var noted bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := lockPersonalMigrationTx(ctx, tx, accountID); err != nil {
			return err
		}
		tag, e := tx.Exec(ctx,
			`UPDATE personal_migrations SET last_error = $2, updated_at = now() WHERE account_id = $1::uuid`,
			accountID, msg)
		noted = tag.RowsAffected() == 1
		return e
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.RecordPersonalMigrationError: %w", err)
	}
	return noted, nil
}

func lockPersonalMigrationTx(ctx context.Context, tx pgx.Tx, accountID string) error {
	_, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('sbci_personal_migration:' || $1::uuid::text, 0))`, accountID)
	if err != nil {
		return fmt.Errorf("ledger lock: %w", err)
	}
	return nil
}

// writePersonalMigrationTx is the ledger's one writer: under the account's
// ledger lock it reads the current stage, refuses a move personalmig.CanMove
// does not allow, upserts the row and, when the stage changed, appends one
// personal_migration_<stage> audit row (ids and counts, no content).
func writePersonalMigrationTx(ctx context.Context, tx pgx.Tx, row PersonalMigrationRow) (bool, error) {
	if !row.Stage.Valid() {
		return false, fmt.Errorf("unknown stage %q: %w", row.Stage, ErrPersonalMigrationStage)
	}
	if err := lockPersonalMigrationTx(ctx, tx, row.AccountID); err != nil {
		return false, err
	}
	cur, found, err := readPersonalMigrationTx(ctx, tx, row.AccountID, true)
	if err != nil {
		return false, err
	}
	from := personalmig.StageNone
	if found {
		from = cur.Stage
	}
	if !personalmig.CanMove(from, row.Stage) {
		return false, fmt.Errorf("%q -> %q: %w", from, row.Stage, ErrPersonalMigrationStage)
	}
	reason := ""
	if row.Stage == personalmig.StageSkipped {
		reason = boundText(row.SkipReason, personalMigrationReasonMax)
		if reason == "" {
			reason = "skipped"
		}
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO personal_migrations
		     (account_id, org_id, stage, skip_reason, results_total, results_exported, results_skipped,
		      rekeyed_subscription_id, bundle_sha256, receipt_inserted, receipt_already_present,
		      receipt_present, last_error)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 ON CONFLICT (account_id) DO UPDATE SET
		     org_id                  = EXCLUDED.org_id,
		     stage                   = EXCLUDED.stage,
		     skip_reason             = EXCLUDED.skip_reason,
		     results_total           = EXCLUDED.results_total,
		     results_exported        = EXCLUDED.results_exported,
		     results_skipped         = EXCLUDED.results_skipped,
		     rekeyed_subscription_id = EXCLUDED.rekeyed_subscription_id,
		     bundle_sha256           = EXCLUDED.bundle_sha256,
		     receipt_inserted        = EXCLUDED.receipt_inserted,
		     receipt_already_present = EXCLUDED.receipt_already_present,
		     receipt_present         = EXCLUDED.receipt_present,
		     last_error              = EXCLUDED.last_error,
		     updated_at              = now()`,
		row.AccountID, nullString(row.OrgID), string(row.Stage), nullString(reason),
		row.ResultsTotal, row.ResultsExported, row.ResultsSkipped,
		nullString(row.RekeyedSubscriptionID), nullString(strings.ToLower(row.BundleSHA256)),
		row.ReceiptInserted, row.ReceiptAlreadyPresent, row.ReceiptPresent,
		nullString(boundText(row.LastError, personalMigrationErrorMax)))
	if err != nil {
		return false, fmt.Errorf("write ledger: %w", err)
	}
	if from == row.Stage {
		return false, nil
	}
	detail, err := json.Marshal(personalMigrationAudit{
		From: string(from), Stage: string(row.Stage), OrgID: row.OrgID,
		ResultsTotal: row.ResultsTotal, ResultsExported: row.ResultsExported, ResultsSkipped: row.ResultsSkipped,
		SubscriptionRekeyed: row.RekeyedSubscriptionID != "", BundleSHA256: strings.ToLower(row.BundleSHA256),
		ReceiptPresent: row.ReceiptPresent, SkipReason: reason,
	})
	if err != nil {
		return false, fmt.Errorf("encode audit: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO security_audit_events (account_id, event_type, detail) VALUES ($1::uuid, $2, $3::jsonb)`,
		row.AccountID, PersonalMigrationAuditPrefix+string(row.Stage), string(detail)); err != nil {
		return false, fmt.Errorf("record audit: %w", err)
	}
	return true, nil
}

// PersonalMigrationAuditPrefix starts the event type of every ledger stage
// change (personal_migration_<stage>); PersonalMigrationRunAudit is the
// run-level event.
const (
	PersonalMigrationAuditPrefix = "personal_migration_"
	PersonalMigrationRunAudit    = "personal_migration_run"
)

// personalMigrationAudit is a stage change's audit detail.
type personalMigrationAudit struct {
	From                string `json:"from"`
	Stage               string `json:"stage"`
	OrgID               string `json:"org_id,omitempty"`
	ResultsTotal        int    `json:"results_total"`
	ResultsExported     int    `json:"results_exported"`
	ResultsSkipped      int    `json:"results_skipped"`
	SubscriptionRekeyed bool   `json:"subscription_rekeyed"`
	BundleSHA256        string `json:"bundle_sha256,omitempty"`
	ReceiptPresent      *int   `json:"receipt_present,omitempty"`
	SkipReason          string `json:"skip_reason,omitempty"`
}

// boundText trims s and cuts it to at most max runes.
func boundText(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	r := []rune(s)
	return string(r[:maxRunes])
}

// EnsurePersonalOrgForMigration is store.EnsurePersonalOrg (personalorg.go,
// the one lazy-create rule shared with the console and the device route) in
// the migration's shape: the account's personal org, provisioned when it has
// none; created reports a new org.
func (s *Store) EnsurePersonalOrgForMigration(ctx context.Context, accountID, tenantDomain string) (personalmig.PersonalOrg, bool, error) {
	org, created, err := s.EnsurePersonalOrg(ctx, accountID, tenantDomain)
	if err != nil {
		return personalmig.PersonalOrg{}, false, fmt.Errorf("cloudserver/store.EnsurePersonalOrgForMigration: %w", err)
	}
	return personalmig.PersonalOrg{OrgID: org.OrgID, Slug: org.Slug, Status: string(org.Status)}, created, nil
}

// RekeyOutcome is what RekeyPersonalSubscription did.
type RekeyOutcome struct {
	// SubscriptionID is the subscription now bound to the personal org (this
	// call or an earlier one), "" when the account has none.
	SubscriptionID string
	// Rekeyed is true when this call moved it.
	Rekeyed bool
	// ClosedPlanRows is the number of Paddle-sourced account plan rows this
	// call closed or removed.
	ClosedPlanRows int
	// Refused is why the re-key was refused (the caller records the account
	// as skipped); nothing was written.
	Refused string
	// Row is the ledger row written (stage rekeyed) when Refused is "".
	Row PersonalMigrationRow
}

// rekeyRefusal is one row of the in-transaction re-check: the facts read
// under the locks are re-checked before anything is written, and the first
// row that refuses decides.
type rekeyRefusal struct {
	refuse func(live []personalmig.Subscription) string
}

var rekeyRefusals = []rekeyRefusal{
	{func(live []personalmig.Subscription) string {
		if len(live) > 1 {
			return fmt.Sprintf("%d live account subscriptions", len(live))
		}
		return ""
	}},
	{func(live []personalmig.Subscription) string {
		if len(live) == 1 && live[0].PlanName != personalmig.AccountPaidPlan {
			return fmt.Sprintf("live subscription %s is on %s, not %s", live[0].ID, live[0].PlanName, personalmig.AccountPaidPlan)
		}
		return ""
	}},
}

// RekeyPersonalSubscription re-keys the account's live plus_beta
// subscription onto its personal org in ONE transaction, and writes the
// ledger row base as stage rekeyed in the same transaction (D-IND-6):
//
//  1. the billing apply's per-account advisory lock (F4) and the 0090
//     trigger's per-org key are taken first, so a concurrent webhook for the
//     account waits and the trigger's own lock is a re-entry;
//  2. the live account subscription (org_id NULL) is bound to the org and
//     its plan rewritten to personalmig.OrgPlanName/OrgPlanVersion, inside a savepoint: a second
//     live subscription of the org is the trigger's refusal, reported as
//     Refused with nothing written;
//  3. the account's Paddle-sourced account_plans rows are closed at now (one
//     starting at or after now is removed), so the account path grants
//     nothing; any other source (an operator grant) is left alone;
//  4. the ledger moves to rekeyed with the subscription id.
//
// Idempotent: with no live account subscription nothing is moved and the
// subscription already bound to the org (if any) is reported; no Paddle API
// is called.
func (s *Store) RekeyPersonalSubscription(ctx context.Context, accountID string, org personalmig.PersonalOrg, base PersonalMigrationRow, now time.Time) (RekeyOutcome, error) {
	if _, ok := entitlements.Plan(personalmig.OrgPlanName, personalmig.OrgPlanVersion); !ok {
		return RekeyOutcome{}, fmt.Errorf("cloudserver/store.RekeyPersonalSubscription: catalog has no %s v%d", personalmig.OrgPlanName, personalmig.OrgPlanVersion)
	}
	if !validOrgID(accountID) || !validOrgID(org.OrgID) {
		return RekeyOutcome{}, ErrNotFound
	}
	now = now.UTC()
	var out RekeyOutcome
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, accountID); e != nil {
			return fmt.Errorf("billing lock: %w", e)
		}
		if e := orgLiveLockTx(ctx, tx, org.OrgID); e != nil {
			return fmt.Errorf("org live lock: %w", e)
		}
		mine, ok, e := migPersonalOrgTx(ctx, tx, accountID)
		if e != nil {
			return e
		}
		if !ok || mine.OrgID != org.OrgID {
			return fmt.Errorf("org %s is not the account's personal org", org.OrgID)
		}
		subs, e := accountSubscriptionsTx(ctx, tx, accountID)
		if e != nil {
			return e
		}
		var live []personalmig.Subscription
		for _, sub := range subs {
			switch {
			case sub.OrgID == "" && sub.Live():
				live = append(live, sub)
			case sub.OrgID == org.OrgID && (out.SubscriptionID == "" || sub.Live()):
				out.SubscriptionID = sub.ID
			}
		}
		for _, r := range rekeyRefusals {
			if why := r.refuse(live); why != "" {
				out.Refused = why
				return nil
			}
		}
		if len(live) == 1 {
			refused, e := inSavepointTx(ctx, tx, func(sp pgx.Tx) error {
				_, err := sp.Exec(ctx,
					`UPDATE paddle_subscriptions
					    SET org_id = $3::uuid, plan_name = $4, plan_version = $5, updated_at = now()
					  WHERE account_id = $1::uuid AND paddle_subscription_id = $2 AND org_id IS NULL`,
					accountID, live[0].ID, org.OrgID, personalmig.OrgPlanName, personalmig.OrgPlanVersion)
				return err
			})
			if e != nil {
				return fmt.Errorf("re-key subscription: %w", e)
			}
			if refused {
				out.Refused = "the personal org already holds a live subscription"
				return nil
			}
			out.SubscriptionID, out.Rekeyed = live[0].ID, true
			tag, e := tx.Exec(ctx,
				`DELETE FROM account_plans
				  WHERE account_id = $1::uuid AND source = $2 AND effective_from >= $3`,
				accountID, personalmig.PaddlePlanSource, now)
			if e != nil {
				return fmt.Errorf("remove scheduled paddle plans: %w", e)
			}
			out.ClosedPlanRows = int(tag.RowsAffected())
			tag, e = tx.Exec(ctx,
				`UPDATE account_plans SET effective_until = $3
				  WHERE account_id = $1::uuid AND source = $2 AND effective_from < $3
				    AND (effective_until IS NULL OR effective_until > $3)`,
				accountID, personalmig.PaddlePlanSource, now)
			if e != nil {
				return fmt.Errorf("close paddle plan: %w", e)
			}
			out.ClosedPlanRows += int(tag.RowsAffected())
		}
		row := base
		row.AccountID, row.OrgID, row.Stage = accountID, org.OrgID, personalmig.StageRekeyed
		row.SkipReason, row.LastError = "", ""
		row.RekeyedSubscriptionID = out.SubscriptionID
		if _, e := writePersonalMigrationTx(ctx, tx, row); e != nil {
			return e
		}
		out.Row = row
		return nil
	})
	if err != nil {
		return RekeyOutcome{}, fmt.Errorf("cloudserver/store.RekeyPersonalSubscription: %w", err)
	}
	return out, nil
}
