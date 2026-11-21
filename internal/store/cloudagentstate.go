package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// This file is the ONE owner of the three node-local cloud-agent tables of
// agent migration 241 (cloud_connector_accounts, cloud_sync_checkpoints,
// cloud_usage_ledger). None of them is ever read by orgpush.go; their names
// sit in the privacy sentinel's forbidden set (tests/invariant/privacy_test.go).
// The connector service (internal/cloudagentssvc, wave B) is the intended
// caller; until it exists nothing writes them.

// cloudTokenPattern bounds the short identifier tokens these tables hold
// (connector id, provider, coverage state, error class, unit): a lowercase
// lead, then lowercase letters, digits, ".", "_", ":" or "-", at most 64.
// Never prose and never raw output, so an error class cannot smuggle a
// vendor error body into the database.
var cloudTokenPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,63}$`)

// maxCloudFieldLen bounds the free-form identity and cursor fields (issuer,
// account id, display e-mail, scope ids, provider cursor).
const maxCloudFieldLen = 512

func validCloudToken(v string) bool { return cloudTokenPattern.MatchString(v) }

func validCloudField(v string) bool { return len(v) <= maxCloudFieldLen }

// CloudConnectorAccount is one linked vendor account (cloud_connector_accounts).
// Secrets are never part of it: they live in the OS keychain.
type CloudConnectorAccount struct {
	ID int64 // row id; zero on insert
	// Connector is the connector id ("codex-cloud", "cursor-cloud", ...).
	Connector string
	// Provider is the vendor ("openai", "cursor", "cognition", ...).
	Provider string
	// Issuer is the issuer or tenant the account id is unique within; "" when
	// the vendor has a single namespace.
	Issuer string
	// AccountID is the vendor's IMMUTABLE account id (never an e-mail that
	// can change).
	AccountID string
	// DisplayEmail is shown on the settings page only.
	DisplayEmail string
	// CoverageState is the account's coverage token; the vocabulary belongs
	// to the connector package (internal/cloudagents, wave B). "" = not yet
	// assessed.
	CoverageState string
	// LastErrorClass is a short error class token, never raw output. "" =
	// no error.
	LastErrorClass string
	// VendorUserID is the vendor user a member-scoped account names (Devin
	// user-<32 hex>, agent migration 247); "" = none chosen. Written only by
	// SetCloudConnectorVendorUser; UpsertCloudConnectorAccount never
	// touches it, so a re-connect keeps the choice.
	VendorUserID string
	// VendorUserPurged is the vendor user id for which the removal of the
	// other members' already-landed sessions last completed (written by
	// MarkCloudConnectorVendorUserPurged). While it differs from
	// VendorUserID that removal is still owed.
	VendorUserPurged string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (a CloudConnectorAccount) validate() error {
	switch {
	case !validCloudToken(a.Connector):
		return fmt.Errorf("connector %q is not a token", a.Connector)
	case !validCloudToken(a.Provider):
		return fmt.Errorf("provider %q is not a token", a.Provider)
	case a.AccountID == "" || !validCloudField(a.AccountID):
		return errors.New("account id is required and bounded")
	case !validCloudField(a.Issuer) || !validCloudField(a.DisplayEmail):
		return errors.New("issuer or display e-mail too long")
	case a.CoverageState != "" && !validCloudToken(a.CoverageState):
		return fmt.Errorf("coverage state %q is not a token", a.CoverageState)
	case a.LastErrorClass != "" && !validCloudToken(a.LastErrorClass):
		return errors.New("last error class is not a token")
	}
	return nil
}

// UpsertCloudConnectorAccount inserts a linked account or, when
// (connector, issuer, account_id) is already linked, updates its display
// e-mail, coverage state and error class in place. It returns the row id.
func (s *Store) UpsertCloudConnectorAccount(ctx context.Context, a CloudConnectorAccount) (int64, error) {
	if err := a.validate(); err != nil {
		return 0, fmt.Errorf("store.UpsertCloudConnectorAccount: %w", err)
	}
	now := timestamp(time.Now())
	var id int64
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO cloud_connector_accounts
		   (connector, provider, issuer, account_id, display_email, coverage_state, last_error_class, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (connector, issuer, account_id) DO UPDATE SET
		   provider = excluded.provider,
		   display_email = excluded.display_email,
		   coverage_state = excluded.coverage_state,
		   last_error_class = excluded.last_error_class,
		   updated_at = excluded.updated_at
		 RETURNING id`,
		a.Connector, a.Provider, a.Issuer, a.AccountID, a.DisplayEmail, a.CoverageState, a.LastErrorClass, now, now,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store.UpsertCloudConnectorAccount: %w", err)
	}
	return id, nil
}

// SetCloudConnectorAccountState records an account's coverage state and last
// error class ("" clears the error). ok is false when the account is gone.
func (s *Store) SetCloudConnectorAccountState(ctx context.Context, id int64, coverage, errorClass string) (bool, error) {
	if coverage != "" && !validCloudToken(coverage) {
		return false, fmt.Errorf("store.SetCloudConnectorAccountState: coverage state %q is not a token", coverage)
	}
	if errorClass != "" && !validCloudToken(errorClass) {
		return false, errors.New("store.SetCloudConnectorAccountState: error class is not a token")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE cloud_connector_accounts SET coverage_state = ?, last_error_class = ?, updated_at = ? WHERE id = ?`,
		coverage, errorClass, timestamp(time.Now()), id)
	if err != nil {
		return false, fmt.Errorf("store.SetCloudConnectorAccountState: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListCloudConnectorAccounts returns every linked account, ordered by
// connector then id. connector "" lists all connectors.
func (s *Store) ListCloudConnectorAccounts(ctx context.Context, connector string) ([]CloudConnectorAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, connector, provider, issuer, account_id, display_email, coverage_state, last_error_class,
		        vendor_user_id, vendor_user_purged, created_at, updated_at
		   FROM cloud_connector_accounts
		  WHERE ? = '' OR connector = ?
		  ORDER BY connector, id`, connector, connector)
	if err != nil {
		return nil, fmt.Errorf("store.ListCloudConnectorAccounts: %w", err)
	}
	defer rows.Close()
	var out []CloudConnectorAccount
	for rows.Next() {
		var a CloudConnectorAccount
		var created, updated string
		if err := rows.Scan(&a.ID, &a.Connector, &a.Provider, &a.Issuer, &a.AccountID, &a.DisplayEmail,
			&a.CoverageState, &a.LastErrorClass, &a.VendorUserID, &a.VendorUserPurged, &created, &updated); err != nil {
			return nil, fmt.Errorf("store.ListCloudConnectorAccounts: scan: %w", err)
		}
		a.CreatedAt, a.UpdatedAt = parseCloudTime(created), parseCloudTime(updated)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListCloudConnectorAccounts: rows: %w", err)
	}
	return out, nil
}

// cloudVendorUserPattern bounds a vendor user id this table keeps: the
// connector package validates its own grammar first (Devin user-<32 hex));
// the store refuses anything that is not a short id token.
var cloudVendorUserPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// SetCloudConnectorVendorUser records the vendor user a member-scoped account
// names (CLOUDAGENTS-6). Setting a different user leaves vendor_user_purged
// as it was, so the removal of the other members' sessions is owed again.
// ok is false when the account is gone.
func (s *Store) SetCloudConnectorVendorUser(ctx context.Context, id int64, userID string) (bool, error) {
	if !cloudVendorUserPattern.MatchString(userID) {
		return false, errors.New("store.SetCloudConnectorVendorUser: the vendor user id is not an id")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE cloud_connector_accounts SET vendor_user_id = ?, updated_at = ? WHERE id = ?`,
		userID, timestamp(time.Now()), id)
	if err != nil {
		return false, fmt.Errorf("store.SetCloudConnectorVendorUser: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// MarkCloudConnectorVendorUserPurged records that the removal of the other
// members' sessions completed for userID. It applies only while userID is
// still the account's chosen user, so a choice changed meanwhile keeps its
// own removal owed. ok is false when nothing was marked.
func (s *Store) MarkCloudConnectorVendorUserPurged(ctx context.Context, id int64, userID string) (bool, error) {
	if userID == "" {
		return false, nil
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE cloud_connector_accounts SET vendor_user_purged = ?, updated_at = ? WHERE id = ? AND vendor_user_id = ?`,
		userID, timestamp(time.Now()), id, userID)
	if err != nil {
		return false, fmt.Errorf("store.MarkCloudConnectorVendorUserPurged: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeleteSessionlessCloudUsage removes the ledger rows of one connector scoped
// to the given vendor session ids that have NO session row: the native-unit
// figures of a task that lands no session (a Warp run of a harness with no
// Observer tool, Warp's own oz) and that the member-scope correction found
// another person or a service account started (CLOUDAGENTS-6, task CA-T8).
// A scope that is a landed session is never touched here: its ledger rows go
// with the session through PurgeToolSessions. The table is node-local (never
// pushed), so nothing is tombstoned. It returns the rows deleted.
func (s *Store) DeleteSessionlessCloudUsage(ctx context.Context, connector string, sessionIDs []string) (int, error) {
	if !validCloudToken(connector) || len(sessionIDs) == 0 {
		return 0, nil
	}
	ids := append([]string(nil), sessionIDs...)
	sort.Strings(ids)
	total := 0
	for len(ids) > 0 {
		n := min(len(ids), purgeChunk)
		part := ids[:n]
		ids = ids[n:]
		args := make([]any, 0, len(part)+1)
		args = append(args, connector)
		for _, id := range part {
			args = append(args, id)
		}
		//nolint:gosec // G202: only bound placeholders are concatenated.
		res, err := s.db.ExecContext(ctx,
			`DELETE FROM cloud_usage_ledger
			  WHERE connector = ? AND scope_session IN (`+strings.TrimSuffix(strings.Repeat("?,", len(part)), ",")+`)
			    AND scope_session <> ''
			    AND NOT EXISTS (SELECT 1 FROM sessions WHERE sessions.id = cloud_usage_ledger.scope_session)`,
			args...)
		if err != nil {
			return total, fmt.Errorf("store.DeleteSessionlessCloudUsage: %w", err)
		}
		k, _ := res.RowsAffected()
		total += int(k)
	}
	return total, nil
}

// DeleteCloudConnectorAccount unlinks an account. Its checkpoints go with it
// (ON DELETE CASCADE: collection state); its ledger rows stay (history is
// never deleted by an unlink). ok is false when the account was not linked.
func (s *Store) DeleteCloudConnectorAccount(ctx context.Context, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM cloud_connector_accounts WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("store.DeleteCloudConnectorAccount: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// CloudSyncGap is one interval a stream could not cover (a live stream that
// resumed only from now, a page that expired). Recorded, never erased, so a
// missed window stays visible.
type CloudSyncGap struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// CloudSyncCheckpoint is one row of cloud_sync_checkpoints: the checkpoint of
// one stream of one linked account.
type CloudSyncCheckpoint struct {
	AccountPK int64
	// Stream is one of the models.SyncStream* kinds.
	Stream string
	// Scope is "" for an account-wide stream and the session id for a
	// per-session history cursor.
	Scope string
	// Cursor is the provider cursor or watermark (opaque to the store).
	Cursor string
	// OverlapSeconds is the re-read window applied before Cursor.
	OverlapSeconds int64
	LastAttemptAt  time.Time
	LastSuccessAt  time.Time
	Gaps           []CloudSyncGap
	UpdatedAt      time.Time
}

func (c CloudSyncCheckpoint) validate() error {
	switch {
	case c.AccountPK <= 0:
		return errors.New("account is required")
	case !models.KnownSyncStream(c.Stream):
		return fmt.Errorf("unknown stream %q", c.Stream)
	case c.OverlapSeconds < 0:
		return errors.New("overlap must not be negative")
	case !validCloudField(c.Scope) || !validCloudField(c.Cursor):
		return errors.New("scope or cursor too long")
	}
	for _, g := range c.Gaps {
		if g.From.IsZero() || g.To.IsZero() || g.To.Before(g.From) {
			return errors.New("a gap needs from <= to")
		}
	}
	return nil
}

// cloudAgentExecer is the subset of *sql.DB / *sql.Tx the checkpoint and ledger
// writers need, so CommitCloudSyncPage can run them in one transaction.
type cloudAgentExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func saveCloudSyncCheckpoint(ctx context.Context, x cloudAgentExecer, c CloudSyncCheckpoint) error {
	if err := c.validate(); err != nil {
		return err
	}
	gaps := c.Gaps
	if gaps == nil {
		gaps = []CloudSyncGap{}
	}
	gapsJSON, err := json.Marshal(gaps)
	if err != nil {
		return err
	}
	_, err = x.ExecContext(ctx,
		`INSERT INTO cloud_sync_checkpoints
		   (account_pk, stream, scope, cursor, overlap_seconds, last_attempt_at, last_success_at, gaps_json, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (account_pk, stream, scope) DO UPDATE SET
		   cursor = excluded.cursor,
		   overlap_seconds = excluded.overlap_seconds,
		   last_attempt_at = excluded.last_attempt_at,
		   last_success_at = excluded.last_success_at,
		   gaps_json = excluded.gaps_json,
		   updated_at = excluded.updated_at`,
		c.AccountPK, c.Stream, c.Scope, c.Cursor, c.OverlapSeconds,
		optionalCloudTime(c.LastAttemptAt), optionalCloudTime(c.LastSuccessAt), string(gapsJSON), timestamp(time.Now()))
	return err
}

// SaveCloudSyncCheckpoint writes (inserts or replaces) one checkpoint. A
// connector that imports a page of ledger rows uses CommitCloudSyncPage
// instead, so the page and its checkpoint commit together.
func (s *Store) SaveCloudSyncCheckpoint(ctx context.Context, c CloudSyncCheckpoint) error {
	if err := saveCloudSyncCheckpoint(ctx, s.db, c); err != nil {
		return fmt.Errorf("store.SaveCloudSyncCheckpoint: %w", err)
	}
	return nil
}

// LoadCloudSyncCheckpoint returns one checkpoint; ok is false when the
// stream has never been checkpointed.
func (s *Store) LoadCloudSyncCheckpoint(ctx context.Context, accountPK int64, stream, scope string) (CloudSyncCheckpoint, bool, error) {
	c := CloudSyncCheckpoint{AccountPK: accountPK, Stream: stream, Scope: scope}
	var attempt, success, gapsJSON, updated string
	err := s.db.QueryRowContext(ctx,
		`SELECT cursor, overlap_seconds, last_attempt_at, last_success_at, gaps_json, updated_at
		   FROM cloud_sync_checkpoints WHERE account_pk = ? AND stream = ? AND scope = ?`,
		accountPK, stream, scope,
	).Scan(&c.Cursor, &c.OverlapSeconds, &attempt, &success, &gapsJSON, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return c, false, nil
	}
	if err != nil {
		return c, false, fmt.Errorf("store.LoadCloudSyncCheckpoint: %w", err)
	}
	if err := json.Unmarshal([]byte(gapsJSON), &c.Gaps); err != nil {
		return c, false, fmt.Errorf("store.LoadCloudSyncCheckpoint: gaps: %w", err)
	}
	c.LastAttemptAt, c.LastSuccessAt, c.UpdatedAt = parseCloudTime(attempt), parseCloudTime(success), parseCloudTime(updated)
	return c, true, nil
}

// ListCloudSyncCheckpoints returns every checkpoint of one stream of one
// account (each scope), ordered by scope. A connector uses it to find the
// per-session history checkpoints it keeps for sessions that were still live
// at their last observation (lane CA-B1).
func (s *Store) ListCloudSyncCheckpoints(ctx context.Context, accountPK int64, stream string) ([]CloudSyncCheckpoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT scope, cursor, overlap_seconds, last_attempt_at, last_success_at, gaps_json, updated_at
		   FROM cloud_sync_checkpoints WHERE account_pk = ? AND stream = ? ORDER BY scope`,
		accountPK, stream)
	if err != nil {
		return nil, fmt.Errorf("store.ListCloudSyncCheckpoints: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []CloudSyncCheckpoint
	for rows.Next() {
		c := CloudSyncCheckpoint{AccountPK: accountPK, Stream: stream}
		var attempt, success, gapsJSON, updated string
		if err := rows.Scan(&c.Scope, &c.Cursor, &c.OverlapSeconds, &attempt, &success, &gapsJSON, &updated); err != nil {
			return nil, fmt.Errorf("store.ListCloudSyncCheckpoints: %w", err)
		}
		if err := json.Unmarshal([]byte(gapsJSON), &c.Gaps); err != nil {
			return nil, fmt.Errorf("store.ListCloudSyncCheckpoints: gaps: %w", err)
		}
		c.LastAttemptAt, c.LastSuccessAt, c.UpdatedAt = parseCloudTime(attempt), parseCloudTime(success), parseCloudTime(updated)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListCloudSyncCheckpoints: %w", err)
	}
	return out, nil
}

// DeleteCloudSyncCheckpoint removes one checkpoint (a per-session history
// cursor whose session has ended). ok is false when there was none.
func (s *Store) DeleteCloudSyncCheckpoint(ctx context.Context, accountPK int64, stream, scope string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM cloud_sync_checkpoints WHERE account_pk = ? AND stream = ? AND scope = ?`,
		accountPK, stream, scope)
	if err != nil {
		return false, fmt.Errorf("store.DeleteCloudSyncCheckpoint: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// CloudUsageEntry is one cloud_usage_ledger row: a provider usage figure in
// its NATIVE unit (CA-D11). Real token counts belong in token_usage, not
// here. Entries are never summed across units, and a cumulative or snapshot
// figure is never summed across reports.
type CloudUsageEntry struct {
	ID int64 // row id; zero on insert
	// Connector is the connector id or rail that produced the figure.
	Connector string
	// SourceRecordID is the vendor's record id (or a derived stable key);
	// when set, (Connector, SourceRecordID) lands once.
	SourceRecordID string
	// MeasurementSource is one of the models.UsageSource* kinds.
	MeasurementSource string
	// ValueType is one of the models.UsageValue* kinds.
	ValueType string
	// Unit is the native unit token ("acu", "credit", "usd", "seconds", ...).
	Unit  string
	Value float64
	// MonetaryStatus is one of the models.UsageMonetary* kinds.
	MonetaryStatus string
	// Scope ids, each "" when the vendor did not state it.
	ScopeRun, ScopeSession, ScopeUser, ScopeAccount, ScopeOrg, ScopeModel string
	IntervalStart, IntervalEnd                                            time.Time
	// IncludesChildren is nil when the vendor does not say whether the
	// figure already includes child runs, sub-agents or retries.
	IncludesChildren *bool
	ReportedAt       time.Time
	ObservedAt       time.Time // set by the store on insert
	// SupersedesID is the row this one replaces or adjusts; 0 = none.
	SupersedesID int64
}

func (e CloudUsageEntry) validate() error {
	switch {
	case !validCloudToken(e.Connector):
		return fmt.Errorf("connector %q is not a token", e.Connector)
	case !models.KnownUsageSource(e.MeasurementSource):
		return fmt.Errorf("unknown measurement source %q", e.MeasurementSource)
	case !models.KnownUsageValueType(e.ValueType):
		return fmt.Errorf("unknown value type %q", e.ValueType)
	case !models.KnownUsageMonetaryStatus(e.MonetaryStatus):
		return fmt.Errorf("unknown monetary status %q", e.MonetaryStatus)
	case !validCloudToken(e.Unit):
		return fmt.Errorf("unit %q is not a token", e.Unit)
	case math.IsNaN(e.Value) || math.IsInf(e.Value, 0):
		return errors.New("value must be finite")
	case e.ReportedAt.IsZero():
		return errors.New("reported_at is required")
	case !e.IntervalStart.IsZero() && !e.IntervalEnd.IsZero() && e.IntervalEnd.Before(e.IntervalStart):
		return errors.New("interval end before start")
	case e.SupersedesID < 0:
		return errors.New("supersedes id must not be negative")
	}
	for _, f := range []string{e.SourceRecordID, e.ScopeRun, e.ScopeSession, e.ScopeUser, e.ScopeAccount, e.ScopeOrg, e.ScopeModel} {
		if !validCloudField(f) {
			return errors.New("a record or scope id is too long")
		}
	}
	return nil
}

// insertCloudUsage lands one entry. inserted is false when (connector,
// source_record_id) was already present; id is then the existing row's id.
func insertCloudUsage(ctx context.Context, x cloudAgentExecer, e CloudUsageEntry) (int64, bool, error) {
	if err := e.validate(); err != nil {
		return 0, false, err
	}
	var children any
	if e.IncludesChildren != nil {
		children = boolInt(*e.IncludesChildren)
	}
	var supersedes any
	if e.SupersedesID > 0 {
		supersedes = e.SupersedesID
	}
	res, err := x.ExecContext(ctx,
		`INSERT INTO cloud_usage_ledger
		   (connector, source_record_id, measurement_source, value_type, unit, value, monetary_status,
		    scope_run, scope_session, scope_user, scope_account, scope_org, scope_model,
		    interval_start, interval_end, includes_children, reported_at, observed_at, supersedes_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (connector, source_record_id) WHERE source_record_id <> '' DO NOTHING`,
		e.Connector, e.SourceRecordID, e.MeasurementSource, e.ValueType, e.Unit, e.Value, e.MonetaryStatus,
		e.ScopeRun, e.ScopeSession, e.ScopeUser, e.ScopeAccount, e.ScopeOrg, e.ScopeModel,
		optionalCloudTime(e.IntervalStart), optionalCloudTime(e.IntervalEnd), children,
		timestamp(e.ReportedAt), timestamp(time.Now()), supersedes)
	if err != nil {
		return 0, false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		id, err := res.LastInsertId()
		return id, true, err
	}
	var id int64
	err = x.QueryRowContext(ctx,
		`SELECT id FROM cloud_usage_ledger WHERE connector = ? AND source_record_id = ?`,
		e.Connector, e.SourceRecordID).Scan(&id)
	return id, false, err
}

// InsertCloudUsage lands one ledger entry. inserted is false when the entry's
// (connector, source_record_id) was already present (a re-pulled page); id
// is then the existing row's id.
func (s *Store) InsertCloudUsage(ctx context.Context, e CloudUsageEntry) (int64, bool, error) {
	id, inserted, err := insertCloudUsage(ctx, s.db, e)
	if err != nil {
		return 0, false, fmt.Errorf("store.InsertCloudUsage: %w", err)
	}
	return id, inserted, nil
}

// CommitCloudSyncPage lands one imported page of ledger entries and the
// checkpoint that covers it in ONE transaction (reference "Retrieval
// checkpoints": the cursor advances only once the records are committed). A
// failure rolls back both, so the page is retried and re-landed idempotently.
// It returns how many entries were new.
func (s *Store) CommitCloudSyncPage(ctx context.Context, entries []CloudUsageEntry, cp CloudSyncCheckpoint) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.CommitCloudSyncPage: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	added := 0
	for i, e := range entries {
		_, inserted, err := insertCloudUsage(ctx, tx, e)
		if err != nil {
			return 0, fmt.Errorf("store.CommitCloudSyncPage: entry %d: %w", i, err)
		}
		if inserted {
			added++
		}
	}
	if err := saveCloudSyncCheckpoint(ctx, tx, cp); err != nil {
		return 0, fmt.Errorf("store.CommitCloudSyncPage: checkpoint: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.CommitCloudSyncPage: commit: %w", err)
	}
	return added, nil
}

// CloudUsageFilter narrows ListCloudUsage. Empty fields match everything.
type CloudUsageFilter struct {
	Connector    string
	ScopeSession string
	Limit        int // 0 = 1000
}

// ListCloudUsage returns ledger entries, newest report first. It never sums:
// each entry keeps its own unit, value type and monetary status, and any
// rollup is the caller's explicit, unit-aware decision.
func (s *Store) ListCloudUsage(ctx context.Context, f CloudUsageFilter) ([]CloudUsageEntry, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, connector, source_record_id, measurement_source, value_type, unit, value, monetary_status,
		        scope_run, scope_session, scope_user, scope_account, scope_org, scope_model,
		        interval_start, interval_end, includes_children, reported_at, observed_at, COALESCE(supersedes_id, 0)
		   FROM cloud_usage_ledger
		  WHERE (? = '' OR connector = ?) AND (? = '' OR scope_session = ?)
		  ORDER BY reported_at DESC, id DESC
		  LIMIT ?`,
		f.Connector, f.Connector, f.ScopeSession, f.ScopeSession, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListCloudUsage: %w", err)
	}
	defer rows.Close()
	var out []CloudUsageEntry
	for rows.Next() {
		var e CloudUsageEntry
		var start, end, reported, observed string
		var children sql.NullInt64
		if err := rows.Scan(&e.ID, &e.Connector, &e.SourceRecordID, &e.MeasurementSource, &e.ValueType, &e.Unit,
			&e.Value, &e.MonetaryStatus, &e.ScopeRun, &e.ScopeSession, &e.ScopeUser, &e.ScopeAccount, &e.ScopeOrg,
			&e.ScopeModel, &start, &end, &children, &reported, &observed, &e.SupersedesID); err != nil {
			return nil, fmt.Errorf("store.ListCloudUsage: scan: %w", err)
		}
		if children.Valid {
			b := children.Int64 != 0
			e.IncludesChildren = &b
		}
		e.IntervalStart, e.IntervalEnd = parseCloudTime(start), parseCloudTime(end)
		e.ReportedAt, e.ObservedAt = parseCloudTime(reported), parseCloudTime(observed)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListCloudUsage: rows: %w", err)
	}
	return out, nil
}

// optionalCloudTime formats t, or "" for the zero time (the columns store ""
// for "not stated", not the store-wide timestamp() default of now).
func optionalCloudTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return timestamp(t)
}

// parseCloudTime reads a stored timestamp; "" and an unparseable value give
// the zero time.
func parseCloudTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}
	}
	return t
}
