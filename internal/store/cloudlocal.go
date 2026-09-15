package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// cloudlocal.go is the ONE store seam over the node-local cloud-intelligence
// tables (migration 097 — CI-P2 Lane D, cloud-intelligence Azure Foundry plan
// of record §6 "CI-P2" node-migrations bullet + §6 "CI-P1" bullet
// "Consent/rebuild coherence"). It owns five tables:
//
//   - cloud_consent_receipts   — receipts a developer confirmed; each binds the
//     upload digest of the literal preview they saw.
//   - cloud_session_map / cloud_project_map — local id <-> RANDOM cloud
//     pseudonym (crypto/rand, NEVER derived from the local id).
//   - cloud_outbox             — the rebuild-at-send state machine; NO envelope
//     bodies, only session ref + feature set + confirmed digests + retry state.
//   - cloud_results            — the validated enrichment results (versioned).
//   - cloud_result_overrides   — the user's edits over a result (user wins).
//
// Dependency discipline (task footprint): this seam does NOT import
// internal/cloudevidence or internal/cloudcontract — the envelope rebuild is
// injected as a small EnvelopeRebuild func so the caller (the later CLI) passes
// a closure over cloudevidence while the store stays dependency-clean. It never
// imports internal/cloudclient/cloudpop/cloudcred (the network lane) — the
// zero-egress invariant (tests/invariant/cloud_egress_test.go) pins that.
//
// NODE-LOCAL: none of these tables ever enter the org-push wire. Their names
// are in the forbidden-table denylist walked by tests/invariant/privacy_test.go.

// CloudOutboxState is the outbox send-state-machine state. The vocabulary is
// closed; the transition table below is the single owner of what may move
// where.
type CloudOutboxState string

const (
	// CloudOutboxPending is a freshly enqueued job awaiting a send attempt.
	CloudOutboxPending CloudOutboxState = "pending"
	// CloudOutboxReconfirmationRequired means a rebuild-and-compare at send
	// time found the envelope no longer matches the confirmed digests (a local
	// edit, scrubber upgrade, schema bump, or an invalidated receipt). The job
	// waits for the developer to reconfirm; it is NEVER auto-sent and the
	// digests are NEVER auto-updated.
	CloudOutboxReconfirmationRequired CloudOutboxState = "reconfirmation_required"
	// CloudOutboxSending means the digests matched and the envelope bytes were
	// handed to the caller for upload.
	CloudOutboxSending CloudOutboxState = "sending"
	// CloudOutboxSent is a terminal success state.
	CloudOutboxSent CloudOutboxState = "sent"
	// CloudOutboxFailedRetryable means the send failed with a retryable error
	// class; a later PrepareSend may re-attempt it.
	CloudOutboxFailedRetryable CloudOutboxState = "failed_retryable"
	// CloudOutboxFailedTerminal is a terminal failure state.
	CloudOutboxFailedTerminal CloudOutboxState = "failed_terminal"
	// CloudOutboxCancelled is a terminal state reached when a receipt is
	// cancelled (e.g. consent revoked) while the job was not yet terminal.
	CloudOutboxCancelled CloudOutboxState = "cancelled"
)

// Sentinel errors the seam returns; callers branch on these with errors.Is.
var (
	// ErrCloudOutboxNotFound is returned when an outbox id does not exist.
	ErrCloudOutboxNotFound = errors.New("store: cloud outbox item not found")
	// ErrCloudReceiptNotFound is returned when a receipt id does not exist.
	ErrCloudReceiptNotFound = errors.New("store: cloud consent receipt not found")
	// ErrCloudSessionIneligible is returned by EnqueueCloudOutbox when the
	// session is not eligible for personal-cloud enrichment (org/unknown
	// authority, or missing). The check delegates to EligibleForPersonalCloud.
	ErrCloudSessionIneligible = errors.New("store: session is not eligible for personal cloud enrichment")
	// ErrCloudReceiptDigestMismatch is returned by EnqueueCloudOutbox when the
	// item's upload digest does not equal the bound receipt's confirmed upload
	// digest (a coherence violation at enqueue time).
	ErrCloudReceiptDigestMismatch = errors.New("store: outbox upload digest does not match the bound receipt")
	// ErrCloudOutboxDuplicate is returned by EnqueueCloudOutbox when the same
	// session's SAME upload bytes are already in flight (pending / sending /
	// failed_retryable) - the auto-enrich sweep and a manual "Enrich now" (or
	// two manual clicks) must not double-send one enrichment. The caller can
	// find the existing job with FindLiveCloudOutboxForUpload.
	ErrCloudOutboxDuplicate = errors.New("store: an identical upload for this session is already queued")
	// ErrIllegalCloudOutboxTransition is returned when a state transition is
	// requested from a state that does not permit it.
	ErrIllegalCloudOutboxTransition = errors.New("store: illegal cloud outbox state transition")
	// ErrCloudReconfirmationRequired is the typed error PrepareCloudOutboxSend
	// returns when the rebuilt envelope's digests do not match what the receipt
	// bound; the item is moved to reconfirmation_required.
	ErrCloudReconfirmationRequired = errors.New("store: cloud outbox item requires reconfirmation")
	// ErrCloudEndpointMismatch is returned by PrepareCloudOutboxSend when the
	// send target does not equal the endpoint the consent receipt bound
	// (FD1: confirmed evidence may only ever go to the approved origin+path).
	// The item is moved to reconfirmation_required.
	ErrCloudEndpointMismatch = errors.New("store: send endpoint does not match the consent receipt's bound endpoint")
	// ErrCloudSendUnauthorized is returned by VerifyCloudSendAuthorization when
	// authorization changed after prepare and before dispatch (receipt
	// invalidated, session upgraded to org, endpoint/digest drift). The item is
	// moved out of `sending` back to reconfirmation_required (FD3).
	ErrCloudSendUnauthorized = errors.New("store: cloud send authorization changed before dispatch")
)

// CloudConsentReceipt is one stored consent receipt. It binds the upload
// digest of the literal preview the developer confirmed (amendment §4.2) so a
// later rebuild-and-compare (PrepareCloudOutboxSend) can detect drift.
type CloudConsentReceipt struct {
	ID                     string
	AccountPseudonym       string
	DeviceLabelRef         string
	Purpose                string
	FieldClassesJSON       string
	EvidenceSettingsJSON   string
	EnvelopeSchemaVersion  string
	ScrubberVersion        string
	Endpoint               string
	RetentionPolicyVersion string
	// UploadDigest binds what the developer confirmed. Its meaning depends on
	// GrantMode (migration 098's REUSE NOTE): for CloudGrantPerUpload it is the
	// digest of the ONE literal preview they saw; for CloudGrantStanding there
	// is no single upload to bind, so it holds the DATA-DICTIONARY digest — the
	// schema-level thing a standing grant actually authorizes — and each
	// individual upload's own digest lives on its cloud_outbox row instead.
	// DataDictionaryDigest carries the same value explicitly so a reader never
	// has to infer this from GrantMode.
	UploadDigest string
	CreatedAt    time.Time
	// InvalidatedAt is nil while the receipt is live; set once invalidated.
	InvalidatedAt *time.Time

	// -- R1 standing-grant binding set (migration 098) ------------------------
	//
	// The binding list is NORMATIVE (divergence-remediation plan rev 4.1 §2 R1):
	// a standing receipt binds {purpose, grant_mode, schema version +
	// data-dictionary digest, field classes, retention policy version, declared
	// timezone, source-window rule, endpoint, expiry/review date, consent
	// generation}. The first five already had columns above; these six complete
	// the set.

	// GrantMode is CloudGrantPerUpload (the 097 semantics — one exact upload)
	// or CloudGrantStanding (authorizes a SCHEMA; each upload still gets its
	// own digest, local row, and pre-send revocation check). Empty on insert
	// defaults to CloudGrantPerUpload, so a pre-098 caller keeps its meaning.
	GrantMode CloudGrantMode
	// DataDictionaryDigest is the digest over the published data dictionary a
	// standing grant authorizes.
	DataDictionaryDigest string
	// DeclaredTimezone is the IANA zone the account declared. It decides what a
	// "day" period means, so it is part of what the developer agreed to.
	DeclaredTimezone string
	// SourceWindowRule is the versioned rule identifier for how activity maps
	// to a window.
	SourceWindowRule string
	// ReviewAt is the grant's expiry / review date; nil when none is set.
	ReviewAt *time.Time
	// ConsentGeneration is bumped whenever the grant is re-confirmed under
	// changed terms. A queued snapshot records the generation it was built
	// under; a mismatch at send time means the terms moved and the item needs
	// reconfirmation rather than a silent send.
	ConsentGeneration int
	// BackgroundGeneration binds an unattended receipt to the policy that scheduled it.
	// Zero denotes explicitly attended per-upload or standing consent.
	BackgroundGeneration int64
}

// CloudOutboxItem is one stored outbox row.
//
// A session-evidence item (the default kind) holds NO body — the envelope is
// rebuilt at send from the live session. A structural-insights item is the
// documented exception (migration 098): its exact canonical bytes ARE stored
// and are resent verbatim. The bytes are deliberately NOT a field here — they
// are read only by PrepareStructuralSend, at the moment of sending, so a
// listing or a dashboard read can never accidentally carry a payload around.
type CloudOutboxItem struct {
	ID string
	// Kind discriminates the payload shape (migration 098). Empty is treated as
	// CloudOutboxKindSessionEvidence by the column default.
	Kind CloudOutboxKind
	// SessionID is the session an evidence item was built from. It is the
	// empty string for a structural item — a window has no session.
	SessionID             string
	FeatureSetJSON        string
	EvidenceContentDigest string
	UploadDigest          string
	ReceiptID             string
	State                 CloudOutboxState
	RetryCount            int
	LastError             string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// CloudSendLease is the authorization snapshot PrepareCloudOutboxSend returns
// alongside the rebuilt bytes. The caller re-verifies it (VerifyCloudSendAuthorization)
// immediately before HTTP dispatch — the last cheap check that closes the gap
// between prepare and the network call (FD3). It carries no envelope body.
type CloudSendLease struct {
	OutboxID     string
	ReceiptID    string
	SessionID    string
	UploadDigest string
	// Endpoint is the normalized send target validated at prepare time.
	Endpoint string

	// -- STANDING-grant terms (structural rail only; zero on the evidence path) --
	//
	// These are read from the receipt THIS item is bound to, inside the same
	// transaction that authorized the send. The wire consent headers are
	// populated from them so an item always declares the terms it was actually
	// validated against — never a separately resolved "newest" grant, which
	// would ship old-terms bytes under a new-terms claim if two live standing
	// receipts ever coexisted.
	ConsentGeneration    int
	DataDictionaryDigest string
	SourceWindowRule     string
}

// CloudResultProvenance carries how an enrichment result was produced.
type CloudResultProvenance struct {
	ModelRoute string
	PromptHash string
	Tokens     int
	CostUSD    float64
}

// CloudResult is one stored enrichment result. ResultJSON is the validated
// session_enrichment payload (the product) and is allowed content, node-local.
type CloudResult struct {
	ID            string
	SessionID     string
	SchemaVersion string
	ResultJSON    string
	Provenance    CloudResultProvenance
	ReceivedAt    time.Time
	// SupersededBy is nil for the newest result of a session; otherwise it is
	// the id of the result that replaced this one.
	SupersededBy *string
}

// CloudResultOverride is one user edit over a result field.
type CloudResultOverride struct {
	Field     string
	UserValue string
	UpdatedAt time.Time
}

// EnvelopeRebuild rebuilds the envelope for an outbox item and returns the
// final serialized upload bytes plus the two digests (evidence-content, upload)
// computed over them. The caller passes a closure over cloudevidence.Serialize;
// the store never imports cloudevidence, keeping the seam dependency-clean.
type EnvelopeRebuild func(ctx context.Context) (uploadBytes []byte, evidenceContentDigest, uploadDigest string, err error)

// cloudFormatTime renders a time as RFC3339Nano UTC for storage; a zero time
// stores as the empty string.
func cloudFormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// cloudParseTime parses a stored RFC3339Nano stamp; an empty or unparseable
// value yields the zero time so a hand-edited row can never wedge a read.
func cloudParseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// cloudRandomID returns prefix + 32 hex chars of crypto/rand entropy. It is
// used for receipt/result/outbox ids AND for the local<->cloud pseudonyms —
// pseudonyms are generated here, NEVER derived from the local id.
func cloudRandomID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("store.cloudRandomID: %w", err)
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

// -- Consent receipts --------------------------------------------------------

// InsertCloudConsentReceipt stores a receipt. If r.ID is empty a random id is
// minted; the stored (or minted) id is returned.
func (s *Store) InsertCloudConsentReceipt(ctx context.Context, r CloudConsentReceipt) (string, error) {
	if r.AccountPseudonym == "" {
		return "", errors.New("store.InsertCloudConsentReceipt: account pseudonym is required")
	}
	if r.UploadDigest == "" {
		return "", errors.New("store.InsertCloudConsentReceipt: upload digest is required")
	}
	if r.ID == "" {
		id, err := cloudRandomID("rcpt_")
		if err != nil {
			return "", fmt.Errorf("store.InsertCloudConsentReceipt: %w", err)
		}
		r.ID = id
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	fieldClasses := r.FieldClassesJSON
	if fieldClasses == "" {
		fieldClasses = "[]"
	}
	// An unset grant mode is per-upload: the 097 semantics, so a caller written
	// before standing grants existed keeps exactly its old meaning.
	grantMode := r.GrantMode
	if grantMode == "" {
		grantMode = CloudGrantPerUpload
	}
	if grantMode != CloudGrantPerUpload && grantMode != CloudGrantStanding {
		return "", fmt.Errorf("store.InsertCloudConsentReceipt: unknown grant mode %q", grantMode)
	}
	if _, err := ParseCloudEvidenceSettings(r.EvidenceSettingsJSON); err != nil {
		return "", fmt.Errorf("store.InsertCloudConsentReceipt: %w", err)
	}
	if r.BackgroundGeneration < 0 {
		return "", ErrCloudBackgroundPolicyChanged
	}
	if r.ConsentGeneration < 0 {
		return "", errors.New("store.InsertCloudConsentReceipt: consent generation is negative")
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO cloud_consent_receipts
		  (id, account_pseudonym, device_label_ref, purpose, field_classes_json,
		   envelope_schema_version, scrubber_version, endpoint,
		   retention_policy_version, upload_digest, created_at, invalidated_at,
		   grant_mode, data_dictionary_digest, declared_timezone,
		   source_window_rule, review_at, consent_generation, background_generation, evidence_settings_json)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE ? = 0 OR EXISTS (
            SELECT 1 FROM cloud_enrich_policy WHERE id = 1 AND background = 1 AND generation = ?
              AND ((level = 'titles' AND ? = 'structural_activity_insights')
                OR (level = 'excerpts' AND ? = 'bounded_context_enrichment'))
        )`,
		r.ID, r.AccountPseudonym, r.DeviceLabelRef, r.Purpose, fieldClasses,
		r.EnvelopeSchemaVersion, r.ScrubberVersion, r.Endpoint,
		r.RetentionPolicyVersion, r.UploadDigest, cloudFormatTime(r.CreatedAt),
		nullableCloudTime(r.InvalidatedAt),
		string(grantMode), r.DataDictionaryDigest, r.DeclaredTimezone,
		r.SourceWindowRule, nullableCloudTime(r.ReviewAt), r.ConsentGeneration, r.BackgroundGeneration, r.EvidenceSettingsJSON,
		r.BackgroundGeneration, r.BackgroundGeneration, r.Purpose, r.Purpose)
	if err != nil {
		return "", fmt.Errorf("store.InsertCloudConsentReceipt: %w", err)
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return "", fmt.Errorf("store.InsertCloudConsentReceipt: %w", ErrCloudBackgroundPolicyChanged)
	}
	return r.ID, nil
}

// GetCloudConsentReceipt loads a receipt by id. ok=false means it does not
// exist.
func (s *Store) GetCloudConsentReceipt(ctx context.Context, id string) (CloudConsentReceipt, bool, error) {
	var (
		r             CloudConsentReceipt
		createdAt     string
		invalidatedAt sql.NullString
		grantMode     string
		reviewAt      sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, account_pseudonym, device_label_ref, purpose, field_classes_json,
		       envelope_schema_version, scrubber_version, endpoint,
		       retention_policy_version, upload_digest, created_at, invalidated_at,
		       grant_mode, data_dictionary_digest, declared_timezone,
		       source_window_rule, review_at, consent_generation, background_generation, evidence_settings_json
		  FROM cloud_consent_receipts WHERE id = ?`, id).
		Scan(&r.ID, &r.AccountPseudonym, &r.DeviceLabelRef, &r.Purpose, &r.FieldClassesJSON,
			&r.EnvelopeSchemaVersion, &r.ScrubberVersion, &r.Endpoint,
			&r.RetentionPolicyVersion, &r.UploadDigest, &createdAt, &invalidatedAt,
			&grantMode, &r.DataDictionaryDigest, &r.DeclaredTimezone,
			&r.SourceWindowRule, &reviewAt, &r.ConsentGeneration, &r.BackgroundGeneration, &r.EvidenceSettingsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudConsentReceipt{}, false, nil
	}
	if err != nil {
		return CloudConsentReceipt{}, false, fmt.Errorf("store.GetCloudConsentReceipt: %w", err)
	}
	r.CreatedAt = cloudParseTime(createdAt)
	if invalidatedAt.Valid && invalidatedAt.String != "" {
		t := cloudParseTime(invalidatedAt.String)
		r.InvalidatedAt = &t
	}
	r.GrantMode = CloudGrantMode(grantMode)
	if reviewAt.Valid && reviewAt.String != "" {
		t := cloudParseTime(reviewAt.String)
		r.ReviewAt = &t
	}
	return r, true, nil
}

// cloudReceiptColumns is the receipt column list every receipt read shares, so
// GetCloudConsentReceipt and the list reads below can never drift apart.
const cloudReceiptColumns = `id, account_pseudonym, device_label_ref, purpose, field_classes_json,
	       envelope_schema_version, scrubber_version, endpoint,
	       retention_policy_version, upload_digest, created_at, invalidated_at,
	       grant_mode, data_dictionary_digest, declared_timezone,
	       source_window_rule, review_at, consent_generation, background_generation, evidence_settings_json`

// scanCloudReceiptRows scans a cloudReceiptColumns result set.
func scanCloudReceiptRows(rows *sql.Rows, pfx string) ([]CloudConsentReceipt, error) {
	var out []CloudConsentReceipt
	for rows.Next() {
		var (
			r             CloudConsentReceipt
			createdAt     string
			invalidatedAt sql.NullString
			grantMode     string
			reviewAt      sql.NullString
		)
		if err := rows.Scan(&r.ID, &r.AccountPseudonym, &r.DeviceLabelRef, &r.Purpose, &r.FieldClassesJSON,
			&r.EnvelopeSchemaVersion, &r.ScrubberVersion, &r.Endpoint,
			&r.RetentionPolicyVersion, &r.UploadDigest, &createdAt, &invalidatedAt,
			&grantMode, &r.DataDictionaryDigest, &r.DeclaredTimezone,
			&r.SourceWindowRule, &reviewAt, &r.ConsentGeneration, &r.BackgroundGeneration, &r.EvidenceSettingsJSON); err != nil {
			return nil, fmt.Errorf("%s: scan: %w", pfx, err)
		}
		r.CreatedAt = cloudParseTime(createdAt)
		if invalidatedAt.Valid && invalidatedAt.String != "" {
			t := cloudParseTime(invalidatedAt.String)
			r.InvalidatedAt = &t
		}
		r.GrantMode = CloudGrantMode(grantMode)
		if reviewAt.Valid && reviewAt.String != "" {
			t := cloudParseTime(reviewAt.String)
			r.ReviewAt = &t
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", pfx, err)
	}
	return out, nil
}

// ListCloudConsentReceipts returns EVERY stored receipt, newest first —
// including invalidated ones, because "what did I ever grant, and when was it
// revoked?" is exactly the question the consent-management surface
// (`observer cloud consent list`) answers. It is content-free: a receipt
// carries purposes, versions, digests and timestamps, never session data.
func (s *Store) ListCloudConsentReceipts(ctx context.Context) ([]CloudConsentReceipt, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+cloudReceiptColumns+`
		  FROM cloud_consent_receipts
		 ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("store.ListCloudConsentReceipts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanCloudReceiptRows(rows, "store.ListCloudConsentReceipts")
}

// ListLiveCloudConsentReceipts returns the receipts that have NOT been
// invalidated, newest first, optionally narrowed to one purpose ("" = every
// purpose). It is the read the consent-gated egress gateway
// (internal/cloudgateway) resolves live grant state from before any feature
// egress.
//
// "Live" here means exactly one thing — not invalidated. Expiry/review_at is
// deliberately NOT applied in SQL: that is a CLOCK policy, and the gateway owns
// the clock (it can be injected in tests, and a single place decides what
// "expired" means). A row this returns is a candidate; the gateway decides.
func (s *Store) ListLiveCloudConsentReceipts(ctx context.Context, purpose string) ([]CloudConsentReceipt, error) {
	query := `SELECT ` + cloudReceiptColumns + `
		  FROM cloud_consent_receipts
		 WHERE COALESCE(invalidated_at, '') = ''`
	args := []any{}
	if purpose != "" {
		query += ` AND purpose = ?`
		args = append(args, purpose)
	}
	query += ` ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListLiveCloudConsentReceipts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanCloudReceiptRows(rows, "store.ListLiveCloudConsentReceipts")
}

// MaxCloudConsentGeneration returns the highest consent_generation recorded for
// a purpose across ALL its receipts, live or invalidated (0 when the purpose has
// none). Counting invalidated receipts too is the point: the generation is a
// monotonic "these terms changed" counter, so revoking and re-granting must
// produce a HIGHER generation, never reuse a retired one — a queued snapshot
// recording generation N must not be silently accepted under a later grant that
// happens to be numbered N again.
func (s *Store) MaxCloudConsentGeneration(ctx context.Context, purpose string) (int, error) {
	if purpose == "" {
		return 0, errors.New("store.MaxCloudConsentGeneration: purpose is required")
	}
	var maxGen int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(consent_generation), 0) FROM cloud_consent_receipts WHERE purpose = ?`,
		purpose).Scan(&maxGen); err != nil {
		return 0, fmt.Errorf("store.MaxCloudConsentGeneration: %w", err)
	}
	return maxGen, nil
}

// StandingGrantReplacement reports what recording a standing grant did to the
// state that preceded it. It is content-free (ids and counts) and exists so the
// CLI can state the consequences rather than performing them silently.
type StandingGrantReplacement struct {
	// ReceiptID is the newly recorded standing receipt.
	ReceiptID string
	// ConsentGeneration is the generation actually allocated inside the
	// transaction — which may differ from any value a caller previewed.
	ConsentGeneration int
	// SupersededReceiptIDs are the previously-live standing receipts for the
	// purpose, now invalidated.
	SupersededReceiptIDs []string
	// RequeuedForReconfirmation is how many non-terminal outbox rows bound to
	// those receipts were moved to reconfirmation_required.
	RequeuedForReconfirmation int
}

// ReplaceStandingConsentGrant records a STANDING grant as the ONE live standing
// grant for its purpose, in a single transaction that:
//
//  1. allocates the consent generation (current max for the purpose, + 1);
//  2. invalidates every other live standing receipt for that purpose;
//  3. moves their non-terminal outbox rows to reconfirmation_required;
//  4. inserts the new receipt.
//
// WHY ONE LIVE RECEIPT PER PURPOSE. With two live standing receipts, a queued
// snapshot stays validly bound to the OLDER one while any path that resolves
// "the newest grant" reads the newer — so bytes built under retired terms could
// ship declaring current terms. Making the re-grant supersede removes the
// ambiguity at the root rather than asking every reader to disambiguate.
//
// WHY RECONFIRMATION, NOT CANCELLATION. The developer re-granting has not
// withdrawn consent; they have changed its terms. Cancelling would silently
// destroy captured windows. reconfirmation_required is the honest state: the
// item is not sendable, and it is visible, so it can be re-bound or re-captured
// under the new grant. (Revoking, which IS a withdrawal, still cancels — see
// CancelCloudOutboxForReceipt.)
//
// GENERATION ALLOCATION happens INSIDE this transaction. The DSN's
// `_txlock=immediate` takes SQLite's write lock at BEGIN, so two concurrent
// grants serialize and cannot both read the same max; migration 099's partial
// UNIQUE index on (purpose, consent_generation) for live-shaped standing rows is
// the backstop that turns any future racy path into a loud failure rather than a
// silent duplicate.
func (s *Store) ReplaceStandingConsentGrant(ctx context.Context, r CloudConsentReceipt) (StandingGrantReplacement, error) {
	const pfx = "store.ReplaceStandingConsentGrant"
	if r.Purpose == "" {
		return StandingGrantReplacement{}, fmt.Errorf("%s: purpose is required", pfx)
	}
	if r.AccountPseudonym == "" {
		return StandingGrantReplacement{}, fmt.Errorf("%s: account pseudonym is required", pfx)
	}
	if r.UploadDigest == "" {
		return StandingGrantReplacement{}, fmt.Errorf("%s: upload digest is required", pfx)
	}
	if r.GrantMode != "" && r.GrantMode != CloudGrantStanding {
		return StandingGrantReplacement{}, fmt.Errorf("%s: grant mode %q is not standing", pfx, r.GrantMode)
	}
	r.GrantMode = CloudGrantStanding
	if r.ID == "" {
		id, err := cloudRandomID("rcpt_")
		if err != nil {
			return StandingGrantReplacement{}, fmt.Errorf("%s: %w", pfx, err)
		}
		r.ID = id
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	if r.FieldClassesJSON == "" {
		r.FieldClassesJSON = "[]"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return StandingGrantReplacement{}, fmt.Errorf("%s: %w", pfx, err)
	}
	defer func() { _ = tx.Rollback() }()

	// 1. Allocate the generation under the write lock this transaction holds.
	var maxGen int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(consent_generation), 0) FROM cloud_consent_receipts WHERE purpose = ?`,
		r.Purpose).Scan(&maxGen); err != nil {
		return StandingGrantReplacement{}, fmt.Errorf("%s: allocate generation: %w", pfx, err)
	}
	out := StandingGrantReplacement{ReceiptID: r.ID, ConsentGeneration: maxGen + 1}

	// 2. Find the live standing receipts this grant supersedes.
	rows, err := tx.QueryContext(ctx, `
		SELECT id FROM cloud_consent_receipts
		 WHERE purpose = ? AND grant_mode = ? AND COALESCE(invalidated_at, '') = ''`,
		r.Purpose, string(CloudGrantStanding))
	if err != nil {
		return StandingGrantReplacement{}, fmt.Errorf("%s: read live standing grants: %w", pfx, err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return StandingGrantReplacement{}, fmt.Errorf("%s: scan: %w", pfx, err)
		}
		out.SupersededReceiptIDs = append(out.SupersededReceiptIDs, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return StandingGrantReplacement{}, fmt.Errorf("%s: %w", pfx, err)
	}
	_ = rows.Close()

	now := cloudFormatTime(time.Now().UTC())
	for _, id := range out.SupersededReceiptIDs {
		if _, err := tx.ExecContext(ctx,
			`UPDATE cloud_consent_receipts SET invalidated_at = ? WHERE id = ? AND invalidated_at IS NULL`,
			now, id); err != nil {
			return StandingGrantReplacement{}, fmt.Errorf("%s: supersede %s: %w", pfx, id, err)
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE cloud_outbox
			   SET state = ?, last_error = 'superseded_by_new_grant', updated_at = ?
			 WHERE receipt_id = ? AND state IN (?, ?, ?)`,
			string(CloudOutboxReconfirmationRequired), now, id,
			string(CloudOutboxPending), string(CloudOutboxFailedRetryable), string(CloudOutboxSending))
		if err != nil {
			return StandingGrantReplacement{}, fmt.Errorf("%s: requeue items of %s: %w", pfx, id, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return StandingGrantReplacement{}, fmt.Errorf("%s: %w", pfx, err)
		}
		out.RequeuedForReconfirmation += int(n)
		// 3b. Cancel the dispatch leases held under the superseded receipt
		// (migration 100, Sol re-review N2). The CLI then waits for those
		// leases to drain — AwaitCloudDispatchQuiescence — OUTSIDE this
		// transaction, so a sender releasing its lease is never blocked behind
		// the write lock this transaction holds.
		if _, err := cancelCloudDispatchLeasesTx(ctx, tx, id, time.Now().UTC()); err != nil {
			return StandingGrantReplacement{}, fmt.Errorf("%s: cancel dispatch leases of %s: %w", pfx, id, err)
		}
	}

	// 4. Insert the new receipt with the generation this transaction allocated.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_consent_receipts
		  (id, account_pseudonym, device_label_ref, purpose, field_classes_json,
		   envelope_schema_version, scrubber_version, endpoint,
		   retention_policy_version, upload_digest, created_at, invalidated_at,
		   grant_mode, data_dictionary_digest, declared_timezone,
		   source_window_rule, review_at, consent_generation)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.AccountPseudonym, r.DeviceLabelRef, r.Purpose, r.FieldClassesJSON,
		r.EnvelopeSchemaVersion, r.ScrubberVersion, r.Endpoint,
		r.RetentionPolicyVersion, r.UploadDigest, cloudFormatTime(r.CreatedAt),
		string(CloudGrantStanding), r.DataDictionaryDigest, r.DeclaredTimezone,
		r.SourceWindowRule, nullableCloudTime(r.ReviewAt), out.ConsentGeneration); err != nil {
		if isUniqueConstraintErr(err) {
			// Migration 099's index fired: another grant for this purpose took the
			// same generation. Say so plainly rather than retrying into a loop —
			// this is an interactive command and a re-run allocates the next one.
			return StandingGrantReplacement{}, fmt.Errorf(
				"%s: consent generation %d for purpose %q was allocated concurrently — nothing was recorded; re-run the grant",
				pfx, out.ConsentGeneration, r.Purpose,
			)
		}
		return StandingGrantReplacement{}, fmt.Errorf("%s: insert receipt: %w", pfx, err)
	}
	if err := tx.Commit(); err != nil {
		return StandingGrantReplacement{}, fmt.Errorf("%s: %w", pfx, err)
	}
	return out, nil
}

// InvalidateCloudConsentReceipt stamps a receipt invalidated (idempotent — a
// re-invalidation keeps the first timestamp). A material change to schema,
// field class, retention, or subprocessors pauses the lane by invalidating the
// receipt (amendment §4.2); CancelCloudOutboxForReceipt then cancels the
// dependent jobs. Missing id is a no-op.
func (s *Store) InvalidateCloudConsentReceipt(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE cloud_consent_receipts
		   SET invalidated_at = ?
		 WHERE id = ? AND invalidated_at IS NULL`,
		cloudFormatTime(time.Now().UTC()), id)
	if err != nil {
		return fmt.Errorf("store.InvalidateCloudConsentReceipt: %w", err)
	}
	return nil
}

// -- Pseudonym mappings ------------------------------------------------------

// GetOrCreateCloudSessionPseudonym returns the random cloud pseudonym for a
// local session id, minting one on first use. The pseudonym is crypto/rand,
// never derived from the local id.
func (s *Store) GetOrCreateCloudSessionPseudonym(ctx context.Context, localSessionID string) (string, error) {
	return s.getOrCreatePseudonym(ctx, "cloud_session_map", "local_session_id", localSessionID, "cs_")
}

// GetOrCreateCloudProjectPseudonym returns the random cloud pseudonym for a
// local project id, minting one on first use.
func (s *Store) GetOrCreateCloudProjectPseudonym(ctx context.Context, localProjectID string) (string, error) {
	return s.getOrCreatePseudonym(ctx, "cloud_project_map", "local_project_id", localProjectID, "cp_")
}

// LookupLocalSessionByCloudPseudonym is the reverse of
// GetOrCreateCloudSessionPseudonym: given a cloud session pseudonym (as
// received on a pulled result's cloud_session_id), it returns the local
// session id this device minted that pseudonym for. It is a read-only lookup
// — unlike getOrCreatePseudonym it never mints, since a pseudonym this device
// doesn't recognize is legitimately unassociable here (e.g. a result for a
// session enrolled from a different device, or a stale pseudonym). ok=false
// on no match is expected, routine behavior, never an error.
func (s *Store) LookupLocalSessionByCloudPseudonym(ctx context.Context, cloudSessionID string) (string, bool, error) {
	if cloudSessionID == "" {
		return "", false, nil
	}
	var localSessionID string
	err := s.db.QueryRowContext(ctx,
		`SELECT local_session_id FROM cloud_session_map WHERE cloud_pseudonym = ?`,
		cloudSessionID).Scan(&localSessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store.LookupLocalSessionByCloudPseudonym: %w", err)
	}
	return localSessionID, true, nil
}

// getOrCreatePseudonym is the shared get-or-create for the two mapping tables.
// The table/column names are internal constants (never caller input), so the
// fmt.Sprintf into the query is not an injection surface.
func (s *Store) getOrCreatePseudonym(ctx context.Context, table, keyCol, localID, prefix string) (string, error) {
	if localID == "" {
		return "", fmt.Errorf("store.getOrCreatePseudonym: local id is required")
	}
	var pseudonym string
	err := s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT cloud_pseudonym FROM %s WHERE %s = ?`, table, keyCol), localID).
		Scan(&pseudonym)
	switch {
	case err == nil:
		return pseudonym, nil
	case !errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("store.getOrCreatePseudonym: %w", err)
	}
	// Mint a random pseudonym. INSERT OR IGNORE + re-select closes the race
	// where two callers mint for the same local id concurrently: the loser's
	// insert is ignored and it reads the winner's pseudonym.
	minted, err := cloudRandomID(prefix)
	if err != nil {
		return "", fmt.Errorf("store.getOrCreatePseudonym: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		fmt.Sprintf(`INSERT OR IGNORE INTO %s (%s, cloud_pseudonym, created_at) VALUES (?, ?, ?)`, table, keyCol),
		localID, minted, cloudFormatTime(time.Now().UTC()))
	if err != nil {
		return "", fmt.Errorf("store.getOrCreatePseudonym: %w", err)
	}
	err = s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT cloud_pseudonym FROM %s WHERE %s = ?`, table, keyCol), localID).
		Scan(&pseudonym)
	if err != nil {
		return "", fmt.Errorf("store.getOrCreatePseudonym: %w", err)
	}
	return pseudonym, nil
}

// -- Outbox ------------------------------------------------------------------

// EnqueueCloudOutbox enqueues one send job in the pending state. It REFUSES
// (ErrCloudSessionIneligible) any session not eligible for personal-cloud
// enrichment — the check delegates to EligibleForPersonalCloud so the
// data-authority contract stays the one source of truth. It also refuses a
// missing/invalidated receipt and a digest incoherent with that receipt.
// item.ID/State/RetryCount/timestamps are set by the store; the returned id is
// the minted outbox id.
func (s *Store) EnqueueCloudOutbox(ctx context.Context, item CloudOutboxItem) (string, error) {
	if item.SessionID == "" {
		return "", errors.New("store.EnqueueCloudOutbox: session id is required")
	}
	if item.ReceiptID == "" {
		return "", errors.New("store.EnqueueCloudOutbox: receipt id is required")
	}
	if item.EvidenceContentDigest == "" || item.UploadDigest == "" {
		return "", errors.New("store.EnqueueCloudOutbox: both digests are required")
	}
	// Eligibility gate (plan §7 invariant 3): org / unknown / missing sessions
	// never reach personal cloud paths.
	eligible, err := s.EligibleForPersonalCloud(ctx, item.SessionID)
	if err != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
	}
	if !eligible {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", ErrCloudSessionIneligible)
	}
	// Receipt must exist, be live, and bind the same upload digest (coherence
	// at enqueue).
	rcpt, ok, err := s.GetCloudConsentReceipt(ctx, item.ReceiptID)
	if err != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
	}
	if !ok {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", ErrCloudReceiptNotFound)
	}
	if rcpt.InvalidatedAt != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w: receipt is invalidated", ErrCloudReconfirmationRequired)
	}
	if item.UploadDigest != rcpt.UploadDigest {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", ErrCloudReceiptDigestMismatch)
	}
	if item.ID == "" {
		id, err := cloudRandomID("job_")
		if err != nil {
			return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
		}
		item.ID = id
	}
	featureSet := item.FeatureSetJSON
	if featureSet == "" {
		featureSet = "[]"
	}
	now := time.Now().UTC()
	// Duplicate guard and insert in ONE transaction: two processes (the
	// daemon's auto-enrich sweep and the dashboard's "Enrich now" both spawn
	// `observer cloud consent`) racing on the same session serialize on the
	// SQLite write lock, so the loser sees the winner's row and refuses.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var dup int
	if err := tx.QueryRowContext(
		ctx, `
		SELECT COUNT(1) FROM cloud_outbox
		 WHERE session_id = ? AND upload_digest = ? AND state IN (?, ?, ?)`,
		item.SessionID, item.UploadDigest,
		string(CloudOutboxPending), string(CloudOutboxSending), string(CloudOutboxFailedRetryable),
	).Scan(&dup); err != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
	}
	if dup > 0 {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", ErrCloudOutboxDuplicate)
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_outbox
		  (id, session_id, feature_set_json, evidence_content_digest, upload_digest,
		   receipt_id, state, retry_count, last_error, created_at, updated_at)
		SELECT ?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?
        WHERE EXISTS (SELECT 1 FROM cloud_consent_receipts WHERE id = ? AND invalidated_at IS NULL)`,
		item.ID, item.SessionID, featureSet, item.EvidenceContentDigest, item.UploadDigest,
		item.ReceiptID, string(CloudOutboxPending), cloudFormatTime(now), cloudFormatTime(now), item.ReceiptID)
	if err != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", ErrCloudReconfirmationRequired)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store.EnqueueCloudOutbox: %w", err)
	}
	return item.ID, nil
}

// FindLiveCloudOutboxForUpload returns the newest in-flight (pending / sending
// / failed_retryable) outbox item for a session whose upload bytes are exactly
// uploadDigest; ok=false when none. It is the read half of EnqueueCloudOutbox's
// duplicate guard, so a caller can report the job that already carries the
// bytes instead of minting a second receipt.
func (s *Store) FindLiveCloudOutboxForUpload(ctx context.Context, sessionID, uploadDigest string) (CloudOutboxItem, bool, error) {
	if sessionID == "" || uploadDigest == "" {
		return CloudOutboxItem{}, false, errors.New("store.FindLiveCloudOutboxForUpload: session id and upload digest are required")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, session_id, feature_set_json, evidence_content_digest, upload_digest,
		       receipt_id, state, retry_count, last_error, created_at, updated_at
		  FROM cloud_outbox
		 WHERE session_id = ? AND upload_digest = ? AND state IN (?, ?, ?)
		 ORDER BY created_at DESC, id DESC
		 LIMIT 1`,
		sessionID, uploadDigest,
		string(CloudOutboxPending), string(CloudOutboxSending), string(CloudOutboxFailedRetryable))
	if err != nil {
		return CloudOutboxItem{}, false, fmt.Errorf("store.FindLiveCloudOutboxForUpload: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items, err := scanCloudOutboxRows(rows, "store.FindLiveCloudOutboxForUpload")
	if err != nil {
		return CloudOutboxItem{}, false, err
	}
	if len(items) == 0 {
		return CloudOutboxItem{}, false, nil
	}
	return items[0], true, nil
}

// GetCloudOutbox loads an outbox item by id. ok=false means it does not exist.
func (s *Store) GetCloudOutbox(ctx context.Context, id string) (CloudOutboxItem, bool, error) {
	var (
		it                 CloudOutboxItem
		kind               string
		state              string
		createdAt, updated string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, kind, session_id, feature_set_json, evidence_content_digest, upload_digest,
		       receipt_id, state, retry_count, last_error, created_at, updated_at
		  FROM cloud_outbox WHERE id = ?`, id).
		Scan(&it.ID, &kind, &it.SessionID, &it.FeatureSetJSON, &it.EvidenceContentDigest, &it.UploadDigest,
			&it.ReceiptID, &state, &it.RetryCount, &it.LastError, &createdAt, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudOutboxItem{}, false, nil
	}
	if err != nil {
		return CloudOutboxItem{}, false, fmt.Errorf("store.GetCloudOutbox: %w", err)
	}
	it.Kind = CloudOutboxKind(kind)
	it.State = CloudOutboxState(state)
	it.CreatedAt = cloudParseTime(createdAt)
	it.UpdatedAt = cloudParseTime(updated)
	return it, true, nil
}

// PrepareCloudOutboxSend is THE reconfirmation rule (plan §6 CI-P1 /
// §7 invariant 4), hardened for FD1 (endpoint binding) and FD3 (atomic
// re-verify). sendEndpoint is the immutable absolute URL the client will POST
// to (client.UploadEndpoint()); it MUST equal the endpoint the consent receipt
// bound, or the send is refused (ErrCloudEndpointMismatch, reconfirmation
// required) — confirmed evidence can only ever reach the approved origin+path.
//
// It rebuilds the envelope ONCE, compares BOTH digests against the stored
// outbox value AND the bound receipt's confirmed upload digest, then — in ONE
// transaction (the DSN's _txlock=immediate holds the write lock from BEGIN) —
// RE-READS eligibility, receipt validity, endpoint and digests and CASes to
// `sending`. The re-read closes the race where the receipt is invalidated or
// the session is upgraded to org DURING the rebuild: such a change makes the
// atomic re-verify fail and the item moves to reconfirmation_required instead
// of sending. The returned CloudSendLease lets the caller re-verify once more
// immediately before HTTP dispatch (VerifyCloudSendAuthorization).
//
// Outcomes:
//   - authorized  -> `sending`, rebuilt bytes + lease returned;
//   - digest/endpoint mismatch, invalidated receipt, or org/ineligible session
//     -> `reconfirmation_required` and a typed error.
//
// It NEVER auto-updates the stored digests and NEVER auto-sends a mismatch.
// Only `pending` and `failed_retryable` items are preparable.
func (s *Store) PrepareCloudOutboxSend(ctx context.Context, id, sendEndpoint string, rebuild EnvelopeRebuild) ([]byte, CloudSendLease, error) {
	if rebuild == nil {
		return nil, CloudSendLease{}, errors.New("store.PrepareCloudOutboxSend: rebuild func is required")
	}
	item, ok, err := s.GetCloudOutbox(ctx, id)
	if err != nil {
		return nil, CloudSendLease{}, err
	}
	if !ok {
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w", ErrCloudOutboxNotFound)
	}
	// This path is session-evidence ONLY: it rebuilds an envelope from a live
	// session and compares digests. A structural snapshot has no session to
	// rebuild from — its stored bytes ARE the artifact — so routing one here
	// would either fail obscurely or, worse, re-aggregate. Refuse explicitly.
	if item.Kind != CloudOutboxKindSessionEvidence {
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w: kind %q — use PrepareStructuralSend", ErrCloudOutboxKindMismatch, item.Kind)
	}
	if item.State != CloudOutboxPending && item.State != CloudOutboxFailedRetryable {
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w: state %q is not preparable", ErrIllegalCloudOutboxTransition, item.State)
	}
	rcpt, ok, err := s.GetCloudConsentReceipt(ctx, item.ReceiptID)
	if err != nil {
		return nil, CloudSendLease{}, err
	}
	if !ok {
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w", ErrCloudReceiptNotFound)
	}
	// An invalidated receipt is a material change: reconfirmation required.
	if rcpt.InvalidatedAt != nil {
		if err := s.moveCloudOutbox(ctx, id, preparableStates(), CloudOutboxReconfirmationRequired, false, "receipt_invalidated"); err != nil {
			return nil, CloudSendLease{}, err
		}
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w", ErrCloudReconfirmationRequired)
	}
	// FD1: the send target must equal the endpoint the receipt bound.
	normSend := normalizeCloudEndpoint(sendEndpoint)
	if normSend == "" || normSend != normalizeCloudEndpoint(rcpt.Endpoint) {
		if err := s.moveCloudOutbox(ctx, id, preparableStates(), CloudOutboxReconfirmationRequired, false, "endpoint_mismatch"); err != nil {
			return nil, CloudSendLease{}, err
		}
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w: bound %q, send %q", ErrCloudEndpointMismatch, rcpt.Endpoint, sendEndpoint)
	}
	// Rebuild ONCE.
	uploadBytes, evDigest, upDigest, err := rebuild(ctx)
	if err != nil {
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: rebuild: %w", err)
	}
	// Compare BOTH digests against the stored outbox values AND the receipt's
	// confirmed upload digest. Any mismatch => reconfirmation required.
	if evDigest != item.EvidenceContentDigest || upDigest != item.UploadDigest || upDigest != rcpt.UploadDigest {
		if err := s.moveCloudOutbox(ctx, id, preparableStates(), CloudOutboxReconfirmationRequired, false, "digest_mismatch"); err != nil {
			return nil, CloudSendLease{}, err
		}
		return nil, CloudSendLease{}, fmt.Errorf("store.PrepareCloudOutboxSend: %w", ErrCloudReconfirmationRequired)
	}
	// FD3: atomically RE-READ authorization and CAS to `sending` in one
	// transaction. Authorization can have changed during the rebuild (a
	// concurrent InvalidateCloudConsentReceipt or a personal->org upgrade); the
	// re-read catches it and refuses the transition.
	if err := s.prepareSendCAS(ctx, item, normSend); err != nil {
		if errors.Is(err, ErrCloudReconfirmationRequired) {
			if merr := s.moveCloudOutbox(ctx, id, preparableStates(), CloudOutboxReconfirmationRequired, false, "authorization_changed"); merr != nil {
				return nil, CloudSendLease{}, merr
			}
		}
		return nil, CloudSendLease{}, err
	}
	return uploadBytes, CloudSendLease{
		OutboxID:     item.ID,
		ReceiptID:    item.ReceiptID,
		SessionID:    item.SessionID,
		UploadDigest: item.UploadDigest,
		Endpoint:     normSend,
	}, nil
}

// prepareSendCAS re-reads eligibility + receipt validity/endpoint/digest inside
// one immediate transaction and CASes the item pending/failed_retryable ->
// sending. A changed authorization returns ErrCloudReconfirmationRequired (the
// caller moves the row to reconfirmation_required); a lost preparable state
// returns ErrIllegalCloudOutboxTransition.
func (s *Store) prepareSendCAS(ctx context.Context, item CloudOutboxItem, normSend string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// State still preparable?
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM cloud_outbox WHERE id = ?`, item.ID).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store.prepareSendCAS: %w", ErrCloudOutboxNotFound)
		}
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	}
	if CloudOutboxState(state) != CloudOutboxPending && CloudOutboxState(state) != CloudOutboxFailedRetryable {
		return fmt.Errorf("store.prepareSendCAS: %w: state %q is not preparable", ErrIllegalCloudOutboxTransition, state)
	}

	// Receipt still live, same endpoint, same upload digest?
	var (
		invalidatedAt sql.NullString
		upDigest      string
		endpoint      string
	)
	if err := tx.QueryRowContext(ctx,
		`SELECT invalidated_at, upload_digest, endpoint FROM cloud_consent_receipts WHERE id = ?`, item.ReceiptID).
		Scan(&invalidatedAt, &upDigest, &endpoint); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store.prepareSendCAS: %w: receipt gone", ErrCloudReconfirmationRequired)
		}
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	}
	if invalidatedAt.Valid && invalidatedAt.String != "" {
		return fmt.Errorf("store.prepareSendCAS: %w: receipt invalidated", ErrCloudReconfirmationRequired)
	}
	if upDigest != item.UploadDigest || normalizeCloudEndpoint(endpoint) != normSend {
		return fmt.Errorf("store.prepareSendCAS: %w: receipt drift", ErrCloudReconfirmationRequired)
	}

	// Session still eligible for personal enrichment (not upgraded to org)?
	if elig, err := sessionEligibleTx(ctx, tx, item.SessionID); err != nil {
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	} else if !elig {
		return fmt.Errorf("store.prepareSendCAS: %w: session no longer personal-eligible", ErrCloudReconfirmationRequired)
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE cloud_outbox SET state = ?, last_error = '', updated_at = ?
		  WHERE id = ? AND state IN (?, ?)`,
		string(CloudOutboxSending), cloudFormatTime(time.Now().UTC()), item.ID,
		string(CloudOutboxPending), string(CloudOutboxFailedRetryable))
	if err != nil {
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store.prepareSendCAS: %w: state changed under the CAS", ErrIllegalCloudOutboxTransition)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.prepareSendCAS: %w", err)
	}
	return nil
}

// sessionEligibleTx reads a session's stored authority through tx and delegates
// the eligibility decision to the pure dataauthority contract (the single
// source of truth). A NULL/missing authority is ineligible (fail closed).
func sessionEligibleTx(ctx context.Context, tx *sql.Tx, sessionID string) (bool, error) {
	var auth sql.NullString
	var ver sql.NullInt64
	err := tx.QueryRowContext(ctx,
		`SELECT authority, authority_classifier_version FROM sessions WHERE id = ?`, sessionID).Scan(&auth, &ver)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !auth.Valid || auth.String == "" {
		return false, nil
	}
	c := dataauthority.Classification{Authority: dataauthority.Authority(auth.String), Version: int(ver.Int64)}
	return c.EligibleForPersonalEnrichment(), nil
}

// VerifyCloudSendAuthorization is the final pre-dispatch check (FD3): called
// immediately before the HTTP upload, it re-reads the receipt validity/endpoint/
// digest and the session eligibility captured in the lease. If anything changed
// (receipt invalidated, session upgraded to org, endpoint/digest drift) it moves
// the item OUT of `sending` back to reconfirmation_required and returns
// ErrCloudSendUnauthorized so the transport aborts without sending. nil means
// still authorized.
func (s *Store) VerifyCloudSendAuthorization(ctx context.Context, lease CloudSendLease) error {
	unauthorized := func(reason string) error {
		if err := s.moveCloudOutbox(ctx, lease.OutboxID, []CloudOutboxState{CloudOutboxSending}, CloudOutboxReconfirmationRequired, false, "send_unauthorized"); err != nil {
			return err
		}
		return fmt.Errorf("store.VerifyCloudSendAuthorization: %w: %s", ErrCloudSendUnauthorized, reason)
	}
	rcpt, ok, err := s.GetCloudConsentReceipt(ctx, lease.ReceiptID)
	if err != nil {
		return err
	}
	if !ok {
		return unauthorized("receipt gone")
	}
	if rcpt.InvalidatedAt != nil {
		return unauthorized("receipt invalidated")
	}
	if rcpt.UploadDigest != lease.UploadDigest || normalizeCloudEndpoint(rcpt.Endpoint) != lease.Endpoint {
		return unauthorized("receipt drift")
	}
	elig, err := s.EligibleForPersonalCloud(ctx, lease.SessionID)
	if err != nil {
		return err
	}
	if !elig {
		return unauthorized("session no longer personal-eligible")
	}
	return nil
}

// normalizeCloudEndpoint reduces an endpoint URL to a comparable origin+path:
// lowercased scheme+host, default ports dropped, cleaned path, query/fragment
// ignored. A URL that does not parse, or lacks scheme/host, normalizes to "" so
// it can never match a real endpoint (fail closed for FD1).
func normalizeCloudEndpoint(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme == "" || host == "" {
		return ""
	}
	if port := u.Port(); port != "" {
		if !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
			host = host + ":" + port
		}
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	} else {
		p = path.Clean(p)
	}
	return scheme + "://" + host + p
}

// MarkCloudOutboxSent transitions a sending item to sent (terminal success).
func (s *Store) MarkCloudOutboxSent(ctx context.Context, id string) error {
	return s.moveCloudOutbox(ctx, id, []CloudOutboxState{CloudOutboxSending}, CloudOutboxSent, false, "")
}

// MarkCloudOutboxRetryable transitions a sending item to failed_retryable,
// increments retry_count, and records the content-free error CLASS string.
func (s *Store) MarkCloudOutboxRetryable(ctx context.Context, id, errClass string) error {
	return s.moveCloudOutbox(ctx, id, []CloudOutboxState{CloudOutboxSending}, CloudOutboxFailedRetryable, true, errClass)
}

// MarkCloudOutboxTerminal transitions a sending or failed_retryable item to
// failed_terminal and records the content-free error CLASS string.
func (s *Store) MarkCloudOutboxTerminal(ctx context.Context, id, errClass string) error {
	return s.moveCloudOutbox(ctx, id, []CloudOutboxState{CloudOutboxSending, CloudOutboxFailedRetryable}, CloudOutboxFailedTerminal, false, errClass)
}

// MarkCloudOutboxReconfirmation transitions a sending item back to
// reconfirmation_required and records the content-free error CLASS string. It is
// the correct landing for a SERVER refusal of the exact bytes
// (reconfirmation_required): the developer re-previews and re-consents (via
// ReconfirmCloudOutbox), rather than the item burning as a terminal failure.
func (s *Store) MarkCloudOutboxReconfirmation(ctx context.Context, id, errClass string) error {
	return s.moveCloudOutbox(ctx, id, []CloudOutboxState{CloudOutboxSending}, CloudOutboxReconfirmationRequired, false, errClass)
}

// ReconfirmCloudOutbox is the ONLY digest-updating transition, and it is
// explicit and developer-driven (never automatic): a reconfirmation_required
// item, once the developer has re-previewed and confirmed a new receipt, moves
// back to pending with its bound receipt and both digests updated. The new
// receipt must exist, be live, and bind newUploadDigest (coherence).
func (s *Store) ReconfirmCloudOutbox(ctx context.Context, id, newReceiptID, newEvidenceDigest, newUploadDigest string) error {
	if newReceiptID == "" || newEvidenceDigest == "" || newUploadDigest == "" {
		return errors.New("store.ReconfirmCloudOutbox: new receipt id and both digests are required")
	}
	rcpt, ok, err := s.GetCloudConsentReceipt(ctx, newReceiptID)
	if err != nil {
		return fmt.Errorf("store.ReconfirmCloudOutbox: %w", err)
	}
	if !ok {
		return fmt.Errorf("store.ReconfirmCloudOutbox: %w", ErrCloudReceiptNotFound)
	}
	if rcpt.InvalidatedAt != nil {
		return fmt.Errorf("store.ReconfirmCloudOutbox: %w: new receipt is invalidated", ErrCloudReconfirmationRequired)
	}
	if newUploadDigest != rcpt.UploadDigest {
		return fmt.Errorf("store.ReconfirmCloudOutbox: %w", ErrCloudReceiptDigestMismatch)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE cloud_outbox
		   SET state = ?, receipt_id = ?, evidence_content_digest = ?, upload_digest = ?,
		       last_error = '', updated_at = ?
		 WHERE id = ? AND state = ?`,
		string(CloudOutboxPending), newReceiptID, newEvidenceDigest, newUploadDigest,
		cloudFormatTime(time.Now().UTC()), id, string(CloudOutboxReconfirmationRequired))
	if err != nil {
		return fmt.Errorf("store.ReconfirmCloudOutbox: %w", err)
	}
	return s.checkTransitionApplied(ctx, id, res, CloudOutboxReconfirmationRequired, CloudOutboxPending)
}

// CancelForReceipt cancels every non-terminal outbox item bound to receiptID
// (consent revocation / material receipt change). pending,
// reconfirmation_required, failed_retryable AND in-flight `sending` items move
// to cancelled (FD3: a revoked receipt must also cancel a row that a sync loop
// already moved to sending — the idempotency key makes an ambiguous prior
// delivery safe, and VerifyCloudSendAuthorization aborts the dispatch before it
// leaves the machine). Already-terminal (sent/failed_terminal/cancelled) items
// are left untouched. Returns the number cancelled.
func (s *Store) CancelCloudOutboxForReceipt(ctx context.Context, receiptID string) (int, error) {
	if receiptID == "" {
		return 0, errors.New("store.CancelCloudOutboxForReceipt: receipt id is required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE cloud_outbox
		   SET state = ?, updated_at = ?
		 WHERE receipt_id = ? AND state IN (?, ?, ?, ?)`,
		string(CloudOutboxCancelled), cloudFormatTime(time.Now().UTC()), receiptID,
		string(CloudOutboxPending), string(CloudOutboxReconfirmationRequired),
		string(CloudOutboxFailedRetryable), string(CloudOutboxSending))
	if err != nil {
		return 0, fmt.Errorf("store.CancelCloudOutboxForReceipt: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store.CancelCloudOutboxForReceipt: %w", err)
	}
	return int(n), nil
}

// ReclaimStaleCloudSending resets outbox items stuck in `sending` since before
// olderThan back to failed_retryable so a later sync retries them (FD4). A
// crash/kill/restart after the transition to sending but before a mark
// operation would otherwise strand the item forever — ListSendableCloudOutbox
// excludes `sending`. The idempotency key (client.Upload) makes a retry of an
// ambiguously-delivered upload safe. `observer cloud sync` calls this at
// startup with a conservative lease age. Returns the number reclaimed.
func (s *Store) ReclaimStaleCloudSending(ctx context.Context, olderThan time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE cloud_outbox
		   SET state = ?, last_error = 'reclaimed_stale_sending', updated_at = ?
		 WHERE state = ? AND updated_at <= ?`,
		string(CloudOutboxFailedRetryable), cloudFormatTime(time.Now().UTC()),
		string(CloudOutboxSending), cloudFormatTime(olderThan.UTC()))
	if err != nil {
		return 0, fmt.Errorf("store.ReclaimStaleCloudSending: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store.ReclaimStaleCloudSending: %w", err)
	}
	return int(n), nil
}

// preparableStates is the from-set for PrepareCloudOutboxSend transitions.
func preparableStates() []CloudOutboxState {
	return []CloudOutboxState{CloudOutboxPending, CloudOutboxFailedRetryable}
}

// moveCloudOutbox is the single guarded state-transition primitive: it moves
// item id from any of `from` to `to` in one UPDATE, optionally incrementing
// retry_count and recording a content-free error class. A zero-row result is
// disambiguated into ErrCloudOutboxNotFound vs ErrIllegalCloudOutboxTransition.
func (s *Store) moveCloudOutbox(ctx context.Context, id string, from []CloudOutboxState, to CloudOutboxState, incRetry bool, errClass string) error {
	if len(from) == 0 {
		return errors.New("store.moveCloudOutbox: empty from-set")
	}
	placeholders := make([]string, len(from))
	args := make([]any, 0, len(from)+4)
	args = append(args, string(to), errClass, cloudFormatTime(time.Now().UTC()))
	for i, st := range from {
		placeholders[i] = "?"
		_ = st // appended below in a second pass to keep arg order clear
	}
	retryClause := ""
	if incRetry {
		retryClause = ", retry_count = retry_count + 1"
	}
	// WHERE args: id then the from-states.
	args = append(args, id)
	for _, st := range from {
		args = append(args, string(st))
	}
	//nolint:gosec // G201: retryClause is a fixed in-function literal and placeholders is a "?, ?" list; every value binds via ?.
	query := fmt.Sprintf(`
		UPDATE cloud_outbox
		   SET state = ?, last_error = ?, updated_at = ?%s
		 WHERE id = ? AND state IN (%s)`,
		retryClause, strings.Join(placeholders, ", "))
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("store.moveCloudOutbox: %w", err)
	}
	return s.checkTransitionApplied(ctx, id, res, from[0], to)
}

// checkTransitionApplied turns a zero-row UPDATE into a typed error: if the row
// does not exist it is ErrCloudOutboxNotFound, otherwise the current state did
// not permit the transition (ErrIllegalCloudOutboxTransition).
func (s *Store) checkTransitionApplied(ctx context.Context, id string, res sql.Result, _ CloudOutboxState, to CloudOutboxState) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store.checkTransitionApplied: %w", err)
	}
	if n > 0 {
		return nil
	}
	cur, ok, err := s.GetCloudOutbox(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("store.checkTransitionApplied: %w", ErrCloudOutboxNotFound)
	}
	return fmt.Errorf("store.checkTransitionApplied: %w: cannot move %q -> %q", ErrIllegalCloudOutboxTransition, cur.State, to)
}

// -- Results + overrides -----------------------------------------------------

// UpsertCloudResult stores a validated enrichment result for a session. If a
// prior newest result exists for the session it is marked superseded_by the new
// row (a regeneration). If r.ID is empty a random id is minted; the id is
// returned.
func (s *Store) UpsertCloudResult(ctx context.Context, r CloudResult) (string, error) {
	if r.SessionID == "" {
		return "", errors.New("store.UpsertCloudResult: session id is required")
	}
	if r.ResultJSON == "" {
		return "", errors.New("store.UpsertCloudResult: result json is required")
	}
	if r.ID == "" {
		id, err := cloudRandomID("res_")
		if err != nil {
			return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
		}
		r.ID = id
	}
	if r.ReceivedAt.IsZero() {
		r.ReceivedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Find the current newest (non-superseded) result for this session so we
	// can chain it. Excludes the row we're about to insert.
	var priorID string
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM cloud_results
		 WHERE session_id = ? AND superseded_by IS NULL AND id <> ?`,
		r.SessionID, r.ID).Scan(&priorID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		priorID = ""
	case err != nil:
		return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO cloud_results
		  (id, session_id, schema_version, result_json, model_route, prompt_hash,
		   tokens, cost_usd, received_at, superseded_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		ON CONFLICT(id) DO UPDATE SET
		  session_id     = excluded.session_id,
		  schema_version = excluded.schema_version,
		  result_json    = excluded.result_json,
		  model_route    = excluded.model_route,
		  prompt_hash    = excluded.prompt_hash,
		  tokens         = excluded.tokens,
		  cost_usd       = excluded.cost_usd,
		  received_at    = excluded.received_at`,
		r.ID, r.SessionID, r.SchemaVersion, r.ResultJSON, r.Provenance.ModelRoute,
		r.Provenance.PromptHash, r.Provenance.Tokens, r.Provenance.CostUSD,
		cloudFormatTime(r.ReceivedAt))
	if err != nil {
		return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
	}
	if priorID != "" {
		if _, err := tx.ExecContext(ctx,
			`UPDATE cloud_results SET superseded_by = ? WHERE id = ?`, r.ID, priorID); err != nil {
			return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store.UpsertCloudResult: %w", err)
	}
	return r.ID, nil
}

// SetCloudResultOverride records (or replaces) a user edit over a result field.
// User edits are keyed by (result_id, field); the value always wins on read.
func (s *Store) SetCloudResultOverride(ctx context.Context, resultID, field, userValue string) error {
	if resultID == "" || field == "" {
		return errors.New("store.SetCloudResultOverride: result id and field are required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cloud_result_overrides (result_id, field, user_value, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(result_id, field) DO UPDATE SET
		  user_value = excluded.user_value,
		  updated_at = excluded.updated_at`,
		resultID, field, userValue, cloudFormatTime(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("store.SetCloudResultOverride: %w", err)
	}
	return nil
}

// GetCloudSessionResult returns the newest (non-superseded) result for a
// session together with the effective per-field overrides. Override handling
// honors two rules (plan §6 CI-P5): the user edit always wins, and a
// regenerated result never clobbers an override — overrides are aggregated
// across ALL of the session's results (latest updated_at per field wins), so an
// override bound to a now-superseded result still applies to its replacement.
// ok=false means the session has no result.
func (s *Store) GetCloudSessionResult(ctx context.Context, sessionID string) (CloudResult, map[string]CloudResultOverride, bool, error) {
	var (
		r            CloudResult
		receivedAt   string
		supersededBy sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, session_id, schema_version, result_json, model_route, prompt_hash,
		       tokens, cost_usd, received_at, superseded_by
		  FROM cloud_results
		 WHERE session_id = ? AND superseded_by IS NULL
		 ORDER BY received_at DESC, id DESC
		 LIMIT 1`, sessionID).
		Scan(&r.ID, &r.SessionID, &r.SchemaVersion, &r.ResultJSON, &r.Provenance.ModelRoute,
			&r.Provenance.PromptHash, &r.Provenance.Tokens, &r.Provenance.CostUSD,
			&receivedAt, &supersededBy)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudResult{}, nil, false, nil
	}
	if err != nil {
		return CloudResult{}, nil, false, fmt.Errorf("store.GetCloudSessionResult: %w", err)
	}
	r.ReceivedAt = cloudParseTime(receivedAt)
	if supersededBy.Valid && supersededBy.String != "" {
		v := supersededBy.String
		r.SupersededBy = &v
	}

	// Aggregate overrides across every result of this session, keeping the
	// latest per field. A regeneration cannot clobber a user edit this way.
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.field, o.user_value, o.updated_at
		  FROM cloud_result_overrides o
		  JOIN cloud_results cr ON cr.id = o.result_id
		 WHERE cr.session_id = ?`, sessionID)
	if err != nil {
		return CloudResult{}, nil, false, fmt.Errorf("store.GetCloudSessionResult: %w", err)
	}
	defer func() { _ = rows.Close() }()
	overrides := map[string]CloudResultOverride{}
	for rows.Next() {
		var field, val, updated string
		if err := rows.Scan(&field, &val, &updated); err != nil {
			return CloudResult{}, nil, false, fmt.Errorf("store.GetCloudSessionResult: %w", err)
		}
		o := CloudResultOverride{Field: field, UserValue: val, UpdatedAt: cloudParseTime(updated)}
		if prev, ok := overrides[field]; !ok || o.UpdatedAt.After(prev.UpdatedAt) {
			overrides[field] = o
		}
	}
	if err := rows.Err(); err != nil {
		return CloudResult{}, nil, false, fmt.Errorf("store.GetCloudSessionResult: %w", err)
	}
	if len(overrides) == 0 {
		overrides = nil
	}
	return r, overrides, true, nil
}

// nullableCloudTime renders an optional time as a nullable stored stamp.
func nullableCloudTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return cloudFormatTime(*t)
}

// -- CI-P2 Lane E CLI reads --------------------------------------------------
//
// These are node-local reads the `observer cloud` CLI composes; SQL stays in
// this store seam (module boundary — cmd/observer holds no SQL). None of them
// import the pure cloud contract/builder packages or the network lane, and
// none touch the org-push wire.

// cloudResultCursorKey is the schema_meta key PREFIX holding the opaque
// results-pull cursor `observer cloud sync` advances (a tiny node-local
// singleton per cloud host; the results themselves are rows in cloud_results).
//
// Since 2026-09-15 the cursor is keyed by the cloud HOST it was minted
// against ("cloud_results_cursor:<host>"): the hosted per-account results
// sequence is per estate, so a node that once synced against staging and
// then pointed at production would otherwise carry staging's cursor (say 6)
// into production, where the first result is seq 1, and never pull a
// production result. The bare legacy key is deliberately NOT read as a
// fallback - its value is ambiguous - so a node starts a fresh pull per host
// (idempotent: cloud_results upserts by result id).
const cloudResultCursorKey = "cloud_results_cursor" //nolint:gosec // G101: schema_meta cursor key name, not a credential.

// cloudResultCursorKeyFor returns the per-host schema_meta key; an empty host
// selects the bare legacy key (tests / callers with no resolved base URL).
func cloudResultCursorKeyFor(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return cloudResultCursorKey
	}
	return cloudResultCursorKey + ":" + host
}

// CloudActionFact is one raw, node-local action fact the CLI maps into a
// cloudevidence.ActionInput. Target is the real local target (a path for file
// actions, the COMMAND STRING for run_command); the pure layer turns it into a
// closed-vocabulary label and never lets it leave the machine.
type CloudActionFact struct {
	// Ref is the action's ORIGINAL 0-based position in the whole session, so a
	// sampled envelope's ref gaps honestly show that sampling happened.
	Ref         string
	Kind        string
	Success     bool
	Target      string
	RawToolName string
	Timestamp   time.Time
}

// CloudKindCount is one whole-session action-kind count.
type CloudKindCount struct {
	Kind  string
	Count int
}

// CloudSessionMetrics is the deterministic numeric substrate of a session:
// summed token usage plus the session row's own recorded scores. All of it is
// already-aggregated counts — no content.
type CloudSessionMetrics struct {
	// TokensIn is SUM(token_usage.input_tokens). Adapters emit NET input (the
	// cached portion lives in CacheReadTokens), so this needs no further
	// netting here — see internal/intelligence/cost's TokenBundle contract.
	TokensIn int
	// TokensOut is SUM(token_usage.output_tokens).
	TokensOut int
	// CacheReadTokens is SUM(token_usage.cache_read_tokens).
	CacheReadTokens int
	// CacheCreationTokens is SUM(token_usage.cache_creation_tokens).
	CacheCreationTokens int
	// ReasoningTokens is SUM(token_usage.reasoning_tokens).
	ReasoningTokens int
	// CostUSD is SUM(token_usage.estimated_cost_usd) + SUM(api_turns.cost_usd).
	// It is 0 for the many adapters that record no per-turn cost; the caller
	// decides whether to fall back to a priced estimate.
	CostUSD float64
	// RecordedRows is how many token_usage rows the sums covered (0 ⇒ the
	// session carried no billable usage at all).
	RecordedRows int
	// QualityScore / RedundancyRatio / ErrorRate come from the sessions row and
	// are 0 when it never recorded them (the common case).
	QualityScore    float64
	RedundancyRatio float64
	ErrorRate       float64
	// Turns is the PER-ROW token substrate, in time order: one entry per
	// token_usage row with that row's OWN model, timestamp and token bundle.
	//
	// It exists because a session's cost cannot be computed from the sums above.
	// Pricing is per model AND date-effective, and several models price input in
	// LONG-CONTEXT BANDS — so pricing a whole session's summed tokens as if they
	// were one turn invents surcharges the session never incurred and collapses
	// two models (or two sides of a price change) onto one rate. The caller
	// prices each turn and sums the money; the engine's own contract says
	// "aggregate AFTER pricing, not before".
	//
	// It is empty for a proxy-only session (no token_usage rows); see
	// ProxyTurns.
	Turns []CloudTokenTurn
	// ProxyTurns is the same per-row substrate read from api_turns, used ONLY
	// when the session has no token_usage rows at all. The two are never summed
	// — a proxied session writes both, which is why the sums above pick one
	// substrate rather than adding them.
	ProxyTurns []CloudTokenTurn
}

// CloudTokenTurn is one billable turn: the model it ran on, when it ran, and
// its token bundle. It carries no content.
type CloudTokenTurn struct {
	// Model is the row's own recorded model (may be empty on rows that never
	// captured one — the caller decides what to do with an unpriceable turn).
	Model string
	// Timestamp is the row's own time, so it is priced at the rate in force
	// then.
	Timestamp time.Time
	// Input is NET input tokens (adapters emit net; cached lives in CacheRead).
	Input int
	// Output is output tokens.
	Output int
	// CacheRead / CacheCreation / Reasoning complete the bundle.
	CacheRead     int
	CacheCreation int
	Reasoning     int
	// CacheCreation1h is the subset of CacheCreation that landed in the 1h tier,
	// which prices differently. WebSearchRequests is the count of server-side
	// web_search invocations, billed as a FLAT per-request fee on top of tokens.
	// Fast marks a turn served in the provider's low-latency tier, which bills
	// every per-token dimension at a multiple of the standard rate.
	//
	// All three exist here because the bundle handed to the cost engine has to be
	// COMPLETE (A6). Dropping them did not merely lose precision: a fast-mode
	// Opus turn priced at half its real cost, and a session that ran a web search
	// lost the fee entirely. A bundle that is missing a priced dimension is not
	// an approximation of the cost — it is a different number.
	CacheCreation1h   int
	WebSearchRequests int
	Fast              bool
	// RecordedCostUSD is the row's own estimated_cost_usd (0 on the many
	// adapters that record none). It is a PER-ROW fact: whether a row is priced
	// from its recording or from the engine is decided per row, because a session
	// routinely mixes rows of both kinds.
	RecordedCostUSD float64
}

// CloudSessionFacts is the raw session substrate the CLI maps into a
// cloudevidence.SessionInput. It carries local values (tool/model/paths); the
// pure builder turns them into the privacy-preserving envelope. Authority is
// read separately via SessionAuthority so the eligibility gate stays the pure
// contract's single source of truth.
type CloudSessionFacts struct {
	Tool      string
	Model     string
	ProjectID int64
	StartedAt time.Time
	EndedAt   time.Time
	// TotalActions is the sessions row's own counter, which many adapters never
	// populate. ActionCount below is the COUNTED truth.
	TotalActions int
	// ActionCount / FailedActions are counted over the actions table, so an
	// error rate is honest even when the sessions row is empty.
	ActionCount   int
	FailedActions int
	// FirstActionAt / LastActionAt bound the observed activity. They are the
	// duration fallback when the sessions row has no ended_at (very common:
	// a session is only stamped ended when the adapter saw an end event).
	FirstActionAt time.Time
	LastActionAt  time.Time
	// ActivityMix is the WHOLE-SESSION kind histogram, independent of how many
	// action rows Actions carries.
	ActivityMix []CloudKindCount
	// Metrics is the deterministic numeric substrate.
	Metrics CloudSessionMetrics
	// Actions is a STRIDED SAMPLE across the session's WHOLE ordered action
	// population — at most maxActions rows, always including the first and the
	// last. Each row's Ref is its ORIGINAL index, so a gap in the refs shows the
	// sampling honestly. ActionCount above is the population it was drawn from,
	// which is what makes the envelope's omission count true.
	Actions []CloudActionFact
	// OutcomeActions is the KIND-BOUNDED population the milestone and outcome
	// derivations run over: every run_command / edit_file / write_file /
	// tool_failure / task_complete / session_end row in the session, plus the
	// earliest failed row of any kind, all of it in time order.
	//
	// It is deliberately NOT the sample above. Milestones and outcomes are
	// existence-and-count facts ("did a test suite run, did the last build
	// pass, when was the first edit"), and computing them from a 256-row sample
	// of a 30,000-action session answers a different question — it reports what
	// the SAMPLE happened to contain. Bounding by KIND rather than by row count
	// keeps the read cheap while keeping the answer exact.
	OutcomeActions []CloudActionFact
}

// cloudOutcomeKinds is the closed kind list OutcomeActions covers: exactly the
// kinds the pure layer's milestone and outcome rules can fire on.
var cloudOutcomeKinds = []string{
	"run_command", "edit_file", "write_file", "tool_failure", "task_complete", "session_end",
}

// cloudOutcomeTargetBytes bounds how much of one command row's target is read.
//
// It MATCHES the pure classifier's own scan bound (cloudevidence's
// maxCommandScanBytes), and that is the whole point (A5). At 512 bytes the
// window was SHORTER than the classifier's, so a command whose program sat past
// byte 512 — `KEY=<600-byte value> go test ./...`, a real shape when a secret or
// a long PATH is exported inline — arrived here already decapitated and
// classified as nothing at all. A window narrower than the classifier's silently
// changes classifications; a matching one cannot.
const cloudOutcomeTargetBytes = 4096

// Bounds on the outcome population. It is high enough that no real session
// reaches it (a session with 50k shell commands is pathological, not a workflow)
// and exists only so a corrupt or synthetic row explosion cannot make one CLI
// command allocate without limit.
//
// WHY HEAD **AND** TAIL (the N3 fix). The bound used to keep the EARLIEST rows
// only, on the reasoning that milestones are first-occurrence facts. But the two
// derivations disagree about which end matters: DeriveMilestones wants the head
// (first_edit, first_test), while DeriveOutcomes reports the LAST build's result
// and `session_end` / `first_task_complete` are by construction at the very end.
// A head-only truncation therefore did not merely under-report — it could assert
// the WRONG build outcome (an early failed build standing in for a later passing
// one) and silently drop the session's terminal milestones. Splitting the same
// budget into an early window plus a late window answers both derivations, and
// the rows that fall out are the MIDDLE ones, which neither derivation reads
// except as counts. When the split IS hit, test counts under-report (honest) and
// the build outcome is the true last one.
const (
	cloudMaxOutcomeRows  = 50000
	cloudOutcomeTailRows = 10000
	cloudOutcomeHeadRows = cloudMaxOutcomeRows - cloudOutcomeTailRows
)

// cloudReader is the read surface every cloud-evidence loader needs. Both
// *sql.DB and *sql.Conn satisfy it, so each loader runs either standalone or —
// as LoadCloudEvidenceFacts does — inside ONE pinned-connection read snapshot.
type cloudReader interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// LoadCloudEvidenceFacts loads a session row, its whole-session aggregates, a
// STRIDED action sample across the whole session, the kind-bounded outcome
// population, and the per-turn token substrate — everything a cloud evidence
// envelope is built from. maxActions caps the sample (defaulting to
// cloudDefaultActionSample); the pure builder bounds again and summarizes
// overflow as a count against the true population. ok=false means the session
// does not exist. NODE-LOCAL.
// WHY ONE READ SNAPSHOT (the N4 fix). The five reads used to run independently
// against the pool, so a session being written WHILE the envelope was built saw
// an inconsistent world: the aggregate query counted N actions and the sample
// query then selected against a table that already held N+1, dropping the last
// action from the sample and making ActionsOmitted disagree with the mix. Two
// rebuilds of the "same" session then differed, which the two-digest protocol
// reads as tampering — the user is told the evidence changed and asked to
// reconfirm, for no reason but a concurrent insert.
//
// The snapshot is a pinned connection running BEGIN DEFERRED, deliberately NOT
// s.db.BeginTx: the agent DSN carries _txlock=immediate, so BeginTx would take
// the database's WRITE lock for the duration of a purely read-only build and
// contend with the daemon's own ingest. A deferred transaction on one pinned
// connection gives the same repeatable-read snapshot (WAL readers do not block
// writers) at no cost to the writer.
func (s *Store) LoadCloudEvidenceFacts(ctx context.Context, sessionID string, maxActions int) (CloudSessionFacts, bool, error) {
	b, ok, err := s.LoadCloudEvidenceBundle(ctx, sessionID, CloudEvidenceRequest{MaxActions: maxActions})
	return b.Facts, ok, err
}

// CloudEvidenceRequest says what one envelope build needs read, so it can ALL be
// read inside a single snapshot.
//
// WHY THE SINKS (A5 / A8). Two of the facts an envelope asserts are
// WHOLE-SESSION claims over populations that can be enormous: "the session ran N
// tests and its last build passed", and "these were its failure classes". Both
// used to be computed over a bounded window of rows and then presented as facts
// about the session — so a build at row 45,000 of 60,000 could be invisible, and
// the dominant failure class could sit in the omitted middle. A sink lets the
// store scan the WHOLE population row by row and hand each row to a pure
// classifier, so the claim covers everything while memory stays constant: no
// slice of the population is ever built.
type CloudEvidenceRequest struct {
	// EvidenceSettings applies explicit content read limits; nil keeps legacy selection.
	EvidenceSettings *CloudEvidenceSettings
	// MaxActions caps the strided action sample (0 ⇒ cloudDefaultActionSample).
	MaxActions int
	// IncludeTexts reads the excerpt substrate. It is set ONLY on the
	// bounded-context-enrichment path; a structural build leaves it false and
	// the text SQL never runs.
	IncludeTexts bool
	// IncludeFirstPrompt reads ONLY the user-prompt rows (Texts.UserPrompts),
	// never the final assistant message or the failure population. It is the
	// "Title only" level's read: a structural build whose receipt binds the
	// first_user_prompt_excerpt class needs the first real prompt and nothing
	// else, so nothing else is read. Ignored when IncludeTexts is set (which
	// reads a superset).
	IncludeFirstPrompt bool
	// Commands, when non-nil, receives EVERY run_command row of the session in
	// time order (target, success) — the outcome population.
	Commands func(target string, success bool)
	// Failures, when non-nil, receives EVERY recorded failure message of the
	// session in time order — the error-class population. It is CONTENT, so it
	// is set only alongside IncludeTexts.
	Failures func(message string)
}

// CloudEvidenceBundle is everything one envelope build reads, from ONE snapshot.
type CloudEvidenceBundle struct {
	Facts CloudSessionFacts
	// Texts is populated only when the request asked for it.
	Texts CloudSessionTexts
}

// cloudEvidenceMidReadHook is a TEST SEAM fired inside the snapshot, after the
// structural facts are read and before the text substrate is. It is nil in
// production and exists so a test can commit a write from a second connection at
// exactly the moment the old code was vulnerable, and prove the snapshot holds.
var cloudEvidenceMidReadHook func()

// LoadCloudEvidenceBundle reads a session's whole evidence substrate — structural
// facts, the streamed outcome and failure populations, and (on request) the text
// substrate — inside ONE pinned-connection read snapshot. NODE-LOCAL.
//
// WHY ONE READ SNAPSHOT (the N4 fix, completed by A7). The reads used to run
// independently against the pool, so a session being written WHILE the envelope
// was built saw an inconsistent world: the aggregate query counted N actions and
// the sample query then selected against a table that already held N+1, dropping
// the last action from the sample and making ActionsOmitted disagree with the
// mix. Two rebuilds of the "same" session then differed, which the two-digest
// protocol reads as tampering — the user is told the evidence changed and asked
// to reconfirm, for no reason but a concurrent insert.
//
// The TEXT substrate was left outside that snapshot, which is the same bug with
// a worse surface: a prompt landing between the facts read and the text read
// changed the excerpts — the part of the envelope a consent receipt is most
// specifically about — while the digest it was bound to stayed the one the user
// previewed. Both halves now read from the same pinned connection.
//
// The snapshot is a pinned connection running BEGIN DEFERRED, deliberately NOT
// s.db.BeginTx: the agent DSN carries _txlock=immediate, so BeginTx would take
// the database's WRITE lock for the duration of a purely read-only build and
// contend with the daemon's own ingest. A deferred transaction on one pinned
// connection gives the same repeatable-read snapshot (WAL readers do not block
// writers) at no cost to the writer.
func (s *Store) LoadCloudEvidenceBundle(ctx context.Context, sessionID string, req CloudEvidenceRequest) (CloudEvidenceBundle, bool, error) {
	if req.EvidenceSettings != nil {
		if err := req.EvidenceSettings.Validate(); err != nil {
			return CloudEvidenceBundle{}, false, err
		}
	}
	maxActions := req.MaxActions
	if maxActions <= 0 {
		maxActions = cloudDefaultActionSample
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return CloudEvidenceBundle{}, false, fmt.Errorf("store.LoadCloudEvidenceBundle: conn: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `BEGIN DEFERRED`); err != nil {
		return CloudEvidenceBundle{}, false, fmt.Errorf("store.LoadCloudEvidenceBundle: begin: %w", err)
	}
	// Read-only: the snapshot always ends in ROLLBACK, never a commit.
	defer func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), `ROLLBACK`) }()

	var out CloudEvidenceBundle
	facts, ok, err := loadCloudSessionRow(ctx, conn, sessionID)
	if err != nil || !ok {
		return CloudEvidenceBundle{}, ok, err
	}
	if err := loadCloudActionAggregates(ctx, conn, sessionID, &facts); err != nil {
		return CloudEvidenceBundle{}, false, err
	}
	if err := loadCloudTokenMetrics(ctx, conn, sessionID, &facts); err != nil {
		return CloudEvidenceBundle{}, false, err
	}
	if err := loadCloudActionScan(ctx, conn, sessionID, maxActions, &facts); err != nil {
		return CloudEvidenceBundle{}, false, err
	}
	if err := loadCloudOutcomeActions(ctx, conn, sessionID, &facts); err != nil {
		return CloudEvidenceBundle{}, false, err
	}
	if req.Commands != nil {
		if err := streamCloudRunCommands(ctx, conn, sessionID, req.Commands); err != nil {
			return CloudEvidenceBundle{}, false, err
		}
	}
	out.Facts = facts

	if hook := cloudEvidenceMidReadHook; hook != nil {
		hook()
	}

	switch {
	case req.EvidenceSettings != nil && (req.IncludeTexts || req.IncludeFirstPrompt):
		settings := *req.EvidenceSettings
		if !req.IncludeTexts {
			settings = settings.ForLevel(CloudEnrichTitles)
		}
		texts, terr := loadCloudSelectedTexts(ctx, conn, sessionID, settings, req.Failures)
		if terr != nil {
			return CloudEvidenceBundle{}, false, terr
		}
		out.Texts = texts
	case req.IncludeTexts:
		texts, terr := loadCloudSessionTexts(ctx, conn, sessionID, req.Failures)
		if terr != nil {
			return CloudEvidenceBundle{}, false, terr
		}
		out.Texts = texts
	case req.IncludeFirstPrompt:
		prompts, perr := loadCloudPromptRows(ctx, conn, sessionID)
		if perr != nil {
			return CloudEvidenceBundle{}, false, perr
		}
		out.Texts = CloudSessionTexts{UserPrompts: prompts}
	}
	return out, true, nil
}

// streamCloudRunCommands hands EVERY run_command row of the session to sink, in
// time order, one at a time — the outcome population (A5).
//
// It is a stream and not a load because the population is unbounded in principle
// (a long session runs tens of thousands of commands) and the caller needs only
// counters from it. Targets are read at cloudOutcomeTargetBytes, which is the
// same bound the shell classifier itself scans, so truncation can never change a
// classification.
//
// Sub-agent rows are INCLUDED here, deliberately: a test a sub-agent ran is a
// test this session ran, and an outcome count carries no content. That is the
// opposite of the excerpt reads, which exclude them because they carry text.
func streamCloudRunCommands(ctx context.Context, db cloudReader, sessionID string, sink func(target string, success bool)) error {
	rows, err := db.QueryContext(ctx, `
		SELECT substr(COALESCE(target, ''), 1, ?), COALESCE(success, 1)
		  FROM actions
		 WHERE session_id = ? AND COALESCE(action_type, '') = 'run_command'
		 ORDER BY timestamp ASC, id ASC`, cloudOutcomeTargetBytes, sessionID)
	if err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceBundle: outcome stream: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			target  string
			success int
		)
		if err := rows.Scan(&target, &success); err != nil {
			return fmt.Errorf("store.LoadCloudEvidenceBundle: scan outcome row: %w", err)
		}
		sink(target, success != 0)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceBundle: outcome stream: %w", err)
	}
	return nil
}

// loadCloudSessionRow reads the sessions row itself.
func loadCloudSessionRow(ctx context.Context, db cloudReader, sessionID string) (CloudSessionFacts, bool, error) {
	var (
		facts       CloudSessionFacts
		model       sql.NullString
		startedAt   sql.NullString
		endedAt     sql.NullString
		total       sql.NullInt64
		quality     sql.NullFloat64
		redundancy  sql.NullFloat64
		sessionErrR sql.NullFloat64
	)
	err := db.QueryRowContext(ctx,
		`SELECT tool, COALESCE(model, ''), project_id, COALESCE(started_at, ''),
		        COALESCE(ended_at, ''), COALESCE(total_actions, 0),
		        quality_score, redundancy_ratio, error_rate
		   FROM sessions WHERE id = ?`, sessionID).
		Scan(&facts.Tool, &model, &facts.ProjectID, &startedAt, &endedAt, &total,
			&quality, &redundancy, &sessionErrR)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudSessionFacts{}, false, nil
	}
	if err != nil {
		return CloudSessionFacts{}, false, fmt.Errorf("store.LoadCloudEvidenceFacts: session row: %w", err)
	}
	facts.Model = model.String
	facts.StartedAt = cloudParseTime(startedAt.String)
	facts.EndedAt = cloudParseTime(endedAt.String)
	facts.TotalActions = int(total.Int64)
	facts.Metrics.QualityScore = quality.Float64
	facts.Metrics.RedundancyRatio = redundancy.Float64
	facts.Metrics.ErrorRate = sessionErrR.Float64
	return facts, true, nil
}

// loadCloudActionAggregates counts the WHOLE session: totals, failures, the
// observed time bounds, and the per-kind mix. These are exact regardless of the
// action-scan bound.
func loadCloudActionAggregates(ctx context.Context, db cloudReader, sessionID string, facts *CloudSessionFacts) error {
	var (
		count, failed int
		minTS, maxTS  sql.NullString
	)
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*),
		        COALESCE(SUM(CASE WHEN COALESCE(success, 1) = 0 THEN 1 ELSE 0 END), 0),
		        MIN(timestamp), MAX(timestamp)
		   FROM actions WHERE session_id = ?`, sessionID).
		Scan(&count, &failed, &minTS, &maxTS); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: action aggregates: %w", err)
	}
	facts.ActionCount = count
	facts.FailedActions = failed
	facts.FirstActionAt = cloudParseTime(minTS.String)
	facts.LastActionAt = cloudParseTime(maxTS.String)

	rows, err := db.QueryContext(ctx,
		`SELECT COALESCE(action_type, ''), COUNT(*)
		   FROM actions WHERE session_id = ?
		  GROUP BY 1 ORDER BY 1 ASC`, sessionID)
	if err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: activity mix: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var kc CloudKindCount
		if err := rows.Scan(&kc.Kind, &kc.Count); err != nil {
			return fmt.Errorf("store.LoadCloudEvidenceFacts: scan activity mix: %w", err)
		}
		facts.ActivityMix = append(facts.ActivityMix, kc)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: activity mix: %w", err)
	}
	return nil
}

// loadCloudTokenMetrics reads the session's recorded token usage and cost from
// the two substrates that can carry it: token_usage (the watcher/JSONL path)
// and api_turns (the proxy path).
//
// They are NOT summed. A proxied session writes BOTH — an api_turns row and its
// token_usage twin — which is exactly why the dashboard's own cost read carries
// a dedup CTE. Without that machinery here, summing would double-count every
// proxied session. So: token_usage wins when it has rows (it is the broader
// substrate), api_turns fills in when it is the only one, and the cost is the
// MAX of the two sums rather than their total — an honest floor instead of an
// inflated figure.
func loadCloudTokenMetrics(ctx context.Context, db cloudReader, sessionID string, facts *CloudSessionFacts) error {
	var (
		rowsN                                     int
		in, out, cacheRead, cacheCreate, reasonin sql.NullInt64
		cost                                      sql.NullFloat64
	)
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*), SUM(COALESCE(input_tokens, 0)), SUM(COALESCE(output_tokens, 0)),
		        SUM(COALESCE(cache_read_tokens, 0)), SUM(COALESCE(cache_creation_tokens, 0)),
		        SUM(COALESCE(reasoning_tokens, 0)), SUM(COALESCE(estimated_cost_usd, 0))
		   FROM token_usage WHERE session_id = ?`, sessionID).
		Scan(&rowsN, &in, &out, &cacheRead, &cacheCreate, &reasonin, &cost); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: token metrics: %w", err)
	}
	m := &facts.Metrics
	m.RecordedRows = rowsN
	m.TokensIn = int(in.Int64)
	m.TokensOut = int(out.Int64)
	m.CacheReadTokens = int(cacheRead.Int64)
	m.CacheCreationTokens = int(cacheCreate.Int64)
	m.ReasoningTokens = int(reasonin.Int64)
	m.CostUSD = cost.Float64

	var (
		turnRows  int
		turnCost  sql.NullFloat64
		tIn, tOut sql.NullInt64
	)
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*), SUM(COALESCE(cost_usd, 0)),
		        SUM(COALESCE(input_tokens, 0)), SUM(COALESCE(output_tokens, 0))
		   FROM api_turns WHERE session_id = ?`, sessionID).
		Scan(&turnRows, &turnCost, &tIn, &tOut); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: api_turns metrics: %w", err)
	}
	if turnRows > 0 && rowsN == 0 {
		// Proxy-only session: api_turns is the whole token substrate.
		m.TokensIn = int(tIn.Int64)
		m.TokensOut = int(tOut.Int64)
		m.RecordedRows = turnRows
	}
	if turnCost.Float64 > m.CostUSD {
		m.CostUSD = turnCost.Float64
	}

	// The PER-ROW substrate, for date- and model-correct pricing (F5). Same
	// substrate choice as the sums: token_usage when it has rows, api_turns only
	// when it is the whole story — never both, or a proxied session double-counts.
	if rowsN > 0 {
		turns, err := loadCloudTokenTurns(ctx, db, `
			SELECT COALESCE(model, ''), timestamp,
			       COALESCE(input_tokens, 0), COALESCE(output_tokens, 0),
			       COALESCE(cache_read_tokens, 0), COALESCE(cache_creation_tokens, 0),
			       COALESCE(reasoning_tokens, 0), COALESCE(cache_creation_1h_tokens, 0),
			       COALESCE(web_search_requests, 0), COALESCE(fast, 0),
			       COALESCE(estimated_cost_usd, 0)
			  FROM token_usage WHERE session_id = ?
			 ORDER BY timestamp ASC, id ASC`, sessionID)
		if err != nil {
			return err
		}
		m.Turns = turns
		return nil
	}
	if turnRows > 0 {
		turns, err := loadCloudTokenTurns(ctx, db, `
			SELECT COALESCE(model, ''), timestamp,
			       COALESCE(input_tokens, 0), COALESCE(output_tokens, 0),
			       COALESCE(cache_read_tokens, 0), COALESCE(cache_creation_tokens, 0),
			       0, COALESCE(cache_creation_1h_tokens, 0),
			       COALESCE(web_search_requests, 0), COALESCE(fast, 0),
			       COALESCE(cost_usd, 0)
			  FROM api_turns WHERE session_id = ?
			 ORDER BY timestamp ASC, id ASC`, sessionID)
		if err != nil {
			return err
		}
		m.ProxyTurns = turns
	}
	return nil
}

// loadCloudTokenTurns runs one per-turn token query and scans it into the
// content-free CloudTokenTurn shape. Both substrates share it so their column
// order can never drift apart.
func loadCloudTokenTurns(ctx context.Context, db cloudReader, query, sessionID string) ([]CloudTokenTurn, error) {
	rows, err := db.QueryContext(ctx, query, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadCloudEvidenceFacts: token turns: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []CloudTokenTurn
	for rows.Next() {
		var (
			t    CloudTokenTurn
			ts   string
			fast int
		)
		if err := rows.Scan(&t.Model, &ts, &t.Input, &t.Output, &t.CacheRead,
			&t.CacheCreation, &t.Reasoning, &t.CacheCreation1h, &t.WebSearchRequests,
			&fast, &t.RecordedCostUSD); err != nil {
			return nil, fmt.Errorf("store.LoadCloudEvidenceFacts: scan token turn: %w", err)
		}
		t.Fast = fast != 0
		t.Timestamp = cloudParseTime(ts)
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadCloudEvidenceFacts: token turns: %w", err)
	}
	return out, nil
}

// cloudDefaultActionSample is the sample size used when a caller passes 0. It
// matches the envelope's own MaxActions; the store cannot import the contract
// (that would invert the dependency), so the CLI passes the real bound and this
// is only the fallback.
const cloudDefaultActionSample = 256

// loadCloudActionScan selects a STRIDED SAMPLE across the session's whole
// ordered action population, never a prefix.
//
// WHY A WINDOW FUNCTION AND NOT `LIMIT n` (the F6 fix). The previous read took
// the first 20,000 rows and let the pure builder sample within them, so a
// 30,000-action session shipped a sample of its FIRST 20,000 — the tail, where
// the work usually lands, could not be selected at all, and the omission count
// was computed against the truncated set rather than the real one. Counting
// first, computing the stride in Go, and filtering on ROW_NUMBER() keeps the
// selection population-wide while still returning only ~maxActions rows to Go.
//
// Ref stays the row's ORIGINAL index in the full order, so ref gaps show the
// sampling honestly, and facts.ActionCount (counted in SQL over every row) is
// the population the caller reports omissions against.
func loadCloudActionScan(ctx context.Context, db cloudReader, sessionID string, maxActions int, facts *CloudSessionFacts) error {
	total := facts.ActionCount
	if total == 0 {
		return nil
	}
	stride := 1
	if total > maxActions {
		// ceil(total / maxActions): the smallest stride whose sample fits. The
		// stride is the ONLY thing the Go-side count is used for — the "always
		// include the last row" predicate compares against the statement's own
		// COUNT(*) OVER (), so a population that grew between the two reads can
		// no longer drop the session's last action from the sample (N4).
		stride = (total + maxActions - 1) / maxActions
	}
	rows, err := db.QueryContext(ctx, `
		WITH ordered AS (
		  SELECT COALESCE(action_type, '') AS kind,
		         COALESCE(success, 1)      AS ok,
		         COALESCE(target, '')      AS target,
		         COALESCE(raw_tool_name, '') AS tool_name,
		         timestamp                 AS ts,
		         ROW_NUMBER() OVER (ORDER BY timestamp ASC, id ASC) AS rn,
		         COUNT(*)     OVER ()                               AS total
		    FROM actions WHERE session_id = ?
		)
		SELECT kind, ok, target, tool_name, ts, rn
		  FROM ordered
		 WHERE (rn - 1) % ? = 0 OR rn = total
		 ORDER BY rn ASC`, sessionID, stride)
	if err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: action sample: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			kind, target, toolName, ts string
			success                    int
			rn                         int64
		)
		if err := rows.Scan(&kind, &success, &target, &toolName, &ts, &rn); err != nil {
			return fmt.Errorf("store.LoadCloudEvidenceFacts: scan action: %w", err)
		}
		facts.Actions = append(facts.Actions, CloudActionFact{
			Ref:         "a" + strconv.FormatInt(rn-1, 10),
			Kind:        kind,
			Success:     success != 0,
			Target:      target,
			RawToolName: toolName,
			Timestamp:   cloudParseTime(ts),
		})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: action sample: %w", err)
	}
	return nil
}

// loadCloudOutcomeActions reads the KIND-BOUNDED outcome population: every row
// whose kind can fire a milestone or an outcome rule, plus any failed row (the
// first_error rule matches a failure of ANY kind). Targets are read truncated —
// command classification only inspects the leading tokens — so the population is
// bounded in memory per row as well as in row count.
//
// The bound is a HEAD WINDOW PLUS A TAIL WINDOW (see cloudMaxOutcomeRows), not a
// prefix: milestones are answered by the head, the last build outcome and the
// terminal milestones by the tail. `COUNT(*) OVER ()` computes the population
// size inside the same statement, so the window edges can never be computed
// against a different read than the one they filter.
func loadCloudOutcomeActions(ctx context.Context, db cloudReader, sessionID string, facts *CloudSessionFacts) error {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(cloudOutcomeKinds)), ",")
	args := make([]any, 0, len(cloudOutcomeKinds)+4)
	args = append(args, cloudOutcomeTargetBytes, sessionID)
	for _, k := range cloudOutcomeKinds {
		args = append(args, k)
	}
	args = append(args, cloudOutcomeHeadRows, cloudOutcomeTailRows)
	rows, err := db.QueryContext(ctx, `
		WITH ordered AS (
		  SELECT COALESCE(action_type, '')      AS kind,
		         COALESCE(success, 1)           AS ok,
		         substr(COALESCE(target, ''), 1, ?) AS target,
		         COALESCE(raw_tool_name, '')    AS tool_name,
		         timestamp                      AS ts,
		         ROW_NUMBER() OVER (ORDER BY timestamp ASC, id ASC) AS rn,
		         COUNT(*)     OVER ()                               AS total
		    FROM actions
		   WHERE session_id = ?
		     AND (COALESCE(action_type, '') IN (`+placeholders+`) OR COALESCE(success, 1) = 0)
		)
		SELECT kind, ok, target, tool_name, ts
		  FROM ordered
		 WHERE rn <= ? OR rn > total - ?
		 ORDER BY rn ASC`, args...)
	if err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: outcome population: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			kind, target, toolName, ts string
			success                    int
		)
		if err := rows.Scan(&kind, &success, &target, &toolName, &ts); err != nil {
			return fmt.Errorf("store.LoadCloudEvidenceFacts: scan outcome row: %w", err)
		}
		facts.OutcomeActions = append(facts.OutcomeActions, CloudActionFact{
			Kind:        kind,
			Success:     success != 0,
			Target:      target,
			RawToolName: toolName,
			Timestamp:   cloudParseTime(ts),
		})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: outcome population: %w", err)
	}
	return nil
}

// -- excerpt substrate (bounded-context enrichment only) ---------------------

// CloudSessionTexts is the raw, node-local TEXT substrate for one session: the
// user's own prompts, the last assistant message, and recorded tool-failure
// messages. It is loaded ONLY on the bounded-context-enrichment path; the
// structural path never calls this read, so a structural envelope cannot even
// have content to leak.
//
// What is deliberately NOT here: commands, tool outputs, file contents, paths,
// and reasoning. Those columns exist on the actions row and are never selected.
type CloudSessionTexts struct {
	UserPrompts           []string
	FinalAssistantMessage string
	AssistantMessages     []string
	Errors                []string
}

// Bounds on the text substrate read. They are generous enough that the pure
// selector always has candidates to sample across, and small enough that the
// read stays cheap.
const (
	cloudMaxPromptRows = 200
	// cloudMaxErrorRows bounds the failure population the pure layer CLASSIFIES
	// and COUNTS. It is deliberately large: unlike a prompt, a failure row never
	// leaves this process as text — only the class label it matched, plus an
	// integer count, ever reaches an envelope — so reading more rows buys a
	// truer distribution at no disclosure cost. The old bound of 8 EARLIEST rows
	// meant the shipped classes described the session's first few failures, not
	// its failures (Q1).
	cloudMaxErrorRows = 2000
	// cloudErrorTailRows is the late window of the head+tail split, so the LAST
	// observed failure class survives a session that blew past the bound.
	cloudErrorTailRows = 400
	// cloudErrorScanBytes bounds how much of one error_message is read. Only the
	// classifier ever sees these bytes and it matches short phrases, so the
	// leading 512 bytes carry the whole signal.
	cloudErrorScanBytes = 512
	// cloudPromptHeadRows is the CONTIGUOUS head window of prompt rows always
	// returned, ahead of the strided remainder.
	//
	// It exists because the pure selector's "first REAL prompt" is defined AFTER
	// harness filtering (a `/clear` envelope, a caveat block, a system reminder
	// are not the developer's prompt), and that filtering happens in Go — SQL
	// cannot know which of the earliest rows are injections. A contiguous head
	// therefore has to be handed over so the earliest surviving prompt is the
	// true one. 24 is the documented BOUND on that guarantee: a session whose
	// first 24 prompt rows are ALL harness injections would have its "first real
	// prompt" drawn from the strided remainder instead — later than the truth,
	// never a different kind of thing. Real sessions open with at most a handful.
	cloudPromptHeadRows = 24
	// cloudTextScanBytes bounds how much of one text column is read. The pure
	// selector caps each excerpt at 1024 pre-scrub bytes, so reading much more
	// than that would only move bytes around in memory.
	cloudTextScanBytes = 4096
)

// notSidechain is the predicate every CONTENT read carries (A1).
//
// A Claude sub-agent shares the PARENT's session id, and its rows land in the
// same `actions` table with is_sidechain = 1. Two of those rows are text:
//
//   - the parent's DELEGATION INSTRUCTION becomes a `user_prompt` row, so a
//     sub-agent brief — routinely a paste of tool output, a file excerpt, or a
//     record the parent wanted analyzed — qualified as the session's
//     "first_user_prompt" and shipped as the developer's own words;
//   - a sub-agent's reply becomes an `assistant_message` row, so the LAST one
//     could be a sub-agent's report rather than the session's conclusion.
//
// Neither is the developer's prompt, and both are richer in incidental content
// than a real prompt is. The excerpt reads therefore take main-thread rows only.
// The STRUCTURAL reads (counts, mixes, outcomes) deliberately do not: a
// sub-agent's work is the session's work, and a count carries no content.
const notSidechain = ` AND COALESCE(is_sidechain, 0) = 0`

// LoadCloudSessionTexts reads the bounded text substrate for one session. The
// SQL is deliberately dumb: it selects candidate rows in time order and leaves
// every judgement (which prompts are harness-injected, which are duplicates,
// which to sample) to the pure selector in internal/cloudevidence. NODE-LOCAL.
//
// It reads from the pool. The envelope build path does NOT use it — it reads the
// same substrate inside its own snapshot via LoadCloudEvidenceBundle (A7).
func (s *Store) LoadCloudSessionTexts(ctx context.Context, sessionID string) (CloudSessionTexts, error) {
	return loadCloudSessionTexts(ctx, s.db, sessionID, nil)
}

// loadCloudSessionTexts is the shared implementation, over any cloudReader so it
// can run inside the evidence snapshot.
//
// When failures is non-nil it receives EVERY recorded failure message of the
// session and out.Errors is left empty: the caller is classifying the whole
// population as it streams (A8) rather than taking a window of it. When it is
// nil the bounded head+tail window is materialized, for callers that want the
// messages themselves.
func loadCloudSessionTexts(ctx context.Context, db cloudReader, sessionID string, failures func(string)) (CloudSessionTexts, error) {
	var out CloudSessionTexts
	prompts, err := loadCloudPromptRows(ctx, db, sessionID)
	if err != nil {
		return CloudSessionTexts{}, err
	}
	out.UserPrompts = prompts

	final, err := cloudTextRows(ctx, db, `
		SELECT substr(CASE WHEN length(COALESCE(raw_tool_input, '')) > length(COALESCE(target, ''))
		                   THEN raw_tool_input ELSE COALESCE(target, '') END, 1, ?)
		  FROM actions
		 WHERE session_id = ? AND action_type = 'assistant_message'
		       AND COALESCE(target, '') <> ''`+notSidechain+`
		 ORDER BY timestamp DESC, id DESC
		 LIMIT 1`, cloudTextScanBytes, sessionID)
	if err != nil {
		return CloudSessionTexts{}, err
	}
	if len(final) > 0 {
		out.FinalAssistantMessage = final[0]
	}

	if failures != nil {
		if err := streamCloudFailures(ctx, db, sessionID, failures); err != nil {
			return CloudSessionTexts{}, err
		}
		return out, nil
	}

	// The failure population, as a head window plus a tail window in time order:
	// the pure layer counts classes over ALL of it and always keeps the LAST
	// observed class, so both ends have to be present.
	errs, err := cloudTextRows(ctx, db, `
		WITH ordered AS (
		  SELECT substr(error_message, 1, ?) AS body,
		         ROW_NUMBER() OVER (ORDER BY timestamp ASC, id ASC) AS rn,
		         COUNT(*)     OVER ()                               AS total
		    FROM actions
		   WHERE session_id = ? AND `+cloudFailureRowPredicate+notSidechain+`
		)
		SELECT body FROM ordered
		 WHERE rn <= ? OR rn > total - ?
		 ORDER BY rn ASC`,
		cloudErrorScanBytes, sessionID,
		cloudMaxErrorRows-cloudErrorTailRows, cloudErrorTailRows)
	if err != nil {
		return CloudSessionTexts{}, err
	}
	out.Errors = errs
	return out, nil
}

// cloudFailureRowPredicate selects the session's FAILURE population.
//
// It is not just `action_type = 'tool_failure'` (A8): an action of any kind that
// recorded success = 0 with an error message is a failure of this session, and
// counting only the rows one adapter happens to label `tool_failure` reported a
// distribution over a subset while calling it the session's.
const cloudFailureRowPredicate = `(COALESCE(action_type, '') = 'tool_failure' OR COALESCE(success, 1) = 0)
	         AND COALESCE(error_message, '') <> ''`

// streamCloudFailures hands EVERY failure message of the session to sink, in
// time order, one at a time. The caller classifies each one into a closed-
// vocabulary label and keeps only counters, so no message is ever materialized
// as a population and no cap is needed (A8).
func streamCloudFailures(ctx context.Context, db cloudReader, sessionID string, sink func(string)) error {
	rows, err := db.QueryContext(ctx, `
		SELECT substr(error_message, 1, ?)
		  FROM actions
		 WHERE session_id = ? AND `+cloudFailureRowPredicate+notSidechain+`
		 ORDER BY timestamp ASC, id ASC`, cloudErrorScanBytes, sessionID)
	if err != nil {
		return fmt.Errorf("store.LoadCloudSessionTexts: failure stream: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var body sql.NullString
		if err := rows.Scan(&body); err != nil {
			return fmt.Errorf("store.LoadCloudSessionTexts: scan failure row: %w", err)
		}
		if strings.TrimSpace(body.String) == "" {
			continue
		}
		sink(body.String)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store.LoadCloudSessionTexts: failure stream: %w", err)
	}
	return nil
}

// loadCloudPromptRows returns the session's user prompts as a CONTIGUOUS HEAD
// window plus a STRIDED SAMPLE across the whole remaining population, in time
// order, bounded at cloudMaxPromptRows.
//
// WHY NOT `LIMIT 200` (the F6 fix). The head-only read meant a 500-prompt
// session's excerpts were drawn entirely from its first 200 prompts, so the
// "evenly strided across the session" spread the pure selector performs was
// striding across a prefix — the end of the session could not be quoted at all.
// The head window is still needed (see cloudPromptHeadRows) so the first REAL
// prompt survives harness filtering in Go; everything past it is sampled across
// the true population.
//
// A user prompt's fullest text sits in raw_tool_input on the adapters that
// record it, with target holding a truncated rendering; the longer of the two is
// taken so the first prompt is not clipped to an ellipsis.
func loadCloudPromptRows(ctx context.Context, db cloudReader, sessionID string) ([]string, error) {
	var total int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM actions WHERE session_id = ? AND action_type = 'user_prompt'`+notSidechain,
		sessionID).Scan(&total); err != nil {
		return nil, fmt.Errorf("store.LoadCloudSessionTexts: count prompts: %w", err)
	}
	if total == 0 {
		return nil, nil
	}
	head := cloudPromptHeadRows
	if head > cloudMaxPromptRows {
		head = cloudMaxPromptRows
	}
	stride := 1
	if remaining := total - head; remaining > 0 {
		if budget := cloudMaxPromptRows - head; budget > 0 && remaining > budget {
			stride = (remaining + budget - 1) / budget
		}
	}
	return cloudTextRows(ctx, db, `
		WITH ordered AS (
		  SELECT substr(CASE WHEN length(COALESCE(raw_tool_input, '')) > length(COALESCE(target, ''))
		                     THEN raw_tool_input ELSE COALESCE(target, '') END, 1, ?) AS body,
		         ROW_NUMBER() OVER (ORDER BY timestamp ASC, id ASC) AS rn
		    FROM actions
		   WHERE session_id = ? AND action_type = 'user_prompt'`+notSidechain+`
		)
		SELECT body FROM ordered
		 WHERE rn <= ? OR (rn - ?) % ? = 0 OR rn = ?
		 ORDER BY rn ASC`,
		cloudTextScanBytes, sessionID, head, head, stride, total)
}

// cloudTextRows runs a one-column text query and returns the non-empty values.
func cloudTextRows(ctx context.Context, db cloudReader, query string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.LoadCloudSessionTexts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var v sql.NullString
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("store.LoadCloudSessionTexts: scan: %w", err)
		}
		if strings.TrimSpace(v.String) == "" {
			continue
		}
		out = append(out, v.String)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadCloudSessionTexts: %w", err)
	}
	return out, nil
}

// ListSendableCloudOutbox returns SESSION-EVIDENCE outbox items in a preparable
// state (pending / failed_retryable), oldest first — the manual drain set for
// `observer cloud sync`. Items awaiting reconfirmation or already terminal are
// deliberately excluded.
//
// The kind filter is load-bearing (migration 098): structural-insights items
// live in the same table but are prepared through an entirely different path
// (PrepareStructuralSend replays stored bytes; PrepareCloudOutboxSend rebuilds
// an envelope from a session). Their drain set is
// ListSendableStructuralOutbox, which orders by revision rather than by
// creation time.
func (s *Store) ListSendableCloudOutbox(ctx context.Context) ([]CloudOutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, session_id, feature_set_json, evidence_content_digest, upload_digest,
		       receipt_id, state, retry_count, last_error, created_at, updated_at
		  FROM cloud_outbox
		 WHERE kind = ? AND state IN (?, ?)
		 ORDER BY created_at ASC, id ASC`,
		string(CloudOutboxKindSessionEvidence),
		string(CloudOutboxPending), string(CloudOutboxFailedRetryable))
	if err != nil {
		return nil, fmt.Errorf("store.ListSendableCloudOutbox: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanCloudOutboxRows(rows, "store.ListSendableCloudOutbox")
}

// SaveCloudResultCursor persists the opaque results-pull cursor for one cloud
// host (schema_meta singleton per host). An empty cursor is a no-op (never
// clobber a real cursor with "").
func (s *Store) SaveCloudResultCursor(ctx context.Context, host, cursor string) error {
	if cursor == "" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		cloudResultCursorKeyFor(host), cursor); err != nil {
		return fmt.Errorf("store.SaveCloudResultCursor: %w", err)
	}
	return nil
}

// LoadCloudResultCursor reads the opaque results-pull cursor for one cloud
// host; "" when never saved against that host (a first sync pulls from the
// beginning).
func (s *Store) LoadCloudResultCursor(ctx context.Context, host string) (string, error) {
	v, err := s.readMeta(ctx, cloudResultCursorKeyFor(host))
	if err != nil {
		return "", fmt.Errorf("store.LoadCloudResultCursor: %w", err)
	}
	return v, nil
}

// HasCloudResultCursor reports whether a results-pull cursor exists for ANY
// cloud host (legacy bare key included) - the dashboard's "has ever synced"
// signal, which does not know the resolved base URL.
func (s *Store) HasCloudResultCursor(ctx context.Context) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM schema_meta WHERE (key = ? OR key LIKE ?) AND COALESCE(value, '') <> ''`,
		cloudResultCursorKey, cloudResultCursorKey+":%").Scan(&n); err != nil {
		return false, fmt.Errorf("store.HasCloudResultCursor: %w", err)
	}
	return n > 0, nil
}

// -- CI-P5 dashboard read seam (FF1) -----------------------------------------
//
// These aggregate reads back the NODE dashboard's Cloud Intelligence surfaces.
// They live in this store seam — not as ad-hoc SQL in the handler — so the
// §7.7 "one store seam per database" invariant holds: a cloud-schema or
// eligibility change is made here once and both the CLI and the dashboard track
// it. The handler decides how to degrade (empty state) on error; the seam
// returns errors rather than swallowing them.

// CloudReceiptCounts returns the total consent receipts and the live (not
// invalidated) subset. invalidated_at is stored NULL or "" while live.
func (s *Store) CloudReceiptCounts(ctx context.Context) (total, live int, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN COALESCE(invalidated_at, '') = '' THEN 1 ELSE 0 END), 0)
		  FROM cloud_consent_receipts`).Scan(&total, &live)
	if err != nil {
		return 0, 0, fmt.Errorf("store.CloudReceiptCounts: %w", err)
	}
	return total, live, nil
}

// CloudOutboxCountsByState returns per-state outbox counts and the total across
// every state (including the terminal states ListSendableCloudOutbox omits).
func (s *Store) CloudOutboxCountsByState(ctx context.Context) (map[string]int, int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT state, COUNT(*) FROM cloud_outbox GROUP BY state`)
	if err != nil {
		return nil, 0, fmt.Errorf("store.CloudOutboxCountsByState: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byState := map[string]int{}
	total := 0
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, 0, fmt.Errorf("store.CloudOutboxCountsByState: scan: %w", err)
		}
		byState[st] = n
		total += n
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store.CloudOutboxCountsByState: %w", err)
	}
	return byState, total, nil
}

// CloudResultsSummary returns the total stored results and the newest
// received_at (RFC3339Nano UTC string, "" when none — chronological via MAX).
func (s *Store) CloudResultsSummary(ctx context.Context) (total int, lastReceivedAt string, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MAX(received_at), '') FROM cloud_results`).
		Scan(&total, &lastReceivedAt)
	if err != nil {
		return 0, "", fmt.Errorf("store.CloudResultsSummary: %w", err)
	}
	return total, lastReceivedAt, nil
}

// ListCloudOutboxForSession returns every outbox item bound to sessionID (any
// state), oldest first — the session-detail surface. NODE-LOCAL.
func (s *Store) ListCloudOutboxForSession(ctx context.Context, sessionID string) ([]CloudOutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, session_id, feature_set_json, evidence_content_digest, upload_digest,
		       receipt_id, state, retry_count, last_error, created_at, updated_at
		  FROM cloud_outbox WHERE session_id = ?
		 ORDER BY created_at ASC, id ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.ListCloudOutboxForSession: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanCloudOutboxRows(rows, "store.ListCloudOutboxForSession")
}
