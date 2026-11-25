package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// cloudlocal.go and its cloudlocal_*.go siblings are the ONE store seam over
// the node-local cloud-intelligence tables (migration 097 — CI-P2 Lane D, cloud-intelligence Azure Foundry plan
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
