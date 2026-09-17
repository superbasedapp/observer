package cloudclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudcred"
	"github.com/marmutapp/superbased-observer/internal/cloudpop"
)

// Header names on the device API wire.
const (
	headerPoP         = "SBO-PoP"
	headerIdempotency = "Idempotency-Key"
	headerFeature     = "SBO-Feature"
)

// Default tuning.
const (
	defaultMaxRetries    = 2
	maxResponseBodyBytes = 8 << 20 // 8 MiB ceiling on any response body read
)

// Sentinel errors callers branch on.
var (
	// ErrNotAuthenticated means no short-lived API token is stored; the caller
	// must run Exchange (after login) first.
	ErrNotAuthenticated = errors.New("cloudclient: no API token; run exchange first")
	// ErrCursorRegression means the server returned a results cursor that did
	// not advance monotonically — a protocol violation the client refuses to
	// loop on.
	ErrCursorRegression = errors.New("cloudclient: results cursor did not advance monotonically")
	// ErrSignInExpired means the stored API token was rejected AND the one-shot
	// self-heal (re-exchange through the persisted WorkOS sign-in) could not
	// mint a replacement — the refresh failed, or the fresh token was rejected
	// too. The only recovery is a new sign-in. Every later authenticated call
	// on this Client fails fast with the same error (no retry storm).
	ErrSignInExpired = errors.New("cloudclient: sign-in expired — run `observer cloud login`")
)

// tokenRejectedCode is the server's error `code` for a bearer it will not
// honour (missing / unknown / expired token, or a failed proof). It is the ONE
// refusal the self-heal reacts to; any other code — a forbidden device, a
// consent-terms mismatch, a conflict — is a decision about the REQUEST, not
// about the credential, and re-exchanging would not change it.
const tokenRejectedCode = "unauthorized"

// APIError is a non-2xx HTTP response from the service.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("cloudclient: server returned %d: %s", e.StatusCode, e.Body)
}

// Options configures a Client.
type Options struct {
	// BaseURL is the service origin (e.g. "https://cloud.superbased.app").
	// Required. A trailing slash is trimmed.
	BaseURL string
	// Cred stores the device key and API token. Required.
	Cred cloudcred.Store
	// Broker mints WorkOS access tokens. Required for Exchange.
	Broker CloudIdentityBroker
	// HTTPClient is used for all requests; a sensible default is created when nil.
	HTTPClient *http.Client
	// Clock returns the current time (for proof iat and tests); nil means
	// time.Now.
	Clock func() time.Time
	// Logger is used for diagnostics; nil means slog.Default.
	Logger *slog.Logger
	// MaxRetries bounds retries of TRANSPORT errors only; <0 means the default.
	MaxRetries int
	// Backoff returns the wait before retry attempt n (0-based); nil means a
	// jittered exponential default.
	Backoff func(attempt int) time.Duration
	// DeviceLabel is a human label sent at exchange time (optional).
	DeviceLabel string
	// OnTokenHealed, when non-nil, is invoked once each time an expired API
	// token was transparently re-exchanged (see sendAuthed). It exists for
	// callers that want to mention the heal to the user; it receives no token.
	OnTokenHealed func()
}

// Client is the personal-cloud device client. It holds no long-lived
// goroutines and makes no network calls until a method is invoked.
type Client struct {
	baseURL     string
	cred        cloudcred.Store
	broker      CloudIdentityBroker
	http        *http.Client
	clock       func() time.Time
	log         *slog.Logger
	maxRetries  int
	backoff     func(attempt int) time.Duration
	deviceLabel string
	dev         device
	onHealed    func()

	// healMu serialises the token self-heal; healFailed latches the FIRST
	// failed heal so a multi-item sync attempts the WorkOS refresh at most once
	// per process instead of once per item (never a retry storm).
	healMu     sync.Mutex
	healFailed error
}

// New constructs a Client. It loads (or creates and persists) the device key via
// Cred but performs NO network I/O.
func New(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.BaseURL) == "" {
		return nil, fmt.Errorf("cloudclient.New: BaseURL is required")
	}
	if opts.Cred == nil {
		return nil, fmt.Errorf("cloudclient.New: Cred is required")
	}
	dev, err := loadOrCreateDevice(opts.Cred)
	if err != nil {
		return nil, fmt.Errorf("cloudclient.New: %w", err)
	}
	c := &Client{
		baseURL:     strings.TrimRight(opts.BaseURL, "/"),
		cred:        opts.Cred,
		broker:      opts.Broker,
		http:        opts.HTTPClient,
		clock:       opts.Clock,
		log:         opts.Logger,
		maxRetries:  opts.MaxRetries,
		backoff:     opts.Backoff,
		deviceLabel: opts.DeviceLabel,
		onHealed:    opts.OnTokenHealed,
		dev:         dev,
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: 30 * time.Second}
	}
	// FD1: refuse EVERY redirect. An evidence upload (or any device-API call)
	// must reach exactly the approved origin; a 307/308 must never re-send the
	// request body to a redirect target the developer never consented to.
	// ErrUseLastResponse returns the 3xx to sendOnce (surfaced as a non-2xx
	// APIError) instead of following it with the body. Set on a caller-supplied
	// client too — this is a security invariant, not a tunable.
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if c.clock == nil {
		c.clock = time.Now
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	if c.maxRetries < 0 {
		c.maxRetries = defaultMaxRetries
	}
	if c.backoff == nil {
		c.backoff = defaultBackoff
	}
	return c, nil
}

// DeviceThumbprint returns the RFC 7638 thumbprint of the device key — the
// stable device identifier the idempotency key is bound to.
func (c *Client) DeviceThumbprint() string { return c.dev.thumbprint }

// DevicePublicKey returns the device public key.
func (c *Client) DevicePublicKey() ed25519.PublicKey { return c.dev.pub }

// UploadEndpoint returns the immutable absolute URL this client POSTs evidence
// to. The node's send path (store.PrepareCloudOutboxSend) compares it against
// the consent receipt's bound endpoint so confirmed evidence can only ever go
// to the origin the developer approved (FD1).
func (c *Client) UploadEndpoint() string { return c.baseURL + "/v1/jobs" }

// --- exchange --------------------------------------------------------------

type nonceResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expires_at"`
}

type exchangeRequest struct {
	WorkOSAccessToken string `json:"workos_access_token"`
	DevicePublicKey   string `json:"device_public_key"`
	Nonce             string `json:"nonce"`
	Signature         string `json:"signature"`
	DeviceLabel       string `json:"device_label,omitempty"`
}

type exchangeResponse struct {
	APIToken  string `json:"api_token"`
	ExpiresAt string `json:"expires_at"`
	DeviceID  string `json:"device_id"`
}

// Exchange fetches a server nonce, obtains a WorkOS access token from the
// broker, signs the nonce with the device key, and exchanges all three for a
// short-lived device-bound SuperBased API token, which it stores via Cred. The
// nonce GET retries transport errors; the exchange POST does not (the nonce is
// single-use, so a fresh Exchange with a fresh nonce is the correct recovery).
func (c *Client) Exchange(ctx context.Context) error {
	if c.broker == nil {
		return fmt.Errorf("cloudclient.Exchange: no identity broker configured")
	}
	access, err := c.broker.AccessToken(ctx)
	if err != nil {
		return fmt.Errorf("cloudclient.Exchange: broker: %w", err)
	}

	// 1. nonce (unauthenticated, retry transport errors).
	nonceRaw, err := c.sendRetryable(ctx, nil, func(int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/auth/nonce", nil)
	})
	if err != nil {
		return fmt.Errorf("cloudclient.Exchange: nonce: %w", err)
	}
	var nr nonceResponse
	if err := json.Unmarshal(nonceRaw, &nr); err != nil {
		return fmt.Errorf("cloudclient.Exchange: decode nonce: %w", err)
	}
	if nr.Nonce == "" {
		return fmt.Errorf("cloudclient.Exchange: server returned empty nonce")
	}

	// 2. sign + exchange (no retry — nonce is single-use).
	sig := ed25519.Sign(c.dev.priv, ExchangeSigningInput(nr.Nonce, c.dev.pub))
	reqBody, err := json.Marshal(exchangeRequest{
		WorkOSAccessToken: access,
		DevicePublicKey:   b64.EncodeToString(c.dev.pub),
		Nonce:             nr.Nonce,
		Signature:         b64.EncodeToString(sig),
		DeviceLabel:       c.deviceLabel,
	})
	if err != nil {
		return fmt.Errorf("cloudclient.Exchange: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/auth/exchange", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("cloudclient.Exchange: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	raw, err := c.sendOnce(req)
	if err != nil {
		return fmt.Errorf("cloudclient.Exchange: %w", err)
	}
	var xr exchangeResponse
	if err := json.Unmarshal(raw, &xr); err != nil {
		return fmt.Errorf("cloudclient.Exchange: decode response: %w", err)
	}
	if xr.APIToken == "" {
		return fmt.Errorf("cloudclient.Exchange: server returned empty api_token")
	}
	if err := c.cred.SaveAPIToken(xr.APIToken); err != nil {
		return fmt.Errorf("cloudclient.Exchange: store token: %w", err)
	}
	return nil
}

// --- upload ----------------------------------------------------------------

// UploadRequest carries one evidence envelope for enrichment. Envelope MUST be
// the EXACT bytes returned by cloudevidence.Serialize — the client never
// re-serializes; it sends what it is handed.
type UploadRequest struct {
	CloudSessionID string
	Feature        string
	Envelope       []byte
	Digests        cloudcontract.Digests
	SchemaVersion  string // defaults to cloudcontract.EnvelopeSchemaVersion when empty

	// PreAttempt (FD3), when non-nil, is invoked immediately before EVERY
	// physical HTTP attempt — after all preparatory I/O (pseudonym mint, request
	// build) and before the body leaves the process, on the first try AND on each
	// transport retry. The caller passes the reconfirmation-lease verifier here;
	// a non-nil error aborts the send without dispatching (never retried), so a
	// receipt invalidated or a session upgraded to org after PrepareCloudOutboxSend
	// cannot leak the confirmed body through the prepare→dispatch or retry windows.
	PreAttempt func() error
	// DispatchGuard holds a bounded cross-process authorization lease for each attempt.
	DispatchGuard DispatchGuard
}

// UploadResponse is the service's acknowledgement of an accepted job.
type UploadResponse struct {
	JobID          string `json:"job_id"`
	Status         string `json:"status"`
	CloudSessionID string `json:"cloud_session_id"`
	// IdempotencyKey is the client key sent for this upload (set by the client
	// for the caller's observability; not part of the wire response).
	IdempotencyKey string `json:"-"`
}

// Upload submits an evidence envelope. The body is exactly req.Envelope; the
// PoP body digest and the declared upload digest must agree with those bytes
// (an internal invariant the client enforces). The Idempotency-Key binds device
// + cloud session + feature + schema + upload digest (Sol SC10); retries of the
// same upload carry the same key, so the server returns the same job.
func (c *Client) Upload(ctx context.Context, req UploadRequest) (UploadResponse, error) {
	if len(req.Envelope) == 0 {
		return UploadResponse{}, fmt.Errorf("cloudclient.Upload: empty envelope")
	}
	if req.CloudSessionID == "" {
		return UploadResponse{}, fmt.Errorf("cloudclient.Upload: empty cloud session id")
	}
	if req.Feature == "" {
		return UploadResponse{}, fmt.Errorf("cloudclient.Upload: empty feature")
	}
	schema := req.SchemaVersion
	if schema == "" {
		schema = cloudcontract.EnvelopeSchemaVersion
	}
	// Invariant: the client sends exact bytes, so the declared upload digest
	// must match those bytes. A mismatch means the caller re-serialized or
	// tampered — refuse rather than sign a lie.
	actual := cloudpop.BodyDigest(req.Envelope)
	if req.Digests.Upload != "" && req.Digests.Upload != actual {
		return UploadResponse{}, fmt.Errorf("cloudclient.Upload: declared upload digest %q != body digest %q", req.Digests.Upload, actual)
	}
	idem := idempotencyKey(c.dev.thumbprint, req.CloudSessionID, req.Feature, schema, actual)

	raw, err := c.sendAuthed(ctx, req.PreAttempt, req.DispatchGuard, func(int) (*http.Request, error) {
		return c.buildAuthed(ctx, http.MethodPost, "/v1/jobs", req.Envelope, map[string]string{
			"Content-Type":    "application/json",
			headerIdempotency: idem,
			headerFeature:     req.Feature,
		})
	})
	if err != nil {
		return UploadResponse{}, fmt.Errorf("cloudclient.Upload: %w", err)
	}
	var out UploadResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return UploadResponse{}, fmt.Errorf("cloudclient.Upload: decode response: %w", err)
	}
	out.IdempotencyKey = idem
	return out, nil
}

// PreviewConfirmRequest carries the two-digest binding a node registers before
// uploading an evidence envelope. The server records a consent receipt keyed on
// (account, upload_digest); the subsequent Upload of those EXACT bytes is then
// admitted (the two-digest preview-truth invariant). The field set mirrors the
// server's /v1/consents/preview-confirmation contract.
type PreviewConfirmRequest struct {
	Purposes        []string
	FieldClasses    []string
	EvidenceSchema  string
	ScrubberVersion string
	RetentionPolicy string
	Endpoint        string
	UploadDigest    string
	ContentDigest   string
}

// PreviewConfirmResponse is the server's acknowledgement of a recorded
// preview-confirmation.
type PreviewConfirmResponse struct {
	ReceiptID  string `json:"receipt_id"`
	Generation int64  `json:"generation"`
}

// previewConfirmWire is the exact JSON body /v1/consents/preview-confirmation
// decodes — the field names are load-bearing and must equal the server contract.
type previewConfirmWire struct {
	Purposes        []string `json:"purposes,omitempty"`
	FieldClasses    []string `json:"field_classes,omitempty"`
	EvidenceSchema  string   `json:"evidence_schema"`
	ScrubberVersion string   `json:"scrubber_version"`
	RetentionPolicy string   `json:"retention_policy,omitempty"`
	Endpoint        string   `json:"endpoint,omitempty"`
	UploadDigest    string   `json:"upload_digest"`
	ContentDigest   string   `json:"evidence_content_digest"`
}

// PreviewConfirm registers the two digests of the EXACT bytes a subsequent
// Upload will carry, so the server admits that upload instead of refusing it
// with reconfirmation_required. It must be called with the same upload digest
// the Upload body hashes to. Authenticated (stored API token + fresh PoP);
// returns ErrNotAuthenticated when no token is stored.
func (c *Client) PreviewConfirm(ctx context.Context, req PreviewConfirmRequest) (PreviewConfirmResponse, error) {
	if req.UploadDigest == "" {
		return PreviewConfirmResponse{}, fmt.Errorf("cloudclient.PreviewConfirm: empty upload digest")
	}
	schema := req.EvidenceSchema
	if schema == "" {
		schema = cloudcontract.EnvelopeSchemaVersion
	}
	body, err := json.Marshal(previewConfirmWire{
		Purposes:        req.Purposes,
		FieldClasses:    req.FieldClasses,
		EvidenceSchema:  schema,
		ScrubberVersion: req.ScrubberVersion,
		RetentionPolicy: req.RetentionPolicy,
		Endpoint:        req.Endpoint,
		UploadDigest:    req.UploadDigest,
		ContentDigest:   req.ContentDigest,
	})
	if err != nil {
		return PreviewConfirmResponse{}, fmt.Errorf("cloudclient.PreviewConfirm: encode body: %w", err)
	}
	raw, err := c.sendAuthed(ctx, nil, nil, func(int) (*http.Request, error) {
		return c.buildAuthed(ctx, http.MethodPost, "/v1/consents/preview-confirmation", body, map[string]string{
			"Content-Type": "application/json",
		})
	})
	if err != nil {
		return PreviewConfirmResponse{}, fmt.Errorf("cloudclient.PreviewConfirm: %w", err)
	}
	var out PreviewConfirmResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return PreviewConfirmResponse{}, fmt.Errorf("cloudclient.PreviewConfirm: decode response: %w", err)
	}
	return out, nil
}

// --- results ---------------------------------------------------------------

// ResultsPage is one page of enrichment results plus the cursor to fetch the
// next page. Results are typed ResultRecords (plan §6 CI-P4): each carries its
// cloud_session_id + provenance, so the node can associate a result with a
// local session (the CI-P3-flagged gap the wire record closes).
type ResultsPage struct {
	Results    []cloudcontract.ResultRecord `json:"results"`
	NextCursor string                       `json:"next_cursor"`
}

// Results fetches enrichment results newer than the opaque `after` cursor. It
// enforces the progress/non-repeat property WITHOUT a lexical ordering (FE5):
// the server's cursor is a decimal string, so "10" follows "9" even though it
// sorts lexicographically BEFORE it. A page that returns rows may not repeat
// `after` exactly, and — when both values parse as decimal integers — the
// numeric cursor may not go backwards. A non-numeric cursor (an opaque token)
// is subject only to the exact-repeat rule. Either violation is
// ErrCursorRegression rather than risking an infinite pull loop.
func (c *Client) Results(ctx context.Context, after string) (ResultsPage, error) {
	path := "/v1/results"
	if after != "" {
		path += "?after=" + urlQueryEscape(after)
	}
	raw, err := c.sendAuthed(ctx, nil, nil, func(int) (*http.Request, error) {
		return c.buildAuthed(ctx, http.MethodGet, path, nil, nil)
	})
	if err != nil {
		return ResultsPage{}, fmt.Errorf("cloudclient.Results: %w", err)
	}
	var page ResultsPage
	if err := json.Unmarshal(raw, &page); err != nil {
		return ResultsPage{}, fmt.Errorf("cloudclient.Results: decode response: %w", err)
	}
	if page.NextCursor != "" && after != "" {
		if len(page.Results) > 0 && page.NextCursor == after {
			return ResultsPage{}, fmt.Errorf("%w: rows returned but cursor did not advance from %q", ErrCursorRegression, after)
		}
		// Numeric backward-motion check ONLY when BOTH cursors parse as the SAME
		// numeric family (E1 / W6b): either both bare decimals (legacy global
		// seq) or both "v2:<n>" (the per-account cursor). The prefix is stripped
		// before the compare so a real regression on the account cursor still
		// fires. A mixed pair (a v2 cursor vs a bare decimal) or any unparseable
		// token falls back to the exact-repeat rule above ONLY — never a false
		// regression, since two different families are not numerically ordered
		// against each other. Lexical comparison is deliberately NOT used: "10"
		// < "9" as strings would wedge the sync.
		av, af, aok := parseCursorValue(after)
		nv, nf, nok := parseCursorValue(page.NextCursor)
		if aok && nok && af == nf && nv < av {
			return ResultsPage{}, fmt.Errorf("%w: next=%q < after=%q", ErrCursorRegression, page.NextCursor, after)
		}
	}
	return page, nil
}

// resultsAccountCursorPrefix marks a per-account (E1 / W6b) results cursor. The
// server emits "v2:<n>" on the account path and a bare decimal on the legacy
// global-seq path; the node round-trips whichever it received opaquely.
const resultsAccountCursorPrefix = "v2:"

// cursorFamily discriminates the two numeric cursor families so the
// monotonicity check never compares a per-account cursor against a legacy
// global one.
type cursorFamily int

const (
	cursorLegacy  cursorFamily = iota // bare decimal (global analysis_results.seq)
	cursorAccount                     // "v2:<n>" (per-account account_seq)
)

// parseCursorValue extracts a results cursor's numeric value AND its family.
// ok is false for any token that is neither a bare decimal nor a "v2:<decimal>"
// (an opaque cursor), in which case only the exact-repeat rule applies. Two
// cursors are compared numerically only when both parse ok AND share a family.
func parseCursorValue(c string) (uint64, cursorFamily, bool) {
	if rest, has := strings.CutPrefix(c, resultsAccountCursorPrefix); has {
		v, err := strconv.ParseUint(rest, 10, 64)
		if err != nil {
			return 0, cursorAccount, false
		}
		return v, cursorAccount, true
	}
	v, err := strconv.ParseUint(c, 10, 64)
	if err != nil {
		return 0, cursorLegacy, false
	}
	return v, cursorLegacy, true
}

// --- usage / plan ------------------------------------------------------------

// UsageView is the node's read of GET /v1/usage — the account's resolved
// plan, its per-window allowances, and (value-upgrade plan §W5) whether that
// plan includes the weekly project digest job kind and how long the hosted
// service keeps results.
//
// DigestWeekly and ResultsRetentionDays are POINTERS deliberately: an older
// server that predates the W5 hosted wave never emits these keys at all, so
// they decode to nil = "unknown" rather than a fabricated false/zero (the
// value-upgrade plan's honesty rule — the same discipline
// internal/store.CloudSyncLast's plan columns carry forward on the node
// side).
type UsageView struct {
	// Plan is the resolved plan's name (e.g. "free", "plus").
	Plan string `json:"plan"`
	// PlanLabel is the plan's user-facing label, verbatim.
	PlanLabel string `json:"plan_label"`
	// PlanVersion identifies the resolved plan definition.
	PlanVersion int `json:"plan_version"`
	// BudgetPool is the pool this account's reservations draw from.
	BudgetPool string `json:"budget_pool"`
	// DailyCap / MonthlyCap are the resolved plan's per-window allowances
	// for the session-enrichment feature.
	DailyCap   int `json:"daily_cap"`
	MonthlyCap int `json:"monthly_cap"`
	// DigestWeekly reports whether the resolved plan includes the weekly
	// project digest job kind. nil on a server that predates the field.
	DigestWeekly *bool `json:"digest_weekly"`
	// ResultsRetentionDays is how long the resolved plan keeps hosted
	// results. nil on a server that predates the field.
	ResultsRetentionDays *int `json:"results_retention_days"`
	// DigestsThisWeek is the count of project-digest results created in the
	// account's current ISO week, present only when DigestWeekly is true.
	DigestsThisWeek int `json:"digests_this_week,omitempty"`
}

// Usage fetches the authenticated account's current plan and allowances
// (GET /v1/usage). It is a plain authenticated read, exactly like Results —
// no new egress path, no request body, no consent purpose of its own (it
// rides whichever feature grant the caller already resolved).
func (c *Client) Usage(ctx context.Context) (UsageView, error) {
	raw, err := c.sendAuthed(ctx, nil, nil, func(int) (*http.Request, error) {
		return c.buildAuthed(ctx, http.MethodGet, "/v1/usage", nil, nil)
	})
	if err != nil {
		return UsageView{}, fmt.Errorf("cloudclient.Usage: %w", err)
	}
	var out UsageView
	if err := json.Unmarshal(raw, &out); err != nil {
		return UsageView{}, fmt.Errorf("cloudclient.Usage: decode response: %w", err)
	}
	return out, nil
}

// --- job status --------------------------------------------------------------

// JobStatus is the node's read of GET /v1/jobs/{id} (internal/cloudserver/api
// handleGetJob), which serves the hosted service's store.Job row verbatim.
// Field names and JSON tags are copied from that type exactly — this mirrors
// what the server actually returns, not a richer shape it might return later.
type JobStatus struct {
	// ID is the job's identifier (the CLOUD job id — e.g. the value
	// UploadResult.JobID carried at submit time — never the node's own local
	// outbox id).
	ID string `json:"id"`
	// State is the job's current lifecycle state, e.g. "queued", "leased",
	// "succeeded", "parked".
	State string `json:"state"`
	// TerminalReason is set once the job reached a terminal, non-retryable
	// state (e.g. "parked"); empty while the job is still in flight or on a
	// server that predates the field.
	TerminalReason string `json:"terminal_reason,omitempty"`
	// Feature is the feature this job belongs to (e.g. "session_enrichment").
	Feature string `json:"feature"`
	// Attempts is how many times this job has been leased and attempted.
	Attempts int `json:"attempts"`
	// CreatedAt is when the job was submitted.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the job's state last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// ErrJobNotFound means the server returned 404 for a job lookup: either the
// id is unknown, or it belongs to a different account (GetJob is tenant-
// scoped, so the two are indistinguishable from the outside — and must stay
// that way, so a lookup can never be used to probe another account's job ids).
var ErrJobNotFound = errors.New("cloudclient: job not found")

// Job fetches one hosted enrichment job's status (GET /v1/jobs/{id}) — a plain
// authenticated read, exactly like Results and Usage: no request body, no new
// egress path, no consent purpose of its own. A 404 is mapped to
// ErrJobNotFound so callers can classify it with errors.Is without inspecting
// the raw APIError status code.
func (c *Client) Job(ctx context.Context, id string) (JobStatus, error) {
	path := "/v1/jobs/" + urlQueryEscape(id)
	raw, err := c.sendAuthed(ctx, nil, nil, func(int) (*http.Request, error) {
		return c.buildAuthed(ctx, http.MethodGet, path, nil, nil)
	})
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return JobStatus{}, fmt.Errorf("cloudclient.Job: %w", ErrJobNotFound)
		}
		return JobStatus{}, fmt.Errorf("cloudclient.Job: %w", err)
	}
	var out JobStatus
	if err := json.Unmarshal(raw, &out); err != nil {
		return JobStatus{}, fmt.Errorf("cloudclient.Job: decode response: %w", err)
	}
	return out, nil
}

// --- logout ----------------------------------------------------------------

// Logout revokes THIS device's API token server-side (POST /v1/logout), so a
// copy of the bearer stops working the moment the node clears its local
// credential. It is device-bound and authenticated exactly like RequestDeletion:
// the stored API token plus a fresh proof-of-possession.
//
// It revokes the TOKEN, not the device registration — the same device can log in
// again with a fresh exchange. It returns ErrNotAuthenticated when no API token
// is stored, and the caller (`observer cloud logout`) treats EVERY failure as
// non-blocking: local credentials are cleared regardless, because a node that
// cannot reach the server must still be able to sign out of itself.
//
// Logout deliberately does NOT use the token self-heal (sendAuthed): a token the
// server already rejects needs no revocation, and minting a fresh one — rotating
// the WorkOS refresh token in the process — purely to revoke it a moment before
// the local clear would be wasted bootstrap egress.
func (c *Client) Logout(ctx context.Context) error {
	if _, err := c.sendRetryable(ctx, nil, func(int) (*http.Request, error) {
		return c.buildAuthed(ctx, http.MethodPost, "/v1/logout", nil, nil)
	}); err != nil {
		return fmt.Errorf("cloudclient.Logout: %w", err)
	}
	return nil
}

// --- deletion --------------------------------------------------------------

// DeletionResponse is the server's acknowledgement of an account-deletion
// request (POST /v1/deletion-requests). It mirrors the server's DeletionRequest
// shape; the node needs the id + state for its confirmation output.
type DeletionResponse struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// RequestDeletion asks the hosted service to delete the authenticated account
// (device-bound, authenticated by the stored API token + a fresh PoP proof).
// It returns ErrNotAuthenticated when no API token is stored (run Exchange /
// `observer cloud login` first). FF5: the CLI's `delete-account` invokes this
// so the command actually reaches the hosted deletion endpoint rather than
// exiting zero having done nothing.
func (c *Client) RequestDeletion(ctx context.Context) (DeletionResponse, error) {
	raw, err := c.sendAuthed(ctx, nil, nil, func(int) (*http.Request, error) {
		return c.buildAuthed(ctx, http.MethodPost, "/v1/deletion-requests", nil, nil)
	})
	if err != nil {
		return DeletionResponse{}, fmt.Errorf("cloudclient.RequestDeletion: %w", err)
	}
	var out DeletionResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return DeletionResponse{}, fmt.Errorf("cloudclient.RequestDeletion: decode response: %w", err)
	}
	return out, nil
}

// --- request plumbing ------------------------------------------------------

// buildAuthed constructs a request with an Authorization bearer and a FRESH PoP
// proof (a new jti/iat every call, so a retry is never rejected by the server's
// replay cache). It reads the stored API token via Cred.
func (c *Client) buildAuthed(ctx context.Context, method, path string, body []byte, headers map[string]string) (*http.Request, error) {
	token, err := c.cred.LoadAPIToken()
	if errors.Is(err, cloudcred.ErrNotFound) {
		return nil, ErrNotAuthenticated
	}
	if err != nil {
		return nil, fmt.Errorf("load api token: %w", err)
	}
	fullURL := c.baseURL + path
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	proof, err := cloudpop.Create(cloudpop.CreateParams{
		PrivateKey:  c.dev.priv,
		Method:      method,
		URL:         fullURL,
		AccessToken: token,
		IssuedAt:    c.clock(),
		Body:        body,
	})
	if err != nil {
		return nil, fmt.Errorf("mint proof: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(headerPoP, proof)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// sendRetryable runs build+send, retrying TRANSPORT errors only (never any HTTP
// status) up to maxRetries with jittered backoff. build is called afresh each
// attempt so the PoP proof carries a new jti/iat per attempt.
//
// preAttempt (FD3), when non-nil, is called immediately before each physical
// send — on the first attempt and before every retry, after the request (and
// any preparatory I/O the caller did before calling in) is built. A non-nil
// preAttempt error aborts without dispatching and is never retried: it is the
// caller's authorization re-check, not a transport fault.
func (c *Client) sendRetryable(ctx context.Context, preAttempt func() error, build func(attempt int) (*http.Request, error)) ([]byte, error) {
	return c.sendGuarded(ctx, preAttempt, nil, build)
}

// sendAuthed is sendGuarded for AUTHENTICATED requests, plus the ONE-SHOT API
// token self-heal. The device-bound API token is short-lived (server TTL, ~1h)
// while the persisted WorkOS sign-in is long-lived, so an aged-out token used
// to fail every feature call permanently until the user re-ran `observer cloud
// login`. Here, when the server rejects the bearer — a 401 whose body code is
// tokenRejectedCode, and ONLY that — the client re-exchanges ONCE through the
// same path `observer cloud login` uses (Exchange: WorkOS refresh → nonce →
// device-key PoP → new token stored via Cred) and re-sends the request ONCE.
// A second rejection, or a failed refresh, is ErrSignInExpired.
//
// This is the BOOTSTRAP lane (`account_device_operations`, R2 disposition
// F10): the re-exchange is authorized by the persisted sign-in, not by any
// consent grant, and it widens nothing — the request it repeats already passed
// the caller's consent check to reach this seam, and the repeat runs the same
// build (fresh PoP), preAttempt (grant re-check) and guard (dispatch lease) as
// any other attempt.
//
// Why RETRY-AFTER-401 rather than a pre-flight, and why it cannot double-send:
// the stored token is opaque (no expiry travels with it), so a pre-flight would
// need a network probe; and a token-rejected 401 is emitted by the server's
// auth middleware BEFORE the body is read or any handler runs, so the rejected
// attempt had no server-side effect — repeating it is indistinguishable from
// the transport retry sendGuarded already performs. Every upload additionally
// carries a deterministic Idempotency-Key, so even a hypothetically admitted
// first attempt would be replay-acked, never stored twice.
//
// Never loops: at most one heal per call, and a FAILED heal latches for the
// Client's lifetime so later calls fail fast without sending.
func (c *Client) sendAuthed(ctx context.Context, preAttempt func() error, guard DispatchGuard, build func(attempt int) (*http.Request, error)) ([]byte, error) {
	if err := c.healLatched(); err != nil {
		return nil, err // the sign-in is known-expired: do not send, do not re-exchange
	}
	body, err := c.sendGuarded(ctx, preAttempt, guard, build)
	if !tokenRejected(err) {
		return body, err
	}
	if herr := c.healToken(ctx, err); herr != nil {
		return nil, herr
	}
	body, err = c.sendGuarded(ctx, preAttempt, guard, build)
	if tokenRejected(err) {
		// The freshly minted token was rejected too. Latch: nothing this process
		// can do will make the next request succeed.
		return nil, c.latchHealFailure(fmt.Errorf("%w: the re-exchanged token was rejected as well: %w", ErrSignInExpired, err))
	}
	return body, err
}

// healToken performs the one-shot re-exchange behind sendAuthed. rejected is
// the 401 that triggered it, carried in the error when the refresh fails so the
// user sees both what the server said and what to do about it.
func (c *Client) healToken(ctx context.Context, rejected error) error {
	c.healMu.Lock()
	defer c.healMu.Unlock()
	if c.healFailed != nil {
		return c.healFailed
	}
	if c.broker == nil {
		c.healFailed = fmt.Errorf("%w: the API token was rejected (%w) and no identity broker is configured, so the persisted sign-in cannot be refreshed", ErrSignInExpired, rejected)
		return c.healFailed
	}
	if err := c.Exchange(ctx); err != nil {
		c.healFailed = fmt.Errorf("%w: the API token was rejected (%w) and refreshing the sign-in failed: %w", ErrSignInExpired, rejected, err)
		return c.healFailed
	}
	c.log.Info("cloudclient: expired API token re-exchanged through the persisted sign-in")
	if c.onHealed != nil {
		c.onHealed()
	}
	return nil
}

// healLatched returns the latched heal failure, if any.
func (c *Client) healLatched() error {
	c.healMu.Lock()
	defer c.healMu.Unlock()
	return c.healFailed
}

// latchHealFailure records err as the terminal heal outcome (first one wins)
// and returns the latched value.
func (c *Client) latchHealFailure(err error) error {
	c.healMu.Lock()
	defer c.healMu.Unlock()
	if c.healFailed == nil {
		c.healFailed = err
	}
	return c.healFailed
}

// tokenRejected reports whether err is the server refusing the BEARER: an HTTP
// 401 whose JSON body carries code tokenRejectedCode. A 401 with any other
// code, a non-JSON 401 body, any other status, and any transport error are all
// false — the self-heal reacts to exactly one refusal.
func tokenRejected(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		return false
	}
	var body struct {
		Code string `json:"code"`
	}
	if json.Unmarshal([]byte(apiErr.Body), &body) != nil {
		return false
	}
	return body.Code == tokenRejectedCode
}

// DispatchGuard is the cross-process DISPATCH LEASE hook a standing-rail upload
// (structural snapshot, community contribution) carries (Sol re-review N2). It
// is invoked immediately before EVERY physical attempt — AFTER PreAttempt, as
// the very last thing before the socket — and its release func immediately
// after the attempt returns.
//
// It returns the instant the lease expires. The client applies that instant as
// the attempt's request-context DEADLINE, so an attempt descheduled past its
// lease finds its request already dead before a byte is written: that is what
// makes a revoke's "wait until no lease can begin dispatch" bounded and true.
// A non-nil error refuses the attempt without dispatching and is never retried
// — it is the caller's consent state saying no, not a transport fault.
type DispatchGuard func(ctx context.Context) (expiresAt time.Time, release func(), err error)

// sendGuarded is sendRetryable with the dispatch-lease guard. Per attempt, in
// order: build the request (fresh PoP proof), run preAttempt, take the lease
// (guard), bound the request by the lease's expiry, dispatch, release.
func (c *Client) sendGuarded(ctx context.Context, preAttempt func() error, guard DispatchGuard, build func(attempt int) (*http.Request, error)) ([]byte, error) {
	var lastErr error
	for attempt := 0; ; attempt++ {
		req, err := build(attempt)
		if err != nil {
			return nil, err // build errors (e.g. not authenticated) are not retryable
		}
		if preAttempt != nil {
			if err := preAttempt(); err != nil {
				return nil, err // authorization revoked between prepare and dispatch — do not send
			}
		}
		body, err := c.dispatchLeased(ctx, req, guard)
		if err == nil {
			return body, nil
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			return nil, err // HTTP status errors are never retried (incl. 4xx)
		}
		lastErr = err // transport error
		if attempt >= c.maxRetries {
			break
		}
		if err := sleep(ctx, c.backoff(attempt)); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("transport error after %d attempt(s): %w", c.maxRetries+1, lastErr)
}

// dispatchLeased takes the dispatch lease (when a guard is set), bounds the
// request by the lease's expiry, sends once, and releases. Without a guard it
// is exactly sendOnce.
func (c *Client) dispatchLeased(ctx context.Context, req *http.Request, guard DispatchGuard) ([]byte, error) {
	if guard == nil {
		return c.sendOnce(req)
	}
	expiresAt, release, err := guard(ctx)
	if err != nil {
		return nil, err // the lease was refused: the receipt is no longer live — do not send
	}
	if release != nil {
		defer release()
	}
	if !expiresAt.IsZero() {
		// The lease's own expiry becomes the attempt's deadline. Go's transport
		// checks the context before it dials or writes, so a request whose lease
		// has already lapsed never reaches the wire.
		actx, cancel := context.WithDeadline(ctx, expiresAt)
		defer cancel()
		req = req.WithContext(actx)
	}
	return c.sendOnce(req)
}

// sendOnce performs a single request and returns the body for a 2xx, or an
// *APIError for a non-2xx, or the raw transport error.
func (c *Client) sendOnce(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	return body, nil
}

// sleep waits d or returns ctx's error if it is cancelled first.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// defaultBackoff is exponential with full jitter, capped at 5s.
func defaultBackoff(attempt int) time.Duration {
	base := 100 * time.Millisecond * (1 << attempt)
	if base > 5*time.Second {
		base = 5 * time.Second
	}
	return time.Duration(rand.Int64N(int64(base) + 1)) //nolint:gosec // backoff jitter, not a security context — math/rand/v2 is correct here
}

// urlQueryEscape percent-encodes a query value without importing net/url at the
// call site (keeps the escaping explicit and minimal for opaque cursors).
func urlQueryEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '.' || ch == '_' || ch == '~' {
			b.WriteByte(ch)
			continue
		}
		const hexd = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hexd[ch>>4])
		b.WriteByte(hexd[ch&0x0f])
	}
	return b.String()
}
