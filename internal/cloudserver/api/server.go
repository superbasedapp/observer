// Package api is the ONLY HTTP owner for the hosted cloud-intelligence service
// (plan §6 CI-P3). It maps the /v1 surface to the store, enforcing device-bound
// authentication + per-request proof-of-possession + jti replay defense on
// every device endpoint. Account scope ALWAYS comes from the verified auth
// context, never a request-body field.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	clouddb "github.com/marmutapp/superbased-observer/internal/cloudserver/db"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// maxBodyBytes bounds request bodies (the largest is an evidence envelope).
const maxBodyBytes = 2 << 20 // 2 MiB

// Options configures a Server.
type Options struct {
	Store    *store.Store
	Queue    jobs.Queue
	Verifier identity.Verifier // broker token verifier (dev-auth or WorkOS)
	PoP      PoPVerifier       // nil ⇒ CloudPoPVerifier
	Now      func() time.Time  // nil ⇒ time.Now
	Logger   *slog.Logger
	// ClockSkew feeds BOTH halves of the cloudpop iat window: how far in the
	// past (MaxAge) and how far in the future (MaxSkew) a proof's iat may be.
	ClockSkew time.Duration
	NonceTTL  time.Duration
	TokenTTL  time.Duration
	// ExternalBaseURL is the absolute externally-visible origin (scheme +
	// host[:port], no trailing slash or path) this server is reachable at.
	// It is the ONLY source for htu reconstruction — the request path is
	// appended to it verbatim. The server never trusts Host or
	// X-Forwarded-* headers for this (a Cloudflare-fronted prod deployment
	// revisits this at launch; see cmd/observer-cloud's SBCI_EXTERNAL_BASE_URL).
	ExternalBaseURL string
	// PortalBaseURL is the absolute externally-visible origin (scheme +
	// host[:port], no trailing slash or path) the PORTAL is reachable at, when
	// the deployment splits the two surfaces across two names (R5:
	// app.superbased.app for /portal/*, cloud.superbased.app for /v1/*).
	//
	// EMPTY ⇒ it falls back to ExternalBaseURL, which is the single-host
	// staging posture and is byte-identical to the pre-split behaviour.
	//
	// It is the origin the browser sign-in leg is anchored to: the OAuth
	// redirect_uri is PortalBaseURL + the callback path (minted at start,
	// re-checked at callback), and it is the origin whose scheme decides the
	// portal cookie shape (see cmd/observer-cloud, which derives
	// PortalSecureCookie from THIS base). ExternalBaseURL keeps its own job —
	// reconstructing the device API's proof-of-possession htu — and the two
	// must not be conflated once the hosts differ.
	PortalBaseURL string
	// PortalSecureCookie selects the portal session-cookie shape: true ⇒ the
	// hardened `__Host-sbci` name with the Secure attribute (https origins);
	// false ⇒ the unprefixed, non-Secure `sbci_session` fallback that is the
	// only thing that works over plain http (local dev). It is a stable
	// server-level property, NOT derived per-request from r.TLS (behind
	// Cloudflare, TLS terminates at the edge and r.TLS is nil), so set it from
	// the external origin's scheme (see cmd/observer-cloud).
	PortalSecureCookie bool
	// PortalSPA is the http.Handler that serves the embedded webcloud SPA under
	// /portal/. Nil ⇒ portal UI routes 404 (BFF endpoints still work), which is
	// the pre-build state.
	PortalSPA http.Handler
	// RateLimit is the per-IP/device/account rate-limit policy (plan §6 CI-P6).
	// Nil ⇒ load it from the SBCI_RATELIMIT_* environment (with sane defaults) —
	// the production wiring path, which needs no change in cmd/observer-cloud.
	// A non-nil pointer (even the zero value, which disables every dimension) is
	// used verbatim: tests pass &RateLimitConfig{} to opt out.
	RateLimit *RateLimitConfig
	// SharedRateLimiter is the atomic cross-replica counter backend. Production
	// normally lets New discover the Postgres implementation on Store; this
	// field is useful for tests and alternate shared backends. RateLimit controls
	// policy only and does not select a local counter when a Store implements the
	// shared contract.
	SharedRateLimiter RateLimiter
	// Edge is the origin/Cloudflare trust boundary. When enabled, all routes
	// except /healthz require a trusted proxy hop and exactly one canonical
	// client identity in the private X-SBCI-Client-IP header (the Worker copies
	// the inbound Cloudflare visitor IP into it; the reserved CF-Connecting-IP
	// is never trusted). Leaving it disabled is the local/direct-origin posture;
	// forwarded headers are ignored there.
	Edge EdgeConfig
	// Attestor + Credentials drive the admission-time policy check (FA6): §2.2
	// requires a fresh matching attestation + credential posture at ENQUEUE as
	// well as at execution. handleSubmitJob resolves the exact route and verifies
	// a fresh attestation + present credential BEFORE reserving allowance or
	// storing evidence — so an unbound route, a stale/unhealthy canary, or an
	// absent credential refuses the job up front instead of taking custody of
	// user evidence for a job the worker will only park.
	//
	// The gate is FAIL-CLOSED: if EITHER is nil, every job is refused with 503
	// provider_policy_unverified and NO evidence is stored. A credential-absent
	// staging server (cmd/observer-cloud `serve` wires chooseAttestor +
	// chooseCredentials, the latter resolving to AbsentCredentials pre-approval)
	// therefore refuses jobs while still exercising the full auth/PoP/digest path.
	// Never leave these nil for a server intended to accept jobs.
	Attestor    jobs.ProviderAttestor
	Credentials jobs.CredentialSource

	// --- WorkOS browser sign-in leg (plan §3 W1) ---
	//
	// PortalWorkOSEnabled is the ACTIVATION GATE (SBCI_PORTAL_WORKOS=1). It is
	// false by default and every /portal/auth/workos/* route answers an honest
	// 501 while it is: browser sign-in stays dev-auth-only until the R7 exposure
	// gates are green, so the leg can never ship by deploy accident.
	PortalWorkOSEnabled bool
	// WorkOSClientID is the public AuthKit client id (WORKOS_CLIENT_ID) — the
	// same value the identity verifier binds tokens to.
	WorkOSClientID string
	// WorkOSAPIKey is the WorkOS client secret (WORKOS_API_KEY). It is used ONLY
	// for the server-side authorization-code exchange and never leaves this
	// process; the browser never sees it.
	WorkOSAPIKey string
	// WorkOSAuthorizeURL / WorkOSTokenURL locate the AuthKit endpoints. Empty ⇒
	// the WorkOS production URLs; tests inject a local fake.
	WorkOSAuthorizeURL string
	WorkOSTokenURL     string
	// WorkOSHTTPClient overrides the HTTP client used for the token exchange.
	// Nil ⇒ a 10-second-timeout client.
	WorkOSHTTPClient *http.Client
	// WorkOSWebhookSecret (WORKOS_WEBHOOK_SECRET) is the shared secret the
	// account-lifecycle webhook's `WorkOS-Signature` HMAC is verified against.
	// EMPTY ⇒ POST /portal/webhooks/workos answers 501 and reads nothing: an
	// unauthenticated route that verified nothing would be an
	// account-revocation lever for anyone who can reach the origin, so the
	// unconfigured state fails closed rather than open.
	WorkOSWebhookSecret string

	// PortalSessionTTL / PortalSessionIdleTTL are the portal browser-session
	// ABSOLUTE and IDLE lifetimes (Wave C, gap 2.4 residual (a); operator
	// ruling 2026-09-11: 24h absolute, 2h idle with rolling refresh on
	// authenticated activity — see store.DefaultBrowserSessionTTL /
	// store.DefaultBrowserSessionIdleTTL). Zero (the default) ⇒ those
	// constants; env-overridable in cmd/observer-cloud via
	// SBCI_PORTAL_SESSION_TTL / SBCI_PORTAL_SESSION_IDLE_TTL. Both halves are
	// threaded through every PortalLogin/IntrospectBrowserSession call site so
	// they never disagree about which idle window a session was minted under
	// versus what a later roll advances it by.
	PortalSessionTTL     time.Duration
	PortalSessionIdleTTL time.Duration

	// PaddleWebhookSecret (SBCI_PADDLE_WEBHOOK_SECRET) is the CURRENT secret the
	// W9 billing webhook's `Paddle-Signature` HMAC is verified against. EMPTY
	// (with PaddleWebhookSecrets also empty) ⇒ POST /portal/webhooks/paddle
	// answers 501 and reads nothing (fail-closed: an unverified billing webhook
	// would be a plan-escalation lever). Dark until the operator provisions the
	// Paddle account + secret.
	PaddleWebhookSecret string
	// PaddleWebhookSecrets holds ADDITIONAL accepted secrets — e.g. the
	// previous secret during a rotation window (SBCI_PADDLE_WEBHOOK_SECRET_
	// PREVIOUS) — composed with PaddleWebhookSecret so every currently-valid
	// secret authenticates a delivery (A3 / gap 1.7: a secret rotation must
	// never be an outage).
	PaddleWebhookSecrets []string
	// PaddleCheckout is the validated portal checkout catalogue (A4/A5/A6 —
	// environment, client token, prices, trial length) GET /portal/api/billing
	// exposes. Zero value ⇒ Available() is false, the honest dark posture.
	PaddleCheckout PaddleCheckout

	// --- Canonical hosts (plan §2 R5) ---
	//
	// PortalHost / APIHost are the exact public names that serve /portal/* and
	// /v1/* respectively (e.g. "app.superbased.app" and "cloud.superbased.app").
	// A request for one of those prefixes arriving on any OTHER Host is answered
	// 421 Misdirected Request.
	//
	// Both are OPTIONAL and independent: empty ⇒ that surface is unenforced,
	// which is the single-host staging/dev deployment. /healthz is host-agnostic
	// in every configuration. Values are normalized (lowercased, port stripped)
	// at New, so configuring "App.Example:443" still matches a plain
	// "app.example" Host.
	PortalHost string
	APIHost    string

	// --- Root redirect (bare-domain Paddle domain-review fix) ---
	//
	// RootRedirectURL selects the "/" (exact match only) redirect target on
	// this server's own origin. nil ⇒ resolved from SBCI_ROOT_REDIRECT_URL,
	// defaulting to https://superbased.app/ when that env var is unset too
	// (see rootRedirectURLFromEnv in rootredirect.go — the same
	// nil-means-load-from-env / non-nil-means-verbatim convention RateLimit
	// uses above). A non-nil pointer is used exactly as given, so passing a
	// pointer to "" deliberately disables the redirect and keeps the bare
	// 404 (tests use this to pin the disabled posture). The resolved value is
	// validated at New (absolute http(s) URL with a host); a malformed value
	// fails closed by disabling the redirect rather than serving a broken
	// one, and logs the rejection.
	RootRedirectURL *string
}

// Production AuthKit endpoints (the same pair internal/cloudclient uses for the
// CLI's loopback PKCE flow).
const (
	defaultWorkOSAuthorizeURL = "https://api.workos.com/user_management/authorize"
	defaultWorkOSTokenURL     = "https://api.workos.com/user_management/authenticate" //nolint:gosec // G101: public WorkOS endpoint URL, not a credential
)

// Server holds the wired dependencies.
type Server struct {
	store              *store.Store
	queue              jobs.Queue
	verifier           identity.Verifier
	pop                PoPVerifier
	now                func() time.Time
	log                *slog.Logger
	clockSkew          time.Duration
	nonceTTL           time.Duration
	tokenTTL           time.Duration
	externalBaseURL    string
	portalBaseURL      string
	portalSecureCookie bool
	portalSPA          http.Handler
	rl                 *rateLimiters
	edge               edgeConfig
	attestor           jobs.ProviderAttestor
	credentials        jobs.CredentialSource

	portalWorkOSEnabled  bool
	workOSClientID       string
	workOSAPIKey         string
	workOSAuthorizeURL   string
	workOSTokenURL       string
	workOSHTTP           *http.Client
	workOSWebhookSecret  string
	paddleWebhookSecrets []string
	paddleCheckout       PaddleCheckout

	portalSessionTTL     time.Duration
	portalSessionIdleTTL time.Duration

	// Normalized canonical hosts; "" ⇒ that surface is unenforced.
	portalHost string
	apiHost    string

	// rootRedirectURL is the validated "/" redirect target; "" ⇒ the route is
	// not registered and "/" stays 404 (see rootredirect.go).
	rootRedirectURL string
}

// New builds a Server, applying defaults.
func New(o Options) *Server {
	s := &Server{
		store: o.Store, queue: o.Queue, verifier: o.Verifier, pop: o.PoP,
		now: o.Now, log: o.Logger, clockSkew: o.ClockSkew, nonceTTL: o.NonceTTL, tokenTTL: o.TokenTTL,
		externalBaseURL:    strings.TrimRight(o.ExternalBaseURL, "/"),
		portalBaseURL:      strings.TrimRight(strings.TrimSpace(o.PortalBaseURL), "/"),
		portalSecureCookie: o.PortalSecureCookie,
		portalSPA:          o.PortalSPA,
		edge:               parseEdgeConfig(o.Edge),
		attestor:           o.Attestor,
		credentials:        o.Credentials,

		portalWorkOSEnabled:  o.PortalWorkOSEnabled,
		workOSClientID:       strings.TrimSpace(o.WorkOSClientID),
		workOSAPIKey:         strings.TrimSpace(o.WorkOSAPIKey),
		workOSAuthorizeURL:   strings.TrimSpace(o.WorkOSAuthorizeURL),
		workOSTokenURL:       strings.TrimSpace(o.WorkOSTokenURL),
		workOSHTTP:           o.WorkOSHTTPClient,
		workOSWebhookSecret:  strings.TrimSpace(o.WorkOSWebhookSecret),
		paddleWebhookSecrets: composePaddleWebhookSecrets(o.PaddleWebhookSecret, o.PaddleWebhookSecrets),
		paddleCheckout:       o.PaddleCheckout,

		portalSessionTTL:     o.PortalSessionTTL,
		portalSessionIdleTTL: o.PortalSessionIdleTTL,

		portalHost: normalizeHost(o.PortalHost),
		apiHost:    normalizeHost(o.APIHost),
	}
	// The portal origin defaults to the API origin: one host serves both, which
	// is the staging shape and keeps this landing behaviour-preserving there.
	if s.portalBaseURL == "" {
		s.portalBaseURL = s.externalBaseURL
	}
	if s.workOSAuthorizeURL == "" {
		s.workOSAuthorizeURL = defaultWorkOSAuthorizeURL
	}
	if s.workOSTokenURL == "" {
		s.workOSTokenURL = defaultWorkOSTokenURL
	}
	if s.workOSHTTP == nil {
		s.workOSHTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if s.pop == nil {
		s.pop = CloudPoPVerifier{}
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.clockSkew <= 0 {
		s.clockSkew = 60 * time.Second
	}
	if s.nonceTTL <= 0 {
		s.nonceTTL = store.DefaultNonceTTL
	}
	if s.tokenTTL <= 0 {
		s.tokenTTL = store.DefaultTokenTTL
	}
	// Rate limiting: nil ⇒ load from SBCI_RATELIMIT_* (defaults active); a
	// supplied config (even all-zero = fully disabled) is used verbatim. The
	// normal production path is shared: Store's implementation is discovered
	// through the narrow RateLimiter contract. An explicit backend always wins;
	// the process-local implementation is used only when a caller deliberately
	// supplies a policy without a Store/backend (test or single-process dev).
	rlCfg := o.RateLimit
	if rlCfg == nil {
		c := RateLimitConfigFromEnv()
		rlCfg = &c
	}
	backend := o.SharedRateLimiter
	if backend == nil && o.Store != nil {
		// Keep the store package free of an API import while allowing its
		// concrete Store to satisfy the contract. If the method is missing, use
		// the fail-closed sentinel below rather than silently reverting to local
		// counters in a horizontally-scaled deployment.
		if shared, ok := any(o.Store).(RateLimiter); ok {
			backend = shared
		}
	}
	if backend == nil {
		if o.RateLimit != nil {
			backend = NewInMemoryRateLimiter(s.now)
		} else {
			backend = unavailableRateLimiter{}
		}
	}
	s.rl = newRateLimitersWithBackend(*rlCfg, backend)

	// Root redirect: nil ⇒ SBCI_ROOT_REDIRECT_URL (default
	// https://superbased.app/); non-nil is used verbatim, including "" to
	// disable. Validated here so New never hands Handler a target that isn't
	// an absolute http(s) URL; a malformed value fails CLOSED (the redirect
	// stays off, "/" stays 404) rather than serving a broken redirect.
	rawRootRedirect := rootRedirectURLFromEnv()
	if o.RootRedirectURL != nil {
		rawRootRedirect = *o.RootRedirectURL
	}
	rootRedirect, err := validateRootRedirectURL(rawRootRedirect)
	if err != nil {
		s.log.Error("cloudserver/api: invalid root redirect URL, leaving / at 404", "err", err)
		rootRedirect = ""
	}
	s.rootRedirectURL = rootRedirect

	return s
}

// Handler returns the routed http.Handler. Public routes (nonce, exchange,
// health) are unauthenticated; every device route is wrapped by authenticate.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public. healthz is unlimited (probes); the two auth-bootstrap endpoints
	// are the unauthenticated abuse points, so they carry the per-IP cap.
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.Handle("GET /v1/auth/nonce", s.rateLimitIP(http.HandlerFunc(s.handleNonce)))
	mux.Handle("POST /v1/auth/exchange", s.rateLimitIP(http.HandlerFunc(s.handleExchange)))

	// Device-authenticated (Bearer + PoP + jti replay).
	mux.Handle("GET /v1/devices", s.authenticate(http.HandlerFunc(s.handleListDevices)))
	mux.Handle("DELETE /v1/devices/{id}", s.authenticate(http.HandlerFunc(s.handleDeleteDevice)))
	mux.Handle("GET /v1/consents", s.authenticate(http.HandlerFunc(s.handleGetConsents)))
	mux.Handle("PUT /v1/consents", s.authenticate(http.HandlerFunc(s.handlePutConsents)))
	mux.Handle("POST /v1/consents/preview-confirmation", s.authenticate(http.HandlerFunc(s.handlePreviewConfirmation)))
	mux.Handle("POST /v1/intelligence/jobs", s.authenticate(http.HandlerFunc(s.handleSubmitJob)))
	mux.Handle("GET /v1/intelligence/jobs/{id}", s.authenticate(http.HandlerFunc(s.handleGetJob)))
	// Aliases: internal/cloudclient (client.go's Upload/Results callers) and
	// cmd/observer/cloud.go both hardcode "/v1/jobs" — a stale path that
	// predates this handler's move to "/v1/intelligence/jobs" (the route the
	// design doc and store.Job's GET comment both document as canonical).
	// Mount the same handlers under the client's actual path rather than
	// editing the client (out of this package's footprint, and not a
	// proof-of-possession format bug); the canonical route stays primary.
	mux.Handle("POST /v1/jobs", s.authenticate(http.HandlerFunc(s.handleSubmitJob)))
	mux.Handle("GET /v1/jobs/{id}", s.authenticate(http.HandlerFunc(s.handleGetJob)))
	// W2 structural-insights rail: one immutable per-device window per POST,
	// under the account's STANDING grant. Device PoP like every /v1 route.
	mux.Handle("POST /v1/structural-insights", s.authenticate(http.HandlerFunc(s.handleStructuralInsights)))
	mux.Handle("GET /v1/results", s.authenticate(http.HandlerFunc(s.handleResults)))
	// W6c (D12/R6): the node syncs a local override up as an ETag-guarded,
	// idempotent, append-only revision (source=node). Device PoP like every /v1.
	mux.Handle("PATCH /v1/results/{id}/correction", s.authenticate(http.HandlerFunc(s.handleResultCorrection)))
	mux.Handle("GET /v1/usage", s.authenticate(http.HandlerFunc(s.handleUsage)))
	// W5 own-percentile read surface (private community bands + own placement).
	mux.Handle("GET /v1/community/percentile", s.authenticate(http.HandlerFunc(s.handleCommunityPercentile)))
	// W5 contribution-upload path: one derived per-window value per POST, under
	// the account's STANDING community_cohort_benchmarking grant. Device PoP.
	mux.Handle("POST /v1/community/contribution", s.authenticate(http.HandlerFunc(s.handleCommunityContribution)))
	mux.Handle("POST /v1/deletion-requests", s.authenticate(http.HandlerFunc(s.handleDeletionRequest)))
	// W6d (D11): the device assembles a portable export of its own account data
	// (device PoP is the strong factor, like the device deletion path) and
	// downloads the encrypted-at-rest artifact within its ≤7-day TTL.
	mux.Handle("POST /v1/export", s.authenticate(http.HandlerFunc(s.handleExportRequest)))
	mux.Handle("GET /v1/exports/{id}", s.authenticate(http.HandlerFunc(s.handleExportDownload)))
	// D17: the device gives up its OWN bearer. Behind authenticate, so the token
	// it revokes is the verified one the middleware resolved — never a token id
	// named in a request body.
	mux.Handle("POST /v1/logout", s.authenticate(http.HandlerFunc(s.handleLogout)))

	// --- Portal (app.superbased.app) — the signed-in-free BROWSER surface.
	// Cookie-auth + double-submit CSRF (portalAuth), NOT the device PoP path.
	// login is public (no cookie yet) ⇒ per-IP capped; every other portal
	// endpoint is wrapped by portalAuth (which carries the per-account cap).
	mux.Handle("POST /portal/auth/login", s.rateLimitIP(http.HandlerFunc(s.handlePortalLogin)))
	mux.Handle("POST /portal/auth/logout", s.portalAuth(http.HandlerFunc(s.handlePortalLogout)))
	// The WorkOS leg is public (the start has no session yet, and the callback
	// arrives cross-site carrying only the Lax transaction cookie) ⇒ per-IP
	// capped, exactly like the other unauthenticated auth-bootstrap endpoints.
	// It is dark until PortalWorkOSEnabled (see portalWorkOSReady).
	mux.Handle("GET /portal/auth/workos/start", s.rateLimitIP(http.HandlerFunc(s.handleWorkOSStart)))
	mux.Handle("GET "+workOSCallbackPath, s.rateLimitIP(http.HandlerFunc(s.handleWorkOSCallback)))
	// The signed-out bootstrap (F12): which sign-in surface should the SPA
	// render? It is deliberately unauthenticated — a browser holding no session
	// is exactly who needs the answer — and returns no account-scoped data at
	// all, only this deployment's own auth-mode configuration.
	mux.Handle("GET /portal/api/auth-config", s.rateLimitIP(http.HandlerFunc(s.handlePortalAuthConfig)))
	mux.Handle("GET /portal/api/session", s.portalAuth(http.HandlerFunc(s.handlePortalSession)))
	mux.Handle("GET /portal/api/overview", s.portalAuth(http.HandlerFunc(s.handlePortalOverview)))
	mux.Handle("GET /portal/api/usage", s.portalAuth(http.HandlerFunc(s.handlePortalUsage)))
	mux.Handle("GET /portal/api/digests", s.portalAuth(http.HandlerFunc(s.handlePortalDigests)))
	mux.Handle("GET /portal/api/devices", s.portalAuth(http.HandlerFunc(s.handlePortalDevices)))
	mux.Handle("DELETE /portal/api/devices/{id}", s.portalAuth(http.HandlerFunc(s.handlePortalRevokeDevice)))
	// "Sign out everywhere" (Wave C, gap 2.4 residual (b)): the browser-session
	// sibling of the device list above — same cookie-auth + CSRF discipline,
	// distinct credential (a portal session, not a device registration).
	mux.Handle("GET /portal/api/sessions/browser", s.portalAuth(http.HandlerFunc(s.handlePortalListBrowserSessions)))
	mux.Handle("POST /portal/api/sessions/browser/revoke-all", s.portalAuth(http.HandlerFunc(s.handlePortalRevokeAllBrowserSessions)))
	mux.Handle("GET /portal/api/consents", s.portalAuth(http.HandlerFunc(s.handlePortalConsents)))
	// W2 Overview v2 + Privacy (D19): the account-day materialization and the
	// standing-grant registrations. Both are READS of data the account's own
	// devices uploaded under its own grant — same session-cookie auth, same
	// CSRF discipline (GET is exempt), same per-account cap as every other
	// portal route.
	mux.Handle("GET /portal/api/insights", s.portalAuth(http.HandlerFunc(s.handlePortalInsights)))
	// W5 portal Community surface: own placement + the metric/cohort definitions.
	mux.Handle("GET /portal/api/community", s.portalAuth(http.HandlerFunc(s.handlePortalCommunity)))
	mux.Handle("GET /portal/api/community/metrics", s.portalAuth(http.HandlerFunc(s.handlePortalCommunityMetrics)))
	// W9 portal Billing surface: current subscription + plan.
	mux.Handle("GET /portal/api/billing", s.portalAuth(http.HandlerFunc(s.handlePortalBilling)))
	// G2-07/F2 server-initiated checkout: mint a server-set custom_data + nonce.
	mux.Handle("POST /portal/api/billing/checkout", s.portalAuth(http.HandlerFunc(s.handlePortalCheckout)))
	mux.Handle("GET /portal/api/grants", s.portalAuth(http.HandlerFunc(s.handlePortalGrants)))
	// The browser consent screen's own state (F9). Distinct from
	// /portal/api/consents, which reports the NODE-authoritative consent
	// generation and granted purposes the device path records: this pair is the
	// PORTAL-plane preference store. See portalconsent.go's scope note.
	mux.Handle("GET /portal/api/consent", s.portalAuth(http.HandlerFunc(s.handlePortalConsentChoices)))
	mux.Handle("POST /portal/api/consent", s.portalAuth(http.HandlerFunc(s.handlePortalSetConsentChoices)))
	// W6c (D4/D12/R6): the portal Sessions surface — a paginated list of the
	// account's enriched sessions, per-session detail with each result's
	// immutable AI original + append-only revision history, and the portal-plane
	// edit path (source=portal). All READS are session-cookie-auth (CSRF-exempt
	// GET); the correction POST carries the double-submit CSRF like every portal
	// mutation.
	mux.Handle("GET /portal/api/sessions", s.portalAuth(http.HandlerFunc(s.handlePortalSessions)))
	mux.Handle("GET /portal/api/sessions/{id}", s.portalAuth(http.HandlerFunc(s.handlePortalSessionDetail)))
	mux.Handle("POST /portal/api/results/{id}/correction", s.portalAuth(http.HandlerFunc(s.handlePortalResultCorrection)))
	mux.Handle("POST /portal/api/deletion-requests", s.portalAuth(http.HandlerFunc(s.handlePortalDeletionRequest)))
	// W6d (D11): the portal export surface — the deletion flow offers "download
	// your data first". Assembly requires the Doc B §3.2 export reauth/step-up
	// (POST, CSRF-guarded); the list + download are session-authed reads.
	mux.Handle("POST /portal/api/exports", s.portalAuth(http.HandlerFunc(s.handlePortalExportRequest)))
	mux.Handle("GET /portal/api/exports", s.portalAuth(http.HandlerFunc(s.handlePortalExportList)))
	mux.Handle("GET /portal/api/exports/{id}/download", s.portalAuth(http.HandlerFunc(s.handlePortalExportDownload)))

	// The WorkOS account-lifecycle webhook (D18 phase 1). WorkOS calls it, so it
	// is deliberately NOT behind portalAuth (there is no cookie and no CSRF
	// token to present) — its credential is the HMAC over the raw body. It
	// answers 501 until a signing secret is configured.
	//
	// It carries its OWN per-IP bucket (F9), not the shared unauthenticated one:
	// WorkOS delivers from a small set of egress IPs, so a delivery burst on the
	// shared bucket would starve sign-in from those addresses, and conversely a
	// sign-in flood must never be able to make us drop lifecycle revocations.
	mux.Handle("POST /portal/webhooks/workos", s.rateLimitWebhook(http.HandlerFunc(s.handleWorkOSWebhook)))
	// W9 Paddle billing webhook (signature-verified; fail-closed when unconfigured).
	mux.Handle("POST /portal/webhooks/paddle", s.rateLimitWebhook(http.HandlerFunc(s.handlePaddleWebhook)))

	// The webcloud SPA is the catch-all under /portal/. Go 1.22 ServeMux gives
	// the specific /portal/api/* + /portal/auth/* patterns above precedence, so
	// this only serves UI routes and static assets. StripPrefix maps /portal/ to
	// the embedded dist root (index.html + /assets/*).
	if s.portalSPA != nil {
		mux.Handle("/portal/", http.StripPrefix("/portal", s.portalSPA))
	}

	// The bare origin root (see rootredirect.go). Exact "/" only — it neither
	// touches nor precedes the /portal/ and /v1/* patterns above, and is a
	// no-op when the redirect is disabled (rootRedirectURL == "").
	s.mountRootRedirect(mux)

	// R5: the canonical-host fence wraps the WHOLE mux, so every route — present
	// and future — is covered by one decision point rather than per-handler
	// checks that a new route could forget. It is a no-op when neither host is
	// configured. securityHeaders (gap 3.3) wraps OUTSIDE that so the fence's
	// own 421 also carries the browser-defensive headers.
	return s.securityHeaders(s.enforceTrustedEdge(s.enforceCanonicalHost(mux)))
}

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type errorBody struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: msg, Code: code})
}

// healthzSchema is the "schema" slice of GET /healthz's body: the embedded
// migration head this binary was built with, the version actually applied to
// the connected database, and whether the two match. It reuses the exact
// same reads `observer-cloud schema-check` uses (clouddb.MaxEmbeddedVersion +
// clouddb.Version against the same store pool) so the two never disagree —
// one owner of "what schema does this binary expect."
type healthzSchema struct {
	Embedded int  `json:"embedded"`
	Deployed int  `json:"deployed"`
	OK       bool `json:"ok"`
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Pool().Ping(r.Context()); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "db_unreachable", "database unreachable")
		return
	}
	body := map[string]any{"status": "ok"}
	embedded, embErr := clouddb.MaxEmbeddedVersion()
	deployed, depErr := clouddb.Version(r.Context(), s.store.Pool())
	if embErr == nil && depErr == nil {
		body["schema"] = healthzSchema{Embedded: embedded, Deployed: deployed, OK: embedded == deployed}
	} else if s.log != nil {
		// Non-fatal: the DB already answered Ping above, so this is a
		// diagnostics gap, not an outage — the response still reports "ok".
		s.log.Warn("cloudserver/api: healthz schema read failed", "embedded_err", embErr, "deployed_err", depErr)
	}
	writeJSON(w, http.StatusOK, body)
}

// context key for the authenticated principal.
type ctxKey int

const principalKey ctxKey = 0

type principal struct {
	AccountID string
	DeviceID  string
	// TokenID is the api_tokens row the presented bearer resolved to. It is a
	// non-secret identifier (never the token itself), carried so a handler can
	// act on THIS credential — POST /v1/logout revokes exactly this row — without
	// the raw bearer secret being threaded any further than the middleware.
	TokenID    string
	Thumbprint string
}

func principalFrom(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalKey).(principal)
	return p, ok
}
