// Command observer-cloud is the SuperBased hosted cloud-intelligence service
// (arc-2 CI-P3 foundation). It is a wholly separate binary from `observer`
// (the agent) and `observer-org` (the customer-self-hosted org server):
// different config, a different database (Postgres, not SQLite), and a
// different deployment (Azure Container Apps — substrate contract).
//
// Subcommands:
//
//	serve       run the /v1 API + portal-BFF HTTP server (the only public ingress)
//	worker      run the inference-worker skeleton (lease → revalidate → no-op executor)
//	migrate     apply the Postgres migration lineage and report the schema version
//	grant-plan  assign an entitlement plan to an account (operator beta grant; runs
//	            and exits — there is deliberately no HTTP route, because no payment
//	            rail exists yet)
//	prove       run the compiled-in synthetic fixture catalog through the real
//	            Foundry pipeline (operator-only, fixture-only; runs and exits).
//	            It has its OWN credential (SBCI_PROVE_FOUNDRY_API_KEY) and never
//	            reads the worker's, so ordinary account admission stays
//	            credential-absent — see internal/cloudserver/prove
//
// Configuration is 12-factor (env):
//
//	SBCI_PG_DSN             Postgres DSN (required). Used directly by migrate,
//	                        grant-plan, and prove (which run as the admin sbci_app
//	                        role), and as the fallback for the two role-scoped
//	                        DSNs below.
//	SBCI_API_PG_DSN         Postgres DSN the `serve` process connects with, whose
//	                        login role is a member of sbci_api ONLY (E2 / W6rs
//	                        least-privilege split). UNSET ⇒ falls back to
//	                        SBCI_PG_DSN (the single-role dev / staging-window
//	                        posture, where one principal assumes either role).
//	SBCI_WORKER_PG_DSN      Postgres DSN the `worker` process connects with, whose
//	                        login role is a member of sbci_worker ONLY. UNSET ⇒
//	                        falls back to SBCI_PG_DSN.
//	SBCI_LISTEN             API listen address (serve; default :8090)
//	SBCI_EXTERNAL_BASE_URL  absolute externally-visible origin (scheme+host[:port],
//	                        no trailing slash/path) used to reconstruct the htu a
//	                        client's proof-of-possession proof was bound to (serve;
//	                        default derived from SBCI_LISTEN — dev/test only. A
//	                        Cloudflare-fronted production deployment MUST set this
//	                        explicitly; the server never trusts X-Forwarded-* for it)
//	SBCI_DEV_AUTH=1         use the dev-auth identity stub (else WorkOS, blocked on the spike)
//	SBCI_PORTAL_BASE_URL    absolute externally-visible origin the PORTAL is served
//	                        at, when /portal/* and /v1/* live on two different names
//	                        (R5). It anchors the WorkOS redirect_uri and the portal
//	                        cookie mode. UNSET ⇒ falls back to SBCI_EXTERNAL_BASE_URL,
//	                        which is the single-host staging posture (unchanged
//	                        behaviour). With the browser sign-in leg ACTIVE and both
//	                        canonical hosts configured, it is REQUIRED and validated
//	                        (https, host == SBCI_PORTAL_HOST, distinct from
//	                        SBCI_API_HOST) — the server refuses to start otherwise
//	SBCI_PORTAL_SECURE      1/0 to force the portal session-cookie Secure mode
//	                        (default: derived from SBCI_PORTAL_BASE_URL's scheme —
//	                        https ⇒ __Host-sbci Secure cookie, http ⇒ dev fallback)
//	SBCI_PORTAL_WORKOS=1    activate the portal's WorkOS browser sign-in leg
//	                        (/portal/auth/workos/*). DARK BY DEFAULT: unset, those
//	                        routes answer an honest 501 and browser sign-in stays
//	                        dev-auth-only until the R7 exposure gates are green.
//	                        Requires WORKOS_CLIENT_ID + WORKOS_API_KEY.
//	WORKOS_CLIENT_ID        public AuthKit client id (also selects the production
//	                        access-token verifier)
//	WORKOS_API_KEY          WorkOS client secret, used ONLY for the server-side
//	                        authorization-code exchange; never sent to a browser
//	SBCI_WORKOS_AUTHORIZE_URL / SBCI_WORKOS_TOKEN_URL
//	                        override the AuthKit endpoints (default: production)
//	WORKOS_WEBHOOK_SECRET   shared secret the account-lifecycle webhook
//	                        (POST /portal/webhooks/workos) verifies its
//	                        `WorkOS-Signature` HMAC against. UNSET ⇒ that route
//	                        answers 501 and reads nothing (fail closed — an
//	                        unauthenticated route that verified nothing would be
//	                        an account-revocation lever for anyone who can reach
//	                        the origin)
//	SBCI_PORTAL_HOST        canonical public host that serves /portal/* (R5),
//	                        e.g. app.superbased.app. Unset ⇒ unenforced (the
//	                        single-host staging deployment)
//	SBCI_API_HOST           canonical public host that serves /v1/* (R5), e.g.
//	                        cloud.superbased.app. Unset ⇒ unenforced. A request
//	                        for either prefix on any other Host is answered 421
//	                        Misdirected Request; /healthz stays host-agnostic
//	SBCI_EDGE_SHARED_SECRET 64 hexadecimal characters (32 random bytes) shared
//	                        only with the Cloudflare Worker. Every non-loopback
//	                        deployment requires it: the API authenticates the
//	                        proxy hop before trusting the private
//	                        X-SBCI-Client-IP header (the Worker copies the
//	                        inbound Cloudflare visitor IP into it; the reserved
//	                        CF-Connecting-IP is never trusted because Cloudflare
//	                        may rewrite it on a cross-zone subrequest). Loopback
//	                        development may omit it.
//	SBCI_QUEUE_MODE         pg (only mode implemented this phase; azure is a later swap)
//	SBCI_WORKER_ID          worker identity (worker; default hostname-derived)
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/attest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/community"
	clouddb "github.com/marmutapp/superbased-observer/internal/cloudserver/db"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/foundry"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/webcloud"
)

var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		var ee *exitCodeError
		if errors.As(err, &ee) {
			// A verb that speaks in exit codes (schema-check: 2 = migration
			// owed, 3 = image too old) returns one of these instead of calling
			// os.Exit itself; this is the single exit point of the binary.
			fmt.Fprintln(os.Stderr, "observer-cloud:", ee.Error())
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "observer-cloud:", err)
		os.Exit(1)
	}
}

// exitCodeError carries a specific process exit code from a verb's RunE back to
// main, so no command needs to call os.Exit itself.
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "observer-cloud",
		Short:         "SuperBased hosted cloud-intelligence service",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newServeCmd(), newWorkerCmd(), newMigrateCmd(), newGrantPlanCmd(), newProveCmd(), newKillSwitchCmd(), newSchemaCheckCmd(), newRestoreSuppressCmd())
	return root
}

func envDSN() (string, error) {
	dsn := strings.TrimSpace(os.Getenv("SBCI_PG_DSN"))
	if dsn == "" {
		return "", errors.New("SBCI_PG_DSN is required")
	}
	return dsn, nil
}

// apiDSN resolves the DSN the serve process connects with: SBCI_API_PG_DSN when
// set (the two-principal split — its login role is a member of sbci_api ONLY),
// else SBCI_PG_DSN (the single-role dev / staging-window posture, E2 / W6rs).
func apiDSN() (string, error) {
	if d := strings.TrimSpace(os.Getenv("SBCI_API_PG_DSN")); d != "" {
		return d, nil
	}
	return envDSN()
}

// workerDSN resolves the DSN the worker process connects with: SBCI_WORKER_PG_DSN
// when set (login role member of sbci_worker ONLY), else SBCI_PG_DSN.
func workerDSN() (string, error) {
	if d := strings.TrimSpace(os.Getenv("SBCI_WORKER_PG_DSN")); d != "" {
		return d, nil
	}
	return envDSN()
}

// openStore opens an admin store (sbci_app role, SBCI_PG_DSN) for the operator
// paths (migrate, grant-plan, prove).
func openStore(ctx context.Context) (*store.Store, error) {
	dsn, err := envDSN()
	if err != nil {
		return nil, err
	}
	return openStoreForRole(ctx, store.RoleApp, dsn)
}

// openStoreForRole opens a store over dsn whose transactions assume role
// (E2 / W6rs: sbci_api for serve, sbci_worker for worker, sbci_app for the
// admin paths). The evidence-key wiring is shared across every role.
func openStoreForRole(ctx context.Context, role store.Role, dsn string) (*store.Store, error) {
	pool, err := clouddb.Open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	s, err := store.NewForRole(pool, role)
	if err != nil {
		pool.Close()
		return nil, err
	}
	// SBCI_EVIDENCE_KEY (64 hex chars ⇒ 32 bytes) shares the evidence-blob
	// AES-256-GCM key across the api (seal) and worker (open) processes. Unset ⇒
	// a process-random key (single-process/dev; a restarted worker treats a
	// decrypt failure as evidence_expired). The Azure driver swaps a Key Vault
	// envelope key behind the same store.Encryptor seam.
	if hexKey := strings.TrimSpace(os.Getenv("SBCI_EVIDENCE_KEY")); hexKey != "" {
		key, err := hex.DecodeString(hexKey)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("SBCI_EVIDENCE_KEY: %w", err)
		}
		enc, err := store.NewAESGCMEncryptor(key)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("SBCI_EVIDENCE_KEY: %w", err)
		}
		s.SetEvidenceEncryptor(enc)
	}
	// Deletion journal (W6d): an append-only record OUTSIDE the Postgres restore
	// domain so a point-in-time restore can re-apply account tombstones before
	// reopening (store.SuppressFromJournal). SBCI_DELETION_JOURNAL_PATH must point
	// at a DURABLE path — a mounted volume, or the Azure append-blob impl bound at
	// deploy time — for the restore-survival guarantee to hold; it defaults to a
	// local file for single-node/dev. The deletion path fails closed without it.
	journalPath := strings.TrimSpace(os.Getenv("SBCI_DELETION_JOURNAL_PATH"))
	if journalPath == "" {
		journalPath = "deletion-journal.jsonl"
	}
	journal, err := deletionjournal.NewFileJournal(journalPath)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("deletion journal: %w", err)
	}
	s.SetDeletionJournal(journal)
	return s, nil
}

// chooseCredentials returns the Foundry credential source. Pre-approval the key
// is simply NOT provisioned (SBCI_FOUNDRY_API_KEY unset) ⇒ AbsentCredentials,
// and every job parks provider_policy_unverified with no provider call — the
// §2.1 pre-approval boundary (the gate is credential absence).
func chooseCredentials(log *slog.Logger) jobs.CredentialSource {
	if k := strings.TrimSpace(os.Getenv("SBCI_FOUNDRY_API_KEY")); k != "" {
		return jobs.StaticCredentials{Key: k}
	}
	log.Warn("observer-cloud: SBCI_FOUNDRY_API_KEY unset — provider credential ABSENT (pre-approval boundary); jobs park provider_policy_unverified")
	return jobs.AbsentCredentials{}
}

// chooseAttestor builds the provider-posture attestation gate. Three modes,
// selected by env, mutually exclusive between the two operator-asserted ones:
//
//   - default: the live ARM REST read of the ContentLogging capability
//     (plan §2.2 — never `az`; token from attestTokenSourceFromEnv). With an
//     unbound route or an empty token the gate fails closed.
//   - SBCI_CONTENT_LOGGING_ATTESTED_RESOURCE (+ _BY): the operator-attested
//     override (attest.OperatorAttestor) — an explicit, audit-labeled assertion
//     that ContentLogging IS false on exactly that resource. Azure AIServices
//     does not expose the capability as a readable ARM property, so a resource
//     that HAS Modified Abuse Monitoring approval cannot be machine-verified;
//     this is the mode for that case and for no other — on a resource whose
//     logging is not off the assertion would be untrue.
//   - SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE (+ _POLICY_VERSION, _BY): the
//     disclosed-posture mode (attest.DisclosedAttestor, operator ruling
//     2026-09-15 option C, docs/modified-abuse-monitoring-filing.md s8): the
//     provider's default flagged-sample retention is accepted and disclosed on
//     the privacy page under the named policy version; the persisted record
//     says "not-disabled" and never claims logging is off.
//
// Both operator modes set at once is an ambiguous deployment: it is logged at
// startup and every job parks provider_policy_unverified until one is removed.
func chooseAttestor(s *store.Store, log *slog.Logger) jobs.ProviderAttestor {
	disclosed := strings.TrimSpace(os.Getenv("SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE"))
	attested := strings.TrimSpace(os.Getenv("SBCI_CONTENT_LOGGING_ATTESTED_RESOURCE"))
	switch {
	case disclosed != "" && attested != "":
		log.Error("observer-cloud: BOTH SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE and SBCI_CONTENT_LOGGING_ATTESTED_RESOURCE are set — conflicting attestation modes; every job parks provider_policy_unverified until one is removed")
		// Returned WITHOUT the caching gate: a healthy record persisted before
		// the conflict was introduced must not authorize jobs for up to the
		// gate's max-age (review finding 2026-09-15).
		return jobs.RefusingAttestor{Reason: "conflicting attestation modes configured (fail closed)"}
	case disclosed != "":
		d := attest.DisclosedAttestor{
			AttestedResourceID: disclosed,
			PolicyVersion:      strings.TrimSpace(os.Getenv("SBCI_PROVIDER_RETENTION_POLICY_VERSION")),
			AttestedBy:         strings.TrimSpace(os.Getenv("SBCI_PROVIDER_RETENTION_DISCLOSED_BY")),
		}
		if d.PolicyVersion == "" {
			log.Error("observer-cloud: SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE is set but SBCI_PROVIDER_RETENTION_POLICY_VERSION is empty — the disclosed mode fails closed until a policy version is named")
		} else {
			log.Info("observer-cloud: attestation mode " + attest.ModeProviderRetentionDisclosed + " (provider flagged-sample retention disclosed; privacy policy v" + d.PolicyVersion + ")")
		}
		return jobs.NewAttestationGate(s, d, 15*time.Minute)
	case attested != "":
		op := attest.OperatorAttestor{
			AttestedResourceID: attested,
			AttestedBy:         strings.TrimSpace(os.Getenv("SBCI_CONTENT_LOGGING_ATTESTED_BY")),
		}
		log.Info("observer-cloud: attestation mode operator-attested (asserts ContentLogging=false for the named resource)")
		return jobs.NewAttestationGate(s, op, 15*time.Minute)
	}
	arm := &attest.ARMAttestor{
		Tokens:     attestTokenSourceFromEnv(),
		BaseURL:    strings.TrimSpace(os.Getenv("SBCI_ARM_BASE_URL")),
		APIVersion: strings.TrimSpace(os.Getenv("SBCI_ARM_API_VERSION")),
	}
	return jobs.NewAttestationGate(s, arm, 15*time.Minute)
}

func chooseVerifier(log *slog.Logger) identity.Verifier {
	if os.Getenv("SBCI_DEV_AUTH") == "1" {
		log.Warn("observer-cloud: SBCI_DEV_AUTH=1 — using the dev-auth identity stub (NEVER in production)")
		return identity.NewDevAuth()
	}
	// Production: validate WorkOS access tokens against the WorkOS JWKS. The
	// client id is public (WORKOS_CLIENT_ID); the WorkOS API key stays server-
	// side and is NOT needed for token validation (JWKS is public). Absent a
	// client id we fall back to the fail-closed placeholder so a misconfigured
	// deployment can never silently accept tokens.
	clientID := strings.TrimSpace(os.Getenv("WORKOS_CLIENT_ID"))
	if clientID == "" {
		log.Warn("observer-cloud: WORKOS_CLIENT_ID unset — using the fail-closed WorkOS placeholder (set it, or SBCI_DEV_AUTH=1 for local)")
		return identity.NewWorkOSPlaceholder()
	}
	v, err := identity.NewWorkOSVerifier(clientID)
	if err != nil {
		log.Warn("observer-cloud: WorkOS verifier init failed — falling back to fail-closed placeholder", "err", err)
		return identity.NewWorkOSPlaceholder()
	}
	log.Info("observer-cloud: WorkOS access-token verifier active", "client_id", clientID, "jwks", "https://api.workos.com/sso/jwks/"+clientID)
	return v
}

// portalWorkOSEnabled reads the SBCI_PORTAL_WORKOS activation gate for the
// portal's WorkOS browser sign-in leg. It is OFF by default (R7: browser
// sign-in stays dev-auth-only until every exposure gate is green), and it warns
// loudly when the gate is set but the WorkOS credentials the server-side code
// exchange needs are missing — in which case the routes still answer 501.
func portalWorkOSEnabled(log *slog.Logger) bool {
	switch strings.TrimSpace(os.Getenv("SBCI_PORTAL_WORKOS")) {
	case "1", "true":
	default:
		return false
	}
	if strings.TrimSpace(os.Getenv("WORKOS_CLIENT_ID")) == "" || strings.TrimSpace(os.Getenv("WORKOS_API_KEY")) == "" {
		log.Warn("observer-cloud: SBCI_PORTAL_WORKOS is set but WORKOS_CLIENT_ID/WORKOS_API_KEY are incomplete — /portal/auth/workos/* will keep answering 501")
	}
	if os.Getenv("SBCI_DEV_AUTH") == "1" {
		log.Warn("observer-cloud: SBCI_PORTAL_WORKOS is set but SBCI_DEV_AUTH=1 — the dev-auth stub wins and the WorkOS browser leg stays inactive")
	}
	log.Info("observer-cloud: portal WorkOS browser sign-in leg ACTIVE (/portal/auth/workos/*)")
	return true
}

// requireDevAuthLoopbackOnly is the C1 startup guard (gap 2.3): the dev-auth
// identity stub is a fail-OPEN broker (`dev:<subject>` mints valid credentials
// for whatever subject a caller names) and must be provably impossible to
// reach from anywhere but a loopback dev origin. It refuses to start when:
//
//   - SBCI_DEV_AUTH=1 AND EITHER configured origin (the API/external base or
//     the portal base) is not loopback (localhost/127.0.0.1/[::1]) — a
//     dev-auth stub may only ever serve a loopback origin, never a public
//     https deploy left on it by accident;
//   - SBCI_DEV_AUTH=1 AND SBCI_PORTAL_WORKOS=1 together. portalWorkOSEnabled
//     today only WARNs that "the dev-auth stub wins" — correct for a
//     deliberate local override, but in a real deployment that combination
//     means someone meant to flip to WorkOS and left the stub on (or the
//     reverse), which is a misconfiguration to refuse, not a precedence rule
//     to silently resolve.
//
// It is a pure function of the four already-resolved config values, so the
// fatal path (and the preserved loopback dev path) is table-tested without a
// running server; the one call site in the serve RunE runs it after `base`
// and `portalBase` are resolved and before the listener starts.
func requireDevAuthLoopbackOnly(devAuth bool, externalBase, portalBase string, portalWorkOS bool) error {
	if !devAuth {
		return nil
	}
	if portalWorkOS {
		return fmt.Errorf("SBCI_DEV_AUTH=1 and SBCI_PORTAL_WORKOS=1 are mutually exclusive: the dev-auth identity stub must never be enabled on a deployment that also activates the WorkOS browser sign-in leg")
	}
	for _, base := range []struct{ name, value string }{
		{"SBCI_EXTERNAL_BASE_URL", externalBase},
		{"SBCI_PORTAL_BASE_URL", portalBase},
	} {
		if !isLoopbackOrigin(base.value) {
			return fmt.Errorf("SBCI_DEV_AUTH=1 requires every configured origin to be loopback; %s=%q is not localhost/127.0.0.1/[::1]", base.name, base.value)
		}
	}
	return nil
}

// isLoopbackOrigin reports whether base's host is loopback (localhost,
// 127.0.0.1, or [::1], with or without a port). An unparsable base is treated
// as NOT loopback — fail closed, matching validatePortalCookieMode's posture.
func isLoopbackOrigin(base string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// portalSessionTTLFromEnv resolves SBCI_PORTAL_SESSION_TTL /
// SBCI_PORTAL_SESSION_IDLE_TTL (Wave C, gap 2.4 residual (a)) into the
// api.Options durations. Both are Go duration strings (e.g. "24h", "2h30m");
// unset or unparsable ⇒ 0, which api.New/store.PortalLogin resolve to
// store.DefaultBrowserSessionTTL / store.DefaultBrowserSessionIdleTTL — so a
// malformed value degrades to "use the default", not a startup failure, since
// session lifetime is not a safety-critical knob the way the dev-auth guard
// above is.
func portalSessionTTLFromEnv(log *slog.Logger) (ttl, idle time.Duration) {
	ttl = parseOptionalDuration(log, "SBCI_PORTAL_SESSION_TTL")
	idle = parseOptionalDuration(log, "SBCI_PORTAL_SESSION_IDLE_TTL")
	return ttl, idle
}

// parseOptionalDuration reads one Go-duration env var, warning (not failing)
// on a value that is set but does not parse.
func parseOptionalDuration(log *slog.Logger, name string) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		log.Warn("observer-cloud: env duration did not parse, using the default", "var", name, "value", raw, "err", err)
		return 0
	}
	return d
}

func queueMode() (string, error) {
	mode := strings.TrimSpace(os.Getenv("SBCI_QUEUE_MODE"))
	if mode == "" {
		mode = "pg"
	}
	if mode != "pg" {
		return "", fmt.Errorf("SBCI_QUEUE_MODE=%q not implemented this phase (only pg; azure is a later swap)", mode)
	}
	return mode, nil
}

// externalBaseURL resolves the SBCI_EXTERNAL_BASE_URL env var, defaulting to
// http://<listen-addr> for dev/tests when unset. A bare ":PORT" listen
// address (empty host) is rewritten to "localhost:PORT" — cloudpop's htu
// canonicalization requires a non-empty host, and ":PORT" alone doesn't
// parse into one. This default is deliberately dev/test-shaped; a real
// deployment sets SBCI_EXTERNAL_BASE_URL to its actual public origin
// (Cloudflare-fronted prod revisits this — X-Forwarded-* is never trusted).
func externalBaseURL(listen string) string {
	if v := strings.TrimSpace(os.Getenv("SBCI_EXTERNAL_BASE_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	addr := listen
	if strings.HasPrefix(addr, ":") {
		addr = "localhost" + addr
	}
	return "http://" + addr
}

// portalBaseURL resolves the origin the PORTAL is served at. Unset ⇒ the API's
// own external base URL, which is the single-host deployment and keeps every
// downstream decision (redirect_uri, cookie mode) byte-identical to before the
// two-origin split existed.
func portalBaseURL(externalBase string) string {
	if v := strings.TrimSpace(os.Getenv("SBCI_PORTAL_BASE_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return externalBase
}

// edgeConfigForExternalOrigin builds the authenticated Cloudflare-to-origin
// boundary. A public deployment may never silently start in direct-origin
// mode: its 32-byte shared secret is mandatory and malformed values fail
// startup. Only loopback development may omit the secret, in which case the
// API ignores every forwarded-IP header and rate-limits the direct peer.
func edgeConfigForExternalOrigin(base, secret string) (api.EdgeConfig, error) {
	u, err := url.Parse(base)
	if err != nil {
		return api.EdgeConfig{}, fmt.Errorf("SBCI_EXTERNAL_BASE_URL %q is not a valid URL: %w", base, err)
	}
	host := u.Hostname()
	if host == "" {
		return api.EdgeConfig{}, fmt.Errorf("SBCI_EXTERNAL_BASE_URL %q has no host", base)
	}
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if secret == "" {
		if loopback {
			return api.EdgeConfig{}, nil
		}
		return api.EdgeConfig{}, errors.New("SBCI_EDGE_SHARED_SECRET is required for a non-loopback origin")
	}
	if strings.TrimSpace(secret) != secret {
		return api.EdgeConfig{}, errors.New("SBCI_EDGE_SHARED_SECRET must not contain leading or trailing whitespace")
	}
	decoded, err := hex.DecodeString(secret)
	if err != nil || len(decoded) != 32 {
		return api.EdgeConfig{}, errors.New("SBCI_EDGE_SHARED_SECRET must be exactly 64 hexadecimal characters (32 random bytes)")
	}
	return api.EdgeConfig{Enabled: true, AuthSecret: secret}, nil
}

// validateTwoOriginConfig refuses to start a fenced deployment whose portal
// origin does not actually match the host the portal is fenced to (F1). The
// two hosts may be distinct (the two-origin split) or the same name (the
// one-host production shape); what must hold either way is that each base
// URL carries the host its surface is fenced to.
//
// It fires ONLY in the configuration where a mistake is silent and costly: the
// browser sign-in leg ACTIVE and both canonical hosts set. In that shape the
// OAuth redirect_uri is minted from the portal base, the canonical-host fence
// answers 421 for /portal/* on any other name, and WorkOS matches the
// redirect_uri exactly — so a portal base still pointing at the API host
// produces a flow that is registered at the provider, sent to a host that
// refuses it, and fails only at the callback, in a browser, for a real user.
// Every other shape (single host, hosts unenforced, leg dark) is left alone.
func validateTwoOriginConfig(portalBase, externalBase, portalHost, apiHost string, workosEnabled bool) error {
	if !workosEnabled || portalHost == "" || apiHost == "" {
		return nil
	}
	pu, err := url.Parse(portalBase)
	if err != nil {
		return fmt.Errorf("SBCI_PORTAL_BASE_URL %q is not a valid URL: %w", portalBase, err)
	}
	eu, err := url.Parse(externalBase)
	if err != nil {
		return fmt.Errorf("SBCI_EXTERNAL_BASE_URL %q is not a valid URL: %w", externalBase, err)
	}
	np, na := normalizeHostName(portalHost), normalizeHostName(apiHost)
	// np == na is the ONE-HOST production shape (operator ruling 2026-09-11:
	// a single public hostname serves /portal/* and /v1/*), not a mistake:
	// the fence still binds each surface to that one name, and the checks
	// below still require both base URLs to carry it. Refusing it (as this
	// function did until 2026-09-14) crash-looped the api the moment the
	// browser leg was enabled on an estate whose hosts `up` had baked equal.
	if pu.Scheme != "https" {
		return fmt.Errorf("SBCI_PORTAL_BASE_URL must be https when the WorkOS browser sign-in leg is active "+
			"(got %q): the portal session cookie is __Host-prefixed and the OAuth redirect_uri is minted from this origin", portalBase)
	}
	if got := normalizeHostName(pu.Host); got != np {
		return fmt.Errorf("SBCI_PORTAL_BASE_URL host %q does not match SBCI_PORTAL_HOST %q; "+
			"the OAuth redirect_uri would be minted for an origin the canonical-host fence answers 421 for "+
			"(set SBCI_PORTAL_BASE_URL=https://%s)", got, np, np)
	}
	if got := normalizeHostName(eu.Host); got != na {
		return fmt.Errorf("SBCI_EXTERNAL_BASE_URL host %q does not match SBCI_API_HOST %q; "+
			"device proof-of-possession reconstructs its htu from this origin, so /v1 would reject every proof "+
			"(set SBCI_EXTERNAL_BASE_URL=https://%s)", got, na, na)
	}
	return nil
}

// normalizeHostName reduces a host (or an authority with a port) to its
// comparable form, mirroring the api package's canonical-host normalization.
func normalizeHostName(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

// portalSecureCookie decides the portal session-cookie shape from the portal
// origin's scheme, unless SBCI_PORTAL_SECURE forces it. An https origin ⇒ the
// hardened `__Host-sbci` Secure cookie; a plain-http origin (local dev) ⇒ the
// unprefixed non-Secure fallback (the only cookie a browser accepts over http).
// SBCI_PORTAL_SECURE=1/0 overrides — e.g. behind a TLS-terminating proxy where
// the process sees http but the browser speaks https, set it to 1.
func portalSecureCookie(base string) bool {
	switch strings.TrimSpace(os.Getenv("SBCI_PORTAL_SECURE")) {
	case "1", "true":
		return true
	case "0", "false":
		return false
	}
	return strings.HasPrefix(base, "https://")
}

// validatePortalCookieMode refuses to start the server in an unsafe portal
// session-cookie configuration (FC4). A non-Secure cookie (no __Host- prefix,
// no Secure attribute) is bearer-equivalent on the wire, so it is permitted
// ONLY for a loopback http dev origin with dev-auth enabled. An explicit
// SBCI_PORTAL_SECURE=0/false is rejected for any https or non-loopback origin,
// and the base URL must parse as an http/https origin.
//
// `base` is the PORTAL origin (SBCI_PORTAL_BASE_URL, falling back to
// SBCI_EXTERNAL_BASE_URL): the cookie belongs to the portal, so its scheme is
// the one that decides.
func validatePortalCookieMode(base string, secure, devAuth bool, explicitSecureEnv string) error {
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("the portal base URL %q is not a valid URL: %w", base, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("the portal base URL scheme %q must be http or https", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("the portal base URL %q has no host", base)
	}
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())

	explicitOff := explicitSecureEnv == "0" || strings.EqualFold(explicitSecureEnv, "false")
	if explicitOff && (u.Scheme == "https" || !loopback) {
		return fmt.Errorf("SBCI_PORTAL_SECURE=0 refused for a non-loopback/https origin (%s): it would send bearer-equivalent session cookies without Secure", base)
	}
	if !secure {
		if u.Scheme == "https" {
			return fmt.Errorf("refusing non-Secure portal cookies for an https origin (%s)", base)
		}
		if !loopback {
			return fmt.Errorf("refusing non-Secure portal cookies for a non-loopback origin (%s): only loopback http dev is allowed", base)
		}
		if !devAuth {
			return fmt.Errorf("refusing non-Secure portal cookies unless dev-auth is enabled (SBCI_DEV_AUTH=1)")
		}
	}
	return nil
}

// portalCookieNameFor mirrors the api package's cookie-name choice, for logging.
func portalCookieNameFor(secure bool) string {
	if secure {
		return "__Host-sbci"
	}
	return "sbci_session"
}

func newMigrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "apply the Postgres migration lineage and report the schema version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			dsn, err := envDSN()
			if err != nil {
				return err
			}
			pool, err := clouddb.Open(ctx, dsn)
			if err != nil {
				return err
			}
			defer pool.Close()
			if err := clouddb.Migrate(ctx, pool); err != nil {
				return err
			}
			v, err := clouddb.Version(ctx, pool)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "observer-cloud: migrated to schema version %d\n", v)
			return nil
		},
	}
}

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "run the /v1 API server (the only public ingress)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := slog.Default()
			if _, err := queueMode(); err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			dsn, err := apiDSN()
			if err != nil {
				return err
			}
			s, err := openStoreForRole(ctx, store.RoleAPI, dsn)
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			log.Info("observer-cloud: serve store bound to application role", "app_role", s.Role())

			// Readiness signal, not a gate: a feature whose only active route
			// is plan_pinned has no eligible ResolveRoute default left (the
			// adversarial-review follow-up to the migration-0039
			// plan_pinned exclusion — see store.classifyFeatureCoverage).
			// ERROR-logged and nothing more: the Sol activation runbook
			// deliberately passes through a window where this is
			// momentarily true, so refusing to start here would make that
			// runbook impossible to follow. GET /healthz's
			// "route_default_missing" field carries the same signal for
			// external monitoring.
			if coverage, covErr := s.FeatureDefaultCoverage(ctx); covErr != nil {
				log.Warn("observer-cloud: startup route-coverage check failed", "err", covErr)
			} else {
				for _, c := range coverage {
					if !c.HasDefault {
						log.Error("observer-cloud: feature has no eligible default route (every route is plan_pinned or inactive) — ResolveRoute will 503 for accounts not pinned to one", "feature", c.Feature)
					}
				}
			}

			// W9 + the 2026-09-12 production-live arc (gaps 1.1/1.5/1.8/1.11):
			// parse the Paddle price catalogue and confirm every configured
			// plan actually exists before wiring it — a typo in
			// SBCI_PADDLE_PRICES fails startup loudly instead of quietly
			// fail-closing every future activation as unknown-price.
			pm, err := paddlePriceMap()
			if err != nil {
				return fmt.Errorf("observer-cloud: SBCI_PADDLE_PRICES: %w", err)
			}
			if len(pm) > 0 {
				s.SetPaddlePriceMap(pm)
				for _, plan := range pm {
					ok, perr := s.PlanExists(ctx, plan.Name, plan.Version)
					if perr != nil {
						return fmt.Errorf("observer-cloud: validate Paddle price plan %s v%d: %w", plan.Name, plan.Version, perr)
					}
					if !ok {
						return fmt.Errorf("observer-cloud: a Paddle price maps to %s v%d, which is not a published plan", plan.Name, plan.Version)
					}
				}
				log.Info("observer-cloud: Paddle price map wired", "prices", len(pm))
			}
			listen := strings.TrimSpace(os.Getenv("SBCI_LISTEN"))
			if listen == "" {
				listen = ":8090"
			}
			// A4 (gap 1.1): the environment switch + go-live invariants — this
			// is the "flip to live by config only" gate: SBCI_PADDLE_ENV=live
			// without a real live client token / webhook secret / price
			// fails startup here rather than silently serving a broken
			// checkout in production.
			paddleCheckout, err := paddleCheckoutFromEnv(pm, externalBaseURL(listen))
			if err != nil {
				return fmt.Errorf("observer-cloud: Paddle checkout configuration: %w", err)
			}
			log.Info("observer-cloud: Paddle checkout configuration",
				"environment", paddleCheckout.Environment, "prices", len(paddleCheckout.Prices),
				"trial_days", paddleCheckout.TrialDays, "checkout_available", paddleCheckout.Available())

			startServeSweepers(ctx, s, log)

			base := externalBaseURL(listen)
			log.Info("observer-cloud: external base URL for proof-of-possession htu reconstruction", "base_url", base)
			// The PORTAL origin. Equal to `base` on a single-host deployment; the
			// browser leg's redirect_uri and the portal cookie mode both key off it.
			portalBase := portalBaseURL(base)
			if portalBase != base {
				log.Info("observer-cloud: two-origin deployment", "portal_base_url", portalBase, "api_base_url", base)
			}
			secureCookie := portalSecureCookie(portalBase)
			// FC4: refuse to start in an unsafe non-Secure cookie configuration.
			if err := validatePortalCookieMode(portalBase, secureCookie,
				os.Getenv("SBCI_DEV_AUTH") == "1", strings.TrimSpace(os.Getenv("SBCI_PORTAL_SECURE"))); err != nil {
				return err
			}
			log.Info("observer-cloud: portal session-cookie mode",
				"secure_cookie", secureCookie, "cookie_name", portalCookieNameFor(secureCookie))

			// R5 canonical hosts. Each half is independent; an unset host leaves
			// that surface unenforced, which is the single-host staging shape.
			portalHost := strings.TrimSpace(os.Getenv("SBCI_PORTAL_HOST"))
			apiHost := strings.TrimSpace(os.Getenv("SBCI_API_HOST"))
			if portalHost == "" && apiHost == "" {
				log.Info("observer-cloud: canonical-host enforcement OFF (SBCI_PORTAL_HOST/SBCI_API_HOST unset) — every Host is accepted")
			} else {
				log.Info("observer-cloud: canonical-host enforcement",
					"portal_host", portalHost, "api_host", apiHost)
			}
			if strings.TrimSpace(os.Getenv("WORKOS_WEBHOOK_SECRET")) == "" {
				log.Warn("observer-cloud: WORKOS_WEBHOOK_SECRET unset — POST /portal/webhooks/workos answers 501 (fail closed); WorkOS lifecycle revocation will NOT propagate")
			}
			workosBrowserLeg := portalWorkOSEnabled(log)
			// C1 (gap 2.3): the dev-auth stub must be provably impossible to reach
			// from anywhere but a loopback origin, and never combined with the
			// WorkOS browser leg. Refuses to start rather than warning, unlike the
			// SBCI_DEV_AUTH+SBCI_PORTAL_WORKOS overlap portalWorkOSEnabled itself
			// only warns about above.
			if err := requireDevAuthLoopbackOnly(os.Getenv("SBCI_DEV_AUTH") == "1", base, portalBase, workosBrowserLeg); err != nil {
				return err
			}
			// F1: with the browser leg live AND both surfaces fenced to their own
			// names, a portal origin that disagrees with the portal host is a
			// misconfiguration that only shows up in a real user's browser at the
			// callback. Refuse to start instead.
			if err := validateTwoOriginConfig(portalBase, base, portalHost, apiHost, workosBrowserLeg); err != nil {
				return err
			}
			edge, err := edgeConfigForExternalOrigin(base, os.Getenv("SBCI_EDGE_SHARED_SECRET"))
			if err != nil {
				return err
			}
			if edge.Enabled {
				log.Info("observer-cloud: authenticated Cloudflare origin boundary active",
					"client_ip_header", "X-SBCI-Client-IP", "hop_auth_header", "X-SBCI-Edge-Auth")
			} else {
				log.Warn("observer-cloud: edge boundary disabled for loopback development; forwarded IP headers are ignored")
			}
			// C3 (gap 2.4 residual (a)): the portal browser-session absolute/idle
			// lifetimes. Zero (unset or unparsable) ⇒ api.New/store.PortalLogin
			// fall back to store.DefaultBrowserSessionTTL (24h) /
			// store.DefaultBrowserSessionIdleTTL (2h).
			portalSessionTTL, portalSessionIdleTTL := portalSessionTTLFromEnv(log)
			srv := &http.Server{
				Addr: listen,
				Handler: api.New(api.Options{
					Store:              s,
					Queue:              jobs.NewPGQueue(s),
					Verifier:           chooseVerifier(log),
					Logger:             log,
					ExternalBaseURL:    base,
					PortalBaseURL:      portalBase,
					PortalSecureCookie: secureCookie,
					PortalSPA:          webcloud.Handler(),
					// FA6: the admission gate is wired at ENQUEUE too, not only at
					// execution. It is fail-closed — with no provider key provisioned
					// (SBCI_FOUNDRY_API_KEY unset), chooseCredentials resolves to
					// AbsentCredentials and every submit is refused up front with 503
					// provider_policy_unverified, so a credential-absent server never
					// takes custody of evidence it cannot process.
					Attestor:    chooseAttestor(s, log),
					Credentials: chooseCredentials(log),
					// The WorkOS browser sign-in leg. Dark unless SBCI_PORTAL_WORKOS=1
					// AND both WorkOS credentials are present (portalWorkOSEnabled
					// re-checks the credentials per request and 501s without them).
					PortalWorkOSEnabled: workosBrowserLeg,
					WorkOSClientID:      strings.TrimSpace(os.Getenv("WORKOS_CLIENT_ID")),
					WorkOSAPIKey:        strings.TrimSpace(os.Getenv("WORKOS_API_KEY")),
					WorkOSAuthorizeURL:  strings.TrimSpace(os.Getenv("SBCI_WORKOS_AUTHORIZE_URL")),
					WorkOSTokenURL:      strings.TrimSpace(os.Getenv("SBCI_WORKOS_TOKEN_URL")),
					// D18 phase 1: the account-lifecycle webhook. Unset secret ⇒ the
					// route answers 501 (fail closed), never "verify nothing".
					WorkOSWebhookSecret: strings.TrimSpace(os.Getenv("WORKOS_WEBHOOK_SECRET")),
					// C3: portal session lifetimes (SBCI_PORTAL_SESSION_TTL /
					// SBCI_PORTAL_SESSION_IDLE_TTL).
					PortalSessionTTL:     portalSessionTTL,
					PortalSessionIdleTTL: portalSessionIdleTTL,
					// W9 Paddle billing webhook. Unset secret ⇒ the route answers 501
					// (fail closed); dark until the operator provisions Paddle.
					PaddleWebhookSecret: strings.TrimSpace(os.Getenv("SBCI_PADDLE_WEBHOOK_SECRET")),
					// A3 (gap 1.7): the previous secret during a rotation window, so
					// flipping SBCI_PADDLE_WEBHOOK_SECRET to a new value is never an
					// outage — keep the old one here until Paddle confirms the new
					// secret is live, then drop it.
					PaddleWebhookSecrets: []string{strings.TrimSpace(os.Getenv("SBCI_PADDLE_WEBHOOK_SECRET_PREVIOUS"))},
					// A4/A5/A6: the validated checkout catalogue GET /portal/api/billing
					// exposes to the portal (environment, client token, prices, trial).
					PaddleCheckout: paddleCheckout,
					// R5 canonical hosts. Unset ⇒ unenforced (single-host staging).
					PortalHost: portalHost,
					APIHost:    apiHost,
					// W6e: authenticate the Cloudflare-to-ACA hop before accepting the
					// one forwarded client identity used by shared rate-limit counters.
					Edge: edge,
				}).Handler(),
				// Slowloris + idle-connection bounds (F9). ReadHeaderTimeout alone
				// caps the header phase only: a client that sends complete headers
				// and then dribbles a body one byte at a time holds a connection (and
				// a goroutine) indefinitely. ReadTimeout bounds the WHOLE request
				// read, and IdleTimeout bounds a kept-alive connection between
				// requests.
				//
				// No WriteTimeout: every response here is small and synchronous, and
				// a write deadline would have to be re-derived if a streaming
				// endpoint is ever added — the two read-side bounds are what close
				// the actual exhaustion path.
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				IdleTimeout:       120 * time.Second,
			}

			errCh := make(chan error, 1)
			go func() {
				log.Info("observer-cloud: serving", "addr", listen)
				if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
				}
			}()
			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				return srv.Shutdown(shutdownCtx)
			case err := <-errCh:
				return err
			}
		},
	}
}

// startServeSweepers launches the serve process's background hygiene loops;
// each exits when ctx is cancelled.
func startServeSweepers(ctx context.Context, s *store.Store, log *slog.Logger) {
	// FC3: periodically sweep expired pop_replay rows so the jti replay
	// cache cannot grow without bound (cross-tenant SECURITY DEFINER delete
	// purely by expires_at).
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := s.SweepExpiredPoPReplay(ctx, time.Now()); err != nil {
					log.Warn("observer-cloud: pop_replay sweep failed", "err", err)
				} else if n > 0 {
					log.Debug("observer-cloud: swept expired pop_replay rows", "deleted", n)
				}
				// W6d: delete export artifacts past their ≤7-day TTL (the other
				// deletion trigger is the account-deletion pass).
				if n, err := s.SweepExpiredExports(ctx, time.Now()); err != nil {
					log.Warn("observer-cloud: export sweep failed", "err", err)
				} else if n > 0 {
					log.Debug("observer-cloud: swept expired export artifacts", "deleted", n)
				}
				// A2 (gap 1.13): checkout_intents grows unbounded without this —
				// the method was shipped (Stream 5) but never wired.
				if n, err := s.SweepExpiredCheckoutIntents(ctx, time.Now()); err != nil {
					log.Warn("observer-cloud: checkout intent sweep failed", "err", err)
				} else if n > 0 {
					log.Debug("observer-cloud: swept expired checkout intents", "deleted", n)
				}
			}
		}
	}()

	// W6d retention hygiene: age out the rows a completed deletion RETAINED
	// (consent-proof at 12 months; audit + the pseudonymized account row at
	// 24 months). Daily-scale work, so an hourly cadence is ample.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if r, err := s.SweepRetention(ctx, time.Now()); err != nil {
					log.Warn("observer-cloud: retention sweep failed", "err", err)
				} else if r.ConsentPurged > 0 || r.AuditPurged > 0 || r.AccountsPurged > 0 {
					log.Info("observer-cloud: retention sweep",
						"consent_purged", r.ConsentPurged, "audit_purged", r.AuditPurged,
						"accounts_purged", r.AccountsPurged)
				}
			}
		}
	}()
}

// runCommunityMaterialization is the W5 delayed-band recompute loop. It ticks
// hourly (and once at startup), materializing the last three finalized windows
// for every registered (cohort, metric) target. It is best-effort: a per-target
// error is logged and the loop continues, so one bad target never stalls the
// others. It exits when ctx is cancelled.
func runCommunityMaterialization(ctx context.Context, s *store.Store, log *slog.Logger) {
	const recentWindows = 3
	do := func() {
		// The set of windows to recompute is the UNION of (a) the recent finalized
		// windows for every registered target — so a window that JUST finalized
		// gets its first snapshot even before any deletion — and (b) every
		// finalized window that still holds a contribution (Sol F7b) — so a
		// deletion from an OLD window propagates to its published snapshot within
		// this cadence (well under R3's 24h). Deduplicated by key.
		seen := map[string]bool{}
		var targets []store.CommunityWindowRef
		add := func(r store.CommunityWindowRef) {
			k := r.CohortKey + "\x00" + r.MetricID + "\x00" + r.WindowID
			if !seen[k] {
				seen[k] = true
				targets = append(targets, r)
			}
		}
		for _, tgt := range community.MaterializationTargets() {
			for _, win := range community.RecentFinalizedWindows(time.Now(), recentWindows) {
				add(store.CommunityWindowRef{CohortKey: tgt.CohortKey, MetricID: tgt.MetricID, MetricVersion: tgt.MetricVersion, WindowID: win})
			}
		}
		live, err := s.ListFinalizedWindowsWithData(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Warn("community materialization: list windows failed", "err", err)
		}
		for _, r := range live {
			add(r)
		}
		for _, r := range targets {
			if _, err := s.MaterializeCommunityWindow(ctx, r.CohortKey, r.MetricID, r.MetricVersion, r.WindowID); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				log.Warn("community materialization failed",
					"cohort", r.CohortKey, "metric", r.MetricID, "window", r.WindowID, "err", err)
			}
		}
		// Prune snapshots for windows whose contributions are entirely gone
		// (fully-emptied cohort). `live` is the authoritative set of windows that
		// still have data; anything else is stale.
		if n, err := s.PruneOrphanCommunitySnapshots(ctx, live); err != nil {
			if !errors.Is(err, context.Canceled) {
				log.Warn("community materialization: prune orphans failed", "err", err)
			}
		} else if n > 0 {
			log.Info("community materialization: pruned orphan snapshots", "count", n)
		}
	}
	do() // once at startup so a fresh deploy fills the snapshot promptly
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			do()
		}
	}
}

// paddlePriceMap reads the Paddle price->plan mapping from deploy env (A5 /
// gap 1.8): SBCI_PADDLE_PRICES (multi-price: "pri_x=plan:version:interval[:
// display]", comma-separated) plus the backward-compatible single legacy
// SBCI_PADDLE_PRICE_PLUS id (mapped to plus_beta v1 month — the original
// single-price shape). All parsing/validation is the pure, tested
// store.ParsePaddlePriceEntries; this is env-reading glue only. Unset ⇒ empty
// map ⇒ the webhook fail-closes every activation as unknown-price (the dark
// posture until Paddle is provisioned). A malformed SBCI_PADDLE_PRICES entry
// is a startup error, never a silently-dropped price.
func paddlePriceMap() (map[string]store.PaddlePlan, error) {
	return store.ParsePaddlePriceEntries(
		os.Getenv("SBCI_PADDLE_PRICES"),
		os.Getenv("SBCI_PADDLE_PRICE_PLUS"),
	)
}

// paddleCheckoutFromEnv composes the validated PaddleCheckout deploy config
// (A4 environment switch + A5/A6 price catalogue) from process env plus the
// already-parsed price map pm. All decision logic is the pure, tested
// api.ValidatePaddleCheckoutEnv; this is glue only (env reads + type
// conversion) so it needs no dedicated unit test of its own.
func paddleCheckoutFromEnv(pm map[string]store.PaddlePlan, externalBase string) (api.PaddleCheckout, error) {
	prices := make([]api.PaddlePriceEntry, 0, len(pm))
	for id, p := range pm {
		prices = append(prices, api.PaddlePriceEntry{
			PriceID: id, PlanName: p.Name, PlanVersion: p.Version, Interval: p.Interval, Display: p.Display,
		})
	}
	webhookConfigured := strings.TrimSpace(os.Getenv("SBCI_PADDLE_WEBHOOK_SECRET")) != "" ||
		strings.TrimSpace(os.Getenv("SBCI_PADDLE_WEBHOOK_SECRET_PREVIOUS")) != ""
	return api.ValidatePaddleCheckoutEnv(api.PaddleCheckoutEnv{
		Environment:       os.Getenv("SBCI_PADDLE_ENV"),
		ClientToken:       os.Getenv("SBCI_PADDLE_CLIENT_TOKEN"),
		WebhookConfigured: webhookConfigured,
		Prices:            prices,
		TrialDaysRaw:      os.Getenv("SBCI_PADDLE_TRIAL_DAYS"),
		// P3-f: sandbox billing on a public origin is refused unless explicitly
		// allowed (SBCI_PADDLE_ALLOW_SANDBOX_ON_PUBLIC_ORIGIN=1, staging only).
		OriginIsPublic: api.PaddleCheckoutEnvFromProcess(externalBase, os.Getenv),
	})
}

func newWorkerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "worker",
		Short: "run the inference-worker skeleton (lease → revalidate → no-op executor)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := slog.Default()
			if _, err := queueMode(); err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			dsn, err := workerDSN()
			if err != nil {
				return err
			}
			s, err := openStoreForRole(ctx, store.RoleWorker, dsn)
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			log.Info("observer-cloud: worker store bound to application role", "app_role", s.Role())

			workerID := strings.TrimSpace(os.Getenv("SBCI_WORKER_ID"))
			if workerID == "" {
				host, _ := os.Hostname()
				workerID = "sbci-worker-" + host
			}
			blobs := store.NewPGBlobStore(s)
			executors := map[string]jobs.Executor{
				store.FeatureSessionEnrichment: jobs.NewLunaExecutor(s, blobs, &foundry.AzureClient{}),
				// W5: the project-digest job kind shares the SAME Foundry client and
				// lease discipline as session enrichment, dispatched by feature
				// through the worker's feature -> Executor table.
				store.FeatureProjectDigest: jobs.NewDigestExecutor(s, blobs, &foundry.AzureClient{}),
			}
			// ONE attestor and ONE credential source for the whole worker process:
			// the lease loop and the digest scheduler's admission gate share the
			// same instances (s12m review: two chooseAttestor calls printed the
			// "attestation mode" startup line twice and held two caches over one
			// persisted attestation record).
			attestor := chooseAttestor(s, log)
			credentials := chooseCredentials(log)
			w := jobs.NewWorker(jobs.Config{
				WorkerID: workerID, Logger: log,
				Classes: []string{store.FeatureSessionEnrichment, store.FeatureProjectDigest},
			}, jobs.NewPGQueue(s), s, attestor, credentials, executors)

			// W5 project-digest scheduler: submits one job per (account, project)
			// due for the previous ISO week. Runs in the WORKER alongside the lease
			// loop — it only ever calls store methods, never HTTP.
			go jobs.RunDigestScheduler(ctx, s, time.Now, jobs.DigestSchedulerConfig{Logger: log, Credentials: credentials, Attestor: attestor})

			// W5 results retention: age out a plan's results past
			// results_retention_days (free 30d, Plus 365d). Daily-scale work, once
			// at start plus a daily cadence, mirroring the W6d retention loop's
			// shape below.
			go func() {
				sweep := func() {
					if n, err := s.SweepResultsRetention(ctx, time.Now()); err != nil {
						log.Warn("observer-cloud: results retention sweep failed", "err", err)
					} else if n > 0 {
						log.Info("observer-cloud: results retention sweep", "deleted", n)
					}
				}
				sweep()
				t := time.NewTicker(24 * time.Hour)
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						sweep()
					}
				}
			}()

			// W5 delayed-band materialization (community percentile). This runs in
			// the WORKER because MaterializeCommunityWindow reads via the aggregator
			// role, and only the worker's login principal (sbci_worker_svc / sbci_svc
			// in dev) is a member of sbci_aggregator — the front-door serve process
			// (sbci_api_svc) deliberately is NOT. Each pass recomputes the last few
			// finalized windows for every registered (cohort, metric) target; a
			// window below the ≥30 floor or not yet finalized materializes nothing.
			go runCommunityMaterialization(ctx, s, log)

			log.Info("observer-cloud: worker running (Foundry Luna + digest executors; credential-absence + attestation gates fail closed)", "worker_id", workerID)
			if err := w.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}
}
