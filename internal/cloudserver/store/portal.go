package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DefaultBrowserSessionTTL bounds a portal browser session ABSOLUTELY. Unlike
// the device API token (WorkOS-refreshed), a browser session is re-established
// by a fresh portal sign-in when it expires. Operator ruling 2026-09-11 (Wave
// C, gap 2.4 residual (a)): 24h absolute, paired with DefaultBrowserSessionIdleTTL's
// 2h sliding idle boundary — whichever bound is hit first ends the session.
const DefaultBrowserSessionTTL = 24 * time.Hour

// DefaultBrowserSessionIdleTTL bounds a portal browser session by INACTIVITY.
// It slides forward on authenticated activity (IntrospectBrowserSession's
// rolling refresh, capped at never exceeding the absolute expires_at) rather
// than being fixed at sign-in like DefaultBrowserSessionTTL.
const DefaultBrowserSessionIdleTTL = 2 * time.Hour

// browserSessionRollInterval coalesces the idle-refresh write: a session's
// idle_expires_at/last_seen_at are only rolled forward when the PREVIOUS roll
// is older than this, so a tab polling the bootstrap endpoint every few
// seconds costs one UPDATE per ~5 minutes of activity, not one per request.
const browserSessionRollInterval = 5 * time.Minute

// PortalSession is the result of a portal sign-in: the RAW session + CSRF
// secrets (returned to the browser once — the session as a cookie, the CSRF
// token in the JSON body for the double-submit header) plus the resolved
// account scope. Only hashes of both secrets are persisted.
type PortalSession struct {
	AccountID    string
	RawSession   string
	RawCSRFToken string
	ExpiresAt    time.Time
}

// PortalLoginOption configures one PortalLogin or IntrospectBrowserSession
// call beyond its required arguments. It is a VARIADIC tail deliberately: both
// functions have a long list of existing call sites across this package and
// api (every one built with the pre-Wave-C signature), and a variadic addition
// is the one signature change that cannot break any of them — an omitted opts
// is simply an empty slice.
type PortalLoginOption func(*portalSessionConfig)

// portalSessionConfig is the option target (only IdleTTL today).
type portalSessionConfig struct {
	idleTTL time.Duration
}

// WithIdleTTL overrides the sliding idle boundary — see
// DefaultBrowserSessionIdleTTL and IntrospectBrowserSession's doc comment for
// the model. Zero/omitted ⇒ DefaultBrowserSessionIdleTTL. Wired from
// api.Options.PortalSessionIdleTTL (cmd/observer-cloud's
// SBCI_PORTAL_SESSION_IDLE_TTL) at both PortalLogin (the session's initial
// idle boundary) and IntrospectBrowserSession (what a roll advances it by) —
// both call sites must agree, since disagreeing values would make the idle
// window silently different depending on which code path last touched a row.
func WithIdleTTL(d time.Duration) PortalLoginOption {
	return func(c *portalSessionConfig) { c.idleTTL = d }
}

// PortalLogin resolves-or-creates the account for a broker identity (mirroring
// Exchange's identity-link bootstrap, minus the device/nonce/PoP machinery a
// browser has no way to present) and opens a browser session bound to it.
//
// It intentionally reuses the SAME (provider, subject) identity link the device
// exchange uses, so a dev subject that signed in on a device and one that signs
// into the portal resolve to ONE account. Account scope is derived here, never
// taken from a caller-supplied field.
func (s *Store) PortalLogin(ctx context.Context, provider, subject string, ttl time.Duration, now time.Time, opts ...PortalLoginOption) (PortalSession, error) {
	if ttl <= 0 {
		ttl = DefaultBrowserSessionTTL
	}
	if now.IsZero() {
		now = time.Now()
	}
	var cfg portalSessionConfig
	for _, o := range opts {
		o(&cfg)
	}
	idleTTL := cfg.idleTTL
	if idleTTL <= 0 {
		idleTTL = DefaultBrowserSessionIdleTTL
	}
	expiresAtWant := now.Add(ttl)
	idleExpiresAt := now.Add(idleTTL)
	// The absolute boundary always wins (F1 of the C3 idle model): a session
	// minted with an idle window longer than its own remaining lifetime (a
	// short custom ttl, or an idle TTL misconfigured larger than the absolute
	// one) must never have its idle boundary outlive the session itself.
	if idleExpiresAt.After(expiresAtWant) {
		idleExpiresAt = expiresAtWant
	}
	rawSession, err := randToken()
	if err != nil {
		return PortalSession{}, fmt.Errorf("cloudserver/store.PortalLogin: rand session: %w", err)
	}
	rawCSRF, err := randToken()
	if err != nil {
		return PortalSession{}, fmt.Errorf("cloudserver/store.PortalLogin: rand csrf: %w", err)
	}

	var out PortalSession
	err = s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, s.appRole.setLocalRoleSQL()); e != nil {
			return fmt.Errorf("set role: %w", e)
		}
		accountID, e := resolveOrCreateAccountTx(ctx, tx, provider, subject)
		if e != nil {
			return e
		}
		var expiresAt time.Time
		if e := tx.QueryRow(ctx,
			`INSERT INTO browser_sessions
			   (account_id, session_hash, csrf_hash, expires_at, idle_expires_at, last_seen_at)
			 VALUES ($1::uuid, $2, $3, $4, $5, $6) RETURNING expires_at`,
			accountID, hashSecret(rawSession), hashSecret(rawCSRF), expiresAtWant, idleExpiresAt, now).Scan(&expiresAt); e != nil {
			return fmt.Errorf("insert browser session: %w", e)
		}
		out = PortalSession{
			AccountID:    accountID,
			RawSession:   rawSession,
			RawCSRFToken: rawCSRF,
			ExpiresAt:    expiresAt,
		}
		return nil
	})
	if err != nil {
		return PortalSession{}, err
	}
	return out, nil
}

// ErrAccountSuspended indicates the identity resolved to an EXISTING account
// whose status is not 'active'. Both identity entry points (the device exchange
// and the portal sign-in) refuse it rather than minting a credential: without
// this, the WorkOS lifecycle revocation (D18) would be undone by the next
// sign-in, because every credential is re-mintable from the same identity link.
//
// It is deliberately raised only for an already-LINKED account: a brand-new
// identity creates a fresh 'active' account as before.
var ErrAccountSuspended = errors.New("cloudserver/store: account is suspended")

// resolveOrCreateAccountTx finds the account for (provider, subject) via the
// cross-tenant definer lookup, creating the account + identity link + seed
// entitlements on first sight, and establishes tenant context for the rest of
// the transaction.
//
// It is the ONE identity-bootstrap seam: both the portal sign-in (PortalLogin)
// and the device exchange (Exchange) go through it, so the portal and device
// paths share one account per identity AND one place where an account's status
// is checked. An existing link whose account is not 'active' yields
// ErrAccountSuspended and NOTHING is minted.
//
// The caller must already have run SET LOCAL ROLE (the store's application
// role) — resolveOrCreateAccountTx is always invoked from within a WithAccount /
// WithSystem-style transaction that has set it.
func resolveOrCreateAccountTx(ctx context.Context, tx pgx.Tx, provider, subject string) (string, error) {
	var accountID, linkID string
	e := tx.QueryRow(ctx,
		`SELECT account_id::text, link_id::text FROM sbci_find_identity_link($1, $2)`,
		provider, subject).Scan(&accountID, &linkID)
	switch {
	case errors.Is(e, pgx.ErrNoRows):
		if e2 := tx.QueryRow(ctx,
			`INSERT INTO accounts DEFAULT VALUES RETURNING account_id::text`).Scan(&accountID); e2 != nil {
			return "", fmt.Errorf("create account: %w", e2)
		}
		if _, e2 := tx.Exec(ctx, `SELECT set_config('sbci.account_id', $1, true)`, accountID); e2 != nil {
			return "", fmt.Errorf("set tenant: %w", e2)
		}
		if _, e2 := tx.Exec(ctx,
			`INSERT INTO identity_links (account_id, provider, subject) VALUES ($1::uuid, $2, $3)`,
			accountID, provider, subject); e2 != nil {
			return "", fmt.Errorf("create identity link: %w", e2)
		}
		if e2 := seedEntitlementsTx(ctx, tx, accountID); e2 != nil {
			return "", e2
		}
	case e != nil:
		return "", fmt.Errorf("find identity link: %w", e)
	default:
		// accounts is a SYSTEM table (no RLS) that sbci_app may SELECT directly,
		// so the status gate needs no definer function. It runs BEFORE tenant
		// context is established — nothing is written on the refusal path.
		var status string
		if e2 := tx.QueryRow(ctx,
			`SELECT status FROM accounts WHERE account_id = $1::uuid`, accountID).Scan(&status); e2 != nil {
			return "", fmt.Errorf("read account status: %w", e2)
		}
		if status != accountStatusActive {
			return "", ErrAccountSuspended
		}
		if _, e2 := tx.Exec(ctx, `SELECT set_config('sbci.account_id', $1, true)`, accountID); e2 != nil {
			return "", fmt.Errorf("set tenant: %w", e2)
		}
	}
	return accountID, nil
}

// accountStatusActive is the one accounts.status value that permits minting a
// new credential. The other three ('suspended', 'closed', 'deleted') are all
// refusals — the same test the two introspection paths already apply.
const accountStatusActive = "active"

// AccountForIdentity resolves an existing (provider, subject) to its account
// via the cross-tenant definer lookup, WITHOUT creating anything. It is the
// reauth check for destructive portal actions: the re-presented credential must
// resolve to an already-linked account. Returns ErrNotFound if no link exists.
func (s *Store) AccountForIdentity(ctx context.Context, provider, subject string) (string, error) {
	var accountID string
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var linkID string
		e := tx.QueryRow(ctx,
			`SELECT account_id::text, link_id::text FROM sbci_find_identity_link($1, $2)`,
			provider, subject).Scan(&accountID, &linkID)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	if err != nil {
		return "", err
	}
	return accountID, nil
}

// BrowserPrincipal is the resolved identity behind a portal session cookie.
type BrowserPrincipal struct {
	AccountID string
	SessionID string
	CSRFHash  string // hex sha256 of the raw CSRF token; compared to X-SBCI-CSRF in Go
	Valid     bool   // session unexpired, unrevoked; account active
}

// IntrospectBrowserSession resolves a raw session cookie value to its principal
// via the SECURITY DEFINER lookup (pre-tenant, like IntrospectToken), then
// applies the validity gates (expiry, idle expiry, revocation, account status)
// in Go.
//
// IDLE MODEL (Wave C, gap 2.4 residual (a), operator ruling 2026-09-11: 24h
// absolute / 2h idle with rolling refresh on authenticated activity). A
// session is refused when EITHER boundary has passed — the absolute
// expires_at, which never moves, or the sliding idle_expires_at. A NULL
// idle_expires_at (a session minted before this migration, or one whose roll
// has not landed yet) is treated as "no idle limit observed YET" rather than
// refused: the session is valid on the absolute boundary alone and the roll
// below establishes an idle boundary going forward, so a live session at
// deploy time is not retroactively logged out.
//
// On a VALID result the idle boundary is rolled forward — but only when the
// previous roll is older than browserSessionRollInterval, so a tab polling the
// session bootstrap endpoint costs one UPDATE per ~5 minutes of activity, not
// one per request. The roll is best-effort: a write failure here must not turn
// an otherwise-valid session invalid, so it is logged and swallowed — the
// session simply rolls on a later request instead.
func (s *Store) IntrospectBrowserSession(ctx context.Context, rawSession string, now time.Time, opts ...PortalLoginOption) (BrowserPrincipal, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var cfg portalSessionConfig
	for _, o := range opts {
		o(&cfg)
	}
	idleTTL := cfg.idleTTL
	if idleTTL <= 0 {
		idleTTL = DefaultBrowserSessionIdleTTL
	}
	var p BrowserPrincipal
	var (
		expiresAt                 time.Time
		revokedAt                 *time.Time
		status                    string
		idleExpiresAt, lastSeenAt *time.Time
	)
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT account_id::text, session_id::text, coalesce(csrf_hash, ''), expires_at, revoked_at, account_status,
			        idle_expires_at, last_seen_at
			   FROM sbci_introspect_browser_session($1)`,
			hashSecret(rawSession)).Scan(&p.AccountID, &p.SessionID, &p.CSRFHash, &expiresAt, &revokedAt, &status,
			&idleExpiresAt, &lastSeenAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return fmt.Errorf("introspect browser session: %w", e)
		}
		idleOK := idleExpiresAt == nil || now.Before(*idleExpiresAt)
		p.Valid = revokedAt == nil && status == "active" && now.Before(expiresAt) && idleOK
		return nil
	})
	if err != nil {
		return BrowserPrincipal{}, err
	}
	if p.Valid && (lastSeenAt == nil || now.Sub(*lastSeenAt) > browserSessionRollInterval) {
		s.rollBrowserSessionIdle(ctx, p.AccountID, rawSession, expiresAt, now, idleTTL)
	}
	return p, nil
}

// rollBrowserSessionIdle advances one session's idle boundary to
// now+idleTTL, capped at expiresAt (the absolute boundary always wins —
// rolling can never extend a session past its own expiry). Best-effort: a
// failure here must not turn an otherwise-valid introspection into an error
// (the store layer has no logger to report it through) — the session simply
// rolls again on a later, sufficiently-stale request.
func (s *Store) rollBrowserSessionIdle(ctx context.Context, accountID, rawSession string, expiresAt, now time.Time, idleTTL time.Duration) {
	idleUntil := now.Add(idleTTL)
	if idleUntil.After(expiresAt) {
		idleUntil = expiresAt
	}
	_ = s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`UPDATE browser_sessions SET idle_expires_at = $3, last_seen_at = $4
			  WHERE account_id = $1::uuid AND session_hash = $2 AND revoked_at IS NULL`,
			accountID, hashSecret(rawSession), idleUntil, now)
		return e
	})
}

// RevokeBrowserSession revokes one session (logout). It is tenant-scoped to the
// account the cookie already resolved to; the raw cookie value identifies which
// row. A missing/already-revoked row is a no-op (idempotent logout).
func (s *Store) RevokeBrowserSession(ctx context.Context, accountID, rawSession string, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	return s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`UPDATE browser_sessions SET revoked_at = $3
			  WHERE account_id = $1::uuid AND session_hash = $2 AND revoked_at IS NULL`,
			accountID, hashSecret(rawSession), now)
		if e != nil {
			return fmt.Errorf("revoke browser session: %w", e)
		}
		return nil
	})
}

// BrowserSession is one row of the "sign out everywhere" surface (Wave C, gap
// 2.4 residual (b)): enough to render a device/session list and let the
// account revoke it, and NOTHING device-identifying beyond timestamps — no IP,
// no user agent, no location (none of that is captured anywhere in this
// package today, and inventing it here would be scope creep on a security
// surface). is_current is deliberately NOT a column: the caller already knows
// its OWN session id from the resolved principal and can compare against ID
// itself, which keeps this a pure read with no "whose session is this
// request's own" concept leaking into the store layer.
type BrowserSession struct {
	ID            string
	CreatedAt     time.Time
	LastSeenAt    *time.Time
	ExpiresAt     time.Time
	IdleExpiresAt *time.Time
}

// ListBrowserSessions returns every LIVE (unrevoked) browser session on the
// account, newest first. A revoked session is not "still signed in" and has
// nothing actionable about it, so it is excluded rather than returned with a
// revoked flag the way ListDevices returns dead devices — devices are a
// registration history; sessions here are specifically the "what can I sign
// out" list.
func (s *Store) ListBrowserSessions(ctx context.Context, accountID string) ([]BrowserSession, error) {
	var out []BrowserSession
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT id::text, created_at, last_seen_at, expires_at, idle_expires_at
			   FROM browser_sessions
			  WHERE account_id = $1::uuid AND revoked_at IS NULL
			  ORDER BY created_at DESC`, accountID)
		if e != nil {
			return fmt.Errorf("list browser sessions: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var bs BrowserSession
			if e := rows.Scan(&bs.ID, &bs.CreatedAt, &bs.LastSeenAt, &bs.ExpiresAt, &bs.IdleExpiresAt); e != nil {
				return e
			}
			out = append(out, bs)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListBrowserSessions: %w", err)
	}
	return out, nil
}

// RevokeAllBrowserSessions is "sign out everywhere" (Wave C, gap 2.4 residual
// (b)): it revokes every LIVE session on the account except, when
// exceptRawSession is non-empty, the one it resolves to — the "everywhere but
// stay signed in here" shape the portal's keep_current option needs. It is
// tenant-scoped (WithAccount), so a caller can only ever revoke its OWN
// account's sessions — the same isolation RevokeBrowserSession already gives
// the single-session logout path. Returns the number of sessions revoked, for
// the audit log.
func (s *Store) RevokeAllBrowserSessions(ctx context.Context, accountID, exceptRawSession string, now time.Time) (int, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var exceptHash string
	if exceptRawSession != "" {
		exceptHash = hashSecret(exceptRawSession)
	}
	var revoked int
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE browser_sessions SET revoked_at = $2
			  WHERE account_id = $1::uuid AND revoked_at IS NULL
			    AND ($3 = '' OR session_hash <> $3)`,
			accountID, now, exceptHash)
		if e != nil {
			return fmt.Errorf("revoke all browser sessions: %w", e)
		}
		revoked = int(ct.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.RevokeAllBrowserSessions: %w", err)
	}
	return revoked, nil
}

// PortalOverview is the enrichment-job COVERAGE view (plan §4(c)): job counts by
// state, results total, and the last result timestamp. It deliberately carries
// NO whole-observer trend data — the portal Overview describes only what the
// cloud enrichment jobs cover.
type PortalOverview struct {
	JobsByState  map[string]int `json:"jobs_by_state"`
	JobsTotal    int            `json:"jobs_total"`
	ResultsTotal int            `json:"results_total"`
	LastResultAt *time.Time     `json:"last_result_at"`
}

// OverviewStats aggregates the account's enrichment-job coverage counters. RLS
// scopes every read to the account.
func (s *Store) OverviewStats(ctx context.Context, accountID string) (PortalOverview, error) {
	out := PortalOverview{JobsByState: map[string]int{}}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT state, count(*) FROM analysis_jobs WHERE account_id = $1::uuid GROUP BY state`,
			accountID)
		if e != nil {
			return fmt.Errorf("count jobs: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var state string
			var n int
			if e := rows.Scan(&state, &n); e != nil {
				return e
			}
			out.JobsByState[state] = n
			out.JobsTotal += n
		}
		if e := rows.Err(); e != nil {
			return e
		}

		var total int
		var last *time.Time
		if e := tx.QueryRow(ctx,
			`SELECT count(*), max(created_at) FROM analysis_results WHERE account_id = $1::uuid`,
			accountID).Scan(&total, &last); e != nil {
			return fmt.Errorf("count results: %w", e)
		}
		out.ResultsTotal = total
		out.LastResultAt = last
		return nil
	})
	if err != nil {
		return PortalOverview{}, err
	}
	return out, nil
}
