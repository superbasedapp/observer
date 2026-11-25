package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	clouddb "github.com/marmutapp/superbased-observer/internal/cloudserver/db"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth/passkey"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/webcloud"
)

// staffserve.go is the separate staff process (operator ruling A3,
// 2026-11-13): `observer-cloud staff serve` serves ONLY the /staff route
// group (api.Server.StaffHandler), on its own listener and host, connected
// with its own database login (sbci_staff_svc, the only member of
// sbci_staff), with the go-webauthn passkey verifier (ruling A2). The
// customer `serve` process mounts no staff route and refuses to start when
// it is handed the staff login or its own login holds the staff role
// (refuseStaffInServe).
//
// Environment (the staff process reads only these, plus
// SBCI_TENANT_CONTEXT_KEY[_FILE], the deployment's tenant-context key; it
// reads the customer serve's SBCI_EDGE_SHARED_SECRET solely to refuse a
// staff secret equal to it):
//
//	SBCI_STAFF_EDGE_SHARED_SECRET / SBCI_STAFF_EDGE_SHARED_SECRET_FILE
//	                            the staff origin's OWN edge secret (operator
//	                            ruling Staff 3): 64 hexadecimal characters,
//	                            shared only with the edge in front of the
//	                            staff host. Required off loopback; refused
//	                            when equal to SBCI_EDGE_SHARED_SECRET, so a
//	                            leak of the customer edge secret never
//	                            authenticates a hop to the staff console
//	SBCI_STAFF_PG_DSN           the staff login's DSN (required unless the
//	                            staff origin is loopback, where SBCI_PG_DSN
//	                            is the dev fallback)
//	SBCI_STAFF_LISTEN           listen address (default :8091)
//	SBCI_STAFF_BASE_URL         the staff origin (default
//	                            https://staff.superbased.app); its host is the
//	                            WebAuthn relying-party id
//	SBCI_STAFF_HOST             the canonical host of /staff (default: the
//	                            base URL's host; must equal it)
//	SBCI_STAFF_SESSION_TTL / SBCI_STAFF_SESSION_IDLE_TTL
//	                            session lifetimes (default 8h / 30m; Go
//	                            durations, at most 12h)
//	SBCI_STAFF_SUPPORT_ISSUER   the platform OIDC issuer identifier (the
//	                            portal origin plus /oauth2, serve's
//	                            SBCI_OIDC_ISSUER). Set, GET
//	                            /staff/oauth2/authorize writes support codes
//	                            for that issuer (M7a.2); unset, it answers
//	                            501 not_available, as before

// Staff process environment variables.
const (
	envStaffDSN        = "SBCI_STAFF_PG_DSN"
	envStaffListen     = "SBCI_STAFF_LISTEN"
	envStaffBaseURL    = "SBCI_STAFF_BASE_URL"
	envStaffHost       = "SBCI_STAFF_HOST"
	envStaffSessionTTL = "SBCI_STAFF_SESSION_TTL"
	envStaffIdleTTL    = "SBCI_STAFF_SESSION_IDLE_TTL"
	envStaffSupportIss = "SBCI_STAFF_SUPPORT_ISSUER"
	defaultStaffListen = ":8091"

	envStaffEdgeSecret     = "SBCI_STAFF_EDGE_SHARED_SECRET"      //nolint:gosec // env var NAME, not a credential
	envStaffEdgeSecretFile = "SBCI_STAFF_EDGE_SHARED_SECRET_FILE" //nolint:gosec // env var NAME, not a credential
)

// staffEdgeRule is one row of the staff edge-secret table: a predicate over
// the resolved secrets and the refusal it earns.
type staffEdgeRule struct {
	match  func(staff, serve string, loopback bool) bool
	reason string
}

// staffEdgeRules is walked top down (operator ruling Staff 3, L-83): the
// staff process authenticates its edge hop with a secret of its own, never
// the customer serve's.
var staffEdgeRules = []staffEdgeRule{
	{
		match: func(staff, _ string, loopback bool) bool { return staff == "" && !loopback },
		reason: envStaffEdgeSecret + " (or " + envStaffEdgeSecretFile + ") is required off loopback: the staff process " +
			"authenticates its edge with its own secret, never " + envEdgeSharedSecret,
	},
	{
		match: func(staff, serve string, _ bool) bool {
			return staff != "" && serve != "" && subtle.ConstantTimeCompare([]byte(staff), []byte(serve)) == 1
		},
		reason: envStaffEdgeSecret + " equals " + envEdgeSharedSecret + "; generate a separate secret for the staff edge " +
			"(e.g. openssl rand -hex 32) so the customer edge secret never authenticates a hop to the staff console",
	},
}

// resolveStaffEdgeSecret reads the staff edge secret (the variable, else the
// file it names) and walks staffEdgeRules. serve's SBCI_EDGE_SHARED_SECRET is
// read only for the equality refusal. It is pure over getenv and readFile, so
// every row is table-tested. It never logs either value.
func resolveStaffEdgeSecret(getenv func(string) string, readFile func(string) ([]byte, error), loopback bool) (string, error) {
	staff := strings.TrimSpace(getenv(envStaffEdgeSecret))
	if staff == "" {
		if path := strings.TrimSpace(getenv(envStaffEdgeSecretFile)); path != "" {
			b, err := readFile(path)
			if err != nil {
				return "", fmt.Errorf("observer-cloud staff serve: %s: %w", envStaffEdgeSecretFile, err)
			}
			staff = strings.TrimSpace(string(b))
		}
	}
	serve := strings.TrimSpace(getenv(envEdgeSharedSecret))
	for _, r := range staffEdgeRules {
		if r.match(staff, serve, loopback) {
			return "", fmt.Errorf("observer-cloud staff serve: %s", r.reason)
		}
	}
	return staff, nil
}

// staffServeConfig is the staff process's resolved configuration.
type staffServeConfig struct {
	listen  string
	baseURL string
	host    string
	dsn     string
	// devFallback is true when the DSN is the admin SBCI_PG_DSN (loopback
	// only); the login checks then warn instead of refusing.
	devFallback bool
	loopback    bool
	// supportIssuer is the issuer the support authorize route writes codes
	// for ("" leaves the route answering not_available).
	supportIssuer string
}

// staffHostRule is one row of the staff host table: a host the staff
// console must never share, read from the environment the processes share.
type staffHostRule struct {
	env    string
	reason string
}

// staffHostRules is walked top down; the staff host (the relying-party id)
// must differ from every configured value, so a staff passkey is never
// scoped to the portal, the API, or the parent domain of every tenant
// (ruling A3).
var staffHostRules = []staffHostRule{
	{env: "SBCI_PORTAL_HOST", reason: "the customer portal's host"},
	{env: "SBCI_API_HOST", reason: "the device API's host"},
	{env: "SBCI_TENANT_DOMAIN", reason: "the parent domain of every tenant (a passkey there would be usable on every tenant subdomain)"},
}

// resolveStaffServeConfig resolves and validates the staff process's
// environment. It is pure over getenv, so every refusal is table-tested.
func resolveStaffServeConfig(getenv func(string) string) (staffServeConfig, error) {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	c := staffServeConfig{listen: get(envStaffListen), baseURL: strings.TrimRight(get(envStaffBaseURL), "/")}
	if c.listen == "" {
		c.listen = defaultStaffListen
	}
	if c.baseURL == "" {
		c.baseURL = api.DefaultStaffBaseURL
	}
	u, err := url.Parse(c.baseURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return staffServeConfig{}, fmt.Errorf("%s %q must be an origin, scheme://host[:port]", envStaffBaseURL, c.baseURL)
	}
	c.loopback = isLoopbackOrigin(c.baseURL)
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && c.loopback:
	default:
		return staffServeConfig{}, fmt.Errorf("%s %q must be https (http only on loopback)", envStaffBaseURL, c.baseURL)
	}
	rpID := api.NormalizeHost(u.Hostname())
	c.host = api.NormalizeHost(get(envStaffHost))
	if c.host == "" {
		c.host = rpID
	}
	if c.host != rpID {
		return staffServeConfig{}, fmt.Errorf("%s %q must equal the host of %s (%q): that host is the WebAuthn relying-party id", envStaffHost, c.host, envStaffBaseURL, rpID)
	}
	if !c.loopback && strings.Count(rpID, ".") < 2 {
		return staffServeConfig{}, fmt.Errorf("the staff host %q is a registrable domain; use a subdomain of its own (default %s), never the parent domain", rpID, api.DefaultStaffHost)
	}
	for _, r := range staffHostRules {
		if v := api.NormalizeHost(get(r.env)); v != "" && v == rpID {
			return staffServeConfig{}, fmt.Errorf("the staff host %q equals %s, %s; the staff console needs a host of its own", rpID, r.env, r.reason)
		}
	}
	if c.supportIssuer = get(envStaffSupportIss); c.supportIssuer != "" {
		if _, err := oidcissuer.ValidateIssuerURL(c.supportIssuer); err != nil {
			return staffServeConfig{}, fmt.Errorf("%s: %w", envStaffSupportIss, err)
		}
	}
	c.dsn = get(envStaffDSN)
	if c.dsn == "" {
		if !c.loopback {
			return staffServeConfig{}, fmt.Errorf("%s is required: the staff process connects only with the staff login (sbci_staff_svc)", envStaffDSN)
		}
		c.dsn = get("SBCI_PG_DSN")
		c.devFallback = true
		if c.dsn == "" {
			return staffServeConfig{}, fmt.Errorf("%s (or, on loopback, SBCI_PG_DSN) is required", envStaffDSN)
		}
	}
	return c, nil
}

// loginRule is one row of a login-membership table: a predicate over the
// login's memberships and the refusal it earns.
type loginRule struct {
	match  func(store.LoginMemberships) bool
	reason string
}

// staffLoginRules: what the staff process's login must and must not be.
var staffLoginRules = []loginRule{
	{match: func(m store.LoginMemberships) bool { return !m.Staff }, reason: "is not a member of sbci_staff (grant it to the staff login: GRANT sbci_staff TO sbci_staff_svc)"},
	{match: func(m store.LoginMemberships) bool { return m.Superuser }, reason: "is a superuser; the staff process must connect with the least-privileged staff login"},
	{match: func(m store.LoginMemberships) bool { return m.API }, reason: "is a member of sbci_api (the customer role); the staff login must hold sbci_staff only"},
	{match: func(m store.LoginMemberships) bool { return m.Worker }, reason: "is a member of sbci_worker; the staff login must hold sbci_staff only"},
}

// serveLoginRules: what the customer serve process's login must not be.
var serveLoginRules = []loginRule{
	{match: func(m store.LoginMemberships) bool { return m.Staff }, reason: "can SET ROLE sbci_staff; the customer login must never hold the staff role (ruling A3; migration 0076 revokes it)"},
}

// checkLogin walks rules over m: in strict mode the first match refuses,
// otherwise every match is a warning (the loopback or single-login dev
// posture, where one admin login runs everything).
func checkLogin(log *slog.Logger, what string, m store.LoginMemberships, rules []loginRule, strict bool) error {
	for _, r := range rules {
		if !r.match(m) {
			continue
		}
		if strict {
			return fmt.Errorf("observer-cloud %s: database login %q %s", what, m.Login, r.reason)
		}
		log.Warn("observer-cloud: "+what+" login check (dev posture, not enforced)", "login", m.Login, "finding", r.reason)
	}
	return nil
}

// refuseStaffInServe is the first half of the customer serve process's
// refusal (ruling A3): it never holds the staff login's DSN. The second
// half is checkLogin over serveLoginRules: in the split posture
// (SBCI_API_PG_DSN set) its own login must not be able to become
// sbci_staff.
func refuseStaffInServe(getenv func(string) string) error {
	if strings.TrimSpace(getenv(envStaffDSN)) != "" {
		return fmt.Errorf("observer-cloud serve: %s is set; the staff login belongs to the staff process alone (`observer-cloud staff serve`), never to the customer serve process", envStaffDSN)
	}
	return nil
}

// loginReader is the store method checkServeIsNotStaff needs.
type loginReader interface {
	LoginMemberships(ctx context.Context) (store.LoginMemberships, error)
}

// checkServeIsNotStaff runs both halves of serve's refusal.
func checkServeIsNotStaff(ctx context.Context, log *slog.Logger, s loginReader, getenv func(string) string) error {
	if err := refuseStaffInServe(getenv); err != nil {
		return err
	}
	m, err := s.LoginMemberships(ctx)
	if err != nil {
		return err
	}
	return checkLogin(log, "serve", m, serveLoginRules, strings.TrimSpace(getenv("SBCI_API_PG_DSN")) != "")
}

func newStaffServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "run the staff console (its own process, host, listener and database login)",
		Long: "Serve ONLY the /staff route group, on " + defaultStaffListen + " by default, for the staff host\n" +
			"(" + api.DefaultStaffHost + " by default), connected as the staff login (" + envStaffDSN + ").\n" +
			"Staff sign in with a passkey (WebAuthn, user verification required); the first\n" +
			"passkey of a staff member is registered with a code from `observer-cloud staff enrol`.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := slog.Default()
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			cfg, err := resolveStaffServeConfig(os.Getenv)
			if err != nil {
				return err
			}
			if cfg.devFallback {
				log.Warn("observer-cloud: staff serve is using SBCI_PG_DSN (loopback dev only); production sets " + envStaffDSN)
			}
			s, err := openStaffStore(ctx, cfg.dsn)
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			m, err := s.LoginMemberships(ctx)
			if err != nil {
				return err
			}
			if err := checkLogin(log, "staff serve", m, staffLoginRules, !cfg.devFallback && !cfg.loopback); err != nil {
				return err
			}
			edgeSecret, err := resolveStaffEdgeSecret(os.Getenv, os.ReadFile, cfg.loopback)
			if err != nil {
				return err
			}
			edge, err := edgeConfigForOrigin(cfg.baseURL, edgeSecret, envStaffEdgeSecret)
			if err != nil {
				return fmt.Errorf("observer-cloud staff serve: %w", err)
			}
			apiServer := api.New(api.Options{
				Store:               s,
				Logger:              log,
				Edge:                edge,
				StaffWebAuthn:       passkey.New(),
				StaffBaseURL:        cfg.baseURL,
				StaffHost:           cfg.host,
				StaffSessionTTL:     parseOptionalDuration(log, envStaffSessionTTL),
				StaffSessionIdleTTL: parseOptionalDuration(log, envStaffIdleTTL),
				// M7a.2: the support authorize route; "" keeps it 501.
				StaffSupportIssuer: cfg.supportIssuer,
				// M6.8: the staff console's own SPA under /staff/.
				StaffSPA: webcloud.StaffHandler(),
			})
			log.Info("observer-cloud: staff console", "base_url", cfg.baseURL, "host", cfg.host, "login", m.Login)
			return runHTTPServer(ctx, log, "observer-cloud: staff serving", cfg.listen, apiServer.StaffHandler())
		},
	}
}

// staffStoreDSN is the DSN the operator's staff commands connect with: the
// staff login when SBCI_STAFF_PG_DSN is set, else the admin SBCI_PG_DSN
// (which works only when that login is a superuser or a member of
// sbci_staff, the dev posture).
func staffStoreDSN() (string, error) {
	if d := strings.TrimSpace(os.Getenv(envStaffDSN)); d != "" {
		return d, nil
	}
	return envDSN()
}

// openStaffStore opens a Store bound to sbci_staff over dsn. The staff
// tables need no evidence key or deletion journal. They need no tenant
// context either, but the store still needs the deployment's configured
// tenant-context key (SBCI_TENANT_CONTEXT_KEY[_FILE], tenantkey.go): without
// one it would try to install a process-random key before its first
// transaction, which the staff login may not do (cloud 0067), so every staff
// transaction would fail.
func openStaffStore(ctx context.Context, dsn string) (*store.Store, error) {
	pool, err := clouddb.Open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	s, err := store.NewForRole(pool, store.RoleStaff)
	if err != nil {
		pool.Close()
		return nil, err
	}
	if err := applyTenantContextKey(s); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}
