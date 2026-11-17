package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// hostapiworker_test.go: the worker's host-API wiring is off unless its
// switch is set, a half configuration refuses to start, and the signer's
// published keys are checked before anything is composed. The end-to-end
// run against the tenant host lives in hostapiworker_e2e_test.go.

func TestResolveHostAPIWorkerConfig(t *testing.T) {
	t.Parallel()
	full := map[string]string{
		envHostAPIHostsFile: "/etc/sbci/hosts.json", envHostAPICAFile: "/etc/sbci/ca.pem",
		envHostAPICertFile: "/etc/sbci/client.pem", envHostAPIKeyFile: "/etc/sbci/client.key",
	}
	with := func(over map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range full {
			m[k] = v
		}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name    string
		env     map[string]string
		enabled bool
		socket  string
		wantErr string
	}{
		{name: "nothing set is off", env: map[string]string{}},
		{name: "the signer socket alone is still off", env: map[string]string{envDocSignerSocket: "/run/x.sock"}},
		{name: "full configuration with the default socket", env: full, enabled: true, socket: defaultDocSignerSocket},
		{name: "explicit socket", env: with(map[string]string{envDocSignerSocket: "/run/d.sock"}), enabled: true, socket: "/run/d.sock"},
		{name: "a TLS file without the switch", env: map[string]string{envHostAPICAFile: "/x"}, wantErr: envHostAPIHostsFile},
		{name: "no CA", env: with(map[string]string{envHostAPICAFile: " "}), wantErr: envHostAPICAFile},
		{name: "no client certificate", env: with(map[string]string{envHostAPICertFile: ""}), wantErr: envHostAPICertFile},
		{name: "no client key", env: with(map[string]string{envHostAPIKeyFile: ""}), wantErr: envHostAPIKeyFile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, enabled, err := resolveHostAPIWorkerConfig(envMap(tc.env))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || enabled {
					t.Fatalf("err = %v, enabled = %v; want an error naming %s", err, enabled, tc.wantErr)
				}
				return
			}
			if err != nil || enabled != tc.enabled || (enabled && cfg.signerSocket != tc.socket) {
				t.Fatalf("cfg = %+v, enabled = %v, err = %v", cfg, enabled, err)
			}
		})
	}
}

// TestWorkerStartsAsBeforeWithoutTheNewEnvironment: with no SBCI_HOSTAPI_*
// variable the worker's host-API hook reads no file, touches no store and
// starts nothing.
func TestWorkerStartsAsBeforeWithoutTheNewEnvironment(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	readFile := func(string) ([]byte, error) {
		t.Fatal("a file was read with the host-API client off")
		return nil, nil
	}
	started, err := startHostAPIWorker(context.Background(), log, nil, envMap(map[string]string{
		"SBCI_PG_DSN": "postgres://x", envDocSignerSocket: "/run/unused.sock",
	}), readFile)
	if err != nil || started {
		t.Fatalf("started = %v, err = %v; want off", started, err)
	}
}

func TestStartHostAPIWorkerRefusesUnreadableFiles(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	env := envMap(map[string]string{
		envHostAPIHostsFile: "/h", envHostAPICAFile: "/ca", envHostAPICertFile: "/c", envHostAPIKeyFile: "/k",
	})
	_, err := startHostAPIWorker(context.Background(), log, nil, env, func(string) ([]byte, error) { return nil, errors.New("no such file") })
	if err == nil {
		t.Fatal("an unreadable hosts file started the client")
	}
	big := func(string) ([]byte, error) { return make([]byte, maxHostAPIConfigFile+1), nil }
	if _, err := startHostAPIWorker(context.Background(), log, nil, env, big); err == nil {
		t.Fatal("an oversized file started the client")
	}
}

// fakeDocSigner is a docSignerClient with a fixed key list.
type fakeDocSigner struct{ keys []signerd.PublishedKey }

func (f fakeDocSigner) PublicKeys(context.Context) ([]signerd.PublishedKey, error) {
	return f.keys, nil
}

func (fakeDocSigner) SignDocument(context.Context, pc.DocumentKind, string, int64, []byte) (signerd.SignedDocument, error) {
	return signerd.SignedDocument{}, errors.New("unused")
}

func (fakeDocSigner) SignRequest(context.Context, string, string, string, string, int64) (pc.Envelope, error) {
	return pc.Envelope{}, errors.New("unused")
}

func seededKey(seed string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(seed))
	return ed25519.NewKeyFromSeed(s[:])
}

func published(p signerd.Purpose, k ed25519.PrivateKey, signing bool) signerd.PublishedKey {
	pub := k.Public().(ed25519.PublicKey)
	return signerd.PublishedKey{Purpose: p, KeyID: pc.DocumentKeyID(pub), Public: pub, Signing: signing}
}

func TestReadSignerKeys(t *testing.T) {
	t.Parallel()
	ent, ent2, host := seededKey("ent"), seededKey("ent-next"), seededKey("host")
	good := []signerd.PublishedKey{
		published(signerd.PurposeEntitlements, ent, true), published(signerd.PurposeEntitlements, ent2, false),
		published(signerd.PurposeAvailability, seededKey("avail"), true), published(signerd.PurposeHostAPI, host, true),
	}
	got, err := readSignerKeys(context.Background(), fakeDocSigner{keys: good}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.hostKeyID != pc.DocumentKeyID(host.Public().(ed25519.PublicKey)) || len(got.entitlements) != 2 {
		t.Fatalf("keys = %+v", got)
	}
	compiledOther := pc.KeySet{pc.NewDocumentKey(seededKey("compiled").Public().(ed25519.PublicKey))}
	forged := published(signerd.PurposeHostAPI, host, true)
	forged.KeyID = "not-the-derived-id"
	for name, tc := range map[string]struct {
		keys     []signerd.PublishedKey
		compiled pc.KeySet
	}{
		"no host-API key":               {keys: good[:3]},
		"host-API key not signing":      {keys: append(append([]signerd.PublishedKey{}, good[:3]...), published(signerd.PurposeHostAPI, host, false))},
		"no signing entitlements key":   {keys: good[1:]},
		"a key whose id is not derived": {keys: append(append([]signerd.PublishedKey{}, good[:3]...), forged)},
		"signing key not compiled in":   {keys: good, compiled: compiledOther},
	} {
		if _, err := readSignerKeys(context.Background(), fakeDocSigner{keys: tc.keys}, tc.compiled); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	compiledOurs := pc.KeySet{pc.NewDocumentKey(ent.Public().(ed25519.PublicKey))}
	if _, err := readSignerKeys(context.Background(), fakeDocSigner{keys: good}, compiledOurs); err != nil {
		t.Fatalf("signing key compiled in: %v", err)
	}
}

// --- the support issuer in serve (M7a.2) ----------------------------------

func TestResolveOIDCServeSupportConfig(t *testing.T) {
	t.Parallel()
	issuer := testPortalBase + oidcissuer.IssuerPath
	staffURL := "https://staff.superbased.example" + oidcissuer.SupportAuthorizePath
	cfg, enabled, err := resolveOIDCServeConfig(envMap(map[string]string{"SBCI_OIDC_ISSUER": issuer}), fixedHost("vm-a", nil), testPortalBase)
	if err != nil || !enabled || cfg.supportAuthorizeURL != "" {
		t.Fatalf("issuer alone: cfg %+v enabled %v err %v; want the support path off", cfg, enabled, err)
	}
	cfg, enabled, err = resolveOIDCServeConfig(envMap(map[string]string{"SBCI_OIDC_ISSUER": issuer, envOIDCSupportAuthorizeURL: staffURL}),
		fixedHost("vm-a", nil), testPortalBase)
	if err != nil || !enabled || cfg.supportAuthorizeURL != staffURL {
		t.Fatalf("with support: cfg %+v enabled %v err %v", cfg, enabled, err)
	}
	if _, _, err := resolveOIDCServeConfig(envMap(map[string]string{envOIDCSupportAuthorizeURL: staffURL}), fixedHost("vm-a", nil), testPortalBase); err == nil {
		t.Fatal("the support path without the issuer was accepted")
	}
}

// serveSupportIssuer builds serve's issuer the way wireOIDCIssuer does, over
// in-memory seams, with the support path configured by env.
func serveSupportIssuer(t *testing.T, env map[string]string, sup *oidctest.MemSupport) *oidcissuer.Issuer {
	t.Helper()
	env["SBCI_OIDC_ISSUER"] = testPortalBase + oidcissuer.IssuerPath
	cfg, enabled, err := resolveOIDCServeConfig(envMap(env), fixedHost("vm-a", nil), testPortalBase)
	if err != nil || !enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
	key := oidctest.NewKey(t)
	signer, err := oidcissuer.NewLocalSigner(cfg.issuer, []*rsa.PrivateKey{key}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	sup.SetKey(oidctest.ActiveKey(key, "vm-a", time.Now().Add(-time.Hour)))
	iss, err := newServeOIDCIssuer(cfg, sup.MemStore, sup, signer)
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

// TestServeSupportIssuerRedeemsASupportCode: with
// SBCI_OIDC_SUPPORT_AUTHORIZE_URL set, serve's issuer advertises the staff
// authorize endpoint and redeems a staff member's support code into a token
// carrying support: true; without it, discovery is unchanged and the same
// code is refused.
func TestServeSupportIssuerRedeemsASupportCode(t *testing.T) {
	t.Parallel()
	const (
		org   = "aaaaaaaa-0000-4000-8000-000000000001"
		staff = "5f5e5d5c-5b5a-4958-8756-555453525150"
	)
	staffURL := "https://staff.superbased.example" + oidcissuer.SupportAuthorizePath
	newSup := func() *oidctest.MemSupport {
		sup := oidctest.NewMemSupport(oidctest.NewMemStore())
		c, err := oidcissuer.ClientForOrg(org, "acme", "superbased.example")
		if err != nil {
			t.Fatal(err)
		}
		sup.AddClient(c)
		sup.SetStaff(staff, true)
		sup.SetOrg(org, "active", true)
		return sup
	}
	verifier := strings.Repeat("v", 50)
	redirect := "https://acme.superbased.example/auth/oidc/callback"
	supportCode := func(t *testing.T, sup *oidctest.MemSupport) string {
		t.Helper()
		authz, err := oidcissuer.NewSupportAuthorizer(oidcissuer.SupportAuthorizerConfig{Issuer: testPortalBase + oidcissuer.IssuerPath, Store: sup})
		if err != nil {
			t.Fatal(err)
		}
		res := authz.Authorize(context.Background(), oidcissuer.AuthorizeRequest{
			ClientID: oidcissuer.ClientIDForOrg(org), RedirectURI: redirect, ResponseType: "code",
			Scope: "openid email profile", State: "s-1", Nonce: "n-1",
			CodeChallenge: oidcissuer.S256Challenge(verifier), CodeChallengeMethod: "S256",
		}, oidcissuer.StaffSession{StaffID: staff, AssertedAt: time.Now().Add(-time.Minute)})
		if res.Outcome != oidcissuer.OutcomeRedirect || res.Err != nil {
			t.Fatalf("support authorize = %+v (%v)", res, res.Err)
		}
		u, err := url.Parse(res.Location)
		if err != nil {
			t.Fatal(err)
		}
		return u.Query().Get("code")
	}
	token := func(code string) oidcissuer.TokenRequest {
		return oidcissuer.TokenRequest{
			GrantType: "authorization_code", Code: code, RedirectURI: redirect,
			ClientID: oidcissuer.ClientIDForOrg(org), CodeVerifier: verifier,
		}
	}

	// On.
	sup := newSup()
	iss := serveSupportIssuer(t, map[string]string{envOIDCSupportAuthorizeURL: staffURL}, sup)
	if d := iss.Discovery(); d.SupportAuthorizationEndpoint != staffURL {
		t.Fatalf("discovery support endpoint = %q", d.SupportAuthorizationEndpoint)
	}
	resp, err := iss.Token(context.Background(), token(supportCode(t, sup)))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	keys, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, err := oidcissuer.VerifyRS256(resp.IDToken, keys.Keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if !c.Support || c.Sub != oidcissuer.SupportSubject(staff) || c.Email != "" || c.Org != org {
		t.Fatalf("support claims = %+v", c)
	}
	if recs := sup.SupportIssued(); len(recs) != 1 || recs[0].StaffID != staff {
		t.Fatalf("support issuance recorded %+v", recs)
	}

	// Off (the deployment as it is today): no endpoint advertised, and a
	// support code is never redeemed.
	sup = newSup()
	iss = serveSupportIssuer(t, map[string]string{}, sup)
	if d := iss.Discovery(); d.SupportAuthorizationEndpoint != "" {
		t.Fatalf("discovery advertises %q with the support path off", d.SupportAuthorizationEndpoint)
	}
	if _, err := iss.Token(context.Background(), token(supportCode(t, sup))); err == nil {
		t.Fatal("a support code was redeemed with the support path off")
	}
}

func TestNewServeOIDCIssuerRefusesSupportWithoutAStore(t *testing.T) {
	t.Parallel()
	cfg := oidcServeConfig{issuer: testPortalBase + oidcissuer.IssuerPath, supportAuthorizeURL: "https://staff.superbased.example" + oidcissuer.SupportAuthorizePath}
	signer, err := oidcissuer.NewLocalSigner(cfg.issuer, []*rsa.PrivateKey{oidctest.NewKey(t)}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newServeOIDCIssuer(cfg, oidctest.NewMemStore(), nil, signer); err == nil {
		t.Fatal("support on with no support store was accepted")
	}
	cfg.supportAuthorizeURL = "https://staff.superbased.example/elsewhere"
	if _, err := newServeOIDCIssuer(cfg, oidctest.NewMemStore(), oidctest.NewMemSupport(oidctest.NewMemStore()), signer); err == nil {
		t.Fatal("a support authorize URL off the staff route was accepted")
	}
}

func TestStaffServeSupportIssuer(t *testing.T) {
	t.Parallel()
	base := map[string]string{envStaffBaseURL: "http://127.0.0.1:8091", "SBCI_PG_DSN": "postgres://x"}
	cfg, err := resolveStaffServeConfig(envMap(base))
	if err != nil || cfg.supportIssuer != "" {
		t.Fatalf("default: %+v, %v; want the support route off", cfg, err)
	}
	base[envStaffSupportIss] = testPortalBase + oidcissuer.IssuerPath
	if cfg, err := resolveStaffServeConfig(envMap(base)); err != nil || cfg.supportIssuer != testPortalBase+oidcissuer.IssuerPath {
		t.Fatalf("with the issuer: %+v, %v", cfg, err)
	}
	base[envStaffSupportIss] = "http://app.superbased.example/oauth2"
	if _, err := resolveStaffServeConfig(envMap(base)); err == nil {
		t.Fatal("a plain-http public issuer was accepted")
	}
}
