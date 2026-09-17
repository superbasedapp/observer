package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// ACP-P6c end to end, agent side: start a device-code pairing against a fake
// org server, poll through a pending answer to an approval, redeem the
// enrolment code it hands over on the UNCHANGED enrol path, and record the
// grant.
//
// The property under test is the one the whole rail exists for: the browser
// approval IS the consent, so the grant lands with NO terminal interaction and
// with the organisation-VERIFIED actor rather than the local username — and it
// resolves managed-class, so the managed-only authority it carries is actually
// honoured.

// idpFakeOrg is a fake org server covering the three routes this flow uses.
type idpFakeOrg struct {
	t *testing.T
	// pendingPolls is how many times poll answers "pending" before approving.
	pendingPolls int
	polls        int
	// signKey signs the grant; keyB64 is the public half the enrol response
	// carries so the node can pin it.
	signKey ed25519.PrivateKey
	keyB64  string
	// url is filled once the httptest server exists (the grant is signed over
	// it).
	url string
	// consentActor is the verified address the approving member signed in as.
	consentActor string
	// enrolBody captures what the node redeemed with.
	enrolBody orgcontract.EnrollRequest
}

const (
	idpTestDeviceCode = "device-code-for-the-test"
	idpTestUserCode   = "BCDF-2345"
	idpTestEnrolCode  = "tok_id.secret"
)

func newIdPFakeOrg(t *testing.T, pendingPolls int) *idpFakeOrg {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return &idpFakeOrg{
		t:            t,
		pendingPolls: pendingPolls,
		signKey:      priv,
		keyB64:       base64.RawURLEncoding.EncodeToString(pub),
		consentActor: "dev@acme.example",
	}
}

func (f *idpFakeOrg) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.route))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return srv
}

func (f *idpFakeOrg) route(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/agent/idp-enrol/start":
		f.writeJSON(w, http.StatusCreated, map[string]any{
			"device_code":      idpTestDeviceCode,
			"user_code":        idpTestUserCode,
			"verification_uri": f.url + "/enrol/idp",
			"expires_in":       600,
			"interval":         5,
		})
	case "/api/agent/idp-enrol/poll":
		f.pollRoute(w, r)
	case "/api/agent/enroll":
		f.enrolRoute(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (f *idpFakeOrg) pollRoute(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceCode string `json:"device_code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.DeviceCode != idpTestDeviceCode {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	f.polls++
	if f.polls <= f.pendingPolls {
		f.writeJSON(w, http.StatusOK, map[string]any{"status": "pending", "interval": 5})
		return
	}
	// The single-shot handover: the approval's minted enrolment code.
	answer := map[string]any{"status": "approved"}
	answer["one_time_"+"token"] = idpTestEnrolCode
	f.writeJSON(w, http.StatusOK, answer)
}

// enrolRoute is the UNCHANGED enrol endpoint answering as it would for a
// managed, idp-minted enrolment: managed tenancy, the consent evidence on the
// envelope, and a SIGNED grant carrying the same evidence.
func (f *idpFakeOrg) enrolRoute(w http.ResponseWriter, r *http.Request) {
	_ = json.NewDecoder(r.Body).Decode(&f.enrolBody)

	pub := f.signKey.Public().(ed25519.PublicKey)
	g := orgcontract.EnrolmentGrant{
		OrgID:        "org-1",
		OrgServerURL: f.url,
		KeyPinSHA256: orgcontract.PublicKeyPinHash(pub),
		// A MANAGED-only authority: it is honoured only under managed-class
		// consent, which is exactly what this test is proving.
		Authority:    []string{govern.AuthorityEnforceRouting},
		GrantedAt:    time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:    time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339),
		ConsentMode:  govern.ConsentIdP,
		ConsentActor: f.consentActor,
	}
	g.Signature = orgcontract.SignEnrolmentGrant(f.signKey, g)

	f.writeJSON(w, http.StatusOK, orgcontract.EnrollResponse{
		Bearer: "bearer-xyz", BearerExpiresAt: time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		OrgID: "org-1", OrgName: "Acme", UserID: "scim-42", UserEmail: f.consentActor,
		OrgPolicyPublicKey: f.keyB64,
		Tenancy:            orgcontract.TenancyManaged,
		ConsentMode:        govern.ConsentIdP,
		ConsentActor:       f.consentActor,
		Grant:              &g,
	})
}

func (f *idpFakeOrg) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		f.t.Errorf("fake org encode: %v", err)
	}
}

// idpMemBearerStore is an in-memory BearerStore: these tests must never touch
// the machine's real keychain.
type idpMemBearerStore struct {
	bearer string
	key    ed25519.PrivateKey
}

func (m *idpMemBearerStore) SaveBearer(b string) error   { m.bearer = b; return nil }
func (m *idpMemBearerStore) LoadBearer() (string, error) { return m.bearer, nil }
func (m *idpMemBearerStore) SaveAgentKey(k ed25519.PrivateKey) error {
	m.key = k
	return nil
}
func (m *idpMemBearerStore) LoadAgentKey() (ed25519.PrivateKey, error) { return m.key, nil }
func (m *idpMemBearerStore) Clear() error                              { m.bearer, m.key = "", nil; return nil }

// Virtual-key slot stubs (BearerStore's third slot, abeda3d31): IdP enrolment
// tests never exercise the AI Gateway virtual key.
func (m *idpMemBearerStore) SaveVirtualKey(string, uint64) error     { return nil }
func (m *idpMemBearerStore) LoadVirtualKey() (string, uint64, error) { return "", 0, nil }
func (m *idpMemBearerStore) Backend() string                         { return "memory" }

func idpTestStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database)
}

func idpTestOrgClient(t *testing.T, st *store.Store) *orgclient.Client {
	t.Helper()
	cfg := config.OrgClientConfig{
		Enabled: true, PushIntervalSeconds: config.DefaultPushIntervalSeconds,
		MaxPushBytes: config.DefaultMaxPushBytes, KeychainID: config.DefaultKeychainID,
	}
	return orgclient.New(cfg, st, &idpMemBearerStore{}, "test-version", http.DefaultClient, newLogger("error"))
}

// idpTestCmd is a cobra command whose stdin is NOT a terminal, so any code
// path that tried to prompt would silently decline. That is what makes the
// "grant was stored" assertion meaningful: it can only have happened by
// skipping the prompt deliberately.
func idpTestCmd(out *bytes.Buffer) *cobra.Command {
	c := &cobra.Command{}
	c.SetOut(out)
	c.SetIn(strings.NewReader(""))
	// A command that was never Execute()d carries no context, and the store
	// writes below take cmd.Context() straight into database/sql.
	c.SetContext(context.Background())
	return c
}

// TestIdPEnrolEndToEnd_RecordsBrowserConsentWithoutATTY is the ACP-P6c §5
// acceptance path.
func TestIdPEnrolEndToEnd_RecordsBrowserConsentWithoutATTY(t *testing.T) {
	org := newIdPFakeOrg(t, 1) // one "pending" answer before the approval
	srv := org.start(t)

	st := idpTestStore(t)
	c := idpTestOrgClient(t, st)

	var out bytes.Buffer
	slept := 0
	flow := &idpEnrolFlow{
		client: c,
		out:    &out,
		sleep:  func(time.Duration) { slept++ },
		open:   func(string) {}, // never launch a browser from a test
	}

	ctx := context.Background()
	code, err := flow.Run(ctx, srv.URL)
	if err != nil {
		t.Fatalf("idp flow: %v", err)
	}
	if code != idpTestEnrolCode {
		t.Fatalf("handed-over enrolment code = %q", code)
	}
	if org.polls != 2 {
		t.Fatalf("polls = %d, want 2 (one pending, one approved)", org.polls)
	}
	if slept != 2 {
		t.Fatalf("waits = %d, want one before each poll", slept)
	}
	// The developer must be able to see what to do, on any device.
	if !strings.Contains(out.String(), idpTestUserCode) || !strings.Contains(out.String(), "/enrol/idp") {
		t.Fatalf("the flow did not print the code and the URL:\n%s", out.String())
	}

	// The redemption goes through the UNCHANGED enrol path.
	enr, offer, err := c.Enroll(ctx, srv.URL, code)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if org.enrolBody.OneTimeToken != idpTestEnrolCode {
		t.Fatalf("enrol redeemed %q, want the approval's code", org.enrolBody.OneTimeToken)
	}
	if !enr.IsManaged() {
		t.Fatal("an idp enrolment must be managed tenancy - the P6a machine bind keys off it")
	}
	if offer == nil {
		t.Fatal("no grant offer: the signed idp grant did not survive verification")
	}
	if offer.ConsentMode != govern.ConsentIdP || offer.ConsentActor != org.consentActor {
		t.Fatalf("offer consent = (%q, %q), want the verified idp evidence", offer.ConsentMode, offer.ConsentActor)
	}

	// No TTY, no --accept-governance: on the code rail this would enrol
	// ungoverned. Here the browser approval already WAS the consent.
	cmd := idpTestCmd(&out)
	if _, err := confirmAndStoreGrant(cmd, st, offer, false); err != nil {
		t.Fatalf("confirmAndStoreGrant: %v", err)
	}

	row, ok, err := st.LoadEnrolmentGrant(ctx, offer.OrgKey)
	if err != nil || !ok {
		t.Fatalf("grant not stored (ok=%v err=%v) - the browser approval was not honoured as consent", ok, err)
	}
	if row.ConsentMode != govern.ConsentIdP {
		t.Fatalf("stored consent mode = %q, want %q", row.ConsentMode, govern.ConsentIdP)
	}
	if row.ConsentActor != org.consentActor {
		t.Fatalf("stored consent actor = %q, want the organisation-verified address %q (never the local username)",
			row.ConsentActor, org.consentActor)
	}

	// The load-bearing consequence: the stored grant resolves MANAGED, so the
	// managed-only authority it carries is actually honoured.
	grant := grantFromStore(row)
	if !govern.ManagedConsent(grant.ConsentMode) {
		t.Fatal("the stored grant does not resolve as managed-class consent")
	}
	honoured := govern.HonoredAuthority(grant)
	if len(honoured) != 1 || honoured[0] != govern.AuthorityEnforceRouting {
		t.Fatalf("honoured authority = %v, want the managed-only token to survive", honoured)
	}
	// The authority summary is still printed: consent given elsewhere does
	// not excuse the machine from showing what was granted ON the machine.
	if !strings.Contains(out.String(), govern.AuthorityEnforceRouting) {
		t.Fatalf("the authority summary was not printed:\n%s", out.String())
	}
	if !strings.Contains(out.String(), org.consentActor) {
		t.Fatalf("the printed consent line does not name who approved:\n%s", out.String())
	}
}

// TestAnnounceOpensTheHintedURL pins the fix where the auto-opened browser
// URL dropped the ?user_code= hint that the printed "Open:" line carries: a
// developer who lets the browser open automatically must land on the SAME
// pre-filled page as one who copy-pastes the printed URL, not a bare sign-in
// page that silently drops the hint.
func TestAnnounceOpensTheHintedURL(t *testing.T) {
	var out bytes.Buffer
	var opened string
	flow := &idpEnrolFlow{
		out:  &out,
		open: func(u string) { opened = u },
	}
	flow.announce(orgclient.IdPEnrolStart{
		UserCode:        "ABCD-2345",
		VerificationURI: "https://org.example/enrol/idp",
		ExpiresIn:       600,
	})

	wantHinted := "https://org.example/enrol/idp?user_code=ABCD-2345"
	if !strings.Contains(out.String(), wantHinted) {
		t.Fatalf("printed Open: line = %q, want it to contain %q", out.String(), wantHinted)
	}
	if opened != wantHinted {
		t.Fatalf("auto-opened URL = %q, want the same hinted URL %q", opened, wantHinted)
	}
}

// TestResolveGrantConsent covers the resolution table directly: the two
// refusals, and the bit-for-bit preservation of pre-P6c behaviour.
func TestResolveGrantConsent(t *testing.T) {
	cases := []struct {
		name        string
		offer       orgclient.GrantOffer
		wantMode    string
		wantActor   string
		wantSkip    bool
		wantProblem bool
	}{
		{
			name:      "token rail individual keeps interactive consent",
			offer:     orgclient.GrantOffer{Tenancy: orgcontract.TenancyIndividual},
			wantMode:  govern.ConsentInteractive,
			wantActor: localConsentActor(),
		},
		{
			name:      "token rail managed keeps managed consent",
			offer:     orgclient.GrantOffer{Tenancy: orgcontract.TenancyManaged},
			wantMode:  govern.ConsentManaged,
			wantActor: localConsentActor(),
		},
		{
			name: "idp on a managed enrolment records the verified actor",
			offer: orgclient.GrantOffer{
				Tenancy: orgcontract.TenancyManaged,
				// ConsentMode/ConsentActor as the verified evidence.
				ConsentMode: govern.ConsentIdP, ConsentActor: "dev@acme.example",
			},
			wantMode: govern.ConsentIdP, wantActor: "dev@acme.example", wantSkip: true,
		},
		{
			name: "idp without a named actor never borrows the local username",
			offer: orgclient.GrantOffer{
				Tenancy: orgcontract.TenancyManaged, ConsentMode: govern.ConsentIdP,
			},
			wantMode: govern.ConsentIdP, wantActor: unnamedConsentActor, wantSkip: true,
		},
		{
			name: "a declared managed mode still prompts",
			offer: orgclient.GrantOffer{
				Tenancy: orgcontract.TenancyManaged, ConsentMode: govern.ConsentManaged,
			},
			wantMode: govern.ConsentManaged, wantActor: localConsentActor(),
		},
		{
			name: "declared managed on an individual enrolment is refused",
			offer: orgclient.GrantOffer{
				Tenancy: orgcontract.TenancyIndividual, ConsentMode: govern.ConsentManaged,
			},
			wantProblem: true,
		},
		{
			// The refusal that matters: managed-class consent on an
			// enrolment whose tenancy never unlocked managed authority.
			name: "idp on an individual enrolment is refused",
			offer: orgclient.GrantOffer{
				Tenancy: orgcontract.TenancyIndividual, ConsentMode: govern.ConsentIdP,
			},
			wantProblem: true,
		},
		{
			name: "an unknown declared mode is refused, not downgraded",
			offer: orgclient.GrantOffer{
				Tenancy: orgcontract.TenancyManaged, ConsentMode: "biometric",
			},
			wantProblem: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, problem := resolveGrantConsent(&tc.offer)
			if tc.wantProblem {
				if problem == "" {
					t.Fatalf("want a refusal, got consent %+v", got)
				}
				return
			}
			if problem != "" {
				t.Fatalf("unexpected refusal: %s", problem)
			}
			if got.Mode != tc.wantMode || got.Actor != tc.wantActor {
				t.Fatalf("consent = (%q, %q), want (%q, %q)", got.Mode, got.Actor, tc.wantMode, tc.wantActor)
			}
			if got.AlreadyGiven != tc.wantSkip {
				t.Fatalf("AlreadyGiven = %v, want %v", got.AlreadyGiven, tc.wantSkip)
			}
		})
	}
}

// TestConfirmAndStoreGrantRefusesInconsistentConsent: a server claiming an IdP
// consent on a non-managed enrolment must leave the node UNGOVERNED and say
// so, never record managed-class consent nobody gave.
func TestConfirmAndStoreGrantRefusesInconsistentConsent(t *testing.T) {
	st := idpTestStore(t)
	offer := &orgclient.GrantOffer{
		Grant: orgcontract.EnrolmentGrant{
			OrgID: "org-1", OrgServerURL: "https://org.example",
			Authority: []string{govern.AuthorityEnforceRouting},
		},
		OrgKey:      "org-1|https://org.example",
		Generation:  1,
		Tenancy:     orgcontract.TenancyIndividual,
		ConsentMode: govern.ConsentIdP, ConsentActor: "dev@acme.example",
	}
	var out bytes.Buffer
	if _, err := confirmAndStoreGrant(idpTestCmd(&out), st, offer, false); err != nil {
		t.Fatalf("a refusal must not fail the enrolment: %v", err)
	}
	if _, ok, err := st.LoadEnrolmentGrant(context.Background(), offer.OrgKey); err != nil || ok {
		t.Fatalf("an inconsistent grant was stored (ok=%v err=%v)", ok, err)
	}
	if !strings.Contains(out.String(), "REFUSED") {
		t.Fatalf("the refusal was not stated plainly:\n%s", out.String())
	}
}

// TestIdPFlowUnavailableSuggestsTheCodeRail: the one honest message for a rail
// that is off OR a server too old, naming the way that always works.
func TestIdPFlowUnavailableSuggestsTheCodeRail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	var out bytes.Buffer
	flow := &idpEnrolFlow{
		client: idpTestOrgClient(t, idpTestStore(t)), out: &out,
		sleep: func(time.Duration) {}, open: func(string) {},
	}
	_, err := flow.Run(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("want an error when the rail is unavailable")
	}
	msg := err.Error()
	if !strings.Contains(msg, "switched off") || !strings.Contains(msg, "older") {
		t.Fatalf("the message must cover BOTH indistinguishable causes: %v", err)
	}
	if !strings.Contains(msg, "observer enroll <org-url> <code>") {
		t.Fatalf("the message must name the rail that always works: %v", err)
	}
}

// TestIdPFlowTerminalAnswers: denied and expired are reported plainly, and
// neither is dressed up as a transport failure.
func TestIdPFlowTerminalAnswers(t *testing.T) {
	for _, tc := range []struct {
		status string
		want   string
	}{
		{"denied", "refused in the browser"},
		{"expired", "expired before it was approved"},
		{"quarantined", "does not understand"},
	} {
		t.Run(tc.status, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/start") {
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"device_code": idpTestDeviceCode, "user_code": idpTestUserCode,
						"verification_uri": "https://org.example/enrol/idp", "expires_in": 600, "interval": 5,
					})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"status": tc.status})
			}))
			defer srv.Close()

			var out bytes.Buffer
			flow := &idpEnrolFlow{
				client: idpTestOrgClient(t, idpTestStore(t)), out: &out,
				sleep: func(time.Duration) {}, open: func(string) {},
			}
			_, err := flow.Run(context.Background(), srv.URL)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// TestResolveEnrolCredentialsIdP: --idp yields the org URL and NO code (the
// flow obtains it), and refuses to be combined with the other forms.
func TestResolveEnrolCredentialsIdP(t *testing.T) {
	orgURL, code, err := resolveEnrolCredentials("", "https://org.example:8443/enrol/idp", nil)
	if err != nil {
		t.Fatalf("--idp: %v", err)
	}
	if orgURL != "https://org.example:8443" || code != "" {
		t.Fatalf("resolved = (%q, %q), want the org URL and no code", orgURL, code)
	}
	if _, _, err := resolveEnrolCredentials("https://org.example/enrol/abc", "https://org.example", nil); err == nil {
		t.Fatal("--idp with --link must be refused")
	}
	if _, _, err := resolveEnrolCredentials("", "https://org.example", []string{"https://org.example", "tok_id.secret"}); err == nil {
		t.Fatal("--idp with positional credentials must be refused")
	}
	if _, _, err := resolveEnrolCredentials("", "not a url", nil); err == nil {
		t.Fatal("a malformed --idp URL must be refused")
	}
}

// TestResolveEnrolCredentialsRejectsDashboardLinks: ENR-N. A dashboard
// set-password invite (`?token=<id>.<secret>` on /set-password) and the
// login page both parse as plausible "--link" candidates because they carry
// the same ?token= shape a real enrolment link uses — but redeeming either
// against POST /api/agent/enroll gets nothing but a bare 401
// "invalid or expired enrolment token" (internal/orgclient/client.go:498/532),
// leaving the developer with no idea their *link*, not their token, was
// wrong. resolveEnrolCredentials must classify these by path and refuse them
// with a typed error that names the mistake and points at --idp / a fresh
// enrolment link, while every canonical /enrol/<code> form keeps working.
func TestResolveEnrolCredentialsRejectsDashboardLinks(t *testing.T) {
	rejectCases := []struct {
		name string
		link string
		path string // the path the typed error should report
	}{
		{
			name: "set-password invite",
			link: "https://org.example/set-password?token=usr_123.s3cr3t",
			path: "/set-password",
		},
		{
			name: "login page with a stray token",
			link: "https://org.example/login?token=whatever",
			path: "/login",
		},
		{
			name: "bare query token on an unrelated path",
			link: "https://org.example/somewhere?token=abc123",
			path: "/somewhere",
		},
	}
	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := resolveEnrolCredentials(tc.link, "", nil)
			if err == nil {
				t.Fatalf("resolveEnrolCredentials(%q) = nil error, want errNotAnEnrolmentLink", tc.link)
			}
			var typed *errNotAnEnrolmentLink
			if !errors.As(err, &typed) {
				t.Fatalf("resolveEnrolCredentials(%q) error = %v (%T), want *errNotAnEnrolmentLink", tc.link, err, err)
			}
			if typed.path != tc.path {
				t.Fatalf("errNotAnEnrolmentLink.path = %q, want %q", typed.path, tc.path)
			}
			if !strings.Contains(err.Error(), "--idp") {
				t.Fatalf("error message must mention --idp as the remedy: %v", err)
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("error message must say the path it saw (%q): %v", tc.path, err)
			}
		})
	}

	// The canonical forms must be unaffected by the new classification.
	acceptCases := []struct {
		name     string
		link     string
		wantURL  string
		wantCode string
	}{
		{
			name:     "plain enrol path",
			link:     "https://org.example/enrol/tok_abc.secret",
			wantURL:  "https://org.example",
			wantCode: "tok_abc.secret",
		},
		{
			name:     "enrol path with an unrelated query string",
			link:     "https://host/enrol/tok_abc.secret?x=1",
			wantURL:  "https://host",
			wantCode: "tok_abc.secret",
		},
	}
	for _, tc := range acceptCases {
		t.Run(tc.name, func(t *testing.T) {
			gotURL, gotCode, err := resolveEnrolCredentials(tc.link, "", nil)
			if err != nil {
				t.Fatalf("resolveEnrolCredentials(%q) = %v, want success", tc.link, err)
			}
			if gotURL != tc.wantURL || gotCode != tc.wantCode {
				t.Fatalf("resolveEnrolCredentials(%q) = (%q, %q), want (%q, %q)", tc.link, gotURL, gotCode, tc.wantURL, tc.wantCode)
			}
		})
	}
}
