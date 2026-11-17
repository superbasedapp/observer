package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/orgenrol"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Settings > Enrolment management (backlog item 6), the cmd half: the
// dashboard manager runs the CLI's own enrol / consent / unenrol code paths
// against a fake org server. The properties pinned here are the ones a UI
// re-implementation would most easily get wrong: the token rail parks the
// grant for an explicit decision (never auto-accepts), an IdP approval IS the
// consent, a decision is refused for an enrolment the machine no longer
// holds, and every org-server refusal reaches the UI classified.

type enrolFakeOrg struct {
	t           *testing.T
	url         string
	tenancy     string
	consentMode string
	authority   []string
	enrolStatus int    // 0 = 200
	enrolError  string // error code for a non-200
	healthzOK   bool
	// frontEndHealthz makes /healthz answer like the shipped HAProxy front end
	// (monitor-uri: its own HTML), as on an estate fronted by it (T-718).
	frontEndHealthz bool
	signKey         ed25519.PrivateKey
	keyB64          string
	enrolCalls      int
	// pushStatus, when set, is the answer to every /api/agent/push (R3-78
	// drain tests); zero keeps the 404 every other test relies on.
	pushStatus int
	pushCalls  int
}

func newEnrolFakeOrg(t *testing.T, tenancy string, authority []string) *enrolFakeOrg {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &enrolFakeOrg{
		t: t, tenancy: tenancy, authority: authority, healthzOK: true, signKey: priv,
		keyB64: base64.RawURLEncoding.EncodeToString(pub),
	}
	srv := httptest.NewServer(http.HandlerFunc(f.route))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

func (f *enrolFakeOrg) route(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		if f.frontEndHealthz {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><h1>200 OK</h1>\nService ready.\n</body></html>\n"))
			return
		}
		if !f.healthzOK {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		f.json(w, http.StatusOK, map[string]any{"status": "ok"})
	case "/readyz":
		if !f.healthzOK {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		f.json(w, http.StatusOK, map[string]any{"status": "ok"})
	case "/api/agent/idp-enrol/start":
		f.json(w, http.StatusCreated, map[string]any{
			"device_code": idpTestDeviceCode, "user_code": idpTestUserCode,
			"verification_uri": f.url + "/enrol/idp", "expires_in": 600, "interval": 5,
		})
	case "/api/agent/idp-enrol/poll":
		answer := map[string]any{"status": "approved"}
		answer["one_time_"+"token"] = idpTestEnrolCode
		f.json(w, http.StatusOK, answer)
	case "/api/agent/push":
		f.pushCalls++
		if f.pushStatus == 0 {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		f.json(w, f.pushStatus, map[string]string{"error": "refused"})
	case "/api/agent/enroll":
		f.enrolCalls++
		if f.enrolStatus != 0 {
			f.json(w, f.enrolStatus, map[string]string{"error": f.enrolError, "message": "no"})
			return
		}
		pub := f.signKey.Public().(ed25519.PublicKey)
		var grant *orgcontract.EnrolmentGrant
		if len(f.authority) > 0 {
			g := orgcontract.EnrolmentGrant{
				OrgID: "org-1", OrgServerURL: f.url, KeyPinSHA256: orgcontract.PublicKeyPinHash(pub),
				Authority: f.authority,
				GrantedAt: time.Now().UTC().Format(time.RFC3339),
				ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339),
			}
			if f.consentMode != "" {
				g.ConsentMode, g.ConsentActor = f.consentMode, "dev@acme.example"
			}
			g.Signature = orgcontract.SignEnrolmentGrant(f.signKey, g)
			grant = &g
		}
		f.json(w, http.StatusOK, orgcontract.EnrollResponse{
			Bearer: "bearer-xyz", BearerExpiresAt: time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
			OrgID: "org-1", OrgName: "Acme", UserID: "u-1", UserEmail: "dev@acme.example",
			OrgPolicyPublicKey: f.keyB64, Tenancy: f.tenancy,
			ConsentMode: f.consentMode, Grant: grant,
		})
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (f *enrolFakeOrg) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// testEnrolDashboard builds the manager over an in-memory bearer store and a
// temp config, never the machine's keychain or ~/.observer.
func testEnrolDashboard(t *testing.T) (*enrolDashboard, *store.Store, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	st := idpTestStore(t)
	client := idpTestOrgClient(t, st)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\nlog_level = \"warn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := newEnrolDashboard(cfgPath, false)
	d.bundle = func(context.Context) (orgBundle, error) {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
		if err != nil {
			return orgBundle{}, err
		}
		return orgBundle{client: client, store: st, cfg: cfg, cleanup: func() {}}, nil
	}
	return d, st, cfgPath
}

func wantFailure(t *testing.T, err error, code orgenrol.Code) {
	t.Helper()
	f, ok := orgenrol.AsFailure(err)
	if !ok || f.Code != code {
		t.Fatalf("err = %v (%T), want an orgenrol %q failure", err, err, code)
	}
}

func TestEnrolDashboardInputValidationNeverReachesServer(t *testing.T) {
	org := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, nil)
	d, _, _ := testEnrolDashboard(t)
	ctx := context.Background()
	cases := []dashapi.EnrolRequest{
		{Method: "code", OrgURL: "", Token: "id.secret"},
		{Method: "code", OrgURL: "not a url", Token: "id.secret"},
		{Method: "code", OrgURL: org.url, Token: "nodot"},
		{Method: "code", OrgURL: org.url, Token: org.url + "/enrol/id.secret"},
		{Method: "link", Link: org.url + "/set-password?token=a.b"},
		{Method: "link", Link: org.url + "/nothing"},
		{Method: "link", Link: ""},
		{Method: "idp", OrgURL: org.url},
		{Method: "telepathy"},
	}
	for _, req := range cases {
		_, err := d.Enrol(ctx, req)
		wantFailure(t, err, orgenrol.CodeInvalidInput)
	}
	if org.enrolCalls != 0 {
		t.Fatalf("invalid input reached the org server %d times", org.enrolCalls)
	}
}

func TestEnrolDashboardReachabilityAndRefusals(t *testing.T) {
	ctx := context.Background()
	d, _, _ := testEnrolDashboard(t)

	// Nothing listening: unreachable, and the code is never sent.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	_, err := d.Enrol(ctx, dashapi.EnrolRequest{Method: "code", OrgURL: deadURL, Token: "id.secret"})
	wantFailure(t, err, orgenrol.CodeUnreachable)
	probe, err := d.Probe(ctx, deadURL)
	if err != nil || probe.OK {
		t.Fatalf("probe of a dead URL = (%+v, %v), want ok=false with a message", probe, err)
	}

	// Something answers, but not an org server.
	org := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, nil)
	org.healthzOK = false
	_, err = d.Enrol(ctx, dashapi.EnrolRequest{Method: "code", OrgURL: org.url, Token: "id.secret"})
	wantFailure(t, err, orgenrol.CodeNotOrgServer)
	if org.enrolCalls != 0 {
		t.Fatal("a failed probe still spent the code")
	}

	// The org refuses the code; the account is pending.
	org.healthzOK = true
	org.enrolStatus = http.StatusUnauthorized
	_, err = d.Enrol(ctx, dashapi.EnrolRequest{Method: "code", OrgURL: org.url, Token: "id.secret"})
	wantFailure(t, err, orgenrol.CodeTokenRejected)
	org.enrolStatus, org.enrolError = http.StatusForbidden, "member_not_active"
	_, err = d.Enrol(ctx, dashapi.EnrolRequest{Method: "code", OrgURL: org.url, Token: "id.secret"})
	wantFailure(t, err, orgenrol.CodeMemberNotActive)

	// Push-now without an enrolment is classified, not a raw error.
	_, err = d.PushNow(ctx)
	wantFailure(t, err, orgenrol.CodeNotEnrolled)
}

// TestEnrolDashboardIndividualParksGrant: the token rail never auto-accepts.
// The grant waits for an explicit decision; accepting records it with local
// interactive consent; an individual enrolment writes no policy block.
func TestEnrolDashboardIndividualParksGrant(t *testing.T) {
	ctx := context.Background()
	org := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, []string{govern.AuthorityDashboardVisibility})
	d, st, cfgPath := testEnrolDashboard(t)

	out, err := d.Enrol(ctx, dashapi.EnrolRequest{Method: "code", OrgURL: org.url + "/", Token: " " + idpTestEnrolCode + " "})
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	if out.Managed || out.Tenancy != orgcontract.TenancyIndividual || !out.BlockWritten || out.FullContent {
		t.Fatalf("individual outcome = %+v", out)
	}
	if !out.RestartRequired {
		t.Fatal("a daemon without a push loop must say a restart is needed")
	}
	if out.PendingGrant == nil || out.Grant != nil {
		t.Fatalf("token-rail grant must be parked for a decision, got pending=%v grant=%v", out.PendingGrant, out.Grant)
	}
	if got := out.PendingGrant.Disclosure.May; len(got) != 1 || got[0].Text != orgenrol.AuthorityPlainEnglish(govern.AuthorityDashboardVisibility) {
		t.Fatalf("disclosure may = %+v", got)
	}
	// Every surface names the organization, never its id.
	if out.OrgDisplay != "Acme" || out.PendingGrant.Disclosure.OrgDisplay != "Acme" {
		t.Fatalf("org display: outcome %q, consent screen %q, want Acme", out.OrgDisplay, out.PendingGrant.Disclosure.OrgDisplay)
	}
	body, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(body), "[org_client]") || !strings.Contains(string(body), "full_content = false") {
		t.Fatalf("config block not written as the CLI writes it:\n%s", body)
	}
	// Nothing recorded before the decision.
	if grant, live, gerr := governanceIdentityLoader(st)(ctx); gerr != nil || !live.Enrolled || grant != nil {
		t.Fatalf("before consent: grant=%v live=%+v err=%v, want enrolled and ungoverned", grant, live, gerr)
	}

	// The overview re-offers the parked consent screen after a reload.
	ov, err := d.Overview(ctx)
	if err != nil || !ov.Enrolled || ov.PendingGrant == nil || ov.PendingGrant.OfferID != out.PendingGrant.OfferID {
		t.Fatalf("overview = %+v (%v)", ov, err)
	}
	if ov.OrgDisplay != "Acme" || ov.PendingGrant.Disclosure.OrgDisplay != "Acme" {
		t.Fatalf("overview org display %q / re-offered screen %q, want Acme", ov.OrgDisplay, ov.PendingGrant.Disclosure.OrgDisplay)
	}
	if ov.ShareMode != "metadata_only" || strings.Contains(ov.ShareModeLine, "—") {
		t.Fatalf("share mode = %q / %q", ov.ShareMode, ov.ShareModeLine)
	}

	dec, err := d.DecideGrant(ctx, out.PendingGrant.OfferID, true)
	if err != nil || dec.Status != "accepted" {
		t.Fatalf("DecideGrant = (%+v, %v)", dec, err)
	}
	rep, err := d.GrantReport(ctx)
	if err != nil || rep.State != "governed" || !strings.HasPrefix(rep.Consent, govern.ConsentInteractive) {
		t.Fatalf("grant report = %+v (%v)", rep, err)
	}
	// The grant row records the id as its org_name; the report still names
	// the organization from the enrolment.
	if rep.OrgDisplay != "Acme" {
		t.Fatalf("grant report org display = %q, want Acme", rep.OrgDisplay)
	}
	body, _ = os.ReadFile(cfgPath)
	if strings.Contains(string(body), "[org_client.policy]") {
		t.Fatal("an individual enrolment must never auto-write the policy block")
	}
	// A second decision on the same offer is gone.
	_, err = d.DecideGrant(ctx, out.PendingGrant.OfferID, true)
	wantFailure(t, err, orgenrol.CodeGone)
}

// TestEnrolDashboardManagedAcceptWritesPolicy: a managed enrolment discloses
// and, on accept, writes the W-5 [org_client.policy] consent keys; declining
// writes nothing.
func TestEnrolDashboardManagedAcceptWritesPolicy(t *testing.T) {
	ctx := context.Background()
	for _, accept := range []bool{true, false} {
		org := newEnrolFakeOrg(t, orgcontract.TenancyManaged, []string{govern.AuthorityDashboardVisibility})
		d, _, cfgPath := testEnrolDashboard(t)
		out, err := d.Enrol(ctx, dashapi.EnrolRequest{Method: "link", Link: org.url + "/enrol/" + idpTestEnrolCode})
		if err != nil {
			t.Fatalf("Enrol: %v", err)
		}
		if !out.Managed || !out.FullContent || out.PendingGrant == nil || len(out.PendingGrant.Disclosure.ConfigWrites) == 0 {
			t.Fatalf("managed outcome = %+v", out)
		}
		dec, err := d.DecideGrant(ctx, out.PendingGrant.OfferID, accept)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := os.ReadFile(cfgPath)
		wrote := strings.Contains(string(body), "accept_families")
		if wrote != accept {
			t.Fatalf("accept=%v: policy block written=%v (decision %+v)\n%s", accept, wrote, dec, body)
		}
	}
}

// TestEnrolDashboardStaleOfferRefused: an offer parked for one enrolment is
// refused once the machine has left.
func TestEnrolDashboardStaleOfferRefused(t *testing.T) {
	ctx := context.Background()
	org := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, []string{govern.AuthorityDashboardVisibility})
	d, _, _ := testEnrolDashboard(t)
	invalidations := 0
	d.withIdentityChanged(func() { invalidations++ })
	out, err := d.Enrol(ctx, dashapi.EnrolRequest{OrgURL: org.url, Token: idpTestEnrolCode})
	if err != nil {
		t.Fatal(err)
	}
	if invalidations != 1 {
		t.Fatalf("Enrol invalidated governance %d times, want 1", invalidations)
	}
	id := out.PendingGrant.OfferID
	// Re-park the offer the way a racing tab would still hold it, then leave.
	d.mu.Lock()
	p := d.offers[id]
	d.mu.Unlock()
	lv, err := d.Leave(ctx, dashapi.SwitchOptions{})
	if err != nil || !lv.WasEnrolled || lv.OrgName != "Acme" {
		t.Fatalf("Leave = (%+v, %v)", lv, err)
	}
	d.mu.Lock()
	d.offers[id] = p
	d.mu.Unlock()
	_, err = d.DecideGrant(ctx, id, true)
	wantFailure(t, err, orgenrol.CodeStale)
	// Leaving twice is a no-op, as `observer unenroll` is.
	lv, err = d.Leave(ctx, dashapi.SwitchOptions{})
	if err != nil || lv.WasEnrolled {
		t.Fatalf("second Leave = (%+v, %v)", lv, err)
	}
	// Enrol, Leave, the refused DecideGrant and the second Leave each drop
	// the governance cache so /api/governance follows without a 15s lag.
	if invalidations != 4 {
		t.Fatalf("governance invalidated %d times, want 4", invalidations)
	}
}

// TestEnrolDashboardIdPConsentIsTheApproval: the sign-in rail enrols on
// approval and records the organization-verified consent without asking.
func TestEnrolDashboardIdPConsentIsTheApproval(t *testing.T) {
	ctx := context.Background()
	org := newEnrolFakeOrg(t, orgcontract.TenancyManaged, []string{govern.AuthorityEnforceRouting})
	org.consentMode = govern.ConsentIdP
	d, _, _ := testEnrolDashboard(t)
	clock := time.Now()
	d.now = func() time.Time { return clock }

	start, err := d.StartIdP(ctx, org.url, dashapi.SwitchOptions{})
	if err != nil || start.UserCode != idpTestUserCode || !strings.Contains(start.VerificationURI, "user_code=") {
		t.Fatalf("StartIdP = (%+v, %v)", start, err)
	}
	// Inside the interval: answered locally, no server poll.
	p, err := d.PollIdP(ctx, start.FlowID)
	if err != nil || p.Status != "pending" {
		t.Fatalf("early poll = (%+v, %v)", p, err)
	}
	clock = clock.Add(6 * time.Second)
	p, err = d.PollIdP(ctx, start.FlowID)
	if err != nil || p.Status != "approved" || p.Outcome == nil {
		t.Fatalf("approved poll = (%+v, %v)", p, err)
	}
	if p.Outcome.PendingGrant != nil || p.Outcome.Grant == nil || p.Outcome.Grant.Status != "consented" {
		t.Fatalf("IdP approval must settle the grant without a prompt, got %+v", p.Outcome)
	}
	_, err = d.PollIdP(ctx, start.FlowID)
	wantFailure(t, err, orgenrol.CodeGone)
}

// TestDashboardGovernanceWarningPointsAtThePage: the loud posture lines name
// the on-page grant panel, never a CLI command, and pass other text through.
func TestDashboardGovernanceWarningPointsAtThePage(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{
			"altered",
			"Governance:       ALTERED - the organization grant stored on this machine does not verify." +
				"\n                  Organization governance is NOT being applied. Run `observer org grant show`.",
			"Governance: ALTERED - the organization grant stored on this machine does not verify. " +
				"Organization governance is NOT being applied. See \"What this organization can manage\" below.",
		},
		{
			"expired", "Governance:       EXPIRED - the organization grant has lapsed; local settings apply again.",
			"Governance: EXPIRED - the organization grant has lapsed; local settings apply again.",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dashboardGovernanceWarning(c.in)
			if got != c.want {
				t.Fatalf("got %q\nwant %q", got, c.want)
			}
			if strings.Contains(got, "observer org") {
				t.Fatalf("UI copy names a CLI command: %q", got)
			}
		})
	}
}

// TestDashboardCopyLeavesNoGrantOrStatusPointer: every share-mode and
// grant content line the dashboard reuses from the CLI comes out pointing
// at the page, never at `observer org grant show` / `observer org status`.
func TestDashboardCopyLeavesNoGrantOrStatusPointer(t *testing.T) {
	var lines []string
	for _, r := range shareModeRules {
		lines = append(lines, r.line)
	}
	for _, r := range enterpriseContentRules {
		lines = append(lines, r.line)
	}
	// T-642: the Cloud Intelligence requirement note on the enrol outcome.
	for _, terms := range []bool{false, true} {
		for _, late := range []bool{false, true} {
			lines = append(lines, orgIntelPendingSentence("Acme", terms, late))
		}
	}
	for _, l := range lines {
		got := dashboardCopy(l)
		if strings.Contains(got, "`observer ") {
			t.Errorf("CLI command left in UI copy: %q", got)
		}
		if strings.Contains(got, "observer org grant show") || strings.Contains(got, "observer org status") {
			t.Errorf("CLI pointer left in UI copy: %q", got)
		}
		if strings.Contains(got, "—") || strings.Contains(got, "  ") {
			t.Errorf("UI copy keeps an em dash or CLI padding: %q", got)
		}
	}
}

// TestEnrolManagerForInvalidatesGovernance (Sol A3-09): the manager every
// host builds drops the governance handle's cached identity on a change, so
// the next /api/governance read re-loads the grant instead of serving the
// old identity for the refresh interval.
func TestEnrolManagerForInvalidatesGovernance(t *testing.T) {
	loads := 0
	gov := newNodeGovernanceHandle(func(context.Context) (*govern.Grant, govern.LiveIdentity, error) {
		loads++
		return nil, govern.LiveIdentity{}, nil
	}, slog.Default())
	ctx := context.Background()
	gov.Effective(ctx)
	gov.Effective(ctx)
	if loads != 1 {
		t.Fatalf("a fresh cache re-loaded: %d loads", loads)
	}
	// The defect: a manager built the way the standalone dashboard used to
	// build it (no hook) leaves the stale identity in place.
	newEnrolDashboard(filepath.Join(t.TempDir(), "config.toml"), false).changed()
	gov.Effective(ctx)
	if loads != 1 {
		t.Fatalf("the bare manager unexpectedly invalidated governance: %d loads", loads)
	}
	enrolManagerFor(filepath.Join(t.TempDir(), "config.toml"), false, gov).changed()
	gov.Effective(ctx)
	if loads != 2 {
		t.Fatalf("after an enrolment change the governance identity was not re-read: %d loads", loads)
	}
}
