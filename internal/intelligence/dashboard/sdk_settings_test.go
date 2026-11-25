package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sdkcredsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestSDKDestinationDescribesTheKeyWithoutIt(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observability]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newRemoteTestServer(t, Options{
		ConfigPath: cfgPath,
		SDK: SDKSeams{Status: func() sdkcredsvc.Status {
			return sdkcredsvc.Status{SignedIn: true, CredentialFile: "/home/u/.observer/sdk/k", Meta: sdkcredsvc.Meta{KeyID: "ik_1", GatewayURL: "https://gw.example.com:4318"}}
		}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/sdk/destination", nil)
	req.Host = "127.0.0.1:8081"
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET: %d %s", rr.Code, rr.Body)
	}
	var d sdkcredsvc.Discovery
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.APIVersion != 1 || d.Destination != "both" || d.Online.KeyID != "ik_1" || d.Local.AdmissionURL != "http://127.0.0.1:8081/api/obs/admission/check" {
		t.Fatalf("discovery = %+v", d)
	}
}

// TestSDKDestinationDashboardURLFromTheEnrolment (SDK quickstart plan 3.8):
// online.dashboard_url is the enrolled organization's dashboard for the
// held key, "" before enrolment, and the online address `observer connect`
// recorded wins over the org server address.
func TestSDKDestinationDashboardURLFromTheEnrolment(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observability]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newRemoteTestServer(t, Options{
		ConfigPath: cfgPath,
		SDK: SDKSeams{Status: func() sdkcredsvc.Status {
			return sdkcredsvc.Status{
				SignedIn: true, CredentialFile: "/home/u/.observer/sdk/k", KeyGatewayURL: "https://u-sam.superbased.app",
				Meta: sdkcredsvc.Meta{KeyID: "ik_1", OrgID: "o1", GatewayURL: "https://u-sam.superbased.app"},
			}
		}},
	})
	get := func() sdkcredsvc.Discovery {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/sdk/destination", nil)
		req.Host = "127.0.0.1:8081"
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET: %d %s", rr.Code, rr.Body)
		}
		var d sdkcredsvc.Discovery
		if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := get(); d.Online.DashboardURL != "" {
		t.Fatalf("not enrolled: dashboard_url %q", d.Online.DashboardURL)
	}
	st := store.New(s.opts.DB)
	ctx := context.Background()
	if err := st.WriteEnrolment(ctx, store.Enrolment{OrgID: "o1", OrgName: "Sam", OrgServerURL: "https://org.internal.example:8443/", UserID: "u1", BearerKeyID: "k"}); err != nil {
		t.Fatal(err)
	}
	if d := get(); d.Online.DashboardURL != "https://org.internal.example:8443" {
		t.Fatalf("enrolled: dashboard_url %q", d.Online.DashboardURL)
	}
	if ok, err := st.SetEnrolmentConnection(ctx, "o1", "Sam", "https://u-sam.superbased.app/"); err != nil || !ok {
		t.Fatalf("connection: %v %v", ok, err)
	}
	if d := get(); d.Online.DashboardURL != "https://u-sam.superbased.app" {
		t.Fatalf("connected: dashboard_url %q", d.Online.DashboardURL)
	}
}

func TestSDKCredentialNeedsTheConfirmToken(t *testing.T) {
	called := false
	s := newRemoteTestServer(t, Options{SDK: SDKSeams{SignIn: func(context.Context) (sdkcredsvc.Status, error) {
		called = true
		return sdkcredsvc.Status{}, nil
	}}})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sdk/credential", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || called {
		t.Fatalf("a sign-in without the confirm token must be refused: %d called=%v", rr.Code, called)
	}
}

// TestSDKInstallKeyRoute pins the dashboard form of `observer sdk use-key`
// (POST /api/sdk/credential/key): confirm token required, the key in the JSON
// body only (a query string is refused unread), never in the answer.
func TestSDKInstallKeyRoute(t *testing.T) {
	const fakeKey = "ik_dash.fakeDashboardSecret"
	type call struct{ key, gateway string }
	var calls []call
	s := newRemoteTestServer(t, Options{SDK: SDKSeams{InstallKey: func(compound, gatewayURL string) (sdkcredsvc.Status, error) {
		calls = append(calls, call{compound, gatewayURL})
		if gatewayURL == "http://gw.example.com" {
			return sdkcredsvc.Status{}, errors.New("the gateway address is not usable for the SDK key; nothing was stored")
		}
		return sdkcredsvc.Status{
			SignedIn: true, CredentialFile: "/home/u/.observer/sdk/k", KeyGatewayURL: gatewayURL,
			Meta: sdkcredsvc.Meta{KeyID: "ik_dash", Origin: sdkcredsvc.KeyOriginAdminIssued},
		}, nil
	}}})
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	send := func(method, target, body string, confirm bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if confirm {
			req.Header.Set(remoteConfirmHeader, token)
			req.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: token})
		}
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		return rr
	}
	good := `{"key":"` + fakeKey + `","gateway_url":"https://acme.superbased.app"}`
	cases := []struct {
		name, method, target, body string
		confirm                    bool
		code                       int
		calls                      int
	}{
		{"no confirm token", http.MethodPost, "/api/sdk/credential/key", good, false, http.StatusForbidden, 0},
		{"a GET", http.MethodGet, "/api/sdk/credential/key", "", true, http.StatusMethodNotAllowed, 0},
		{"the key in a query string", http.MethodPost, "/api/sdk/credential/key?key=" + fakeKey, "{}", true, http.StatusBadRequest, 0},
		{"not JSON", http.MethodPost, "/api/sdk/credential/key", "key=" + fakeKey, true, http.StatusBadRequest, 0},
		{"a refused install", http.MethodPost, "/api/sdk/credential/key", `{"key":"` + fakeKey + `","gateway_url":"http://gw.example.com"}`, true, http.StatusBadRequest, 1},
		{"installed", http.MethodPost, "/api/sdk/credential/key", good, true, http.StatusOK, 1},
	}
	for _, tc := range cases {
		calls = nil
		rr := send(tc.method, tc.target, tc.body, tc.confirm)
		if rr.Code != tc.code || len(calls) != tc.calls {
			t.Fatalf("%s: %d calls=%d %s", tc.name, rr.Code, len(calls), rr.Body)
		}
		if strings.Contains(rr.Body.String(), "fakeDashboardSecret") {
			t.Fatalf("%s: the answer carries the key: %s", tc.name, rr.Body)
		}
	}
	// The last row: the seam got the key and the address from the body, and
	// the answer is the key's status.
	if calls[0].key != fakeKey || calls[0].gateway != "https://acme.superbased.app" {
		t.Fatalf("seam input = %+v", calls[0])
	}
	rr := send(http.MethodPost, "/api/sdk/credential/key", good, true)
	var out struct {
		Status sdkcredsvc.Status `json:"status"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.Status.KeyID != "ik_dash" || out.Status.Origin != sdkcredsvc.KeyOriginAdminIssued || !out.Status.SignedIn {
		t.Fatalf("answer: %v %s", err, rr.Body)
	}
	// Not wired: 501, nothing read.
	bare := newRemoteTestServer(t, Options{})
	req := httptest.NewRequest(http.MethodPost, "/api/sdk/credential/key", strings.NewReader(good))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(remoteConfirmHeader, token)
	req.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: token})
	rec := httptest.NewRecorder()
	bare.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("unwired: %d", rec.Code)
	}
}

// TestProposalResolveMarksApprovedOnlyWhenInForce pins the D19 approve rule:
// resolving as approved is refused until PUT /api/config/keys wrote the
// value; reject needs no write.
func TestProposalResolveMarksApprovedOnlyWhenInForce(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte(keysCorpus), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newRemoteTestServer(t, Options{ConfigPath: cfgPath})
	st := store.New(s.opts.DB)
	ctx := context.Background()
	id, err := st.FileSettingsProposal(ctx, store.NewSettingsProposal{Key: "observability.sdk.destination", Value: "online"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	other, _ := st.FileSettingsProposal(ctx, store.NewSettingsProposal{Key: "observability.store_content", Value: "false"}, time.Now())

	// The list mints the confirm token.
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config/proposals", nil))
	var list struct {
		Proposals []store.SettingsProposal `json:"proposals"`
		Token     string                   `json:"confirm_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil || len(list.Proposals) != 2 || list.Token == "" {
		t.Fatalf("list: %v %s", err, rr.Body)
	}
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			cookie = c
		}
	}
	resolve := func(id int64, decision string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/config/proposals/"+strconv.FormatInt(id, 10)+"/resolve", strings.NewReader(`{"decision":"`+decision+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(remoteConfirmHeader, list.Token)
		req.AddCookie(cookie)
		out := httptest.NewRecorder()
		s.Handler().ServeHTTP(out, req)
		return out
	}
	if rr := resolve(id, "approved"); rr.Code != http.StatusConflict {
		t.Fatalf("approving before the value is saved must be refused: %d %s", rr.Code, rr.Body)
	}
	etag, _, _ := configGet(t, s)
	if rr := putKeys(t, s, keysBody(etag, `{"key":"observability.sdk.destination","value":"online"}`), true); rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body)
	}
	if rr := resolve(id, "approved"); rr.Code != http.StatusOK {
		t.Fatalf("approve once in force: %d %s", rr.Code, rr.Body)
	}
	if p, _ := st.GetSettingsProposal(ctx, id); p.Status != store.SettingsProposalApproved || p.DecidedBy != "dashboard" {
		t.Fatalf("proposal = %+v", p)
	}
	if rr := resolve(id, "rejected"); rr.Code != http.StatusConflict {
		t.Fatalf("a decided proposal stays decided: %d", rr.Code)
	}
	if rr := resolve(other, "rejected"); rr.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rr.Code, rr.Body)
	}
	if rr := resolve(other+100, "rejected"); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", rr.Code)
	}
}

// TestProposalResolveRefusesAnExpiredProposal pins review E-50 on the
// dashboard: approving a proposal older than settingsgate.ProposalMaxAge is
// refused with 409 expired; rejecting it still works.
func TestProposalResolveRefusesAnExpiredProposal(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observability]\nenabled = true\n\n[observability.sdk]\ndestination = \"online\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newRemoteTestServer(t, Options{ConfigPath: cfgPath})
	st := store.New(s.opts.DB)
	ctx := context.Background()
	id, err := st.FileSettingsProposal(ctx, store.NewSettingsProposal{Key: "observability.sdk.destination", Value: "online"}, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config/proposals", nil))
	var list struct {
		Token string `json:"confirm_token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			cookie = c
		}
	}
	resolve := func(decision string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/config/proposals/"+strconv.FormatInt(id, 10)+"/resolve", strings.NewReader(`{"decision":"`+decision+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(remoteConfirmHeader, list.Token)
		req.AddCookie(cookie)
		out := httptest.NewRecorder()
		s.Handler().ServeHTTP(out, req)
		return out
	}
	if rr := resolve("approved"); rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "expired") {
		t.Fatalf("approving an expired proposal (value already in force) = %d %s, want 409 expired", rr.Code, rr.Body)
	}
	if rr := resolve("rejected"); rr.Code != http.StatusOK {
		t.Fatalf("reject an expired proposal: %d %s", rr.Code, rr.Body)
	}
}

// TestOTLPReceiverRouteReportsABindFailure pins review E-72's server half:
// the AI Apps pages read the daemon's receiver record, and an unwired or
// empty record reads as unknown.
func TestOTLPReceiverRouteReportsABindFailure(t *testing.T) {
	get := func(s *Server) map[string]string {
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sdk/receiver", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("GET /api/sdk/receiver: %d %s", rr.Code, rr.Body)
		}
		var out map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := get(newRemoteTestServer(t, Options{})); got["state"] != "unknown" {
		t.Fatalf("unwired = %v, want unknown", got)
	}
	s := newRemoteTestServer(t, Options{SDK: SDKSeams{Receiver: func() (OTLPReceiverState, bool) {
		return OTLPReceiverState{State: "bind_failed", HTTPAddr: "127.0.0.1:4318", Error: "listen tcp 127.0.0.1:4318: bind: address already in use"}, true
	}}})
	got := get(s)
	if got["state"] != "bind_failed" || got["http_addr"] != "127.0.0.1:4318" || !strings.Contains(got["error"], "address already in use") {
		t.Fatalf("bind failure = %v", got)
	}
}
