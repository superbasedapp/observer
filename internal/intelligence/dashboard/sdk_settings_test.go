package dashboard

import (
	"context"
	"encoding/json"
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
