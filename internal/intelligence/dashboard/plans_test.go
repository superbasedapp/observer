package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/planlimitssvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newPlansServer wires a dashboard over a fresh database with the Plans &
// limits service, an in-memory keychain and NO egress (a nil Egress makes
// any network source fail with "egress not wired", never a call).
func newPlansServer(t *testing.T) (*Server, *keystore.MemStore) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	keys := &keystore.MemStore{}
	svc := planlimitssvc.New(planlimitssvc.Options{Store: store.New(database), Keys: keys})
	s, err := New(Options{DB: database, DBPath: path, Plans: svc})
	if err != nil {
		t.Fatal(err)
	}
	return s, keys
}

func plansDo(t *testing.T, s *Server, method, path, body string, arm bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if arm {
		req = armLocalWrite(req)
	} else if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestPlansAPI_PageModelAndCatalog(t *testing.T) {
	s, _ := newPlansServer(t)
	rec := plansDo(t, s, http.MethodGet, "/api/plans", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/plans = %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		View struct {
			Cards    []json.RawMessage `json:"cards"`
			Accounts []json.RawMessage `json:"accounts"`
		} `json:"view"`
		Catalog []struct {
			ID      string `json:"id"`
			Sources []struct {
				ID           string `json:"id"`
				Experimental bool   `json:"experimental"`
			} `json:"sources"`
		} `json:"catalog"`
		Token string `json:"confirm_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Token == "" || got.View.Cards == nil || got.View.Accounts == nil {
		t.Fatalf("page model incomplete: %s", rec.Body.String())
	}
	exp := map[string]bool{}
	for _, p := range got.Catalog {
		for _, src := range p.Sources {
			if src.Experimental {
				exp[src.ID] = true
			}
		}
	}
	for _, id := range []string{"claude.oauth", "cursor.app", "windsurf.cache"} {
		if !exp[id] {
			t.Errorf("catalog does not mark %s experimental", id)
		}
	}
}

func TestPlansAPI_WritesNeedTheConfirmToken(t *testing.T) {
	s, _ := newPlansServer(t)
	for _, c := range []struct{ path, body string }{
		{"/api/plans/accounts", `{"provider":"cursor","source":"manual","params":{"unit":"usd","allowance":"20"}}`},
		{"/api/plans/optin", `{"provider":"claude","on":true}`},
		{"/api/plans/accounts/x/remove", `{}`},
		{"/api/plans/accounts/x/refresh", `{}`},
		{"/api/plans/probe", `{"provider":"deepseek","source":"deepseek.api","secrets":{"key":"k"}}`},
	} {
		if rec := plansDo(t, s, http.MethodPost, c.path, c.body, false); rec.Code != http.StatusForbidden {
			t.Errorf("%s without token = %d, want 403", c.path, rec.Code)
		}
	}
}

func TestPlansAPI_AccountLifecycleNeverReturnsASecret(t *testing.T) {
	s, keys := newPlansServer(t)
	const secret = "sk-or-v1-thisisnotarealkey0000"
	rec := plansDo(t, s, http.MethodPost, "/api/plans/accounts",
		`{"provider":"openrouter","source":"openrouter.api","label":"Work","secrets":{"key":"`+secret+`"}}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("add = %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("the add response carries the secret")
	}
	var added struct {
		Account struct {
			ID      string   `json:"id"`
			Secrets []string `json:"secrets"`
		} `json:"account"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &added); err != nil {
		t.Fatal(err)
	}
	if v, err := keys.Get("account." + added.Account.ID + ".key"); err != nil || v != secret {
		t.Fatalf("secret not in the keychain: %v", err)
	}
	page := plansDo(t, s, http.MethodGet, "/api/plans", "", false)
	if strings.Contains(page.Body.String(), secret) {
		t.Fatal("the page model carries the secret")
	}
	hist := plansDo(t, s, http.MethodGet, "/api/plans/accounts/"+added.Account.ID+"/history", "", false)
	if hist.Code != http.StatusOK {
		t.Fatalf("history = %d %s", hist.Code, hist.Body.String())
	}
	// A source with no daily usage answers available=false, no reconciliation.
	usage := plansDo(t, s, http.MethodGet, "/api/plans/accounts/"+added.Account.ID+"/usage?days=14", "", false)
	if usage.Code != http.StatusOK {
		t.Fatalf("usage = %d %s", usage.Code, usage.Body.String())
	}
	var uv struct {
		Available      bool            `json:"available"`
		Days           int             `json:"days"`
		Reconciliation json.RawMessage `json:"reconciliation"`
	}
	if err := json.Unmarshal(usage.Body.Bytes(), &uv); err != nil || uv.Available || uv.Days != 14 || uv.Reconciliation != nil {
		t.Fatalf("usage body %s %v", usage.Body.String(), err)
	}
	if rec := plansDo(t, s, http.MethodGet, "/api/plans/accounts/nope/usage", "", false); rec.Code != http.StatusNotFound {
		t.Fatalf("usage of an unknown account = %d, want 404", rec.Code)
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/plans/accounts/"+added.Account.ID, `{"label":"Home"}`, true); rec.Code != http.StatusOK {
		t.Fatalf("edit = %d %s", rec.Code, rec.Body.String())
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/plans/accounts/"+added.Account.ID+"/remove", `{}`, true); rec.Code != http.StatusOK {
		t.Fatalf("remove = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := keys.Get("account." + added.Account.ID + ".key"); err == nil {
		t.Fatal("remove left the secret in the keychain")
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/plans/accounts/"+added.Account.ID+"/refresh", `{}`, true); rec.Code != http.StatusNotFound {
		t.Fatalf("refresh of a removed account = %d, want 404", rec.Code)
	}
}

func TestPlansAPI_ExperimentalNeedsTheSwitch(t *testing.T) {
	s, _ := newPlansServer(t)
	body := `{"provider":"cursor","source":"cursor.app"}`
	if rec := plansDo(t, s, http.MethodPost, "/api/plans/accounts", body, true); rec.Code != http.StatusConflict {
		t.Fatalf("experimental add without the switch = %d, want 409", rec.Code)
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/plans/optin", `{"provider":"openrouter","on":true}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("switch on a provider with no experimental source = %d, want 400", rec.Code)
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/plans/optin", `{"provider":"cursor","on":true}`, true); rec.Code != http.StatusOK {
		t.Fatalf("switch on = %d %s", rec.Code, rec.Body.String())
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/plans/accounts", body, true); rec.Code != http.StatusOK {
		t.Fatalf("experimental add with the switch = %d %s", rec.Code, rec.Body.String())
	}
}

func TestPlansAPI_ManualAccountShowsACard(t *testing.T) {
	s, _ := newPlansServer(t)
	rec := plansDo(t, s, http.MethodPost, "/api/plans/accounts",
		`{"provider":"cursor","source":"manual","label":"Pro","params":{"plan":"Pro","unit":"requests","allowance":"500","used":"120"}}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("add manual = %d %s", rec.Code, rec.Body.String())
	}
	page := plansDo(t, s, http.MethodGet, "/api/plans", "", false)
	var got struct {
		View struct {
			Cards []struct {
				Provider string `json:"provider"`
				Windows  []struct {
					Used  *float64 `json:"used"`
					Limit *float64 `json:"limit"`
				} `json:"windows"`
			} `json:"cards"`
		} `json:"view"`
	}
	if err := json.Unmarshal(page.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range got.View.Cards {
		if c.Provider == "cursor" && len(c.Windows) > 0 && c.Windows[0].Limit != nil && *c.Windows[0].Limit == 500 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no cursor card with the manual allowance: %s", page.Body.String())
	}
}

func TestPlansAPI_StatusLineFeed(t *testing.T) {
	s, _ := newPlansServer(t)
	body := `{"session_id":"s1","observed_at":0,"rate_limits":{"five_hour":{"used_percentage":42,"resets_at":4102444800}}}`
	if rec := plansDo(t, s, http.MethodPost, "/api/plans/statusline", body, false); rec.Code != http.StatusNoContent {
		t.Fatalf("status line feed = %d %s", rec.Code, rec.Body.String())
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/plans/statusline", `{"session_id":"s1"}`, false); rec.Code != http.StatusBadRequest {
		t.Fatalf("a feed with no limits = %d, want 400", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/plans/statusline", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("a non-JSON feed = %d, want 415", rec.Code)
	}
}

func TestPlansAPI_ProbeStoresNothingAndHidesVendorText(t *testing.T) {
	s, keys := newPlansServer(t)
	const secret = "sk-deepseek-notreal"
	rec := plansDo(t, s, http.MethodPost, "/api/plans/probe",
		`{"provider":"deepseek","source":"deepseek.api","secrets":{"key":"`+secret+`"}}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("probe = %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		OK      bool   `json:"ok"`
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.OK || got.Outcome == "" || strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("probe with no egress should fail with a code only: %s", rec.Body.String())
	}
	if n := len(keys.Names()); n != 0 {
		t.Fatalf("probe stored %d secrets", n)
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/plans/probe", `{"provider":"deepseek","source":"cursor.app"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("probe of a source the provider cannot use = %d, want 400", rec.Code)
	}
}

func TestPlansAPI_UnwiredAnswers503(t *testing.T) {
	s, _ := newTestServer(t)
	if rec := plansDo(t, s, http.MethodGet, "/api/plans", "", false); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /api/plans with no service = %d, want 503", rec.Code)
	}
}
