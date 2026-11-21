package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/cloudagentssvc"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudAgentsFakeNet answers recorded CLI output and counts calls.
type cloudAgentsFakeNet struct {
	mu    sync.Mutex
	out   map[string][]byte
	calls int
}

func (f *cloudAgentsFakeNet) Run(_ context.Context, req cloudagents.Request) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if b, ok := f.out[strings.Join(req.Argv, " ")]; ok {
		return b, nil
	}
	return nil, cloudagents.NewError(cloudagents.ErrNotSignedIn, "x")
}

func newCloudAgentsServer(t *testing.T) (*Server, *cloudAgentsFakeNet) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	net := &cloudAgentsFakeNet{out: map[string][]byte{}}
	svc := cloudagentssvc.New(cloudagentssvc.Options{Store: store.New(database), Net: net, Keys: &keystore.MemStore{}})
	s, err := New(Options{DB: database, DBPath: path, CloudAgents: svc})
	if err != nil {
		t.Fatal(err)
	}
	return s, net
}

func cloudAgentsFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "cloudagents", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCloudAgentsAPI_Unwired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	s, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if rec := plansDo(t, s, http.MethodGet, "/api/cloud-agents", "", false); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired GET = %d", rec.Code)
	}
}

func TestCloudAgentsAPI_Lifecycle(t *testing.T) {
	s, net := newCloudAgentsServer(t)

	rec := plansDo(t, s, http.MethodGet, "/api/cloud-agents", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body.String())
	}
	var page struct {
		View struct {
			Connectors []struct {
				ID      string            `json:"id"`
				Signals []json.RawMessage `json:"signals"`
			} `json:"connectors"`
			Accounts []json.RawMessage `json:"accounts"`
		} `json:"view"`
		Token string `json:"confirm_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Token == "" || len(page.View.Connectors) < 2 || page.View.Accounts == nil || len(page.View.Accounts) != 0 {
		t.Fatalf("page model: %s", rec.Body.String())
	}
	if net.calls != 0 {
		t.Fatalf("a page view called out: %d", net.calls)
	}

	// Writes need the confirm token and a catalog connector.
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/connect", `{"connector":"copilot-agent"}`, false); rec.Code != http.StatusForbidden {
		t.Fatalf("connect without token = %d", rec.Code)
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/connect", `{"connector":"rm -rf"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("free-text connector = %d %s", rec.Code, rec.Body.String())
	}
	if net.calls != 0 {
		t.Fatalf("a refused write called out: %d", net.calls)
	}

	// A failed probe links nothing.
	rec = plansDo(t, s, http.MethodPost, "/api/cloud-agents/test", `{"connector":"copilot-agent"}`, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"error_class":"not_signed_in"`) {
		t.Fatalf("test = %d %s", rec.Code, rec.Body.String())
	}

	gh, _ := cloudagents.ConnectorByID(cloudagents.ConnectorCopilotAgent)
	idReq, _ := gh.IdentityRequest()
	listReq, _ := gh.ListRequest("")
	net.out[strings.Join(idReq.Argv, " ")] = cloudAgentsFixture(t, "copilot-agent/user.json")
	net.out[strings.Join(listReq.Argv, " ")] = cloudAgentsFixture(t, "copilot-agent/list.json")
	rec = plansDo(t, s, http.MethodPost, "/api/cloud-agents/connect", `{"connector":"copilot-agent"}`, true)
	var conn struct {
		Account struct {
			ID int64 `json:"id"`
		} `json:"account"`
		Sync struct {
			Tasks int `json:"tasks"`
		} `json:"sync"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &conn) != nil || conn.Account.ID == 0 || conn.Sync.Tasks != 3 {
		t.Fatalf("connect = %d %s", rec.Code, rec.Body.String())
	}
	id := strconv.FormatInt(conn.Account.ID, 10)
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/accounts/"+id+"/sync", `{}`, true); rec.Code != http.StatusOK {
		t.Fatalf("sync = %d %s", rec.Code, rec.Body.String())
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/accounts/"+id+"/bogus", `{}`, true); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown verb = %d", rec.Code)
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/accounts/"+id+"/disconnect", `{}`, true); rec.Code != http.StatusOK {
		t.Fatalf("disconnect = %d %s", rec.Code, rec.Body.String())
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/accounts/"+id+"/disconnect", `{}`, true); rec.Code != http.StatusNotFound {
		t.Fatalf("second disconnect = %d", rec.Code)
	}
}

// cloudAgentsFakeAPI answers the API connectors: Cursor's key probe and an
// empty agent list. It records the key each call presented.
type cloudAgentsFakeAPI struct {
	mu   sync.Mutex
	keys []string
	urls []string
	me   []byte
}

func (f *cloudAgentsFakeAPI) Call(_ context.Context, req cloudagents.Request, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, key)
	f.urls = append(f.urls, req.URL)
	if strings.HasSuffix(req.URL, "/v1/me") {
		return f.me, nil
	}
	return []byte(`{"items":[]}`), nil
}

func (f *cloudAgentsFakeAPI) Stream(context.Context, cloudagents.Request, string, time.Duration, func(cloudagents.SSEEvent) bool) (cloudagents.StreamEnd, error) {
	return cloudagents.StreamEnd{}, cloudagents.NewError(cloudagents.ErrFailed, "unexpected stream")
}

// TestCloudAgentsAPI_KeyInBodyOnly: an API connector's key arrives in the
// POST body behind the confirm token, reaches the keychain, and is never
// echoed in a response or a URL.
func TestCloudAgentsAPI_KeyInBodyOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	me, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "vendorapi", "cursor", "cursor.cloudagent.meta", "normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	api := &cloudAgentsFakeAPI{me: me}
	keys := &keystore.MemStore{}
	svc := cloudagentssvc.New(cloudagentssvc.Options{Store: store.New(database), Net: &cloudAgentsFakeNet{}, API: api, Keys: keys})
	s, err := New(Options{DB: database, DBPath: path, CloudAgents: svc})
	if err != nil {
		t.Fatal(err)
	}
	const key = "key_dash_SECRET_9f8e7d"
	rec := plansDo(t, s, http.MethodGet, "/api/cloud-agents", "", false)
	if !strings.Contains(rec.Body.String(), `"needs_key":true`) || !strings.Contains(rec.Body.String(), `"api.cursor.com"`) {
		t.Fatalf("catalog does not say which connectors take a key: %s", rec.Body.String())
	}
	// No key: a 400 and no call.
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/connect", `{"connector":"cursor-cloud"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("connect without key = %d %s", rec.Code, rec.Body.String())
	}
	// Devin without its organization: a 400 and no call.
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/connect", `{"connector":"devin","key":"`+key+`"}`, true); rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("devin without org = %d %s", rec.Code, rec.Body.String())
	}
	if len(api.urls) != 0 {
		t.Fatalf("a refused connect called out: %v", api.urls)
	}
	// Without the confirm token the key is never even read.
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/connect", `{"connector":"cursor-cloud","key":"`+key+`"}`, false); rec.Code != http.StatusForbidden {
		t.Fatalf("connect without token = %d", rec.Code)
	}
	rec = plansDo(t, s, http.MethodPost, "/api/cloud-agents/test", `{"connector":"cursor-cloud","key":"`+key+`"}`, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("test = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := keys.Get(cloudagentssvc.SecretName(cloudagents.ConnectorCursorCloud, 1)); err == nil {
		t.Fatal("a probe stored the key")
	}
	rec = plansDo(t, s, http.MethodPost, "/api/cloud-agents/connect", `{"connector":"cursor-cloud","key":"`+key+`"}`, true)
	var conn struct {
		Account struct {
			ID int64 `json:"id"`
		} `json:"account"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &conn) != nil || conn.Account.ID == 0 || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("connect = %d %s", rec.Code, rec.Body.String())
	}
	if got, err := keys.Get(cloudagentssvc.SecretName(cloudagents.ConnectorCursorCloud, conn.Account.ID)); err != nil || got != key {
		t.Fatalf("keychain = %q %v", got, err)
	}
	for _, u := range api.urls {
		if strings.Contains(u, key) {
			t.Fatalf("the key reached a URL: %s", u)
		}
	}
	rec = plansDo(t, s, http.MethodGet, "/api/cloud-agents", "", false)
	if strings.Contains(rec.Body.String(), key) {
		t.Fatal("the page model echoes the key")
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/accounts/"+strconv.FormatInt(conn.Account.ID, 10)+"/disconnect", `{}`, true); rec.Code != http.StatusOK {
		t.Fatalf("disconnect = %d", rec.Code)
	}
	if _, err := keys.Get(cloudagentssvc.SecretName(cloudagents.ConnectorCursorCloud, conn.Account.ID)); err == nil {
		t.Fatal("disconnect left the key")
	}
}

// devinPickerAPI answers a Devin organization with two members' sessions.
type devinPickerAPI struct {
	mu   sync.Mutex
	urls []string
}

const (
	pickerOrg  = "org-00112233445566778899aabbccddeeff"
	pickerMe   = "user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pickerThem = "user-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func (f *devinPickerAPI) Call(_ context.Context, req cloudagents.Request, _ string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.urls = append(f.urls, req.URL)
	item := func(id, user string) string {
		return `{"session_id":"` + id + `","status":"finished","user_id":"` + user + `","service_user_id":null,"org_id":"` + pickerOrg +
			`","created_at":1793350800,"updated_at":1793353200,"acus_consumed":1.0,"pull_requests":[],"parent_session_id":null}`
	}
	switch {
	case strings.Contains(req.URL, "/sessions?"):
		return []byte(`{"items":[` + item("s-me", pickerMe) + `,` + item("s-them", pickerThem) + `],"end_cursor":null,"has_next_page":false}`), nil
	case strings.Contains(req.URL, "/s-me/messages"):
		return []byte(`{"items":[{"event_id":"e1","source":"user","message":"x","created_at":1793350801,"username":"me","user_id":"` + pickerMe + `"}],"end_cursor":null,"has_next_page":false}`), nil
	case strings.Contains(req.URL, "/s-them/messages"):
		return []byte(`{"items":[{"event_id":"e2","source":"user","message":"x","created_at":1793350801,"username":"them","user_id":"` + pickerThem + `"}],"end_cursor":null,"has_next_page":false}`), nil
	}
	return nil, cloudagents.NewError(cloudagents.ErrPermissionDenied, "unexpected")
}

func (f *devinPickerAPI) Stream(context.Context, cloudagents.Request, string, time.Duration, func(cloudagents.SSEEvent) bool) (cloudagents.StreamEnd, error) {
	return cloudagents.StreamEnd{}, cloudagents.NewError(cloudagents.ErrFailed, "unexpected stream")
}

// TestCloudAgentsAPI_DevinUserPicker: a Devin account pulls nothing until
// its user is picked; the users route lists the organization's users (a
// picker, behind the confirm token); the user route takes only an id of the
// connector's grammar and then pulls that user's sessions only.
func TestCloudAgentsAPI_DevinUserPicker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	api := &devinPickerAPI{}
	svc := cloudagentssvc.New(cloudagentssvc.Options{Store: store.New(database), Net: &cloudAgentsFakeNet{}, API: api, Keys: &keystore.MemStore{}})
	s, err := New(Options{DB: database, DBPath: path, CloudAgents: svc})
	if err != nil {
		t.Fatal(err)
	}
	rec := plansDo(t, s, http.MethodGet, "/api/cloud-agents", "", false)
	if !strings.Contains(rec.Body.String(), `"chooses_user":true`) {
		t.Fatalf("catalog does not mark Devin as taking a user: %s", rec.Body.String())
	}
	rec = plansDo(t, s, http.MethodPost, "/api/cloud-agents/connect", `{"connector":"devin","key":"k_devin_1","params":{"org_id":"`+pickerOrg+`"}}`, true)
	var conn struct {
		Account struct {
			ID        int64  `json:"id"`
			UserState string `json:"user_state"`
		} `json:"account"`
		Sync struct {
			Tasks     int    `json:"tasks"`
			UserState string `json:"user_state"`
		} `json:"sync"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &conn) != nil || conn.Account.ID == 0 ||
		conn.Account.UserState != "vendor_user_not_chosen" || conn.Sync.UserState != "vendor_user_not_chosen" || conn.Sync.Tasks != 0 {
		t.Fatalf("connect = %d %s", rec.Code, rec.Body.String())
	}
	var n int
	_ = database.QueryRow(`SELECT COUNT(*) FROM sessions WHERE tool = 'devin'`).Scan(&n)
	if n != 0 {
		t.Fatalf("an unchosen account landed %d sessions", n)
	}
	id := strconv.FormatInt(conn.Account.ID, 10)
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/accounts/"+id+"/users", `{}`, false); rec.Code != http.StatusForbidden {
		t.Fatalf("users without token = %d", rec.Code)
	}
	rec = plansDo(t, s, http.MethodPost, "/api/cloud-agents/accounts/"+id+"/users", `{}`, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"username":"me"`) || !strings.Contains(rec.Body.String(), pickerThem) {
		t.Fatalf("users = %d %s", rec.Code, rec.Body.String())
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/accounts/"+id+"/user", `{"user_id":"me"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("free-text user = %d %s", rec.Code, rec.Body.String())
	}
	rec = plansDo(t, s, http.MethodPost, "/api/cloud-agents/accounts/"+id+"/user", `{"user_id":"`+pickerMe+`"}`, true)
	var chose struct {
		Account struct {
			VendorUser string `json:"vendor_user"`
		} `json:"account"`
		Sync struct {
			Tasks              int `json:"tasks"`
			SkippedOtherMember int `json:"skipped_other_member"`
		} `json:"sync"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &chose) != nil || chose.Account.VendorUser != pickerMe ||
		chose.Sync.Tasks != 1 || chose.Sync.SkippedOtherMember != 1 {
		t.Fatalf("choose = %d %s", rec.Code, rec.Body.String())
	}
	_ = database.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id = 's-them'`).Scan(&n)
	if n != 0 {
		t.Fatal("another member's session landed after the choice")
	}
}

// TestCloudAgentsAPI_SyncAll pins POST /api/cloud-agents/sync, the dashboard
// twin of `observer cloud-agents sync` with no account id (lane CA-B5): the
// confirm token is required, nothing linked means an empty list and no call,
// and with an account linked every account gets one pass.
func TestCloudAgentsAPI_SyncAll(t *testing.T) {
	s, net := newCloudAgentsServer(t)

	if rec := plansDo(t, s, http.MethodGet, "/api/cloud-agents/sync", "", false); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET sync = %d", rec.Code)
	}
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/sync", `{}`, false); rec.Code != http.StatusForbidden {
		t.Fatalf("sync without token = %d", rec.Code)
	}
	rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/sync", `{}`, true)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"syncs":[]}` {
		t.Fatalf("sync with nothing linked = %d %s", rec.Code, rec.Body.String())
	}
	if net.calls != 0 {
		t.Fatalf("sync with nothing linked called out: %d", net.calls)
	}

	gh, _ := cloudagents.ConnectorByID(cloudagents.ConnectorCopilotAgent)
	idReq, _ := gh.IdentityRequest()
	listReq, _ := gh.ListRequest("")
	net.out[strings.Join(idReq.Argv, " ")] = cloudAgentsFixture(t, "copilot-agent/user.json")
	net.out[strings.Join(listReq.Argv, " ")] = cloudAgentsFixture(t, "copilot-agent/list.json")
	if rec := plansDo(t, s, http.MethodPost, "/api/cloud-agents/connect", `{"connector":"copilot-agent"}`, true); rec.Code != http.StatusOK {
		t.Fatalf("connect = %d %s", rec.Code, rec.Body.String())
	}
	before := net.calls
	rec = plansDo(t, s, http.MethodPost, "/api/cloud-agents/sync", `{}`, true)
	var got struct {
		Syncs []struct {
			Account   int64  `json:"account"`
			Connector string `json:"connector"`
		} `json:"syncs"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || len(got.Syncs) != 1 ||
		got.Syncs[0].Connector != cloudagents.ConnectorCopilotAgent || got.Syncs[0].Account == 0 {
		t.Fatalf("sync all = %d %s", rec.Code, rec.Body.String())
	}
	if net.calls == before {
		t.Fatal("sync all made no pass")
	}

	// A vendor-side failure is carried in the account's result, not a 5xx.
	delete(net.out, strings.Join(listReq.Argv, " "))
	rec = plansDo(t, s, http.MethodPost, "/api/cloud-agents/sync", `{}`, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"error_class":"not_signed_in"`) {
		t.Fatalf("failing sync all = %d %s", rec.Code, rec.Body.String())
	}
}
