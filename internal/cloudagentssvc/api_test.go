package cloudagentssvc

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

const apiKey = "key_live_SECRET-0123456789abcdef"

// fakeAPI answers API connector requests from a handler; it records every
// URL and the key each call presented.
type fakeAPI struct {
	t      *testing.T
	mu     sync.Mutex
	forbid bool
	calls  []string
	keys   []string
	call   func(req cloudagents.Request) ([]byte, error)
	stream func(req cloudagents.Request) ([]byte, error)
}

func (f *fakeAPI) record(req cloudagents.Request, key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := req.URL
	if req.LastEventID != "" {
		u += " last-event-id=" + req.LastEventID
	}
	f.calls = append(f.calls, u)
	f.keys = append(f.keys, key)
	if f.forbid {
		f.t.Errorf("egress with no linked account: %s", u)
		return false
	}
	return true
}

func (f *fakeAPI) Call(_ context.Context, req cloudagents.Request, key string) ([]byte, error) {
	if !f.record(req, key) {
		return nil, errors.New("forbidden")
	}
	return f.call(req)
}

func (f *fakeAPI) Stream(_ context.Context, req cloudagents.Request, key string, _ time.Duration, on func(cloudagents.SSEEvent) bool) (cloudagents.StreamEnd, error) {
	if !f.record(req, key) {
		return cloudagents.StreamEnd{}, errors.New("forbidden")
	}
	body, err := f.stream(req)
	if err != nil {
		return cloudagents.StreamEnd{}, err
	}
	var d cloudagents.SSEDecoder
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		if ev, ok := d.Line(sc.Text()); ok && !on(ev) {
			return cloudagents.StreamEnd{Reason: cloudagents.StreamEndDone}, nil
		}
	}
	return cloudagents.StreamEnd{Reason: cloudagents.StreamEndWindow}, nil
}

func (f *fakeAPI) reset() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls = nil
	return c
}

func vendorFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vendorapi", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newAPIService(t *testing.T, api *fakeAPI, clk *clock) (*Service, *store.Store, *sql.DB, *keystore.MemStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.db")
	svc, st, database := newTestServiceAt(t, path, &fakeNet{}, clk)
	api.t = t
	keys := &keystore.MemStore{}
	svc.api, svc.keys = api, keys
	return svc, st, database, keys, path
}

// newTestServiceAt is newTestService on a database at path.
func newTestServiceAt(t *testing.T, path string, net *fakeNet, clk *clock) (*Service, *store.Store, *sql.DB) {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	net.t = t
	net.out, net.errs = map[string][]byte{}, map[string]error{}
	st := store.New(database)
	return New(Options{Store: st, Net: net, Keys: &keystore.MemStore{}, Now: clk.now}), st, database
}

func notFound(req cloudagents.Request) error {
	return cloudagents.NewError(cloudagents.ErrPermissionDenied, "unexpected "+req.URL)
}

func TestAPIConnectorsNoAccountNoEgress(t *testing.T) {
	api := &fakeAPI{forbid: true}
	clk := &clock{t: t0}
	svc, _, _, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	if _, err := svc.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if rs, err := svc.SyncAll(ctx); err != nil || len(rs) != 0 {
		t.Fatalf("SyncAll = %v %v", rs, err)
	}
	clk.set(t0.Add(time.Hour))
	if rs := svc.SyncDue(ctx); len(rs) != 0 {
		t.Fatalf("SyncDue = %v", rs)
	}
	// A connect without a key, or without the organization Devin needs,
	// is refused before any call.
	for _, tc := range []struct {
		connector string
		cred      Credentials
	}{
		{cloudagents.ConnectorCursorCloud, Credentials{}},
		{cloudagents.ConnectorOpenHandsCloud, Credentials{Key: "two words"}},
		{cloudagents.ConnectorDevin, Credentials{Key: apiKey}},
		{cloudagents.ConnectorDevin, Credentials{Key: apiKey, Params: map[string]string{"org_id": "../x"}}},
	} {
		if _, _, err := svc.ConnectWith(ctx, tc.connector, tc.cred); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s %v: %v", tc.connector, tc.cred, err)
		}
	}
	if got := api.reset(); len(got) != 0 {
		t.Fatalf("calls with no account: %v", got)
	}
}

func TestAPIKeyLivesOnlyInTheKeychain(t *testing.T) {
	failMe := true
	api := &fakeAPI{call: func(req cloudagents.Request) ([]byte, error) {
		if strings.Contains(req.URL, "/app-conversations/search?") {
			return vendorFixture(t, "openhands/openhands.cloud.app_conversations_search/last_page.json"), nil
		}
		if strings.HasSuffix(req.URL, "/v1/me") {
			if failMe {
				return nil, cloudagents.NewError(cloudagents.ErrNotSignedIn, "HTTP Unauthorized")
			}
			return vendorFixture(t, "cursor/cursor.cloudagent.meta/normal_page.json"), nil
		}
		return nil, notFound(req)
	}}
	svc, st, database, keys, path := newAPIService(t, api, &clock{t: t0})
	ctx := context.Background()
	cred := Credentials{Key: "  " + apiKey + "\n"}
	if strings.Contains(cred.String()+cred.GoString(), apiKey) {
		t.Fatal("Credentials print the key")
	}
	// A refused key links nothing and stores nothing.
	res, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, cred)
	if err != nil || av != nil || res.OK || res.ErrorClass != cloudagents.ErrNotSignedIn {
		t.Fatalf("refused probe: %+v %v %v", res, av, err)
	}
	if accts, _ := st.ListCloudConnectorAccounts(ctx, ""); len(accts) != 0 {
		t.Fatal("a refused key linked an account")
	}
	if _, err := keys.Get(SecretName(cloudagents.ConnectorCursorCloud, 1)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatal("a refused key reached the keychain")
	}
	failMe = false
	res, av, err = svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, cred)
	if err != nil || av == nil || !res.OK || av.AccountID != "user:42" || av.Display != "developer@example.com" {
		t.Fatalf("connect: %+v %+v %v", res, av, err)
	}
	got, err := keys.Get(SecretName(cloudagents.ConnectorCursorCloud, av.ID))
	if err != nil || got != apiKey {
		t.Fatalf("keychain entry = %q %v", got, err)
	}
	for _, k := range api.keys {
		if k != apiKey {
			t.Fatalf("egress was handed %q, want the trimmed key", k)
		}
	}
	// The key is nowhere in the database.
	_, _ = database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	for _, f := range []string{path, path + "-wal"} {
		if b, err := os.ReadFile(f); err == nil && bytes.Contains(b, []byte(apiKey)) {
			t.Fatalf("%s holds the key", filepath.Base(f))
		}
	}
	// Re-linking the same key owner replaces the key in place.
	if _, av2, err := svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey + "2"}); err != nil || av2.ID != av.ID {
		t.Fatalf("relink: %+v %v", av2, err)
	}
	if got, _ := keys.Get(SecretName(cloudagents.ConnectorCursorCloud, av.ID)); got != apiKey+"2" {
		t.Fatalf("relinked key = %q", got)
	}
	// A keychain that refuses the key links nothing.
	svc.keys = refusingKeys{}
	if _, av3, err := svc.ConnectWith(ctx, cloudagents.ConnectorOpenHandsCloud, Credentials{Key: apiKey}); !errors.Is(err, ErrKeychain) || av3 != nil {
		t.Fatalf("refusing keychain: %+v %v", av3, err)
	}
	if accts, _ := st.ListCloudConnectorAccounts(ctx, cloudagents.ConnectorOpenHandsCloud); len(accts) != 0 {
		t.Fatal("an account was linked without its key")
	}
	svc.keys = keys
	// Disconnect deletes the key.
	if err := svc.Disconnect(ctx, av.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Get(SecretName(cloudagents.ConnectorCursorCloud, av.ID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatal("disconnect left the key in the keychain")
	}
}

type refusingKeys struct{}

func (refusingKeys) Get(string) (string, error) { return "", keystore.ErrNotFound }
func (refusingKeys) Set(string, string) error   { return errors.New("locked") }
func (refusingKeys) Delete(string) error        { return nil }
func (refusingKeys) Backend() string            { return "test" }
func (refusingKeys) SecurityDiagnostic() string { return "" }

// cursorRuns renders a runs page for the stream tests.
const cursorRunsTwo = `{"items":[
 {"id":"run-00000000-0000-0000-0000-000000000002","agentId":"bc-00000000-0000-0000-0000-000000000001","status":"RUNNING","createdAt":"2026-04-13T18:50:00.000Z","updatedAt":"2026-04-13T18:51:00.000Z","git":{"branches":[{"repoUrl":"github.com/your-org/your-repo","branch":"b"}]}},
 {"id":"run-old","agentId":"bc-00000000-0000-0000-0000-000000000001","status":"FINISHED","createdAt":"2026-04-13T18:30:00.000Z","updatedAt":"2026-04-13T18:40:00.000Z"}
]}`

func TestCursorSyncDetailStreamsResumeAndGap(t *testing.T) {
	runs := vendorFixture(t, "cursor/cursor.cloudagent.runs/normal_page.json")
	api := &fakeAPI{}
	api.call = func(req cloudagents.Request) ([]byte, error) {
		switch {
		case strings.HasSuffix(req.URL, "/v1/me"):
			return vendorFixture(t, "cursor/cursor.cloudagent.meta/normal_page.json"), nil
		case strings.HasSuffix(req.URL, "/v1/agents?limit=100"):
			return vendorFixture(t, "cursor/cursor.cloudagent.agents/normal_page.json"), nil
		case strings.Contains(req.URL, "/v1/agents?cursor="):
			return []byte(`{"items":[]}`), nil
		case strings.HasSuffix(req.URL, "/runs?limit=100"):
			return runs, nil
		case strings.HasSuffix(req.URL, "/usage"):
			return vendorFixture(t, "cursor/cursor.cloudagent.usage/normal_page.json"), nil
		}
		return nil, notFound(req)
	}
	api.stream = func(req cloudagents.Request) ([]byte, error) {
		switch {
		case strings.Contains(req.URL, "/runs/run-old/"):
			return nil, cloudagents.NewError(cloudagents.ErrStreamExpired, "HTTP Gone")
		case req.LastEventID == "1792264210000-13":
			return fixture(t, "cursor-cloud/stream-resume.sse"), nil
		case req.LastEventID == "":
			return fixture(t, "cursor-cloud/stream-live.sse"), nil
		}
		return nil, cloudagents.NewError(cloudagents.ErrStreamResumeRefused, "HTTP Bad Request")
	}
	// The clock sits right after the fixture runs: their streams are inside
	// Cursor's 24 h retention, so they are requested.
	cursorT0 := time.Date(2026, 4, 13, 19, 0, 0, 0, time.UTC)
	clk := &clock{t: cursorT0}
	svc, st, database, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey})
	if err != nil || av == nil {
		t.Fatal(err)
	}
	api.reset()
	res, err := svc.SyncAccount(ctx, av.ID)
	if err != nil {
		t.Fatalf("sync: %v %+v", err, res)
	}
	if res.Tasks != 1 || res.Pages != 2 || res.Details != 2 || res.Streams != 1 || res.StreamGaps != 0 || res.ErrorClass != "" {
		t.Fatalf("first sync = %+v", res)
	}
	sid := "bc-00000000-0000-0000-0000-000000000001"
	var tool, loc, root string
	if err := database.QueryRowContext(ctx, `SELECT s.tool, COALESCE(s.execution_location,''), p.root_path FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = ?`, sid).Scan(&tool, &loc, &root); err != nil {
		t.Fatal(err)
	}
	if tool != models.ToolCursor || loc != models.ExecutionVendorCloud || root != "cloud:github.com/your-org/your-repo" {
		t.Fatalf("session: tool=%s loc=%s root=%s", tool, loc, root)
	}
	var in, out, cr, cw int64
	var source string
	if err := database.QueryRowContext(ctx, `SELECT input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, source FROM token_usage WHERE session_id = ?`, sid).Scan(&in, &out, &cr, &cw, &source); err != nil {
		t.Fatal(err)
	}
	if in != 12480 || out != 3110 || cr != 42600 || cw != 18200 || source != models.TokenSourceSessionSummary {
		t.Fatalf("tokens %d %d %d %d %s", in, out, cr, cw, source)
	}
	actionTypes := func() map[string]int {
		rows, err := database.QueryContext(ctx, `SELECT action_type FROM actions WHERE session_id = ?`, sid)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		m := map[string]int{}
		for rows.Next() {
			var a string
			_ = rows.Scan(&a)
			m[a]++
		}
		return m
	}
	// One action per call id (live shape 2026-11-01): read_file,
	// file_search and edit_file (still running, outcome pending); the
	// argless run_terminal_cmd waits for the next window.
	if got := actionTypes(); got[models.ActionReadFile] != 1 || got[models.ActionSearchFiles] != 1 || got[models.ActionEditFile] != 1 ||
		got[models.ActionSessionStart] != 1 || got[models.ActionRunCommand] != 0 {
		t.Fatalf("actions after window 1: %v", got)
	}
	toolRows := func() map[string]string {
		rows, err := database.QueryContext(ctx, `SELECT raw_tool_name, COALESCE(target,''), success, timestamp FROM actions WHERE session_id = ? AND raw_tool_name NOT LIKE 'cloud_%'`, sid)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		m := map[string]string{}
		for rows.Next() {
			var name, target, at string
			var ok bool
			if err := rows.Scan(&name, &target, &ok, &at); err != nil {
				t.Fatal(err)
			}
			m[name] = fmt.Sprintf("%s|%v|%s", target, ok, at)
		}
		return m
	}
	if got := toolRows()["read_file"]; !strings.HasPrefix(got, "/workspace/src/loader.go|true|2026-10-17T19:10:06") {
		t.Fatalf("read_file row = %q (target, success, the event id's time)", got)
	}
	scope := sid + "/run-00000000-0000-0000-0000-000000000002"
	cp, found, err := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamLive, scope)
	if err != nil || !found {
		t.Fatalf("live checkpoint: %v %v", found, err)
	}
	if c := cloudagents.DecodeStreamCursor(cp.Cursor); c.LastEventID != "1792264210000-13" || c.State != cloudagents.StreamOpen {
		t.Fatalf("stream cursor = %+v", c)
	}

	// Second pass: the agent is unchanged but still running, so it is
	// re-read; the run's stream resumes with Last-Event-ID and reaches
	// done; the run finishes.
	runs = []byte(strings.Replace(string(runs), `"RUNNING"`, `"FINISHED"`, 1))
	clk.set(cursorT0.Add(20 * time.Minute))
	res, err = svc.SyncAccount(ctx, av.ID)
	if err != nil || res.Streams != 1 {
		t.Fatalf("second sync: %v %+v", err, res)
	}
	calls := api.reset()
	if !containsCall(calls, "/stream last-event-id=1792264210000-13") {
		t.Fatalf("no resumed stream in %v", calls)
	}
	if got := actionTypes(); got[models.ActionRunCommand] != 1 || got[models.ActionSessionEnd] != 1 || got[models.ActionEditFile] != 1 ||
		got[models.ActionSpawnSubagent] != 1 || got[models.ActionHarnessCall] != 2 {
		t.Fatalf("actions after resume: %v", got)
	}
	// The edit read running in window 1 completes in window 2: same row,
	// path kept, outcome patched; the failed command lands failed.
	rows := toolRows()
	if !strings.HasPrefix(rows["edit_file"], "/workspace/src/loader.go|true|") ||
		!strings.HasPrefix(rows["run_terminal_cmd"], "go test ./src/... -run TestLoader|false|") {
		t.Fatalf("rows after resume = %v", rows)
	}
	// The child agent the run created is not listed yet: its link waits.
	if _, found, _ := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamLive, "child/bc-5e1f0a2b-7c3d-4e5f-8a9b-0c1d2e3f4a09"); !found {
		t.Fatal("no pending child link")
	}
	cp, _, _ = st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamLive, scope)
	if c := cloudagents.DecodeStreamCursor(cp.Cursor); c.State != cloudagents.StreamDone {
		t.Fatalf("stream cursor after done = %+v", c)
	}
	if open, _ := st.ListCloudSyncCheckpoints(ctx, av.ID, models.SyncStreamSessionHistory); len(open) != 0 {
		t.Fatalf("a finished, fully read agent keeps a checkpoint: %+v", open)
	}

	// Third pass: a newer update brings an older run whose stream expired:
	// the run's interval is a recorded gap, the account says so, and the
	// streamed-to-done run is never re-read.
	runs = []byte(strings.Replace(cursorRunsTwo, `"RUNNING"`, `"FINISHED"`, 1))
	api.call = func(req cloudagents.Request) ([]byte, error) {
		if strings.HasSuffix(req.URL, "/v1/agents?limit=100") {
			return []byte(strings.Replace(string(vendorFixture(t, "cursor/cursor.cloudagent.agents/normal_page.json")),
				"2026-04-13T18:45:00.000Z", "2026-04-13T19:45:00.000Z", 1)), nil
		}
		switch {
		case strings.Contains(req.URL, "/v1/agents?cursor="):
			return []byte(`{"items":[]}`), nil
		case strings.HasSuffix(req.URL, "/runs?limit=100"):
			return runs, nil
		case strings.HasSuffix(req.URL, "/usage"):
			return vendorFixture(t, "cursor/cursor.cloudagent.usage/normal_page.json"), nil
		}
		return nil, notFound(req)
	}
	clk.set(cursorT0.Add(40 * time.Minute))
	res, err = svc.SyncAccount(ctx, av.ID)
	if err != nil || res.StreamGaps != 1 || res.Streams != 1 {
		t.Fatalf("third sync: %v %+v", err, res)
	}
	calls = api.reset()
	if containsCall(calls, "run-00000000-0000-0000-0000-000000000002/stream") {
		t.Fatalf("a done stream was re-read: %v", calls)
	}
	v, err := svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	acct := v.Accounts[0]
	if acct.ActivityGaps != 1 || len(acct.Gaps) != 1 || !strings.HasPrefix(acct.Gaps[0].Scope, "run "+sid+"/run-old") {
		t.Fatalf("account view gaps = %+v", acct)
	}
	if acct.Coverage != cloudagents.CoverageVerified {
		t.Fatalf("an expired stream is not an account failure: %s", acct.Coverage)
	}
	// Fourth pass: the expired stream is not retried.
	clk.set(cursorT0.Add(60 * time.Minute))
	if _, err := svc.SyncAccount(ctx, av.ID); err != nil {
		t.Fatal(err)
	}
	if calls := api.reset(); containsCall(calls, "run-old/stream") {
		t.Fatalf("an expired stream was retried: %v", calls)
	}
}

func containsCall(calls []string, sub string) bool {
	for _, c := range calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

// devinCorpusUsers maps the corpus fixtures' synthetic user ids onto ids of
// the live grammar (user-<32 hex>), so an account can choose one.
var devinCorpusUsers = strings.NewReplacer(
	`"user_synth0001"`, `"`+devinMe+`"`,
	`"user_synth0002"`, `"`+devinColleague+`"`,
)

// TestDevinSyncACUsAndMessages pulls the corpus organization as the user who
// started devin-synth0001: devin-synth0002 (a service user's automation) and
// devin-synth0003 (another member) are listed but never land (CLOUDAGENTS-6).
func TestDevinSyncACUsAndMessages(t *testing.T) {
	api := &fakeAPI{}
	api.call = func(req cloudagents.Request) ([]byte, error) {
		u := req.URL
		switch {
		case strings.Contains(u, "/sessions?") && strings.Contains(u, "after=synthsession0002"):
			return []byte(devinCorpusUsers.Replace(string(vendorFixture(t, "cognition/cognition.devin_v3.org_sessions/last_page.json")))), nil
		case strings.Contains(u, "/sessions?"):
			return []byte(devinCorpusUsers.Replace(string(vendorFixture(t, "cognition/cognition.devin_v3.org_sessions/normal_page.json")))), nil
		case strings.Contains(u, "/devin-synth0001/messages?after=synthmessage0003"):
			return vendorFixture(t, "cognition/cognition.devin_v3.session_messages/last_page.json"), nil
		case strings.Contains(u, "/devin-synth0001/messages?"):
			return vendorFixture(t, "cognition/cognition.devin_v3.session_messages/normal_page.json"), nil
		case strings.Contains(u, "/messages?"):
			return []byte(`{"items":[],"has_next_page":false,"end_cursor":null}`), nil
		}
		return nil, notFound(req)
	}
	clk := &clock{t: t0}
	svc, st, database, _, path := newAPIService(t, api, clk)
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorDevin, Credentials{Key: apiKey, Params: map[string]string{"org_id": "org_synth01"}})
	if err != nil || av == nil || av.AccountID != "org_synth01" {
		t.Fatalf("connect: %+v %v", av, err)
	}
	if _, err := svc.ChooseVendorUser(ctx, av.ID, devinMe); err != nil {
		t.Fatal(err)
	}
	api.reset()
	res, err := svc.SyncAccount(ctx, av.ID)
	if err != nil || res.Tasks != 1 || res.Pages != 2 || res.HistoryPages != 2 || res.LedgerNew != 2 ||
		res.SkippedOtherMember != 1 || res.SkippedServiceUser != 1 || res.SkippedNoUser != 0 {
		t.Fatalf("sync: %v %+v", err, res)
	}
	for _, other := range []string{"devin-synth0002", "devin-synth0003"} {
		var n int
		_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE id = ?`, other).Scan(&n)
		if n != 0 {
			t.Errorf("%s (not the chosen user's) landed", other)
		}
	}
	var tool, loc, root string
	if err := database.QueryRowContext(ctx, `SELECT s.tool, COALESCE(s.execution_location,''), p.root_path FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = 'devin-synth0001'`).Scan(&tool, &loc, &root); err != nil {
		t.Fatal(err)
	}
	if tool != models.ToolDevin || loc != models.ExecutionVendorCloud || root != "cloud:github.com/acme/widget" {
		t.Fatalf("session: %s %s %s", tool, loc, root)
	}
	var n int
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_usage WHERE tool = 'devin'`).Scan(&n)
	if n != 0 {
		t.Fatalf("ACUs reached token_usage: %d rows", n)
	}
	led, err := st.ListCloudUsage(ctx, store.CloudUsageFilter{Connector: cloudagents.ConnectorDevin})
	if err != nil {
		t.Fatal(err)
	}
	acu := map[string]float64{}
	for _, e := range led {
		if e.Unit == "acu" {
			acu[e.ScopeSession] = e.Value
		}
		if e.Unit == "usd" && (e.MonetaryStatus != models.UsageMonetaryReported || e.IncludesChildren == nil || *e.IncludesChildren) {
			t.Errorf("on-demand usd row = %+v", e)
		}
	}
	if acu["devin-synth0001"] != 3.75 || len(acu) != 1 {
		t.Fatalf("acu ledger = %v (only the chosen user's session; an absent figure is no row)", acu)
	}
	rows, err := database.QueryContext(ctx, `SELECT action_type, COALESCE(target,'') FROM actions WHERE session_id = 'devin-synth0001' AND action_type IN ('user_prompt','assistant_message')`)
	if err != nil {
		t.Fatal(err)
	}
	msgs := 0
	for rows.Next() {
		var at, target string
		_ = rows.Scan(&at, &target)
		if target != "" {
			t.Errorf("message text landed: %q", target)
		}
		msgs++
	}
	rows.Close()
	if msgs != 4 {
		t.Fatalf("message rows = %d", msgs)
	}
	cp, found, _ := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamSessionHistory, "devin-synth0001")
	if h := cloudagents.DecodeHistoryCursor(cp.Cursor); !found || h.After != "synthmessage0003" {
		t.Fatalf("running session checkpoint %v %+v", found, h)
	}
	if _, found, _ := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamSessionHistory, "devin-synth0003"); found {
		t.Fatal("a finished, fully read session keeps a checkpoint")
	}
	_, _ = database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	if b, _ := os.ReadFile(path); bytes.Contains(b, []byte("flaky login test")) || bytes.Contains(b, []byte(apiKey)) {
		t.Fatal("message text or the key reached the database")
	}
	// Second pass: the vendor is asked for the window only, and the running
	// session's history resumes from its stored page (re-read, deduplicated).
	clk.set(t0.Add(20 * time.Minute))
	res, err = svc.SyncAccount(ctx, av.ID)
	if err != nil {
		t.Fatal(err)
	}
	calls := api.reset()
	if !containsCall(calls, "updated_after=") || !containsCall(calls, "/devin-synth0001/messages?after=synthmessage0003") {
		t.Fatalf("second pass calls: %v", calls)
	}
	if res.ActionsNew != 0 {
		t.Fatalf("a re-read inserted %d actions", res.ActionsNew)
	}
}

func TestOpenHandsSyncTokensAndEvents(t *testing.T) {
	api := &fakeAPI{}
	api.call = func(req cloudagents.Request) ([]byte, error) {
		u := req.URL
		switch {
		case strings.Contains(u, "/app-conversations/search?") && strings.Contains(u, "page_id=synthpage0002"):
			// The fixture's last conversation names no creator: here it is
			// the chosen user's (the member scope is TestOpenHandsOwnConversationsOnly's).
			return bytes.Replace(vendorFixture(t, "openhands/openhands.cloud.app_conversations_search/last_page.json"),
				[]byte(`"created_by_user_id": null`), []byte(`"created_by_user_id": "`+openHandsMe+`"`), 1), nil
		case strings.Contains(u, "/app-conversations/search?"):
			return vendorFixture(t, "openhands/openhands.cloud.app_conversations_search/normal_page.json"), nil
		case strings.Contains(u, "000000000001/events/search?") && strings.Contains(u, "page_id=syntheventpage0002"):
			return vendorFixture(t, "openhands/openhands.cloud.events_search/last_page.json"), nil
		case strings.Contains(u, "000000000001/events/search?"):
			return vendorFixture(t, "openhands/openhands.cloud.events_search/normal_page.json"), nil
		case strings.Contains(u, "/events/search?"):
			return []byte(`{"items":[],"next_page_id":null}`), nil
		}
		return nil, notFound(req)
	}
	clk := &clock{t: t0}
	svc, st, database, _, path := newAPIService(t, api, clk)
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorOpenHandsCloud, Credentials{Key: apiKey})
	if err != nil || av == nil || av.AccountID != cloudagents.KeychainKeyAccount {
		t.Fatalf("connect: %+v %v", av, err)
	}
	if _, err := svc.ChooseVendorUser(ctx, av.ID, openHandsMe); err != nil {
		t.Fatal(err)
	}
	res, err := svc.SyncAccount(ctx, av.ID)
	if err != nil || res.Tasks != 3 {
		t.Fatalf("sync: %v %+v", err, res)
	}
	sid := "5b8f0c3e-0000-4000-8000-000000000001"
	var in, out, cr, cw int64
	var source, tool, loc string
	if err := database.QueryRowContext(ctx, `SELECT t.input_tokens, t.output_tokens, t.cache_read_tokens, t.cache_creation_tokens, t.source, s.tool, COALESCE(s.execution_location,'')
		FROM token_usage t JOIN sessions s ON s.id = t.session_id WHERE t.session_id = ?`, sid).Scan(&in, &out, &cr, &cw, &source, &tool, &loc); err != nil {
		t.Fatal(err)
	}
	if in != 182340-150200 || out != 6120 || cr != 150200 || cw != 21400 || source != models.TokenSourceSessionSummary ||
		tool != cloudagents.ToolOpenHands || loc != models.ExecutionVendorCloud {
		t.Fatalf("tokens %d %d %d %d %s %s %s", in, out, cr, cw, source, tool, loc)
	}
	led, _ := st.ListCloudUsage(ctx, store.CloudUsageFilter{Connector: cloudagents.ConnectorOpenHandsCloud})
	usd := map[string]float64{}
	for _, e := range led {
		usd[e.ScopeSession] = e.Value
	}
	if usd[sid] != 0.4215 || len(usd) != 2 {
		t.Fatalf("usd ledger = %v", usd)
	}
	var tc int
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions WHERE session_id = ? AND raw_tool_name = 'terminal'`, sid).Scan(&tc)
	if tc != 1 {
		t.Fatalf("tool call rows = %d", tc)
	}
	// The conversation with no repository goes to the placeholder bucket.
	var root string
	_ = database.QueryRowContext(ctx, `SELECT p.root_path FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = '5b8f0c3e-0000-4000-8000-000000000003'`).Scan(&root)
	if root != "[openhands-cloud]" || res.RepositoryNotReported != 1 {
		t.Fatalf("placeholder: %q %d", root, res.RepositoryNotReported)
	}
	cp, found, _ := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamSessionHistory, "5b8f0c3e-0000-4000-8000-000000000002")
	if !found || cloudagents.DecodeHistoryCursor(cp.Cursor).Lifecycle != string(cloudagents.LifecycleRunning) {
		t.Fatalf("running child conversation checkpoint: %v %q", found, cp.Cursor)
	}
	_, _ = database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	b, _ := os.ReadFile(path)
	for _, secret := range []string{apiKey, "synthetic-session-placeholder", "runtime-synth-0001", "Summarize this repository", "ls -la"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("%q reached the database", secret)
		}
	}
}

func TestAPIKeyMissingFromKeychainIsDisconnected(t *testing.T) {
	api := &fakeAPI{call: func(req cloudagents.Request) ([]byte, error) {
		return vendorFixture(t, "openhands/openhands.cloud.app_conversations_search/last_page.json"), nil
	}}
	svc, _, _, keys, _ := newAPIService(t, api, &clock{t: t0})
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorOpenHandsCloud, Credentials{Key: apiKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChooseVendorUser(ctx, av.ID, openHandsMe); err != nil {
		t.Fatal(err)
	}
	_ = keys.Delete(SecretName(cloudagents.ConnectorOpenHandsCloud, av.ID))
	api.reset()
	res, err := svc.SyncAccount(ctx, av.ID)
	if !IsCollectionError(err) || res.ErrorClass != cloudagents.ErrNotSignedIn || res.Coverage != cloudagents.CoverageDisconnected {
		t.Fatalf("missing key: %+v %v", res, err)
	}
	if calls := api.reset(); len(calls) != 0 {
		t.Fatalf("a pass with no key called out: %v", calls)
	}
}

// TestCursorDetailBudgetCarriesOver: a pass details at most MaxViews
// agents; the rest are owed, kept on a checkpoint, and detailed on a later
// pass even though the list no longer shows them as changed.
func TestCursorDetailBudgetCarriesOver(t *testing.T) {
	c, _ := cloudagents.ConnectorByID(cloudagents.ConnectorCursorCloud)
	n := c.MaxViews + 1
	var items []string
	for i := 0; i < n; i++ {
		// Newest first; the last agent was updated an hour before the rest.
		upd := "2026-04-13T19:00:00.000Z"
		if i == n-1 {
			upd = "2026-04-13T18:00:00.000Z"
		}
		items = append(items, `{"id":"bc-agent-`+string(rune('a'+i))+`","status":"ACTIVE","createdAt":"2026-04-13T17:00:00.000Z","updatedAt":"`+upd+`"}`)
	}
	list := `{"items":[` + strings.Join(items, ",") + `]}`
	detailed := map[string]int{}
	api := &fakeAPI{}
	api.call = func(req cloudagents.Request) ([]byte, error) {
		switch {
		case strings.HasSuffix(req.URL, "/v1/me"):
			return vendorFixture(t, "cursor/cursor.cloudagent.meta/normal_page.json"), nil
		case strings.HasSuffix(req.URL, "/v1/agents?limit=100"):
			return []byte(list), nil
		case strings.HasSuffix(req.URL, "/runs?limit=100"):
			id := strings.TrimSuffix(strings.TrimPrefix(req.URL, "https://api.cursor.com/v1/agents/"), "/runs?limit=100")
			detailed[id]++
			return []byte(`{"items":[{"id":"run-` + id + `","agentId":"` + id + `","status":"FINISHED","createdAt":"2026-04-13T17:00:00.000Z","updatedAt":"2026-04-13T17:30:00.000Z"}]}`), nil
		case strings.HasSuffix(req.URL, "/usage"):
			return []byte(`{"totalUsage":{"inputTokens":1},"runs":[]}`), nil
		}
		return nil, notFound(req)
	}
	api.stream = func(cloudagents.Request) ([]byte, error) { return []byte("id: 1\nevent: done\ndata: {}\n\n"), nil }
	budgetT0 := time.Date(2026, 4, 13, 19, 10, 0, 0, time.UTC) // the runs ended inside the 24 h stream retention
	clk := &clock{t: budgetT0}
	svc, _, _, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey})
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.SyncAccount(ctx, av.ID)
	if err != nil || res.Details != 2*c.MaxViews || res.DetailPending != 1 {
		t.Fatalf("first pass: %v %+v", err, res)
	}
	last := "bc-agent-" + string(rune('a'+n-1))
	if detailed[last] != 0 {
		t.Fatalf("the agent over budget was detailed: %v", detailed)
	}
	clk.set(budgetT0.Add(20 * time.Minute))
	res, err = svc.SyncAccount(ctx, av.ID)
	if err != nil || res.DetailPending != 0 || detailed[last] != 1 {
		t.Fatalf("second pass: %v %+v %v", err, res, detailed)
	}
	// The first pass streamed MaxStreams runs to done; those agents are
	// finished and fully read and are not re-read. The other two still owed
	// their stream, so they were re-read to reach it.
	for i := 0; i < n-1; i++ {
		id := "bc-agent-" + string(rune('a'+i))
		want := 1
		if i >= c.MaxStreams {
			want = 2
		}
		if detailed[id] != want {
			t.Errorf("%s detailed %d times, want %d", id, detailed[id], want)
		}
	}
}

// setRefusingKeys wraps a MemStore and refuses Set; deleteRefusingKeys
// refuses Delete. Both keep Get working so a test can see what survived.
type setRefusingKeys struct{ *keystore.MemStore }

func (setRefusingKeys) Set(string, string) error { return errors.New("locked") }

type deleteRefusingKeys struct{ *keystore.MemStore }

func (deleteRefusingKeys) Delete(string) error { return errors.New("locked") }

// TestAPIReconnectAndDisconnectNeverOrphanAKey pins the two keychain
// failure paths: a failed re-connect of a linked account keeps that
// account and its working key, and a failed key delete keeps the account
// linked (so disconnect can be retried) instead of orphaning the key.
func TestAPIReconnectAndDisconnectNeverOrphanAKey(t *testing.T) {
	api := &fakeAPI{call: func(req cloudagents.Request) ([]byte, error) {
		if strings.HasSuffix(req.URL, "/v1/me") {
			return vendorFixture(t, "cursor/cursor.cloudagent.meta/normal_page.json"), nil
		}
		return nil, notFound(req)
	}}
	svc, st, _, keys, _ := newAPIService(t, api, &clock{t: t0})
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey})
	if err != nil || av == nil {
		t.Fatalf("connect: %+v %v", av, err)
	}
	name := SecretName(cloudagents.ConnectorCursorCloud, av.ID)

	// Re-connect while the keychain refuses the new key: the account and
	// its previous key both stay.
	svc.keys = setRefusingKeys{keys}
	if _, av2, err := svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey + "2"}); !errors.Is(err, ErrKeychain) || av2 != nil {
		t.Fatalf("refused re-connect: %+v %v", av2, err)
	}
	accts, _ := st.ListCloudConnectorAccounts(ctx, cloudagents.ConnectorCursorCloud)
	if len(accts) != 1 || accts[0].ID != av.ID || accts[0].DisplayEmail != "developer@example.com" {
		t.Fatalf("a failed re-connect dropped the linked account: %+v", accts)
	}
	if got, err := keys.Get(name); err != nil || got != apiKey {
		t.Fatalf("previous key = %q %v", got, err)
	}

	// Disconnect while the keychain refuses the delete: the account stays
	// so the live key is not orphaned, and the error says why.
	svc.keys = deleteRefusingKeys{keys}
	if err := svc.Disconnect(ctx, av.ID); !errors.Is(err, ErrKeychainDelete) {
		t.Fatalf("refused delete: %v", err)
	}
	if accts, _ := st.ListCloudConnectorAccounts(ctx, cloudagents.ConnectorCursorCloud); len(accts) != 1 {
		t.Fatal("a refused key delete dropped the account row")
	}
	// A retry once the keychain works removes both.
	svc.keys = keys
	if err := svc.Disconnect(ctx, av.ID); err != nil {
		t.Fatal(err)
	}
	if accts, _ := st.ListCloudConnectorAccounts(ctx, cloudagents.ConnectorCursorCloud); len(accts) != 0 {
		t.Fatal("retried disconnect kept the row")
	}
	if _, err := keys.Get(name); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatal("retried disconnect left the key")
	}
	// A key already gone is not a refusal.
	_, av, _ = svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey})
	_ = keys.Delete(SecretName(cloudagents.ConnectorCursorCloud, av.ID))
	if err := svc.Disconnect(ctx, av.ID); err != nil {
		t.Fatalf("disconnect with the key already gone: %v", err)
	}
}
