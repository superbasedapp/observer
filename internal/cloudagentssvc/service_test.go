package cloudagentssvc

import (
	"context"
	"database/sql"
	"errors"
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

// fakeNet answers recorded CLI output keyed by the joined argv.
type fakeNet struct {
	t      *testing.T
	mu     sync.Mutex
	forbid bool
	out    map[string][]byte
	errs   map[string]error
	calls  []string
}

func (f *fakeNet) Run(_ context.Context, req cloudagents.Request) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Join(req.Argv, " ")
	f.calls = append(f.calls, key)
	if f.forbid {
		f.t.Errorf("egress with no linked account: %s", key)
		return nil, errors.New("forbidden")
	}
	if err, ok := f.errs[key]; ok {
		return nil, err
	}
	if b, ok := f.out[key]; ok {
		return b, nil
	}
	f.t.Errorf("unexpected call: %s", key)
	return nil, cloudagents.NewError(cloudagents.ErrFailed, "unexpected")
}

func (f *fakeNet) set(argv []string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.errs, strings.Join(argv, " "))
	f.out[strings.Join(argv, " ")] = b
}

func (f *fakeNet) fail(argv []string, class cloudagents.ErrorClass) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[strings.Join(argv, " ")] = cloudagents.NewError(class, "x")
}

func (f *fakeNet) reset() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls = nil
	return c
}

func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cloudagents", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

func newTestService(t *testing.T, net *fakeNet, clk *clock) (*Service, *store.Store, *sql.DB) {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: t.TempDir() + "/c.db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	net.t = t
	if net.out == nil {
		net.out = map[string][]byte{}
	}
	if net.errs == nil {
		net.errs = map[string]error{}
	}
	return New(Options{Store: st, Net: net, Keys: &keystore.MemStore{}, Now: clk.now}), st, database
}

var t0 = time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)

func conn(t *testing.T, id string) cloudagents.Connector {
	t.Helper()
	c, ok := cloudagents.ConnectorByID(id)
	if !ok {
		t.Fatal(id)
	}
	return c
}

// reqFor returns a helper that unwraps a request builder's result.
func reqFor(t *testing.T) func(cloudagents.Request, error) []string {
	return func(r cloudagents.Request, err error) []string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return r.Argv
	}
}

type sessionRow struct {
	tool, root, loc, ended string
}

func loadSession(t *testing.T, database *sql.DB, id string) (sessionRow, bool) {
	t.Helper()
	var r sessionRow
	err := database.QueryRow(`SELECT s.tool, p.root_path, COALESCE(s.execution_location,''), COALESCE(s.ended_at,'')
		FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = ?`, id).Scan(&r.tool, &r.root, &r.loc, &r.ended)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return r, true
}

func count(t *testing.T, database *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := database.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestConnectorSurfaceHostsShipVerbatim is the producer-side drift guard for
// the connector table's surface hosts (CA-D15): every host a connector can
// stamp must be in orgpush.go's closed knownSurfaceHosts list, or the org
// would read it as "other".
func TestConnectorSurfaceHostsShipVerbatim(t *testing.T) {
	for _, c := range cloudagents.Connectors {
		if c.SurfaceHost != "" && !store.SurfaceHostShipsVerbatim(c.SurfaceHost) {
			t.Errorf("connector %s surface host %q is not in knownSurfaceHosts", c.ID, c.SurfaceHost)
		}
	}
}

func TestNoAccountsMeansNoEgress(t *testing.T) {
	net := &fakeNet{forbid: true}
	s, _, _ := newTestService(t, net, &clock{t: t0})
	ctx := context.Background()
	if r, err := s.SyncAll(ctx); err != nil || r != nil {
		t.Fatalf("SyncAll: %v %v", r, err)
	}
	if r := s.SyncDue(ctx); r != nil {
		t.Fatalf("SyncDue: %v", r)
	}
	v, err := s.Status(ctx)
	if err != nil || len(v.Accounts) != 0 || len(v.Connectors) != len(cloudagents.Connectors) {
		t.Fatalf("status: %+v %v", v, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { s.Run(cctx); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done
	if c := net.reset(); len(c) != 0 {
		t.Fatalf("calls with no account: %v", c)
	}
}

func TestCopilotConnectSyncAndRefresh(t *testing.T) {
	mustReq := reqFor(t)
	net := &fakeNet{}
	clk := &clock{t: t0}
	s, st, database := newTestService(t, net, clk)
	ctx := context.Background()
	gh := conn(t, cloudagents.ConnectorCopilotAgent)
	idArgv := mustReq(gh.IdentityRequest())
	listArgv := mustReq(gh.ListRequest(""))
	net.set(idArgv, fixture(t, "copilot-agent/user.json"))
	net.set(listArgv, fixture(t, "copilot-agent/list.json"))

	// A local checkout of the same repository already exists: the cloud
	// sessions land on it (CA-D3).
	if _, err := st.UpsertProject(ctx, "/home/u/src/observer-demo", "git@github.com:acme-dev/observer-demo.git"); err != nil {
		t.Fatal(err)
	}

	res, av, err := s.Connect(ctx, gh.ID)
	if err != nil || !res.OK || av == nil || av.AccountID != "5551234" || av.Display != "octo-dev" || av.Coverage != cloudagents.CoverageVerified {
		t.Fatalf("connect: %+v %+v %v", res, av, err)
	}
	r, err := s.SyncAccount(ctx, av.ID)
	if err != nil || r.Tasks != 3 || r.Coverage != cloudagents.CoverageVerified || r.OpenTasks != 1 || r.ErrorClass != "" {
		t.Fatalf("sync: %+v %v", r, err)
	}
	live, ok := loadSession(t, database, "8f1c2d3e-4b5a-4c6d-9e7f-0a1b2c3d4e5f")
	if !ok || live.tool != models.ToolCopilot || live.root != "/home/u/src/observer-demo" || live.loc != models.ExecutionVendorCloud {
		t.Fatalf("live session: %+v %v", live, ok)
	}
	orphan, _ := loadSession(t, database, "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b")
	if orphan.root != "[copilot-agent]" || orphan.loc != models.ExecutionVendorCloud {
		t.Fatalf("no-repository session must use the placeholder: %+v", orphan)
	}
	// CA-D15: the product is told apart by the surface host, the tool id
	// stays copilot, and the surface kind stays unknown.
	if n := count(t, database, `SELECT COUNT(*) FROM sessions WHERE tool = ? AND surface_host = ? AND IFNULL(surface, '') = ''`,
		models.ToolCopilot, cloudagents.SurfaceHostCopilotCodingAgent); n != 3 {
		t.Fatalf("copilot-coding-agent host stamps: %d", n)
	}
	actions := count(t, database, `SELECT COUNT(*) FROM actions WHERE source_file = 'cloud-agents/copilot-agent'`)
	if actions != 5 { // 3 starts + 2 ends
		t.Fatalf("actions: %d", actions)
	}
	// Lane CA-C5: each task's stated PR is stored as a delivery link on its
	// repository (two of the three tasks state one).
	if n := count(t, database, `SELECT COUNT(*) FROM cloud_session_links WHERE connector = 'copilot-agent' AND remote = 'github.com/acme-dev/observer-demo' AND pr_number IN (412, 409)`); n != 2 {
		t.Fatalf("delivery links: %d", n)
	}

	// Re-sync is idempotent (overlap window re-reads everything here).
	clk.set(t0.Add(20 * time.Minute))
	if _, err := s.SyncAccount(ctx, av.ID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, database, `SELECT COUNT(*) FROM actions WHERE source_file = 'cloud-agents/copilot-agent'`); n != actions {
		t.Fatalf("re-sync duplicated actions: %d -> %d", actions, n)
	}
	if n := count(t, database, `SELECT COUNT(*) FROM cloud_session_links`); n != 2 {
		t.Fatalf("re-sync duplicated delivery links: %d", n)
	}

	// The live session falls off the list; it is re-read by id and its end
	// lands; its open-session checkpoint goes away.
	net.set(listArgv, []byte(`[]`))
	viewArgv := mustReq(gh.ViewRequest("8f1c2d3e-4b5a-4c6d-9e7f-0a1b2c3d4e5f"))
	net.set(viewArgv, fixture(t, "copilot-agent/view.json"))
	net.reset()
	clk.set(t0.Add(40 * time.Minute))
	r, err = s.SyncAccount(ctx, av.ID)
	if err != nil || r.Views != 1 || r.OpenTasks != 0 {
		t.Fatalf("refresh: %+v %v", r, err)
	}
	live, _ = loadSession(t, database, "8f1c2d3e-4b5a-4c6d-9e7f-0a1b2c3d4e5f")
	if live.ended == "" {
		t.Fatalf("ended_at not set after the view: %+v", live)
	}
	calls := net.reset()
	if len(calls) != 2 || calls[1] != strings.Join(viewArgv, " ") {
		t.Fatalf("calls: %v", calls)
	}

	// Status shows the account and its per-signal coverage.
	v, err := s.Status(ctx)
	if err != nil || len(v.Accounts) != 1 || v.Accounts[0].LastSuccess == nil || len(v.Accounts[0].Signals) != len(cloudagents.Signals()) {
		t.Fatalf("status: %+v %v", v, err)
	}

	// Disconnect drops the account and its checkpoints, keeps sessions.
	if err := s.Disconnect(ctx, av.ID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, database, `SELECT COUNT(*) FROM cloud_connector_accounts`); n != 0 {
		t.Fatalf("account kept: %d", n)
	}
	if n := count(t, database, `SELECT COUNT(*) FROM cloud_sync_checkpoints`); n != 0 {
		t.Fatalf("checkpoints kept: %d", n)
	}
	if _, ok := loadSession(t, database, "8f1c2d3e-4b5a-4c6d-9e7f-0a1b2c3d4e5f"); !ok {
		t.Fatal("disconnect deleted history")
	}
	if err := s.Disconnect(ctx, av.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second disconnect: %v", err)
	}
}

func TestCodexPagingOverlapAndProjects(t *testing.T) {
	mustReq := reqFor(t)
	net := &fakeNet{}
	clk := &clock{t: t0}
	s, st, database := newTestService(t, net, clk)
	ctx := context.Background()
	cx := conn(t, cloudagents.ConnectorCodexCloud)
	net.set(mustReq(cx.IdentityRequest()), fixture(t, "codex-cloud/list-page2.json"))
	page1 := mustReq(cx.ListRequest(""))
	page2 := mustReq(cx.ListRequest("eyJvZmZzZXQiOjJ9"))
	net.set(page1, fixture(t, "codex-cloud/list-page1.json"))
	net.set(page2, fixture(t, "codex-cloud/list-page2.json"))

	// A session with the same native id already exists under a local
	// project (another rail filed it): the pull must not move it.
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "/x.jsonl", SourceEventID: "e1", SessionID: "task_e_6720aa02b2c3d4e5f6a7b8c9d0e1f2a4",
		ProjectRoot: "/home/u/src/elsewhere", Tool: models.ToolCodex, Timestamp: t0.Add(-5 * time.Hour),
		ActionType: models.ActionUserPrompt, Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	res, av, err := s.Connect(ctx, cx.ID)
	if err != nil || !res.OK || av.AccountID != cloudagents.LocalLoginAccount {
		t.Fatalf("connect: %+v %v", res, err)
	}
	net.reset()
	r, err := s.SyncAccount(ctx, av.ID)
	// CA-D16: no known project carries the label's remote yet, so the
	// slug-shaped label does not make a project: two tasks go to the bucket
	// with the "repository not reported" note (the third stays where another
	// rail filed it).
	if err != nil || r.Pages != 2 || r.Tasks != 3 || r.Partial || r.RepositoryNotReported != 2 {
		t.Fatalf("first sync: %+v %v", r, err)
	}
	a, _ := loadSession(t, database, "task_e_6720aa01b2c3d4e5f6a7b8c9d0e1f2a3")
	if a.root != "[codex-cloud]" || a.tool != models.ToolCodex || a.loc != models.ExecutionVendorCloud || a.ended != "" {
		t.Fatalf("pending task: %+v", a)
	}
	if n := count(t, database, `SELECT COUNT(*) FROM projects WHERE root_path LIKE 'cloud:%'`); n != 0 {
		t.Fatalf("an environment label created %d synthetic project(s)", n)
	}
	b, _ := loadSession(t, database, "task_e_6720aa02b2c3d4e5f6a7b8c9d0e1f2a4")
	if b.root != "/home/u/src/elsewhere" || b.loc != models.ExecutionVendorCloud {
		t.Fatalf("existing session was moved or not stamped: %+v", b)
	}
	c, _ := loadSession(t, database, "task_e_6720aa03b2c3d4e5f6a7b8c9d0e1f2a5")
	if c.root != "[codex-cloud]" {
		t.Fatalf("prose environment label must not become a repository: %+v", c)
	}
	cp, ok, _ := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamDiscovery, "")
	if !ok || cp.Cursor != "2026-10-31T09:40:00Z" || cp.OverlapSeconds != int64(cx.Overlap/time.Second) || len(cp.Gaps) != 0 {
		t.Fatalf("checkpoint: %+v", cp)
	}

	// The developer clones the repository locally: the label now matches a
	// known project's remote, and the bucketed task upgrades onto it.
	if _, err := st.UpsertProject(ctx, "/home/u/src/observer-demo", "git@github.com:acme-dev/observer-demo.git"); err != nil {
		t.Fatal(err)
	}

	// Second pass: the overlap window stops on page 1.
	clk.set(t0.Add(30 * time.Minute))
	r, err = s.SyncAccount(ctx, av.ID)
	if err != nil || r.Pages != 1 || r.Tasks != 1 || r.RepositoryNotReported != 0 {
		t.Fatalf("second sync: %+v %v", r, err)
	}
	a, _ = loadSession(t, database, "task_e_6720aa01b2c3d4e5f6a7b8c9d0e1f2a3")
	if a.root != "/home/u/src/observer-demo" {
		t.Fatalf("bucketed task did not upgrade onto the known project: %+v", a)
	}
	if calls := net.reset(); len(calls) != 3 || calls[2] != strings.Join(page1, " ") {
		t.Fatalf("calls: %v", calls)
	}
}

func TestFailuresRecordCoverageAndBackOff(t *testing.T) {
	mustReq := reqFor(t)
	net := &fakeNet{}
	clk := &clock{t: t0}
	s, st, _ := newTestService(t, net, clk)
	ctx := context.Background()
	cx := conn(t, cloudagents.ConnectorCodexCloud)
	idArgv := mustReq(cx.IdentityRequest())
	net.fail(idArgv, cloudagents.ErrNotSignedIn)
	res, av, err := s.Connect(ctx, cx.ID)
	if err != nil || res.OK || av != nil || res.ErrorClass != cloudagents.ErrNotSignedIn || res.Coverage != cloudagents.CoverageDisconnected {
		t.Fatalf("failed connect: %+v %v %v", res, av, err)
	}
	if accts, _ := st.ListCloudConnectorAccounts(ctx, ""); len(accts) != 0 {
		t.Fatal("a failed probe linked an account")
	}

	net.set(idArgv, fixture(t, "codex-cloud/list-page2.json"))
	_, av, err = s.Connect(ctx, cx.ID)
	if err != nil {
		t.Fatal(err)
	}
	page1 := mustReq(cx.ListRequest(""))
	net.set(page1, fixture(t, "codex-cloud/list-page2.json"))
	if _, err := s.SyncAccount(ctx, av.ID); err != nil {
		t.Fatal(err)
	}
	before, _, _ := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamDiscovery, "")

	net.fail(page1, cloudagents.ErrNotSignedIn)
	clk.set(t0.Add(time.Hour))
	r, err := s.SyncAccount(ctx, av.ID)
	if !IsCollectionError(err) || r.ErrorClass != cloudagents.ErrNotSignedIn || r.Coverage != cloudagents.CoverageDisconnected {
		t.Fatalf("failed sync: %+v %v", r, err)
	}
	after, _, _ := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamDiscovery, "")
	if after.Cursor != before.Cursor || !after.LastSuccessAt.Equal(before.LastSuccessAt) || !after.LastAttemptAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("a failure moved the checkpoint: %+v -> %+v", before, after)
	}
	accts, _ := st.ListCloudConnectorAccounts(ctx, "")
	if accts[0].CoverageState != string(cloudagents.CoverageDisconnected) || accts[0].LastErrorClass != string(cloudagents.ErrNotSignedIn) {
		t.Fatalf("account state: %+v", accts[0])
	}
	// SyncAll carries on past a collection failure.
	if rs, err := s.SyncAll(ctx); err != nil || len(rs) != 1 {
		t.Fatalf("SyncAll: %v %v", rs, err)
	}
	// Backing off: the loop does not retry within the backoff.
	net.reset()
	clk.set(t0.Add(2 * time.Hour))
	if r := s.SyncDue(ctx); len(r) != 0 {
		t.Fatalf("retried within backoff: %+v", r)
	}
	if c := net.reset(); len(c) != 0 {
		t.Fatalf("calls within backoff: %v", c)
	}
	// After the backoff and a recovered login, the loop syncs and clears it.
	net.set(page1, fixture(t, "codex-cloud/list-page2.json"))
	clk.set(t0.Add(30 * time.Hour))
	if r := s.SyncDue(ctx); len(r) != 1 || r[0].ErrorClass != "" {
		t.Fatalf("recovery: %+v", r)
	}
	accts, _ = st.ListCloudConnectorAccounts(ctx, "")
	if accts[0].LastErrorClass != "" || accts[0].CoverageState != string(cloudagents.CoverageVerified) {
		t.Fatalf("recovered state: %+v", accts[0])
	}
	// Not due again until the connector interval passes.
	if r := s.SyncDue(ctx); len(r) != 0 {
		t.Fatalf("synced before the interval: %+v", r)
	}
}

func TestUnknownConnectorAndBackoffTable(t *testing.T) {
	s, _, _ := newTestService(t, &fakeNet{forbid: true}, &clock{t: t0})
	if _, err := s.Test(context.Background(), "made-up"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown connector: %v", err)
	}
	cases := []struct {
		class cloudagents.ErrorClass
		n     int
		want  time.Duration
	}{
		{cloudagents.ErrUnreachable, 1, 15 * time.Minute},
		{cloudagents.ErrUnreachable, 3, time.Hour},
		{cloudagents.ErrUnreachable, 30, 6 * time.Hour},
		{cloudagents.ErrRateLimited, 1, time.Hour},
		{cloudagents.ErrNotSignedIn, 5, 24 * time.Hour},
	}
	for _, tc := range cases {
		if got := BackoffFor(tc.class, tc.n); got != tc.want {
			t.Errorf("BackoffFor(%s,%d) = %s want %s", tc.class, tc.n, got, tc.want)
		}
	}
}
