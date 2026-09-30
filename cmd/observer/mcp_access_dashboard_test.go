package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// mcpAccessCLIStatus runs `observer mcp status --json --no-remote` and
// decodes it: the contract the dashboard read must reproduce.
func mcpAccessCLIStatus(t *testing.T, cfgPath string) mcpRelayStatus {
	t.Helper()
	out, err := runMCPCLI(t, "mcp", "status", "--config", cfgPath, "--json", "--no-remote")
	if err != nil {
		t.Fatalf("mcp status: %v\n%s", err, out)
	}
	var s mcpRelayStatus
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatalf("status json: %v\n%s", err, out)
	}
	return s
}

// mcpAccessJSON round-trips a value through JSON (compares wire shapes).
func mcpAccessJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestMCPAccessView_MatchesCLIStatus pins the one-derivation contract: with
// the same remote-forwarding resolution, the dashboard read's `status` is
// byte-for-byte the `observer mcp status --json` body, the coverage rows are
// the rows that summary counts, and the approved servers / connect target
// come from the same table and origin rules `observer mcp connect` uses.
func TestMCPAccessView_MatchesCLIStatus(t *testing.T) {
	ctx := context.Background()
	e := newMCPCLIEnv(t, true)
	cursorPath := e.writeClient(t, ".cursor/mcp.json", projTestCursor)
	e.writeClient(t, ".config/opencode/opencode.json", projTestOpenCode)
	e.seedTable(t, "https://auth.acme", "vault_user")
	if out, err := runMCPCLI(t, "mcp", "wrap", "--config", e.cfgPath, "--no-remote"); err != nil {
		t.Fatalf("wrap: %v\n%s", err, out)
	}
	cfg, database, cleanup, err := loadConfigAndDB(ctx, e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := store.New(database).WriteEnrolment(ctx, store.Enrolment{OrgID: "acme", OrgServerURL: "https://org.acme:9443/api", UserID: "usr_1", Tenancy: "managed"}); err != nil {
		t.Fatal(err)
	}
	// Two chain records under the node key, so the chain walk is real.
	rs := record.NewSQLStore(database, mcpRelayNodeKey(ctx, cfg, store.New(database)))
	for i := int64(1); i <= 2; i++ {
		if _, err := rs.Append(ctx, record.Record{Kind: record.KindGap, TS: 1_700_000_000 + i, GapFrom: record.Int(i), GapTo: record.Int(i), LostCount: record.Int(1), GapReason: "local_append_failed"}); err != nil {
			t.Fatal(err)
		}
	}
	want := mcpAccessCLIStatus(t, e.cfgPath)
	if want.ChainHead != 2 || want.ChainOK == nil || !*want.ChainOK {
		t.Fatalf("CLI chain %d %v", want.ChainHead, want.ChainOK)
	}
	cursorBefore := mcpReadFile(t, cursorPath)
	// A live handle in the process global must NOT be read when the
	// daemon did not bind the relay (daemonRelay=false).
	prev := processMCPRelay.Load()
	t.Cleanup(func() { processMCPRelay.Store(prev) })
	live := newMCPRelayHandle(cfg, store.New(database), nil, slog.New(slog.DiscardHandler))
	live.SetProjectionApplied(true)
	if f, _ := live.Facts(); f.EnforceMode != "enforce" {
		t.Fatalf("live handle not enforcing: %+v", f)
	}
	processMCPRelay.Store(live)

	v, err := buildMCPAccessView(ctx, cfg, database, false, &mcpRelayRemote{Reason: "not probed (--no-remote)"}, true)
	if err != nil {
		t.Fatalf("buildMCPAccessView: %v", err)
	}
	if got, w := mcpAccessJSON(t, v.Status), mcpAccessJSON(t, want); got != w {
		t.Fatalf("dashboard status != CLI status\n got %s\nwant %s", got, w)
	}
	if !v.Available || !v.Enrolled || !v.Managed || v.RemoteSource != mcpAccessRemoteDaemon || !v.Status.Enabled || v.Status.PointStatus != "effective" {
		t.Fatalf("view header %+v", v)
	}
	counts := map[string]int{}
	for _, r := range v.CoverageRows {
		counts[r.Coverage]++
		if r.Client == "" || r.Transport == "" || r.Method == "" || r.Note == "" {
			t.Fatalf("coverage row missing a field: %+v", r)
		}
	}
	for label, n := range v.Status.Coverage {
		if counts[string(label)] != n {
			t.Fatalf("coverage rows %v disagree with the summary %v", counts, v.Status.Coverage)
		}
	}
	if len(v.CoverageRows) == 0 || counts["mediated"] == 0 {
		t.Fatalf("expected mediated rows after wrap: %v", counts)
	}
	if len(v.VServers) != 1 || v.VServers[0].ID != "vs-gh" || v.VServers[0].Slug != "github" || len(v.VServers[0].Servers) != 1 ||
		v.VServers[0].Servers[0].ID != "gh" || !v.VServers[0].Servers[0].PerUserConnect || v.VServers[0].Servers[0].CredentialMode != "vault_user" {
		t.Fatalf("vservers %+v", v.VServers)
	}
	if v.Connect.URL != "https://org.acme:9443/agent-access/connections" || v.Connect.OriginSource != "enrolment" || v.Connect.Unavailable != "" ||
		len(v.Connect.ConnectableServers) != 1 || v.Connect.ConnectableServers[0].ServerID != "gh" {
		t.Fatalf("connect %+v", v.Connect)
	}
	// The daemon did not bind the relay in this process: the effective
	// state is the honest none/no_policy row the node ACKs too.
	if v.EffectiveState.Status != "none" || v.EffectiveState.Reason != "no_policy" || v.EffectiveState.Mode != "off" {
		t.Fatalf("effective state without a live handle %+v", v.EffectiveState)
	}
	if !v.ChainVerified || v.Status.ChainHead != 2 || v.Status.ChainOK == nil || !*v.Status.ChainOK {
		t.Fatalf("chain_verified %v head %d ok %v", v.ChainVerified, v.Status.ChainHead, v.Status.ChainOK)
	}
	// A read writes nothing.
	if mcpReadFile(t, cursorPath) != cursorBefore {
		t.Fatal("the read rewrote a client config")
	}

	// verify=false skips the chain walk (chain_ok absent) and says so.
	v2, err := buildMCPAccessView(ctx, cfg, database, false, &mcpRelayRemote{Reason: "not probed (--no-remote)"}, false)
	if err != nil || v2.ChainVerified || v2.Status.ChainOK != nil {
		t.Fatalf("verify=false: %v verified=%v chain_ok=%v", err, v2.ChainVerified, v2.Status.ChainOK)
	}
}

// TestMCPAccessView_DisabledIsInert pins the kill switch: with
// [mcp_relay].enabled = false the read is the disabled `observer mcp
// status` shape, lists no approved registry and no coverage, reports the
// remote source as disabled, and writes nothing (journal and record rows
// unchanged, client config byte-identical).
func TestMCPAccessView_DisabledIsInert(t *testing.T) {
	ctx := context.Background()
	e := newMCPCLIEnv(t, false)
	cursorPath := e.writeClient(t, ".cursor/mcp.json", projTestCursor)
	e.seedTable(t, "https://auth.acme", "service")
	cfg, database, cleanup, err := loadConfigAndDB(ctx, e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	count := func(table string) int {
		t.Helper()
		var n int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	specsBefore, recordsBefore := count("mcp_relay_launch_spec"), count("mcp_relay_record")
	want := mcpAccessCLIStatus(t, e.cfgPath)

	v, err := buildMCPAccessView(ctx, cfg, database, false, nil, true)
	if err != nil {
		t.Fatalf("buildMCPAccessView: %v", err)
	}
	if got, w := mcpAccessJSON(t, v.Status), mcpAccessJSON(t, want); got != w {
		t.Fatalf("disabled dashboard status != CLI disabled status\n got %s\nwant %s", got, w)
	}
	if v.Status.Enabled || v.RemoteSource != mcpAccessRemoteDisabled || len(v.CoverageRows) != 0 || len(v.VServers) != 0 ||
		v.EffectiveState.Status != "none" || v.Enrolled || v.Connect.URL != "" || v.Connect.Unavailable == "" {
		t.Fatalf("disabled view %+v", v)
	}
	if count("mcp_relay_launch_spec") != specsBefore || count("mcp_relay_record") != recordsBefore || mcpReadFile(t, cursorPath) != projTestCursor {
		t.Fatal("a disabled read wrote state")
	}
}

// TestMCPAccessView_LiveEffectiveState: when the daemon bound the relay, the
// effective state is policystate.Resolve over the LIVE handle's facts - the
// same row the policy-state reporter ACKs (minus the fetch outcome).
func TestMCPAccessView_LiveEffectiveState(t *testing.T) {
	ctx := context.Background()
	e := newMCPCLIEnv(t, true)
	cfg, database, cleanup, err := loadConfigAndDB(ctx, e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	live := appliedHandle(t, cfg, "observe", false)
	prev := processMCPRelay.Load()
	t.Cleanup(func() { processMCPRelay.Store(prev) })
	processMCPRelay.Store(live)
	v, err := buildMCPAccessView(ctx, cfg, database, true, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := live.Facts()
	want := policystate.Resolve(policystate.PointNodeMCPRelay, policystate.FamilyToolsMCPAccess, f)
	if v.EffectiveState.Status != want.Status || v.EffectiveState.Reason != want.Reason || v.EffectiveState.Mode != want.Mode ||
		v.EffectiveState.Status != "accepted_inert" || v.EffectiveState.Reason != "mode_observe" {
		t.Fatalf("effective state %+v, want %s/%s/%s", v.EffectiveState, want.Status, want.Reason, want.Mode)
	}
	if !v.DaemonRelay || v.RemoteSource != mcpAccessRemoteNotStarted || !strings.Contains(v.Status.RemoteForwarding.Reason, "has not started") {
		t.Fatalf("runtime-not-started remote %+v / %q", v.Status.RemoteForwarding, v.RemoteSource)
	}
}

// TestMCPAccessRemote is the remote-source rule table, one case per row.
func TestMCPAccessRemote(t *testing.T) {
	held := &mcpRelayRemote{Wired: true, CredentialID: "cred-1"}
	cases := []struct {
		name        string
		daemonRelay bool
		remote      *mcpRelayRemote
		wantSource  string
		wantWired   bool
		wantReason  string
	}{
		{"runtime resolution wins", true, held, mcpAccessRemoteDaemon, true, ""},
		{"daemon started with the relay off", false, nil, mcpAccessRemoteNotStarted, false, "started with the relay disabled"},
		{"relay bound, runtime not started", true, nil, mcpAccessRemoteNotStarted, false, "has not started"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, src := mcpAccessRemote(tc.daemonRelay, tc.remote)
			if src != tc.wantSource || r.Wired != tc.wantWired || (tc.wantReason != "" && !strings.Contains(r.Reason, tc.wantReason)) {
				t.Fatalf("got %+v / %q", r, src)
			}
			if tc.remote != nil && !reflect.DeepEqual(r, *tc.remote) {
				t.Fatalf("resolution not passed through: %+v", r)
			}
		})
	}
}

// TestMCPAccessConnectTarget walks the connect-origin sources the read uses:
// enrolment first, then [org_client].org_server_url, else the honest
// not-enrolled reason (never a guessed URL).
func TestMCPAccessConnectTarget(t *testing.T) {
	h := newMCPRelayHandle(mcpRelayTestCfg(t, true), nil, nil, slog.New(slog.DiscardHandler))
	table := h.Table()
	cases := []struct {
		name, enr, cfgURL    string
		url, source, unavail string
	}{
		{name: "enrolment", enr: "https://org.acme/api", cfgURL: "https://cfg.acme", url: "https://org.acme/agent-access/connections", source: "enrolment"},
		{name: "config only", cfgURL: "http://127.0.0.1:9443", url: "http://127.0.0.1:9443/agent-access/connections", source: "[org_client].org_server_url"},
		{name: "not enrolled", unavail: "not enrolled with an organization"},
		{name: "bad enrolment URL", enr: "org.acme", unavail: "absolute http(s)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg config.Config
			cfg.OrgClient.OrgServerURL = tc.cfgURL
			var enr *store.Enrolment
			if tc.enr != "" {
				enr = &store.Enrolment{OrgServerURL: tc.enr}
			}
			c := mcpAccessConnectTarget(cfg, enr, table)
			if c.URL != tc.url || c.OriginSource != tc.source || (tc.unavail == "") != (c.Unavailable == "") ||
				(tc.unavail != "" && !strings.Contains(c.Unavailable, tc.unavail)) || c.ConnectableServers == nil ||
				strings.Contains(c.Unavailable, "--dashboard-url") {
				t.Fatalf("got %+v", c)
			}
		})
	}
}

// mcpAccessJSONFields lists a struct type's JSON field names and which of
// them are always emitted (no omitempty).
func mcpAccessJSONFields(t reflect.Type) (all, required map[string]bool) {
	all, required = map[string]bool{}, map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		all[name] = true
		if !strings.Contains(opts, "omitempty") {
			required[name] = true
		}
	}
	return all, required
}

// mcpAccessCheckObject asserts an untyped JSON object carries every
// always-emitted field of t and no field t does not declare.
func mcpAccessCheckObject(t *testing.T, where string, obj map[string]any, typ reflect.Type) {
	t.Helper()
	all, required := mcpAccessJSONFields(typ)
	for k := range obj {
		if !all[k] {
			t.Errorf("%s: fixture key %q is not in %s", where, k, typ.Name())
		}
	}
	for k := range required {
		if _, ok := obj[k]; !ok {
			t.Errorf("%s: fixture lacks always-emitted key %q of %s", where, k, typ.Name())
		}
	}
}

// TestMCPAccessView_FixturesMatchGoShape pins the VS Code / web fixtures
// (vscode/test/fixtures/agentAccess, generated from buildMCPAccessView) to
// the Go wire shape, so a field rename here fails loudly instead of leaving
// the TypeScript tests green against a stale payload.
func TestMCPAccessView_FixturesMatchGoShape(t *testing.T) {
	dir := filepath.Join("..", "..", "vscode", "test", "fixtures", "agentAccess")
	for _, name := range []string{"enabled", "ineffective", "unenrolled", "disabled"} {
		raw, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil {
			t.Fatalf("fixture %s: %v", name, err)
		}
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("fixture %s: %v", name, err)
		}
		mcpAccessCheckObject(t, name, v, reflect.TypeOf(mcpAccessView{}))
		obj := func(k string) map[string]any { m, _ := v[k].(map[string]any); return m }
		mcpAccessCheckObject(t, name+".status", obj("status"), reflect.TypeOf(mcpRelayStatus{}))
		st := obj("status")
		rf, _ := st["remote_forwarding"].(map[string]any)
		mcpAccessCheckObject(t, name+".status.remote_forwarding", rf, reflect.TypeOf(mcpRelayRemote{}))
		mcpAccessCheckObject(t, name+".effective_state", obj("effective_state"), reflect.TypeOf(mcpAccessEffective{}))
		mcpAccessCheckObject(t, name+".connect", obj("connect"), reflect.TypeOf(mcpAccessConnect{}))
		rows, _ := v["coverage_rows"].([]any)
		for i, r := range rows {
			m, _ := r.(map[string]any)
			mcpAccessCheckObject(t, fmt.Sprintf("%s.coverage_rows[%d]", name, i), m, reflect.TypeOf(mcpAccessCoverageRow{}))
		}
		vss, _ := v["vservers"].([]any)
		for i, x := range vss {
			m, _ := x.(map[string]any)
			mcpAccessCheckObject(t, fmt.Sprintf("%s.vservers[%d]", name, i), m, reflect.TypeOf(mcpAccessVServer{}))
			svs, _ := m["servers"].([]any)
			for j, y := range svs {
				sm, _ := y.(map[string]any)
				mcpAccessCheckObject(t, fmt.Sprintf("%s.vservers[%d].servers[%d]", name, i, j), sm, reflect.TypeOf(mcpAccessServer{}))
			}
		}
	}
}

// TestMCPAccess_RuntimePublishesRemote: a started relay runtime publishes
// the remote-forwarding resolution it reached, which is what the dashboard
// read reports (never a per-read org-server probe).
func TestMCPAccess_RuntimePublishesRemote(t *testing.T) {
	ctx := context.Background()
	e := newMCPCLIEnv(t, true)
	cfg, database, cleanup, err := loadConfigAndDB(ctx, e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	prev := processMCPRelayRemote.Load()
	t.Cleanup(func() { processMCPRelayRemote.Store(prev) })
	processMCPRelayRemote.Store(nil)
	st := store.New(database)
	h := newMCPRelayHandle(cfg, st, nil, slog.New(slog.DiscardHandler))
	if _, err := startMCPRelayRuntime(ctx, cfg, database, st, h, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("startMCPRelayRuntime: %v", err)
	}
	got := processMCPRelayRemote.Load()
	if got == nil || got.Wired || got.Reason != "not enrolled" {
		t.Fatalf("published remote %+v, want the not-enrolled resolution", got)
	}
	r, src := mcpAccessRemote(true, got)
	if src != mcpAccessRemoteDaemon || r.Reason != "not enrolled" {
		t.Fatalf("read reports %+v / %q", r, src)
	}
}

// TestMCPAccessView_ServiceServerIsNotPerUser: only a vault_user server is
// a per-user connect target, exactly as `observer mcp connect` lists them.
func TestMCPAccessView_ServiceServerIsNotPerUser(t *testing.T) {
	ctx := context.Background()
	e := newMCPCLIEnv(t, true)
	e.seedTable(t, "https://auth.acme", "service")
	cfg, database, cleanup, err := loadConfigAndDB(ctx, e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	v, err := buildMCPAccessView(ctx, cfg, database, false, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.VServers) != 1 || len(v.VServers[0].Servers) != 1 || v.VServers[0].Servers[0].PerUserConnect ||
		v.VServers[0].Servers[0].CredentialMode != "service" || len(v.Connect.ConnectableServers) != 0 {
		t.Fatalf("service server view %+v / %+v", v.VServers, v.Connect)
	}
}
