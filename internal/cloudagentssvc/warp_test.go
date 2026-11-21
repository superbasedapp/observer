package cloudagentssvc

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// warpMe is the fixtures' person creator, the account's chosen Warp user.
const warpMe = "synthUserUid0001"

// warpAllUserCreated turns the fixture's one service-account run into a run
// warpMe created, so the harness test lands all four runs (the member scope
// is TestWarpOwnRunsOnly's).
func warpAllUserCreated(b []byte) []byte {
	return bytes.Replace(b, []byte(`{"type": "service_account", "uid": "synthServiceAcct0001"}`), []byte(`{"type": "user", "uid": "synthUserUid0001"}`), 1)
}

// TestWarpSyncHarnessRowsAndLedger (lane CA-V1): one pass over the warp
// driver fixtures. The Claude Code and Codex harness runs land as sessions
// under their tools with the warp-cloud surface host, vendor-cloud
// execution, the conversation id as the second reference, harness tokens
// and the parent link; the oz runs land no session, action or token row,
// read no harness usage or conversation, and keep only their ledger rows.
// The transcript is never fetched and no prompt or key reaches the database.
func TestWarpSyncHarnessRowsAndLedger(t *testing.T) {
	const (
		runClaude = "7c1e2a40-0000-4000-8000-000000000001"
		runCodex  = "7c1e2a40-0000-4000-8000-000000000002"
		runOz     = "7c1e2a40-0000-4000-8000-000000000003"
		runOz2    = "7c1e2a40-0000-4000-8000-000000000004"
	)
	api := &fakeAPI{}
	api.call = func(req cloudagents.Request) ([]byte, error) {
		u := req.URL
		switch {
		case strings.Contains(u, "/agent/runs?") && strings.Contains(u, "cursor=synthRunsCursor0002"):
			return vendorFixture(t, "warp/warp.agent_api.runs_list/last_page.json"), nil
		case strings.Contains(u, "/agent/runs?"):
			return warpAllUserCreated(vendorFixture(t, "warp/warp.agent_api.runs_list/normal_page.json")), nil
		case strings.HasSuffix(u, runClaude+"/harness-usage"):
			return vendorFixture(t, "warp/warp.agent_api.run_harness_usage/normal_page.json"), nil
		case strings.HasSuffix(u, runCodex+"/harness-usage"):
			return vendorFixture(t, "warp/warp.agent_api.run_harness_usage/enum_sweep.json"), nil
		case strings.HasSuffix(u, runClaude+"/conversation"):
			return vendorFixture(t, "warp/warp.agent_api.run_conversation/normal_page.json"), nil
		case strings.HasSuffix(u, runCodex+"/conversation"):
			return []byte(`{"conversation_id":"9a4f7c21-0000-4000-8000-0000000000c2","steps":[]}`), nil
		}
		return nil, notFound(req)
	}
	clk := &clock{t: t0}
	svc, st, database, _, path := newAPIService(t, api, clk)
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorWarpCloud, Credentials{Key: apiKey})
	if err != nil || av == nil || av.AccountID != cloudagents.KeychainKeyAccount {
		t.Fatalf("connect: %+v %v", av, err)
	}
	if av.UserState != cloudagents.VendorUserNotChosen {
		t.Fatalf("a new Warp account reads %q, want vendor_user_not_chosen", av.UserState)
	}
	if _, err := svc.ChooseVendorUser(ctx, av.ID, warpMe); err != nil {
		t.Fatal(err)
	}
	api.reset()
	res, err := svc.SyncAccount(ctx, av.ID)
	if err != nil || res.Tasks != 4 || res.NoToolRows != 2 {
		t.Fatalf("sync: %v %+v", err, res)
	}
	calls := api.reset()
	for _, c := range calls {
		if !strings.HasPrefix(c, "https://app.warp.dev/api/v1/agent/runs") || strings.Contains(c, "/transcript") ||
			strings.Contains(c, runOz) || strings.Contains(c, runOz2) {
			t.Errorf("unexpected call %s", c)
		}
	}
	if !containsCall(calls, "execution_location=REMOTE") || !containsCall(calls, runCodex+"/harness-usage") {
		t.Fatalf("calls %v", calls)
	}
	type row struct{ tool, host, loc, ref, parent string }
	for id, want := range map[string]row{
		runClaude: {models.ToolClaudeCode, "warp-cloud", models.ExecutionVendorCloud, "9a4f7c21-0000-4000-8000-0000000000c1", ""},
		runCodex:  {models.ToolCodex, "warp-cloud", models.ExecutionVendorCloud, "9a4f7c21-0000-4000-8000-0000000000c2", runClaude},
	} {
		var got row
		if err := database.QueryRowContext(ctx, `SELECT tool, COALESCE(surface_host,''), COALESCE(execution_location,''),
			COALESCE(vendor_session_ref,''), COALESCE(parent_thread_id,'') FROM sessions WHERE id = ?`, id).
			Scan(&got.tool, &got.host, &got.loc, &got.ref, &got.parent); err != nil {
			t.Fatalf("session %s: %v", id, err)
		}
		if got != want {
			t.Errorf("session %s = %+v, want %+v", id, got, want)
		}
	}
	for _, id := range []string{runOz, runOz2} {
		var n int
		for _, q := range []string{
			`SELECT COUNT(*) FROM sessions WHERE id = ?`, `SELECT COUNT(*) FROM actions WHERE session_id = ?`,
			`SELECT COUNT(*) FROM token_usage WHERE session_id = ?`,
		} {
			_ = database.QueryRowContext(ctx, q, id).Scan(&n)
			if n != 0 {
				t.Errorf("oz run %s landed a tool row (%s)", id, q)
			}
		}
	}
	var in, out, cr, cw, cw1h int64
	if err := database.QueryRowContext(ctx, `SELECT input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
		COALESCE(cache_creation_1h_tokens,0) FROM token_usage WHERE session_id = ?`, runClaude).Scan(&in, &out, &cr, &cw, &cw1h); err != nil {
		t.Fatal(err)
	}
	if in != 1840 || out != 6120 || cr != 150200 || cw != 21400 || cw1h != 1400 {
		t.Fatalf("claude tokens %d %d %d %d %d", in, out, cr, cw, cw1h)
	}
	if err := database.QueryRowContext(ctx, `SELECT input_tokens, output_tokens FROM token_usage WHERE session_id = ?`, runCodex).Scan(&in, &out); err != nil {
		t.Fatal(err)
	}
	if in != 16000 || out != 1800 {
		t.Fatalf("codex tokens netted %d %d", in, out)
	}
	led, err := st.ListCloudUsage(ctx, store.CloudUsageFilter{Connector: cloudagents.ConnectorWarpCloud})
	if err != nil {
		t.Fatal(err)
	}
	type key struct{ session, unit string }
	got := map[key]float64{}
	for _, e := range led {
		got[key{e.ScopeSession, e.Unit}] += e.Value
	}
	for k, v := range map[key]float64{
		{runClaude, "warp_credit"}: 54.75, {runClaude, "usd"}: 0.5475,
		{runCodex, "warp_credit"}: 12, {runCodex, "usd"}: 0.12,
		{runOz, "warp_credit"}: 8, {runOz, "usd"}: 0.08,
	} {
		if got[k] != v {
			t.Errorf("ledger %v = %v, want %v", k, got[k], v)
		}
	}
	if len(got) != 6 {
		t.Errorf("ledger %v", got)
	}
	var tc, failed int
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*), SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) FROM actions
		WHERE session_id = ? AND raw_tool_name IN ('run_command','edit_files')`, runClaude).Scan(&tc, &failed)
	if tc != 2 || failed != 1 {
		t.Fatalf("tool call rows %d failed %d", tc, failed)
	}
	// The running Codex run keeps its checkpoint with its harness, so a
	// later pass that only re-reads it still knows its tool.
	cp, found, _ := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamSessionHistory, runCodex)
	if h := cloudagents.DecodeHistoryCursor(cp.Cursor); !found || h.Harness != "codex" || h.Lifecycle != string(cloudagents.LifecycleRunning) {
		t.Fatalf("codex checkpoint %v %q", found, cp.Cursor)
	}
	_, _ = database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	b, _ := os.ReadFile(path)
	for _, secret := range []string{apiKey, "Fix the flaky auth test", "go test ./auth", "synthetic.user@example.com", "I will run the test first"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("%q reached the database", secret)
		}
	}
}
