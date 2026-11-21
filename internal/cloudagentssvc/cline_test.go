package cloudagentssvc

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestClineSyncLandsSessionsTokensAndFork is a full cline-cloud pass (lane
// CA-V6) against the recorded fixtures: the list, a status read and a
// history read per session, where the second session has no archive and no
// status (the egress answers its 404 / 410 with the JSON null). It lands
// both sessions under tool cline with surface host cline-cloud and
// execution vendor_cloud, the task id as vendor reference, tokens and a
// reported USD figure only for the session whose history reported them,
// the handoff as a user fork once the local source session exists, and no
// message text or key in the database.
func TestClineSyncLandsSessionsTokensAndFork(t *testing.T) {
	api := &fakeAPI{}
	api.call = func(req cloudagents.Request) ([]byte, error) {
		u := req.URL
		switch {
		case strings.HasSuffix(u, "/api/v1/session"):
			return vendorFixture(t, "cline/cline.cloud.sessions/normal_page.json"), nil
		case strings.HasSuffix(u, "/ses-synth0001/status"):
			return vendorFixture(t, "cline/cline.cloud.session_status/normal_page.json"), nil
		case strings.HasSuffix(u, "/ses-synth0001/history"):
			return vendorFixture(t, "cline/cline.cloud.session_history/normal_page.json"), nil
		case strings.HasSuffix(u, "/ses-synth0002/status"), strings.HasSuffix(u, "/ses-synth0002/history"):
			return []byte("null"), nil
		}
		return nil, notFound(req)
	}
	clk := &clock{t: t0}
	svc, st, database, _, path := newAPIService(t, api, clk)
	ctx := context.Background()
	// The local VS Code task the first cloud session was handed off from.
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "local/cline", SourceEventID: "local-1", SessionID: "1793351400123", ProjectRoot: "/home/u/widget",
		Tool: models.ToolCline, Timestamp: t0.Add(-48 * time.Hour), ActionType: models.ActionSessionStart, Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorClineCloud, Credentials{Key: apiKey})
	if err != nil || av == nil || av.AccountID != cloudagents.KeychainKeyAccount {
		t.Fatalf("connect: %+v %v", av, err)
	}
	res, err := svc.SyncAccount(ctx, av.ID)
	if err != nil || res.Tasks != 2 || res.ErrorClass != "" {
		t.Fatalf("sync: %v %+v", err, res)
	}
	for sid, wantRef := range map[string]string{"ses-synth0001": "task-synth-0001", "ses-synth0002": "task-synth-0002"} {
		var tool, host, loc, ref string
		if err := database.QueryRowContext(ctx, `SELECT tool, COALESCE(surface_host,''), COALESCE(execution_location,''),
			COALESCE(vendor_session_ref,'') FROM sessions WHERE id = ?`, sid).Scan(&tool, &host, &loc, &ref); err != nil {
			t.Fatalf("%s: %v", sid, err)
		}
		if tool != models.ToolCline || host != cloudagents.SurfaceHostClineCloud || loc != models.ExecutionVendorCloud || ref != wantRef {
			t.Fatalf("%s: tool %s host %s location %s ref %s", sid, tool, host, loc, ref)
		}
	}
	var in, out, cr, cw int64
	var source string
	if err := database.QueryRowContext(ctx, `SELECT input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, source
		FROM token_usage WHERE session_id = 'ses-synth0001'`).Scan(&in, &out, &cr, &cw, &source); err != nil {
		t.Fatal(err)
	}
	// The fixture reports input gross of cache reads (20700, 19200 of it
	// cache reads), as the live archive does; the row carries it net.
	if in != 1500 || out != 460 || cr != 19200 || cw != 800 || source != models.TokenSourceSessionSummary {
		t.Fatalf("tokens %d %d %d %d %s", in, out, cr, cw, source)
	}
	var none int
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_usage WHERE session_id = 'ses-synth0002'`).Scan(&none)
	if none != 0 {
		t.Fatalf("a session with no reported usage got %d token rows", none)
	}
	led, _ := st.ListCloudUsage(ctx, store.CloudUsageFilter{Connector: cloudagents.ConnectorClineCloud})
	if len(led) != 1 || led[0].ScopeSession != "ses-synth0001" || led[0].Unit != "usd" || led[0].Value != 0.0174 ||
		led[0].MonetaryStatus != models.UsageMonetaryReported {
		t.Fatalf("ledger %+v", led)
	}
	// The Cline SDK's tool names land classified through cline-cli's
	// vocabulary, under tool cline (live check 2026-11-02: they landed as
	// unknown before).
	for raw, want := range map[string]string{"editor": models.ActionEditFile, "run_commands": models.ActionRunCommand} {
		var actionType, tool string
		if err := database.QueryRowContext(ctx, `SELECT action_type, tool FROM actions
			WHERE session_id = 'ses-synth0001' AND raw_tool_name = ?`, raw).Scan(&actionType, &tool); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if actionType != want || tool != models.ToolCline {
			t.Fatalf("%s: action %q tool %q, want %q under cline", raw, actionType, tool, want)
		}
	}
	var root string
	_ = database.QueryRowContext(ctx, `SELECT p.root_path FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = 'ses-synth0002'`).Scan(&root)
	if root != "[cline-cloud]" {
		t.Fatalf("a session without a repository: %q", root)
	}
	var forked, threadSrc, parent string
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(forked_from_id,''), COALESCE(thread_source,''), COALESCE(parent_thread_id,'')
		FROM sessions WHERE id = 'ses-synth0001'`).Scan(&forked, &threadSrc, &parent); err != nil {
		t.Fatal(err)
	}
	if forked != "1793351400123" || threadSrc != cloudagents.ThreadSourceUser || parent != "" {
		t.Fatalf("handoff lineage: forked %q source %q parent %q", forked, threadSrc, parent)
	}
	_, _ = database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	b, _ := os.ReadFile(path)
	for _, secret := range []string{apiKey, "placeholder", "sandbox.invalid"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("%q reached the database", secret)
		}
	}
	// The catalog renders the coverage level for the dashboard and the CLI.
	for _, c := range Catalog() {
		if c.ID == cloudagents.ConnectorClineCloud && (c.Grounding != cloudagents.GroundingObservedUndocumented ||
			c.GroundingLabel != "Observed in vendor client, undocumented" || c.GroundingRank != 2 || c.GroundingMeaning == "") {
			t.Fatalf("catalog grounding %+v", c)
		}
	}
}
