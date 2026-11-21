//go:build !sbo_omit_ingest_otlp

package main

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/claudecode"
	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/cloudlane"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
)

// cloudotel_fold_test.go is the part-3 proof of cloud-agents lane CA-C7: a
// Claude Code cloud session reported by BOTH the in-sandbox transcript
// (Rail S) and the session's own OpenTelemetry export (Rail T, whether it
// went to this node's receiver or to the in-sandbox loopback receiver) is ONE
// session, joined by its id and stamped with its ccr.session.id, and its
// tokens are counted once, at the transcript's figures (CA-D12: transcript >
// provider run total > OTel provisional), whichever rail lands first.

func intAttr(k string, v int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v}}}
}

// cloudFoldRef is the ccr.session.id (CLAUDE_CODE_REMOTE_SESSION_ID) both
// rails carry.
const cloudFoldRef = "cse_0123456789abcdefABCDEFGH"

// otelTwins builds the session's api_request export: one record per
// transcript token row, with the same per-call usage Anthropic returns to
// both (the transcript stores message.usage, the export reports it), a
// request id, a vendor cost and a timestamp a few hundred ms later, as the
// live check saw (15 ms apart). sideCalls adds requests the transcript never
// logs (title generation on a small model).
func otelTwins(tokens []models.TokenEvent, sessionID string, sideCalls int) *collogspb.ExportLogsServiceRequest {
	var recs []*logspb.LogRecord
	rec := func(ts time.Time, attrs ...*commonpb.KeyValue) {
		attrs = append(attrs, strAttr("session.id", sessionID), strAttr("ccr.session.id", cloudFoldRef))
		recs = append(recs, &logspb.LogRecord{EventName: "claude_code.api_request", TimeUnixNano: uint64(ts.UnixNano()), Attributes: attrs})
	}
	var last time.Time
	for i, e := range tokens {
		last = e.Timestamp
		rec(e.Timestamp.Add(300*time.Millisecond),
			strAttr("request_id", "req_fold_"+string(rune('a'+i%26))+e.SourceEventID), strAttr("model", e.Model),
			intAttr("input_tokens", e.InputTokens), intAttr("output_tokens", e.OutputTokens),
			intAttr("cache_read_tokens", e.CacheReadTokens), intAttr("cache_creation_tokens", e.CacheCreationTokens),
			intAttr("cache_creation_1h_tokens", e.CacheCreation1hTokens),
			strAttr("cost_usd", "0.01"), intAttr("duration_ms", 900))
	}
	for i := 0; i < sideCalls; i++ {
		rec(last.Add(time.Duration(i+1)*time.Second),
			strAttr("request_id", "req_side_"+string(rune('a'+i))), strAttr("model", "claude-haiku-4-5"),
			intAttr("input_tokens", 500), intAttr("output_tokens", 20), strAttr("cost_usd", "0.0006"))
	}
	return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: recs}},
	}}}
}

// tokenSum is the token figure the fold compares.
type tokenSum struct {
	Turns                                               int
	Input, Output, CacheRead, CacheCreation, Creation1h int64
}

func sumTokenEvents(tokens []models.TokenEvent) tokenSum {
	var s tokenSum
	for _, e := range tokens {
		s.Turns++
		s.Input += e.InputTokens
		s.Output += e.OutputTokens
		s.CacheRead += e.CacheReadTokens
		s.CacheCreation += e.CacheCreationTokens
		s.Creation1h += e.CacheCreation1hTokens
	}
	return s
}

func sumTurnRows(rows []cost.TurnRow, sessionID string) tokenSum {
	var s tokenSum
	for _, r := range rows {
		if r.SessionID != sessionID {
			continue
		}
		s.Turns++
		s.Input += r.Tokens.Input
		s.Output += r.Tokens.Output
		s.CacheRead += r.Tokens.CacheRead
		s.CacheCreation += r.Tokens.CacheCreation
		s.Creation1h += r.Tokens.CacheCreation1h
	}
	return s
}

// parseCloudFixture parses one Claude Code transcript fixture with the real
// adapter, laid out as the cloud VM lays it out.
//
// A rel ending in "+1h" reads the fixture without that suffix and gives its
// usage the 1-hour cache-write split a current cloud session reports (the
// live check of 2026-11-01 saw every cache write at the 1-hour TTL; the
// recorded fixtures predate the split).
func parseCloudFixture(t *testing.T, rel string) ([]models.ToolEvent, []models.TokenEvent, []models.SessionExecution) {
	t.Helper()
	with1h := strings.HasSuffix(rel, "+1h")
	rel = strings.TrimSuffix(rel, "+1h")
	src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	if with1h {
		const usage = `"cache_creation_input_tokens":67744,`
		if !bytes.Contains(src, []byte(usage)) {
			t.Fatalf("%s: usage shape changed", rel)
		}
		src = bytes.ReplaceAll(src, []byte(usage), []byte(usage+`"cache_creation":{"ephemeral_1h_input_tokens":67744,"ephemeral_5m_input_tokens":0},`))
	}
	dir := filepath.Join(t.TempDir(), "projects", "-home-user-example-repo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, filepath.Base(rel))
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := claudecode.New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(res.TokenEvents) == 0 {
		t.Fatal("fixture has no token rows")
	}
	return res.ToolEvents, res.TokenEvents, res.SessionExecutions
}

// TestCloudOTelFoldsIntoSandboxTranscript is the fold / precedence proof.
func TestCloudOTelFoldsIntoSandboxTranscript(t *testing.T) {
	for _, fx := range []string{"cloud/remote_desktop.jsonl", "cloud/remote_desktop.jsonl+1h", "gen-timing-real.jsonl"} {
		for _, order := range []string{"transcript first", "otel first"} {
			for _, side := range []int{0, 2} {
				name := fx + "/" + order
				if side > 0 {
					name += "/side calls"
				}
				t.Run(name, func(t *testing.T) { runCloudFold(t, fx, order == "otel first", side) })
			}
		}
	}
}

func runCloudFold(t *testing.T, fixture string, otelFirst bool, sideCalls int) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	events, tokens, execs := parseCloudFixture(t, fixture)
	sid := tokens[0].SessionID
	var mine []models.TokenEvent
	for _, e := range tokens {
		if e.SessionID == sid {
			mine = append(mine, e)
		}
	}
	transcript := sumTokenEvents(mine)
	if strings.HasSuffix(fixture, "+1h") && transcript.Creation1h == 0 {
		t.Fatal("the 1-hour split did not reach the transcript rows")
	}
	export := otelTwins(mine, sid, sideCalls)

	landTranscript := func() {
		// What Rail S lands: the transcript's own rows, stamped as the hook
		// rail stamps them (vendor_cloud plus the reference).
		ex := append(append([]models.SessionExecution(nil), execs...),
			models.SessionExecution{SessionID: sid, ExecutionLocation: models.ExecutionVendorCloud, VendorSessionRef: cloudFoldRef})
		if _, err := st.Ingest(ctx, events, tokens, store.IngestOptions{SessionExecutions: ex}); err != nil {
			t.Fatalf("ingest transcript: %v", err)
		}
	}
	landExport := func() {
		// What Rail T lands: the same ingest glue the node receiver and the
		// in-sandbox loopback receiver run, with Claude Code's transcript
		// capture on (the node and the sandbox both scan it).
		h := otlpLogsHandler(st, slog.New(slog.NewTextHandler(io.Discard, nil)), false, config.DefaultIngestOTelContentMaxBytes)
		if err := h(ctx, export); err != nil {
			t.Fatalf("otlp: %v", err)
		}
	}
	if otelFirst {
		landExport()
		landTranscript()
	} else {
		landTranscript()
		landExport()
	}

	// One session row, on the transcript's project (never the export's
	// placeholder), stamped vendor_cloud with the ccr.session.id.
	if n := countRows(t, database, `SELECT COUNT(*) FROM sessions WHERE id = ?`, sid); n != 1 {
		t.Fatalf("session rows = %d", n)
	}
	var root string
	var projectID int64
	if err := database.QueryRow(`SELECT p.root_path, p.id FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = ?`, sid).Scan(&root, &projectID); err != nil {
		t.Fatal(err)
	}
	if root == "[claude-code]" {
		t.Errorf("session left on the export's placeholder project")
	}
	ex, err := st.LoadSessionExecution(ctx, sid)
	if err != nil || ex.ExecutionLocation != models.ExecutionVendorCloud || ex.VendorSessionRef != cloudFoldRef {
		t.Fatalf("execution = %+v, %v", ex, err)
	}
	if got, ok, err := st.SessionIDByVendorRef(ctx, models.ToolClaudeCode, cloudFoldRef); err != nil || !ok || got != sid {
		t.Errorf("SessionIDByVendorRef = %q, %v, %v; want %s", got, ok, err, sid)
	}

	// Both rails really are stored: summing them raw would double count.
	raw := rawRailTurns(t, database, sid)
	if raw != 2*transcript.Turns+sideCalls {
		t.Fatalf("stored turns = %d; want transcript %d + export %d", raw, transcript.Turns, transcript.Turns+sideCalls)
	}

	// The spend every surface reads counts each call once, at the
	// transcript's figures (1-hour split included), plus only the calls
	// the transcript never logged.
	want := transcript
	want.Turns += sideCalls
	want.Input += int64(500 * sideCalls)
	want.Output += int64(20 * sideCalls)
	engine := cost.NewEngine(config.IntelligenceConfig{})
	rows, err := engine.TurnRows(ctx, database, cost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := sumTurnRows(rows, sid); got != want {
		t.Errorf("cost engine = %+v\nwant          %+v (transcript %+v, side calls %d)", got, want, transcript, sideCalls)
	}

	// The project figures (CA-C1's CA-D12 fold over off-machine sessions)
	// agree and set nothing aside: a folded call already carries the
	// transcript's figure, and a call only the export saw duplicates none.
	folded, err := dashapi.LoadFoldedProjectSpend(ctx, st, engine, projectID, time.Time{}, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if folded.SupersededTurns != 0 {
		t.Errorf("superseded turns = %d; want 0", folded.SupersededTurns)
	}
	var fs tokenSum
	for _, tr := range folded.All.Turns {
		if tr.SessionID == sid {
			fs.Turns++
			fs.Input += tr.Input
			fs.Output += tr.Output
			fs.CacheRead += tr.CacheRead
			fs.CacheCreation += tr.CacheCreation
			fs.Creation1h += tr.CacheCreation1h
		}
	}
	if fs != want {
		t.Errorf("project figures = %+v; want %+v", fs, want)
	}
}

// rawRailTurns counts the session's stored rows on both rails.
func rawRailTurns(t *testing.T, database *sql.DB, sid string) int {
	t.Helper()
	return countRows(t, database, `SELECT COUNT(*) FROM api_turns WHERE session_id = ?`, sid) +
		countRows(t, database, `SELECT COUNT(*) FROM token_usage WHERE session_id = ?`, sid)
}

// TestCloudOTelPrecedenceTiers pins how the CA-D12 table ranks the rows the
// two Claude Code rails leave behind: a transcript row and an export turn
// that survived the per-call fold both rank as the per-turn tier (the export
// turn then carries its twin's figure), a provisional telemetry token row
// ranks below a provider run total, and with a transcript-tier row present
// a provisional row is set aside, never summed.
func TestCloudOTelPrecedenceTiers(t *testing.T) {
	for src, want := range map[string]cloudagents.TokenSourceKind{
		models.TokenSourceJSONL: cloudagents.TokenFromSandboxTranscript,
		"proxy":                 cloudagents.TokenFromSandboxTranscript, // an api_turns row, cost.TurnRow.Source
		models.TokenSourceOTel:  cloudagents.TokenFromOTelProvisional,
	} {
		if got := cloudlane.TierOf(src); got != want {
			t.Errorf("TierOf(%q) = %s; want %s", src, got, want)
		}
	}
	if !cloudagents.TokenSupersedes(cloudagents.TokenFromSandboxTranscript, cloudagents.TokenFromOTelProvisional) ||
		!cloudagents.TokenSupersedes(cloudagents.TokenFromProviderRunTotal, cloudagents.TokenFromOTelProvisional) {
		t.Fatal("CA-D12 order changed")
	}
	off := func(string) bool { return true }
	got := cloudlane.SupersededTurns([]cloudlane.FoldTurn{
		{SessionID: "s", TokenSource: models.TokenSourceJSONL},
		{SessionID: "s", TokenSource: "proxy"},
		{SessionID: "s", TokenSource: models.TokenSourceOTel},
	}, off)
	if got[0] || got[1] || !got[2] {
		t.Errorf("superseded = %v; want [false false true]", got)
	}
}
