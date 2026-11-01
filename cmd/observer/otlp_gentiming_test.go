//go:build !sbo_omit_ingest_otlp

package main

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/codebuddy"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/otlpvendor"
	"github.com/marmutapp/superbased-observer/internal/store"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

// codebuddyTimingFixture is the agentlens capture and its transcript: the
// one pair proving request.id == providerData.messageId.
const (
	codebuddyTimingSession    = "01a165ad-1a86-7973-8bb9-a42e9af357ad"
	codebuddyTimingTranscript = "01a165ad-1a86-7973-8bb9-a42e9af357ad.jsonl"
)

// codebuddyWantGen is the end-to-end duration each call's export carries
// (span end - first_token_received + ttft_ms), keyed by messageId.
var codebuddyWantGen = map[string]int64{
	"01a165ad1cf775ed99158878cfa4ee77": 53,
	"01a165ad1ed87934a1734acbac73157b": 20,
}

// TestOTLPTimingKeysAcceptedByStore pins the two vocabularies of the
// transcript join: every key the vendor table may declare is one the store's
// seam accepts (otherwise every stamp would fail as a permanent error).
func TestOTLPTimingKeysAcceptedByStore(t *testing.T) {
	if string(otlpvendor.TimingKeyMessageID) != store.TranscriptKeyMessageID {
		t.Fatalf("otlpvendor.TimingKeyMessageID %q != store.TranscriptKeyMessageID %q", otlpvendor.TimingKeyMessageID, store.TranscriptKeyMessageID)
	}
	st, _ := newGenTimingNode(t)
	for _, k := range otlpvendor.TimingKeys() {
		got, err := st.StampTranscriptGenTiming(context.Background(), store.TranscriptGenStamp{
			Tool: models.ToolCodeBuddy, SessionID: "s", Key: string(k), KeyValue: "m", GenMs: 1,
		})
		if err != nil || got != store.GenStampNoRow {
			t.Errorf("key %q: outcome %d err %v, want a clean no-row", k, got, err)
		}
	}
}

func newGenTimingNode(t *testing.T) (*store.Store, *sql.DB) {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database), database
}

// codebuddyTranscriptTokens parses the fixture transcript with the real
// adapter, the way the watcher would.
func codebuddyTranscriptTokens(t *testing.T) []models.TokenEvent {
	t.Helper()
	raw, err := os.ReadFile(fixturePath("codebuddy", codebuddyTimingTranscript))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), codebuddyTimingTranscript)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	pr, err := codebuddy.New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("adapter parse: %v", err)
	}
	return pr.TokenEvents
}

func codebuddyExport(t *testing.T) *coltracepb.ExportTraceServiceRequest {
	t.Helper()
	raw, err := os.ReadFile(fixturePath("codebuddy", "traces.json"))
	if err != nil {
		t.Fatal(err)
	}
	var req coltracepb.ExportTraceServiceRequest
	if err := otlpingest.UnmarshalJSON(raw, &req); err != nil {
		t.Fatal(err)
	}
	return &req
}

type genRow struct {
	ms    int64
	basis string
}

func readGenRows(t *testing.T, database *sql.DB) map[string]genRow {
	t.Helper()
	rows, err := database.Query(`SELECT message_id, COALESCE(gen_ms, 0), COALESCE(gen_basis, '') FROM token_usage WHERE session_id = ? AND tool = ?`,
		codebuddyTimingSession, models.ToolCodeBuddy)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]genRow{}
	for rows.Next() {
		var id string
		var r genRow
		if err := rows.Scan(&id, &r.ms, &r.basis); err != nil {
			t.Fatal(err)
		}
		out[id] = r
	}
	return out
}

// TestOTLPGenTimingStampsTranscript is the AP-131 follow-up end to end on the
// live CodeBuddy capture: the transcript rows the real adapter writes carry
// the export's request.id as message_id (the proven join), and the export's
// per-call duration lands on exactly those rows with gen_basis "otel" in
// either arrival order, while the export still lands no token row of its own.
func TestOTLPGenTimingStampsTranscript(t *testing.T) {
	ctx := context.Background()
	tokens := codebuddyTranscriptTokens(t)
	ids := map[string]bool{}
	for _, tk := range tokens {
		if tk.SessionID == codebuddyTimingSession && tk.GenMs == 0 {
			ids[tk.MessageID] = true
		}
	}
	for id := range codebuddyWantGen {
		if !ids[id] {
			t.Fatalf("transcript has no untimed token row with message_id %s (rows %v): the join is not proven", id, ids)
		}
	}
	check := func(t *testing.T, database *sql.DB) {
		t.Helper()
		got := readGenRows(t, database)
		for id, ms := range codebuddyWantGen {
			if got[id] != (genRow{ms, models.GenBasisOTel}) {
				t.Errorf("row %s = %+v, want %d otel", id, got[id], ms)
			}
		}
		if n := countRows(t, database, `SELECT COUNT(*) FROM api_turns`); n != 0 {
			t.Errorf("export landed %d api_turns beside the transcript, want 0", n)
		}
	}
	newIngest := func(st *store.Store, transcript bool) *otlpIngest {
		return newOTLPIngest(st, slog.New(slog.NewTextHandler(io.Discard, nil)), true, config.DefaultIngestOTelContentMaxBytes,
			func(string) bool { return transcript })
	}

	t.Run("transcript first", func(t *testing.T) {
		st, database := newGenTimingNode(t)
		if _, err := st.Ingest(ctx, nil, tokens, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		ing := newIngest(st, true)
		for range 2 { // at-least-once redelivery is a no-op
			if err := ing.traces(nil)(ctx, codebuddyExport(t)); err != nil {
				t.Fatal(err)
			}
		}
		check(t, database)
		if n := ing.genPending.size(); n != 0 {
			t.Errorf("%d stamps parked although every row existed", n)
		}
	})

	t.Run("export first, row lands later", func(t *testing.T) {
		st, database := newGenTimingNode(t)
		ing := newIngest(st, true)
		if err := ing.traces(nil)(ctx, codebuddyExport(t)); err != nil {
			t.Fatal(err)
		}
		if n := ing.genPending.size(); n != len(codebuddyWantGen) {
			t.Fatalf("parked %d stamps, want %d", n, len(codebuddyWantGen))
		}
		if _, err := st.Ingest(ctx, nil, tokens, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		ing.retryPendingGenTimings(ctx)
		check(t, database)
		if n := ing.genPending.size(); n != 0 {
			t.Errorf("%d stamps still parked after their rows landed", n)
		}
	})

	t.Run("a parked stamp expires after the TTL", func(t *testing.T) {
		st, database := newGenTimingNode(t)
		ing := newIngest(st, true)
		now := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
		ing.clock = func() time.Time { return now }
		if err := ing.traces(nil)(ctx, codebuddyExport(t)); err != nil {
			t.Fatal(err)
		}
		now = now.Add(genTimingPendingTTL + time.Second)
		if _, err := st.Ingest(ctx, nil, tokens, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		ing.retryPendingGenTimings(ctx)
		if n := ing.genPending.size(); n != 0 {
			t.Errorf("%d expired stamps still parked", n)
		}
		for id, r := range readGenRows(t, database) {
			if r.ms != 0 {
				t.Errorf("row %s stamped by an expired stamp: %+v", id, r)
			}
		}
	})

	t.Run("transcript capture off: no stamp", func(t *testing.T) {
		st, database := newGenTimingNode(t)
		if _, err := st.Ingest(ctx, nil, tokens, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		ing := newIngest(st, false)
		if err := ing.traces(nil)(ctx, codebuddyExport(t)); err != nil {
			t.Fatal(err)
		}
		for id, r := range readGenRows(t, database) {
			if r.ms != 0 {
				t.Errorf("row %s stamped with the adapter off: %+v", id, r)
			}
		}
		if ing.genPending.size() != 0 {
			t.Error("stamps parked with the adapter off")
		}
		// The export owns the call here: its own turn carries the duration.
		if n := countRows(t, database, `SELECT COUNT(*) FROM api_turns WHERE session_id = ? AND total_response_ms > 0`, codebuddyTimingSession); n != 2 {
			t.Errorf("export turns with a duration = %d, want 2", n)
		}
	})
}
