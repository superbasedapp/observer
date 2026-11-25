package invariant

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/hookliveness"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/ownagent"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolaccount"
)

// seedCacheEvents inserts one cache_events row with a sentinel model, so a
// SelectUnpushedSince batch can be searched for whether the P5c cache aggregate
// shipped. cache_segments/entries/events stay NODE-LOCAL; only the content-free
// (day, model, kind) aggregate crosses the wire, and only under cache_detail.
func seedCacheEvents(ctx context.Context, t *testing.T, database *sql.DB, model string) {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, tokens_read, tokens_written, cost_delta_usd)
		 VALUES ('sess-cc-1', 'proxy', ?, ?, 'hit', 4000, 0, -0.012)`, ts, model); err != nil {
		t.Fatalf("seed cache_events: %v", err)
	}
}

// TestPushPayloadCarriesCacheWhenOptedIn is the Arc 4 P5c extraction tier: under
// the DISTINCT cache_detail opt-in, the node-local cache_events log ships as a
// content-free (day × model × kind) aggregate. The cache_* table NAMES still
// never appear in orgpush.go (SelectCacheSummaries owns the read in a separate
// file — TestSelectUnpushedSinceExcludesCacheTables guards that); this proves
// the aggregate itself flips onto the wire under the tier.
func TestPushPayloadCarriesCacheWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secCacheModel = "SENTINEL_CACHE_MODEL_pangram_zz"
	seedCacheEvents(ctx, t, database, secCacheModel)

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{CacheDetail: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.CacheSummaries) == 0 {
		t.Fatal("cache_detail opt-in shipped no CacheSummaries — the tier failed to flip the seam")
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if !bytes.Contains(raw, []byte(secCacheModel)) {
		t.Error("cache aggregate did NOT ship under cache_detail — the tier failed to flip the seam")
	}
}

// TestPushPayloadStripsCacheWhenNotOptedIn is the other side of the tier: with
// cache_detail OFF, the fleet cache aggregate must NOT ship — not even under
// full_content (maximum path/content disclosure). cache_detail is a DISTINCT
// tier, orthogonal to shipsRawContent().
//
// Org-parity W2.1 nuance (plan §0/§3.1, 2026-08-24), extended by the per-event
// timeline (operator directive item 6): TWO session-scoped cache wires
// deliberately ride shipsRawContent() rather than cache_detail —
// SessionCacheSummaries (the bucket) and SessionCacheEvents (the per-event
// log). full_content / admin_managed nodes DO ship both, model included. So
// under full_content-only the batch-wide byte-scan for the sentinel model is
// scoped to exclude those two legitimate wires; the zero-value (metadata-only,
// TEAMS default) case still byte-scans the ENTIRE batch — nothing cache-shaped
// may cross there, which is the guard that actually protects the teams tier.
func TestPushPayloadStripsCacheWhenNotOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secCacheModel = "SENTINEL_CACHE_MODEL_pangram_zz"
	seedCacheEvents(ctx, t, database, secCacheModel)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"zero-value", store.ShareOptions{}},
		{"full_content-only", store.ShareOptions{FullContent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.CacheSummaries) != 0 {
				t.Errorf("cache aggregate shipped under %s (cache_detail OFF) — the cache tier must be orthogonal and opt-in", tc.name)
			}
			if tc.share.FullContent {
				// full_content legitimately ships BOTH session-scoped cache
				// wires (model included) — scope the leak scan to the batch
				// WITHOUT them so the fleet cache_detail tier stays pinned
				// orthogonal.
				if len(batch.SessionCacheSummaries) == 0 {
					t.Error("full_content shipped no session cache wire — the W2.1 enterprise wire failed to flip")
				}
				if len(batch.SessionCacheEvents) == 0 {
					t.Error("full_content shipped no session cache EVENTS — the per-event timeline wire failed to flip")
				}
				batch.SessionCacheSummaries = nil
				batch.SessionCacheEvents = nil
			} else {
				if len(batch.SessionCacheSummaries) != 0 {
					t.Errorf("session cache wire shipped under %s (metadata-only) — it must ride shipsRawContent only", tc.name)
				}
				if len(batch.SessionCacheEvents) != 0 {
					t.Errorf("session cache EVENT wire shipped under %s (metadata-only) — it must ride shipsRawContent only", tc.name)
				}
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			if bytes.Contains(raw, []byte(secCacheModel)) {
				t.Errorf("cache model leaked under %s without cache_detail", tc.name)
			}
		})
	}
}

// seedCacheEventTimeline inserts TWO cache_events rows shaped for the per-event
// timeline wire (operator directive item 6):
//
//   - a fully-populated anomaly carrying every optional column, including the
//     `detail` diagnostic JSON with its own sentinel and diverged_seq = 0 /
//     cost_delta_usd = 0 — the two values whose meaning would be destroyed by
//     a "zero means absent" mapping;
//   - a bare baseline row with cause / diverged_seq / diverged_level /
//     cost_delta_usd / predicted_kind / message_id all NULL.
//
// Together they let one test prove both directions of the NULL rule and the
// `detail` exclusion at once.
func seedCacheEventTimeline(ctx context.Context, t *testing.T, database *sql.DB, model, detailSentinel, msgSentinel string) {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO cache_events
		   (session_id, tier, timestamp, model, kind, cause,
		    diverged_seq, diverged_level,
		    tokens_read, tokens_written, tokens_written_1h,
		    cost_delta_usd, predicted_kind, message_id, detail)
		 VALUES ('sess-cc-1', 'proxy', ?, ?, 'mispredict', 'tools_changed',
		         0, 'tools', 4000, 1200, 300, 0, 'hit', ?, ?)`,
		ts, model, msgSentinel, `{"note":"`+detailSentinel+`"}`); err != nil {
		t.Fatalf("seed cache_events (anomaly): %v", err)
	}
	// A 0/0 token pair on this baseline hit lets one test also pin the
	// ZeroUsageOf rule: a hit with no token movement is NOT vacant (only a
	// mispredict with no tokens is), so ZeroUsageOf() must read false here.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO cache_events
		   (session_id, tier, timestamp, model, kind, tokens_read, tokens_written)
		 VALUES ('sess-cc-1', 'proxy', ?, ?, 'hit', 0, 0)`, ts, model); err != nil {
		t.Fatalf("seed cache_events (baseline): %v", err)
	}
}

// TestSessionCacheEventsShipOnlyUnderRawContent is the wire-surface pin for the
// PER-EVENT cache timeline (server migration 142, operator directive item 6).
//
// WHAT CHANGED, AND WHAT DID NOT. "cache_events" STAYS in forbiddenCacheTables:
// that sentinel is a SOURCE-LEVEL rule about internal/store/orgpush.go — the
// table name may not appear there — and TestSelectUnpushedSinceExcludesCacheTables
// still enforces it, because the read lives in its own seam file
// (internal/store/cacheeventorgrows.go) exactly as the two existing cache wires
// already do. What this test pins is the DATA posture, which the enterprise-
// first ruling deliberately reverses: the per-event log may now cross, under
// the node's own raw-content posture.
//
// Four properties, in one table:
//
//	(a) the zero value ships NOTHING — the teams/metadata default is untouched;
//	(b) cache_detail ALONE ships nothing here either. That flag gates the
//	    CONTENT-FREE FLEET day aggregate and is ORTHOGONAL in both directions;
//	    the per-event log is not a louder version of it;
//	(c) full_content, and separately admin_managed, DO ship it — with every
//	    field cachetrack.TimelineEvent needs, and with the two NULLABLE numerics
//	    round-tripped honestly: 0 stays 0 (not nil) and NULL stays nil (not 0);
//	(d) the node's `detail` diagnostic JSON NEVER crosses — not even under
//	    full_content, which is the widest posture a node can be in. That is a
//	    policy exclusion made structural in the seam's SELECT list, and this is
//	    the case that keeps it that way.
func TestSessionCacheEventsShipOnlyUnderRawContent(t *testing.T) {
	const (
		secCacheModel  = "SENTINEL_CACHE_EVT_MODEL_pangram_gg"
		secCacheDetail = "SENTINEL_CACHE_EVT_DETAIL_pangram_hh"
		secCacheMsg    = "SENTINEL_CACHE_EVT_MSGID_pangram_ii"
	)
	for _, tc := range []struct {
		name     string
		share    store.ShareOptions
		wantRows bool
	}{
		{"zero-value", store.ShareOptions{}, false},
		{"cache_detail-only", store.ShareOptions{CacheDetail: true}, false},
		{"full_content", store.ShareOptions{FullContent: true}, true},
		{"admin_managed", store.ShareOptions{AdminManaged: true}, true},
		{"cache_detail+full_content", store.ShareOptions{CacheDetail: true, FullContent: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st)
			seedCacheEventTimeline(ctx, t, database, secCacheModel, secCacheDetail, secCacheMsg)

			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
				tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}

			if !tc.wantRows {
				if len(batch.SessionCacheEvents) != 0 {
					t.Errorf("per-event cache timeline shipped %d rows under %s — it rides shipsRawContent() "+
						"ONLY; cache_detail gates the content-free FLEET aggregate and is orthogonal",
						len(batch.SessionCacheEvents), tc.name)
				}
			} else {
				if len(batch.SessionCacheEvents) != 2 {
					t.Fatalf("per-event cache timeline shipped %d rows under %s, want 2 — the enterprise wire failed to flip",
						len(batch.SessionCacheEvents), tc.name)
				}
				var sawAnomaly, sawBaseline bool
				for _, r := range batch.SessionCacheEvents {
					if r.SessionID != "sess-cc-1" || r.Model != secCacheModel || r.Tier != "proxy" {
						t.Errorf("row identity = %q/%q/%q, want sess-cc-1/%s/proxy",
							r.SessionID, r.Model, r.Tier, secCacheModel)
					}
					if r.NodeEventID == 0 {
						t.Error("NodeEventID = 0 — the node's own cache_events.id is the idempotency key and must ship")
					}
					if r.Timestamp == "" {
						t.Error("Timestamp is empty — it is the timeline's ordering key")
					}
					switch r.Kind {
					case "mispredict":
						sawAnomaly = true
						if r.Cause != "tools_changed" || r.DivergedLevel != "tools" || r.PredictedKind != "hit" {
							t.Errorf("anomaly enums = cause %q / level %q / predicted %q, want tools_changed/tools/hit",
								r.Cause, r.DivergedLevel, r.PredictedKind)
						}
						if r.MessageID != secCacheMsg {
							t.Errorf("MessageID = %q, want the seeded sentinel — the drawer joins a cache event to its message on it", r.MessageID)
						}
						if r.TokensRead != 4000 || r.TokensWritten != 1200 || r.TokensWritten1H != 300 {
							t.Errorf("token movement = %d/%d/%d, want 4000/1200/300",
								r.TokensRead, r.TokensWritten, r.TokensWritten1H)
						}
						// The load-bearing half of the NULL rule: a stored 0
						// must arrive as a PRESENT zero, never as nil. 0 means
						// "the FIRST block diverged" / "a genuinely zero cost
						// delta", both real readings.
						if r.DivergedSeq == nil || *r.DivergedSeq != 0 {
							t.Errorf("DivergedSeq = %v, want a non-nil 0 — 0 means the FIRST block diverged, "+
								"and collapsing it onto nil would report it as \"not computed\"", r.DivergedSeq)
						}
						if r.CostDeltaUSD == nil || *r.CostDeltaUSD != 0 {
							t.Errorf("CostDeltaUSD = %v, want a non-nil 0 — 0 is a genuinely zero delta, not an absence", r.CostDeltaUSD)
						}
						if r.ZeroUsageOf() {
							t.Error("ZeroUsageOf() = true for an event with 4000 read — the derivation disagrees with its own tokens")
						}
					case "hit":
						sawBaseline = true
						// The other half: a stored NULL must arrive as nil, so
						// no reader can present "not computed" as a value.
						if r.DivergedSeq != nil {
							t.Errorf("DivergedSeq = %v for a row with NULL diverged_seq, want nil", *r.DivergedSeq)
						}
						if r.CostDeltaUSD != nil {
							t.Errorf("CostDeltaUSD = %v for a row with NULL cost_delta_usd, want nil", *r.CostDeltaUSD)
						}
						// A 0/0 hit is NOT vacant — only a mispredict with no
						// tokens is. ZeroUsageOf now delegates to
						// cachetrack.IsZeroUsage, so the two surfaces agree.
						if r.ZeroUsageOf() {
							t.Error("ZeroUsageOf() = true for a 0/0 HIT — a hit that moved no cache tokens is a real event, not vacant")
						}
						if r.Cause != "" || r.DivergedLevel != "" || r.PredictedKind != "" || r.MessageID != "" {
							t.Errorf("baseline row carried enums it was not seeded with: cause %q level %q predicted %q msg %q",
								r.Cause, r.DivergedLevel, r.PredictedKind, r.MessageID)
						}
					default:
						t.Errorf("unexpected kind %q", r.Kind)
					}
				}
				if !sawAnomaly || !sawBaseline {
					t.Error("both seeded events must ship — BuildTimeline needs the baseline runs as well as the anomalies")
				}
			}

			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			// The `detail` diagnostic JSON is excluded BY POLICY at every
			// posture, including the widest one. This is the case that keeps
			// the seam's SELECT list honest.
			if bytes.Contains(raw, []byte(secCacheDetail)) {
				t.Errorf("cache_events.detail leaked under %s — the engine's diagnostic JSON is excluded by policy "+
					"at EVERY posture; it is not selected by internal/store/cacheeventorgrows.go and must never be", tc.name)
			}
			// The model and message id are per-event detail: present exactly
			// when the wire ships, absent otherwise. cache_detail-only must not
			// smuggle them through the fleet aggregate's message-id-less shape.
			if leaked := bytes.Contains(raw, []byte(secCacheMsg)); leaked != tc.wantRows {
				t.Errorf("message id present in the marshalled batch = %v, want %v under %s",
					leaked, tc.wantRows, tc.name)
			}
		})
	}
}

// seedCodeintel inserts one codeintel file + symbol + edge whose project path
// and symbol name are sentinels, so a SelectUnpushedSince batch can be searched
// both for whether the P5f codeintel-detail aggregate shipped AND for whether
// any raw source identity leaked. codeintel_* stays NODE-LOCAL; only the
// content-free per (project-HASH × lang) file/symbol/edge count aggregate
// crosses, and only under codeintel_detail — the project path is hashed and the
// symbol name is never shipped.
func seedCodeintel(ctx context.Context, t *testing.T, database *sql.DB, project, symbol string) {
	t.Helper()
	res, err := database.ExecContext(ctx,
		`INSERT INTO codeintel_files (project, path, lang, status) VALUES (?, ?, 'go', 'indexed')`,
		project, project+"/main.go")
	if err != nil {
		t.Fatalf("seed codeintel_files: %v", err)
	}
	fileID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("codeintel_files last id: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO codeintel_nodes (project, file_id, kind, name, fqn, lang) VALUES (?, ?, 'function', ?, ?, 'go')`,
		project, fileID, symbol, symbol); err != nil {
		t.Fatalf("seed codeintel_nodes: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO codeintel_edges (project, file_id, src_id, dst_id, kind) VALUES (?, ?, 0, 0, 'CALLS')`,
		project, fileID); err != nil {
		t.Fatalf("seed codeintel_edges: %v", err)
	}
}

// TestPushPayloadCarriesCodeintelWhenOptedIn is the Arc 4 P5f extraction tier:
// under the DISTINCT codeintel_detail opt-in, the node-local codeintel index
// ships as a content-free per (project-HASH × language) file/symbol/edge count
// aggregate. Two properties are proven together: (1) the tier FLIPS the seam
// (CodeintelSummaries is non-empty and the ProjectHash is a hash, not the raw
// path); and (2) even when it ships, NO raw source identity crosses — neither
// the project path nor the symbol name appears in the marshalled batch. The
// codeintel_* table NAMES still never appear in orgpush.go (SelectCodeintelSummaries
// owns the read in a separate file — TestSelectUnpushedSinceExcludesCacheTables
// guards that).
func TestPushPayloadCarriesCodeintelWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const (
		secProject = "SENTINEL_CODEINTEL_PROJECT_pangram_zz"
		secSymbol  = "SENTINEL_CODEINTEL_SYMBOL_pangram_zz"
	)
	seedCodeintel(ctx, t, database, secProject, secSymbol)

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{CodeintelDetail: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.CodeintelSummaries) == 0 {
		t.Fatal("codeintel_detail opt-in shipped no CodeintelSummaries — the tier failed to flip the seam")
	}
	// The project path must be HASHED, never raw.
	for _, r := range batch.CodeintelSummaries {
		if r.ProjectHash == "" {
			t.Error("CodeintelSummaryRow.ProjectHash is empty — the project must ship as a hash")
		}
		if r.ProjectHash == secProject {
			t.Error("CodeintelSummaryRow.ProjectHash is the RAW project path — it must be hashed")
		}
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	// Content-free even when shipped: no raw path, no symbol name.
	if bytes.Contains(raw, []byte(secProject)) {
		t.Error("raw project path leaked into the codeintel aggregate — it must ship only as a hash")
	}
	if bytes.Contains(raw, []byte(secSymbol)) {
		t.Error("symbol name leaked into the codeintel aggregate — only structure counts may ship")
	}
}

// TestPushPayloadStripsCodeintelWhenNotOptedIn is the other side of the tier:
// with codeintel_detail OFF, the aggregate must NOT ship — not even under
// full_content (maximum path/content disclosure). codeintel_detail is a DISTINCT
// tier, orthogonal to shipsRawContent(), and raised only by the DISTINCT
// extract.codeintel authority on a managed node.
func TestPushPayloadStripsCodeintelWhenNotOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const (
		secProject = "SENTINEL_CODEINTEL_PROJECT_pangram_zz"
		secSymbol  = "SENTINEL_CODEINTEL_SYMBOL_pangram_zz"
	)
	seedCodeintel(ctx, t, database, secProject, secSymbol)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"zero-value", store.ShareOptions{}},
		{"full_content-only", store.ShareOptions{FullContent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.CodeintelSummaries) != 0 {
				t.Errorf("codeintel aggregate shipped under %s (codeintel_detail OFF) — the tier must be orthogonal and opt-in", tc.name)
			}
			if tc.share.FullContent {
				// Enterprise (org-parity W2.4): full_content legitimately
				// ships the per-dev codeintel wire, which carries the RAW
				// project root (operator ruling 2026-08-24) — scope the
				// leak scan past it. Symbol names still NEVER cross on any
				// wire, so secSymbol stays in the unscoped scan below.
				if len(batch.CodeintelDevRows) == 0 {
					t.Error("full_content shipped no codeintel dev rows — the W2.4 enterprise wire failed to flip")
				}
				batch.CodeintelDevRows = nil
			} else if len(batch.CodeintelDevRows) != 0 {
				t.Errorf("codeintel dev rows shipped under %s (metadata-only) — must ride shipsRawContent only", tc.name)
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			if bytes.Contains(raw, []byte(secProject)) || bytes.Contains(raw, []byte(secSymbol)) {
				t.Errorf("codeintel identity leaked under %s without codeintel_detail", tc.name)
			}
		})
	}
}

// seedProcessRun inserts one process_runs row whose exe_path and argv are
// sentinels, so a SelectUnpushedSince batch can be searched both for whether the
// P5g process-detail aggregate shipped AND for whether any raw process identity
// leaked. process_* stays NODE-LOCAL; only the content-free per (day × tool)
// run/exit count aggregate crosses, and only under process_detail — the exe
// path and argv are never shipped.
func seedProcessRun(ctx context.Context, t *testing.T, database *sql.DB, tool, exePath, argv string) {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO process_runs
		   (process_key, pid, attribution_source, attribution_confidence, tool,
		    exe_path, argv_preview, started_at, last_seen_at, exited_at, exit_code, duration_ms)
		 VALUES (?, 4242, 'pidbridge', 'high', ?, ?, ?, ?, ?, ?, 0, 1500)`,
		"pk-"+exePath, tool, exePath, argv, ts, ts, ts); err != nil {
		t.Fatalf("seed process_runs: %v", err)
	}
}

// TestPushPayloadCarriesProcessWhenOptedIn is the Arc 4 P5g extraction tier:
// under the DISTINCT process_detail opt-in, the node-local process_runs log
// ships as a content-free per (day × tool) run/exit count aggregate. Two
// properties are proven together: (1) the tier FLIPS the seam (ProcessSummaries
// is non-empty); and (2) even when it ships, NO raw process identity crosses —
// neither the exe path nor the argv appears in the marshalled batch. The
// process_* table NAMES still never appear in orgpush.go (SelectProcessSummaries
// owns the read in a separate file — TestSelectUnpushedSinceExcludesCacheTables
// guards that).
func TestPushPayloadCarriesProcessWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const (
		secExe  = "SENTINEL_PROCESS_EXE_pangram_zz"
		secArgv = "SENTINEL_PROCESS_ARGV_pangram_zz"
	)
	seedProcessRun(ctx, t, database, "claude-code", secExe, secArgv)

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{ProcessDetail: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.ProcessSummaries) == 0 {
		t.Fatal("process_detail opt-in shipped no ProcessSummaries — the tier failed to flip the seam")
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	// Content-free even when shipped: no exe path, no argv.
	if bytes.Contains(raw, []byte(secExe)) {
		t.Error("exe path leaked into the process aggregate — only run/exit counts may ship")
	}
	if bytes.Contains(raw, []byte(secArgv)) {
		t.Error("argv leaked into the process aggregate — only run/exit counts may ship")
	}
}

// TestPushPayloadStripsProcessWhenNotOptedIn is the other side of the tier: with
// process_detail OFF, the aggregate must NOT ship — not even under full_content
// (maximum disclosure). process_detail is a DISTINCT tier, orthogonal to
// shipsRawContent(), and raised only by the DISTINCT extract.process authority
// on a managed node.
func TestPushPayloadStripsProcessWhenNotOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const (
		secExe  = "SENTINEL_PROCESS_EXE_pangram_zz"
		secArgv = "SENTINEL_PROCESS_ARGV_pangram_zz"
	)
	seedProcessRun(ctx, t, database, "claude-code", secExe, secArgv)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"zero-value", store.ShareOptions{}},
		{"full_content-only", store.ShareOptions{FullContent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.ProcessSummaries) != 0 {
				t.Errorf("process aggregate shipped under %s (process_detail OFF) — the tier must be orthogonal and opt-in", tc.name)
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			if bytes.Contains(raw, []byte(secExe)) || bytes.Contains(raw, []byte(secArgv)) {
				t.Errorf("process identity leaked under %s without process_detail", tc.name)
			}
		})
	}
}

// TestSessionProcessWireCarriesMetricsMessageIDAndCapsSamples is the W-A wire
// property (org session-detail parity): under shipsRawContent() the
// session-scoped process row carries the NON-CONTENT process metadata
// working_set_bytes / thread_count / message_id (resolved from the correlated
// action) / metric_samples_json alongside the rest of the raw row; a run that
// never captured them ships zero/empty (an honest absence, never a phantom
// zero); and the high-volume samples ring is capped so it can never dominate
// the envelope. process_runs stays NODE-LOCAL (its table name never appears in
// orgpush.go — pinned by TestSelectUnpushedSinceExcludesCacheTables); these are
// numeric counters / an opaque id, no new content surface.
func TestSessionProcessWireCarriesMetricsMessageIDAndCapsSamples(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st) // creates session sess-cc-1 + its project

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`SELECT project_id FROM sessions WHERE id = 'sess-cc-1'`).Scan(&projectID); err != nil {
		t.Fatalf("resolve project id: %v", err)
	}

	ts := time.Now().UTC().Format(time.RFC3339)

	// An action carrying a message id, correlated to the metric-bearing run by
	// action_id (process_runs has no message_id column; the wire resolves it
	// through actions.message_id).
	res, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, tool, action_type, message_id, success, source_file, source_event_id)
		 VALUES ('sess-cc-1', ?, ?, 'claude-code', 'run_command', 'msg_proc_1', 1, 'p.jsonl', 'proc-ev-1')`,
		projectID, ts)
	if err != nil {
		t.Fatalf("insert correlated action: %v", err)
	}
	actionID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}

	// A 90-sample ring (over the 60-sample cap) so the wire cap is exercised.
	var ring strings.Builder
	ring.WriteByte('[')
	for i := 0; i < 90; i++ {
		if i > 0 {
			ring.WriteByte(',')
		}
		ring.WriteString(`{"t":"2026-08-24T10:00:00Z","cpu_ms":`)
		ring.WriteString(strconv.Itoa(i))
		ring.WriteString(`,"ws":`)
		ring.WriteString(strconv.Itoa(i * 1024))
		ring.WriteByte('}')
	}
	ring.WriteByte(']')

	// A run WITH the metrics + correlated action.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO process_runs
		   (process_key, pid, session_id, action_id, attribution_source, attribution_confidence, tool,
		    exe_path, argv_preview, started_at, last_seen_at,
		    working_set_bytes, thread_count, metric_samples_json)
		 VALUES ('pk-metrics', 700, 'sess-cc-1', ?, 'bridge', 'high', 'claude-code',
		         '/usr/bin/node', 'node x.js', ?, ?, ?, ?, ?)`,
		actionID, ts, ts, 6<<20, 15, ring.String()); err != nil {
		t.Fatalf("insert metric-bearing process_run: %v", err)
	}

	// A run WITHOUT the metrics (older / non-Windows capture) → zero/empty.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO process_runs
		   (process_key, pid, session_id, attribution_source, attribution_confidence, tool,
		    exe_path, argv_preview, started_at, last_seen_at)
		 VALUES ('pk-bare', 701, 'sess-cc-1', 'bridge', 'high', 'claude-code',
		         '/usr/bin/git', 'git status', ?, ?)`,
		ts, ts); err != nil {
		t.Fatalf("insert bare process_run: %v", err)
	}

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{AdminManaged: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}

	var withMetrics, bare *orgcontract.SessionProcessRow
	for i := range batch.SessionProcesses {
		switch batch.SessionProcesses[i].RunKey {
		case "pk-metrics":
			withMetrics = &batch.SessionProcesses[i]
		case "pk-bare":
			bare = &batch.SessionProcesses[i]
		}
	}
	if withMetrics == nil || bare == nil {
		t.Fatalf("expected both process rows on the wire, got %+v", batch.SessionProcesses)
	}

	if withMetrics.WorkingSetBytes != 6<<20 {
		t.Errorf("WorkingSetBytes = %d, want %d", withMetrics.WorkingSetBytes, 6<<20)
	}
	if withMetrics.ThreadCount != 15 {
		t.Errorf("ThreadCount = %d, want 15", withMetrics.ThreadCount)
	}
	if withMetrics.MessageID != "msg_proc_1" {
		t.Errorf("MessageID = %q, want msg_proc_1 (resolved from the correlated action)", withMetrics.MessageID)
	}

	// The samples ring is present but capped: at most 60 samples, within the
	// byte ceiling.
	var kept []map[string]any
	if err := json.Unmarshal([]byte(withMetrics.MetricSamplesJSON), &kept); err != nil {
		t.Fatalf("metric_samples_json not a valid JSON array: %v (%q)", err, withMetrics.MetricSamplesJSON)
	}
	if len(kept) > 60 {
		t.Errorf("metric samples not capped: %d on the wire, want <= 60", len(kept))
	}
	if len(withMetrics.MetricSamplesJSON) > 8<<10 {
		t.Errorf("metric_samples_json = %d bytes, exceeds the 8 KiB wire ceiling", len(withMetrics.MetricSamplesJSON))
	}

	// The bare run carries honest zeros/empties, never a phantom value.
	if bare.WorkingSetBytes != 0 || bare.ThreadCount != 0 || bare.MessageID != "" || bare.MetricSamplesJSON != "" {
		t.Errorf("bare run carries phantom metrics: %+v", bare)
	}
}

// TestSessionSurfaceAndSidechainTokensShipAsMetadata is the W1 wire property
// (node session-detail trickle-up, server migration 139) and the deliberate
// REVERSAL of the migration-107 posture: sessions.surface / surface_host and
// token_usage.is_sidechain used to be pinned OUT of the push seam in every
// share mode, and now ship UNCONDITIONALLY — including in the zero-value,
// metadata-only posture that is every node's default.
//
// They are METADATA, not content: surface is a closed vocabulary
// (models.KnownSurface — cli | ide | desktop | sdk | web) the node's
// SetSessionSurface refuses to write outside of, surface_host is a bounded
// host token, and is_sidechain is a bool over a row that already ships (the
// exact disclosure class as ActionRow.IsSidechain, on the wire since the
// baseline). None can carry a path, a prompt or a branch name, so none is
// gated by shipsRawContent() and none gets a [org_client.share] key.
//
// The second half is the honesty half, and the reason this is an invariant
// rather than a unit test: a session the node never stamped (a pre-107 agent,
// or a transcript never re-scanned) must reach the org as EMPTY. The wire may
// never manufacture a default — "cli" is a real answer, not a fallback.
//
// Also covers sessions.tool_version (server migration 161 / pg 0027), which
// this change reclassified the same way: a bounded, non-prose,
// vendor-authored token that now ships unconditionally, honest-empty when
// unstamped.
func TestSessionSurfaceAndSidechainTokensShipAsMetadata(t *testing.T) {
	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		// The zero value IS the default metadata-only posture; the gated
		// postures must not change the answer, which is what "not gated" means.
		{"metadata_only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st) // sess-cc-1, sess-cur-1, sess-cdx-1 + their token rows

			// Exactly ONE session is stamped; the others stay unstamped so the
			// honest-absence half of the assertion is non-vacuous. Written
			// directly rather than through SetSessionSurface so the probe reads
			// the COLUMN, not the store's vocabulary check. parent_thread_id
			// points at a real seeded session id ('sess-cur-1'), the same
			// opaque-vendor-pointer shape production writes via
			// Store.SetSessionLineage.
			if _, err := database.ExecContext(ctx,
				`UPDATE sessions SET surface = 'ide', surface_host = 'vscode', tool_version = '1.2.3', tool_version_last = '1.3.0', parent_thread_id = 'sess-cur-1',
				        execution_location = 'vendor_cloud', vendor_session_ref = 'cse_01privacy' WHERE id = 'sess-cc-1'`); err != nil {
				t.Fatalf("stamp surface + tool_version + parent_thread_id: %v", err)
			}
			// Likewise exactly ONE usage row is a sub-agent row.
			if _, err := database.ExecContext(ctx,
				`UPDATE token_usage SET is_sidechain = 1, turn_id = 'turn-canary-3mode', gen_ms = 20000, gen_basis = 'native' WHERE source_event_id = 'cc-tok-1'`); err != nil {
				t.Fatalf("stamp is_sidechain + turn_id + gen_ms/gen_basis: %v", err)
			}

			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
				tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}

			var stamped, unstamped *orgcontract.SessionRow
			for i := range batch.Sessions {
				switch batch.Sessions[i].ID {
				case "sess-cc-1":
					stamped = &batch.Sessions[i]
				case "sess-cur-1":
					unstamped = &batch.Sessions[i]
				}
			}
			if stamped == nil || unstamped == nil {
				t.Fatalf("expected both sessions on the wire, got %+v", batch.Sessions)
			}
			if stamped.Surface != "ide" || stamped.SurfaceHost != "vscode" {
				t.Errorf("stamped session surface = %q/%q, want ide/vscode — W1 ships capture surface in every posture",
					stamped.Surface, stamped.SurfaceHost)
			}
			if unstamped.Surface != "" || unstamped.SurfaceHost != "" {
				t.Errorf("unstamped session carries a phantom surface %q/%q; an unknown surface must reach the org EMPTY, never defaulted to cli",
					unstamped.Surface, unstamped.SurfaceHost)
			}
			// token_usage.turn_id (server migration 160 / pg 0026): the same
			// unconditional-metadata posture in all three share modes (the
			// sentinel review of 2026-09-22 asked for this to match the
			// tool_version canary's rigor).
			var turnStamped, turnUnstamped int
			for _, tu := range batch.TokenUsage {
				switch {
				case tu.SourceEventID == "cc-tok-1" && tu.TurnID == "turn-canary-3mode":
					turnStamped++
				case tu.SourceEventID != "cc-tok-1" && tu.TurnID != "":
					turnUnstamped++
				}
			}
			if turnStamped != 1 {
				t.Errorf("stamped token row turn_id not on the wire in mode %s (found %d)", tc.name, turnStamped)
			}
			if turnUnstamped != 0 {
				t.Errorf("%d unstamped token rows carry a phantom turn_id in mode %s", turnUnstamped, tc.name)
			}
			// token_usage.gen_ms / gen_basis (server migration 174 / pg
			// 0040): the same unconditional-metadata posture in all three
			// share modes, mirroring the turn_id canary immediately above.
			var genStamped, genUnstamped int
			for _, tu := range batch.TokenUsage {
				switch {
				case tu.SourceEventID == "cc-tok-1" && tu.GenMs == 20000 && tu.GenBasis == "native":
					genStamped++
				case tu.SourceEventID != "cc-tok-1" && (tu.GenMs != 0 || tu.GenBasis != ""):
					genUnstamped++
				}
			}
			if genStamped != 1 {
				t.Errorf("stamped token row gen_ms/gen_basis not on the wire in mode %s (found %d)", tc.name, genStamped)
			}
			if genUnstamped != 0 {
				t.Errorf("%d unstamped token rows carry a phantom gen_ms/gen_basis in mode %s", genUnstamped, tc.name)
			}
			// Tool-version trickle-up (server migration 161 / pg 0027): the
			// same unconditional-metadata / honest-absence pair, in the same
			// three share modes.
			if stamped.ToolVersion != "1.2.3" {
				t.Errorf("stamped session tool_version = %q, want 1.2.3 — this change ships it in every posture", stamped.ToolVersion)
			}
			if unstamped.ToolVersion != "" {
				t.Errorf("unstamped session carries a phantom tool_version %q; unknown must reach the org EMPTY, never a fabricated guess", unstamped.ToolVersion)
			}
			// tool_version_last (agent 162 / server 232): same posture.
			if stamped.ToolVersionLast != "1.3.0" {
				t.Errorf("stamped session tool_version_last = %q, want 1.3.0 in every posture", stamped.ToolVersionLast)
			}
			if unstamped.ToolVersionLast != "" {
				t.Errorf("unstamped session carries a phantom tool_version_last %q", unstamped.ToolVersionLast)
			}
			// parent_thread_id trickle-up (server migration 162 / pg 0028): the
			// same unconditional-metadata / honest-absence pair, in the same
			// three share modes — the tool-account-parity fix (LINEAGE-1).
			if stamped.ParentThreadID != "sess-cur-1" {
				t.Errorf("stamped session parent_thread_id = %q, want sess-cur-1 — this change ships it in every posture", stamped.ParentThreadID)
			}
			if unstamped.ParentThreadID != "" {
				t.Errorf("unstamped session carries a phantom parent_thread_id %q; a session with no parent must reach the org EMPTY, never a fabricated guess", unstamped.ParentThreadID)
			}
			// Cloud-agents arc (agent 240 / server 300 / pg 0170): the same
			// unconditional-metadata / honest-absence pair. An unstamped
			// session must reach the org as UNKNOWN, never a defaulted "local".
			if stamped.ExecutionLocation != "vendor_cloud" || stamped.VendorSessionRef != "cse_01privacy" {
				t.Errorf("stamped session (execution_location, vendor_session_ref) = (%q, %q), want (vendor_cloud, cse_01privacy) in every posture",
					stamped.ExecutionLocation, stamped.VendorSessionRef)
			}
			if unstamped.ExecutionLocation != "" || unstamped.VendorSessionRef != "" {
				t.Errorf("unstamped session carries a phantom (execution_location, vendor_session_ref) = (%q, %q)",
					unstamped.ExecutionLocation, unstamped.VendorSessionRef)
			}

			var sidechain, ordinary *orgcontract.TokenUsageRow
			for i := range batch.TokenUsage {
				switch batch.TokenUsage[i].SourceEventID {
				case "cc-tok-1":
					sidechain = &batch.TokenUsage[i]
				case "cur-tok-1":
					ordinary = &batch.TokenUsage[i]
				}
			}
			if sidechain == nil || ordinary == nil {
				t.Fatalf("expected both token_usage rows on the wire, got %+v", batch.TokenUsage)
			}
			if !sidechain.IsSidechain {
				t.Errorf("sub-agent usage row shipped IsSidechain=false; W1 carries the flag unconditionally, like actions.is_sidechain")
			}
			if ordinary.IsSidechain {
				t.Errorf("main-thread usage row shipped IsSidechain=true; the flag must reflect the node column, not a default")
			}
		})
	}
}

// TestSessionSurfaceHostClosedVocabulary is the PRIV-2 pin (codebase audit
// 2026-09-16). sessions.surface_host ships in EVERY posture, including the
// metadata-only teams default, on the stated grounds that it is "a bounded host
// token" which "can never carry a path, a prompt or a branch name". Nothing
// enforced that: the store's own writer documents surface_host as free-form
// (unlike `surface`, which it refuses outside models.KnownSurface), so an
// adapter resolving a host from a directory name or a vendor suffix could put
// an arbitrary string on an ungated wire.
//
// The seam now applies a closed vocabulary. Three behaviors, one per row:
// a KNOWN token crosses verbatim (the org still gets its product attribution);
// an UNKNOWN one coarsens to "other" (never verbatim, whatever it holds — a
// path, a branch name, a prompt fragment); and EMPTY stays empty, because an
// unstamped session must reach the org as unknown and "other" would claim a
// stamp that was never made.
//
// Written with direct SQL, bypassing Store.SetSessionSurface, precisely because
// the threat is a value that reached the column some other way.
func TestSessionSurfaceHostClosedVocabulary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stored string
		want   string
	}{
		{"known vscode token", "vscode", "vscode"},
		{"known jetbrains product", "jetbrains-goland", "jetbrains-goland"},
		{"known desktop token", "claude-desktop", "claude-desktop"},
		// MCP audit #4c: Claude Code print mode (entrypoint "sdk-cli")
		// stamps host "cli"; it must reach the org as "cli", not "other".
		{"claude code print-mode sdk host", "cli", "cli"},
		{"claude code sdk language host", "ts", "ts"},
		{"unstamped stays unstamped", "", ""},
		{"unknown vendor token coarsens", "some-new-editor-2027", "other"},
		{"a path never crosses verbatim", "/home/dev/clients/acme-migration", "other"},
		{"a branch name never crosses verbatim", "feature/PROJ-1421-acme", "other"},
		{"prose never crosses verbatim", "rewrite the acme billing module", "other"},
		{"case variant is not the token", "VSCode", "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st)

			if _, err := database.ExecContext(ctx,
				`UPDATE sessions SET surface = 'ide', surface_host = ? WHERE id = 'sess-cc-1'`, tc.stored); err != nil {
				t.Fatalf("stamp surface_host: %v", err)
			}

			// Metadata-only — the posture the gate exists for. A gated value
			// must not reappear under a wider posture either, so the widest
			// one is checked in the same breath below.
			for _, share := range []store.ShareOptions{{}, {FullContent: true}, {AdminManaged: true}} {
				batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
					share, store.ScopeOptions{})
				if err != nil {
					t.Fatalf("SelectUnpushedSince: %v", err)
				}
				var got *orgcontract.SessionRow
				for i := range batch.Sessions {
					if batch.Sessions[i].ID == "sess-cc-1" {
						got = &batch.Sessions[i]
					}
				}
				if got == nil {
					t.Fatalf("sess-cc-1 missing from the wire, got %+v", batch.Sessions)
				}
				if got.SurfaceHost != tc.want {
					t.Errorf("surface_host on the wire = %q, want %q (stored %q, share %+v)",
						got.SurfaceHost, tc.want, tc.stored, share)
				}
				// Byte-level: an out-of-vocabulary value must not survive
				// anywhere in the serialized batch.
				if tc.want == "other" {
					raw, err := json.Marshal(batch)
					if err != nil {
						t.Fatalf("marshal batch: %v", err)
					}
					if bytes.Contains(raw, []byte(tc.stored)) {
						t.Errorf("out-of-vocabulary surface_host %q survived into the batch bytes under %+v", tc.stored, share)
					}
				}
			}
		})
	}
}

// TestOwnAgentNameShipsHashedUnlessRawContent pins the own-agent name on the
// org wire (P-228, design docs/plans/discovery-sdk-2026-11-03.md section 4.5,
// orchestrator call "hashed unless shipsRawContent()"). The name is not a new
// wire column: it rides sessions.surface_host as "agent:<name>", which ships
// in every posture, so this is its sentinel. A developer-chosen name can
// encode a client or a project: in the metadata-only posture the batch bytes
// must not contain it at all, and the hashed token must still group one
// agent's sessions; under each shipsRawContent() disjunct it ships raw.
//
// The row is stamped with direct SQL, like the closed-vocabulary pin above,
// because the threat is a value that reached the column some other way.
func TestOwnAgentNameShipsHashedUnlessRawContent(t *testing.T) {
	const secretAgent = "acme-billing-migration-bot"
	stored := ownagent.SurfaceHost(secretAgent)
	hashed, _ := ownagent.WireSurfaceHost(stored, false)
	for _, tc := range []struct {
		name  string
		share store.ShareOptions
		want  string
		raw   bool
	}{
		{"metadata-only ships the hash", store.ShareOptions{}, hashed, false},
		{"full_content ships the name", store.ShareOptions{FullContent: true}, stored, true},
		{"admin_managed ships the name", store.ShareOptions{AdminManaged: true}, stored, true},
		{"enterprise grant ships the name", store.ShareOptions{EnterpriseGranted: true}, stored, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st)
			if _, err := database.ExecContext(ctx,
				`UPDATE sessions SET tool = 'custom-agent', surface = 'sdk', surface_host = ? WHERE id = 'sess-cc-1'`, stored); err != nil {
				t.Fatalf("stamp surface_host: %v", err)
			}
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
				tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			var got *orgcontract.SessionRow
			for i := range batch.Sessions {
				if batch.Sessions[i].ID == "sess-cc-1" {
					got = &batch.Sessions[i]
				}
			}
			if got == nil {
				t.Fatalf("sess-cc-1 missing from the wire, got %+v", batch.Sessions)
			}
			if got.SurfaceHost != tc.want {
				t.Errorf("surface_host on the wire = %q, want %q", got.SurfaceHost, tc.want)
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			if leaked := bytes.Contains(raw, []byte(secretAgent)); leaked != tc.raw {
				t.Errorf("agent name in the batch bytes = %v, want %v under %+v", leaked, tc.raw, tc.share)
			}
		})
	}
}

// seedSessionTasks writes one checklist item and one status transition for
// sess-cc-1 whose PROSE columns are sentinels but whose STATUS columns are the
// real closed vocabulary, so one SelectUnpushedSince batch can be searched both
// for whether the W2 task wire shipped AND for whether any plan text leaked.
//
// Written with direct SQL rather than through Store.applyTaskEvents so the
// fixture does not depend on the taskflow decoder's per-tool vocabulary — the
// wire Select reads these columns whatever wrote them.
func seedSessionTasks(ctx context.Context, t *testing.T, database *sql.DB, content, activeForm, owner string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO task_items
		   (session_id, tool, key, key_kind, content, active_form, owner,
		    raw_status, status, order_index, first_seen_at, last_seen_at, unmatched)
		 VALUES ('sess-cc-1', 'claude-code', 'task-1', 'native_id', ?, ?, ?,
		         'in_progress', 'in_progress', 0, ?, ?, 0)`,
		content, activeForm, owner, now, now); err != nil {
		t.Fatalf("seed task_items: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO task_transitions
		   (session_id, key, from_status, to_status, ts, action_id, source_event_id)
		 VALUES ('sess-cc-1', 'task-1', 'pending', 'in_progress', ?, 7, 'evt-task-1')`,
		now); err != nil {
		t.Fatalf("seed task_transitions: %v", err)
	}
}

// TestSessionTasksShipOnlyUnderTaskDetail is the W2 wire-surface pin, and the
// replacement for the blanket task_items/task_transitions entry this file's
// forbiddenCacheTables used to carry (agent migration 109 pinned them
// node-local "for this first slice"; docs/plans/
// node-session-detail-trickle-up-to-org-plan-2026-09-10.md §2 W2 is the
// reviewed reversal). It is STRICTLY STRONGER than the absence assertion it
// replaces, because it pins the GATE in all three postures rather than the
// silence in one:
//
//	(a) the ZERO-VALUE ShareOptions ships NOTHING — no item, no transition, and
//	    no sentinel anywhere in the marshalled batch. full_content ALONE does
//	    not unlock the tier either: task_detail is orthogonal, exactly like
//	    cache_detail.
//	(b) task_detail ALONE ships the STATUS half — status, the vendor raw_status
//	    spelling, key/key_kind, order/seen times and the transitions — while
//	    every PROSE sentinel (content / active_form / owner) is STRIPPED. This
//	    is the two-level tier: an org can render "in progress, 1 of N" without
//	    ever learning what the work was.
//	(c) task_detail + full_content, and task_detail + admin_managed, BOTH carry
//	    the prose. Two rows rather than one because shipsRawContent() is a
//	    three-way disjunction and a regression that dropped one of its terms
//	    would otherwise pass.
func TestSessionTasksShipOnlyUnderTaskDetail(t *testing.T) {
	const (
		secTaskContent    = "SENTINEL_TASK_PROSE_pangram_aa"
		secTaskActiveForm = "SENTINEL_TASK_ACTIVEFORM_pangram_bb"
		secTaskOwner      = "SENTINEL_TASK_OWNER_pangram_cc"
	)
	for _, tc := range []struct {
		name        string
		share       store.ShareOptions
		wantRows    bool
		wantContent bool
	}{
		{"zero-value", store.ShareOptions{}, false, false},
		{"full_content-only", store.ShareOptions{FullContent: true}, false, false},
		{"task_detail", store.ShareOptions{TaskDetail: true}, true, false},
		{"task_detail+full_content", store.ShareOptions{TaskDetail: true, FullContent: true}, true, true},
		{"task_detail+admin_managed", store.ShareOptions{TaskDetail: true, AdminManaged: true}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st)
			seedSessionTasks(ctx, t, database, secTaskContent, secTaskActiveForm, secTaskOwner)

			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
				tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}

			if !tc.wantRows {
				if len(batch.SessionTaskItems) != 0 || len(batch.SessionTaskTransitions) != 0 {
					t.Errorf("task wire shipped %d items / %d transitions under %s — task_detail is OFF, so the checklist must not cross at all",
						len(batch.SessionTaskItems), len(batch.SessionTaskTransitions), tc.name)
				}
			} else {
				if len(batch.SessionTaskItems) == 0 {
					t.Fatalf("task_detail shipped no items under %s — the W2 tier failed to flip", tc.name)
				}
				if len(batch.SessionTaskTransitions) == 0 {
					t.Errorf("task_detail shipped no transitions under %s — the status-change log rides the same tier as the items", tc.name)
				}
				item := batch.SessionTaskItems[0]
				if item.SessionID != "sess-cc-1" || item.Key != "task-1" || item.KeyKind != "native_id" {
					t.Errorf("item identity = %q/%q/%q, want sess-cc-1/task-1/native_id", item.SessionID, item.Key, item.KeyKind)
				}
				if item.Status != "in_progress" || item.RawStatus != "in_progress" {
					t.Errorf("status/raw_status = %q/%q, want in_progress/in_progress — the STATUS half ships under task_detail alone",
						item.Status, item.RawStatus)
				}
				if item.Tool != "claude-code" || item.FirstSeenAt == "" || item.LastSeenAt == "" {
					t.Errorf("metadata half incomplete: tool=%q first=%q last=%q", item.Tool, item.FirstSeenAt, item.LastSeenAt)
				}
				tr := batch.SessionTaskTransitions[0]
				if tr.FromStatus != "pending" || tr.ToStatus != "in_progress" || tr.ActionID != 7 || tr.SourceEventID != "evt-task-1" {
					t.Errorf("transition = %q->%q action=%d src=%q, want pending->in_progress action=7 src=evt-task-1",
						tr.FromStatus, tr.ToStatus, tr.ActionID, tr.SourceEventID)
				}

				gotContent := item.Content != "" || item.ActiveForm != "" || item.Owner != ""
				if gotContent != tc.wantContent {
					t.Errorf("prose present = %v, want %v under %s (content=%q active_form=%q owner=%q) — "+
						"the plan text is a SECOND gate on top of task_detail: it ships only under shipsRawContent()",
						gotContent, tc.wantContent, tc.name, item.Content, item.ActiveForm, item.Owner)
				}
				if tc.wantContent {
					if item.Content != secTaskContent || item.ActiveForm != secTaskActiveForm || item.Owner != secTaskOwner {
						t.Errorf("prose under %s = %q/%q/%q, want the seeded sentinels verbatim",
							tc.name, item.Content, item.ActiveForm, item.Owner)
					}
				}
			}

			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			for _, sentinel := range []string{secTaskContent, secTaskActiveForm, secTaskOwner} {
				leaked := bytes.Contains(raw, []byte(sentinel))
				if leaked != tc.wantContent {
					t.Errorf("sentinel %q present in the marshalled batch = %v, want %v under %s",
						sentinel, leaked, tc.wantContent, tc.name)
				}
			}
		})
	}
}

// seedSessionToolAccounts writes two login observations for sess-cc-1: one
// whose IDENTITY columns are sentinels, and a SECOND with a different
// account_key for the same binding, so the fixture also exercises the
// conflict-retention shape (the node keeps both; the wire must too).
func seedSessionToolAccounts(ctx context.Context, t *testing.T, database *sql.DB, email, name, accountID string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rows := []struct {
		accountKey string
		source     string
	}{
		{"acct-key-primary", "hook"},
		{"acct-key-other", "transcript"},
	}
	for _, r := range rows {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO tool_account_observations
			   (session_id, tool, binding_kind, binding_id, role, account_key,
			    email, name, account_id, source, scope, stage, observed_at)
			 VALUES ('sess-cc-1', 'claude-code', 'message', 'msg-1', 'assistant', ?,
			         ?, ?, ?, ?, 'session', 'start', ?)`,
			r.accountKey, email, name, accountID, r.source, now); err != nil {
			t.Fatalf("seed tool_account_observations: %v", err)
		}
	}
}

// TestSessionToolAccountsShipOnlyUnderToolAccountDetail is the W3 wire-surface
// pin, replacing this file's former blanket tool_account_observations entry
// (agent migration 111: "Never copied by org push or foreign import"). Same
// three-posture shape as its W2 sibling, and the second gate here is the arc's
// one genuine developer-PII boundary (operator decision D2):
//
//	(a) zero-value ships nothing, and full_content ALONE does not unlock the
//	    tier — tool_account_detail is orthogonal.
//	(b) tool_account_detail ALONE ships the BINDING half: binding_kind /
//	    binding_id / role / source / scope / stage, the OPAQUE account_key and
//	    observed_at. That is enough to render "account changed / conflict /
//	    unknown" and count distinct accounts — while email / name / account_id
//	    are STRIPPED, so no developer is named.
//	(c) with full_content, and separately with admin_managed, the raw identity
//	    crosses.
//
// It additionally pins CONFLICT RETENTION: both differing observations for the
// same binding ship, because a surface that saw only one could not honestly say
// "conflict".
func TestSessionToolAccountsShipOnlyUnderToolAccountDetail(t *testing.T) {
	const (
		secAcctEmail = "SENTINEL_ACCOUNT_EMAIL_pangram_dd@example.invalid"
		secAcctName  = "SENTINEL_ACCOUNT_NAME_pangram_ee"
		secAcctID    = "SENTINEL_ACCOUNT_ID_pangram_ff"
	)
	for _, tc := range []struct {
		name        string
		share       store.ShareOptions
		wantRows    bool
		wantContent bool
	}{
		{"zero-value", store.ShareOptions{}, false, false},
		{"full_content-only", store.ShareOptions{FullContent: true}, false, false},
		{"tool_account_detail", store.ShareOptions{ToolAccountDetail: true}, true, false},
		{"tool_account_detail+full_content", store.ShareOptions{ToolAccountDetail: true, FullContent: true}, true, true},
		{"tool_account_detail+admin_managed", store.ShareOptions{ToolAccountDetail: true, AdminManaged: true}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st)
			seedSessionToolAccounts(ctx, t, database, secAcctEmail, secAcctName, secAcctID)

			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
				tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}

			if !tc.wantRows {
				if len(batch.SessionToolAccounts) != 0 {
					t.Errorf("tool-account wire shipped %d rows under %s — tool_account_detail is OFF, so login evidence must not cross at all",
						len(batch.SessionToolAccounts), tc.name)
				}
			} else {
				if len(batch.SessionToolAccounts) != 2 {
					t.Fatalf("tool_account_detail shipped %d rows under %s, want 2 — a CONFLICTING observation must ride along, never be resolved away",
						len(batch.SessionToolAccounts), tc.name)
				}
				keys := map[string]bool{}
				for _, r := range batch.SessionToolAccounts {
					keys[r.AccountKey] = true
					if r.SessionID != "sess-cc-1" || r.BindingKind != "message" || r.BindingID != "msg-1" || r.Role != "assistant" {
						t.Errorf("binding half = %q/%q/%q/%q, want sess-cc-1/message/msg-1/assistant",
							r.SessionID, r.BindingKind, r.BindingID, r.Role)
					}
					if r.Scope != "session" || r.Stage != "start" || r.ObservedAt == "" || r.Tool != "claude-code" {
						t.Errorf("provenance half incomplete: tool=%q scope=%q stage=%q observed_at=%q",
							r.Tool, r.Scope, r.Stage, r.ObservedAt)
					}
					gotContent := r.Email != "" || r.Name != "" || r.AccountID != ""
					if gotContent != tc.wantContent {
						t.Errorf("identity present = %v, want %v under %s (email=%q name=%q account_id=%q) — "+
							"the raw vendor identity is a SECOND gate on top of tool_account_detail (decision D2)",
							gotContent, tc.wantContent, tc.name, r.Email, r.Name, r.AccountID)
					}
					if tc.wantContent && (r.Email != secAcctEmail || r.Name != secAcctName || r.AccountID != secAcctID) {
						t.Errorf("identity under %s = %q/%q/%q, want the seeded sentinels verbatim",
							tc.name, r.Email, r.Name, r.AccountID)
					}
				}
				if !keys["acct-key-primary"] || !keys["acct-key-other"] {
					t.Errorf("account keys shipped = %v, want BOTH observed keys — the opaque key is what makes "+
						"\"same account or not\" answerable without the e-mail", keys)
				}
			}

			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			for _, sentinel := range []string{secAcctEmail, secAcctName, secAcctID} {
				leaked := bytes.Contains(raw, []byte(sentinel))
				if leaked != tc.wantContent {
					t.Errorf("sentinel %q present in the marshalled batch = %v, want %v under %s",
						sentinel, leaked, tc.wantContent, tc.name)
				}
			}
		})
	}
}

// TestSessionHookActivityShipOnlyUnderHookActivity is the DEC-5 wire-surface
// pin for the per-session hook liveness wire (surface-gap review OBS-7, lane
// w5-wire). hook_activity STAYS in forbiddenCacheTables: that sentinel is the
// source-level rule that orgpush.go never names the table (the read lives in
// internal/store/hookactivitysummary.go, the cache_events arrangement). What
// this test pins is the DATA posture:
//
//	(a) the zero value ships nothing, and full_content ALONE does not unlock
//	    the tier: hook_activity is its own consent;
//	(b) hook_activity ALONE ships the count half (session, tool, event,
//	    count, first and last time, the coarse env classes) and DROPS the
//	    CLAUDE_CONFIG_DIR path hash;
//	(c) with full_content, admin_managed, or the org-signed enterprise
//	    content grant, the hash crosses too.
func TestSessionHookActivityShipOnlyUnderHookActivity(t *testing.T) {
	hash := hookliveness.PathHashClass("/home/dev/SENTINEL_CONFIG_DIR_pangram_gg")
	for _, tc := range []struct {
		name     string
		share    store.ShareOptions
		wantRows bool
		wantHash bool
	}{
		{"zero-value", store.ShareOptions{}, false, false},
		{"full_content-only", store.ShareOptions{FullContent: true}, false, false},
		{"hook_activity", store.ShareOptions{HookActivity: true}, true, false},
		{"hook_activity+full_content", store.ShareOptions{HookActivity: true, FullContent: true}, true, true},
		{"hook_activity+admin_managed", store.ShareOptions{HookActivity: true, AdminManaged: true}, true, true},
		{"hook_activity+enterprise_granted", store.ShareOptions{HookActivity: true, EnterpriseGranted: true}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st)
			now := time.Now().UTC()
			if err := st.UpsertHookActivity(ctx, []store.HookActivityRow{{
				Tool: "claude-code", Event: "PreToolUse", SessionID: "sess-cc-1", Count: 3,
				FirstAt: now.Add(-time.Minute), LastAt: now,
				EnvClasses: map[string]string{"ANTHROPIC_BASE_URL": "loopback", "CLAUDE_CONFIG_DIR": hash},
			}}); err != nil {
				t.Fatalf("UpsertHookActivity: %v", err)
			}

			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
				tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if !tc.wantRows {
				if len(batch.SessionHookActivity) != 0 {
					t.Errorf("hook activity shipped %d rows under %s; the tier is OFF", len(batch.SessionHookActivity), tc.name)
				}
			} else {
				if len(batch.SessionHookActivity) != 1 {
					t.Fatalf("hook_activity shipped %d rows under %s, want 1", len(batch.SessionHookActivity), tc.name)
				}
				r := batch.SessionHookActivity[0]
				if r.SessionID != "sess-cc-1" || r.Tool != "claude-code" || r.Event != "PreToolUse" || r.Count != 3 ||
					r.FirstAt == "" || r.LastAt == "" || r.EnvClasses["ANTHROPIC_BASE_URL"] != "loopback" || r.OrgID != "org-1" {
					t.Errorf("count half = %+v, want the seeded row with its coarse class", r)
				}
				if _, got := r.EnvClasses["CLAUDE_CONFIG_DIR"]; got != tc.wantHash {
					t.Errorf("config dir hash present = %v, want %v under %s: the hash is a SECOND gate (shipsRawContent)",
						got, tc.wantHash, tc.name)
				}
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			if leaked := bytes.Contains(raw, []byte(hash)); leaked != tc.wantHash {
				t.Errorf("hash present in the marshalled batch = %v, want %v under %s", leaked, tc.wantHash, tc.name)
			}
		})
	}
}

// TestSessionToolAccountKeyGatedWhenIdentityDerived is the PRIV-1 pin (codebase
// audit 2026-09-16). TestSessionToolAccountsShipOnlyUnderToolAccountDetail
// above pins that the IDENTITY columns need the second gate; this pins that the
// account_key does too WHEN IT IS DERIVED FROM ONE OF THEM.
//
// account_key is an unsalted sha256(tool || 0x00 || identity) and identity is
// the first non-empty of account_id, email, name
// (internal/toolaccount.Normalize). For an email- or name-derived key the
// preimage space is small and enumerable — an org admin holds the member
// roster — so shipping that key under the metadata tier hands over the identity
// half through the binding half's door. The keys here are computed by the
// PRODUCTION derivation, not hand-written, so the assertion is exactly "the
// string an admin with the roster would compute must not be on the wire".
//
// Two rows, one of each shape, in ONE batch:
//
//	(a) an ACCOUNT-ID-derived key is opaque in both directions and ships under
//	    tool_account_detail alone, unchanged;
//	(b) an EMAIL-derived key ships blank under tool_account_detail alone and
//	    only crosses once the node ALSO ships raw content.
func TestSessionToolAccountKeyGatedWhenIdentityDerived(t *testing.T) {
	const (
		secKeyEmail = "keygate-pangram-jj@example.invalid"
		secKeyName  = "Keygate Pangram Kk"
		secKeyAcct  = "keygate-acct-pangram-ll"
	)
	// Derive both keys the way production does, so the sentinel below is the
	// real recoverable string rather than a stand-in.
	_, idKey, ok := toolaccount.Normalize(models.ToolAccountObservation{
		SessionID: "sess-cc-1", Tool: "claude-code", BindingKind: "message",
		BindingID: "msg-id", Role: "assistant", Stage: "activity",
		Source: "hook", Scope: "session", AccountID: secKeyAcct,
	})
	if !ok {
		t.Fatal("toolaccount.Normalize refused the account-id observation — the fixture is wrong")
	}
	_, emailKey, ok := toolaccount.Normalize(models.ToolAccountObservation{
		SessionID: "sess-cc-1", Tool: "claude-code", BindingKind: "message",
		BindingID: "msg-email", Role: "assistant", Stage: "activity",
		Source: "hook", Scope: "session", Email: secKeyEmail, Name: secKeyName,
	})
	if !ok {
		t.Fatal("toolaccount.Normalize refused the email observation — the fixture is wrong")
	}
	if emailKey == idKey || emailKey == "" {
		t.Fatalf("derived keys are degenerate (id=%q email=%q) — the test would be vacuous", idKey, emailKey)
	}

	for _, tc := range []struct {
		name            string
		share           store.ShareOptions
		wantEmailKeyOut bool
	}{
		{"tool_account_detail", store.ShareOptions{ToolAccountDetail: true}, false},
		{"tool_account_detail+full_content", store.ShareOptions{ToolAccountDetail: true, FullContent: true}, true},
		{"tool_account_detail+admin_managed", store.ShareOptions{ToolAccountDetail: true, AdminManaged: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st)

			now := time.Now().UTC().Format(time.RFC3339Nano)
			for _, r := range []struct {
				bindingID, key, email, name, accountID string
			}{
				{"msg-id", idKey, "", "", secKeyAcct},
				{"msg-email", emailKey, secKeyEmail, secKeyName, ""},
			} {
				if _, err := database.ExecContext(ctx,
					`INSERT INTO tool_account_observations
					   (session_id, tool, binding_kind, binding_id, role, account_key,
					    email, name, account_id, source, scope, stage, observed_at)
					 VALUES ('sess-cc-1', 'claude-code', 'message', ?, 'assistant', ?,
					         ?, ?, ?, 'hook', 'session', 'activity', ?)`,
					r.bindingID, r.key, r.email, r.name, r.accountID, now); err != nil {
					t.Fatalf("seed tool_account_observations (%s): %v", r.bindingID, err)
				}
			}

			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
				tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.SessionToolAccounts) != 2 {
				t.Fatalf("shipped %d tool-account rows, want 2 — both observations must ride", len(batch.SessionToolAccounts))
			}
			for _, r := range batch.SessionToolAccounts {
				switch r.BindingID {
				case "msg-id":
					// An opaque, account-id-derived key ALWAYS ships under the
					// tier. If this ever blanks, the binding half stops
					// answering "same account or not" and the tier is pointless.
					if r.AccountKey != idKey {
						t.Errorf("account-id-derived key = %q, want %q — an opaque key ships under tool_account_detail alone", r.AccountKey, idKey)
					}
				case "msg-email":
					wantKey := ""
					if tc.wantEmailKeyOut {
						wantKey = emailKey
					}
					if r.AccountKey != wantKey {
						t.Errorf("email-derived key = %q, want %q under %s — an enumerable preimage rides the identity gate (PRIV-1)",
							r.AccountKey, wantKey, tc.name)
					}
				default:
					t.Errorf("unexpected binding_id %q on the wire", r.BindingID)
				}
			}

			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			// Byte-level sentinel: the derived key string itself.
			if got := bytes.Contains(raw, []byte(emailKey)); got != tc.wantEmailKeyOut {
				t.Errorf("email-derived account_key present in the marshalled batch = %v, want %v under %s",
					got, tc.wantEmailKeyOut, tc.name)
			}
			if !bytes.Contains(raw, []byte(idKey)) {
				t.Errorf("account-id-derived account_key missing from the batch under %s — the tier must still ship an opaque key", tc.name)
			}
			// And the identity itself keeps its own gate, unchanged.
			for _, sentinel := range []string{secKeyEmail, secKeyName, secKeyAcct} {
				if got := bytes.Contains(raw, []byte(sentinel)); got != tc.wantEmailKeyOut {
					t.Errorf("identity sentinel %q present = %v, want %v under %s", sentinel, got, tc.wantEmailKeyOut, tc.name)
				}
			}
		})
	}
}

// seedTerminalActivity inserts one terminal_run (+ command) and one remote_audit
// row whose SENSITIVE columns are sentinels but whose public enums (tool, kind,
// decision, principal) are benign, so a SelectUnpushedSince batch can be
// searched both for whether the P5h terminal-detail aggregate shipped AND for
// whether any raw terminal/remote identity leaked. terminal_* / remote_audit
// stay pinned ENTIRELY out of the wire otherwise (the dedicated
// TestTerminalRunTablesPinnedOutOfPush / TestRemoteAuditTablePinnedOutOfPush);
// only the content-free count aggregate crosses, and only under terminal_detail.
func seedTerminalActivity(ctx context.Context, t *testing.T, st *store.Store, sentinel string) {
	t.Helper()
	if err := st.InsertTerminalRun(ctx, store.TerminalRun{
		RunID: "run-" + sentinel, Tool: "claude-code", Kind: "handoff",
		SourceSessionID: sentinel, ProjectRootHash: sentinel, CorrelationTokenHash: sentinel,
	}); err != nil {
		t.Fatalf("InsertTerminalRun: %v", err)
	}
	if err := st.InsertTerminalCommand(ctx, store.TerminalCommand{
		RunID: "run-" + sentinel, TurnSeq: 1, Trust: "hint", CmdHash: sentinel,
	}); err != nil {
		t.Fatalf("InsertTerminalCommand: %v", err)
	}
	if err := st.InsertRemoteAudit(ctx, store.RemoteAuditEvent{
		Kind: "session_paired", SessionID: sentinel, Principal: "view",
		RemoteAddr: sentinel, Route: sentinel, Decision: "ok", Detail: sentinel,
	}); err != nil {
		t.Fatalf("InsertRemoteAudit: %v", err)
	}
}

// TestPushPayloadCarriesTerminalWhenOptedIn is the Arc 4 P5h extraction tier:
// under the DISTINCT terminal_detail opt-in, the node-local terminal_run +
// remote_audit logs ship as content-free count aggregates. Two properties are
// proven together: (1) the tier FLIPS the seam (both TerminalSummaries and
// RemoteAuditSummaries are non-empty); and (2) even when it ships, NO raw
// terminal/remote identity crosses — no project/correlation/command hash, no
// source session id, no remote session id, no peer address, no route, no detail.
// The raw table NAMES still never appear in orgpush.go (SelectTerminalSummaries
// / SelectRemoteAuditSummaries own the reads in a separate file), and the
// pre-existing never-ships tests (which assert absence under full_content) stay
// true because this aggregate is orthogonal to full_content.
func TestPushPayloadCarriesTerminalWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secTerm = "SENTINEL_TERMINAL_grandiloquent_zz"
	seedTerminalActivity(ctx, t, st, secTerm)

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{TerminalDetail: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.TerminalSummaries) == 0 {
		t.Fatal("terminal_detail opt-in shipped no TerminalSummaries — the tier failed to flip the seam")
	}
	if len(batch.RemoteAuditSummaries) == 0 {
		t.Fatal("terminal_detail opt-in shipped no RemoteAuditSummaries — the tier failed to flip the seam")
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	// Content-free even when shipped: none of the sensitive columns cross.
	if bytes.Contains(raw, []byte(secTerm)) {
		t.Error("terminal/remote identity leaked into the aggregate — only counts + public enums may ship")
	}
}

// TestPushPayloadStripsTerminalWhenNotOptedIn is the other side of the tier:
// with terminal_detail OFF, neither aggregate ships — not even under
// full_content (maximum disclosure). terminal_detail is a DISTINCT tier,
// orthogonal to shipsRawContent(), raised only by the DISTINCT extract.terminal
// authority on a managed node. This is what keeps the raw-table never-ships
// pins intact: the ONLY way terminal/remote data crosses at all is this
// content-free aggregate under this explicit tier.
func TestPushPayloadStripsTerminalWhenNotOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secTerm = "SENTINEL_TERMINAL_grandiloquent_zz"
	seedTerminalActivity(ctx, t, st, secTerm)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"zero-value", store.ShareOptions{}},
		{"full_content-only", store.ShareOptions{FullContent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.TerminalSummaries) != 0 || len(batch.RemoteAuditSummaries) != 0 {
				t.Errorf("terminal aggregate shipped under %s (terminal_detail OFF) — the tier must be orthogonal and opt-in", tc.name)
			}
			if tc.share.FullContent {
				// Enterprise (org-parity W2.6): full_content legitimately
				// ships the per-dev terminal/remote visibility wires —
				// scope the leak scan past them; the teams-tier aggregates
				// above stay flag-gated.
				if len(batch.TerminalRuns) == 0 {
					t.Error("full_content shipped no terminal runs — the W2.6 enterprise wire failed to flip")
				}
				batch.TerminalRuns, batch.TerminalCommands, batch.RemoteAudit = nil, nil, nil
			} else if len(batch.TerminalRuns) != 0 || len(batch.TerminalCommands) != 0 || len(batch.RemoteAudit) != 0 {
				t.Errorf("terminal/remote dev wires shipped under %s (metadata-only) — must ride shipsRawContent only", tc.name)
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			if bytes.Contains(raw, []byte(secTerm)) {
				t.Errorf("terminal/remote identity leaked under %s without terminal_detail", tc.name)
			}
		})
	}
}

// seedRouterDecision inserts one router_decisions row with a sentinel model, so
// a SelectUnpushedSince batch can be searched for whether the P5d routing-detail
// aggregate shipped. router_decisions stays NODE-LOCAL; only the content-free
// (day, model→model, turn_kind, mode) aggregate crosses, and only under
// routing_detail.
func seedRouterDecision(ctx context.Context, t *testing.T, database *sql.DB, selectedModel string) {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO router_decisions (session_id, ts, mode, channel, original_model, selected_model, turn_kind, policy_hash, applied, est_savings_usd)
		 VALUES ('sess-cc-1', ?, 'enforce', 'proxy', 'claude-opus-4-8', ?, 'edit', 'ph', 1, 0.03)`, ts, selectedModel); err != nil {
		t.Fatalf("seed router_decisions: %v", err)
	}
}

// TestPushPayloadCarriesRoutingDetailWhenOptedIn is the Arc 4 P5d extraction
// tier: under the DISTINCT routing_detail opt-in, the node-local
// router_decisions log ships as a content-free but MODEL-ID-BEARING aggregate.
// The router_decisions table NAME still never appears in orgpush.go
// (SelectRoutingDetail owns the read in a separate file); this proves the
// aggregate itself flips onto the wire under the tier.
func TestPushPayloadCarriesRoutingDetailWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secRouteModel = "SENTINEL_ROUTE_MODEL_pangram_zz"
	seedRouterDecision(ctx, t, database, secRouteModel)

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{RoutingDetail: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.RoutingDetails) == 0 {
		t.Fatal("routing_detail opt-in shipped no RoutingDetails — the tier failed to flip the seam")
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if !bytes.Contains(raw, []byte(secRouteModel)) {
		t.Error("routing detail did NOT ship the selected model under routing_detail — the tier failed to flip the seam")
	}
}

// TestPushPayloadStripsRoutingDetailWhenNotOptedIn is the other side of the
// tier: with routing_detail OFF, the routing detail must NOT ship — not even
// under full_content, and not under the model-id-FREE routing_summary tier
// (which ships a DIFFERENT aggregate). routing_detail is a DISTINCT tier.
func TestPushPayloadStripsRoutingDetailWhenNotOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secRouteModel = "SENTINEL_ROUTE_MODEL_pangram_zz"
	seedRouterDecision(ctx, t, database, secRouteModel)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"zero-value", store.ShareOptions{}},
		{"full_content-only", store.ShareOptions{FullContent: true}},
		{"routing_summary-only", store.ShareOptions{RoutingSummary: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.RoutingDetails) != 0 {
				t.Errorf("routing detail shipped under %s (routing_detail OFF) — the tier must be distinct and opt-in", tc.name)
			}
			if tc.share.FullContent {
				// Enterprise (org-parity W2.3): full_content legitimately
				// ships the per-dev routing wire, which MAY carry the
				// model (plan §0.1) — scope the leak scan past it. The
				// routing_summary-only and zero-value cases stay fully
				// clean (the teams posture).
				if len(batch.RoutingDevRows) == 0 {
					t.Error("full_content shipped no routing dev rows — the W2.3 enterprise wire failed to flip")
				}
				batch.RoutingDevRows = nil
			} else if len(batch.RoutingDevRows) != 0 {
				t.Errorf("routing dev rows shipped under %s (no raw-content tier) — must ride shipsRawContent only", tc.name)
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			if bytes.Contains(raw, []byte(secRouteModel)) {
				t.Errorf("selected model leaked under %s without routing_detail", tc.name)
			}
		})
	}
}

// seedLimitSnapshot inserts one limit_snapshots row with a sentinel scope_hash,
// so a SelectUnpushedSince batch can be searched to prove the P5e aggregate
// ships utilization stats but NEVER the raw scope hash. The raw limit_snapshots
// log stays NODE-LOCAL; only two derived metadata shapes cross, both composed
// in internal/store/limitgauge.go: the (day, provider) utilization aggregate
// (limit_gauge only) and the per-session newest-window row (lane F-WIRE; see
// TestSessionLimitSnapshotsWireShipsMetadataOnly).
func seedLimitSnapshot(ctx context.Context, t *testing.T, database *sql.DB, scopeHash string) {
	t.Helper()
	if _, err := database.ExecContext(ctx,
		`INSERT INTO limit_snapshots (scope_hash, provider, observed_at, window_5h_util, window_7d_util)
		 VALUES (?, 'anthropic', ?, 0.73, 0.41)`, scopeHash, time.Now().UTC().Unix()); err != nil {
		t.Fatalf("seed limit_snapshots: %v", err)
	}
}

// TestPushPayloadCarriesLimitGaugeWhenOptedIn is the Arc 4 P5e extraction tier:
// under the DISTINCT limit_gauge opt-in, the node-local limit_snapshots log
// ships as a content-free per (day, provider) utilization aggregate — and the
// raw scope_hash (auth identity) is NEVER on the wire. The limit_snapshots table
// NAME still never appears in orgpush.go (SelectLimitGauges owns the read in a
// separate file).
func TestPushPayloadCarriesLimitGaugeWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secScopeHash = "SENTINEL_LIMIT_SCOPE_pangram_zz"
	seedLimitSnapshot(ctx, t, database, secScopeHash)

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{LimitGauge: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.LimitGauges) == 0 {
		t.Fatal("limit_gauge opt-in shipped no LimitGauges — the tier failed to flip the seam")
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	// The aggregate rides, but the raw auth-scope hash must NOT.
	if bytes.Contains(raw, []byte(secScopeHash)) {
		t.Error("limit gauge leaked the raw scope_hash — only the (day, provider) utilization aggregate may ship")
	}
	if batch.LimitGauges[0].Provider != "anthropic" || batch.LimitGauges[0].Max5hUtil <= 0 {
		t.Errorf("limit gauge = %+v, want anthropic with a positive 5h util", batch.LimitGauges[0])
	}
}

// TestPushPayloadStripsLimitGaugeWhenNotOptedIn is the other side of the tier:
// with limit_gauge OFF, the aggregate must NOT ship — not even under
// full_content. It is a DISTINCT tier.
func TestPushPayloadStripsLimitGaugeWhenNotOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secScopeHash = "SENTINEL_LIMIT_SCOPE_pangram_zz"
	seedLimitSnapshot(ctx, t, database, secScopeHash)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"zero-value", store.ShareOptions{}},
		{"full_content-only", store.ShareOptions{FullContent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.LimitGauges) != 0 {
				t.Errorf("limit gauge shipped under %s (limit_gauge OFF) — the tier must be distinct and opt-in", tc.name)
			}
		})
	}
}

// TestSessionLimitSnapshotsWireShipsMetadataOnly pins the lane F-WIRE
// per-session rate-limit window wire at the privacy seam. The gate: an
// individual node with no limit_gauge opt-in ships NO row and its cursor stays
// put; the limit_gauge opt-in or a full-capture node ships the newest window
// per (session, provider). The content: whatever the posture, the node's
// scope_hash (auth identity), raw header subset and status passthrough never
// reach the marshalled batch.
func TestSessionLimitSnapshotsWireShipsMetadataOnly(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	// Enrolment-style cursor: every other wire at its high-water mark, so the
	// batch carries only what this test seeds next.
	cur, err := st.CurrentMaxIDs(ctx)
	if err != nil {
		t.Fatalf("CurrentMaxIDs: %v", err)
	}
	const (
		secScope  = "SENTINEL_SESSLIMIT_SCOPE_qq"
		secRaw    = "SENTINEL_SESSLIMIT_RAW_qq"
		secStatus = "SENTINEL_SESSLIMIT_STATUS_qq"
	)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO limit_snapshots (scope_hash, provider, session_id, observed_at,
		     window_5h_util, window_5h_reset, window_7d_util, window_7d_reset,
		     req_limit, req_remaining, tok_limit, tok_remaining, status, raw)
		 VALUES (?, 'anthropic', 'sess-cc-1', ?, 0.61, 1790012000, 0.23, 1790400000,
		     50, 49, 400000, 399000, ?, ?)`,
		secScope, time.Now().UTC().Unix(), secStatus, secRaw); err != nil {
		t.Fatalf("seed limit_snapshots: %v", err)
	}

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
		want  int
	}{
		{"zero-value", store.ShareOptions{}, 0},
		{"limit_gauge", store.ShareOptions{LimitGauge: true}, 1},
		{"full_content", store.ShareOptions{FullContent: true}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, cur, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if got := len(batch.SessionLimitSnapshots); got != tc.want {
				t.Fatalf("shipped %d session limit rows, want %d", got, tc.want)
			}
			if tc.want == 0 && batch.Cursor.LimitSnapshots != cur.LimitSnapshots {
				t.Errorf("cursor moved to %d with the wire gated off (want %d): an individual node must not consume windows it never ships",
					batch.Cursor.LimitSnapshots, cur.LimitSnapshots)
			}
			if tc.want == 1 {
				r := batch.SessionLimitSnapshots[0]
				if r.SessionID != "sess-cc-1" || r.Tool != models.ToolClaudeCode || r.Provider != "anthropic" ||
					r.Window5hUtil == nil || *r.Window5hUtil != 0.61 || r.Window7dReset == nil || *r.Window7dReset != 1790400000 {
					t.Errorf("row = %+v, want the sess-cc-1 claude-code anthropic window", r)
				}
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			for _, sentinel := range []string{secScope, secRaw, secStatus} {
				if bytes.Contains(raw, []byte(sentinel)) {
					t.Errorf("%s: sentinel %q reached the push batch - only window metadata may ship", tc.name, sentinel)
				}
			}
		})
	}
}

// TestSessionLimitSnapshotRowFieldSet pins the per-session rate-limit wire
// row's exact field set, so a future scope_hash / raw / status / counter
// field on the wire is a loud, reviewed change rather than a silent widening.
func TestSessionLimitSnapshotRowFieldSet(t *testing.T) {
	t.Parallel()
	want := []string{
		"OrgID", "UserEmail", "SessionID", "Tool", "Provider", "LocalID", "ObservedAt",
		"Window5hUtil", "Window7dUtil", "Window5hReset", "Window7dReset",
	}
	rt := reflect.TypeOf(orgcontract.SessionLimitSnapshotRow{})
	var got []string
	for i := 0; i < rt.NumField(); i++ {
		got = append(got, rt.Field(i).Name)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("SessionLimitSnapshotRow fields = %v, want %v - a new field on this wire needs a privacy review "+
			"(scope_hash, raw headers, status and the req/tok counters must never ship)", got, want)
	}
}
