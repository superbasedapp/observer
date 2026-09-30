package dashboard

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestLoadActionExcerpts_MatchesFullScanOracle pins the indexed excerpt
// lookup (rowid IN (SELECT id FROM action_excerpts_content WHERE c0 IN …))
// to the old full-scan form (kept verbatim as loadActionExcerptsOracle):
// first excerpt per action_id = lowest FTS rowid, missing ids absent, the
// maxBytes substr variant, and id sets larger than one chunk.
func TestLoadActionExcerpts_MatchesFullScanOracle(t *testing.T) {
	ctx := context.Background()
	database, err := openTestDB(ctx, db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	// 1..1400 get one excerpt each except: every 7th id gets 2-3 excerpts
	// inserted in SHUFFLED order (so lowest rowid != lexically smallest
	// text), every 11th id gets none. Ids > 1400 never exist.
	rng := rand.New(rand.NewSource(42))
	type ins struct {
		id   int64
		text string
	}
	var rowsToInsert []ins
	for id := int64(1); id <= 1400; id++ {
		if id%11 == 0 {
			continue
		}
		n := 1
		if id%7 == 0 {
			n = 2 + rng.Intn(2)
		}
		for k := 0; k < n; k++ {
			rowsToInsert = append(rowsToInsert, ins{id, fmt.Sprintf("excerpt-%d-%d-%s", id, k, strings.Repeat("x", rng.Intn(400)))})
		}
	}
	rng.Shuffle(len(rowsToInsert), func(i, j int) { rowsToInsert[i], rowsToInsert[j] = rowsToInsert[j], rowsToInsert[i] })
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rowsToInsert {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO action_excerpts (action_id, tool_name, target, excerpt, error_message) VALUES (?, 'Bash', 't', ?, '')`,
			r.id, r.text); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	span := func(from, to int64) []int64 {
		var out []int64
		for i := from; i <= to; i++ {
			out = append(out, i)
		}
		return out
	}
	idSets := []struct {
		name string
		ids  []int64
	}{
		{"empty", nil},
		{"single", []int64{7}},
		{"missing only", []int64{11, 22, 5000, 99999}},
		{"mixed with duplicates", []int64{7, 7, 14, 11, 3, 5000, 3, 21}},
		{"over one chunk", span(1, 1100)},
		{"whole range plus missing", span(1, 1600)},
	}
	for _, set := range idSets {
		for _, maxBytes := range []int{0, 280, 5} {
			t.Run(fmt.Sprintf("%s/max=%d", set.name, maxBytes), func(t *testing.T) {
				want, err := loadActionExcerptsOracle(ctx, database, set.ids, maxBytes)
				if err != nil {
					t.Fatal(err)
				}
				got, err := loadActionExcerpts(ctx, database, set.ids, maxBytes)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("map mismatch: got %d entries, want %d", len(got), len(want))
				}
			})
		}
	}

	// The lookup must SEEK via migration 147's index, not scan.
	var plan []string
	rows, err := database.QueryContext(ctx,
		`EXPLAIN QUERY PLAN SELECT rowid, action_id, excerpt FROM action_excerpts
		  WHERE rowid IN (SELECT id FROM action_excerpts_content WHERE c0 IN (?, ?))`, 7, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if !strings.Contains(strings.Join(plan, "\n"), "idx_action_excerpts_content_c0") {
		t.Errorf("excerpt lookup does not use idx_action_excerpts_content_c0; plan:\n%s", strings.Join(plan, "\n"))
	}
}

// seedHydrateCorpus writes a randomized multi-session fixture for the
// oracle equality test and returns the session ids. Sessions: a
// claude-code coding session (user prompts incl. > inline-cap inputs and
// attachments, run_command argv JSON, tool outputs, proxy/JSONL twins,
// equal-timestamp ties, multi-excerpt actions), a chatgpt-web browser
// session (long ASCII and multibyte assistant bodies — elided flag,
// LENGTH-in-characters vs byte cap), and a codex session dominated by
// token-only inference rows (orphan-token stubs, ?detail=inference).
func seedHydrateCorpus(t *testing.T, database *sql.DB, seed int64) []string {
	t.Helper()
	ctx := context.Background()
	rng := rand.New(rand.NewSource(seed))
	st := store.New(database)
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC).Add(time.Duration(seed) * time.Hour)
	randText := func(max int) string {
		n := rng.Intn(max + 1)
		return strings.Repeat(string(rune('a'+rng.Intn(26))), n)
	}

	// --- claude-code session ---------------------------------------
	cc := fmt.Sprintf("cc-%d", seed)
	var evts []models.ToolEvent
	var toks []models.TokenEvent
	var proxy []struct {
		ts  time.Time
		req string
		in  int64
		out int64
	}
	ts := base
	nMsgs := 40 + rng.Intn(40)
	for i := 0; i < nMsgs; i++ {
		ts = ts.Add(time.Duration(1+rng.Intn(20)) * time.Second)
		mid := fmt.Sprintf("msg_%d_%d", seed, i)
		if rng.Intn(3) == 0 {
			input := randText(300)
			if rng.Intn(4) == 0 {
				input = strings.Repeat("P", fullTextInlineMax+rng.Intn(200)-50)
			}
			evts = append(evts, models.ToolEvent{
				SourceFile: "f", SourceEventID: "u" + mid, SessionID: cc, ProjectRoot: "/tmp/hydrate-cc",
				Timestamp: ts, Tool: models.ToolClaudeCode, ActionType: models.ActionUserPrompt,
				Target: "prompt " + mid, Success: true, RawToolName: "user", RawToolInput: input,
				MessageID: "user:" + mid,
			})
		}
		nActs := rng.Intn(4)
		for k := 0; k < nActs; k++ {
			ats := ts
			if rng.Intn(3) != 0 { // else an equal-timestamp tie
				ats = ts.Add(time.Duration(k*100) * time.Millisecond)
			}
			ev := models.ToolEvent{
				SourceFile: "f", SourceEventID: fmt.Sprintf("%s_%d", mid, k), SessionID: cc,
				ProjectRoot: "/tmp/hydrate-cc", Timestamp: ats, Tool: models.ToolClaudeCode,
				Success: rng.Intn(5) != 0, DurationMs: int64(rng.Intn(3000)), MessageID: mid,
				Metadata: &models.ActionMetadata{EffortLevel: []string{"", "low", "high"}[rng.Intn(3)]},
			}
			if !ev.Success {
				ev.ErrorMessage = "boom " + randText(20)
			}
			switch rng.Intn(6) {
			case 0:
				ev.ActionType, ev.RawToolName, ev.Target = models.ActionRunCommand, "Bash", "ls -la "+randText(10)
				if rng.Intn(2) == 0 {
					ev.RawToolInput = `["bash","-lc","ls -la ` + randText(30) + `"]`
				} else {
					ev.RawToolInput = "ls " + randText(50)
				}
			case 1:
				ev.ActionType, ev.RawToolName, ev.Target = models.ActionReadFile, "Read", "/tmp/hydrate-cc/"+randText(8)+".go"
				ev.RawToolInput = `{"file_path":"x"}`
			case 2:
				ev.ActionType, ev.RawToolName, ev.Target = models.ActionEditFile, "Edit", "/tmp/hydrate-cc/e.go"
				ev.RawToolInput = strings.Repeat("E", 5000)
			case 3:
				ev.ActionType, ev.RawToolName, ev.Target = models.ActionAssistantMessage, "claude.assistant_text", "narration "+randText(40)
			case 4:
				ev.ActionType, ev.RawToolName, ev.Target = models.ActionAskUser, "AskUserQuestion", "which one?"
				ev.RawToolInput = randText(5000)
			default:
				ev.ActionType, ev.RawToolName, ev.Target = models.ActionWebSearch, "WebSearch", ""
			}
			if rng.Intn(2) == 0 {
				ev.ToolOutput = randText(6000)
			}
			evts = append(evts, ev)
		}
		in, out := int64(100+rng.Intn(5000)), int64(10+rng.Intn(900))
		toks = append(toks, models.TokenEvent{
			SourceFile: "f", SourceEventID: "t" + mid, SessionID: cc, Timestamp: ts,
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-8", InputTokens: in, OutputTokens: out,
			CacheReadTokens: int64(rng.Intn(20000)), MessageID: mid,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
		})
		if rng.Intn(3) == 0 { // proxy twin
			proxy = append(proxy, struct {
				ts  time.Time
				req string
				in  int64
				out int64
			}{ts.Add(200 * time.Millisecond), mid, in, out})
		}
	}
	if _, err := st.Ingest(ctx, evts, toks, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range proxy {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens,
			   cache_read_tokens, cache_creation_tokens, request_id, cost_usd)
			 VALUES (?, ?, 'anthropic', 'claude-opus-4-8', ?, ?, 0, 0, ?, 0)`,
			cc, p.ts.Format(time.RFC3339Nano), p.in, p.out, p.req); err != nil {
			t.Fatal(err)
		}
	}
	// Attachments on some user prompts.
	if _, err := database.ExecContext(ctx,
		`UPDATE actions SET user_attachments = '[{"kind":"image","media_type":"image/png"},{"kind":"file"}]'
		  WHERE session_id = ? AND action_type = 'user_prompt' AND id % 2 = 0`, cc); err != nil {
		t.Fatal(err)
	}

	// --- chatgpt-web browser session ------------------------------------
	web := fmt.Sprintf("web-%d", seed)
	evts, toks = nil, nil
	ts = base
	for i := 0; i < 12+rng.Intn(10); i++ {
		ts = ts.Add(time.Duration(5+rng.Intn(30)) * time.Second)
		mid := fmt.Sprintf("wm_%d_%d", seed, i)
		var body string
		switch rng.Intn(5) {
		case 0:
			body = strings.Repeat("A", fullTextInlineMax+500) // ASCII over cap
		case 1:
			body = strings.Repeat("ü", 3000) // < cap chars, > cap bytes
		case 2:
			body = strings.Repeat("é", fullTextInlineMax+10) // > cap chars
		case 3:
			body = ""
		default:
			body = "short answer " + randText(100)
		}
		evts = append(evts,
			models.ToolEvent{
				SourceFile: "fw", SourceEventID: mid + ":user", SessionID: web, ProjectRoot: "browser://chatgpt.com",
				Timestamp: ts, Tool: models.ToolChatGPTWeb, ActionType: models.ActionUserPrompt,
				Target: "q " + mid, Success: true, RawToolName: "chatgpt.user_prompt",
				RawToolInput: "question " + randText(200), MessageID: "user:" + mid,
			},
			models.ToolEvent{
				SourceFile: "fw", SourceEventID: mid, SessionID: web, ProjectRoot: "browser://chatgpt.com",
				Timestamp: ts.Add(2 * time.Second), Tool: models.ToolChatGPTWeb, ActionType: models.ActionAssistantMessage,
				Target: "gpt-5", Success: true, RawToolName: "chatgpt.assistant_text", ToolOutput: body,
				MessageID: mid, DurationMs: 1500,
				Metadata: &models.ActionMetadata{
					RequestURL: "/backend-api/conversation", IDSource: "resume",
					Granularity: "full", PromptTokensEst: 12, ResponseTokensEst: 340,
				},
			})
		toks = append(toks, models.TokenEvent{
			SourceFile: "fw", SourceEventID: mid + ":tok", SessionID: web, Timestamp: ts.Add(2 * time.Second),
			Tool: models.ToolChatGPTWeb, Model: "gpt-5", InputTokens: 12, OutputTokens: 340, MessageID: mid,
			Source: models.TokenSourceEstimated, Reliability: models.ReliabilityUnreliable,
		})
	}
	if _, err := st.Ingest(ctx, evts, toks, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// --- codex session (inference-heavy, mostly orphan turns) ----------
	cx := fmt.Sprintf("cx-%d", seed)
	evts, toks = nil, nil
	ts = base
	for i := 0; i < 30+rng.Intn(30); i++ {
		ts = ts.Add(time.Duration(1+rng.Intn(10)) * time.Second)
		// One message id per inference call; only ~1/4 carry an action,
		// so the orphan ratio clears the stub gate (> 0.5).
		turn := fmt.Sprintf("cxm_%d_%d", seed, i)
		if rng.Intn(4) == 0 {
			evts = append(evts, models.ToolEvent{
				SourceFile: "fx", SourceEventID: fmt.Sprintf("cxa_%d_%d", seed, i), SessionID: cx,
				ProjectRoot: "/tmp/hydrate-cx", Timestamp: ts, Tool: models.ToolCodex,
				ActionType: models.ActionRunCommand, RawToolName: "shell", Target: "go test ./...",
				RawToolInput: `["go","test","./..."]`, Success: true, MessageID: turn, ToolOutput: randText(300),
				Metadata: &models.ActionMetadata{EffortLevel: "medium", ServiceTier: "priority"},
			})
		}
		toks = append(toks, models.TokenEvent{
			SourceFile: "fx", SourceEventID: fmt.Sprintf("cxt_%d_%d", seed, i), SessionID: cx, Timestamp: ts,
			Tool: models.ToolCodex, Model: "gpt-5.5", InputTokens: int64(1000 + rng.Intn(9000)),
			OutputTokens: int64(rng.Intn(500)), CacheReadTokens: int64(rng.Intn(8000)), MessageID: turn,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
		})
	}
	if _, err := st.Ingest(ctx, evts, toks, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// Excerpts: 1-3 per action for ~2/3 of all actions, shuffled so the
	// lowest rowid is not the lexically smallest excerpt.
	idRows, err := database.QueryContext(ctx, `SELECT id FROM actions WHERE session_id IN (?, ?, ?)`, cc, web, cx)
	if err != nil {
		t.Fatal(err)
	}
	var excerptRows [][2]any
	for idRows.Next() {
		var id int64
		if err := idRows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		if rng.Intn(3) == 0 {
			continue
		}
		for k := 0; k <= rng.Intn(3); k++ {
			excerptRows = append(excerptRows, [2]any{id, fmt.Sprintf("ex-%d-%d %s", id, k, randText(300))})
		}
	}
	idRows.Close()
	rng.Shuffle(len(excerptRows), func(i, j int) { excerptRows[i], excerptRows[j] = excerptRows[j], excerptRows[i] })
	for _, e := range excerptRows {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO action_excerpts (action_id, tool_name, target, excerpt, error_message) VALUES (?, 'x', 'y', ?, '')`,
			e[0], e[1]); err != nil {
			t.Fatal(err)
		}
	}
	return []string{cc, web, cx, "no-such-session"}
}

// TestAPISessionMessages_HydrateMatchesOracle asserts the page-window
// hydrating handler returns BYTE-IDENTICAL responses (status + body) to the
// pre-hydration handler (handleSessionMessagesOracle, a verbatim copy) for
// every query shape, over a randomized multi-session corpus and several
// seeds.
func TestAPISessionMessages_HydrateMatchesOracle(t *testing.T) {
	queries := []string{
		"",
		"?limit=25",
		"?limit=25&offset=25",
		"?limit=7&offset=3",
		"?limit=0",
		"?offset=100000",
		"?limit=1",
		"?detail=inference",
		"?detail=inference&limit=10&offset=5",
		"?detail=inference&limit=0",
		"?sort_by=content&sort_dir=asc&limit=10",
		"?sort_by=content&sort_dir=desc&limit=10&offset=10",
		"?sort_by=tool_call_count&sort_dir=desc&limit=5",
		"?sort_by=attachments&sort_dir=desc&limit=5",
		"?sort_by=cost_usd&sort_dir=desc&limit=0",
		"?sort_by=tokens_per_sec&sort_dir=asc&limit=8",
		"?sort_by=elapsed_ms&sort_dir=desc",
		"?sort_by=nonsense&limit=10",
		"?tail=5",
		"?tail=1",
		"?tail=500",
		"?tail=0",
		"?tail=abc",
		"?tail=6&sort_by=content&sort_dir=desc",
		"?tail=6&detail=inference",
		"?tail=5&offset=2",
		"?tail=5&limit=2",
		"?tail=5&locate=x",
		"?limit=10&locate=LOCATE",
		"?limit=10&locate=no-such-id",
		"?limit=10&locate=LOCATE&sort_by=content&sort_dir=desc",
		"?limit=0&locate=LOCATE",
	}
	for _, seed := range []int64{1, 2, 3, 4} {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "d.db")
			database, err := openTestDB(context.Background(), db.Options{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { database.Close() })
			sessions := seedHydrateCorpus(t, database, seed)
			srv, err := New(Options{DB: database, DBPath: path})
			if err != nil {
				t.Fatal(err)
			}
			call := func(h func(http.ResponseWriter, *http.Request, string), sid, q string) *httptest.ResponseRecorder {
				rr := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/api/session/"+sid+"/messages"+q, nil)
				h(rr, req, sid)
				return rr
			}
			var sawElided, sawExcerpt, sawStub, sawAttachment, sawOutput int
			for _, sid := range sessions {
				// A real message id from the middle of the timeline, for
				// ?locate=.
				full := call(srv.handleSessionMessagesOracle, sid, "?limit=0").Body.String()
				locate := "absent"
				if i := strings.Index(full, `"message_id":"`); i >= 0 {
					ids := strings.Split(full, `"message_id":"`)
					mid := ids[len(ids)/2]
					locate = mid[:strings.IndexByte(mid, '"')]
				}
				sawElided += strings.Count(full, `"full_text_elided":true`)
				sawExcerpt += strings.Count(full, `"excerpt":"ex-`)
				sawStub += strings.Count(full, `"synthetic.api_call"`)
				sawAttachment += strings.Count(full, `"attachments":[`)
				sawOutput += strings.Count(full, `"has_full_output":true`)
				for _, q := range queries {
					q = strings.ReplaceAll(q, "LOCATE", locate)
					want := call(srv.handleSessionMessagesOracle, sid, q)
					got := call(srv.handleSessionMessages, sid, q)
					if want.Code != got.Code {
						t.Fatalf("%s%s: status got %d want %d", sid, q, got.Code, want.Code)
					}
					if !bytes.Equal(want.Body.Bytes(), got.Body.Bytes()) {
						w, g := want.Body.String(), got.Body.String()
						i := 0
						for i < len(w) && i < len(g) && w[i] == g[i] {
							i++
						}
						lo := i - 200
						if lo < 0 {
							lo = 0
						}
						t.Fatalf("%s%s: body differs at byte %d\nwant …%s\ngot  …%s", sid, q, i,
							w[lo:min(len(w), i+200)], g[lo:min(len(g), i+200)])
					}
				}
			}
			// Guard against a vacuous equality: the corpus must exercise
			// every hydrated field and the stub path.
			for name, n := range map[string]int{
				"elided": sawElided, "excerpt": sawExcerpt, "stub": sawStub,
				"attachment": sawAttachment, "has_full_output": sawOutput,
			} {
				if n == 0 {
					t.Errorf("corpus never exercised %s", name)
				}
			}
		})
	}
}
