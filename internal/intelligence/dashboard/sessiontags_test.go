package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newTagTestServer seeds three sessions across one project so the
// classification filters have something to discriminate. Each session carries a
// distinct token/cost profile so the per-tag rollup is checkable.
func newTagTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tags.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	st := store.New(database)
	root := t.TempDir()
	base := time.Now().UTC().Add(-time.Hour)
	var events []models.ToolEvent
	var tokens []models.TokenEvent
	for i, sid := range []string{"sess-a", "sess-b", "sess-c"} {
		ts := base.Add(time.Duration(i) * time.Minute)
		events = append(events, models.ToolEvent{
			SourceFile: "f.jsonl", SourceEventID: sid + "-e1", SessionID: sid,
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
			Model: "claude-opus-4-7", ActionType: models.ActionReadFile,
			Target: "a.go", Success: true,
		})
		tokens = append(tokens, models.TokenEvent{
			SourceFile: "f.jsonl", SourceEventID: sid + "-t1", SessionID: sid,
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
			Model: "claude-opus-4-7", InputTokens: int64(1000 * (i + 1)),
			OutputTokens: int64(100 * (i + 1)), Source: "jsonl", Reliability: "unreliable",
		})
	}
	if _, err := st.Ingest(context.Background(), events, tokens, store.IngestOptions{}); err != nil {
		t.Fatalf("seed Ingest: %v", err)
	}

	s, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatalf("dashboard.New: %v", err)
	}
	return s, st
}

func doJSON(t *testing.T, s *Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: decode body %q: %v", method, path, rec.Body.String(), err)
		}
	}
	return rec.Code, out
}

// TestSessionTagsMutationRoundTrip pins POST /api/session/<id>/tags: adds,
// removes, the partial favorite/note semantics, the echoed post-state, and the
// 400s for an invalid tag / an over-cap add.
func TestSessionTagsMutationRoundTrip(t *testing.T) {
	s, _ := newTagTestServer(t)

	code, body := doJSON(t, s, http.MethodPost, "/api/session/sess-a/tags",
		`{"add":["Backend","ui ux"],"favorite":true,"note":"baseline run"}`)
	if code != http.StatusOK {
		t.Fatalf("POST tags = %d", code)
	}
	tags, _ := body["tags"].([]any)
	if len(tags) != 2 || tags[0] != "backend" || tags[1] != "ui-ux" {
		t.Fatalf("tags = %v, want normalized [backend ui-ux]", body["tags"])
	}
	if body["favorite"] != true || body["note"] != "baseline run" {
		t.Fatalf("annotation echo = %v", body)
	}

	// Partial update: only the star flips; the note survives.
	_, body = doJSON(t, s, http.MethodPost, "/api/session/sess-a/tags", `{"favorite":false}`)
	if body["favorite"] != false || body["note"] != "baseline run" {
		t.Fatalf("partial update clobbered the note: %v", body)
	}

	// Remove one tag.
	_, body = doJSON(t, s, http.MethodPost, "/api/session/sess-a/tags", `{"remove":["backend"]}`)
	tags, _ = body["tags"].([]any)
	if len(tags) != 1 || tags[0] != "ui-ux" {
		t.Fatalf("after remove = %v", body["tags"])
	}

	if code, _ := doJSON(t, s, http.MethodPost, "/api/session/sess-a/tags", `{"add":["bad/tag"]}`); code != http.StatusBadRequest {
		t.Fatalf("invalid tag = %d, want 400", code)
	}
	many := make([]string, 0, store.MaxTagsPerSession+1)
	for i := 0; i <= store.MaxTagsPerSession; i++ {
		many = append(many, "\"t"+string(rune('a'+i))+"\"")
	}
	over := `{"add":[` + strings.Join(many, ",") + `]}`
	if code, _ := doJSON(t, s, http.MethodPost, "/api/session/sess-a/tags", over); code != http.StatusBadRequest {
		t.Fatalf("over-cap add = %d, want 400", code)
	}
	// GET on the sub-route is a read-only snapshot of the current state
	// (used by SessionEnrichmentHeader) — it must NOT mutate anything.
	code, body = doJSON(t, s, http.MethodGet, "/api/session/sess-a/tags", "")
	if code != http.StatusOK {
		t.Fatalf("GET /tags = %d, want 200", code)
	}
	tags, _ = body["tags"].([]any)
	if len(tags) != 1 || tags[0] != "ui-ux" {
		t.Fatalf("GET tags = %v, want [ui-ux] (unchanged by the rejected POSTs)", body["tags"])
	}
	if body["favorite"] != false || body["note"] != "baseline run" {
		t.Fatalf("GET annotation = %v", body)
	}
	if _, ok := body["title"]; ok {
		t.Fatalf("GET title = %v, want omitted (empty, no title set)", body["title"])
	}

	// A method the sub-route never accepts (neither GET nor POST) is 405.
	req := httptest.NewRequest(http.MethodDelete, "/api/session/sess-a/tags", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE /tags = %d, want 405", rec.Code)
	}
}

// TestSessionTagsTitleRoundTrip pins the developer-authored title (migration
// 116): it round-trips through POST, is readable via GET without mutating
// anything, clearing it ("") garbage-collects an otherwise-empty annotation
// row, and the store's length/newline rules surface as 400s.
func TestSessionTagsTitleRoundTrip(t *testing.T) {
	s, st := newTagTestServer(t)
	ctx := context.Background()

	// No title yet: GET reads the zero annotation, and the field is omitted.
	code, body := doJSON(t, s, http.MethodGet, "/api/session/sess-a/tags", "")
	if code != http.StatusOK {
		t.Fatalf("GET /tags = %d", code)
	}
	if _, ok := body["title"]; ok {
		t.Fatalf("untitled session title = %v, want omitted", body["title"])
	}

	code, body = doJSON(t, s, http.MethodPost, "/api/session/sess-a/tags", `{"title":"the compression baseline"}`)
	if code != http.StatusOK {
		t.Fatalf("POST title = %d", code)
	}
	if body["title"] != "the compression baseline" {
		t.Fatalf("POST title echo = %v", body)
	}
	annot, err := st.GetSessionAnnotation(ctx, "sess-a")
	if err != nil {
		t.Fatalf("GetSessionAnnotation: %v", err)
	}
	if annot.Title != "the compression baseline" {
		t.Fatalf("persisted title = %q", annot.Title)
	}

	// GET reflects the persisted title without touching it.
	_, body = doJSON(t, s, http.MethodGet, "/api/session/sess-a/tags", "")
	if body["title"] != "the compression baseline" {
		t.Fatalf("GET title = %v", body)
	}

	// Clearing the title ("") is a valid mutation, distinct from omitting the
	// field (which leaves it untouched).
	code, body = doJSON(t, s, http.MethodPost, "/api/session/sess-a/tags", `{"title":""}`)
	if code != http.StatusOK {
		t.Fatalf("clear title = %d", code)
	}
	if _, ok := body["title"]; ok {
		t.Fatalf("cleared title = %v, want omitted", body["title"])
	}
	annot, err = st.GetSessionAnnotation(ctx, "sess-a")
	if err != nil {
		t.Fatalf("GetSessionAnnotation: %v", err)
	}
	if annot.Title != "" {
		t.Fatalf("title not cleared: %q", annot.Title)
	}

	// Store-level rules surface as 400s through the handler.
	longTitle := strings.Repeat("t", store.MaxTitleLen+1)
	if code, _ := doJSON(t, s, http.MethodPost, "/api/session/sess-a/tags", `{"title":"`+longTitle+`"}`); code != http.StatusBadRequest {
		t.Fatalf("over-long title = %d, want 400", code)
	}
	if code, _ := doJSON(t, s, http.MethodPost, "/api/session/sess-a/tags", `{"title":"line one\nline two"}`); code != http.StatusBadRequest {
		t.Fatalf("newline title = %d, want 400", code)
	}
	// Neither rejected mutation touched the (already-cleared) title.
	annot, err = st.GetSessionAnnotation(ctx, "sess-a")
	if err != nil {
		t.Fatalf("GetSessionAnnotation: %v", err)
	}
	if annot.Title != "" {
		t.Fatalf("a rejected title mutation still wrote: %q", annot.Title)
	}
}

// TestSessionsTagFilterPaginationCoherence is the plan §7 handler obligation:
// the tag= and favorite= filters must land in the SHARED where slice so `total`
// and `scored_count` describe the FILTERED set, not the whole corpus. Repeated
// tag= is AND, not OR.
func TestSessionsTagFilterPaginationCoherence(t *testing.T) {
	s, st := newTagTestServer(t)
	ctx := context.Background()
	if err := st.MutateSessionTags(ctx, "sess-a", []string{"backend", "experiment"}, nil); err != nil {
		t.Fatalf("tag sess-a: %v", err)
	}
	if err := st.MutateSessionTags(ctx, "sess-b", []string{"backend"}, nil); err != nil {
		t.Fatalf("tag sess-b: %v", err)
	}
	yes := true
	if err := st.SetSessionAnnotation(ctx, "sess-c", &yes, nil, nil, nil); err != nil {
		t.Fatalf("favorite sess-c: %v", err)
	}

	// Unfiltered baseline.
	_, body := doJSON(t, s, http.MethodGet, "/api/sessions?limit=50&days=30", "")
	if body["total"].(float64) != 3 {
		t.Fatalf("baseline total = %v, want 3", body["total"])
	}

	// One tag → 2 sessions, and `total` agrees with the row count.
	_, body = doJSON(t, s, http.MethodGet, "/api/sessions?limit=50&days=30&tag=backend", "")
	rows := body["rows"].([]any)
	if len(rows) != 2 || body["total"].(float64) != 2 {
		t.Fatalf("tag=backend: rows=%d total=%v, want 2/2", len(rows), body["total"])
	}

	// Two tags → AND semantics (only sess-a carries both).
	_, body = doJSON(t, s, http.MethodGet, "/api/sessions?limit=50&days=30&tag=backend&tag=experiment", "")
	rows = body["rows"].([]any)
	if len(rows) != 1 || body["total"].(float64) != 1 {
		t.Fatalf("AND filter: rows=%d total=%v, want 1/1", len(rows), body["total"])
	}
	first := rows[0].(map[string]any)
	if first["id"] != "sess-a" {
		t.Fatalf("AND filter returned %v", first["id"])
	}
	gotTags, _ := first["tags"].([]any)
	if len(gotTags) != 2 {
		t.Fatalf("row tags = %v, want the batched per-page attach", first["tags"])
	}

	// favorite=1 selects only the starred session and reports favorite:true.
	_, body = doJSON(t, s, http.MethodGet, "/api/sessions?limit=50&days=30&favorite=1", "")
	rows = body["rows"].([]any)
	if len(rows) != 1 || body["total"].(float64) != 1 {
		t.Fatalf("favorite filter: rows=%d total=%v, want 1/1", len(rows), body["total"])
	}
	if rows[0].(map[string]any)["favorite"] != true {
		t.Fatalf("favorite row = %v", rows[0])
	}

	// A tag that normalizes to nothing valid is a 400, not a silent full list.
	req := httptest.NewRequest(http.MethodGet, "/api/sessions?tag=bad%2Ftag", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed tag = %d, want 400", rec.Code)
	}
}

// TestSessionsFavoriteSort pins the new `favorite` sort key: starred sessions
// come first by default (desc), and the key survives the allow-list clamp.
func TestSessionsFavoriteSort(t *testing.T) {
	s, st := newTagTestServer(t)
	yes := true
	if err := st.SetSessionAnnotation(context.Background(), "sess-a", &yes, nil, nil, nil); err != nil {
		t.Fatalf("favorite sess-a: %v", err)
	}

	_, body := doJSON(t, s, http.MethodGet, "/api/sessions?limit=50&days=30&sort_by=favorite", "")
	if body["sort_by"] != "favorite" {
		t.Fatalf("sort_by echoed as %v — the allow-list dropped it", body["sort_by"])
	}
	rows := body["rows"].([]any)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if rows[0].(map[string]any)["id"] != "sess-a" {
		t.Fatalf("favorite sort put %v first, want sess-a", rows[0].(map[string]any)["id"])
	}
	// Ascending flips it.
	_, body = doJSON(t, s, http.MethodGet, "/api/sessions?limit=50&days=30&sort_by=favorite&sort_dir=asc", "")
	rows = body["rows"].([]any)
	if rows[len(rows)-1].(map[string]any)["id"] != "sess-a" {
		t.Fatalf("asc favorite sort put %v last, want sess-a", rows[len(rows)-1])
	}
}

// TestSessionsRatingSort pins the `rating` sort key: the highest-rated session
// comes first by default (desc), sort_dir=asc surfaces the worst-rated
// (unrated=0 to the top), and the key survives the allow-list clamp.
func TestSessionsRatingSort(t *testing.T) {
	s, st := newTagTestServer(t)
	ctx := context.Background()
	nine, three := 9, 3
	if err := st.SetSessionAnnotation(ctx, "sess-a", nil, nil, &three, nil); err != nil {
		t.Fatalf("rate sess-a: %v", err)
	}
	if err := st.SetSessionAnnotation(ctx, "sess-b", nil, nil, &nine, nil); err != nil {
		t.Fatalf("rate sess-b: %v", err)
	}
	// sess-c is left unrated (rating 0).

	_, body := doJSON(t, s, http.MethodGet, "/api/sessions?limit=50&days=30&sort_by=rating", "")
	if body["sort_by"] != "rating" {
		t.Fatalf("sort_by echoed as %v — the allow-list dropped it", body["sort_by"])
	}
	rows := body["rows"].([]any)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if rows[0].(map[string]any)["id"] != "sess-b" {
		t.Fatalf("rating desc put %v first, want sess-b (rating 9)", rows[0].(map[string]any)["id"])
	}
	// The top row also carries the numeric rating on the wire.
	if got := rows[0].(map[string]any)["rating"]; got != float64(9) {
		t.Fatalf("sess-b rating on the wire = %v, want 9", got)
	}
	// Ascending flips it: the unrated session (0) sinks to the top.
	_, body = doJSON(t, s, http.MethodGet, "/api/sessions?limit=50&days=30&sort_by=rating&sort_dir=asc", "")
	rows = body["rows"].([]any)
	if rows[len(rows)-1].(map[string]any)["id"] != "sess-b" {
		t.Fatalf("asc rating sort put %v last, want sess-b", rows[len(rows)-1])
	}
	if rows[0].(map[string]any)["id"] != "sess-c" {
		t.Fatalf("asc rating sort put %v first, want the unrated sess-c", rows[0].(map[string]any)["id"])
	}
}

// TestSessionsTagsRollup pins GET /api/sessions/tags: one row per tag with the
// session count and the summed cost/tokens of the sessions carrying it, from a
// single cost-engine pass.
func TestSessionsTagsRollup(t *testing.T) {
	s, st := newTagTestServer(t)
	ctx := context.Background()
	if err := st.MutateSessionTags(ctx, "sess-a", []string{"backend"}, nil); err != nil {
		t.Fatalf("tag a: %v", err)
	}
	if err := st.MutateSessionTags(ctx, "sess-b", []string{"backend", "junk"}, nil); err != nil {
		t.Fatalf("tag b: %v", err)
	}

	code, body := doJSON(t, s, http.MethodGet, "/api/sessions/tags", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/sessions/tags = %d", code)
	}
	rows := body["tags"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rollup rows = %v, want 2 tags", rows)
	}
	byTag := map[string]map[string]any{}
	for _, r := range rows {
		m := r.(map[string]any)
		byTag[m["tag"].(string)] = m
	}
	if byTag["backend"]["sessions"].(float64) != 2 {
		t.Fatalf("backend sessions = %v, want 2", byTag["backend"]["sessions"])
	}
	if byTag["junk"]["sessions"].(float64) != 1 {
		t.Fatalf("junk sessions = %v, want 1", byTag["junk"]["sessions"])
	}
	// sess-a = 1000 in / 100 out, sess-b = 2000 / 200 → backend covers both.
	if got := byTag["backend"]["tokens"].(float64); got != 3300 {
		t.Fatalf("backend tokens = %v, want 3300", got)
	}
	if got := byTag["junk"]["tokens"].(float64); got != 2200 {
		t.Fatalf("junk tokens = %v, want 2200", got)
	}
	if byTag["backend"]["cost_usd"].(float64) <= 0 {
		t.Fatalf("backend cost_usd = %v, want > 0", byTag["backend"]["cost_usd"])
	}

	// Empty vocabulary emits [] not null.
	s2, _ := newTagTestServer(t)
	_, body = doJSON(t, s2, http.MethodGet, "/api/sessions/tags", "")
	if rows, ok := body["tags"].([]any); !ok || len(rows) != 0 {
		t.Fatalf("empty vocabulary = %#v, want []", body["tags"])
	}
}

// TestSessionsTagsManage pins POST /api/sessions/tags/manage: rename merges,
// delete drops, the XOR body contract is enforced, and non-POST is 405.
func TestSessionsTagsManage(t *testing.T) {
	s, st := newTagTestServer(t)
	ctx := context.Background()
	if err := st.MutateSessionTags(ctx, "sess-a", []string{"be", "backend"}, nil); err != nil {
		t.Fatalf("tag a: %v", err)
	}
	if err := st.MutateSessionTags(ctx, "sess-b", []string{"be"}, nil); err != nil {
		t.Fatalf("tag b: %v", err)
	}

	code, body := doJSON(t, s, http.MethodPost, "/api/sessions/tags/manage",
		`{"rename":{"from":"be","to":"backend"}}`)
	if code != http.StatusOK || body["affected"].(float64) != 2 {
		t.Fatalf("rename = %d %v, want 200/affected 2", code, body)
	}
	tags, _ := st.SessionTags(ctx, "sess-a")
	if len(tags) != 1 || tags[0] != "backend" {
		t.Fatalf("sess-a after merge = %v", tags)
	}

	code, body = doJSON(t, s, http.MethodPost, "/api/sessions/tags/manage", `{"delete":"backend"}`)
	if code != http.StatusOK || body["affected"].(float64) != 2 {
		t.Fatalf("delete = %d %v, want 200/affected 2", code, body)
	}
	if vocab, _ := st.TagVocabulary(ctx); len(vocab) != 0 {
		t.Fatalf("vocabulary after delete = %v", vocab)
	}

	for _, bad := range []string{`{}`, `{"rename":{"from":"a","to":"b"},"delete":"c"}`} {
		if code, _ := doJSON(t, s, http.MethodPost, "/api/sessions/tags/manage", bad); code != http.StatusBadRequest {
			t.Fatalf("body %s = %d, want 400", bad, code)
		}
	}
	if code, _ := doJSON(t, s, http.MethodPost, "/api/sessions/tags/manage", `{"delete":"bad/tag"}`); code != http.StatusBadRequest {
		t.Fatalf("invalid tag = %d, want 400", code)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/sessions/tags/manage", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET manage = %d, want 405", rec.Code)
	}
}

// TestSessionDetailCarriesClassification pins the detail payload extension:
// tags is always present (never null) and favorite/note round-trip.
func TestSessionDetailCarriesClassification(t *testing.T) {
	s, st := newTagTestServer(t)
	ctx := context.Background()

	_, body := doJSON(t, s, http.MethodGet, "/api/session/sess-a", "")
	if tags, ok := body["tags"].([]any); !ok || len(tags) != 0 {
		t.Fatalf("unclassified detail tags = %#v, want []", body["tags"])
	}
	if body["favorite"] != false {
		t.Fatalf("unclassified detail favorite = %v", body["favorite"])
	}

	if err := st.MutateSessionTags(ctx, "sess-a", []string{"experiment"}, nil); err != nil {
		t.Fatalf("tag: %v", err)
	}
	yes := true
	note := "compression baseline"
	if err := st.SetSessionAnnotation(ctx, "sess-a", &yes, &note, nil, nil); err != nil {
		t.Fatalf("annotate: %v", err)
	}
	_, body = doJSON(t, s, http.MethodGet, "/api/session/sess-a", "")
	tags := body["tags"].([]any)
	if len(tags) != 1 || tags[0] != "experiment" {
		t.Fatalf("detail tags = %v", body["tags"])
	}
	if body["favorite"] != true || body["note"] != note {
		t.Fatalf("detail annotation = %v", body)
	}
}

// TestSessionsTagsRollupChunksPastBindLimit is the revert-proof pin on the
// bind-variable ceiling (codex HIGH #1). tagRollup scopes EVERY tagged session
// id into the cost engine; before the fix that was ONE `IN (...)` list, and
// SQLite refuses a statement carrying more than 32766 bound parameters ("too
// many SQL variables"). Because tagRollup treats a cost error as an enrichment
// failure and degrades to counts, the symptom was not a 500 but silently ZEROED
// cost/token columns on every row — so this test asserts the TOTALS, not merely
// the absence of an error.
//
// The filler rows are tag assignments for session ids that carry no cost rows:
// session_tags has no FK (migration 075, by design), so padding the id set past
// the ceiling costs one bulk insert rather than 33k seeded sessions, and the
// expected token total stays exactly the three real sessions'.
func TestSessionsTagsRollupChunksPastBindLimit(t *testing.T) {
	s, st := newTagTestServer(t)
	ctx := context.Background()
	for _, sid := range []string{"sess-a", "sess-b", "sess-c"} {
		if err := st.MutateSessionTags(ctx, sid, []string{"bulk"}, nil); err != nil {
			t.Fatalf("tag %s: %v", sid, err)
		}
	}

	// 33_000 > 32766 = SQLITE_MAX_VARIABLE_NUMBER in modernc.org/sqlite.
	const filler = 33_000
	tx, err := s.db().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO session_tags (session_id, tag, created_at) VALUES (?, 'bulk', '2026-07-30T00:00:00Z')`)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	for i := 0; i < filler; i++ {
		if _, err := stmt.ExecContext(ctx, fmt.Sprintf("filler-%06d", i)); err != nil {
			t.Fatalf("insert filler %d: %v", i, err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatalf("stmt.Close: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	code, body := doJSON(t, s, http.MethodGet, "/api/sessions/tags", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/sessions/tags = %d", code)
	}
	rows := body["tags"].([]any)
	if len(rows) != 1 {
		t.Fatalf("rollup rows = %d, want 1 (only 'bulk')", len(rows))
	}
	row := rows[0].(map[string]any)
	if got := row["sessions"].(float64); got != filler+3 {
		t.Fatalf("bulk sessions = %v, want %d", got, filler+3)
	}
	// sess-a 1100 + sess-b 2200 + sess-c 3300 — the filler ids price to nothing.
	if got := row["tokens"].(float64); got != 6600 {
		t.Fatalf("bulk tokens = %v, want 6600 — the cost pass was dropped (bind-limit regression)", got)
	}
	if got := row["cost_usd"].(float64); got <= 0 {
		t.Fatalf("bulk cost_usd = %v, want > 0 — the cost pass was dropped (bind-limit regression)", got)
	}
}

// TestSessionsTagFilterCappedAndDeduped pins the repeatable `tag=` param's
// bounds (codex MEDIUM #2): each accepted tag appends a correlated EXISTS to a
// WHERE clause executed by the page query, the `total` COUNT and scored_count,
// so an uncapped list is an authenticated amplification lever. Duplicates
// (after normalization) collapse instead of multiplying the chain, and >8
// DISTINCT tags is a 400 with a clear message rather than a slow 200 or a 500.
func TestSessionsTagFilterCappedAndDeduped(t *testing.T) {
	s, st := newTagTestServer(t)
	ctx := context.Background()
	if err := st.MutateSessionTags(ctx, "sess-a", []string{"backend"}, nil); err != nil {
		t.Fatalf("tag sess-a: %v", err)
	}

	// Baseline: one filter.
	_, body := doJSON(t, s, http.MethodGet, "/api/sessions?limit=50&days=30&tag=backend", "")
	wantTotal := body["total"].(float64)
	if wantTotal != 1 {
		t.Fatalf("baseline total = %v, want 1", wantTotal)
	}

	// The SAME tag repeated (incl. a differently-cased spelling that normalizes
	// identically) must not change the answer and must not error.
	_, dup := doJSON(t, s, http.MethodGet,
		"/api/sessions?limit=50&days=30&tag=backend&tag=backend&tag=BACKEND&tag=+backend+", "")
	if got := dup["total"].(float64); got != wantTotal {
		t.Fatalf("duplicated tag total = %v, want %v (dedup changed the result)", got, wantTotal)
	}
	if len(dup["rows"].([]any)) != len(body["rows"].([]any)) {
		t.Fatalf("duplicated tag rows = %d, want %d", len(dup["rows"].([]any)), len(body["rows"].([]any)))
	}

	q := func(n int) string {
		u := "/api/sessions?limit=50&days=30"
		for i := 0; i < n; i++ {
			u += fmt.Sprintf("&tag=t%d", i)
		}
		return u
	}
	// At the cap: accepted.
	req := httptest.NewRequest(http.MethodGet, q(maxSessionTagFilters), nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d distinct tags = %d, want 200", maxSessionTagFilters, rec.Code)
	}
	// One past the cap: 400 with a message naming the limit.
	req = httptest.NewRequest(http.MethodGet, q(maxSessionTagFilters+1), nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%d distinct tags = %d, want 400", maxSessionTagFilters+1, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "too many tag filters") {
		t.Fatalf("over-cap message = %q", rec.Body.String())
	}
	// Duplicates do NOT consume cap budget: cap distinct + repeats still passes.
	req = httptest.NewRequest(http.MethodGet, q(maxSessionTagFilters)+"&tag=t0&tag=t1", nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cap distinct + duplicates = %d, want 200 (dedup must precede the cap)", rec.Code)
	}
}

// TestSessionTagsRejectsBeforeAnyWrite pins the combined-request atomicity
// (codex MEDIUM #3): tags and the annotation are two store calls, so a body
// whose tags are valid but whose note is over-long used to COMMIT the tags and
// then 400 — a partial write. Everything is validated up front now, so the 400
// leaves the session exactly as it was.
func TestSessionTagsRejectsBeforeAnyWrite(t *testing.T) {
	s, st := newTagTestServer(t)
	ctx := context.Background()

	longNote := strings.Repeat("n", store.MaxNoteLen+1)
	code, _ := doJSON(t, s, http.MethodPost, "/api/session/sess-a/tags",
		`{"add":["x"],"note":"`+longNote+`"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("over-long note = %d, want 400", code)
	}
	tags, err := st.SessionTags(ctx, "sess-a")
	if err != nil {
		t.Fatalf("SessionTags: %v", err)
	}
	if len(tags) != 0 {
		t.Fatalf("tags = %v after a rejected request — the tag write was committed before the note was validated", tags)
	}

	// Symmetric case: a valid note alongside an INVALID tag must not write the
	// note either (validation covers the whole body, and tags are written first).
	code, _ = doJSON(t, s, http.MethodPost, "/api/session/sess-a/tags",
		`{"add":["bad/tag"],"note":"keep me out"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("invalid tag + note = %d, want 400", code)
	}
	annot, err := st.GetSessionAnnotation(ctx, "sess-a")
	if err != nil {
		t.Fatalf("GetSessionAnnotation: %v", err)
	}
	if annot.Note != "" {
		t.Fatalf("note = %q after a rejected request", annot.Note)
	}
}

// TestSessionTagsRemoteAuthzRefusesNonExecute is the PRODUCTION-behaviour pin
// behind sessionSubRouteCapabilities' (documentation-only) /tags row: what
// actually protects POST /api/session/<id>/tags on a remotely-exposed bind is
// requiredCapability's method-aware View→Execute escalation. An anonymous
// caller and a paired VIEW-only principal must both be refused, and neither may
// leave a tag behind.
func TestSessionTagsRemoteAuthzRefusesNonExecute(t *testing.T) {
	rc, enc := newReadyRemoteController(t)
	s := newRemoteTestServer(t, Options{Remote: rc})
	h := s.remoteGuardedHandler(rc)

	do := func(cookie *http.Cookie, csrf string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/session/sess-a/tags",
			strings.NewReader(`{"add":["remote-write"]}`))
		req.Host = testRemoteHost
		req.Header.Set("Origin", "https://"+testRemoteHost)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set(remoteCSRFHeader, csrf)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do(nil, ""); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Errorf("anonymous POST /api/session/sess-a/tags = %d, want 401/403", code)
	}
	cookie, csrf := pairSession(t, h, enc)
	if code := do(cookie, csrf); code != http.StatusForbidden {
		t.Errorf("view principal POST /api/session/sess-a/tags = %d, want 403", code)
	}
	tags, err := store.New(s.db()).SessionTags(context.Background(), "sess-a")
	if err != nil {
		t.Fatalf("SessionTags: %v", err)
	}
	if len(tags) != 0 {
		t.Fatalf("a refused remote request still wrote tags: %v", tags)
	}
}
