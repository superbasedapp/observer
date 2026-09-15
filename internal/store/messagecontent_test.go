package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// enterpriseCapture wires the producer as an admin-managed / full-content node
// would (see cmd/observer/wireContentCapture).
func enterpriseCapture(s *Store, maxBytes int) {
	share := ShareOptions{AdminManaged: true}
	s.SetContentCapture(ContentCapture{
		ShipsRawContent: share.ShipsRawContent,
		MaxBytes:        maxBytes,
	})
}

// conversationEvents is one adapter-shaped batch: a user prompt, a tool call
// with input + output, and an assistant reply — the exact column layout the
// claudecode / opencode adapters produce (prompt body in RawToolInput,
// assistant body in ToolOutput).
func conversationEvents(ts time.Time) []models.ToolEvent {
	return []models.ToolEvent{
		{
			SourceFile: "/t/sess.jsonl", SourceEventID: "u1", SessionID: "s1",
			ProjectRoot: "/t/proj", Timestamp: ts, Tool: "opencode",
			ActionType: models.ActionUserPrompt, RawToolName: "chat.message",
			Target: "refactor the parser", PrecedingReasoning: "refactor the parser",
			RawToolInput: "refactor the parser", MessageID: "user:u1", Success: true,
		},
		{
			SourceFile: "/t/sess.jsonl", SourceEventID: "t1", SessionID: "s1",
			ProjectRoot: "/t/proj", Timestamp: ts.Add(time.Second), Tool: "opencode",
			ActionType: models.ActionReadFile, RawToolName: "read",
			Target: "/t/proj/parser.go", RawToolInput: `{"path":"/t/proj/parser.go"}`,
			ToolOutput: "package parser", MessageID: "asst:m1", Success: true,
		},
		{
			SourceFile: "/t/sess.jsonl", SourceEventID: "a1", SessionID: "s1",
			ProjectRoot: "/t/proj", Timestamp: ts.Add(2 * time.Second), Tool: "opencode",
			ActionType: models.ActionAssistantMessage, RawToolName: "opencode.assistant_text",
			Target: "I split the lexer", ToolOutput: "I split the lexer out of the parser.",
			MessageID: "asst:m1", Success: true,
		},
	}
}

func contentRows(t *testing.T, s *Store) map[string]string {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT kind, COALESCE(content,''), content_hash, COALESCE(request_id,''),
		        COALESCE(tool_use_id,''), COALESCE(session_id,''), COALESCE(source,'')
		   FROM otel_content ORDER BY id`)
	if err != nil {
		t.Fatalf("query otel_content: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var kind, content, hash, req, tuid, sess, src string
		if err := rows.Scan(&kind, &content, &hash, &req, &tuid, &sess, &src); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if sess != "s1" {
			t.Errorf("kind %s: session_id = %q, want s1", kind, sess)
		}
		if src != messageContentSource {
			t.Errorf("kind %s: source = %q, want %q", kind, src, messageContentSource)
		}
		if req == "" || tuid == "" {
			t.Errorf("kind %s: request_id/tool_use_id must be populated for idempotency, got %q/%q", kind, req, tuid)
		}
		if hash == "" {
			t.Errorf("kind %s: content_hash must always be present", kind)
		}
		out[kind+"|"+tuid] = content
	}
	return out
}

// TestMessageContent_GateOffWritesNothing is the MUTATION-PROOF test for the
// producer gate: a metadata-only node (no ContentCapture wired, and one wired
// from a zero ShareOptions) must leave the local DB byte-identical to the
// pre-producer build. Deleting the capturesMessageContent() check in
// captureMessageContent fails this by name.
func TestMessageContent_GateOffWritesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ts := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name string
		wire func(*Store)
	}{
		{"never wired", func(*Store) {}},
		{"wired from a metadata-only share posture", func(s *Store) {
			share := ShareOptions{} // the v1.8.0 default: no full_content, no admin_managed
			s.SetContentCapture(ContentCapture{ShipsRawContent: share.ShipsRawContent})
		}},
		{"wired but the capture level is off", func(s *Store) {
			s.SetContentCapture(ContentCapture{ShipsRawContent: func() bool { return false }})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			tc.wire(s)
			res, err := s.Ingest(ctx, conversationEvents(ts), nil, IngestOptions{})
			if err != nil {
				t.Fatalf("Ingest: %v", err)
			}
			if res.MessageContentRows != 0 {
				t.Errorf("MessageContentRows = %d, want 0", res.MessageContentRows)
			}
			var n int
			if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM otel_content`).Scan(&n); err != nil {
				t.Fatalf("count: %v", err)
			}
			if n != 0 {
				t.Fatalf("a metadata-only node wrote %d otel_content rows; it must write none", n)
			}
			// The rest of ingest is unaffected.
			if res.ActionsInserted != 3 {
				t.Errorf("ActionsInserted = %d, want 3", res.ActionsInserted)
			}
		})
	}
}

// TestMessageContent_AdminManagedCapturesKinds pins the enterprise behaviour:
// prompts, tool input, tool output and assistant replies all land, each under
// the kind the org viewer renders.
func TestMessageContent_AdminManagedCapturesKinds(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	enterpriseCapture(s, 0)
	ctx := context.Background()
	ts := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

	res, err := s.Ingest(ctx, conversationEvents(ts), nil, IngestOptions{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if res.MessageContentRows != 4 {
		t.Fatalf("MessageContentRows = %d, want 4 (prompt + tool_input + tool_output + assistant)", res.MessageContentRows)
	}
	got := contentRows(t, s)
	want := map[string]string{
		kindPrompt + "|s1/u1":     "refactor the parser",
		kindToolInput + "|s1/t1":  `{"path":"/t/proj/parser.go"}`,
		kindToolOutput + "|s1/t1": "package parser",
		kindAssistant + "|s1/a1":  "I split the lexer out of the parser.",
	}
	for k, wantBody := range want {
		body, ok := got[k]
		if !ok {
			t.Errorf("missing row %s", k)
			continue
		}
		if body != wantBody {
			t.Errorf("%s content = %q, want %q", k, body, wantBody)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d rows, want %d: %v", len(got), len(want), got)
	}
}

// TestMessageContent_ReparseIsIdempotent pins the ON CONFLICT contract across
// the producer: a watcher re-scan of the same window re-derives the identical
// (content_hash, kind, request_id, tool_use_id) key and inserts nothing.
func TestMessageContent_ReparseIsIdempotent(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	enterpriseCapture(s, 0)
	ctx := context.Background()
	ts := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

	if _, err := s.Ingest(ctx, conversationEvents(ts), nil, IngestOptions{}); err != nil {
		t.Fatalf("first Ingest: %v", err)
	}
	res, err := s.Ingest(ctx, conversationEvents(ts), nil, IngestOptions{})
	if err != nil {
		t.Fatalf("re-parse Ingest: %v", err)
	}
	if res.MessageContentRows != 0 {
		t.Errorf("re-parse inserted %d rows, want 0", res.MessageContentRows)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM otel_content`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 4 {
		t.Fatalf("after re-parse got %d rows, want 4", n)
	}
}

// TestMessageContent_IdenticalPromptsInTwoSessionsBothLand guards the reason
// tool_use_id carries the event id: with it empty, two identical prompts would
// share (hash, kind, empty, empty) and ON CONFLICT DO NOTHING would silently drop the
// second — real data loss, not a cosmetic dedup quirk.
func TestMessageContent_IdenticalPromptsInTwoSessionsBothLand(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	enterpriseCapture(s, 0)
	ctx := context.Background()
	ts := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

	// SAME per-file event id and SAME message id in both sessions — the shape
	// an adapter with per-file counters produces. Only the session scoping in
	// eventContentKey keeps these two rows apart.
	mk := func(sess string) models.ToolEvent {
		return models.ToolEvent{
			SourceFile: "/t/" + sess + ".jsonl", SourceEventID: "1", SessionID: sess,
			ProjectRoot: "/t/proj", Timestamp: ts, Tool: "opencode",
			ActionType: models.ActionUserPrompt, RawToolInput: "run the tests",
			MessageID: "user:1", Success: true,
		}
	}
	res, err := s.Ingest(ctx, []models.ToolEvent{mk("s1"), mk("s2")}, nil, IngestOptions{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if res.MessageContentRows != 2 {
		t.Fatalf("MessageContentRows = %d, want 2 (one per session)", res.MessageContentRows)
	}
}

// TestMessageContent_TruncationHashesFullBody pins the ContentHash footgun the
// store's doc comment documents: the stored body is capped, the hash covers the
// FULL scrubbed text, so two long bodies sharing a prefix do not collide.
func TestMessageContent_TruncationHashesFullBody(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	enterpriseCapture(s, 64)
	ctx := context.Background()
	ts := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

	prefix := strings.Repeat("a", 200)
	mk := func(evID, tail string) models.ToolEvent {
		return models.ToolEvent{
			SourceFile: "/t/s.jsonl", SourceEventID: evID, SessionID: "s1",
			ProjectRoot: "/t/proj", Timestamp: ts, Tool: "opencode",
			ActionType: models.ActionUserPrompt, RawToolInput: prefix + tail,
			MessageID: "req1", Success: true,
		}
	}
	// Same request_id AND same tool_use_id, differing only past the cap: a
	// post-truncation hash would make these one row.
	same := mk("same", "-one")
	other := mk("same", "-two")
	if _, err := s.Ingest(ctx, []models.ToolEvent{same, other}, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	rows, err := s.db.QueryContext(ctx, `SELECT content, content_hash FROM otel_content ORDER BY id`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var content, hash string
		if err := rows.Scan(&content, &hash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(content) > 64 {
			t.Errorf("stored content is %d bytes, cap is 64", len(content))
		}
		hashes = append(hashes, hash)
	}
	if len(hashes) != 2 {
		t.Fatalf("got %d rows, want 2 — the hash must cover the pre-truncation body", len(hashes))
	}
	if hashes[0] == hashes[1] {
		t.Fatalf("both rows share a content_hash; the hash was taken after truncation")
	}
	if hashes[0] != HashOTelContent(prefix+"-one") {
		t.Errorf("content_hash is not the sha256 of the full body")
	}
}

// TestMessageContent_ScrubsSecrets pins requirement 4: the producer never
// stores a secret, even if an adapter handed one through unscrubbed.
func TestMessageContent_ScrubsSecrets(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	enterpriseCapture(s, 0)
	ctx := context.Background()
	ts := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

	secret := "ghp_" + strings.Repeat("Z", 36)
	ev := models.ToolEvent{
		SourceFile: "/t/s.jsonl", SourceEventID: "u1", SessionID: "s1",
		ProjectRoot: "/t/proj", Timestamp: ts, Tool: "opencode",
		ActionType: models.ActionUserPrompt, RawToolInput: "use " + secret + " please",
		MessageID: "user:u1", Success: true,
	}
	if _, err := s.Ingest(ctx, []models.ToolEvent{ev}, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	var content string
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(content,'') FROM otel_content`).Scan(&content); err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(content, secret) {
		t.Fatalf("stored content leaked the secret: %q", content)
	}
}

// TestMessageContent_SkipsEmptyAndUningestableEvents: an event Ingest itself
// skips (no session / no project root) must never conjure a content row, and an
// event with no text produces nothing.
func TestMessageContent_SkipsEmptyAndUningestableEvents(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	enterpriseCapture(s, 0)
	ctx := context.Background()
	ts := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

	evs := []models.ToolEvent{
		{
			SourceFile: "/t/s.jsonl", SourceEventID: "x1", SessionID: "", ProjectRoot: "/t/proj",
			Timestamp: ts, Tool: "opencode", ActionType: models.ActionUserPrompt, RawToolInput: "orphan",
		},
		{
			SourceFile: "/t/s.jsonl", SourceEventID: "x2", SessionID: "s1", ProjectRoot: "",
			Timestamp: ts, Tool: "opencode", ActionType: models.ActionUserPrompt, RawToolInput: "orphan",
		},
		{
			SourceFile: "/t/s.jsonl", SourceEventID: "x3", SessionID: "s1", ProjectRoot: "/t/proj",
			Timestamp: ts, Tool: "opencode", ActionType: models.ActionRunCommand, RawToolName: "bash",
			Target: "make test", RawToolInput: "   ", ToolOutput: "",
		},
	}
	res, err := s.Ingest(ctx, evs, nil, IngestOptions{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if res.MessageContentRows != 0 {
		t.Fatalf("MessageContentRows = %d, want 0", res.MessageContentRows)
	}
}

// TestMessageContent_ReachesTheOrgWire closes the loop: rows the producer wrote
// are picked up by the existing org-push seam under the existing envelope, with
// the body present under a content-sharing posture and stripped (hash only)
// without one. No wire shape changed — this is the producer feeding a wire that
// already existed.
func TestMessageContent_ReachesTheOrgWire(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	enterpriseCapture(s, 0)
	ctx := context.Background()
	ts := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

	if _, err := s.Ingest(ctx, conversationEvents(ts), nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1",
		"dev@acme.example", ShareOptions{AdminManaged: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.OTelContent) != 4 {
		t.Fatalf("wire carried %d otel_content rows, want 4", len(batch.OTelContent))
	}
	var sawPrompt bool
	for _, r := range batch.OTelContent {
		if r.ContentHash == "" {
			t.Errorf("kind %s: content_hash must always ship", r.Kind)
		}
		if r.Content == "" {
			t.Errorf("kind %s: body must ship under admin_managed", r.Kind)
		}
		if r.Kind == kindPrompt && r.Content == "refactor the parser" {
			sawPrompt = true
		}
	}
	if !sawPrompt {
		t.Error("the user prompt did not reach the wire")
	}

	// Metadata-only posture at push time still strips the body — the local
	// rows exist, the admin gets hashes only.
	stripped, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1",
		"dev@acme.example", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (metadata-only): %v", err)
	}
	if len(stripped.OTelContent) != 4 {
		t.Fatalf("metadata-only wire carried %d rows, want 4 (hash-only)", len(stripped.OTelContent))
	}
	for _, r := range stripped.OTelContent {
		if r.Content != "" {
			t.Errorf("kind %s: body shipped under a metadata-only posture", r.Kind)
		}
		if r.ContentHash == "" {
			t.Errorf("kind %s: content_hash must still ship", r.Kind)
		}
	}
}
