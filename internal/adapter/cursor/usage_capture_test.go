package cursor

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestStoreDBStampsResolvedAutoModel: an Auto-mode ("default") CLI
// conversation names the answering model only inside its per-turn blobs.
// The blob shape is node-1's 2026-09-27 store.db (reasoning part carrying
// providerOptions.cursor.modelName), with the prose replaced.
func TestStoreDBStampsResolvedAutoModel(t *testing.T) {
	for _, tc := range []struct {
		name, modelName, want string
	}{
		{"auto_resolves_to_answering_model", "cursor-grok-4.5-high", "cursor-grok-4.5-high"},
		{"placeholder_only_stays_unset", "default", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cursorRoot := filepath.Join(t.TempDir(), ".cursor")
			conv := "c0c0c001-0000-4000-8000-000000000001"
			storeDB := filepath.Join(cursorRoot, "chats", "0850bdaac15dc73d", conv, "store.db")
			writeCursorStoreDB(t, storeDB, map[string][]byte{
				"sys": []byte(`{"role":"system","content":"You are Auto, an agent router designed by Cursor."}`),
				"asst": []byte(`{"role":"assistant","id":"msg_1","content":[{"type":"reasoning","text":"","signature":"x","providerOptions":{"cursor":{"modelName":"` +
					tc.modelName + `"}}},{"type":"text","text":"Hello."}]}`),
			})
			res, err := NewWithOptions(nil, cursorRoot).ParseSessionFile(context.Background(), storeDB, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.ToolEvents) == 0 {
				t.Fatal("no store.db rows")
			}
			for _, ev := range res.ToolEvents {
				if ev.Model != tc.want {
					t.Fatalf("%s row model = %q, want %q", ev.ActionType, ev.Model, tc.want)
				}
			}
		})
	}
}

// TestBuildTokenEventNetsBothCacheBuckets: Cursor's hook input_tokens is the
// gross prompt, INCLUDING cache reads and cache writes (the CLI itself nets
// both before printing usage), so net input subtracts both.
func TestBuildTokenEventNetsBothCacheBuckets(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		input, read, write, wantNet int64
	}{
		{"read_only", 54833, 41088, 0, 13745},
		{"read_and_write", 123, 67, 8, 48},
		{"write_only", 5000, 0, 4800, 200},
		{"anomaly_clamps_to_zero", 10, 8, 8, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"hook_event_name":"afterAgentResponse","conversation_id":"c1","generation_id":"g1","model":"m","workspace_roots":["/r"],` +
				`"input_tokens":` + strconv.FormatInt(tc.input, 10) + `,"output_tokens":5,"cache_read_tokens":` + strconv.FormatInt(tc.read, 10) + `,"cache_write_tokens":` + strconv.FormatInt(tc.write, 10) + `}`)
			ev, ok, err := BuildResponseTokenEvent(body)
			if err != nil || !ok {
				t.Fatalf("build: %v %v", ok, err)
			}
			if ev.InputTokens != tc.wantNet || ev.CacheReadTokens != tc.read || ev.CacheCreationTokens != tc.write || ev.Source != models.TokenSourceHook {
				t.Fatalf("event = %+v, want net input %d", ev, tc.wantNet)
			}
		})
	}
}

// writeOrderedStoreDB inserts blobs in the given order (rowid order is what
// ties an answer to its request).
func writeOrderedStoreDB(t *testing.T, path string, blobs ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE blobs (id TEXT PRIMARY KEY, data BLOB)`); err != nil {
		t.Fatal(err)
	}
	for i, b := range blobs {
		// ids are content hashes in real stores, so id order != insertion order.
		if _, err := db.Exec(`INSERT INTO blobs (id, data) VALUES (?, ?)`, strconv.Itoa(99-i), []byte(b)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestStoreModelLadder_PerRequestAutoRouting: Cursor bills each Auto request
// at the model it was routed to, so a store whose turns were answered by
// different models must price each generation by ITS answer.
func TestStoreModelLadder_PerRequestAutoRouting(t *testing.T) {
	home := t.TempDir()
	conv := "c0c0c001-0000-4000-8000-000000000001"
	const r1, r2 = "aaaaaaaa-0000-4000-8000-000000000001", "bbbbbbbb-0000-4000-8000-000000000002"
	user := func(rid string) string {
		return `{"role":"user","content":[{"type":"text","text":"q"}],"providerOptions":{"cursor":{"requestId":"` + rid + `"}}}`
	}
	answer := func(model string) string {
		return `{"role":"assistant","content":[{"type":"reasoning","text":"","providerOptions":{"cursor":{"modelName":"` + model + `"}}},{"type":"text","text":"a"}]}`
	}
	storeDB := filepath.Join(home, ".cursor", "chats", "ws", conv, "store.db")
	writeOrderedStoreDB(t, storeDB,
		`{"role":"system","content":"s"}`,
		user(r1), answer("composer-2.5"), "\x0a\x20protobuf-checkpoint",
		user(r2), answer("cursor-grok-4.5-high"), answer("cursor-grok-4.5-high"),
	)
	for _, tc := range []struct{ name, gen, want string }{
		{"first_request", r1, "composer-2.5"},
		{"second_request", r2, "cursor-grok-4.5-high"},
		{"ide_step_suffix", r1 + "-0-de6k", "composer-2.5"},
		{"unknown_request_falls_to_latest", "cccccccc-0000-4000-8000-000000000003", "cursor-grok-4.5-high"},
		{"no_generation_falls_to_latest", "", "cursor-grok-4.5-high"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolvePlaceholderModelIn("default", conv, tc.gen, []string{home}); got != tc.want {
				t.Fatalf("model = %q, want %q", got, tc.want)
			}
		})
	}
	if got := ResolvePlaceholderModelFor("claude-opus-5-5", conv, r1); got != "claude-opus-5-5" {
		t.Fatalf("an explicit model must never be re-resolved: %q", got)
	}
	// The CLI outcome path prices by the request's own answer, and never
	// guesses across models without one.
	a := NewWithOptions(nil, filepath.Join(home, ".cursor", "chats"))
	if m, _ := a.cliUsageContext(context.Background(), conv, r1); m != "composer-2.5" {
		t.Fatalf("cli request model = %q", m)
	}
	if m, _ := a.cliUsageContext(context.Background(), conv, ""); m != "" {
		t.Fatalf("cli without request id must not guess across models, got %q", m)
	}
}
