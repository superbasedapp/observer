package claudecode

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestTeleportTranscriptFixture pins the CA-D20 teleport rules on the
// synthetic fixture built from the 2026-10-31 probe's shape: cloud-origin
// copies (remoteSourced) contribute no tokens and no actions, the
// remote_session_change attachment becomes the lineage parent, and the
// local session is stamped cli and never vendor_cloud.
func TestTeleportTranscriptFixture(t *testing.T) {
	t.Parallel()
	const sid = "5f0c2a9e-1d4b-4c8e-9a7f-2b3c4d5e6f70"
	res, err := signalAdapter(nil).ParseSessionFile(context.Background(), fixturePath(t, filepath.Join("teleport", "teleport.jsonl")), 0)
	if err != nil {
		t.Fatal(err)
	}
	// Tokens: only the local continuation's message.
	if len(res.TokenEvents) != 1 || res.TokenEvents[0].MessageID != "msg_local_0001" || res.TokenEvents[0].OutputTokens != 40 {
		t.Fatalf("token events = %+v; want only msg_local_0001", res.TokenEvents)
	}
	for _, tk := range res.TokenEvents {
		if tk.SessionID != sid {
			t.Fatalf("token event under %q", tk.SessionID)
		}
	}
	// Actions: nothing from the copied cloud tool call or its result.
	for _, e := range res.ToolEvents {
		if e.MessageID == "msg_cloud_0001" || e.Target == "git status" || e.RawToolName == "Bash" {
			t.Fatalf("a cloud-origin copy produced an action: %+v", e)
		}
	}
	var read bool
	for _, e := range res.ToolEvents {
		if e.ActionType == models.ActionReadFile {
			read = true
		}
	}
	if !read {
		t.Fatalf("the local Read tool call is missing: %+v", res.ToolEvents)
	}
	// Lineage: a user fork of the claude.ai session, recorded as-is.
	want := models.SessionLineage{SessionID: sid, ForkedFromID: "session_01ExampleTeleportParent00", ThreadSource: "user"}
	if len(res.SessionLineages) != 1 || res.SessionLineages[0] != want {
		t.Fatalf("lineages = %+v; want %+v", res.SessionLineages, want)
	}
	// Surface: a local cli session; execution: nothing.
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceCLI {
		t.Fatalf("surface = %+v", res.SessionSurfaces)
	}
	if len(res.SessionExecutions) != 0 {
		t.Fatalf("a teleported local session was stamped %+v", res.SessionExecutions)
	}
}

// TestLineOriginTable pins the line-origin rows.
func TestLineOriginTable(t *testing.T) {
	t.Parallel()
	if lineContributes(rawLine{RemoteSourced: true}) {
		t.Fatal("a remoteSourced line contributed")
	}
	if !lineContributes(rawLine{}) {
		t.Fatal("an ordinary line did not contribute")
	}
	for _, r := range lineOriginRules {
		if r.name == "" || r.match == nil {
			t.Fatalf("unnamed row %+v", r)
		}
	}
}

// TestTeleportParent pins which attachment URLs name a lineage parent.
func TestTeleportParent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		att  *rawAttachment
		want string
	}{
		{"claude.ai session url", &rawAttachment{Type: "remote_session_change", URL: "https://claude.ai/code/session_01ExampleTeleportParent00"}, "session_01ExampleTeleportParent00"},
		{"trailing slash", &rawAttachment{Type: "remote_session_change", URL: "https://claude.ai/code/session_01ExampleTeleportParent00/"}, "session_01ExampleTeleportParent00"},
		{"another attachment type", &rawAttachment{Type: "file", URL: "https://claude.ai/code/session_01ExampleTeleportParent00"}, ""},
		{"another host", &rawAttachment{Type: "remote_session_change", URL: "https://evil.example/code/session_01ExampleTeleportParent00"}, ""},
		{"plain http", &rawAttachment{Type: "remote_session_change", URL: "http://claude.ai/code/session_01ExampleTeleportParent00"}, ""},
		{"a cse id is not a claude.ai session id", &rawAttachment{Type: "remote_session_change", URL: "https://claude.ai/code/cse_01ExampleTeleportParent00"}, ""},
		{"path characters", &rawAttachment{Type: "remote_session_change", URL: "https://claude.ai/code/session_../../x"}, ""},
		{"no attachment", nil, ""},
	}
	for _, tc := range tests {
		got, ok := teleportParent(tc.att)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: teleportParent = %q, %v; want %q", tc.name, got, ok, tc.want)
		}
	}
}

// TestTeleportFixtureLandsThroughStore runs the fixture through the store
// seam the watcher uses: the local session gets one token row (the local
// message) and the claude.ai session as its fork parent.
func TestTeleportFixtureLandsThroughStore(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	res, err := signalAdapter(nil).ParseSessionFile(ctx, fixturePath(t, filepath.Join("teleport", "teleport.jsonl")), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.New(database).Ingest(ctx, res.ToolEvents, res.TokenEvents, store.IngestOptions{
		SessionSurfaces: res.SessionSurfaces, SessionLineages: res.SessionLineages,
	}); err != nil {
		t.Fatal(err)
	}
	const sid = "5f0c2a9e-1d4b-4c8e-9a7f-2b3c4d5e6f70"
	var fork, source string
	var tokens int
	if err := database.QueryRow(`SELECT COALESCE(forked_from_id,''), COALESCE(thread_source,'') FROM sessions WHERE id = ?`, sid).Scan(&fork, &source); err != nil {
		t.Fatal(err)
	}
	_ = database.QueryRow(`SELECT COUNT(*) FROM token_usage WHERE session_id = ?`, sid).Scan(&tokens)
	if fork != "session_01ExampleTeleportParent00" || source != "user" || tokens != 1 {
		t.Fatalf("landed fork %q source %q tokens %d", fork, source, tokens)
	}
}
