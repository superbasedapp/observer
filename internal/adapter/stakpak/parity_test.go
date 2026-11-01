package stakpak

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// repoDir builds a throwaway git working tree whose HEAD names branch.
func repoDir(t *testing.T, branch string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/"+branch+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestGitBranchStamped pins that the session's branch (resolved from the
// cwd's git identity) rides every row the parse emits.
func TestGitBranchStamped(t *testing.T) {
	dbPath, root := emptyStore(t)
	repo := repoDir(t, "feat/parity")
	addSession(t, dbPath, "s1", repo)
	addCheckpoint(t, dbPath, "c1", "s1", "", "2026-10-21T07:00:01+00:00", stateJSON(`{"role":"user","content":"hi"}`))
	addCheckpoint(t, dbPath, "c2", "s1", "c1", "2026-10-21T07:00:02+00:00", stateJSON(
		`{"role":"user","content":"hi"}`,
		`{"role":"assistant","content":"hello","tool_calls":[{"id":"t1","type":"function","function":{"name":"stakpak__run_command","arguments":"{\"command\":\"ls\"}"}}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`))
	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) < 4 || len(res.TokenEvents) != 1 {
		t.Fatalf("events = %d tool / %d token, want >=4 / 1", len(res.ToolEvents), len(res.TokenEvents))
	}
	for _, ev := range res.ToolEvents {
		if ev.GitBranch != "feat/parity" {
			t.Errorf("%s GitBranch = %q", ev.SourceEventID, ev.GitBranch)
		}
	}
	for _, tk := range res.TokenEvents {
		if tk.GitBranch != "feat/parity" {
			t.Errorf("%s GitBranch = %q", tk.SourceEventID, tk.GitBranch)
		}
	}
}

// TestUserPromptCarriesMessageID pins that a prompt groups with the
// checkpoint that introduced it.
func TestUserPromptCarriesMessageID(t *testing.T) {
	res := parseFixture(t, 0)
	got := map[string]string{}
	for _, ev := range res.ToolEvents {
		if ev.ActionType != models.ActionUserPrompt {
			continue
		}
		if ev.MessageID == "" {
			t.Errorf("prompt %s has no MessageID", ev.SourceEventID)
		}
		// SourceEventID is prompt:<checkpoint>:<index>.
		parts := strings.Split(ev.SourceEventID, ":")
		if len(parts) != 3 || parts[1] != ev.MessageID {
			t.Errorf("prompt %s MessageID = %q, want the checkpoint id", ev.SourceEventID, ev.MessageID)
		}
		if _, ok := got[ev.SessionID]; !ok {
			got[ev.SessionID] = ev.MessageID
		}
	}
	if got[winSession] != "00000000-0000-4000-8000-000000000002" {
		t.Errorf("first windows prompt MessageID = %q", got[winSession])
	}
}

// TestSessionStartRow pins the explicit session_start row: stamped from
// sessions.created_at, emitted once with the root checkpoint, and not
// repeated by a later window.
func TestSessionStartRow(t *testing.T) {
	res := parseFixture(t, 0)
	var starts []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionSessionStart {
			starts = append(starts, ev)
		}
	}
	if len(starts) != 2 {
		t.Fatalf("session_start rows = %d, want 2 (one per session)", len(starts))
	}
	for _, ev := range starts {
		if ev.SourceEventID != "session_start:"+ev.SessionID || ev.RawToolName != "stakpak.session_start" {
			t.Errorf("session_start row = %+v", ev)
		}
		if ev.Timestamp.IsZero() || ev.MessageID != "" {
			t.Errorf("session_start timestamp/message = %v/%q", ev.Timestamp, ev.MessageID)
		}
		got := ev.Timestamp.Format("2006-01-02T15:04:05.000")
		if got != "2026-10-21T07:10:31.289" && got != "2026-10-21T07:08:12.919" {
			t.Errorf("session_start time = %s, want sessions.created_at", got)
		}
	}
	// A window past the root checkpoint never re-emits it.
	later := parseFixture(t, 1)
	for _, ev := range later.ToolEvents {
		if ev.ActionType == models.ActionSessionStart && ev.SessionID == winSession {
			t.Errorf("window past the root re-emitted %s", ev.SourceEventID)
		}
	}
}

// fakeBinary writes a stand-in stakpak binary into <home>/.local/bin with the
// compiled-in banner at offset (so tests cover chunk-boundary straddling).
func fakeBinary(t *testing.T, home, name, banner string, offset int) string {
	t.Helper()
	dir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, offset+len(banner)+64)
	copy(body[offset:], banner)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSessionToolVersionFromInstalledBinary(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".stakpak", "data")
	dbPath := filepath.Join(root, "local.db")
	if err := buildDB(dbPath, schemaOnly); err != nil {
		t.Fatal(err)
	}
	addSession(t, dbPath, "s-b", "")
	addSession(t, dbPath, "s-a", "")
	addCheckpoint(t, dbPath, "c1", "s-a", "", "2026-10-21T07:00:01+00:00", stateJSON(`{"role":"user","content":"a"}`))
	addCheckpoint(t, dbPath, "c2", "s-b", "", "2026-10-21T07:00:02+00:00", stateJSON(`{"role":"user","content":"b"}`))
	a := NewWithOptions(nil, []string{root})

	// No binary installed: nothing is stamped (honest unknown).
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionToolVersions) != 0 {
		t.Fatalf("no binary, got versions %+v", res.SessionToolVersions)
	}

	// The banner straddles the first 4 MiB chunk boundary.
	fakeBinary(t, home, "stakpak", "stakpak v9.8.7 (https://github.com/stakpak/agent)\n", scanChunk-20)
	res, err = a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []models.SessionToolVersion{{SessionID: "s-a", Version: "9.8.7"}, {SessionID: "s-b", Version: "9.8.7"}}
	if len(res.SessionToolVersions) != 2 || res.SessionToolVersions[0] != want[0] || res.SessionToolVersions[1] != want[1] {
		t.Fatalf("versions = %+v, want %+v", res.SessionToolVersions, want)
	}

	// An upgraded binary (new size) is re-read; a pre-release tail is kept.
	fakeBinary(t, home, "stakpak", "stakpak v9.9.0-rc.1 (https://github.com/stakpak/agent)\n", 100)
	res, err = a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionToolVersions) != 2 || res.SessionToolVersions[0].Version != "9.9.0-rc.1" {
		t.Fatalf("after upgrade versions = %+v", res.SessionToolVersions)
	}
}

func TestInstalledVersionRejectsForeignAndMissing(t *testing.T) {
	home := t.TempDir()
	if got := installedVersion(filepath.Join(home, "elsewhere", "local.db")); got != "" {
		t.Errorf("store not under .stakpak/data gave %q", got)
	}
	p := fakeBinary(t, home, "stakpak.exe", "no banner here", 10)
	if got := binaryVersion(p); got != "" {
		t.Errorf("bannerless binary gave %q", got)
	}
	if got := binaryVersion(filepath.Join(home, "absent")); got != "" {
		t.Errorf("absent binary gave %q", got)
	}
	if got := storeHome(filepath.Join(home, ".stakpak", "data", "local.db")); got != home {
		t.Errorf("storeHome = %q, want %q", got, home)
	}
}

func TestReadTranscriptFixture(t *testing.T) {
	a := NewWithOptions(nil, []string{fixtureRoot})
	ctx := context.Background()
	msgs, err := a.ReadTranscript(ctx, models.Session{ID: winSession}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 4 {
		t.Fatalf("windows transcript = %d messages, want 4 (user, assistant, queued user, assistant)", len(msgs))
	}
	if msgs[0].Role != models.TranscriptUser || msgs[1].Role != models.TranscriptAssistant ||
		msgs[2].Role != models.TranscriptUser || msgs[3].Role != models.TranscriptAssistant {
		t.Errorf("roles = %v %v %v %v", msgs[0].Role, msgs[1].Role, msgs[2].Role, msgs[3].Role)
	}
	for i, m := range msgs {
		if m.Index != i || m.ID == "" || m.Time.IsZero() {
			t.Errorf("message %d = index %d id %q time %v", i, m.Index, m.ID, m.Time)
		}
		if strings.Contains(m.Text, localContextTag) {
			t.Errorf("message %d leaked the <local_context> block", i)
		}
	}
	if msgs[0].ID != "00000000-0000-4000-8000-000000000002" {
		t.Errorf("first user message id = %q, want the introducing checkpoint", msgs[0].ID)
	}
	if len(msgs[1].ToolCalls) != 1 || msgs[1].ToolCalls[0].Name != "create" || !msgs[1].ToolCalls[0].Resolved ||
		msgs[1].ToolCalls[0].ResultExcerpt != sentinelCancelled {
		t.Errorf("first exchange calls = %+v", msgs[1].ToolCalls)
	}
	if len(msgs[3].ToolCalls) != 7 {
		t.Errorf("last exchange has %d calls, want 7", len(msgs[3].ToolCalls))
	}

	// Linux session: the newest state ends with a call whose result is
	// still pending, which must stay unresolved.
	lin, err := a.ReadTranscript(ctx, models.Session{ID: linSession}, []string{fixtureDB})
	if err != nil {
		t.Fatal(err)
	}
	last := lin[len(lin)-1]
	if got := last.ToolCalls[len(last.ToolCalls)-1]; got.Resolved {
		t.Errorf("trailing call %s should be unresolved", got.ID)
	}

	// Full reader lifts the excerpt caps.
	full, err := a.ReadTranscriptFull(ctx, models.Session{ID: linSession}, nil)
	if err != nil {
		t.Fatal(err)
	}
	maxResult := func(ms []models.TranscriptMessage) int {
		n := 0
		for _, m := range ms {
			for _, c := range m.ToolCalls {
				if len(c.ResultExcerpt) > n {
					n = len(c.ResultExcerpt)
				}
			}
		}
		return n
	}
	capped, fullMax := maxResult(lin), maxResult(full)
	if capped > 310 || fullMax <= capped {
		t.Errorf("caps: capped max %d (want <=300 + ellipsis), full max %d (want >capped)", capped, fullMax)
	}
}

func TestReadTranscriptErrors(t *testing.T) {
	a := NewWithOptions(nil, []string{fixtureRoot})
	if _, err := a.ReadTranscript(context.Background(), models.Session{ID: "nope"}, nil); err == nil {
		t.Error("unknown session should error")
	}
	if _, err := a.ReadTranscript(context.Background(), models.Session{}, nil); err == nil {
		t.Error("empty session id should error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.ReadTranscript(ctx, models.Session{ID: winSession}, nil); err == nil {
		t.Error("cancelled context should error")
	}
	empty := NewWithOptions(nil, []string{filepath.Join(t.TempDir(), ".stakpak", "data")})
	if _, err := empty.ReadTranscript(context.Background(), models.Session{ID: winSession}, nil); err == nil {
		t.Error("missing store should error")
	}
}

// TestReadTranscriptFollowsLatestBranch pins that a session resumed at an
// older checkpoint reads only the branch ending in the newest write.
func TestReadTranscriptFollowsLatestBranch(t *testing.T) {
	dbPath, root := emptyStore(t)
	addSession(t, dbPath, "s1", "")
	u := `{"role":"user","content":"start"}`
	addCheckpoint(t, dbPath, "root", "s1", "", "2026-10-21T07:00:01+00:00", stateJSON(u))
	addCheckpoint(t, dbPath, "old", "s1", "root", "2026-10-21T07:00:02+00:00", stateJSON(u, `{"role":"assistant","content":"abandoned"}`))
	addCheckpoint(t, dbPath, "new", "s1", "root", "2026-10-21T07:00:03+00:00", stateJSON(u, `{"role":"assistant","content":"kept"}`))
	a := NewWithOptions(nil, []string{root})
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: "s1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[1].Text != "kept" || msgs[1].ID != "new" {
		t.Fatalf("messages = %+v", msgs)
	}
}
