package antigravity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeCLILog mirrors the lines we care about from a real
// cli-YYYYMMDD_HHMMSS.log captured on 2026-05-23 from agy v0+ on
// WSL2. Only the project-binding + creation lines are kept; surrounding
// noise (auth retries, redraw events) is omitted because the parser
// doesn't depend on it.
const fakeCLILog = `I0523 14:12:09.620642  8011 project.go:141] project: created project "/home/u/code/proj-a" (id=11111111-2222-3333-4444-555555555555) at /home/u/.gemini/config/projects/11111111-2222-3333-4444-555555555555.json, symlinked from /home/u/code/proj-a/.antigravitycli/11111111-2222-3333-4444-555555555555.json
I0523 14:13:00.169616  8011 conversation_manager.go:284] Starting new conversation (agent=false)
I0523 14:13:00.169651  8011 server.go:726] Conversation using project ID: 11111111-2222-3333-4444-555555555555
I0523 14:13:00.172473  8011 server.go:747] Created conversation aaaa1111-2222-3333-4444-555555555555
I0523 15:30:00.500000  8011 conversation_manager.go:284] Starting new conversation (agent=false)
I0523 15:30:00.510000  8011 server.go:726] Conversation using project ID: 11111111-2222-3333-4444-555555555555
I0523 15:30:00.512000  8011 server.go:747] Created conversation bbbb1111-2222-3333-4444-555555555555
`

const fakeCLIProjectJSON = `{
  "id": "11111111-2222-3333-4444-555555555555",
  "name": "/home/u/code/proj-a",
  "projectResources": {
    "resources": [
      {
        "gitFolder": {
          "folderUri": "file:///home/u/code/proj-a",
          "allowWrite": true
        }
      }
    ]
  }
}`

// setupFakeCLILayout builds a tmp tree mirroring the on-disk shape of
// a real Antigravity-CLI install, with one project + two conversations
// and one project JSON. Returns the .pb path the adapter would parse.
func setupFakeCLILayout(t *testing.T, conversationID string) (pbPath string) {
	t.Helper()
	homeDir := t.TempDir()
	cliRoot := filepath.Join(homeDir, ".gemini", "antigravity-cli")
	logDir := filepath.Join(cliRoot, "log")
	convDir := filepath.Join(cliRoot, "conversations")
	projDir := filepath.Join(homeDir, ".gemini", "config", "projects")
	for _, d := range []string{logDir, convDir, projDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(logDir, "cli-20260523_141208.log"), []byte(fakeCLILog), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projDir, "11111111-2222-3333-4444-555555555555.json"), []byte(fakeCLIProjectJSON), 0o644); err != nil {
		t.Fatalf("write project: %v", err)
	}
	pbPath = filepath.Join(convDir, conversationID+".pb")
	if err := os.WriteFile(pbPath, []byte("dummy"), 0o644); err != nil {
		t.Fatalf("write pb: %v", err)
	}
	return pbPath
}

func TestLookupCLIIndexEntry(t *testing.T) {
	pbPath := setupFakeCLILayout(t, "aaaa1111-2222-3333-4444-555555555555")
	a := NewWithOptions(nil, filepath.Dir(pbPath))

	entry := a.lookupCLIIndexEntry(pbPath, "aaaa1111-2222-3333-4444-555555555555")
	if entry == nil {
		t.Fatal("lookupCLIIndexEntry returned nil for known conversation")
	}
	if entry.title != "/home/u/code/proj-a" {
		t.Errorf("title = %q, want %q", entry.title, "/home/u/code/proj-a")
	}
	if entry.workspaceURI != "file:///home/u/code/proj-a" {
		t.Errorf("workspaceURI = %q, want file:///home/u/code/proj-a", entry.workspaceURI)
	}
	if entry.created.Month() != time.May || entry.created.Day() != 23 {
		t.Errorf("created month/day = %v/%v, want May/23 (year tolerated from fallback)", entry.created.Month(), entry.created.Day())
	}
	if entry.created.Hour() != 14 || entry.created.Minute() != 13 {
		t.Errorf("created hh:mm = %02d:%02d, want 14:13", entry.created.Hour(), entry.created.Minute())
	}
}

// TestLookupCLIIndexEntryDefaultProjectWorkspace covers the no-active-workspace
// "default-cli-project" session: the project id in the log is NOT a UUID (so
// the project-json path can't resolve a folder), but agy still logs the launch
// workspace dir. The conversation must attribute to that dir instead of the
// "[antigravity]" placeholder — the operator-reported "no project folder" bug.
func TestLookupCLIIndexEntryDefaultProjectWorkspace(t *testing.T) {
	homeDir := t.TempDir()
	cliRoot := filepath.Join(homeDir, ".gemini", "antigravity-cli")
	logDir := filepath.Join(cliRoot, "log")
	convDir := filepath.Join(cliRoot, "conversations")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(convDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Real default-cli-project log shape: workspace dir logged at init,
	// non-UUID project id, then the conversation create.
	log := `I0627 03:38:20.174511 790310 server.go:217] Creating CLI server backend: product=antigravity workspaceDirs=[/home/marmutapp/superbased-observer] appDataDir=/home/marmutapp/.gemini/antigravity-cli
I0627 03:38:20.183839 790310 manager.go:303] Initializing CLI store manager for workspace /home/marmutapp/superbased-observer
I0627 03:38:24.879323 790310 server.go:771] Conversation using project ID: default-cli-project
I0627 03:38:24.957272 790310 server.go:800] Created conversation 7204d1d1-882b-404b-a03b-81dd9b06c3ee
`
	if err := os.WriteFile(filepath.Join(logDir, "cli-20260627_033819.log"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	pbPath := filepath.Join(convDir, "7204d1d1-882b-404b-a03b-81dd9b06c3ee.pb")
	if err := os.WriteFile(pbPath, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, filepath.Dir(pbPath))
	entry := a.lookupCLIIndexEntry(pbPath, "7204d1d1-882b-404b-a03b-81dd9b06c3ee")
	if entry == nil {
		t.Fatal("lookupCLIIndexEntry returned nil for default-cli-project conversation")
	}
	if entry.workspaceURI != "file:///home/marmutapp/superbased-observer" {
		t.Errorf("workspaceURI = %q, want file:///home/marmutapp/superbased-observer", entry.workspaceURI)
	}
	if got, _, _ := decodeFileURIToRoot(entry.workspaceURI); got != "/home/marmutapp/superbased-observer" {
		t.Errorf("decoded root = %q, want /home/marmutapp/superbased-observer", got)
	}
}

func TestLookupCLIIndexEntryUnknownConversation(t *testing.T) {
	pbPath := setupFakeCLILayout(t, "aaaa1111-2222-3333-4444-555555555555")
	a := NewWithOptions(nil, filepath.Dir(pbPath))
	if got := a.lookupCLIIndexEntry(pbPath, "ffffffff-2222-3333-4444-555555555555"); got != nil {
		t.Fatalf("expected nil for unknown conversation, got %+v", got)
	}
}

func TestLookupCLIIndexEntrySecondConversation(t *testing.T) {
	// Same log file has TWO conversations on the same project. Looking
	// up the second one exercises the multi-binding cache path.
	pbPath := setupFakeCLILayout(t, "bbbb1111-2222-3333-4444-555555555555")
	a := NewWithOptions(nil, filepath.Dir(pbPath))
	entry := a.lookupCLIIndexEntry(pbPath, "bbbb1111-2222-3333-4444-555555555555")
	if entry == nil {
		t.Fatal("lookupCLIIndexEntry returned nil for second conversation")
	}
	if entry.created.Hour() != 15 || entry.created.Minute() != 30 {
		t.Errorf("created hh:mm = %02d:%02d, want 15:30", entry.created.Hour(), entry.created.Minute())
	}
}

func TestLookupIndexEntryDispatchByLayout(t *testing.T) {
	// CLI layout must route through lookupCLIIndexEntry — the desktop
	// path returns nil because no state.vscdb exists in the fake tree.
	pbPath := setupFakeCLILayout(t, "aaaa1111-2222-3333-4444-555555555555")
	a := NewWithOptions(nil, filepath.Dir(pbPath))
	entry := a.lookupIndexEntry(pbPath, "aaaa1111-2222-3333-4444-555555555555")
	if entry == nil {
		t.Fatal("lookupIndexEntry returned nil; expected CLI path to resolve")
	}
	if !strings.Contains(entry.title, "proj-a") {
		t.Errorf("title = %q, want substring 'proj-a'", entry.title)
	}
}

func TestCliRootsFor(t *testing.T) {
	homeDir := t.TempDir()
	cliRoot := filepath.Join(homeDir, ".gemini", "antigravity-cli")
	convDir := filepath.Join(cliRoot, "conversations")
	if err := os.MkdirAll(convDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pbPath := filepath.Join(convDir, "abc.pb")

	gotCLI, gotGemini := cliRootsFor(pbPath)
	if gotCLI != cliRoot {
		t.Errorf("cliRoot = %q, want %q", gotCLI, cliRoot)
	}
	if gotGemini != filepath.Join(homeDir, ".gemini") {
		t.Errorf("geminiRoot = %q, want %q", gotGemini, filepath.Join(homeDir, ".gemini"))
	}

	// Non-CLI path → empty.
	cli2, gem2 := cliRootsFor("/home/u/some/random/path.pb")
	if cli2 != "" || gem2 != "" {
		t.Errorf("expected empty roots for unrelated path, got cli=%q gemini=%q", cli2, gem2)
	}
}

func TestParseCLILogTimestamp(t *testing.T) {
	fallback := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	got := parseCLILogTimestamp("I0523 14:13:00.172473  8011 server.go:747] Created conversation abc", fallback)
	want := time.Date(2026, time.May, 23, 14, 13, 0, 172473000, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}

	// Malformed lines return zero time.
	if !parseCLILogTimestamp("not a glog line", fallback).IsZero() {
		t.Error("expected zero time for non-glog line")
	}
}
