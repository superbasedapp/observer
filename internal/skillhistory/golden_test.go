package skillhistory

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata golden files")

// TestCompositeGolden pins the whole Result for one composite scenario
// (history with a revert, a resumed session whose skill changed, a CRLF
// working copy, a Skill-tool invocation joined by tool_use_id, a codex
// session, a home skill and a plugin invocation) so a change anywhere in
// the derivation shows up as a reviewable golden diff.
// Regenerate with: go test ./internal/skillhistory -run TestCompositeGolden -update
func TestCompositeGolden(t *testing.T) {
	in := base()
	in.Inventory = append(in.Inventory, InventoryFile{Scope: ScopeUser, RelPath: "~/.claude/skills/tidy/SKILL.md", Name: "tidy", Present: true})
	in.Timeline = []TimelineCommit{
		{SHA: sha1c, CommittedAt: at(-400), Subject: "add deploy skill", Reachable: true, Files: []string{skMD}},
		{SHA: sha2c, CommittedAt: at(-300), Subject: "tighten deploy", Reachable: true, Files: []string{skMD}},
		{SHA: sha3c, CommittedAt: at(-200), Subject: "revert", Reachable: true, Files: []string{skMD}},
	}
	in.Trees = []Tree{
		{SHA: sha1c, State: TreeOK, Files: map[string]TreeFile{skMD: {Mode: "100644", BlobOID: blobA}}},
		{SHA: sha2c, State: TreeOK, Files: map[string]TreeFile{skMD: {Mode: "100644", BlobOID: blobB}}},
		{SHA: sha3c, State: TreeOK, Files: map[string]TreeFile{skMD: {Mode: "100644", BlobOID: blobA}}},
	}
	in.HeadMoves = []HeadMove{
		{MovedAt: at(-400), SHA: sha1c, Kind: "commit"},
		{MovedAt: at(-300), SHA: sha2c, Kind: "commit"},
		{MovedAt: at(-200), SHA: sha3c, Kind: "commit"},
	}
	in.Git.HeadSHA = sha3c
	in.Git.ReflogSince = at(-400)
	crlf := mem("dddddddd44444444444444444444444444444444")
	crlf.BlobOIDLF = blobA
	home := Member{Scope: ScopeUser, RelPath: "~/.claude/skills/tidy/SKILL.md", Name: "tidy", State: MemberPresent, BlobOID: blobC}
	in.Sessions = []Session{
		{ID: "old", Tool: cc, StartedAt: at(-450)},
		{ID: "mid", Tool: cc, StartedAt: at(-250)},
		{ID: "cx", Tool: codex, StartedAt: at(-150)},
		{ID: "now", Tool: cc, StartedAt: at(0)},
	}
	in.Snapshots = []Snapshot{
		snap("mid", -250, mem(blobB), home),
		snap("mid", -220, mem(blobA), home),
		snap("now", 0, crlf, home),
		{
			SessionID: "now", Tool: cc, Event: EventSkillInvoke, ToolUseID: "tu1", ObservedAt: at(3), Complete: true, HomeResolved: true,
			Members: []Member{crlf},
		},
	}
	in.Invocations = []Invocation{
		{SessionID: "now", Tool: cc, Name: "deploy", ToolUseID: "tu1", At: at(3)},
		{SessionID: "now", Tool: cc, Name: "superpowers:plan", ToolUseID: "tu2", At: at(4)},
	}
	got, err := json.MarshalIndent(Build(in), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "composite.golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
		t.Errorf("composite result drifted from %s; rerun with -update and review the diff\ngot:\n%s", path, got)
	}
}
