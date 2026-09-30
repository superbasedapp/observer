package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/skillhistory"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func writeSkillFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// skillFixture builds a project root and a home with three skills: a
// project skill, a project skill whose frontmatter name differs from its
// directory and whose body has CRLF line endings, and a home skill.
func skillFixture(t *testing.T) (root, home string, env skillSnapEnv) {
	t.Helper()
	root, home = t.TempDir(), t.TempDir()
	writeSkillFile(t, filepath.Join(root, ".claude", "skills", "deploy", "SKILL.md"), "---\nname: deploy\ndescription: ship it\n---\nsteps\n")
	writeSkillFile(t, filepath.Join(root, ".claude", "skills", "lint", "SKILL.md"), "---\r\nname: lint-helper\r\n---\r\nrun lint\r\n")
	writeSkillFile(t, filepath.Join(home, ".claude", "skills", "tidy", "SKILL.md"), "---\nname: tidy\n---\nclean\n")
	env = productionSkillSnapEnv()
	env.ProjectRoot = func(cwd string) string { return cwd }
	env.UserHome = func() (string, error) { return home, nil }
	env.Now = func() time.Time { return time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC) }
	return root, home, env
}

func memberBy(members []store.SkillSnapshotMember, rel string) *store.SkillSnapshotMember {
	for i := range members {
		if members[i].RelPath == rel {
			return &members[i]
		}
	}
	return nil
}

func TestBuildSkillSnapshotSessionStart(t *testing.T) {
	root, home, env := skillFixture(t)
	snap, ok := buildSkillSnapshot(context.Background(), env, skillSnapRequest{
		SessionID: "s1", Event: skillhistory.EventSessionStart, Source: "startup", Cwd: root,
		TranscriptPath: filepath.Join(home, ".claude", "projects", "x", "s1.jsonl"),
	})
	if !ok || !snap.Complete || !snap.HomeResolved || len(snap.Members) != 3 {
		t.Fatalf("snapshot = ok:%v %+v", ok, snap)
	}
	deploy := memberBy(snap.Members, ".claude/skills/deploy/SKILL.md")
	wantOID, _ := guidance.GitBlobOID([]byte("---\nname: deploy\ndescription: ship it\n---\nsteps\n"))
	if deploy == nil || deploy.BlobOID != wantOID || deploy.State != skillhistory.MemberPresent || deploy.Scope != "project" {
		t.Errorf("deploy member = %+v, want blob %s", deploy, wantOID)
	}
	lint := memberBy(snap.Members, ".claude/skills/lint/SKILL.md")
	if lint == nil || lint.BlobOIDLF == "" || lint.Name != "lint-helper" {
		t.Errorf("CRLF member = %+v, want an LF blob id and the frontmatter name", lint)
	}
	if tidy := memberBy(snap.Members, "~/.claude/skills/tidy/SKILL.md"); tidy == nil || tidy.Scope != "user" {
		t.Errorf("home member = %+v", tidy)
	}
}

func TestSkillHomeLadder(t *testing.T) {
	root, home, env := skillFixture(t)
	cases := []struct {
		name       string
		hostOS     string
		cwd        string
		transcript string
		wantHome   string
		wantOK     bool
	}{
		{"transcript names the tool's .claude", "linux", root, filepath.Join(home, ".claude", "projects", "p", "s.jsonl"), home, true},
		{"native cwd falls back to the hook's home", "linux", root, "", home, true},
		{"foreign (Windows) cwd with no transcript is unresolved", "linux", `D:\work\repo`, "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := env
			e.HostOS = c.hostOS
			got, ok := resolveSkillHome(e, skillSnapRequest{Cwd: c.cwd, TranscriptPath: c.transcript})
			if got != c.wantHome || ok != c.wantOK {
				t.Errorf("home = %q,%v; want %q,%v", got, ok, c.wantHome, c.wantOK)
			}
		})
	}
}

func TestBuildSkillSnapshotHomeUnresolvedAndIncomplete(t *testing.T) {
	root, _, env := skillFixture(t)
	env.HostOS = "linux"
	env.UserHome = func() (string, error) { return "", os.ErrNotExist }
	snap, ok := buildSkillSnapshot(context.Background(), env, skillSnapRequest{SessionID: "s", Event: skillhistory.EventSessionStart, Cwd: root})
	if !ok || snap.HomeResolved || len(snap.Members) != 2 {
		t.Fatalf("snapshot = %+v, want project members only with HomeResolved=false", snap)
	}

	env.Scan = func(context.Context, string, guidance.Options) (guidance.Result, error) {
		return guidance.Result{Incomplete: true}, context.DeadlineExceeded
	}
	snap, _ = buildSkillSnapshot(context.Background(), env, skillSnapRequest{SessionID: "s", Event: skillhistory.EventSessionStart, Cwd: root})
	if snap.Complete {
		t.Error("an incomplete scan produced a Complete snapshot (a missing skill would read absent)")
	}
}

func TestBuildSkillSnapshotInvoke(t *testing.T) {
	root, home, env := skillFixture(t)
	tp := filepath.Join(home, ".claude", "projects", "x", "s.jsonl")
	cases := []struct {
		name     string
		skill    string
		wantOK   bool
		wantRels []string
	}{
		{"by directory name", "deploy", true, []string{".claude/skills/deploy/SKILL.md"}},
		{"by frontmatter name", "lint-helper", true, []string{".claude/skills/lint/SKILL.md"}},
		{"home skill", "tidy", true, []string{"~/.claude/skills/tidy/SKILL.md"}},
		{"plugin skill is not snapshotted", "superpowers:plan", false, nil},
		{"unknown skill", "nope", false, nil},
		{"path-like name refused", "../../etc", false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			snap, ok := buildSkillSnapshot(context.Background(), env, skillSnapRequest{
				SessionID: "s", Event: skillhistory.EventSkillInvoke, ToolUseID: "toolu_1",
				InvokedName: c.skill, Cwd: root, TranscriptPath: tp,
			})
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (%+v)", ok, c.wantOK, snap)
			}
			if !ok {
				return
			}
			if len(snap.Members) != len(c.wantRels) || snap.ToolUseID != "toolu_1" {
				t.Fatalf("members = %+v, want %v", snap.Members, c.wantRels)
			}
			for i, rel := range c.wantRels {
				if snap.Members[i].RelPath != rel || snap.Members[i].BlobOID == "" {
					t.Errorf("member %d = %+v, want %s with a blob id", i, snap.Members[i], rel)
				}
			}
		})
	}
}

// TestInvokedSkillNameDotSegmentsRefused pins that "." and ".." never
// address the skills root: with a SKILL.md planted one level up, the
// invoke snapshot must still refuse instead of hashing it.
func TestInvokedSkillNameDotSegmentsRefused(t *testing.T) {
	root, home, env := skillFixture(t)
	for _, dir := range []string{filepath.Join(root, ".claude"), filepath.Join(root, ".claude", "skills")} {
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: planted\n---\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tp := filepath.Join(home, ".claude", "projects", "x", "s.jsonl")
	for _, name := range []string{".", ".."} {
		snap, ok := buildSkillSnapshot(context.Background(), env, skillSnapRequest{
			SessionID: "s", Event: skillhistory.EventSkillInvoke, ToolUseID: "toolu_1",
			InvokedName: name, Cwd: root, TranscriptPath: tp,
		})
		if ok {
			t.Errorf("invoked name %q produced a snapshot: %+v", name, snap)
		}
	}
}

func TestSkillSnapRequestFor(t *testing.T) {
	p := func(tool, tu string) claudeSkillSnapPayload {
		var x claudeSkillSnapPayload
		x.SessionID, x.Cwd, x.ToolName, x.ToolUseID = "s", "/r", tool, tu
		x.ToolInput.Skill = "deploy"
		return x
	}
	cases := []struct {
		name  string
		event string
		p     claudeSkillSnapPayload
		want  bool
		ev    string
	}{
		{"session start", "SessionStart", p("", ""), true, skillhistory.EventSessionStart},
		{"skill tool", "PostToolUse", p("Skill", "toolu_1"), true, skillhistory.EventSkillInvoke},
		{"other tool", "PostToolUse", p("Bash", "toolu_1"), false, ""},
		{"skill tool without tool_use_id", "PostToolUse", p("Skill", ""), false, ""},
		{"other event", "Stop", p("Skill", "toolu_1"), false, ""},
	}
	for _, c := range cases {
		req, ok := skillSnapRequestFor(c.event, c.p)
		if ok != c.want || (ok && req.Event != c.ev) {
			t.Errorf("%s: ok=%v event=%q, want %v %q", c.name, ok, req.Event, c.want, c.ev)
		}
	}
}

// TestRecordClaudeSkillSnapshotEndToEnd drives the PostToolUse hook entry
// point against a real config + DB: the Skill call lands one skill_invoke
// snapshot, a Bash call lands nothing, and [projects].skill_history=false
// turns capture off.
func TestRecordClaudeSkillSnapshotEndToEnd(t *testing.T) {
	root, home, _ := skillFixture(t)
	// The production env resolves the project root with git.FindRoot; make
	// the fixture root its own repository so an enclosing checkout (a
	// developer box whose temp dir sits inside one) cannot capture it.
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	configPath := filepath.Join(t.TempDir(), "observer.toml")
	writeSkillFile(t, configPath, "[observer]\ndb_path = "+strconv.Quote(filepath.ToSlash(dbPath))+"\n")
	offPath := filepath.Join(t.TempDir(), "off.toml")
	writeSkillFile(t, offPath, "[observer]\ndb_path = "+strconv.Quote(filepath.ToSlash(dbPath))+"\n[projects]\nskill_history = false\n")

	body := func(tool, tu string) []byte {
		b, _ := json.Marshal(map[string]any{
			"session_id": "s", "cwd": root, "tool_name": tool, "tool_use_id": tu,
			"tool_input": map[string]string{"skill": "deploy"},
		})
		return b
	}
	var stderr bytes.Buffer
	recordClaudeSkillSnapshot(body("Skill", "toolu_1"), "PostToolUse", "t", configPath, &stderr)
	recordClaudeSkillSnapshot(body("Bash", "toolu_2"), "PostToolUse", "t", configPath, &stderr)
	recordClaudeSkillSnapshot(body("Skill", "toolu_3"), "PostToolUse", "t", offPath, &stderr)

	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var n int
	var tu string
	if err := database.QueryRow(`SELECT COUNT(*), COALESCE(MAX(tool_use_id), '') FROM session_skill_snapshots WHERE event='skill_invoke'`).Scan(&n, &tu); err != nil {
		t.Fatal(err)
	}
	if n != 1 || tu != "toolu_1" {
		t.Errorf("skill_invoke snapshots = %d (%s), want exactly toolu_1; stderr=%s", n, tu, stderr.String())
	}
}
