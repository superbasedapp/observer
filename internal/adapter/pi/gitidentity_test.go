package pi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeGitRepo writes the minimal .git/HEAD + .git/config fixture
// git.ResolveIdentity needs to resolve a branch and an "origin" remote —
// no git binary required. Same shape as internal/git/git_test.go's
// unexported makeRepo helper, duplicated here because that helper isn't
// visible outside the git package.
func makeGitRepo(t *testing.T, dir, branch, remote string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"),
		[]byte("ref: refs/heads/"+branch+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := `[core]
	repositoryformatversion = 0
[remote "origin"]
	url = ` + remote + `
	fetch = +refs/heads/*:refs/remotes/origin/*
`
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestParseSessionFile_GitIdentity pins D-DEMO-9: a pi session's `session`
// line cwd is resolved to its git identity — branch, normalized remote,
// and the Project Identity Resolver v2 bundle (GitRemoteOwner etc, via
// adapter.ApplyProjectIdentity) — exactly like goose/crush/primeagent
// already do. Before this fix, GitBranch/GitRemote stayed permanently
// empty on every pi ToolEvent/TokenEvent, so pi sessions never folded
// into a repo's org project (git_remote_hash, the org's fold key, was
// always empty).
func TestParseSessionFile_GitIdentity(t *testing.T) {
	for _, tc := range []struct {
		name            string
		makeCwd         func(t *testing.T) string
		wantBranch      string
		wantRemote      string
		wantRemoteOwner string
	}{
		{
			name: "git_repo_resolves_branch_and_remote",
			makeCwd: func(t *testing.T) string {
				dir := t.TempDir()
				makeGitRepo(t, dir, "feature/x", "git@github.com:acme/widgets.git")
				return dir
			},
			wantBranch:      "feature/x",
			wantRemote:      "github.com/acme/widgets",
			wantRemoteOwner: "github.com/acme",
		},
		{
			name: "non_git_cwd_leaves_identity_empty",
			makeCwd: func(t *testing.T) string {
				// A real, existing directory with no .git anywhere above it
				// (t.TempDir() roots are never inside a git working tree).
				return t.TempDir()
			},
			wantBranch:      "",
			wantRemote:      "",
			wantRemoteOwner: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := tc.makeCwd(t)
			root := t.TempDir()
			path := filepath.Join(root, "session.jsonl")
			// JSON-escape any backslashes so a Windows-shaped cwd (not
			// exercised by this test, but kept defensive) round-trips.
			cwdJSON := strings.ReplaceAll(cwd, `\`, `\\`)
			body := strings.Join([]string{
				`{"type":"session","version":3,"id":"ses_g","timestamp":"2026-04-23T05:47:02.362Z","cwd":"` + cwdJSON + `"}`,
				`{"type":"model_change","id":"m1","parentId":null,"timestamp":"2026-04-23T05:47:02.372Z","provider":"anthropic","modelId":"claude-sonnet-4-5"}`,
				`{"type":"message","id":"u1","parentId":"m1","timestamp":"2026-04-23T05:47:02.380Z","message":{"role":"user","content":[{"type":"text","text":"Hi"}],"timestamp":1776923222379}}`,
				`{"type":"message","id":"a1","parentId":"u1","timestamp":"2026-04-23T05:47:02.390Z","message":{"role":"assistant","content":[{"type":"text","text":"Hello"}],"provider":"anthropic","model":"claude-sonnet-4-5","usage":{"input":10,"output":2,"totalTokens":12},"stopReason":"stop","timestamp":1776923222395}}`,
				"",
			}, "\n")
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}

			a := NewWithOptions(nil, []string{root})
			res, err := a.ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if len(res.ToolEvents) == 0 {
				t.Fatal("expected at least one tool event")
			}
			if len(res.TokenEvents) == 0 {
				t.Fatal("expected at least one token event")
			}

			for _, ev := range res.ToolEvents {
				if ev.GitBranch != tc.wantBranch {
					t.Errorf("ToolEvent %q GitBranch = %q, want %q", ev.RawToolName, ev.GitBranch, tc.wantBranch)
				}
				if ev.GitRemote != tc.wantRemote {
					t.Errorf("ToolEvent %q GitRemote = %q, want %q", ev.RawToolName, ev.GitRemote, tc.wantRemote)
				}
				if ev.GitRemoteOwner != tc.wantRemoteOwner {
					t.Errorf("ToolEvent %q GitRemoteOwner = %q, want %q", ev.RawToolName, ev.GitRemoteOwner, tc.wantRemoteOwner)
				}
				// ProjectRoot is unaffected by this fix — pi still uses the
				// raw session cwd, not the resolved git root.
				if ev.ProjectRoot != cwd {
					t.Errorf("ToolEvent %q ProjectRoot = %q, want %q (unchanged)", ev.RawToolName, ev.ProjectRoot, cwd)
				}
			}
			for _, tok := range res.TokenEvents {
				if tok.GitBranch != tc.wantBranch {
					t.Errorf("TokenEvent GitBranch = %q, want %q", tok.GitBranch, tc.wantBranch)
				}
				if tok.GitRemote != tc.wantRemote {
					t.Errorf("TokenEvent GitRemote = %q, want %q", tok.GitRemote, tc.wantRemote)
				}
			}
		})
	}
}

// TestParseSessionFile_GitIdentity_IncrementalReparse proves the identity
// resolved from the header `session` line survives an incremental
// re-parse (fromOffset > 0), which seeks past that line — the same
// recovery path canonicalSessionID/ProjectRoot already needed
// (recoverSessionState) now also has to recover GitBranch/GitRemote.
func TestParseSessionFile_GitIdentity_IncrementalReparse(t *testing.T) {
	cwd := t.TempDir()
	makeGitRepo(t, cwd, "main", "git@github.com:acme/widgets.git")

	root := t.TempDir()
	path := filepath.Join(root, "2026-06-26T21-09-23-295Z_019f05c4-10dc-72de-8382-4991c000af2d.jsonl")
	header := strings.Join([]string{
		`{"type":"session","version":3,"id":"019f05c4-10dc-72de-8382-4991c000af2d","timestamp":"2026-06-26T21:09:23.295Z","cwd":"` + cwd + `"}`,
		`{"type":"model_change","id":"m1","timestamp":"2026-06-26T21:09:23.300Z","provider":"openai-codex","modelId":"gpt-5.5"}`,
		`{"type":"message","id":"u1","timestamp":"2026-06-26T21:09:24.000Z","message":{"role":"user","content":[{"type":"text","text":"First"}],"timestamp":1777000000000}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(header), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}

	appended := strings.Join([]string{
		`{"type":"message","id":"a2","timestamp":"2026-06-26T21:09:30.000Z","message":{"role":"assistant","content":[{"type":"text","text":"Second"}],"provider":"openai-codex","model":"gpt-5.5","usage":{"input":12,"output":3,"totalTokens":15},"stopReason":"stop","timestamp":1777000030000}}`,
		"",
	}, "\n")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(appended); err != nil {
		t.Fatal(err)
	}
	f.Close()

	second, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil {
		t.Fatalf("incremental parse: %v", err)
	}
	if len(second.ToolEvents) == 0 {
		t.Fatal("incremental parse produced no events")
	}
	for _, ev := range second.ToolEvents {
		if ev.GitBranch != "main" {
			t.Errorf("incremental event GitBranch = %q, want main", ev.GitBranch)
		}
		if ev.GitRemote != "github.com/acme/widgets" {
			t.Errorf("incremental event GitRemote = %q, want github.com/acme/widgets", ev.GitRemote)
		}
	}
}
