package aiderdesk

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsSessionFile pins which files the skeleton claims: a task's
// context.json under a project's tasks root, nothing else.
func TestIsSessionFile(t *testing.T) {
	proj := filepath.Join(string(filepath.Separator), "w", "proj")
	a := New([]string{proj, proj})
	if len(a.WatchPaths()) != 1 || a.WatchPaths()[0] != filepath.Join(proj, ".aider-desk", "tasks") {
		t.Fatalf("WatchPaths = %v", a.WatchPaths())
	}
	tasks := filepath.Join(proj, ".aider-desk", "tasks")
	for _, tc := range []struct {
		path string
		want bool
	}{
		{filepath.Join(tasks, "a1b2c3d4", "context.json"), true},
		{filepath.Join(tasks, "a1b2c3d4", "context.pre-compaction.001.json"), false},
		{filepath.Join(tasks, "a1b2c3d4", "settings.json"), false},
		{filepath.Join(tasks, "a1b2c3d4", "todos.json"), false},
		{filepath.Join(tasks, "a1b2c3d4", "worktree", "x", "context.json"), false},
		{filepath.Join(tasks, "context.json"), false},
		{filepath.Join(proj, ".aider-desk", "mcp-servers.json"), false},
		{filepath.Join(string(filepath.Separator), "tmp", "foreign", ".aider-desk", "tasks", "t", "context.json"), false},
		{filepath.Join(proj, ".aider.chat.history.md"), false},
	} {
		if got := a.IsSessionFile(tc.path); got != tc.want {
			t.Errorf("IsSessionFile(%s) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestParseRefusesToGuess: the skeleton emits nothing, warns once naming
// the fixture README, and moves the offset to the file's size. The input
// is SYNTHETIC.
func TestParseRefusesToGuess(t *testing.T) {
	p := filepath.Join(t.TempDir(), "context.json")
	body := `{"version":2,"contextMessages":[{"id":"m1","role":"user","content":"SYNTHETIC","timestamp":1}],"contextFiles":[]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := New(nil).ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 || res.NewOffset != int64(len(body)) {
		t.Errorf("result = %+v", res)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], fixtureREADME) || strings.Contains(res.Warnings[0], "SYNTHETIC") {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

// TestHomeDir pins AIDER_DESK_HOME_DIR: an absolute value moves the home,
// a relative one is refused, unset is <home>/.aider-desk.
func TestHomeDir(t *testing.T) {
	home := t.TempDir()
	abs := filepath.Join(t.TempDir(), "ad")
	for _, tc := range []struct {
		name, env, want string
		err             bool
	}{
		{"unset", "", filepath.Join(home, ".aider-desk", "mcp-servers.json"), false},
		{"absolute", abs, filepath.Join(abs, "mcp-servers.json"), false},
		{"relative", "rel/ad", "", true},
	} {
		got, err := MCPServersPath(home, func(k string) string {
			if k == homeEnv {
				return tc.env
			}
			return ""
		})
		if (err != nil) != tc.err || got != tc.want {
			t.Errorf("%s: MCPServersPath = %q, %v", tc.name, got, err)
		}
		if err != nil && strings.Contains(err.Error(), "rel/ad") {
			t.Errorf("%s: the error quotes the value", tc.name)
		}
	}
	for _, tc := range []struct {
		name, dir, want string
		err             bool
	}{
		{"renamed segment", ".ad2", filepath.Join(home, ".ad2", "mcp-servers.json"), false},
		{"leading separator kept as a segment", "/ad3", filepath.Join(home, "ad3", "mcp-servers.json"), false},
		{"climbs out", "../x", "", true},
	} {
		got, err := MCPServersPath(home, func(k string) string {
			if k == dirEnv {
				return tc.dir
			}
			return ""
		})
		if (err != nil) != tc.err || got != tc.want {
			t.Errorf("%s: MCPServersPath = %q, %v", tc.name, got, err)
		}
	}
	if _, err := HomeDir("", nil); err == nil {
		t.Error("no home resolved to a path")
	}
}
