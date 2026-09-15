//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter/codex"
)

type codexProcFixture struct {
	t    *testing.T
	root string
}

func (f codexProcFixture) write(path, content string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f codexProcFixture) process(pid, parent int, exe string, children ...int) {
	f.t.Helper()
	base := filepath.Join(f.root, strconv.Itoa(pid))
	fields := strings.Fields("S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1234")
	fields[1] = strconv.Itoa(parent)
	f.write(filepath.Join(base, "stat"), fmt.Sprintf("%d (name with (parentheses)) %s", pid, strings.Join(fields, " ")))
	installed := filepath.Join(f.root, "installed", exe)
	f.write(installed, "synthetic executable")
	if err := os.Symlink(installed, filepath.Join(base, "exe")); err != nil {
		f.t.Fatal(err)
	}
	var kids []string
	for _, child := range children {
		kids = append(kids, strconv.Itoa(child))
	}
	// Spawn on a non-main thread: /task/<pid>/children alone misses Go execs.
	f.write(filepath.Join(base, "task", strconv.Itoa(pid), "children"), "")
	f.write(filepath.Join(base, "task", strconv.Itoa(pid+1), "children"), strings.Join(kids, " "))
	if err := os.MkdirAll(filepath.Join(base, "fd"), 0o700); err != nil {
		f.t.Fatal(err)
	}
}

func (f codexProcFixture) rollout(pid, fd int, id string, source any, writer bool) string {
	f.t.Helper()
	meta := map[string]any{"type": "session_meta", "payload": map[string]any{"id": id, "source": source}}
	raw, err := json.Marshal(meta)
	if err != nil {
		f.t.Fatal(err)
	}
	target := filepath.Join(f.root, "sessions", "rollout-2026-09-14-"+id+".jsonl")
	f.write(target, string(raw)+"\n"+`{"type":"event_msg","payload":{"message":"must not be read"}}`+"\n")
	base := filepath.Join(f.root, strconv.Itoa(pid))
	if err := os.Symlink(target, filepath.Join(base, "fd", strconv.Itoa(fd))); err != nil {
		f.t.Fatal(err)
	}
	flags := "0102001"
	if !writer {
		flags = "0100000"
	}
	f.write(filepath.Join(base, "fdinfo", strconv.Itoa(fd)), "flags:\t"+flags+"\n")
	return target
}

func TestCodexNativeWriterIdentity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(codexProcFixture)
		want    string
	}{
		{"primary alongside subagent and history", func(f codexProcFixture) {
			f.rollout(200, 5, "main", "cli", true)
			f.rollout(200, 6, "child", map[string]any{"subagent": map[string]any{"thread_spawn": map[string]string{"parent_thread_id": "main"}}}, true)
			f.rollout(200, 7, "old-main", "cli", false)
		}, "main"},
		{"primary alongside review subagent", func(f codexProcFixture) {
			f.rollout(200, 5, "main", "cli", true)
			f.rollout(200, 6, "review", map[string]string{"subagent": "review"}, true)
		}, "main"},
		{"exec primary", func(f codexProcFixture) { f.rollout(200, 5, "exec-main", "exec", true) }, "exec-main"},
		{"duplicate descriptors agree", func(f codexProcFixture) {
			f.rollout(200, 5, "main", "cli", true)
			f.rollout(200, 6, "main", "cli", true)
		}, "main"},
		{"two primary writers abstain", func(f codexProcFixture) { f.rollout(200, 5, "a", "cli", true); f.rollout(200, 6, "b", "cli", true) }, ""},
		{"subagent only abstains", func(f codexProcFixture) { f.rollout(200, 5, "child", map[string]string{"subagent": "review"}, true) }, ""},
		{"no rollout yet", func(codexProcFixture) {}, ""},
		{"partial metadata waits", func(f codexProcFixture) {
			path := f.rollout(200, 5, "main", "cli", true)
			f.write(path, `{"type":"session_meta"`)
		}, ""},
		{"metadata filename disagree", func(f codexProcFixture) {
			path := f.rollout(200, 5, "main", "cli", true)
			f.write(path, "{\"type\":\"session_meta\",\"payload\":{\"id\":\"other\",\"source\":\"cli\"}}\n")
		}, ""},
		{"wrong native executable", func(f codexProcFixture) {
			f.rollout(200, 5, "main", "cli", true)
			if err := os.Remove(filepath.Join(f.root, "200", "exe")); err != nil {
				f.t.Fatal(err)
			}
			if err := os.Symlink("/installed/cat", filepath.Join(f.root, "200", "exe")); err != nil {
				f.t.Fatal(err)
			}
		}, ""},
		{"reparented child", func(f codexProcFixture) {
			f.rollout(200, 5, "main", "cli", true)
			path := filepath.Join(f.root, "200", "stat")
			data, err := os.ReadFile(path)
			if err != nil {
				f.t.Fatal(err)
			}
			f.write(path, strings.Replace(string(data), "S 100 ", "S 999 ", 1))
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := codexProcFixture{t: t, root: t.TempDir()}
			f.process(100, 1, "observer", 200)
			f.process(200, 100, "codex")
			tc.prepare(f)
			a := codex.NewWithOptions(nil, filepath.Join(f.root, "sessions"))
			got, err := terminalSessionInProc(context.Background(), f.root, 100, a, a, terminalProcessBinding{paths: []string{filepath.Join(f.root, "installed", "codex")}})
			if tc.want == "" {
				if err == nil || got.sessionID != "" {
					t.Fatalf("expected abstention, got %q, %v", got.sessionID, err)
				}
				return
			}
			if err != nil || got.sessionID != tc.want {
				t.Fatalf("got %q, %v; want %q", got.sessionID, err, tc.want)
			}
		})
	}
}

func TestCodexNativeWriterHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := codex.NewWithOptions(nil, t.TempDir())
	if _, err := terminalSessionInProc(ctx, t.TempDir(), 100, a, a, terminalProcessBinding{}); err == nil {
		t.Fatal("cancelled discovery continued")
	}
}
