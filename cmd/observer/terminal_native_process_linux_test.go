//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/qwencode"
	"github.com/marmutapp/superbased-observer/internal/config"
)

type nativeResolverFixture struct {
	*fakeAdapterBasic
	resolve func(context.Context, adapter.TerminalProcess) (adapter.TerminalSessionIdentity, error)
}

func (f *nativeResolverFixture) ResolveTerminalSession(ctx context.Context, p adapter.TerminalProcess) (adapter.TerminalSessionIdentity, error) {
	return f.resolve(ctx, p)
}

func TestTerminalNativeProcessIsAdapterIndependent(t *testing.T) {
	for _, name := range []string{"interpreter", "qwen", "cline"} {
		t.Run(name, func(t *testing.T) {
			f := codexProcFixture{t: t, root: t.TempDir()}
			f.process(100, 1, "observer", 200)
			f.process(200, 100, name, 300)
			f.process(300, 200, name) // nested invocation must not identify its parent
			f.write(filepath.Join(f.root, "sys/kernel/random/boot_id"), "test-boot\n")
			calls := 0
			a := &nativeResolverFixture{fakeAdapterBasic: &fakeAdapterBasic{}, resolve: func(_ context.Context, p adapter.TerminalProcess) (adapter.TerminalSessionIdentity, error) {
				calls++
				if p.PID != 200 || p.StartIdentity != "linux:test-boot:1234" {
					t.Fatalf("wrong primary process: %+v", p)
				}
				return adapter.TerminalSessionIdentity{SessionID: "primary", Evidence: "native-lease"}, nil
			}}
			got, err := terminalSessionInProc(context.Background(), f.root, 100, a, a, terminalProcessBinding{paths: []string{filepath.Join(f.root, "installed", name)}})
			if err != nil || got.sessionID != "primary" || calls != 1 {
				t.Fatalf("identity=%+v err=%v calls=%d", got, err, calls)
			}
		})
	}
}

func TestTerminalNativeProcessRejectsRaces(t *testing.T) {
	for _, mutation := range []string{"birth", "executable", "descriptor flags", "descriptor inode", "script argv", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			f := codexProcFixture{t: t, root: t.TempDir()}
			f.process(100, 1, "observer", 200)
			f.process(200, 100, "node")
			script := filepath.Join(f.root, "cli.js")
			f.write(script, "#!/usr/bin/env node\n")
			f.write(filepath.Join(f.root, "200/cmdline"), "node\x00"+script+"\x00")
			path := f.rollout(200, 5, "main", "cli", true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a := &nativeResolverFixture{fakeAdapterBasic: &fakeAdapterBasic{suffix: ".jsonl"}, resolve: func(_ context.Context, p adapter.TerminalProcess) (adapter.TerminalSessionIdentity, error) {
				if len(p.Files) != 1 || !p.Files[0].Writable || !p.Files[0].Append {
					t.Fatal("missing native writer")
				}
				switch mutation {
				case "birth":
					f.write(filepath.Join(f.root, "200/stat"), "200 (node) S 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 9999")
				case "executable":
					exe := filepath.Join(f.root, "200/exe")
					if err := os.Remove(exe); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("/installed/other", exe); err != nil {
						t.Fatal(err)
					}
				case "descriptor flags":
					f.write(filepath.Join(f.root, "200/fdinfo/5"), "flags:\t0100000\n")
				case "descriptor inode":
					replacement := filepath.Join(f.root, "replacement")
					f.write(replacement, "replacement")
					if err := os.Rename(replacement, path); err != nil {
						t.Fatal(err)
					}
				case "script argv":
					f.write(filepath.Join(f.root, "200/cmdline"), "node\x00/other.js\x00")
				case "cancel":
					cancel()
				}
				return adapter.TerminalSessionIdentity{SessionID: "main", Evidence: "writer"}, nil
			}}
			got, err := terminalSessionInProc(ctx, f.root, 100, a, a, terminalProcessBinding{script: script, interpreter: "node"})
			if err == nil || got.sessionID != "" {
				t.Fatalf("accepted raced process: %+v, %v", got, err)
			}
		})
	}
}

func TestTerminalNativeProcessAmbiguityAndLimits(t *testing.T) {
	for _, shape := range []string{"two primary processes", "two processes same id", "too many processes", "too many descriptors", "too many tasks"} {
		t.Run(shape, func(t *testing.T) {
			f := codexProcFixture{t: t, root: t.TempDir()}
			f.process(100, 1, "observer", 200)
			f.process(200, 100, "native")
			switch shape {
			case "two primary processes", "two processes same id":
				f.write(filepath.Join(f.root, "100/task/101/children"), "200 300")
				f.process(300, 100, "native")
			case "too many processes":
				// A chain of wrappers exceeds the bounded walk before a primary.
				f = codexProcFixture{t: t, root: t.TempDir()}
				for pid := 100; pid < 166; pid++ {
					f.process(pid, pid-1, "wrapper", pid+1)
				}
			case "too many descriptors":
				for i := 0; i < 1025; i++ {
					f.write(filepath.Join(f.root, "200/fd", strconv.Itoa(i)), "")
				}
			case "too many tasks":
				for i := 0; i < 257; i++ {
					f.write(filepath.Join(f.root, "100/task", strconv.Itoa(i), "children"), "")
				}
			}
			a := &nativeResolverFixture{fakeAdapterBasic: &fakeAdapterBasic{}, resolve: func(_ context.Context, p adapter.TerminalProcess) (adapter.TerminalSessionIdentity, error) {
				id := "main"
				if p.PID == 300 && shape != "two processes same id" {
					id = "other"
				}
				return adapter.TerminalSessionIdentity{SessionID: id, Evidence: "native"}, nil
			}}
			got, err := terminalSessionInProc(context.Background(), f.root, 100, a, a, terminalProcessBinding{paths: []string{filepath.Join(f.root, "installed", "native")}})
			if err == nil || got.sessionID != "" {
				t.Fatalf("accepted ambiguity/overflow: %+v, %v", got, err)
			}
		})
	}
}

func TestTerminalNativeQwenWrapperFindsLeaseOwner(t *testing.T) {
	f := codexProcFixture{t: t, root: t.TempDir()}
	f.process(100, 1, "observer", 200)
	f.process(200, 100, "node", 300)
	f.process(300, 200, "node", 400)
	f.process(400, 300, "node")
	pkg := filepath.Join(f.root, "qwen-package")
	entry := filepath.Join(pkg, "cli-entry.js")
	runtimeScript := filepath.Join(pkg, "cli.js")
	f.write(entry, "#!/usr/bin/env node\n// installed wrapper")
	f.write(runtimeScript, "// installed runtime")
	f.write(filepath.Join(pkg, "package.json"), `{"name":"@qwen-code/qwen-code","version":"0.21.0"}`)
	f.write(filepath.Join(f.root, "200/cmdline"), "node\x00"+entry+"\x00")
	f.write(filepath.Join(f.root, "300/cmdline"), "node\x00--expose-gc\x00"+runtimeScript+"\x00")
	f.write(filepath.Join(f.root, "400/cmdline"), "node\x00--expose-gc\x00"+runtimeScript+"\x00")
	f.write(filepath.Join(f.root, "sys/kernel/random/boot_id"), "test-boot")
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		pid int
		id  string
	}{{300, "primary"}, {400, "nested"}} {
		raw, err := json.Marshal(map[string]any{"schema_version": 1, "session_id": row.id, "owner_id": "owner-" + row.id, "pid": row.pid, "process_start_identity": "linux:test-boot:1234", "hostname": host, "process_kind": "interactive", "acquired_at": "2026-09-14T00:00:00Z"})
		if err != nil {
			t.Fatal(err)
		}
		f.write(filepath.Join(f.root, "tmp/session-writer-locks", row.id+".lock"), string(raw))
	}
	a := qwencode.NewWithOptions(nil, filepath.Join(f.root, "projects"))
	cfg := config.Config{Launch: config.LaunchConfig{Tools: map[string]config.LaunchToolConfig{"qwen-code": {Path: entry}}}}
	binding := terminalBindingForAdapter(a, &cfg)
	got, err := terminalSessionInProc(context.Background(), f.root, 100, a, a, binding, "linux:test-boot:1234")
	if err != nil || got.sessionID != "primary" {
		t.Fatalf("wrapper must resolve runtime lease, got %+v, %v", got, err)
	}
	got, err = terminalSessionInProc(context.Background(), f.root, 100, a, a, binding, "linux:test-boot:9999")
	if err == nil || got.sessionID != "" {
		t.Fatal("accepted a root whose birth differs from spawn")
	}
}
