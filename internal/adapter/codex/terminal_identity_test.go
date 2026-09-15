package codex

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

func terminalRollout(t *testing.T, root, id, payload string) string {
	t.Helper()
	path := filepath.Join(root, "2026", "09", "14", "rollout-2026-09-14T00-00-00-"+id+".jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	line := `{"timestamp":"2026-09-14T00:00:00Z","type":"session_meta","payload":{"id":"` + id + `",` + payload + `}}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func terminalProcessFile(path string) adapter.TerminalProcess {
	return adapter.TerminalProcess{PID: 42, Files: []adapter.TerminalSessionFile{{
		Path: path, ReadPath: path, Append: true, Writable: true,
	}}}
}

func writeTerminalNativeFixture(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("\x7fELFfixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return realPath
}

func TestTerminalNativeExecutablePaths(t *testing.T) {
	t.Parallel()
	triple, platformPackage, executable := codexNativeTarget()
	if triple == "" {
		t.Skip("Codex npm launcher has no native target for this platform")
	}

	t.Run("npm architecture package current layout", func(t *testing.T) {
		root := t.TempDir()
		entrypoint := filepath.Join(root, "node_modules", "@openai", "codex", "bin", "codex.js")
		if err := os.MkdirAll(filepath.Dir(entrypoint), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(entrypoint, []byte("#!/usr/bin/env node\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		want := writeTerminalNativeFixture(t, filepath.Join(root, "node_modules", "@openai", "codex", "node_modules", "@openai", platformPackage, "vendor", triple, "bin", executable))
		wrong := writeTerminalNativeFixture(t, filepath.Join(root, "wrong", "bin", executable))

		got := New().TerminalNativeExecutablePaths(entrypoint)
		if !slices.Contains(got, want) {
			t.Fatalf("TerminalNativeExecutablePaths = %v, want %q", got, want)
		}
		if slices.Contains(got, wrong) {
			t.Fatalf("TerminalNativeExecutablePaths accepted same-basename wrong path %q", wrong)
		}
	})

	t.Run("bundled historical layout", func(t *testing.T) {
		root := t.TempDir()
		entrypoint := filepath.Join(root, "codex", "bin", "codex.js")
		if err := os.MkdirAll(filepath.Dir(entrypoint), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(entrypoint, []byte("#!/usr/bin/env node\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		want := writeTerminalNativeFixture(t, filepath.Join(root, "codex", "vendor", triple, "codex", executable))
		got := New().TerminalNativeExecutablePaths(entrypoint)
		if !slices.Contains(got, want) {
			t.Fatalf("TerminalNativeExecutablePaths = %v, want bundled %q", got, want)
		}
	})

	t.Run("native launchers and variant boundary", func(t *testing.T) {
		root := t.TempDir()
		codexNative := writeTerminalNativeFixture(t, filepath.Join(root, "codex"))
		if got := New().TerminalNativeExecutablePaths(codexNative); !slices.Equal(got, []string{codexNative}) {
			t.Fatalf("native Codex paths = %v, want launcher itself", got)
		}

		interpreter := writeTerminalNativeFixture(t, filepath.Join(root, "standalone", "bin", "interpreter"))
		if got := NewOpenInterpreter().TerminalNativeExecutablePaths(interpreter); !slices.Equal(got, []string{interpreter}) {
			t.Fatalf("native Open Interpreter paths = %v, want launcher itself", got)
		}
		script := filepath.Join(root, "fake-interpreter", "bin", "codex.js")
		if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(script, []byte("#!/usr/bin/env node\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeTerminalNativeFixture(t, filepath.Join(root, "fake-interpreter", "vendor", triple, "bin", executable))
		if got := NewOpenInterpreter().TerminalNativeExecutablePaths(script); len(got) != 0 {
			t.Fatalf("Open Interpreter variant accepted Codex npm vendor path: %v", got)
		}
	})
}

func TestResolveTerminalSessionCodexAndOpenInterpreter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		new     func(string) *Adapter
		payload string
	}{
		{"codex cli", func(root string) *Adapter { return NewWithOptions(nil, root) }, `"source":"cli","originator":"codex_cli_rs"`},
		{"codex exec", func(root string) *Adapter { return NewWithOptions(nil, root) }, `"source":"exec","originator":"codex_exec"`},
		{"open interpreter cli", func(root string) *Adapter { return NewOpenInterpreterWithOptions(nil, root) }, `"source":"cli","originator":"codex-tui"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			const id = "019f6f69-23a0-7e32-bdba-9a9fabc946be"
			path := terminalRollout(t, root, id, tc.payload)
			got, err := tc.new(root).ResolveTerminalSession(context.Background(), terminalProcessFile(path))
			if err != nil {
				t.Fatal(err)
			}
			want := (adapter.TerminalSessionIdentity{SessionID: id, Evidence: path})
			if got != want {
				t.Fatalf("ResolveTerminalSession = %+v, want %+v", got, want)
			}
		})
	}
}

func TestResolveTerminalSessionRejectsNonPrimaryOrUnownedRollouts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		payload    string
		fileMutate func(*adapter.TerminalSessionFile)
	}{
		{"desktop source", `"source":"vscode","originator":"Codex Desktop"`, nil},
		{"interpreter desktop originator", `"source":"cli","originator":"codex_ui"`, nil},
		{"subagent parent", `"source":"cli","parent_thread_id":"parent"`, nil},
		{"subagent source", `"source":"cli","thread_source":"subagent"`, nil},
		{"unknown source", `"source":"carrier-pigeon"`, nil},
		{"read only", `"source":"cli"`, func(f *adapter.TerminalSessionFile) { f.Writable = false }},
		{"not append", `"source":"cli"`, func(f *adapter.TerminalSessionFile) { f.Append = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			path := terminalRollout(t, root, "session-a", tc.payload)
			process := terminalProcessFile(path)
			if tc.fileMutate != nil {
				tc.fileMutate(&process.Files[0])
			}
			got, err := NewWithOptions(nil, root).ResolveTerminalSession(context.Background(), process)
			if err != nil {
				t.Fatal(err)
			}
			if got.SessionID != "" {
				t.Fatalf("ResolveTerminalSession = %+v, want abstention", got)
			}
		})
	}
}

func TestResolveTerminalSessionRejectsFilenameMismatchOversizeAndAmbiguity(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	a := NewWithOptions(nil, root)

	mismatch := terminalRollout(t, root, "path-id", `"source":"cli"`)
	body := `{"type":"session_meta","payload":{"id":"other-id","source":"cli"}}` + "\n"
	if err := os.WriteFile(mismatch, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := a.ResolveTerminalSession(context.Background(), terminalProcessFile(mismatch)); err != nil || got.SessionID != "" {
		t.Fatalf("filename mismatch = (%+v, %v), want abstention", got, err)
	}

	oversize := terminalRollout(t, root, "oversize", `"source":"cli"`)
	if err := os.WriteFile(oversize, []byte(strings.Repeat(" ", terminalMetadataLimit)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := a.ResolveTerminalSession(context.Background(), terminalProcessFile(oversize)); err != nil || got.SessionID != "" {
		t.Fatalf("oversize = (%+v, %v), want abstention", got, err)
	}

	one := terminalRollout(t, root, "one", `"source":"cli"`)
	two := terminalRollout(t, root, "two", `"source":"cli"`)
	process := terminalProcessFile(one)
	process.Files = append(process.Files, terminalProcessFile(two).Files...)
	if got, err := a.ResolveTerminalSession(context.Background(), process); err != nil || got.SessionID != "" {
		t.Fatalf("ambiguous = (%+v, %v), want abstention", got, err)
	}
}

func TestResolveTerminalSessionValidPrimaryPlusMalformedWriterAbstains(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	primary := terminalRollout(t, root, "primary", `"source":"cli"`)
	malformed := terminalRollout(t, root, "malformed", `"source":"cli"`)
	if err := os.WriteFile(malformed, []byte("{partial\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	process := terminalProcessFile(primary)
	process.Files = append(process.Files, terminalProcessFile(malformed).Files...)
	got, err := NewWithOptions(nil, root).ResolveTerminalSession(context.Background(), process)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "" {
		t.Fatalf("ResolveTerminalSession = %+v, want abstention while a second writer is uncertain", got)
	}
}

func TestResolveTerminalSessionValidPrimaryIgnoresDocumentedObjectSubagent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	primary := terminalRollout(t, root, "primary", `"source":"cli"`)
	subagent := terminalRollout(t, root, "child", `"source":{"subagent":{"thread_spawn":{"parent_thread_id":"primary"}}}`)
	process := terminalProcessFile(primary)
	process.Files = append(process.Files, terminalProcessFile(subagent).Files...)

	got, err := NewWithOptions(nil, root).ResolveTerminalSession(context.Background(), process)
	if err != nil {
		t.Fatal(err)
	}
	want := adapter.TerminalSessionIdentity{SessionID: "primary", Evidence: primary}
	if got != want {
		t.Fatalf("ResolveTerminalSession = %+v, want primary with documented object subagent excluded", got)
	}
}

func TestResolveTerminalSessionHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := NewWithOptions(nil, t.TempDir()).ResolveTerminalSession(ctx, adapter.TerminalProcess{PID: 42})
	if err == nil || got.SessionID != "" {
		t.Fatalf("canceled = (%+v, %v), want context error", got, err)
	}
}
