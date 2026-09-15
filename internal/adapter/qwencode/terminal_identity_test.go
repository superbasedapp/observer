package qwencode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

const terminalTestStartIdentity = "linux:11111111-2222-3333-4444-555555555555:424242"

func writeTerminalLease(t *testing.T, qwenHome, fileID string, mutate func(map[string]any)) string {
	t.Helper()
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	record := map[string]any{
		"schema_version":         1,
		"session_id":             fileID,
		"owner_id":               "owner-1",
		"pid":                    4242,
		"process_start_identity": terminalTestStartIdentity,
		"hostname":               host,
		"process_kind":           "interactive",
		"acquired_at":            time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		"qwen_version":           "0.21.0",
	}
	if mutate != nil {
		mutate(record)
	}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(qwenHome, "tmp", "session-writer-locks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, fileID+".lock")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func terminalQwenProcess() adapter.TerminalProcess {
	return adapter.TerminalProcess{PID: 4242, StartIdentity: terminalTestStartIdentity}
}

func writeTerminalQwenPackage(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"name":"@qwen-code/qwen-code","version":"0.21.0"}`)
	if err := os.WriteFile(filepath.Join(root, "package.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTerminalQwenScript(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/usr/bin/env node\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return realPath
}

func TestTerminalScriptExecutablePaths(t *testing.T) {
	t.Parallel()
	t.Run("current wrapper selects sibling and skips wrapper", func(t *testing.T) {
		root := t.TempDir()
		writeTerminalQwenPackage(t, root)
		wrapper := writeTerminalQwenScript(t, filepath.Join(root, "cli-entry.js"))
		primary := writeTerminalQwenScript(t, filepath.Join(root, "cli.js"))
		writeTerminalQwenScript(t, filepath.Join(filepath.Dir(root), "dist", "cli.js"))
		wrong := writeTerminalQwenScript(t, filepath.Join(root, "wrong", "cli.js"))

		got := NewWithOptions(nil, filepath.Join(t.TempDir(), "projects")).TerminalScriptExecutablePaths(wrapper)
		if len(got) != 1 || got[0] != primary {
			t.Fatalf("TerminalScriptExecutablePaths = %v, want sibling %q", got, primary)
		}
		if got[0] == wrapper || got[0] == wrong {
			t.Fatalf("TerminalScriptExecutablePaths accepted wrapper or same-basename wrong path: %v", got)
		}
	})

	t.Run("wrapper falls back to parent dist", func(t *testing.T) {
		root := t.TempDir()
		writeTerminalQwenPackage(t, root)
		wrapper := writeTerminalQwenScript(t, filepath.Join(root, "bin", "cli-entry.js"))
		primary := writeTerminalQwenScript(t, filepath.Join(root, "dist", "cli.js"))

		got := NewWithOptions(nil, filepath.Join(t.TempDir(), "projects")).TerminalScriptExecutablePaths(wrapper)
		if len(got) != 1 || got[0] != primary {
			t.Fatalf("TerminalScriptExecutablePaths = %v, want dist %q", got, primary)
		}
	})

	t.Run("legacy direct cli is primary", func(t *testing.T) {
		root := t.TempDir()
		writeTerminalQwenPackage(t, root)
		direct := writeTerminalQwenScript(t, filepath.Join(root, "cli.js"))
		got := NewWithOptions(nil, filepath.Join(t.TempDir(), "projects")).TerminalScriptExecutablePaths(direct)
		if len(got) != 1 || got[0] != direct {
			t.Fatalf("TerminalScriptExecutablePaths = %v, want direct %q", got, direct)
		}
	})

	t.Run("unowned same basename is rejected", func(t *testing.T) {
		path := writeTerminalQwenScript(t, filepath.Join(t.TempDir(), "cli-entry.js"))
		if got := NewWithOptions(nil, filepath.Join(t.TempDir(), "projects")).TerminalScriptExecutablePaths(path); len(got) != 0 {
			t.Fatalf("TerminalScriptExecutablePaths accepted unowned script: %v", got)
		}
	})
}

func TestResolveTerminalSessionUsesNativeWriterLease(t *testing.T) {
	t.Parallel()
	qwenHome := t.TempDir()
	root := filepath.Join(qwenHome, "projects")
	const id = "11111111-2222-4333-8444-555555555555"
	lease := writeTerminalLease(t, qwenHome, id, nil)

	got, err := NewWithOptions(nil, root).ResolveTerminalSession(context.Background(), terminalQwenProcess())
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != id || !strings.HasPrefix(got.Evidence, lease+":sha256:") {
		t.Fatalf("ResolveTerminalSession = %+v, want id %q and lease-bound evidence", got, id)
	}
}

func TestResolveTerminalSessionNativeWriterLeaseReplacementChangesEvidence(t *testing.T) {
	t.Parallel()
	qwenHome := t.TempDir()
	root := filepath.Join(qwenHome, "projects")
	const id = "11111111-2222-4333-8444-555555555555"
	writeTerminalLease(t, qwenHome, id, nil)
	a := NewWithOptions(nil, root)

	before, err := a.ResolveTerminalSession(context.Background(), terminalQwenProcess())
	if err != nil {
		t.Fatal(err)
	}
	writeTerminalLease(t, qwenHome, id, func(m map[string]any) { m["owner_id"] = "owner-2" })
	after, err := a.ResolveTerminalSession(context.Background(), terminalQwenProcess())
	if err != nil {
		t.Fatal(err)
	}
	if before.SessionID != id || after.SessionID != id || before.Evidence == after.Evidence {
		t.Fatalf("lease replacement identities = (%+v, %+v), want same id and distinct ownership evidence", before, after)
	}
}

func TestResolveTerminalSessionRejectsInvalidNativeWriterLease(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		mutate        func(map[string]any)
		processMutate func(*adapter.TerminalProcess)
		fileID        string
	}{
		{"pid mismatch", func(m map[string]any) { m["pid"] = 9999 }, nil, "session-a"},
		{"birth mismatch", func(m map[string]any) { m["process_start_identity"] = "linux:other:1" }, nil, "session-a"},
		{"foreign host", func(m map[string]any) { m["hostname"] = "other-host" }, nil, "session-a"},
		{"noninteractive", func(m map[string]any) { m["process_kind"] = "daemon" }, nil, "session-a"},
		{"missing owner", func(m map[string]any) { m["owner_id"] = "" }, nil, "session-a"},
		{"bad acquisition time", func(m map[string]any) { m["acquired_at"] = "yesterday-ish" }, nil, "session-a"},
		{"filename mismatch", func(m map[string]any) { m["session_id"] = "session-b" }, nil, "session-a"},
		{"caller missing birth", nil, func(p *adapter.TerminalProcess) { p.StartIdentity = "" }, "session-a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			qwenHome := t.TempDir()
			root := filepath.Join(qwenHome, "projects")
			writeTerminalLease(t, qwenHome, tc.fileID, tc.mutate)
			process := terminalQwenProcess()
			if tc.processMutate != nil {
				tc.processMutate(&process)
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

func TestResolveTerminalSessionRejectsSymlinkOversizeAndAmbiguousLeases(t *testing.T) {
	t.Parallel()
	qwenHome := t.TempDir()
	root := filepath.Join(qwenHome, "projects")
	a := NewWithOptions(nil, root)

	real := writeTerminalLease(t, qwenHome, "real", nil)
	symlink := filepath.Join(filepath.Dir(real), "linked.lock")
	if err := os.Symlink(real, symlink); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(real); err != nil {
		t.Fatal(err)
	}
	if got, err := a.ResolveTerminalSession(context.Background(), terminalQwenProcess()); err != nil || got.SessionID != "" {
		t.Fatalf("symlink lease = (%+v, %v), want abstention", got, err)
	}

	if err := os.Remove(symlink); err != nil {
		t.Fatal(err)
	}
	oversize := filepath.Join(filepath.Dir(real), "oversize.lock")
	if err := os.WriteFile(oversize, []byte(strings.Repeat("x", terminalLeaseLimit+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := a.ResolveTerminalSession(context.Background(), terminalQwenProcess()); err != nil || got.SessionID != "" {
		t.Fatalf("oversize lease = (%+v, %v), want abstention", got, err)
	}

	if err := os.Remove(oversize); err != nil {
		t.Fatal(err)
	}
	writeTerminalLease(t, qwenHome, "one", nil)
	writeTerminalLease(t, qwenHome, "two", func(m map[string]any) { m["owner_id"] = "owner-2" })
	if got, err := a.ResolveTerminalSession(context.Background(), terminalQwenProcess()); err != nil || got.SessionID != "" {
		t.Fatalf("ambiguous leases = (%+v, %v), want abstention", got, err)
	}
}

func TestResolveTerminalSessionNativeLeaseUncertaintyAndBoundedDirectory(t *testing.T) {
	t.Parallel()
	t.Run("valid plus malformed current candidate abstains", func(t *testing.T) {
		qwenHome := t.TempDir()
		root := filepath.Join(qwenHome, "projects")
		writeTerminalLease(t, qwenHome, "valid", nil)
		malformed := filepath.Join(qwenHome, "tmp", "session-writer-locks", "unknown.lock")
		if err := os.WriteFile(malformed, []byte("{partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := NewWithOptions(nil, root).ResolveTerminalSession(context.Background(), terminalQwenProcess())
		if err != nil {
			t.Fatal(err)
		}
		if got.SessionID != "" {
			t.Fatalf("ResolveTerminalSession = %+v, want abstention with unclassifiable lease", got)
		}
	})

	t.Run("known foreign process is safely excluded", func(t *testing.T) {
		qwenHome := t.TempDir()
		root := filepath.Join(qwenHome, "projects")
		writeTerminalLease(t, qwenHome, "valid", nil)
		writeTerminalLease(t, qwenHome, "foreign", func(m map[string]any) {
			m["pid"] = 9999
			m["owner_id"] = ""
		})
		got, err := NewWithOptions(nil, root).ResolveTerminalSession(context.Background(), terminalQwenProcess())
		if err != nil {
			t.Fatal(err)
		}
		if got.SessionID != "valid" {
			t.Fatalf("ResolveTerminalSession = %+v, want known foreign lease excluded", got)
		}
	})

	t.Run("directory entry cap prevents legacy fallback", func(t *testing.T) {
		qwenHome := t.TempDir()
		root := filepath.Join(qwenHome, "projects")
		host, err := os.Hostname()
		if err != nil {
			t.Fatal(err)
		}
		transcript, _ := writeLegacyTerminalFiles(t, root, "legacy", 4242, host, "legacy")
		dir := filepath.Join(qwenHome, "tmp", "session-writer-locks")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for i := 0; i <= terminalLeaseEntryLimit; i++ {
			name := filepath.Join(dir, "irrelevant-"+strconv.Itoa(i))
			if err := os.WriteFile(name, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		process := terminalQwenProcess()
		process.Files = []adapter.TerminalSessionFile{{Path: transcript, ReadPath: transcript, Append: true, Writable: true}}
		got, err := NewWithOptions(nil, root).ResolveTerminalSession(context.Background(), process)
		if err != nil {
			t.Fatal(err)
		}
		if got.SessionID != "" {
			t.Fatalf("ResolveTerminalSession = %+v, want bounded-directory abstention", got)
		}
	})
}

func writeLegacyTerminalFiles(t *testing.T, root, id string, pid int, hostname string, transcriptIDs ...string) (string, string) {
	t.Helper()
	dir := filepath.Join(root, "project", "chats")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(dir, id+".jsonl")
	var lines []string
	for i, transcriptID := range transcriptIDs {
		lines = append(lines, `{"sessionId":"`+transcriptID+`","type":"user","uuid":"u`+string(rune('a'+i))+`"}`)
	}
	if err := os.WriteFile(transcript, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sidecar := strings.TrimSuffix(transcript, ".jsonl") + ".runtime.json"
	body, err := json.Marshal(map[string]any{
		"schema_version": 1, "pid": pid, "session_id": id, "hostname": hostname,
		"started_at": 1789344000.125, "work_dir": "/project", "qwen_version": "0.19.8",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecar, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return transcript, sidecar
}

func TestResolveTerminalSessionLegacyOwnedTranscriptFallback(t *testing.T) {
	t.Parallel()
	qwenHome := t.TempDir()
	root := filepath.Join(qwenHome, "projects")
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	const id = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	transcript, sidecar := writeLegacyTerminalFiles(t, root, id, 4242, host, id, id)
	process := adapter.TerminalProcess{PID: 4242, Files: []adapter.TerminalSessionFile{{
		Path: transcript, ReadPath: transcript, Append: true, Writable: true,
	}}}

	got, err := NewWithOptions(nil, root).ResolveTerminalSession(context.Background(), process)
	if err != nil {
		t.Fatal(err)
	}
	want := adapter.TerminalSessionIdentity{SessionID: id, Evidence: sidecar}
	if got != want {
		t.Fatalf("ResolveTerminalSession = %+v, want %+v", got, want)
	}
}

func TestResolveTerminalSessionLegacyRejectsMismatchForeignAndNonwriter(t *testing.T) {
	t.Parallel()
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		sidecarPID    int
		sidecarHost   string
		transcriptIDs []string
		fileMutate    func(*adapter.TerminalSessionFile)
	}{
		{"sidecar pid mismatch", 9999, host, []string{"session-a"}, nil},
		{"foreign host", 4242, host + "-other", []string{"session-a"}, nil},
		{"transcript disagreement", 4242, host, []string{"session-a", "session-b"}, nil},
		{"read only", 4242, host, []string{"session-a"}, func(f *adapter.TerminalSessionFile) { f.Writable = false }},
		{"not append", 4242, host, []string{"session-a"}, func(f *adapter.TerminalSessionFile) { f.Append = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			qwenHome := t.TempDir()
			root := filepath.Join(qwenHome, "projects")
			transcript, _ := writeLegacyTerminalFiles(t, root, "session-a", tc.sidecarPID, tc.sidecarHost, tc.transcriptIDs...)
			file := adapter.TerminalSessionFile{Path: transcript, ReadPath: transcript, Append: true, Writable: true}
			if tc.fileMutate != nil {
				tc.fileMutate(&file)
			}
			got, err := NewWithOptions(nil, root).ResolveTerminalSession(context.Background(), adapter.TerminalProcess{PID: 4242, Files: []adapter.TerminalSessionFile{file}})
			if err != nil {
				t.Fatal(err)
			}
			if got.SessionID != "" {
				t.Fatalf("ResolveTerminalSession = %+v, want abstention", got)
			}
		})
	}
}

func TestResolveTerminalSessionLegacyValidPlusMalformedWriterAbstains(t *testing.T) {
	t.Parallel()
	qwenHome := t.TempDir()
	root := filepath.Join(qwenHome, "projects")
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	valid, _ := writeLegacyTerminalFiles(t, root, "session-a", 4242, host, "session-a")
	malformed, _ := writeLegacyTerminalFiles(t, root, "session-b", 4242, host, "wrong-session")
	process := adapter.TerminalProcess{PID: 4242, Files: []adapter.TerminalSessionFile{
		{Path: valid, ReadPath: valid, Append: true, Writable: true},
		{Path: malformed, ReadPath: malformed, Append: true, Writable: true},
	}}

	got, err := NewWithOptions(nil, root).ResolveTerminalSession(context.Background(), process)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "" {
		t.Fatalf("ResolveTerminalSession = %+v, want abstention while a second writer is uncertain", got)
	}
}

func TestResolveTerminalSessionHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := NewWithOptions(nil, filepath.Join(t.TempDir(), "projects")).ResolveTerminalSession(ctx, terminalQwenProcess())
	if err == nil || got.SessionID != "" {
		t.Fatalf("canceled = (%+v, %v), want context error", got, err)
	}
}
