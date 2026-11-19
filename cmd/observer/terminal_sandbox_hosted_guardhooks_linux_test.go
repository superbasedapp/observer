//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// fileBox is a box with a tiny file system the guard hook seed reads and
// writes through its two scripts; every other exec answers empty.
type fileBox struct {
	sandboxremote.Client
	mu       sync.Mutex
	files    map[string]string
	execs    []sandboxremote.ExecSpec
	failWrit bool
}

func (b *fileBox) Exec(_ context.Context, _ string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.execs = append(b.execs, spec)
	a := spec.Argv
	if len(a) >= 5 && a[0] == "sh" && a[2] == hostedReadBoxFileScript {
		c, ok := b.files[a[4]]
		if !ok {
			return doneProc{Reader: strings.NewReader(""), code: hostedBoxFileAbsent}, nil
		}
		return doneProc{Reader: strings.NewReader(c), code: 0}, nil
	}
	if len(a) >= 6 && a[0] == "sh" && a[2] == hostedWriteBoxHookScript {
		if b.failWrit {
			return doneProc{Reader: strings.NewReader("read-only file system"), code: 1}, nil
		}
		b.files[a[4]] = a[5]
		return doneProc{Reader: strings.NewReader(""), code: 0}, nil
	}
	return doneProc{Reader: strings.NewReader(""), code: 0}, nil
}

// guardHooksTestRun is a hosted run on Daytona's layout over box.
func guardHooksTestRun(t *testing.T, box sandboxremote.Client, tool string, seed bool) *hostedRun {
	t.Helper()
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorDaytona)
	r := &hostedRun{
		plan:   hostedPlanFile{RunID: "r1", Provider: v.ID, ObserverDir: t.TempDir(), Root: "/w/app", Tool: tool, GuardHooks: seed},
		t:      hostedTerm{out: io.Discard},
		now:    time.Now,
		vendor: v, client: box,
	}
	r.layout = v.Layout(r.plan.Root)
	r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, "https://box.example.com", "", r.plan.RunID, r.now(), time.Hour)
	r.rec.VendorID = "box-1"
	return r
}

// TestHostedSeedsGuardHooksIntoTheBoxOnly (SBXD-6): with the plan's
// guard_hooks on, the tool's settings file in the BOX home gets exactly
// hook.RenderBoxHooks's content, nothing is written on this machine, a
// second seed (a resumed box) writes nothing, and with it off no hook
// exec runs at all.
func TestHostedSeedsGuardHooksIntoTheBoxOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	box := &fileBox{files: map[string]string{}}
	r := guardHooksTestRun(t, box, "claude-code", true)
	r.seedBoxHooks(context.Background())
	if r.guardHooksErr != nil {
		t.Fatalf("seed: %v", r.guardHooksErr)
	}
	want := path.Join(r.layout.Home, ".claude", "settings.json")
	got, ok := box.files[want]
	if !ok || len(box.files) != 1 {
		t.Fatalf("box files %v, want only %s", keysOf(box.files), want)
	}
	c, _ := integration.For("claude-code")
	env := r.agentEnv()
	f, err := hook.RenderBoxHooks(hook.BoxHookInput{Capability: c, Home: r.layout.Home, Binary: r.layout.Binary, Getenv: func(k string) string { return env[k] }, SkipEvent: autoRegisterSkipEvent})
	if err != nil {
		t.Fatal(err)
	}
	if got != string(f.Content) || !strings.Contains(got, r.layout.Binary+" hook claude-code pre-tool") {
		t.Fatalf("seeded file:\n%s", got)
	}
	for _, e := range box.execs {
		for _, a := range e.Argv[min(len(e.Argv), 4):] {
			if strings.HasPrefix(a, "/") && !strings.HasPrefix(a, r.layout.Home+"/") {
				t.Fatalf("a hook exec names a path outside the box home: %v", e.Argv)
			}
		}
	}
	entries, _ := os.ReadDir(home)
	if len(entries) != 0 {
		t.Fatalf("the seed wrote on this machine: %v", entries)
	}
	// A resumed box already holds it: read, no write.
	box.execs = nil
	r.seedBoxHooks(context.Background())
	if r.guardHooksErr != nil || len(box.execs) != 1 || box.execs[0].Argv[2] != hostedReadBoxFileScript {
		t.Fatalf("the second seed: err %v execs %v", r.guardHooksErr, box.execs)
	}
	// guard_hooks resolved off: no exec.
	off := &fileBox{files: map[string]string{}}
	ro := guardHooksTestRun(t, off, "claude-code", false)
	ro.seedToolState(context.Background())
	for _, e := range off.execs {
		if len(e.Argv) > 2 && (e.Argv[2] == hostedReadBoxFileScript || e.Argv[2] == hostedWriteBoxHookScript) {
			t.Fatalf("a hook exec ran with guard_hooks off: %v", e.Argv)
		}
	}
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestHostedGuardHooksSeedFailureRefusesTheRun: a seed that cannot write,
// a tool that cannot be covered and a box file that turns hooks off each
// leave guardHooksErr set (runBox refuses before the agent starts), in
// plain words with the detail marked technical.
func TestHostedGuardHooksSeedFailureRefusesTheRun(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	for _, tc := range []struct {
		name     string
		tool     string
		failWrit bool
		existing string
		cause    string
	}{
		{"write fails", "claude-code", true, "", "read-only file system"},
		{"tool not covered", "aider", false, "", "cannot be seeded"},
		{"box turns hooks off", "claude-code", false, `{"disableAllHooks":true}`, "disableAllHooks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			box := &fileBox{files: map[string]string{}, failWrit: tc.failWrit}
			r := guardHooksTestRun(t, box, tc.tool, true)
			if tc.existing != "" {
				box.files[path.Join(r.layout.Home, ".claude", "settings.json")] = tc.existing
			}
			r.seedBoxHooks(context.Background())
			err := r.guardHooksErr
			if err == nil || !strings.Contains(err.Error(), "the agent did not start") || !strings.Contains(err.Error(), tc.cause) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// TestBoxGateHookFailsClosedOnRelayDrop (SBXD-6): the seeded PreToolUse
// command, run in a box whose relay cannot be reached (the hosted relay
// dropped and was not re-opened within the hook's budget), blocks the tool
// call, while a capture-only event is spooled, never blocked.
func TestBoxGateHookFailsClosedOnRelayDrop(t *testing.T) {
	c, _ := integration.For("claude-code")
	f, err := hook.RenderBoxHooks(hook.BoxHookInput{Capability: c, Home: "/home/box", Binary: "/home/box/.observer-box/bin/observer"})
	if err != nil {
		t.Fatal(err)
	}
	gate, capture := seededArgs(t, f.Content, "pre-tool"), seededArgs(t, f.Content, "post-tool")

	sock := relayShortDir(t)
	if err := os.Chmod(sock, 0o700); err != nil {
		t.Fatal(err)
	}
	run, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "run-box", Tool: "claude-code", ProjectRoot: sock, WorkspaceDir: sock, Roots: []string{sock}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteBoxRecord(sock, run); err != nil {
		t.Fatal(err)
	}
	oldSock, oldRec, oldSpool := boxSocketDir, boxRecordPath, relaySpoolDir
	boxSocketDir, boxRecordPath, relaySpoolDir = sock, filepath.Join(sock, sandboxrelayd.BoxRecordName), filepath.Join(t.TempDir(), "spool")
	t.Cleanup(func() { boxSocketDir, boxRecordPath, relaySpoolDir = oldSock, oldRec, oldSpool })
	// A hosted agent's environment: the redial wait, bounded by a short
	// hook budget. No relay socket listens: the relay dropped.
	t.Setenv(hostedRelayRedialEnv, "1")
	t.Setenv("OBSERVER_HOOK_MAX_RUNTIME", "600ms")

	var out, errb bytes.Buffer
	code, boxed := boxHookRelay(gate, bytes.NewReader([]byte(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`)), &out, &errb)
	if !boxed {
		t.Fatal("the in-box hook was not handled as a box hook")
	}
	blocked := code == 2 || bytes.Contains(out.Bytes(), []byte(`"deny"`)) || bytes.Contains(out.Bytes(), []byte(`"block"`))
	if !blocked {
		t.Fatalf("a gate hook with the relay down was not blocked: code %d out %q err %q", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String()+errb.String(), "relay") {
		t.Fatalf("the block does not say why: out %q err %q", out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	code, _ = boxHookRelay(capture, bytes.NewReader([]byte(`{}`)), &out, &errb)
	if code != 0 || out.Len() != 0 {
		t.Fatalf("a capture-only event with the relay down: code %d out %q err %q", code, out.String(), errb.String())
	}
	if n := spooledCount(); n != 1 {
		t.Fatalf("the capture event was not spooled (%d files)", n)
	}
}

// seededArgs returns the `observer hook` arguments (after the binary and
// "hook") of the seeded command for one event spelling.
func seededArgs(t *testing.T, settings []byte, eventArg string) []string {
	t.Helper()
	for _, line := range strings.Split(string(settings), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `"command": "`) || !strings.HasSuffix(line, " "+eventArg+`"`) {
			continue
		}
		toks := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(line, `"command": "`), `"`))
		if len(toks) < 4 || toks[1] != "hook" {
			t.Fatalf("seeded command %q", line)
		}
		return toks[2:]
	}
	t.Fatalf("no seeded command for %s", eventArg)
	return nil
}

// spooledCount is how many capture events wait in the box's spool.
func spooledCount() int {
	entries, err := os.ReadDir(relaySpoolDir)
	if err != nil {
		return 0
	}
	return len(entries)
}
