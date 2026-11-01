package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// staleCopilotHooksFile is the exact file an older Observer build (WINNODE,
// observer.exe dated 2026-10-11) wrote on a Windows node (FU-166, Windows rig
// run 2026-10-29 round 4): a bash-only handler, which Copilot CLI on Windows
// cannot run.
const staleCopilotHooksFile = `{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"C:/Users/developer/AppData/Local/SuperBased/Observer/bin/observer.exe hook copilot-cli preToolUse","timeoutSec":30}]}}`

// staleCopilotObserverBinary is the binary the stale file names, which is
// also where the updated build is installed.
const staleCopilotObserverBinary = "C:/Users/developer/AppData/Local/SuperBased/Observer/bin/observer.exe"

func writeStaleCopilotHooks(t *testing.T, home, body string) string {
	t.Helper()
	dir := filepath.Join(home, ".copilot", "hooks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "superbased-observer.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCopilotCLIPowerShellFlagsTheStaleBashOnlyFile pins the FU-166 check:
// on a Windows-native Observer the stale bash-only file reads as Observer's
// entry for preToolUse with no runnable powershell command; on Linux the
// check does not apply (Copilot runs bash there); a file the current writer
// wrote is clean; a foreign file is never Observer's.
func TestCopilotCLIPowerShellFlagsTheStaleBashOnlyFile(t *testing.T) {
	opts := func(home, goos string) Options {
		return Options{BinaryPath: staleCopilotObserverBinary, HomeDir: home, GOOS: goos, DryRun: true}
	}
	t.Run("stale file on windows", func(t *testing.T) {
		home := t.TempDir()
		path := writeStaleCopilotHooks(t, home, staleCopilotHooksFile)
		r, err := NewRegistry(opts(home, "windows"))
		if err != nil {
			t.Fatal(err)
		}
		rep := r.CopilotCLIPowerShell()
		if !rep.Applies || rep.Unreadable || rep.ConfigPath != path {
			t.Fatalf("report = %+v, want an applicable readable report for %s", rep, path)
		}
		if !slices.Equal(rep.Registered, []string{"preToolUse"}) || !slices.Equal(rep.Stale, []string{"preToolUse"}) {
			t.Fatalf("Registered = %v, Stale = %v; want preToolUse both", rep.Registered, rep.Stale)
		}
	})
	t.Run("same file on linux", func(t *testing.T) {
		home := t.TempDir()
		writeStaleCopilotHooks(t, home, staleCopilotHooksFile)
		r, err := NewRegistry(opts(home, "linux"))
		if err != nil {
			t.Fatal(err)
		}
		if rep := r.CopilotCLIPowerShell(); rep.Applies {
			t.Fatalf("report = %+v, want not applicable off Windows", rep)
		}
	})
	t.Run("current writer's file", func(t *testing.T) {
		home := t.TempDir()
		w, err := NewRegistry(Options{BinaryPath: staleCopilotObserverBinary, HomeDir: home, GOOS: "windows", ChecksumsPath: filepath.Join(home, "cs.json")})
		if err != nil {
			t.Fatal(err)
		}
		if res := w.Register("copilot-cli"); res.Error != nil {
			t.Fatal(res.Error)
		}
		r, _ := NewRegistry(opts(home, "windows"))
		rep := r.CopilotCLIPowerShell()
		if len(rep.Registered) == 0 || len(rep.Stale) != 0 {
			t.Fatalf("report = %+v, want registered and nothing stale", rep)
		}
	})
	t.Run("foreign bash-only entry", func(t *testing.T) {
		home := t.TempDir()
		writeStaleCopilotHooks(t, home, `{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"C:/tools/audit.exe preToolUse","timeoutSec":30}]}}`)
		r, _ := NewRegistry(opts(home, "windows"))
		if rep := r.CopilotCLIPowerShell(); len(rep.Registered) != 0 || len(rep.Stale) != 0 {
			t.Fatalf("report = %+v, want a foreign entry ignored", rep)
		}
	})
	t.Run("unreadable file", func(t *testing.T) {
		home := t.TempDir()
		writeStaleCopilotHooks(t, home, `{"version":1,"hooks":`)
		r, _ := NewRegistry(opts(home, "windows"))
		if rep := r.CopilotCLIPowerShell(); !rep.Unreadable {
			t.Fatalf("report = %+v, want Unreadable", rep)
		}
	})
}

// TestCopilotCLIRegisterRewritesTheStaleBashOnlyFile pins the FU-166 repair:
// the registration `observer start` runs (Register, the same writer) on a
// Windows-native Observer replaces Observer's own stale bash-only entry with
// one carrying the powershell command, keeps "bash", the timeout and the
// version, and leaves a foreign entry of another event and a foreign file in
// the hooks directory byte for byte as they were.
func TestCopilotCLIRegisterRewritesTheStaleBashOnlyFile(t *testing.T) {
	home := t.TempDir()
	const foreign = `{"type":"command","bash":"C:/tools/audit.exe postToolUse","timeoutSec":5}`
	body := `{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"` + staleCopilotObserverBinary + ` hook copilot-cli preToolUse","timeoutSec":30}],"postToolUse":[` + foreign + `]}}`
	path := writeStaleCopilotHooks(t, home, body)
	other := filepath.Join(filepath.Dir(path), "lc-fu159.json")
	const otherBody = `{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"echo marker","powershell":"Write-Output marker"}]}}`
	if err := os.WriteFile(other, []byte(otherBody), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{BinaryPath: staleCopilotObserverBinary, HomeDir: home, GOOS: "windows", ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json")})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("copilot-cli")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if !slices.Contains(res.HooksAdded, "preToolUse") {
		t.Fatalf("HooksAdded = %v, want the stale preToolUse entry rewritten", res.HooksAdded)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version int                          `json:"version"`
		Hooks   map[string][]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, raw)
	}
	if got.Version != 1 {
		t.Errorf("version = %d, want 1", got.Version)
	}
	pre := got.Hooks["preToolUse"]
	if len(pre) != 1 {
		t.Fatalf("preToolUse = %s, want exactly Observer's entry", pre)
	}
	var h map[string]any
	if err := json.Unmarshal(pre[0], &h); err != nil {
		t.Fatal(err)
	}
	wantBash := staleCopilotObserverBinary + " hook copilot-cli preToolUse"
	wantPS := "& " + staleCopilotObserverBinary + " hook copilot-cli preToolUse" + copilotPowerShellExit
	if h["bash"] != wantBash || h["powershell"] != wantPS || h["timeoutSec"] != float64(30) || h["type"] != "command" {
		t.Errorf("preToolUse handler = %v, want bash %q, powershell %q, timeoutSec 30", h, wantBash, wantPS)
	}
	if post := got.Hooks["postToolUse"]; len(post) != 1 || !jsonEqual(post[0], json.RawMessage(foreign)) {
		t.Errorf("foreign postToolUse entry changed: %s", post)
	}
	if b, err := os.ReadFile(other); err != nil || string(b) != otherBody {
		t.Errorf("foreign hooks file changed: %q, %v", b, err)
	}
	ro, _ := NewRegistry(Options{BinaryPath: staleCopilotObserverBinary, HomeDir: home, GOOS: "windows", DryRun: true})
	if rep := ro.CopilotCLIPowerShell(); len(rep.Stale) != 0 {
		t.Errorf("after the rewrite Stale = %v, want none", rep.Stale)
	}
}

// TestCopilotCLIWindowsPowerShellFlagsTheStaleBridge pins the FU-166 tail:
// a WSL Observer reads the copilot-cli-windows bridge file it writes into
// the Windows home. The bridge the current writer wrote is clean; the same
// file with its powershell fields gone (what an older WSL build wrote) is
// stale on every event; a foreign entry is never Observer's; and the check
// does not apply on a Windows-native Observer or when no Windows home
// resolves (a pinned home with none named).
func TestCopilotCLIWindowsPowerShellFlagsTheStaleBridge(t *testing.T) {
	home := t.TempDir()
	winHome := filepath.Join(home, "win")
	if err := os.MkdirAll(filepath.Join(winHome, ".copilot"), 0o755); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		BinaryPath: "/usr/local/bin/observer", HomeDir: home, GOOS: "linux",
		WSLDistro: "Ubuntu", WindowsCopilotHome: winHome,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	}
	r, err := NewRegistry(opts)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("copilot-cli-windows"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	path := filepath.Join(winHome, ".copilot", "hooks", "superbased-observer.json")
	rep := r.CopilotCLIWindowsPowerShell()
	if !rep.Applies || rep.Target != "copilot-cli-windows" || rep.ConfigPath != path || len(rep.Registered) != 2 || len(rep.Stale) != 0 {
		t.Fatalf("fresh bridge = %+v, want two registered events and none stale", rep)
	}

	// An older WSL build wrote the same bridge with bash only.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, hs := range doc["hooks"].(map[string]any) {
		for _, h := range hs.([]any) {
			delete(h.(map[string]any), "powershell")
		}
	}
	stale, _ := json.Marshal(doc)
	if err := os.WriteFile(path, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	rep = r.CopilotCLIWindowsPowerShell()
	if !slices.Equal(rep.Stale, []string{"preToolUse", "userPromptSubmitted"}) {
		t.Fatalf("bash-only bridge = %+v, want both events stale", rep)
	}

	// A foreign entry is never Observer's.
	if err := os.WriteFile(path, []byte(`{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"my-own-hook","timeoutSec":5}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep := r.CopilotCLIWindowsPowerShell(); len(rep.Registered) != 0 || len(rep.Stale) != 0 {
		t.Errorf("foreign entry = %+v, want nothing of Observer's", rep)
	}

	// Not on a Windows-native Observer (the native check covers it), and
	// not when no Windows home resolves.
	win := opts
	win.GOOS = "windows"
	if rw, err := NewRegistry(win); err != nil || rw.CopilotCLIWindowsPowerShell().Applies {
		t.Errorf("a Windows-native Observer read the bridge (err %v)", err)
	}
	none := opts
	none.WindowsCopilotHome = ""
	if rn, err := NewRegistry(none); err != nil || rn.CopilotCLIWindowsPowerShell().Applies {
		t.Errorf("a pinned home with no Windows home named read a bridge (err %v)", err)
	}
}
