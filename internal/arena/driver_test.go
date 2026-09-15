package arena

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeBin writes an executable shell script at dir/name. The script dumps
// "$@" to a file and prints whatever body says, letting tests observe argv
// while pretending to be claude/codex.
func fakeBin(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func arenaTestStore(t *testing.T) *store.Store {
	t.Helper()
	// File-backed temp DB (not :memory:): the sqlite driver gives each
	// pooled connection its own :memory: database, so migrations would
	// land on a different connection than the queries.
	path := filepath.Join(t.TempDir(), "arena.db")
	d, err := db.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	return store.New(d)
}

func initArenaRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init")
	run("config", "user.email", "t@example.com")
	run("config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(dir, "base.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-m", "init")
	return dir
}

const claudeFakeBody = `
echo "$@" > "$ARENA_ARGS_FILE"
cat <<JSON
{"type":"result","result":"I did the task","session_id":"$5"}
JSON
`

func TestExecuteDrive_ClaudeShape(t *testing.T) {
	binDir := t.TempDir()
	argsFile := filepath.Join(binDir, "args.txt")
	bin := fakeBin(t, binDir, "claude-fake",
		strings.ReplaceAll(claudeFakeBody, "$ARENA_ARGS_FILE", argsFile))
	driveBinOverrides["claude-code"] = bin
	defer delete(driveBinOverrides, "claude-code")

	wt := t.TempDir()
	claudeSpec, _ := integration.For("claude-code")
	res, err := executeDrive(context.Background(), bin, claudeSpec.Headless, driveRequest{
		Tool:         "claude-code",
		Model:        "sonnet",
		WorktreePath: wt,
		Prompt:       "fix the bug",
		Timeout:      30 * time.Second,
	})
	if err != nil {
		t.Fatalf("executeDrive: %v", err)
	}
	raw, _ := os.ReadFile(argsFile)
	argv := string(raw)
	for _, want := range []string{"-p fix the bug", "--session-id ", "--output-format json", "--dangerously-skip-permissions", "--model sonnet"} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv missing %q:\n%s", want, argv)
		}
	}
	if res.FinalAnswer != "I did the task" {
		t.Errorf("FinalAnswer=%q", res.FinalAnswer)
	}
	if len(res.SessionIDs) != 1 || res.SessionIDs[0] == "" {
		t.Errorf("SessionIDs=%v", res.SessionIDs)
	}
	if res.ExitCode != 0 || res.TimedOut {
		t.Errorf("exit=%d timedOut=%v", res.ExitCode, res.TimedOut)
	}
}

func TestExecuteDrive_CodexShape(t *testing.T) {
	binDir := t.TempDir()
	outFile := ""
	bin := fakeBin(t, binDir, "codex-fake", `
echo "$@" > "`+binDir+`/args.txt"
# emulate codex: thread line on stdout, final message to -o arg
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then echo "codex did it" > "$a"; fi
  prev="$a"
done
echo '{"type":"thread.started","thread_id":"thr-123"}'
`)
	_ = outFile

	codexSpec, _ := integration.For("codex")
	wt := t.TempDir()
	driveBinOverrides["codex"] = bin
	defer delete(driveBinOverrides, "codex")

	res, err := executeDrive(context.Background(), bin, codexSpec.Headless, driveRequest{
		Tool:         "codex",
		Model:        "gpt-test",
		WorktreePath: wt,
		Prompt:       "add tests",
		Timeout:      30 * time.Second,
	})
	if err != nil {
		t.Fatalf("executeDrive: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(binDir, "args.txt"))
	argv := string(raw)
	for _, want := range []string{"exec", "--skip-git-repo-check", "-s workspace-write", "-C", "--json"} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv missing %q:\n%s", want, argv)
		}
	}
	if res.FinalAnswer != "codex did it\n" {
		t.Errorf("FinalAnswer=%q", res.FinalAnswer)
	}
	if len(res.SessionIDs) != 1 || res.SessionIDs[0] != "thr-123" {
		t.Errorf("SessionIDs=%v, want [thr-123]", res.SessionIDs)
	}
}

func TestParseGrokResult(t *testing.T) {
	t.Parallel()
	doc := `{"text":"4","stopReason":"end_turn","sessionId":"01a02e28-fd95","usage":{"input_tokens":2665,"output_tokens":40},"total_cost_usd":0.0019261}`
	ans, sid, ok := parseGrokResult([]byte(doc))
	if !ok || ans != "4" || sid != "01a02e28-fd95" {
		t.Fatalf("parseGrokResult = %q %q %v", ans, sid, ok)
	}
	if _, _, ok := parseGrokResult([]byte(`{"stopReason":"end_turn"}`)); ok {
		t.Fatal("empty text must not parse as an answer")
	}
}

func TestParseOpenCodeEvents(t *testing.T) {
	t.Parallel()
	stream := `{"type":"step_start","sessionID":"ses_a","part":{"type":"step-start"}}
{"type":"text","sessionID":"ses_a","part":{"type":"text","text":"working"}}
{"type":"text","sessionID":"ses_b","part":{"type":"text","text":"final answer"}}
{"type":"step_finish","sessionID":"ses_b","part":{"type":"step-finish"}}`
	ans, sids := parseOpenCodeEvents([]byte(stream))
	if ans != "final answer" {
		t.Fatalf("answer = %q", ans)
	}
	if len(sids) != 2 || sids[0] != "ses_a" || sids[1] != "ses_b" {
		t.Fatalf("session ids = %v", sids)
	}
}

func TestProxyEnvFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		tool string
		want []string
	}{
		{name: "claude", tool: "claude-code", want: []string{"ANTHROPIC_BASE_URL=http://127.0.0.1:8820"}},
		{name: "grok named upstream", tool: "grok", want: []string{"GROK_CLI_CHAT_PROXY_BASE_URL=http://127.0.0.1:8820/up/grok/v1"}},
		{name: "opencode named openrouter", tool: "opencode", want: []string{`OPENCODE_CONFIG_CONTENT={"provider":{"openrouter":{"options":{"baseURL":"http://127.0.0.1:8820/up/openrouter/api/v1"}}}}`}},
		{name: "aider litellm", tool: "aider", want: []string{"OPENAI_API_BASE=http://127.0.0.1:8820/v1"}},
		{name: "codex config route", tool: "codex", want: nil},
		{name: "unknown", tool: "future", want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := proxyEnvFor(tc.tool, "http://127.0.0.1:8820/")
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("proxyEnvFor(%q) = %v; want %v", tc.tool, got, tc.want)
			}
		})
	}
}

func TestExecuteDrive_AiderContextFiles(t *testing.T) {
	t.Parallel()
	binDir := t.TempDir()
	argsFile := filepath.Join(binDir, "args.txt")
	bin := fakeBin(t, binDir, "aider-fake", `
echo "$@" > "`+argsFile+`"
echo "done"
`)
	ic, ok := integration.For("aider")
	if !ok || ic.Headless == nil {
		t.Fatal("aider headless contract missing")
	}
	res, err := executeDrive(context.Background(), bin, ic.Headless, driveRequest{
		Tool:         "aider",
		WorktreePath: t.TempDir(),
		Prompt:       "update both files",
		ContextFiles: []string{"one.go", filepath.Join("pkg", "two.go")},
	})
	if err != nil {
		t.Fatalf("executeDrive: %v", err)
	}
	if res.ExitCode != 0 || res.FinalAnswer != "done\n" {
		t.Fatalf("result = %+v", res)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	argv := string(raw)
	for _, want := range []string{"--message update both files", "--yes --no-auto-commits", "one.go", filepath.Join("pkg", "two.go")} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv missing %q:\n%s", want, argv)
		}
	}
}

func TestExecuteDrive_OpenCodeProxyDefaultsToRoutedModel(t *testing.T) {
	binDir := t.TempDir()
	argsFile := filepath.Join(binDir, "args.txt")
	bin := fakeBin(t, binDir, "opencode-fake", `
echo "$@" > "`+argsFile+`"
cat <<'JSON'
{"type":"text","sessionID":"ses_routed","part":{"type":"text","text":"done"}}
JSON
`)
	ic, ok := integration.For("opencode")
	if !ok || ic.Headless == nil {
		t.Fatal("opencode headless contract missing")
	}
	res, err := executeDrive(context.Background(), bin, ic.Headless, driveRequest{
		Tool:         "opencode",
		WorktreePath: t.TempDir(),
		Prompt:       "make a small edit",
		ProxyURL:     "http://127.0.0.1:8820",
	})
	if err != nil {
		t.Fatalf("executeDrive: %v", err)
	}
	if res.FinalAnswer != "done" || len(res.SessionIDs) != 1 || res.SessionIDs[0] != "ses_routed" {
		t.Fatalf("result = %+v", res)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if argv := string(raw); !strings.Contains(argv, "--model openrouter/stealth/ox-alpha") {
		t.Fatalf("routed default model missing from argv:\n%s", argv)
	}
}

func TestExecuteDrive_OpenCodeProxyRejectsUnroutableProvider(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	bin := fakeBin(t, t.TempDir(), "opencode-fake", `
touch "`+marker+`"
`)
	ic, ok := integration.For("opencode")
	if !ok || ic.Headless == nil {
		t.Fatal("opencode headless contract missing")
	}
	_, err := executeDrive(context.Background(), bin, ic.Headless, driveRequest{
		Tool:         "opencode",
		Model:        "opencode/x-preview-f-free",
		WorktreePath: t.TempDir(),
		Prompt:       "make a small edit",
		ProxyURL:     "http://127.0.0.1:8820",
	})
	if err == nil || !strings.Contains(err.Error(), `expected prefix "openrouter/"`) {
		t.Fatalf("executeDrive error = %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("unroutable harness started: %v", statErr)
	}
}

// A harness that spawns a background grandchild holding the stdout pipe
// must not wedge the drive: file-backed capture returns at direct-child
// exit (live regression: headless-20260823-01 grok "timed out" at 600s
// while the binary finished in ~15s because a hook grandchild held the
// pipe).
func TestExecuteDrive_GrandchildDoesNotWedge(t *testing.T) {
	t.Parallel()
	bin := fakeBin(t, t.TempDir(), "wedge-fake", `
echo '{"type":"result","result":"quick answer"}'
sleep 30 &
exit 0
`)
	prev := driveBinOverrides["claude-code"]
	driveBinOverrides["claude-code"] = bin
	defer func() { driveBinOverrides["claude-code"] = prev }()

	ic, _ := integration.For("claude-code")
	res, err := executeDrive(context.Background(), bin, ic.Headless, driveRequest{
		Tool:      "claude-code",
		Prompt:    "p",
		Timeout:   10 * time.Second,
		ConfigDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("executeDrive: %v", err)
	}
	if res.TimedOut || res.ExitCode != 0 {
		t.Fatalf("unexpected outcome: %+v", res)
	}
	if res.FinalAnswer != "quick answer" {
		t.Fatalf("answer lost across file capture: %q", res.FinalAnswer)
	}
}

func TestExecuteDrive_ProcessAttributionCallbacksBracketWait(t *testing.T) {
	bin := fakeBin(t, t.TempDir(), "callback-fake", `
cat <<'JSON'
{"type":"result","result":"done"}
JSON
`)
	ic, _ := integration.For("claude-code")
	var events []string
	res, err := executeDrive(context.Background(), bin, ic.Headless, driveRequest{
		Tool:      "claude-code",
		Prompt:    "p",
		ConfigDir: t.TempDir(),
		OnStart: func(pid int) error {
			if pid <= 0 {
				t.Fatalf("invalid started pid %d", pid)
			}
			events = append(events, "start")
			return nil
		},
		OnExit: func(pid int) {
			if pid <= 0 {
				t.Fatalf("invalid exited pid %d", pid)
			}
			events = append(events, "exit")
		},
	})
	if err != nil || res.FinalAnswer != "done" {
		t.Fatalf("executeDrive = %+v err=%v", res, err)
	}
	if strings.Join(events, ",") != "start,exit" {
		t.Fatalf("callback order = %v", events)
	}
}

func TestExecuteDrive_AttributionFailureStopsHarness(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "spent.txt")
	bin := fakeBin(t, t.TempDir(), "attribution-fail-fake", `
sleep 1
echo spent > "`+marker+`"
`)
	ic, _ := integration.For("claude-code")
	_, err := executeDrive(context.Background(), bin, ic.Headless, driveRequest{
		Tool:      "claude-code",
		Prompt:    "p",
		ConfigDir: t.TempDir(),
		OnStart: func(int) error {
			return errors.New("bridge write failed")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "process attribution") {
		t.Fatalf("executeDrive error = %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("harness continued after attribution failure: %v", err)
	}
}

func TestExecuteDrive_AdmissionFailureNeverStartsHarness(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "spent.txt")
	bin := fakeBin(t, t.TempDir(), "admission-fail-fake", `
echo spent > "`+marker+`"
`)
	ic, _ := integration.For("claude-code")
	wantErr := errors.New("managed budget refused")
	_, err := executeDrive(context.Background(), bin, ic.Headless, driveRequest{
		Tool:      "claude-code",
		Prompt:    "p",
		ProxyURL:  "http://127.0.0.1:8820",
		ConfigDir: t.TempDir(),
		Admission: func(ctx context.Context, tool, proxyURL string) error {
			if ctx == nil || tool != "claude-code" || proxyURL != "http://127.0.0.1:8820" {
				t.Fatalf("admission inputs: ctx=%v tool=%q proxy=%q", ctx, tool, proxyURL)
			}
			return wantErr
		},
	})
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "arena.executeDrive: admission") {
		t.Fatalf("executeDrive error = %v, want wrapped admission error", err)
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("harness started before admission: %v", statErr)
	}
}
