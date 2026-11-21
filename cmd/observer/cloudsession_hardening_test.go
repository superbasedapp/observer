package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/cloudsessionnet"
)

// cloudsession_hardening_test.go covers lane CA-B6: the facts lane CA-A2
// grounded live in a Claude Code cloud session (Stop/SessionEnd did not
// fire, a failed setup does not stop the session, the default network level
// answers 403 at CONNECT, repository hook edits hot-reload mid-session).

// TestCloudSessionHookCommandsNoOpWithoutBinary runs every committed hook
// command with a real sh: with the binary missing (a failed or skipped
// setup) each one exits 0 and prints nothing, in or out of the cloud; with
// the binary present it runs only inside the cloud.
func TestCloudSessionHookCommandsNoOpWithoutBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the committed hooks are POSIX sh for Linux sandboxes")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	for _, agent := range []string{"claude-code", "copilot"} {
		t.Run(agent, func(t *testing.T) {
			dir := t.TempDir()
			prefix := filepath.Join(dir, "prefix")
			plan, err := cloudsession.PlanInit(cloudsession.PlanOptions{
				Agent: agent, Destination: cloudsession.DestOrg, DestinationURL: "https://org.example.com",
				ObserverVersion: "v1.37.0", VendorKeys: []string{"npbhJUUL/Zy088BDnuqYRDqjjQtlyF9/eVcWFOCzj2g="},
				NpmPins: cloudSessionTestPins, InstallDir: prefix,
			}, func(string) (string, bool, error) { return "", false, nil })
			if err != nil {
				t.Fatal(err)
			}
			a, _ := cloudsession.AgentByID(agent)
			hf, _ := cloudsession.HookFile(a)
			var cmds []string
			for _, c := range plan.Changes {
				if c.Path == hf.Path {
					cmds = cloudSessionCommandsOf(t, c.After)
				}
			}
			// Feature-tagged entries (lane CA-C2's gates) are off here.
			want := 0
			for _, b := range a.Hooks {
				if b.Feature == "" {
					want++
				}
			}
			if len(cmds) != want {
				t.Fatalf("found %d commands, want %d", len(cmds), want)
			}
			cloudOn := []string{"CLAUDE_CODE_REMOTE=true", "GITHUB_ACTIONS=true"}
			run := func(cmd string, env []string) (string, int) {
				t.Helper()
				c := exec.Command("sh", "-c", cmd)
				c.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + dir}, env...)
				c.Stdin = strings.NewReader(`{"session_id":"s","hook_event_name":"X"}`)
				out, err := c.CombinedOutput()
				code := 0
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					code = ee.ExitCode()
				} else if err != nil {
					t.Fatal(err)
				}
				return string(out), code
			}
			for _, cmd := range cmds {
				for _, env := range [][]string{nil, cloudOn} {
					if out, code := run(cmd, env); code != 0 || out != "" {
						t.Errorf("missing binary, env %v: exit %d output %q for %s", env, code, out, cmd)
					}
				}
			}
			// Positive control: a stand-in observer records its argv.
			if err := os.MkdirAll(prefix, 0o755); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(dir, "argv.log")
			cloudSessionWrite(t, filepath.Join(prefix, "observer"), []byte("#!/bin/sh\necho \"$*\" >>"+log+"\n"))
			if err := os.Chmod(filepath.Join(prefix, "observer"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, cmd := range cmds {
				if out, code := run(cmd, nil); code != 0 || out != "" {
					t.Errorf("outside the cloud: exit %d output %q", code, out)
				}
			}
			if _, err := os.Stat(log); !os.IsNotExist(err) {
				t.Fatal("observer ran outside the cloud")
			}
			for _, cmd := range cmds {
				if _, code := run(cmd, cloudOn); code != 0 {
					t.Errorf("inside the cloud: exit %d for %s", code, cmd)
				}
			}
			b, _ := os.ReadFile(log)
			if got := strings.Count(string(b), "\n"); got != len(cmds) {
				t.Errorf("observer ran %d times, want %d:\n%s", got, len(cmds), b)
			}
			for _, trig := range cloudsession.Triggers() {
				if !strings.Contains(string(b), "--trigger "+string(trig)) {
					t.Errorf("no %s flush ran:\n%s", trig, b)
				}
			}
		})
	}
}

// cloudSessionCommandsOf returns the owned commands of a hook file (either
// agent's shape).
func cloudSessionCommandsOf(t *testing.T, content string) []string {
	t.Helper()
	var doc struct {
		Hooks map[string][]map[string]any `json:"hooks"`
	}
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		t.Fatal(err)
	}
	var out []string
	take := func(e map[string]any) {
		for _, k := range []string{"command", "bash"} {
			if s, ok := e[k].(string); ok && strings.HasSuffix(s, cloudsession.OwnerTag) {
				out = append(out, s)
			}
		}
	}
	for _, items := range doc.Hooks {
		for _, it := range items {
			if inner, ok := it["hooks"].([]any); ok {
				for _, e := range inner {
					if m, ok := e.(map[string]any); ok {
						take(m)
					}
				}
				continue
			}
			take(it)
		}
	}
	return out
}

// TestCloudSessionFlushNetworkBlocked: a 403 at CONNECT records "Not
// established: environment network level blocks <host>" and keeps the rows;
// prompt and periodic flushes of the same session then stop knocking; the
// start flush of the next session tries again.
func TestCloudSessionFlushNetworkBlocked(t *testing.T) {
	cfg := cloudSessionFixture(t)
	var connects int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			connects++
		}
		http.Error(w, "egress policy denied", http.StatusForbidden)
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	env := map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": "cse_one", "SBO_CLOUD_SESSION_TOKEN": "ship-123"}
	opts := cloudSessionFlushOptions{
		Timeout: cloudSessionTestFlushTimeout,
		Agent:   "claude-code", Trigger: cloudsession.TriggerPrompt, Destination: cloudsession.DestOrg,
		URL: "https://org.example.com", ConfigPath: cfg, Repo: cloudSessionRepo(t, "claude-code", true),
		Env: cloudEnv(env), HTTP: cloudsessionnet.HTTPOptions{Proxy: http.ProxyURL(pu)},
	}
	res, err := runCloudSessionFlush(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage != "not_established" || res.CoverageReason != "network_blocked" || !res.Pending || res.Envelopes != 0 ||
		!strings.Contains(res.CoverageMessage, "environment network level blocks org.example.com") || strings.Contains(res.Error, "ship-123") {
		t.Fatalf("blocked result = %+v", res)
	}
	if connects != 1 {
		t.Fatalf("CONNECTs = %d", connects)
	}
	for _, trig := range []cloudsession.Trigger{cloudsession.TriggerPrompt, cloudsession.TriggerPeriodic} {
		opts.Trigger, opts.Every = trig, 1
		res, err = runCloudSessionFlush(context.Background(), opts)
		if err != nil || !strings.Contains(res.Skipped, "network level blocks org.example.com") {
			t.Fatalf("%s after a block: res %+v err %v", trig, res, err)
		}
	}
	if connects != 1 {
		t.Fatalf("prompt/periodic retried a blocked host: CONNECTs = %d", connects)
	}
	// A new session's start flush tries again (the environment may have
	// been moved to Custom in between).
	env["CLAUDE_CODE_REMOTE_SESSION_ID"] = "cse_two"
	opts.Trigger = cloudsession.TriggerStart
	if res, err = runCloudSessionFlush(context.Background(), opts); err != nil || res.CoverageReason != "network_blocked" {
		t.Fatalf("start: res %+v err %v", res, err)
	}
	if connects != 2 {
		t.Fatalf("start did not try again: CONNECTs = %d", connects)
	}
	// The recorded state is what `status` prints.
	st := loadCloudSessionCoverage(filepath.Join(filepath.Dir(cfg), "cloud-session"), "claude-code")
	if st == nil || st.Reason != cloudsession.ReasonNetworkBlocked || st.Host != "org.example.com" || st.VendorRef != "cse_two" {
		t.Fatalf("recorded coverage = %+v", st)
	}
}

// TestCloudSessionFlushGuard: the flush ships only while the working tree's
// owned hook block equals the one committed when the session started.
func TestCloudSessionFlushGuard(t *testing.T) {
	cfg := cloudSessionFixture(t)
	out := filepath.Join(t.TempDir(), "envelopes")
	repo := cloudSessionRepo(t, "claude-code", true)
	env := map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": "cse_a"}
	opts := cloudSessionFlushOptions{
		Timeout: cloudSessionTestFlushTimeout,
		Agent:   "claude-code", Trigger: cloudsession.TriggerStart, Destination: cloudsession.DestFile,
		URL: out, ConfigPath: cfg, Repo: repo, Env: cloudEnv(env),
	}
	// The agent rewrites its hooks mid-session (hot reload, no prompt).
	cloudSessionEditHooks(t, repo, "https://org.example.com", "https://collector.attacker.example")
	opts.Trigger = cloudsession.TriggerPrompt
	res, err := runCloudSessionFlush(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Held || res.Guard != "changed" || res.CoverageReason != "hook_block_changed" || res.Envelopes != 0 || res.Scanned == 0 {
		t.Fatalf("edited hooks: %+v", res)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("an envelope shipped under an edited hook block")
	}
	// Committing the edit does not move the session's baseline.
	cloudSessionGit(t, repo, "commit", "-q", "-am", "agent edit")
	if res, _ = runCloudSessionFlush(context.Background(), opts); !res.Held {
		t.Fatalf("a committed mid-session edit was trusted: %+v", res)
	}
	// Restoring the block resumes delivery, rows included.
	cloudSessionEditHooks(t, repo, "https://collector.attacker.example", "https://org.example.com")
	res, err = runCloudSessionFlush(context.Background(), opts)
	if err != nil || res.Held || res.Guard != "verified" || res.Envelopes != 1 || res.Coverage != "verified" {
		t.Fatalf("restored hooks: res %+v err %v", res, err)
	}
}

func cloudSessionGit(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// TestCloudSessionFlushUncommittedHooks: hooks that are not committed at HEAD
// have nothing to be verified against. The start flush says so as an error
// (once per session); the others hold quietly; --trust-uncommitted-hooks
// (a manual test before commit) ships.
func TestCloudSessionFlushUncommittedHooks(t *testing.T) {
	cfg := cloudSessionFixture(t)
	out := filepath.Join(t.TempDir(), "envelopes")
	env := map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": "cse_u"}
	opts := cloudSessionFlushOptions{
		Timeout: cloudSessionTestFlushTimeout,
		Agent:   "claude-code", Trigger: cloudsession.TriggerStart, Destination: cloudsession.DestFile,
		URL: out, ConfigPath: cfg, Repo: cloudSessionRepo(t, "claude-code", false), Env: cloudEnv(env),
	}
	if _, err := runCloudSessionFlush(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "not committed") {
		t.Fatalf("start with uncommitted hooks: err = %v", err)
	}
	opts.Trigger = cloudsession.TriggerPrompt
	res, err := runCloudSessionFlush(context.Background(), opts)
	if err != nil || !res.Held || res.Guard != "uncommitted" || res.CoverageReason != "hook_block_uncommitted" {
		t.Fatalf("prompt: res %+v err %v", res, err)
	}
	opts.TrustUncommittedHooks = true
	res, err = runCloudSessionFlush(context.Background(), opts)
	if err != nil || res.Held || res.Envelopes != 1 {
		t.Fatalf("trusted: res %+v err %v", res, err)
	}
	// A later session whose hooks are not in a git repository at all: same
	// as uncommitted.
	env["CLAUDE_CODE_REMOTE_SESSION_ID"] = "cse_v"
	opts.TrustUncommittedHooks = false
	opts.Repo = t.TempDir()
	if res, err = runCloudSessionFlush(context.Background(), opts); err != nil || res.Guard != "uncommitted" {
		t.Fatalf("no repository: res %+v err %v", res, err)
	}
}

// TestCloudSessionStartShipsLeftovers: rows a session could not ship (its
// Stop never fired, or its last delivery failed) go out with the next
// session's start flush in the same VM.
func TestCloudSessionStartShipsLeftovers(t *testing.T) {
	cfg := cloudSessionFixture(t)
	fail := true
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		got++
	}))
	defer srv.Close()
	env := map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": "cse_first", "SBO_CLOUD_SESSION_TOKEN": "t"}
	opts := cloudSessionFlushOptions{
		Timeout: cloudSessionTestFlushTimeout,
		Agent:   "claude-code", Trigger: cloudsession.TriggerPrompt, Destination: cloudsession.DestOrg,
		URL: srv.URL, ConfigPath: cfg, Repo: cloudSessionRepo(t, "claude-code", true), Env: cloudEnv(env),
	}
	if res, err := runCloudSessionFlush(context.Background(), opts); err != nil || !res.Pending || res.Envelopes != 0 {
		t.Fatalf("first session: res %+v err %v", res, err)
	}
	fail = false
	env["CLAUDE_CODE_REMOTE_SESSION_ID"] = "cse_second"
	opts.Trigger = cloudsession.TriggerStart
	res, err := runCloudSessionFlush(context.Background(), opts)
	if err != nil || res.Envelopes != 1 || got != 1 || res.Rows == 0 {
		t.Fatalf("next session's start: res %+v err %v (server got %d)", res, err, got)
	}
}
