package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/shiptoken"
)

// cloudSessionTestFlushTimeout replaces the trigger's production budget
// (cloudsession's trigger table: 20s for prompt, 30s for start, 45s for
// periodic and final) on every flush a test runs. A test's first flush
// opens a fresh database and runs every migration inside that deadline;
// under -race on a small host that alone can pass 20s (PT-83). The bound
// still keeps a hung flush from running to the binary's timeout.
const cloudSessionTestFlushTimeout = 10 * time.Minute

// cloudSessionFixture lays out a sandbox-shaped home: a Claude Code
// transcript under ~/.claude/projects and an observer config whose database
// lives in the temporary home. It returns the config path.
//
// The config selects adapter.claude-code where this build leaves it
// inactive by default: the minimal and managed editions start an
// unconfigured node with every adapter off (selected locally or by policy),
// so the flush's scan would register no adapter and ship nothing. The
// setup script installs the full release (npm platform package or the full
// archive) in the vendor sandbox, where the adapter is active with no
// [components] block; a plain build leaves the file unchanged.
func cloudSessionFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "simple-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(home, ".claude", "projects", "-tmp-superbased-fixture-simple")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "sess-001.jsonl"), src, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(home, ".observer", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(home, ".observer", "observer.db")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n" + selectionTOMLIfInactive(t, "adapter.claude-code")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// cloudSessionTestPins are fixed npm pins for init in tests (no registry
// lookup): sha512 of "x64" and "arm64".
var cloudSessionTestPins = []cloudsession.NpmPin{
	{Arch: "x64", Integrity: "sha512-YHnaxMOZhyPde3PGr4grjQqDQSEuEWW5bgtCXfiWX6DNYAlBqgAOIyrHG/FsBYMS0pyDGFPTi8pQi3m1qSSdRA=="},
	{Arch: "arm64", Integrity: "sha512-74hSRaiQE+e1eRzWN5i0G/g8EWCB+xDQA5yIL7NRxRIgyXl5d/OxO16cuGrWseoMeDSbZBKcq7M74NXGbWij3w=="},
}

// cloudSessionRepo makes a git repository holding the agent's committed
// init files (destination org at https://org.example.com) and returns its
// root. commit=false leaves the files uncommitted.
func cloudSessionRepo(t *testing.T, agent string, commit bool) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	cloudSessionWrite(t, filepath.Join(root, "README.md"), []byte("fixture\n"))
	plan, err := cloudsession.PlanInit(cloudsession.PlanOptions{
		Agent: agent, Destination: cloudsession.DestOrg, DestinationURL: "https://org.example.com",
		ObserverVersion: "v1.37.0", VendorKeys: []string{"npbhJUUL/Zy088BDnuqYRDqjjQtlyF9/eVcWFOCzj2g="},
		NpmPins: cloudSessionTestPins,
	}, repoReader(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRepoPlan(root, plan); err != nil {
		t.Fatal(err)
	}
	if commit {
		git("add", "-A")
		git("commit", "-q", "-m", "cloud-session init")
	} else {
		git("add", "README.md")
		git("commit", "-q", "-m", "readme only")
	}
	return root
}

// cloudSessionEditHooks rewrites the owned destination in the working tree's
// hook file, as an agent editing its own hooks mid-session would.
func cloudSessionEditHooks(t *testing.T, root string, from, to string) {
	t.Helper()
	p := filepath.Join(root, ".claude", "settings.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(from)) {
		t.Fatalf("%s not in the hook file", from)
	}
	cloudSessionWrite(t, p, bytes.ReplaceAll(b, []byte(from), []byte(to)))
}

func cloudEnv(m map[string]string) cloudsession.LookupEnv {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func readEnvelopes(t *testing.T, dir string) []orgcontract.PushEnvelope {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	var out []orgcontract.PushEnvelope
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var env orgcontract.PushEnvelope
		if err := json.Unmarshal(b, &env); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		out = append(out, env)
	}
	return out
}

// TestCloudSessionFlushToFile: inside the sandbox the flush scans the
// agent's transcript, builds the org push envelope from the local database
// with the metadata-only strip, writes it to the file destination, and a
// second flush sends nothing new.
func TestCloudSessionFlushToFile(t *testing.T) {
	cfg := cloudSessionFixture(t)
	out := filepath.Join(t.TempDir(), "envelopes")
	opts := cloudSessionFlushOptions{
		Timeout: cloudSessionTestFlushTimeout,
		Agent:   "claude-code", Trigger: cloudsession.TriggerFinal, Destination: cloudsession.DestFile,
		URL: out, ConfigPath: cfg, Repo: cloudSessionRepo(t, "claude-code", true),
		Env: cloudEnv(map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": "cse_test"}),
	}
	res, err := runCloudSessionFlush(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped != "" || res.Envelopes != 1 || res.Rows == 0 || res.Scanned == 0 || res.Location != "vendor_cloud" ||
		res.Guard != "verified" || res.Coverage != "verified" {
		t.Fatalf("result = %+v", res)
	}
	envs := readEnvelopes(t, out)
	if len(envs) != 1 {
		t.Fatalf("envelopes = %d", len(envs))
	}
	env := envs[0]
	if len(env.Sessions) != 1 || env.Sessions[0].ID != "sess-001" || len(env.Actions) == 0 || len(env.TokenUsage) == 0 {
		t.Fatalf("envelope: %d sessions (%+v), %d actions, %d token rows", len(env.Sessions), env.Sessions, len(env.Actions), len(env.TokenUsage))
	}
	// Metadata-only by default: no raw path or target, the hash is there.
	s := env.Sessions[0]
	if s.ProjectRoot != "" || s.ProjectRootHash == "" {
		t.Errorf("session ships project_root %q (hash %q): want metadata-only", s.ProjectRoot, s.ProjectRootHash)
	}
	for _, a := range env.Actions {
		if a.Target != "" {
			t.Errorf("action %s ships a raw target under metadata-only sharing", a.ActionType)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(out, mustOnlyEntry(t, out)))
	for _, leak := range []string{"func main", "go test ./...", "Please show me"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Errorf("envelope carries content %q", leak)
		}
	}
	if env.AgentVersion == "" {
		t.Error("agent_version missing")
	}

	res2, err := runCloudSessionFlush(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Envelopes != 0 || len(readEnvelopes(t, out)) != 1 {
		t.Errorf("second flush resent rows: %+v", res2)
	}
}

func mustOnlyEntry(t *testing.T, dir string) string {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("%d entries in %s", len(entries), dir)
	}
	return entries[0].Name()
}

// TestCloudSessionFlushNoMarkerIsNoOp: without the vendor marker nothing is
// scanned, opened or written, whatever else is configured.
func TestCloudSessionFlushNoMarkerIsNoOp(t *testing.T) {
	cfg := cloudSessionFixture(t)
	out := filepath.Join(t.TempDir(), "envelopes")
	for _, env := range []map[string]string{
		{},
		{"CLAUDE_CODE_REMOTE": "false"},
		{"CLAUDE_CODE_REMOTE_SESSION_ID": "cse_x", "SBO_CLOUD_SESSION_URL": out},
	} {
		res, err := runCloudSessionFlush(context.Background(), cloudSessionFlushOptions{
			Timeout: cloudSessionTestFlushTimeout,
			Agent:   "claude-code", Trigger: cloudsession.TriggerFinal, Destination: cloudsession.DestFile,
			URL: out, ConfigPath: cfg, Env: cloudEnv(env),
		})
		if err != nil || res.Skipped == "" {
			t.Fatalf("env %v: res %+v err %v", env, res, err)
		}
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("a destination was written without a marker")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfg), "observer.db")); !os.IsNotExist(err) {
		t.Error("the database was created without a marker")
	}
}

// TestCloudSessionFlushPeriodicCadence: a periodic flush ships only on every
// Nth call.
func TestCloudSessionFlushPeriodicCadence(t *testing.T) {
	cfg := cloudSessionFixture(t)
	out := filepath.Join(t.TempDir(), "envelopes")
	opts := cloudSessionFlushOptions{
		Timeout: cloudSessionTestFlushTimeout,
		Agent:   "claude-code", Trigger: cloudsession.TriggerPeriodic, Every: 3, Destination: cloudsession.DestFile,
		URL: out, ConfigPath: cfg, Repo: cloudSessionRepo(t, "claude-code", true), Env: cloudEnv(map[string]string{"CLAUDE_CODE_REMOTE": "true"}),
	}
	for i := 1; i <= 3; i++ {
		res, err := runCloudSessionFlush(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		if ran := res.Skipped == ""; ran != (i == 3) {
			t.Fatalf("call %d: %+v", i, res)
		}
	}
	if len(readEnvelopes(t, out)) != 1 {
		t.Error("periodic flush did not ship on the third call")
	}
}

// TestCloudSessionFlushHTTPRetryKeepsRows: a refused delivery leaves the
// rows for the next flush, which then ships them with the ship token.
func TestCloudSessionFlushHTTPRetryKeepsRows(t *testing.T) {
	cfg := cloudSessionFixture(t)
	fail := true
	var auth []string
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		if r.URL.Path != "/ingest/cloud-session/v1/batch" {
			t.Errorf("path %s", r.URL.Path)
		}
		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		got++
		_, _ = w.Write([]byte(`{"accepted_rows":1}`))
	}))
	defer srv.Close()
	opts := cloudSessionFlushOptions{
		Timeout: cloudSessionTestFlushTimeout,
		Agent:   "claude-code", Trigger: cloudsession.TriggerFinal, Destination: cloudsession.DestOrg,
		URL: srv.URL, ConfigPath: cfg, Repo: cloudSessionRepo(t, "claude-code", true),
		Env: cloudEnv(map[string]string{"CLAUDE_CODE_REMOTE": "true", "SBO_CLOUD_SESSION_TOKEN": "ship-123"}),
	}
	res, err := runCloudSessionFlush(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Envelopes != 0 || !res.Pending || !strings.Contains(res.Error, "503") || strings.Contains(res.Error, "ship-123") ||
		res.Coverage != "delayed_reporting" {
		t.Fatalf("failed delivery result = %+v", res)
	}
	fail = false
	res, err = runCloudSessionFlush(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Envelopes != 1 || got != 1 || res.Error != "" {
		t.Fatalf("retry result = %+v (server got %d)", res, got)
	}
	for _, a := range auth {
		if a != "Bearer ship-123" {
			t.Errorf("Authorization = %q", a)
		}
	}
	// No token: a misconfiguration. The start flush (once per session)
	// reports it as an error; the others record it and exit 0, so a broken
	// setup does not raise a hook error on every prompt.
	opts.Env = cloudEnv(map[string]string{"CLAUDE_CODE_REMOTE": "true"})
	opts.Trigger = cloudsession.TriggerStart
	if _, err := runCloudSessionFlush(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "ship token") {
		t.Errorf("missing token on start: err = %v", err)
	}
	for _, trig := range []cloudsession.Trigger{cloudsession.TriggerPrompt, cloudsession.TriggerFinal} {
		opts.Trigger = trig
		res, err := runCloudSessionFlush(context.Background(), opts)
		if err != nil || !strings.Contains(res.Skipped, "ship token") || res.CoverageReason != "not_configured" {
			t.Errorf("missing token on %s: res %+v err %v", trig, res, err)
		}
	}
}

// requireCloudSessionVendorKey skips a test that writes a setup script in a
// build with no vendor verification key. The key lives in internal/update,
// which sbo_omit_org_update (the minimal edition) compiles out, so there
// `observer cloud-session init` refuses rather than write a script that
// would install an unverified binary (cloudsession_vendorkey_omit.go). The
// helper pins that refusal before it skips.
func requireCloudSessionVendorKey(t *testing.T) {
	t.Helper()
	if len(cloudSessionVendorKeys()) > 0 {
		return
	}
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := newCloudSessionCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	pin := "--npm-integrity=x64=" + cloudSessionTestPins[0].Integrity
	cmd.SetArgs([]string{"init", "--agent", "copilot", "--repo", repo, "--observer-version", "v1.37.0", "--url", "https://org.example.com", pin, "--dry-run"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "no vendor verification key") {
		t.Fatalf("init with no vendor key: err = %v, want the no-vendor-key refusal\n%s", err, out.String())
	}
	t.Skip("this build carries no vendor verification key (org.update compiled out), so cloud-session init refuses; the refusal is pinned above")
}

// TestCloudSessionInitAndRemoveCommand drives the cobra commands end to end
// in a temporary repository.
func TestCloudSessionInitAndRemoveCommand(t *testing.T) {
	requireCloudSessionVendorKey(t)
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		cmd := newCloudSessionCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out.String())
		}
		return out.String()
	}
	pin := "--npm-integrity=x64=" + cloudSessionTestPins[0].Integrity
	out := run("init", "--agent", "copilot", "--repo", repo, "--observer-version", "v1.37.0", "--url", "https://org.example.com", pin, "--dry-run")
	if !strings.Contains(out, "+++ b/"+cloudsession.CopilotHooksPath) || !strings.Contains(out, "dry run") {
		t.Fatalf("dry run output:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(repo, ".github")); !os.IsNotExist(err) {
		t.Fatal("dry run wrote files")
	}
	run("init", "--agent", "copilot", "--repo", repo, "--observer-version", "v1.37.0", "--url", "https://org.example.com", pin)
	fi, err := os.Stat(filepath.Join(repo, filepath.FromSlash(cloudsession.SetupScriptPath)))
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755) { // Windows has no exec bit
		t.Fatalf("setup script: %v %v", fi, err)
	}
	if out := run("init", "--agent", "copilot", "--repo", repo, "--observer-version", "v1.37.0", "--url", "https://org.example.com", pin); !strings.Contains(out, "no repository changes") {
		t.Errorf("second init changed files:\n%s", out)
	}
	run("remove", "--agent", "copilot", "--repo", repo)
	for _, p := range []string{cloudsession.CopilotHooksPath, cloudsession.SetupScriptPath, cloudsession.CopilotSetupStepsPath} {
		if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(p))); !os.IsNotExist(err) {
			t.Errorf("%s left after remove", p)
		}
	}
}

func TestReleaseTagOf(t *testing.T) {
	for in, want := range map[string]string{"dev": "", "": "", "1.37.0": "v1.37.0", "v1.37.0": "v1.37.0"} {
		if got := releaseTagOf(in); got != want {
			t.Errorf("releaseTagOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCloudSessionFlushSharePosture pins decision CA-D19 in the sandbox: the
// committed --share posture decides what ships through the one push seam. A
// file flush with --share full_content carries the raw project root; the
// default for a non-node destination stays metadata only; an unknown posture
// is a misconfiguration. The node default (full content) and the shared
// spelling with the org server are pinned too.
func TestCloudSessionFlushSharePosture(t *testing.T) {
	for _, tc := range []struct {
		name     string
		share    cloudsession.SharePosture
		wantRoot bool
	}{
		{"full content", cloudsession.ShareFullContent, true},
		{"explicit metadata only", cloudsession.ShareMetadataOnly, false},
		{"default for a file destination", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cloudSessionFixture(t)
			out := filepath.Join(t.TempDir(), "envelopes")
			res, err := runCloudSessionFlush(context.Background(), cloudSessionFlushOptions{
				Timeout: cloudSessionTestFlushTimeout,
				Agent:   "claude-code", Trigger: cloudsession.TriggerFinal, Destination: cloudsession.DestFile, Share: tc.share,
				URL: out, ConfigPath: cfg, Repo: cloudSessionRepo(t, "claude-code", true),
				Env: cloudEnv(map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": "cse_test"}),
			})
			if err != nil || res.Envelopes != 1 {
				t.Fatalf("flush: %+v %v", res, err)
			}
			envs := readEnvelopes(t, out)
			if got := envs[0].Sessions[0].ProjectRoot != ""; got != tc.wantRoot {
				t.Fatalf("project_root shipped = %v, want %v", got, tc.wantRoot)
			}
		})
	}
	cfg := cloudSessionFixture(t)
	// A misconfiguration fails the start flush (the others record it as
	// coverage and exit 0, CLOUDSESS-7).
	if _, err := runCloudSessionFlush(context.Background(), cloudSessionFlushOptions{
		Timeout: cloudSessionTestFlushTimeout,
		Agent:   "claude-code", Trigger: cloudsession.TriggerStart, Destination: cloudsession.DestFile, Share: "everything",
		URL: t.TempDir(), ConfigPath: cfg, Repo: cloudSessionRepo(t, "claude-code", true),
		Env: cloudEnv(map[string]string{"CLAUDE_CODE_REMOTE": "true"}),
	}); err == nil || !strings.Contains(err.Error(), "--share") {
		t.Fatalf("an unknown --share was accepted: %v", err)
	}
	if p, _ := cloudsession.ResolveShare(cloudsession.DestNode, ""); p != cloudsession.ShareFullContent {
		t.Fatalf("node default posture = %q, want full content (CA-D19)", p)
	}
	// The posture the org server's mint response names is the value init
	// takes.
	if string(cloudsession.ShareFullContent) != shiptoken.PostureFullContent || string(cloudsession.ShareMetadataOnly) != shiptoken.PostureMetadataOnly {
		t.Fatal("cloudsession and shiptoken spell the share postures differently")
	}
}

// TestCloudSessionFlushPricesTokenRows (CA-C7 org live check, 2026-11-03):
// a transcript-only token_usage row (Claude Code stores no cost) is priced
// at push time by the same pricer the daemon's org push uses, so it does not
// ship $0 for a model the compiled seed prices (the fixture's
// claude-sonnet-4-20250514).
func TestCloudSessionFlushPricesTokenRows(t *testing.T) {
	cfg := cloudSessionFixture(t)
	out := filepath.Join(t.TempDir(), "envelopes")
	opts := cloudSessionFlushOptions{
		Timeout: cloudSessionTestFlushTimeout,
		Agent:   "claude-code", Trigger: cloudsession.TriggerFinal, Destination: cloudsession.DestFile,
		URL: out, ConfigPath: cfg, Repo: cloudSessionRepo(t, "claude-code", true),
		Env: cloudEnv(map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": "cse_test"}),
	}
	if _, err := runCloudSessionFlush(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	envs := readEnvelopes(t, out)
	if len(envs) != 1 || len(envs[0].TokenUsage) == 0 {
		t.Fatalf("no token rows shipped: %d envelopes", len(envs))
	}
	for _, r := range envs[0].TokenUsage {
		if r.InputTokens+r.OutputTokens+r.CacheReadTokens+r.CacheCreationTokens == 0 {
			continue
		}
		if r.EstimatedCostUSD <= 0 {
			t.Errorf("token row %s (model %s, %d in / %d out) shipped estimated_cost_usd %v; want a priced amount",
				r.SourceEventID, r.Model, r.InputTokens, r.OutputTokens, r.EstimatedCostUSD)
		}
	}
}
