package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// cloudsession_gate_test.go covers lane CA-C2: `init --guard` fetches and
// commits a signed policy, the committed gate evaluates it in the sandbox
// with no network call, refuses a tampered file (fail closed under enforce),
// and stops prompts on an over-budget org snapshot.

// gateUserPolicy is the user guard policy the node signs in these tests.
const gateUserPolicy = `[[rule]]
id = 'U-901'
category = 'boundary'
decision = 'deny'
applies_to = ['shell_exec']
match.command_base = 'curl'
match.arg_contains = 'example.invalid'
`

// gateRepo makes a repository with `init --guard --destination node` applied
// for agent, signed by the fixture node's key with gateUserPolicy, and returns
// the root and the planned options.
func gateRepo(t *testing.T, agent string, mode cloudsession.GuardMode) (string, cloudsession.PlanOptions) {
	t.Helper()
	cfgPath := cloudSessionFixture(t)
	home, _ := os.UserHomeDir()
	cloudSessionWrite(t, filepath.Join(home, ".observer", "guard-policy.toml"), []byte(gateUserPolicy))
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	gs, _, err := cloudSessionInitGuard(context.Background(), root, cloudsession.DestNode, cfgPath, mode)
	if err != nil {
		t.Fatal(err)
	}
	opts := cloudsession.PlanOptions{
		Agent: agent, Destination: cloudsession.DestNode, DestinationURL: "https://node.example.com",
		ObserverVersion: "v1.37.0", VendorKeys: []string{"npbhJUUL/Zy088BDnuqYRDqjjQtlyF9/eVcWFOCzj2g="},
		NpmPins: cloudSessionTestPins, Guard: gs,
	}
	plan, err := cloudsession.PlanInit(opts, repoReader(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRepoPlan(root, plan); err != nil {
		t.Fatal(err)
	}
	return root, opts
}

// gateRun runs the gate for one event and returns stdout, stderr, exit code.
func gateRun(t *testing.T, root string, opts cloudsession.PlanOptions, event, payload string, inCloud bool) (string, string, int) {
	t.Helper()
	return gateRunAt(t, root, opts, event, payload, inCloud, nil)
}

// gateRunAt is gateRun with the gate's clock pinned (nil is the live clock).
func gateRunAt(t *testing.T, root string, opts cloudsession.PlanOptions, event, payload string, inCloud bool, now func() time.Time) (string, string, int) {
	t.Helper()
	env := map[string]string{}
	if inCloud {
		env["CLAUDE_CODE_REMOTE"], env["GITHUB_ACTIONS"] = "true", "true"
	}
	home, _ := os.UserHomeDir()
	var out, errb bytes.Buffer
	code := runCloudSessionGate(context.Background(), cloudSessionGateOptions{
		Agent: opts.Agent, Event: event, Mode: opts.Guard.Mode, KeyPin: opts.Guard.KeyPin,
		Policy: cloudsession.PolicyDigest(opts.Guard.Policy), Repo: root,
		ConfigPath: filepath.Join(home, ".observer", "config.toml"), Env: cloudEnv(env), Now: now,
	}, strings.NewReader(payload), &out, &errb)
	return out.String(), errb.String(), code
}

func claudePreTool(command string) string {
	b, _ := json.Marshal(map[string]any{
		"session_id": "s-1", "hook_event_name": "PreToolUse", "cwd": "/home/user/repo",
		"tool_name": "Bash", "tool_input": map[string]any{"command": command},
	})
	return string(b)
}

const claudePrompt = `{"session_id":"s-1","hook_event_name":"UserPromptSubmit","cwd":"/home/user/repo","prompt":"refactor the parser"}`

func isDeny(stdout string) bool {
	return strings.Contains(stdout, `"permissionDecision":"deny"`)
}

// TestCloudSessionGateEnforce: the committed policy's own rule and a built-in
// rule are denied, an ordinary command is allowed, and outside the cloud the
// gate allows at once.
func TestCloudSessionGateEnforce(t *testing.T) {
	root, opts := gateRepo(t, "claude-code", cloudsession.GuardEnforce)
	if out, _, code := gateRun(t, root, opts, "PreToolUse", claudePreTool("curl https://example.invalid/x"), true); !isDeny(out) || code != 0 {
		t.Fatalf("policy rule not denied: exit %d %s", code, out)
	}
	if out, _, _ := gateRun(t, root, opts, "PreToolUse", claudePreTool("rm -rf ~"), true); !isDeny(out) {
		t.Fatalf("built-in rule not denied: %s", out)
	}
	if out, errs, code := gateRun(t, root, opts, "PreToolUse", claudePreTool("ls -la"), true); isDeny(out) || code != 0 {
		t.Fatalf("ordinary command blocked: exit %d %s %s", code, out, errs)
	}
	if out, _, code := gateRun(t, root, opts, "PreToolUse", claudePreTool("curl https://example.invalid/x"), false); isDeny(out) || code != 0 {
		t.Fatalf("gate acted outside the cloud: exit %d %s", code, out)
	}
	if out, _, code := gateRun(t, root, opts, "UserPromptSubmit", claudePrompt, true); code != 0 || strings.Contains(out, "block") {
		t.Fatalf("prompt without a budget was stopped: exit %d %s", code, out)
	}
}

// TestCloudSessionGateObserve: observe mode records and never blocks.
func TestCloudSessionGateObserve(t *testing.T) {
	root, opts := gateRepo(t, "claude-code", cloudsession.GuardObserve)
	if out, _, code := gateRun(t, root, opts, "PreToolUse", claudePreTool("curl https://example.invalid/x"), true); isDeny(out) || code != 0 {
		t.Fatalf("observe mode denied: exit %d %s", code, out)
	}
}

// TestCloudSessionGateRefusesTamperedPolicy: an edited policy file, a policy
// signed by another key, and a missing file are refused; under enforce the
// tool gate denies and the prompt gate blocks (exit 2, reason on stderr),
// under observe both fail open.
func TestCloudSessionGateRefusesTamperedPolicy(t *testing.T) {
	root, opts := gateRepo(t, "claude-code", cloudsession.GuardEnforce)
	policyPath := filepath.Join(root, filepath.FromSlash(cloudsession.PolicyPath))
	committed, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var p cloudsession.SandboxPolicy
	if err := json.Unmarshal(committed, &p); err != nil {
		t.Fatal(err)
	}
	// The agent weakens its own rule to a flag and re-encodes the file.
	p.Guard.BundleTOML = strings.Replace(p.Guard.BundleTOML, "decision = 'deny'", "decision = 'flag'", 1)
	weakened, _ := cloudsession.EncodePolicy(p)
	// The agent signs a permissive policy with a key of its own.
	seed := bytes.Repeat([]byte{4}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	p.Guard = orgcontract.PolicyBundle{Version: 99, BundleTOML: "", Signature: orgcontract.SignPolicyBundle(priv, 99, nil), PublicKey: base64.RawURLEncoding.EncodeToString(pub)}
	forged, _ := cloudsession.EncodePolicy(p)

	for _, tc := range []struct {
		name    string
		content []byte // nil = delete
		want    string
	}{
		{"weakened", weakened, "digest_mismatch"},
		{"forged key", forged, "digest_mismatch"},
		{"deleted", nil, "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.content == nil {
				if err := os.Remove(policyPath); err != nil {
					t.Fatal(err)
				}
			} else {
				cloudSessionWrite(t, policyPath, tc.content)
			}
			t.Cleanup(func() { cloudSessionWrite(t, policyPath, committed) })
			out, errs, code := gateRun(t, root, opts, "PreToolUse", claudePreTool("ls"), true)
			if !isDeny(out) || !strings.Contains(out, tc.want) || code != 0 {
				t.Fatalf("tool gate: exit %d stdout %s stderr %s, want a deny naming %s", code, out, errs, tc.want)
			}
			out, errs, code = gateRun(t, root, opts, "UserPromptSubmit", claudePrompt, true)
			if code != 2 || !strings.Contains(errs, tc.want) {
				t.Fatalf("prompt gate: exit %d stdout %s stderr %s, want exit 2 naming %s", code, out, errs, tc.want)
			}
			obs := opts
			g := *opts.Guard
			g.Mode = cloudsession.GuardObserve
			obs.Guard = &g
			if out, errs, code := gateRun(t, root, obs, "PreToolUse", claudePreTool("ls"), true); isDeny(out) || code != 0 || !strings.Contains(errs, "fails open") {
				t.Fatalf("observe: exit %d %s %s", code, out, errs)
			}
		})
	}

	// A committed command whose pins are not the file's (a hand-edited hook)
	// is refused the same way.
	bad := opts
	g := *opts.Guard
	g.KeyPin = strings.Repeat("a", 64)
	bad.Guard = &g
	var outb, errb bytes.Buffer
	code := runCloudSessionGate(context.Background(), cloudSessionGateOptions{
		Agent: "claude-code", Event: "PreToolUse", Mode: cloudsession.GuardEnforce, KeyPin: g.KeyPin,
		Policy: cloudsession.PolicyDigest(committed), Repo: root, Env: cloudEnv(map[string]string{"CLAUDE_CODE_REMOTE": "true"}),
	}, strings.NewReader(claudePreTool("ls")), &outb, &errb)
	if !isDeny(outb.String()) || !strings.Contains(outb.String(), "key_pin") || code != 0 {
		t.Fatalf("wrong key pin: exit %d %s %s", code, outb.String(), errb.String())
	}
}

// orgPolicyRepo commits an org-origin policy (signed here, standing in for
// the org server) with a budget body, and returns the gate options.
func orgPolicyRepo(t *testing.T, body orgcontract.BudgetPolicyBody) (string, cloudsession.PlanOptions) {
	t.Helper()
	cloudSessionFixture(t)
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	doc, err := orgcontract.SignBudgetPolicy(priv, "org-1", "user-1", body)
	if err != nil {
		t.Fatal(err)
	}
	toml := "# org policy\n"
	p := cloudsession.SandboxPolicy{
		Origin: cloudsession.OriginOrg, KeyPin: orgcontract.PublicKeyPinHash(pub),
		Guard:  orgcontract.PolicyBundle{Version: 3, BundleTOML: toml, Signature: orgcontract.SignPolicyBundle(priv, 3, []byte(toml)), PublicKey: base64.RawURLEncoding.EncodeToString(pub)},
		Budget: &cloudsession.SandboxBudget{OrgID: "org-1", Subject: "user-1", Document: doc},
	}
	raw, err := cloudsession.EncodePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dst := filepath.Join(root, filepath.FromSlash(cloudsession.PolicyPath))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	cloudSessionWrite(t, dst, raw)
	return root, cloudsession.PlanOptions{Agent: "claude-code", Guard: &cloudsession.GuardSetup{Mode: cloudsession.GuardEnforce, KeyPin: p.KeyPin, Policy: raw}}
}

// TestCloudSessionGateSoftBudgetStop: a prompt stops when the org's snapshot
// is over a cap in the current period, and passes when it is under, or when
// the figure is from an earlier period. The cap is calendar_day in UTC (no
// Timezone), so the current-period figure is dated at the start of the gate's
// UTC day: "an hour ago" is yesterday between 00:00 and 01:00 UTC (P-238). The
// pinned case runs the gate at 00:30 UTC through its clock seam.
func TestCloudSessionGateSoftBudgetStop(t *testing.T) {
	pinned := time.Date(2026, 11, 4, 0, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		now  func() time.Time
	}{
		{"live clock", nil},
		{"pinned at 00:30 UTC", func() time.Time { return pinned }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := time.Now().UTC()
			if tc.now != nil {
				at = tc.now().UTC()
			}
			asOf := time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
			run := func(root string, opts cloudsession.PlanOptions, event, payload string) (string, string, int) {
				return gateRunAt(t, root, opts, event, payload, true, tc.now)
			}
			over := orgcontract.BudgetPolicyBody{
				Version: 2, Period: "calendar_day", Enforcement: "hard",
				Caps: []orgcontract.BudgetPolicyCap{{Period: "calendar_day", Enforcement: "hard", CapUSD: 5, SpentUSD: 7.5, SpentAsOf: asOf, ResolvedScope: "team:core"}},
			}
			root, opts := orgPolicyRepo(t, over)
			out, errs, code := run(root, opts, "UserPromptSubmit", claudePrompt)
			if code != 2 || !strings.Contains(errs, "budget (team:core) is used up") || !strings.Contains(errs, "soft stop") {
				t.Fatalf("over budget: exit %d stdout %s stderr %s", code, out, errs)
			}
			// The tool gate does not apply the budget (no pre-call token gate).
			if out, _, _ := run(root, opts, "PreToolUse", claudePreTool("ls")); isDeny(out) {
				t.Fatalf("tool gate applied the budget: %s", out)
			}
			under := over
			under.Caps = []orgcontract.BudgetPolicyCap{{Period: "calendar_day", Enforcement: "hard", CapUSD: 5, SpentUSD: 1, SpentAsOf: asOf}}
			root, opts = orgPolicyRepo(t, under)
			if _, errs, code := run(root, opts, "UserPromptSubmit", claudePrompt); code != 0 {
				t.Fatalf("under budget stopped: exit %d %s", code, errs)
			}
			stale := over
			stale.Caps = []orgcontract.BudgetPolicyCap{{Period: "calendar_day", Enforcement: "hard", CapUSD: 5, SpentUSD: 9, SpentAsOf: at.Add(-72 * time.Hour).Format(time.RFC3339)}}
			root, opts = orgPolicyRepo(t, stale)
			if _, errs, code := run(root, opts, "UserPromptSubmit", claudePrompt); code != 0 || !strings.Contains(errs, "earlier period") {
				t.Fatalf("stale figure: exit %d %s", code, errs)
			}
			if tc.now == nil {
				return
			}
			// At 00:30 UTC the old "an hour ago" figure is yesterday's: the
			// gate is right to skip it, which is what made the test flaky.
			stale.Caps = []orgcontract.BudgetPolicyCap{{Period: "calendar_day", Enforcement: "hard", CapUSD: 5, SpentUSD: 9, SpentAsOf: at.Add(-time.Hour).Format(time.RFC3339)}}
			root, opts = orgPolicyRepo(t, stale)
			if _, errs, code := run(root, opts, "UserPromptSubmit", claudePrompt); code != 0 || !strings.Contains(errs, "earlier period") {
				t.Fatalf("an hour before 00:30 UTC: exit %d %s", code, errs)
			}
		})
	}
}

// failingTransport fails the test on any HTTP round trip.
type failingTransport struct{ calls *atomic.Int32 }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.calls.Add(1)
	return nil, errors.New("network call during a cloud-session gate")
}

// TestCloudSessionGateMakesNoNetworkCall: every gate path (allow, deny,
// tampered policy, budget stop) completes with the default HTTP transport
// failing and every proxy variable pointing at a listener that counts
// connections; neither sees anything.
func TestCloudSessionGateMakesNoNetworkCall(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var conns, calls atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			_ = c.Close()
		}
	}()
	proxy := "http://" + ln.Addr().String()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(k, proxy)
	}
	t.Setenv("NO_PROXY", "")
	prev := http.DefaultTransport
	http.DefaultTransport = failingTransport{calls: &calls}
	t.Cleanup(func() { http.DefaultTransport = prev })

	root, opts := gateRepo(t, "claude-code", cloudsession.GuardEnforce)
	gateRun(t, root, opts, "PreToolUse", claudePreTool("ls"), true)
	gateRun(t, root, opts, "PreToolUse", claudePreTool("curl https://example.invalid/x"), true)
	gateRun(t, root, opts, "PreToolUse", claudePreTool("rm -rf ~"), true)
	gateRun(t, root, opts, "UserPromptSubmit", claudePrompt, true)
	cloudSessionWrite(t, filepath.Join(root, filepath.FromSlash(cloudsession.PolicyPath)), []byte("{}\n"))
	gateRun(t, root, opts, "PreToolUse", claudePreTool("ls"), true)

	asOf := time.Now().UTC().Format(time.RFC3339)
	broot, bopts := orgPolicyRepo(t, orgcontract.BudgetPolicyBody{
		Version: 1, Period: "calendar_month", Enforcement: "soft",
		Caps: []orgcontract.BudgetPolicyCap{{Period: "calendar_month", Enforcement: "soft", CapUSD: 1, SpentUSD: 2, SpentAsOf: asOf}},
	})
	gateRun(t, broot, bopts, "UserPromptSubmit", claudePrompt, true)

	if calls.Load() != 0 || conns.Load() != 0 {
		t.Fatalf("the gate reached the network: %d HTTP round trips, %d proxy connections", calls.Load(), conns.Load())
	}
}

// TestCloudSessionGateImportsNoEgress keeps the sandbox-side files of lane
// CA-C2 free of every network package and of the org client: the gate and
// the setup step evaluate and build locally.
func TestCloudSessionGateImportsNoEgress(t *testing.T) {
	forbidden := map[string]bool{
		"net": true, "net/http": true, "os/exec": true,
		modulePathForTest + "/internal/cloudsessionnet": true,
		modulePathForTest + "/internal/orgclient":       true,
		modulePathForTest + "/internal/cloudagentsnet":  true,
	}
	for _, f := range []string{"cloudsession_gate.go", "cloudsession_setup.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if forbidden[p] {
				t.Errorf("%s imports %s: the sandbox gate and setup must make no network call", f, p)
			}
		}
	}
}

const modulePathForTest = "github.com/marmutapp/superbased-observer"

// TestCloudSessionGateCommandsWithoutBinary runs the committed gate commands
// with a real sh and observer missing: under enforce a dialect that can block
// without observer's reply blocks with the reason; every other gate, and
// every gate outside the cloud, exits 0.
func TestCloudSessionGateCommandsWithoutBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the committed hooks are POSIX sh for Linux sandboxes")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	for _, agent := range []string{"claude-code", "copilot"} {
		for _, mode := range cloudsession.GuardModes() {
			root, opts := gateRepo(t, agent, mode)
			opts.InstallDir = filepath.Join(t.TempDir(), "missing")
			plan, err := cloudsession.PlanInit(opts, repoReader(root))
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
			cov := cloudsession.GateCoverageFor(a, mode)
			gates := 0
			for _, cmd := range cmds {
				if !strings.Contains(cmd, "cloud-session gate ") {
					continue
				}
				var c cloudsession.GateCoverage
				for _, row := range cov {
					if strings.Contains(cmd, "--event "+row.Event+" ") {
						c = row
					}
				}
				gates++
				for _, inCloud := range []bool{false, true} {
					env := []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir()}
					if inCloud {
						env = append(env, "CLAUDE_CODE_REMOTE=true", "GITHUB_ACTIONS=true")
					}
					sh := exec.Command("sh", "-c", cmd)
					sh.Env = env
					sh.Stdin = strings.NewReader("{}")
					var stderr bytes.Buffer
					sh.Stderr = &stderr
					err := sh.Run()
					code := 0
					var ee *exec.ExitError
					if errors.As(err, &ee) {
						code = ee.ExitCode()
					}
					wantClosed := inCloud && c.MissingBinary == cloudsession.FailClosed
					if (code == 2) != wantClosed || (wantClosed && !strings.Contains(stderr.String(), "not installed")) {
						t.Errorf("%s %s %s cloud=%v: exit %d stderr %q, want fail-closed=%v", agent, mode, c.Event, inCloud, code, stderr.String(), wantClosed)
					}
				}
			}
			if gates != len(cov) {
				t.Errorf("%s %s: ran %d gate commands, want %d", agent, mode, gates, len(cov))
			}
		}
	}
}

// TestCloudSessionInitGuardCommand drives `init --guard --destination node
// --mcp` through cobra: the policy file and the MCP config land, the gate
// coverage is printed, a second run changes nothing, and remove takes it all
// back out.
func TestCloudSessionInitGuardCommand(t *testing.T) {
	requireCloudSessionVendorKey(t)
	cfgPath := cloudSessionFixture(t)
	home, _ := os.UserHomeDir()
	cloudSessionWrite(t, filepath.Join(home, ".observer", "guard-policy.toml"), []byte(gateUserPolicy))
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
	args := []string{
		"init", "--agent", "claude-code", "--repo", repo, "--observer-version", "v1.37.0", "--destination", "node",
		"--url", "https://node.example.com", pin, "--guard", "--mcp", "--config", cfgPath,
	}
	out := run(args...)
	for _, want := range []string{"guard: enforce mode", "PreToolUse tool gate", "UserPromptSubmit prompt gate", "the node policy carries your user guard policy file only"} {
		if !strings.Contains(out, want) {
			t.Errorf("init output lacks %q:\n%s", want, out)
		}
	}
	for _, p := range []string{cloudsession.PolicyPath, cloudsession.ClaudeMCPPath} {
		if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(p))); err != nil {
			t.Fatalf("%s not written: %v", p, err)
		}
	}
	key := filepath.Join(home, ".observer", "cloud-session", cloudSessionPolicyKeyFile)
	if fi, err := os.Stat(key); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) { // Windows has no Unix permission bits
		t.Fatalf("policy signing key: %v %v", fi, err)
	}
	if out := run(args...); !strings.Contains(out, "no repository changes") {
		t.Errorf("second init changed files:\n%s", out)
	}
	run("remove", "--agent", "claude-code", "--repo", repo)
	for _, p := range []string{cloudsession.PolicyPath, cloudsession.ClaudeMCPPath, cloudsession.ClaudeSettingsPath} {
		if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(p))); !os.IsNotExist(err) {
			t.Errorf("%s left after remove", p)
		}
	}
}

// TestCloudSessionInitGuardOrgNeedsEnrolment: the org destination verifies
// against the key pinned at enrolment, so an unenrolled node is refused with
// the way out.
func TestCloudSessionInitGuardOrgNeedsEnrolment(t *testing.T) {
	cfgPath := cloudSessionFixture(t)
	_, err := fetchSandboxPolicy(context.Background(), cloudsession.DestOrg, cfgPath, time.Now())
	if err == nil || !strings.Contains(err.Error(), "enrol") {
		t.Fatalf("err = %v, want an enrolment refusal", err)
	}
}

// TestCloudSessionSetupBuildsDatabase: the setup step builds the database the
// MCP server reads and, with --codeintel, writes the server's config.
func TestCloudSessionSetupBuildsDatabase(t *testing.T) {
	cfgPath := cloudSessionFixture(t)
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cloudSessionWrite(t, filepath.Join(repo, "main.go"), []byte("package main\n\nfunc main() {}\n"))
	var out bytes.Buffer
	if err := runCloudSessionSetup(context.Background(), &out, cfgPath, repo, true, true); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.Observer.DBPath); err != nil {
		t.Fatalf("database not built: %v\n%s", err, out.String())
	}
	home, _ := os.UserHomeDir()
	b, err := os.ReadFile(filepath.Join(home, filepath.FromSlash(cloudsession.SandboxMCPConfig)))
	if err != nil || !strings.Contains(string(b), "[codeintel]\nenabled = true") {
		t.Fatalf("mcp config: %q %v", b, err)
	}
	if err := runCloudSessionSetup(context.Background(), &out, cfgPath, repo, false, true); err == nil {
		t.Fatal("--codeintel without --mcp accepted")
	}
}

// TestCloudSessionGateIgnoresSandboxConfig: the sandbox's own
// ~/.observer/config.toml is a file the agent can write as root, so the gate
// builds its guard from the defaults, never from that file (ledger
// CLOUDSESS-10). A hostile config that disables built-in rules, widens
// [guard.boundary] allow_paths, empties the protected branches and turns the
// guard off changes no verdict.
func TestCloudSessionGateIgnoresSandboxConfig(t *testing.T) {
	root, opts := gateRepo(t, "claude-code", cloudsession.GuardEnforce)
	home, _ := os.UserHomeDir()
	cfgPath := filepath.Join(home, ".observer", "config.toml")
	base, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		command string
	}{
		{"built-in delete rule", "rm -rf ~"},
		{"allow_paths exemption", "find /srv/data -delete"},
		{"committed policy rule", "curl https://example.invalid/x"},
	}
	// Each verdict without the hostile file first: the hostile file must not
	// move any of them.
	clean := map[string]string{}
	for _, tc := range cases {
		out, errs, code := gateRun(t, root, opts, "PreToolUse", claudePreTool(tc.command), true)
		if code != 0 || !gateBlocks(out) {
			t.Fatalf("%s: not blocked with the default config: exit %d %s %s", tc.name, code, out, errs)
		}
		clean[tc.name] = gateDecision(out)
	}
	hostile := string(base) + `
[guard]
enabled = false
mode = "observe"

[guard.rules]
disable = ["R-100", "R-101", "R-102", "R-103", "U-901"]

[guard.boundary]
allow_paths = ["/**", "~/**"]
protected_branches = []
`
	cloudSessionWrite(t, cfgPath, []byte(hostile))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, errs, code := gateRun(t, root, opts, "PreToolUse", claudePreTool(tc.command), true)
			if code != 0 || gateDecision(out) != clean[tc.name] {
				t.Fatalf("hostile sandbox config moved the verdict: exit %d %s %s, want %s", code, out, errs, clean[tc.name])
			}
		})
	}
}

// gateDecision returns the permissionDecision of a Claude Code PreToolUse
// reply ("" when the reply carries none).
func gateDecision(stdout string) string {
	var r struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &r); err != nil {
		return ""
	}
	return r.HookSpecificOutput.PermissionDecision
}

// gateBlocks reports a reply that does not let the call through unasked.
func gateBlocks(stdout string) bool {
	d := gateDecision(stdout)
	return d == "deny" || d == "ask"
}

// gateRunEnv is gateRun with the in-cloud environment plus extra variables.
func gateRunEnv(t *testing.T, root string, opts cloudsession.PlanOptions, event, payload string, extra map[string]string) string {
	t.Helper()
	env := map[string]string{"CLAUDE_CODE_REMOTE": "true"}
	for k, v := range extra {
		env[k] = v
	}
	home, _ := os.UserHomeDir()
	var out, errb bytes.Buffer
	runCloudSessionGate(context.Background(), cloudSessionGateOptions{
		Agent: opts.Agent, Event: event, Mode: opts.Guard.Mode, KeyPin: opts.Guard.KeyPin,
		Policy: cloudsession.PolicyDigest(opts.Guard.Policy), Repo: root,
		ConfigPath: filepath.Join(home, ".observer", "config.toml"), Env: cloudEnv(env),
	}, strings.NewReader(payload), &out, &errb)
	return out.String()
}

// claudePreToolIn is claudePreTool with the payload's cwd set (empty omits
// it).
func claudePreToolIn(cwd, command string) string {
	m := map[string]any{
		"session_id": "s-1", "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "tool_input": map[string]any{"command": command},
	}
	if cwd != "" {
		m["cwd"] = cwd
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// TestCloudSessionGateSandboxBlockReason (2026-11-03 live check finding 2):
// a sandbox block names whose policy the rule comes from and how to change
// it, never the node-local org-lock or request-access wording, and R-101
// judges a delete against the session's repository (the payload's cwd, else
// CLAUDE_PROJECT_DIR) instead of an unknown project root.
func TestCloudSessionGateSandboxBlockReason(t *testing.T) {
	never := []string{"your organization locks this rule", "request access", "Requests page", "dashboard", "the project root is unknown"}
	check := func(t *testing.T, out string, want ...string) {
		t.Helper()
		if !isDeny(out) {
			t.Fatalf("not denied: %s", out)
		}
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Errorf("reason lacks %q: %s", w, out)
			}
		}
		for _, n := range never {
			if strings.Contains(out, n) {
				t.Errorf("reason says %q: %s", n, out)
			}
		}
	}
	t.Run("node origin", func(t *testing.T) {
		root, opts := gateRepo(t, "claude-code", cloudsession.GuardEnforce)
		check(t, gateRunEnv(t, root, opts, "PreToolUse", claudePreToolIn(root, "curl https://example.invalid/x"), nil),
			"U-901 blocked this command.", "committed cloud-session policy", "the developer's own guard policy", "cloud-session init --guard")
		check(t, gateRunEnv(t, root, opts, "PreToolUse", claudePreToolIn(root, "rm -rf "+outside(root)), nil),
			"R-101 blocked this command.", "built-in Observer rule", "the developer's own guard policy", "resolves outside the project root")
		// No cwd in the payload: CLAUDE_PROJECT_DIR names the project.
		check(t, gateRunEnv(t, root, opts, "PreToolUse", claudePreToolIn("", "rm -rf "+outside(root)), map[string]string{"CLAUDE_PROJECT_DIR": root}),
			"R-101 blocked this command.", "resolves outside the project root")
	})
	t.Run("org origin", func(t *testing.T) {
		root, opts := orgPolicyRepo(t, orgcontract.BudgetPolicyBody{Version: 1})
		if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		check(t, gateRunEnv(t, root, opts, "PreToolUse", claudePreToolIn(root, "rm -rf "+outside(root)), nil),
			"R-101 blocked this command.", "resolves outside the project root", "the organization's guard policy", "ask an org admin")
	})
}

// TestCloudSessionRootEnrich: the gate's Enrich step stamps the git tree of
// the payload's cwd, falls back to the given directory when the payload has
// none, and leaves a host-sent project root alone.
func TestCloudSessionRootEnrich(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(repo, "pkg")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(repo)
	cases := []struct {
		name               string
		ev                 policy.Event
		fallback           string
		wantRepo, wantLook string
	}{
		{name: "cwd in a subdirectory", ev: policy.Event{Cwd: sub}, wantRepo: want, wantLook: want},
		{name: "no cwd, fallback", ev: policy.Event{}, fallback: sub, wantRepo: want, wantLook: want},
		{name: "no cwd, no fallback", ev: policy.Event{}},
		{name: "host root kept", ev: policy.Event{ProjectRoot: "/srv/x"}, fallback: sub, wantLook: "/srv/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := tc.ev
			cloudSessionRootEnrich(tc.fallback)(&ev)
			if ev.RepoRoot != tc.wantRepo || ev.ProjectLookupRoot != tc.wantLook {
				t.Fatalf("RepoRoot %q ProjectLookupRoot %q, want %q %q", ev.RepoRoot, ev.ProjectLookupRoot, tc.wantRepo, tc.wantLook)
			}
		})
	}
}

// outside is a delete target outside the project that is neither a system
// root, the home directory, a folder directly in it, nor under a temp
// directory (which [guard.boundary] allows): R-101 denies it as "outside the
// project root" only when the gate knows the project root. With no root such a
// path is left alone, which is what the live check hit. root is unused but
// keeps the call sites readable.
func outside(_ string) string {
	if runtime.GOOS == "windows" {
		return "C:/ProgramData/sbo-guard-c2/nonexistent"
	}
	return "/opt/sbo-guard-c2/nonexistent"
}
