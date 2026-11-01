//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxsignin"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// signInFakeSecret is the FAKE sign-in value the tests write; no posture,
// notice or log line may ever carry it.
const signInFakeSecret = "sbo-fake-signin-value-7f3c"

// lastSignInPlan is the last composed plan file's bytes.
var lastSignInPlan []byte

// signInRun composes a claude-code run on backend with delivery d over a
// temp home holding a fake sign-in (made by mk), the run's sign-in decision
// taken from req exactly as Create takes it. It returns the driver, the
// claude projection's host dir (empty when nothing is projected), the plan,
// the run id, the compose error and the daemon log.
func signInRun(t *testing.T, backend string, dl sandboxoci.Delivery, req termsvc.PrepareRequest, remembered []string, mk func(claude string)) (*ociDriver, string, ociPlanFile, string, error, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	// No relocation unless the test's mk sets one.
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real
	}
	claude := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claude, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(claude, "settings.json"), []byte(`{"env":{"ANTHROPIC_API_KEY":"`+signInFakeSecret+`"}}`), 0o600)
	mk(claude)
	ws := filepath.Join(home, "proj")
	_ = os.MkdirAll(ws, 0o700)
	cfg := ociTestConfig(t, true, backend)
	cfg.Terminal.Sandbox.OCI.AllowRootful = true
	cfg.Terminal.Sandbox.SignInSeedTools = remembered
	exe, _ := os.Executable()
	var logs bytes.Buffer
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, filepath.Join(home, ".observer"), exe, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rt.applyDaemonConfig(cfg)
	d, ok := rt.drivers[backend].(*ociDriver)
	if !ok {
		t.Fatalf("no %s driver", backend)
	}
	req.Tool = "claude-code"
	projected := sandboxoci.ProjectsState(dl, d.profile.CrossesKernel)
	runID := "runsignin00000001"
	d.choices.Store(runID, ociRunChoice{image: "node@sha256:" + strings.Repeat("b", 64), delivery: dl, signIn: rt.signInDecision(req, projected, false)})
	res := sandboxoci.ProbeResult{
		Socket:   "/run/docker.sock",
		Identity: sandboxoci.Identity{Engine: sandboxoci.EngineDocker, Mode: sandboxoci.ModeRootful, APIVersion: "1.52", Fingerprint: "f"},
		User:     sandboxoci.UserPlan{Row: "rootful engine (opt-in)", User: "1000:1000"},
		Bridge:   sandboxoci.BridgeHostUDS,
	}
	wrap, cerr := d.compose(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: runID, Tool: "claude-code", Dir: ws}, ProxyRouted: true}, res)
	if cerr != nil {
		return d, "", ociPlanFile{}, runID, cerr, &logs
	}
	lastSignInPlan, _ = os.ReadFile(wrap[3])
	plan, err := readOCIPlan(wrap[3])
	if err != nil {
		t.Fatal(err)
	}
	var host string
	for _, p := range plan.Projections {
		if p.Target == claude {
			host = p.Host
		}
	}
	return d, host, plan, runID, nil, &logs
}

func writeFakeCredential(claude string) {
	_ = os.WriteFile(filepath.Join(claude, ".credentials.json"), []byte(`{"claudeAiOauth":{"accessToken":"`+signInFakeSecret+`"}}`), 0o600)
}

var projectingRows = []struct {
	name, backend string
	dl            sandboxoci.Delivery
}{
	{"runsc row", sandboxbackend.BackendOCIRunsc, sandboxoci.DeliveryHostBind},
	{"image copy on oci-runc", sandboxbackend.BackendOCIRunc, sandboxoci.DeliveryImageInstalled},
}

// TestSignInSeedNeedsConsent: with no consent (headless, nothing
// remembered) and with a no for this launch, no sign-in file is in the box
// on either projecting path, and the run's notice says why.
func TestSignInSeedNeedsConsent(t *testing.T) {
	no := false
	for _, row := range projectingRows {
		for _, req := range []termsvc.PrepareRequest{{}, {SignInSeed: &no}} {
			_, host, plan, _, err, _ := signInRun(t, row.backend, row.dl, req, nil, writeFakeCredential)
			if err != nil {
				t.Fatalf("%s: %v", row.name, err)
			}
			if host == "" {
				t.Fatalf("%s: nothing projected", row.name)
			}
			if _, err := os.Lstat(filepath.Join(host, ".credentials.json")); err == nil {
				t.Fatalf("%s: the sign-in was copied without consent", row.name)
			}
			if !strings.Contains(strings.Join(plan.Notices, "\n"), "sign-in: not copied") {
				t.Fatalf("%s: notices %q", row.name, plan.Notices)
			}
		}
	}
}

// TestSignInSeedCopiesTheRowsFilesOwnerOnly: a consent for this launch and
// a remembered one copy exactly the registry's sign-in file, owner-only,
// and nothing else secret; the notice and the daemon's one log line name
// the file, never its value; the copy is gone after Destroy and after the
// stale-run sweep (the helper's own ends: TestSignInCopyGoesWithEveryHelperEnd).
func TestSignInSeedCopiesTheRowsFilesOwnerOnly(t *testing.T) {
	yes := true
	ends := []struct {
		name string
		end  func(d *ociDriver, plan ociPlanFile, runID string) error
	}{
		{"Destroy", func(d *ociDriver, _ ociPlanFile, runID string) error {
			_, err := d.Destroy(context.Background(), termsvc.SandboxRun{ID: runID, Tool: "claude-code"})
			return err
		}},
		{"the daemon-start sweep of a run with no relay record", func(d *ociDriver, _ ociPlanFile, _ string) error {
			_, err := ociSweepRunState(d.r.observerDir, d.r.managedRoot, ociRunLive(d.r.observerDir))
			return err
		}},
	}
	for _, row := range projectingRows {
		for _, consent := range []struct {
			name       string
			req        termsvc.PrepareRequest
			remembered []string
		}{{"launch yes", termsvc.PrepareRequest{SignInSeed: &yes}, nil}, {"remembered", termsvc.PrepareRequest{}, []string{"claude-code"}}} {
			for _, end := range ends {
				name := row.name + "/" + consent.name + "/" + end.name
				d, host, plan, runID, err, logs := signInRun(t, row.backend, row.dl, consent.req, consent.remembered, writeFakeCredential)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				cp := filepath.Join(host, ".credentials.json")
				fi, err := os.Lstat(cp)
				if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
					t.Fatalf("%s: the copy %v %v", name, fi, err)
				}
				if di, err := os.Stat(host); err != nil || di.Mode().Perm() != 0o700 {
					t.Fatalf("%s: the projected dir is not owner-only: %v", name, err)
				}
				if b, _ := os.ReadFile(cp); !strings.Contains(string(b), signInFakeSecret) {
					t.Fatalf("%s: the copy is not the file", name)
				}
				if _, err := os.Lstat(filepath.Join(host, "settings.json")); err == nil {
					t.Fatalf("%s: settings.json was copied", name)
				}
				notices := strings.Join(plan.Notices, "\n")
				if !strings.Contains(notices, "copied claude-code's sign-in") || !strings.Contains(notices, ".claude/.credentials.json") {
					t.Fatalf("%s: notices %q", name, notices)
				}
				if n := strings.Count(logs.String(), "sign-in seeded"); n != 1 || !strings.Contains(logs.String(), ".claude/.credentials.json") {
					t.Fatalf("%s: %d log lines: %s", name, n, logs.String())
				}
				// The plan file is what the helper reads; it too names no value.
				planBytes := lastSignInPlan
				for what, s := range map[string]string{"notices": notices, "log": logs.String(), "plan": string(planBytes)} {
					if strings.Contains(s, signInFakeSecret) {
						t.Fatalf("%s: the fake secret reached the %s", name, what)
					}
				}
				if err := end.end(d, plan, runID); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if _, err := os.Lstat(cp); err == nil {
					t.Fatalf("%s: the sign-in copy outlived the run", name)
				}
			}
		}
	}
}

// TestSignInSeedRefusesALinkOrAnOversizedFile: a symlinked sign-in file is
// never followed and an oversized one is not copied; either refuses the
// launch and leaves no projection behind.
func TestSignInSeedRefusesALinkOrAnOversizedFile(t *testing.T) {
	yes := true
	for name, mk := range map[string]func(string){
		"symlink": func(claude string) {
			target := filepath.Join(filepath.Dir(claude), "elsewhere.json")
			_ = os.WriteFile(target, []byte(signInFakeSecret), 0o600)
			_ = os.Symlink(target, filepath.Join(claude, ".credentials.json"))
		},
		"oversized": func(claude string) {
			_ = os.WriteFile(filepath.Join(claude, ".credentials.json"), bytes.Repeat([]byte("x"), sandboxSignInMaxBytes+1), 0o600)
		},
		// A FIFO is refused without blocking the open (O_NONBLOCK).
		"fifo": func(claude string) {
			_ = syscall.Mkfifo(filepath.Join(claude, ".credentials.json"), 0o600)
		},
		// A symbolic link at a directory component (here the relocated
		// config directory) is refused, never followed.
		"linked directory": func(claude string) {
			home := filepath.Dir(claude)
			real := filepath.Join(home, "realcfg")
			_ = os.MkdirAll(real, 0o700)
			writeFakeCredential(real)
			_ = os.Symlink(real, filepath.Join(home, "cfglink"))
			t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "cfglink"))
		},
	} {
		d, _, _, runID, err, logs := signInRun(t, sandboxbackend.BackendOCIRunsc, sandboxoci.DeliveryHostBind, termsvc.PrepareRequest{SignInSeed: &yes}, nil, mk)
		if err == nil || !strings.Contains(err.Error(), "sign-in") {
			t.Fatalf("%s: the launch was not refused: %v", name, err)
		}
		if strings.Contains(err.Error(), signInFakeSecret) || strings.Contains(logs.String(), signInFakeSecret) {
			t.Fatalf("%s: the refusal carries the value", name)
		}
		if _, serr := os.Lstat(ociProjectionRoot(d.r.managedRoot, runID)); serr == nil {
			t.Fatalf("%s: the projection outlived the refused launch", name)
		}
	}
}

// TestSignInSeedOnABoundRunCopiesNothing: oci-runc running the host's tool
// binds the real state, so even a consented run copies nothing, and every
// launch of it (consented, declined or never asked) says plainly that the
// tool's sign-in is shared with the box (operator ruling P-183), naming the
// file, never its value.
func TestSignInSeedOnABoundRunCopiesNothing(t *testing.T) {
	yes := true
	_, host, plan, _, err, logs := signInRun(t, sandboxbackend.BackendOCIRunc, sandboxoci.DeliveryHostBind, termsvc.PrepareRequest{SignInSeed: &yes}, nil, writeFakeCredential)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" || strings.Contains(logs.String(), "sign-in seeded") {
		t.Fatalf("a bound run was seeded: %q %s", host, logs.String())
	}
	no := false
	for _, req := range []termsvc.PrepareRequest{{SignInSeed: &yes}, {SignInSeed: &no}, {}} {
		_, _, plan, _, err, _ = signInRun(t, sandboxbackend.BackendOCIRunc, sandboxoci.DeliveryHostBind, req, nil, writeFakeCredential)
		if err != nil {
			t.Fatal(err)
		}
		notices := strings.Join(plan.Notices, "\n")
		if !strings.Contains(notices, "shares claude-code's own state with this machine, sign-in included (~/.claude/.credentials.json)") ||
			!strings.Contains(notices, "not the tool's own login") || strings.Contains(notices, signInFakeSecret) {
			t.Fatalf("%+v: notices %q", req, notices)
		}
	}
}

// TestSignInSeedFollowsTheVendorRelocation (audit finding 5): with
// CLAUDE_CONFIG_DIR set, the sign-in is read where the tool reads it and
// copied to the box's default place; a relative value the tool reads
// against its own working directory refuses by the variable's name.
func TestSignInSeedFollowsTheVendorRelocation(t *testing.T) {
	yes := true
	_, host, _, _, err, _ := signInRun(t, sandboxbackend.BackendOCIRunsc, sandboxoci.DeliveryHostBind, termsvc.PrepareRequest{SignInSeed: &yes}, nil, func(claude string) {
		alt := filepath.Join(filepath.Dir(claude), "alt-claude")
		_ = os.MkdirAll(alt, 0o700)
		writeFakeCredential(alt)
		t.Setenv("CLAUDE_CONFIG_DIR", alt)
	})
	if err != nil {
		t.Fatal(err)
	}
	if b, rerr := os.ReadFile(filepath.Join(host, ".credentials.json")); rerr != nil || !strings.Contains(string(b), signInFakeSecret) {
		t.Fatalf("the relocated sign-in was not copied: %v", rerr)
	}
	_, _, _, _, err, _ = signInRun(t, sandboxbackend.BackendOCIRunsc, sandboxoci.DeliveryHostBind, termsvc.PrepareRequest{SignInSeed: &yes}, nil, func(claude string) {
		writeFakeCredential(claude)
		t.Setenv("CLAUDE_CONFIG_DIR", "relative/dir")
	})
	if err == nil || !strings.Contains(err.Error(), "CLAUDE_CONFIG_DIR") {
		t.Fatalf("a relative relocation was not refused by name: %v", err)
	}
}

// TestSignInCopyGoesWithEveryHelperEnd (audit finding 7): the helper's own
// end of a run (driveOCIRun, then ociEndRun, as runOCIHostWith does)
// removes the sign-in copy, for each way the run ends (P-178): the tool
// exits, and the terminal closes (a hangup stops the container). A killed
// helper is TestOCIReaperRemovesAKilledHelpersSignInCopy.
func TestSignInCopyGoesWithEveryHelperEnd(t *testing.T) {
	yes := true
	old := ociProjectionSettle
	ociProjectionSettle = 0
	defer func() { ociProjectionSettle = old }()
	for _, end := range []string{"tool_exit", "terminal_closed"} {
		_, host, signed, _, err, _ := signInRun(t, sandboxbackend.BackendOCIRunsc, sandboxoci.DeliveryHostBind, termsvc.PrepareRequest{SignInSeed: &yes}, nil, writeFakeCredential)
		if err != nil {
			t.Fatal(err)
		}
		cp := filepath.Join(host, ".credentials.json")
		if _, err := os.Lstat(cp); err != nil {
			t.Fatalf("%s: no copy to remove: %v", end, err)
		}
		f := newOCIFake(t)
		plan := ociRunPlan(t, f)
		plan.Projections = signed.Projections
		tt := newOCITestTerm()
		done := make(chan int, 1)
		go func() {
			done <- driveOCIRun(context.Background(), plan, []string{"/usr/bin/observer", "claude"}, nil, tt.term)
		}()
		tt.waitFor(t, "agent$ ")
		if end == "tool_exit" {
			_, _ = tt.inW.Write([]byte("exit\n"))
		} else {
			tt.stop <- "hangup"
		}
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatalf("%s: the run never ended", end)
		}
		// What runOCIHostWith does once driveOCIRun returns.
		ociEndRun(plan, tt.term, func() {})
		if _, err := os.Lstat(cp); err == nil {
			t.Fatalf("%s: the sign-in copy outlived the helper's end of the run", end)
		}
		if strings.Contains(tt.out.String(), signInFakeSecret) {
			t.Fatalf("%s: the terminal showed the value", end)
		}
	}
}

// TestOCIReaperRemovesAKilledHelpersSignInCopy (audit finding 1): the
// helper is SIGKILLed while the daemon lives; the periodic sweep prunes its
// record, hands it to the run ender (process_gone), removes the box and
// removes the run's projected state, the sign-in copy in it included, while
// a live run's state stays.
func TestOCIReaperRemovesAKilledHelpersSignInCopy(t *testing.T) {
	f := newOCIFake(t)
	obs := t.TempDir()
	managed := t.TempDir()
	run, live := "killedrun0000002", "liverun00000002"
	writeTestRunRecord(t, obs, run)
	writeTestRunRecord(t, obs, live)
	state := func(id string) string { return filepath.Join(managed, id+sandboxoci.ProjectionLeaf) }
	for _, id := range []string{run, live} {
		claude := filepath.Join(state(id), "home", ".claude")
		if err := os.MkdirAll(claude, 0o700); err != nil {
			t.Fatal(err)
		}
		writeFakeCredential(claude)
	}
	f.list = []map[string]any{{"Id": "box", "State": "running", "Labels": sandboxoci.Labels("inst000000000001", run)}}
	var mu sync.Mutex
	var ended []string
	ender := func(rec sandboxrelayd.RunRecord) { mu.Lock(); ended = append(ended, rec.RunID); mu.Unlock() }
	prev := relayGoneRunEnder.Swap(&ender)
	defer relayGoneRunEnder.Store(prev)
	rp := &ociReaper{every: 100 * time.Millisecond}
	rp.ensure(f.sock, "1.52", "inst000000000001", obs, managed)
	defer rp.stop()
	deadline := time.Now().Add(10 * time.Second)
	for rp.sweeps.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Lstat(state(run)); err != nil {
		t.Fatalf("a live run's state was removed: %v", err)
	}
	// SIGKILL: the helper's liveness lock file stays, held by nobody.
	if err := os.WriteFile(filepath.Join(sandboxrelayd.RunsDir(obs), run+".alive"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitOCIRemoved(t, f, "box", 5*time.Second)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Lstat(state(run)); os.IsNotExist(err) {
			break
		}
	}
	if _, err := os.Lstat(state(run)); !os.IsNotExist(err) {
		t.Fatalf("the killed helper's sign-in copy outlived it while the daemon runs: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(state(live), "home", ".claude", ".credentials.json")); err != nil {
		t.Fatalf("a live run's copy was removed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(ended, ",") != run {
		t.Fatalf("the run ender saw %v, want %s", ended, run)
	}
}

// TestSignInNeverShowsTheValue (audit finding 7): with a fake sign-in on
// disk, no surface that talks about it carries its value: the doctor line,
// the CLI's question on stderr, the box's shared-sign-in line and the
// bound-row notice.
func TestSignInNeverShowsTheValue(t *testing.T) {
	yes := true
	_, _, plan, _, err, logs := signInRun(t, sandboxbackend.BackendOCIRunc, sandboxoci.DeliveryHostBind, termsvc.PrepareRequest{SignInSeed: &yes}, nil, writeFakeCredential)
	if err != nil {
		t.Fatal(err)
	}
	surfaces := map[string]string{"notices": strings.Join(plan.Notices, "\n"), "log": logs.String()}
	for _, c := range sandboxSignInDoctorChecks(config.TerminalSandboxConfig{SignInSeedTools: []string{"claude-code"}}) {
		surfaces["doctor"] += c.Message
	}
	r := &sandboxRuntime{}
	ask := termsvc.PrepareRequest{Tool: "claude-code", SignInAsk: true}
	var q *termsvc.SignInConsentError
	if gerr := signInGate(ask, r.signInDecision(ask, true, false)); !errors.As(gerr, &q) {
		t.Fatal("no consent question")
	}
	var stderr bytes.Buffer
	if _, _, err := sandboxCLIAskSignIn(strings.NewReader("y\n"), &stderr, q); err != nil {
		t.Fatal(err)
	}
	surfaces["cli stderr"] = stderr.String()
	var box bytes.Buffer
	t.Setenv(sandboxenv.EnvSignInShared, "claude-code")
	sandboxEnvPosture(&box)
	surfaces["box"] = box.String()
	if !strings.Contains(box.String(), "sign-in included (~/.claude/.credentials.json)") {
		t.Fatalf("the box does not say the sign-in is shared: %q", box.String())
	}
	for what, s := range surfaces {
		if strings.Contains(s, signInFakeSecret) {
			t.Fatalf("the fake secret reached the %s", what)
		}
	}
	if !strings.Contains(surfaces["doctor"], sandboxsignin.BoundNote) {
		t.Fatalf("the doctor line does not say bound rows share the sign-in: %s", surfaces["doctor"])
	}
}

// TestSignInSeedProjectedRunDropsTheRelocation (round 2 verification, F5):
// a projected run's box never gets CLAUDE_CONFIG_DIR, so a relocated tool
// reads the seeded copy at its default path in the box rather than the
// unbound host path; a bound run keeps the variable.
func TestSignInSeedProjectedRunDropsTheRelocation(t *testing.T) {
	yes := true
	var alt string
	relocate := func(claude string) {
		alt = filepath.Join(filepath.Dir(claude), "alt-claude")
		_ = os.MkdirAll(alt, 0o700)
		writeFakeCredential(alt)
		t.Setenv("CLAUDE_CONFIG_DIR", alt)
	}
	// The helper's environment: the variable set, and the launch's
	// allow-list naming it (the row's ProviderEnv).
	helperEnv := func() []string {
		return []string{"PATH=/usr/bin", "HOME=/home/dev", "CLAUDE_CONFIG_DIR=" + alt, sandboxenv.EnvAllow + "=" + sandboxenv.Encode(sandboxEnvAllowNames("claude-code", nil))}
	}
	_, host, plan, _, err, _ := signInRun(t, sandboxbackend.BackendOCIRunsc, sandboxoci.DeliveryHostBind, termsvc.PrepareRequest{SignInSeed: &yes}, nil, relocate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(host, ".credentials.json")); err != nil {
		t.Fatalf("no seeded copy: %v", err)
	}
	if got := strings.Join(ociContainerEnv(helperEnv(), plan.DropEnv...), " "); strings.Contains(got, "CLAUDE_CONFIG_DIR="+alt) {
		t.Fatalf("a projected box got the relocation, so the tool would read %s, not the copy: %s", alt, got)
	}
	_, _, bound, _, err, _ := signInRun(t, sandboxbackend.BackendOCIRunc, sandboxoci.DeliveryHostBind, termsvc.PrepareRequest{SignInSeed: &yes}, nil, relocate)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ociContainerEnv(helperEnv(), bound.DropEnv...), " "); !strings.Contains(got, "CLAUDE_CONFIG_DIR="+alt) {
		t.Fatalf("a bound box lost the tool's own relocation: %s", got)
	}
}
