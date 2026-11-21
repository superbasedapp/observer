//go:build linux && !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// recordingBox is a fake client that records every exec with the token
// purpose its context carries and answers exit 0 (or the scripted Get).
type recordingBox struct {
	sandboxremote.Client
	execs    []sandboxremote.ExecSpec
	purposes []string
	running  bool
	gets     int
	answer   string
}

func (b *recordingBox) Exec(ctx context.Context, _ string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	b.execs = append(b.execs, spec)
	b.purposes = append(b.purposes, sandboxremote.TokenPurpose(ctx))
	return doneProc{Reader: strings.NewReader(b.answer), code: 0}, nil
}

func (b *recordingBox) Get(context.Context, string) (sandboxremote.BoxInfo, error) {
	b.gets++
	return sandboxremote.BoxInfo{Running: b.running}, nil
}

func orgShellTestRun(t *testing.T, c sandboxremote.Client) *hostedRun {
	t.Helper()
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	r := &hostedRun{
		plan:   hostedPlanFile{RunID: "r1", Provider: v.ID, ObserverDir: t.TempDir(), CloneURL: "https://git.example.com/acme/app.git", Root: "/home/dev/app", TimeoutMinutes: 30, DailyBoxMinutes: 240},
		t:      hostedTerm{out: io.Discard},
		now:    time.Now,
		vendor: v, client: c,
	}
	r.layout = v.Layout(r.plan.Root)
	r.start = r.now()
	return r
}

// TestOrgShellCloneExecIsTheCoreClone (fix round 1, A1): the node's clone
// exec is byte for byte the core's CloneArgv and CloneEnv, under a create
// token, with no working directory, no stdin and no TTY.
func TestOrgShellCloneExecIsTheCoreClone(t *testing.T) {
	box := &recordingBox{}
	r := orgShellTestRun(t, box)
	if err := r.boxClone(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(box.execs) != 1 {
		t.Fatalf("execs %d", len(box.execs))
	}
	got := box.execs[0]
	if !slices.Equal(got.Argv, osorg.CloneArgv(r.plan.CloneURL)) || !maps.Equal(got.Env, osorg.CloneEnv()) {
		t.Errorf("clone exec %v %v, want %v %v", got.Argv, got.Env, osorg.CloneArgv(r.plan.CloneURL), osorg.CloneEnv())
	}
	if got.Cwd != "" || got.Stdin || got.PTY || len(got.StdinData) != 0 || got.AsRoot {
		t.Errorf("clone exec shape %+v", got)
	}
	if box.purposes[0] != string(osorg.PurposeCreate) {
		t.Errorf("clone token purpose %q", box.purposes[0])
	}
	if want := []string{"git", "clone", "--", r.plan.CloneURL, "/sandbox/workspace"}; !slices.Equal(got.Argv, want) {
		t.Errorf("clone argv %v, want the ruled %v", got.Argv, want)
	}
}

// TestOrgShellFixedBoxPaths (ruling A3): the vendor row's fixed paths are
// the org compile's, and the setup step runs as the box user (no root
// exec) under /sandbox.
func TestOrgShellFixedBoxPaths(t *testing.T) {
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	if v.BoxWorkspace != osorg.BoxWorkspace || v.BoxRunDir != osorg.BoxRunDir || v.BoxHome != osorg.BoxHome {
		t.Errorf("vendor paths %s %s %s, compile %s %s %s", v.BoxWorkspace, v.BoxRunDir, v.BoxHome, osorg.BoxWorkspace, osorg.BoxRunDir, osorg.BoxHome)
	}
	// Every box-side file the node writes is under the run dir (OB-084): the
	// binary the network rule names, the baseline the org collects.
	if l := v.Layout("/home/dev/app"); l.Binary != osorg.BoxObserverBinary || guestBaselineFile != osorg.BoxBaselineFile || !strings.HasPrefix(osorg.BoxBaselineFile, osorg.BoxRunDir+"/") {
		t.Errorf("binary %s (rule %s), baseline %s (core %s)", l.Binary, osorg.BoxObserverBinary, guestBaselineFile, osorg.BoxBaselineFile)
	}
	box := &recordingBox{}
	r := orgShellTestRun(t, box)
	if err := r.setupDirs(context.Background(), "1000:1000"); err != nil {
		t.Fatal(err)
	}
	if err := r.giveToBoxUser(context.Background(), "1000:1000", r.layout.Workspace); err != nil {
		t.Fatal(err)
	}
	if len(box.execs) != 1 || box.execs[0].AsRoot {
		t.Fatalf("execs %+v", box.execs)
	}
	args := strings.Join(box.execs[0].Argv, " ")
	if !strings.Contains(args, "/sandbox/workspace") || !strings.Contains(args, "/sandbox/run") || strings.Contains(args, "/home/dev") {
		t.Errorf("setup argv %s", args)
	}
}

// TestOrgShellResumeFailureHandsOver (fix round 1, A5): a resume whose box
// does not start hands this machine's record over (removed, settled),
// never leaving a leftover; a resume that starts re-uploads nothing it does
// not need and keeps the record.
func TestOrgShellResumeFailureHandsOver(t *testing.T) {
	oldWait, oldPoll := hostedResumeWait, hostedResumePoll
	hostedResumeWait, hostedResumePoll = 50*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { hostedResumeWait, hostedResumePoll = oldWait, oldPoll })
	box := &recordingBox{running: false}
	r := orgShellTestRun(t, box)
	r.plan.ResumeBoxRunID = "r0"
	r.cred = sandboxremote.Credential{Minted: namedSource("obsheldbox")}
	if err := r.create(context.Background()); err == nil {
		t.Fatal("a resume whose box never ran succeeded")
	}
	if recs := hostedLoadRecords(r.plan.ObserverDir); len(recs) != 0 {
		t.Errorf("records left after a failed resume: %+v", recs)
	}
}

// TestOrgShellResumeTakesOverTheHeldBox (fix round 1, A4 and A8) is the
// success path: the held box runs, the run dir is set up as the box user,
// the in-box observer answers, the record names the held box and the
// resumed run's minutes are reserved on the ledger.
func TestOrgShellResumeTakesOverTheHeldBox(t *testing.T) {
	box := &recordingBox{running: true, answer: version}
	r := orgShellTestRun(t, box)
	r.plan.ResumeBoxRunID = "r0"
	r.cred = sandboxremote.Credential{Minted: namedSource("obsheldbox")}
	if err := r.takeOverHeld(context.Background()); err != nil {
		t.Fatal(err)
	}
	recs := hostedLoadRecords(r.plan.ObserverDir)
	if len(recs) != 1 || recs[0].VendorID != "obsheldbox" || !r.resumed || !r.rekey {
		t.Fatalf("records %+v resumed %v rekey %v", recs, r.resumed, r.rekey)
	}
	if box.gets == 0 {
		t.Error("the resume never asked whether the held box runs")
	}
	setup := false
	for _, e := range box.execs {
		if e.AsRoot {
			t.Errorf("a resume exec asked for root: %v", e.Argv)
		}
		if strings.Contains(strings.Join(e.Argv, " "), r.layout.RunDir) {
			setup = true
		}
	}
	if !setup {
		t.Errorf("the run dir was not set up again: %v", box.execs)
	}
	var used int
	_ = hostedUpdateLedger(r.plan.ObserverDir, r.now(), func(l *sandboxremote.Ledger) error {
		used = l.Used(r.plan.Provider, sandboxremote.DayOf(r.now()))
		return nil
	})
	if used == 0 {
		t.Error("a resumed run reserved no minutes")
	}
}

type namedSource string

func (n namedSource) Token(context.Context) (string, error) { return "tok", nil }
func (n namedSource) BoxName() string                       { return string(n) }

// TestOrgShellLeftoverIsHandOverOnly (fix round 1, A5): deleting an org
// row's leftover never builds a client or calls the org: the record is
// handed over and removed.
func TestOrgShellLeftoverIsHandOverOnly(t *testing.T) {
	obs := t.TempDir()
	rec := sandboxremote.NewIntent("r7", sandboxremote.VendorOpenShellOrg, "https://sandbox.example.com", "", "r7", time.Now(), time.Hour)
	rec.VendorID = "obsr7"
	_ = rec.Apply(sandboxremote.EvCreateOK)
	if err := hostedSaveRecord(obs, rec); err != nil {
		t.Fatal(err)
	}
	built := 0
	old := hostedVendorRegs[sandboxremote.VendorOpenShellOrg]
	reg := old
	reg.newClient = func(sandboxremote.Credential, string) (sandboxremote.Client, error) {
		built++
		return nil, errors.New("no client in tests")
	}
	hostedVendorRegs[sandboxremote.VendorOpenShellOrg] = reg
	t.Cleanup(func() { hostedVendorRegs[sandboxremote.VendorOpenShellOrg] = old })
	var out bytes.Buffer
	if err := hostedDeleteRun(context.Background(), obs, "r7", false, &out); err != nil {
		t.Fatal(err)
	}
	if built != 0 || len(hostedLoadRecords(obs)) != 0 || !strings.Contains(out.String(), "handed to your organization") {
		t.Errorf("built %d records %v out %q", built, hostedLoadRecords(obs), out.String())
	}
}

// TestOrgShellStoredCredentialVerbsRefused (fix round 1, A7): connect,
// disconnect and adopt refuse the org row with a pointer to org-shell login.
func TestOrgShellStoredCredentialVerbsRefused(t *testing.T) {
	if _, err := hostedStoredVendorArg(sandboxremote.VendorOpenShellOrg); err == nil || !strings.Contains(err.Error(), "org-shell login") {
		t.Errorf("stored-credential verb: %v", err)
	}
	if _, err := hostedStoredVendorArg(sandboxremote.VendorE2B); err != nil {
		t.Errorf("e2b refused: %v", err)
	}
}

// TestOrgShellRunCap (fix round 1, A8): the org's max_run_minutes lowers the
// local cap and never raises it.
func TestOrgShellRunCap(t *testing.T) {
	cases := []struct{ local, org, want int }{{60, 30, 30}, {60, 120, 60}, {60, 0, 60}}
	for _, tc := range cases {
		cfg := orgShellPublishedConfig()
		cfg.Hosted.MaxRunMinutes = tc.local
		cfg.Hosted.OpenShellOrg.Published.MaxRunMinutes = tc.org
		a, b := 0, 0
		d := orgShellTestDriver(t, cfg, &a, &b)
		d.reg.runCap = orgShellRunCap
		if got := d.maxRunMinutes(); got != tc.want {
			t.Errorf("local %d org %d: %d, want %d", tc.local, tc.org, got, tc.want)
		}
	}
}

// TestOrgShellStatusRouteMakesNoOrgCall (fix round 1, A6): rendering the
// card (the status GET) and a held-list request without the confirm token
// never open the org client.
func TestOrgShellStatusRouteMakesNoOrgCall(t *testing.T) {
	calls := 0
	old := orgShellOrgClient
	orgShellOrgClient = func(context.Context) (*orgclient.Client, *store.Enrolment, config.Config, func(), error) {
		calls++
		return nil, nil, config.Config{}, func() {}, errors.New("no org in tests")
	}
	t.Cleanup(func() { orgShellOrgClient = old })
	dir := t.TempDir()
	load := func(context.Context) (config.TerminalSandboxHostedOrgShellConfig, string, error) {
		return orgShellPublishedConfig().Hosted.OpenShellOrg, dir, nil
	}
	w := httptest.NewRecorder()
	orgShellStatusHandler(load)(w, httptest.NewRequest(http.MethodGet, "/api/terminal/sandbox/orgshell", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"offered":true`) {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/terminal/sandbox/orgshell/held", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	orgShellHeldHandler(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("held without the confirm token: %d", w.Code)
	}
	if calls != 0 {
		t.Errorf("the org client was opened %d times without a user action", calls)
	}
}

// TestHostedExecScriptsRunUnderSh (fix round 1, A12): the real part and
// unpack scripts, run by sh: the parts join, the digest is checked, the tar
// unpacks under the root with its modes, and a digest mismatch unpacks
// nothing.
func TestHostedExecScriptsRunUnderSh(t *testing.T) {
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("no tar")
	}
	data := bytes.Repeat([]byte("0123456789"), 3000)
	payload, sum, err := hostedPackTar([]sandboxremote.UploadFile{
		{Path: "/sandbox/workspace/a.txt", Mode: 0o644, Size: int64(len(data)), Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }},
		{Path: "/sandbox/workspace/bin/run", Mode: 0o755, Size: 2, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("hi")), nil }},
	})
	if err != nil {
		t.Fatal(err)
	}
	stage, root := t.TempDir(), t.TempDir()
	var parts []string
	for i := 0; i*7000 < len(payload); i++ {
		end := min((i+1)*7000, len(payload))
		p := filepath.Join(stage, ".upload.0123456789abcdef.part."+string(rune('0'+i)))
		cmd := exec.Command("sh", "-c", hostedExecPartScript, "sh", p)
		cmd.Stdin = bytes.NewReader(payload[i*7000 : end])
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("part %d: %v %s", i, err, out)
		}
		parts = append(parts, p)
	}
	bad := sha256.Sum256([]byte("other"))
	argv := append([]string{"-c", hostedExecUnpackScript, "sh", filepath.Join(stage, "j.tar"), hex.EncodeToString(bad[:]), root}, parts...)
	if out, err := exec.Command("sh", argv...).CombinedOutput(); err == nil || !strings.Contains(string(out), "digest mismatch") {
		t.Errorf("a mismatched digest unpacked: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "sandbox")); err == nil {
		t.Error("a mismatched upload left files")
	}
	// The parts were removed by the failed run; write them again.
	parts = parts[:0]
	for i := 0; i*7000 < len(payload); i++ {
		end := min((i+1)*7000, len(payload))
		p := filepath.Join(stage, ".upload.0123456789abcdef.part."+string(rune('0'+i)))
		_ = os.WriteFile(p, payload[i*7000:end], 0o600)
		parts = append(parts, p)
	}
	argv = append([]string{"-c", hostedExecUnpackScript, "sh", filepath.Join(stage, "j.tar"), sum, root}, parts...)
	if out, err := exec.Command("sh", argv...).CombinedOutput(); err != nil {
		t.Fatalf("unpack: %v %s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(root, "sandbox/workspace/a.txt"))
	if err != nil || !bytes.Equal(got, data) {
		t.Errorf("unpacked %d bytes %v", len(got), err)
	}
	if fi, err := os.Stat(filepath.Join(root, "sandbox/workspace/bin/run")); err != nil || fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("mode %v %v", fi, err)
	}
	for _, p := range parts {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("part %s left behind", p)
		}
	}
}

// TestOrgShellBundleFailureIsAFailedReturn (fix round 1, A12 and the 11.4
// oversized-bundle row): a bundle that failed, was cut at its cap (exit 3)
// or errored is a failed return, so the box is not deleted from here; no
// commits is a return with nothing to save.
func TestOrgShellBundleFailureIsAFailedReturn(t *testing.T) {
	r := orgShellTestRun(t, &recordingBox{})
	cases := []struct {
		name string
		out  []byte
		code int
		err  error
		want bool
	}{
		{"saved", []byte("bundle"), 0, nil, true},
		{"no commits", nil, 2, nil, true},
		{"oversized, cut at the cap", []byte("x"), 3, nil, false},
		{"exec error", nil, 0, errors.New("stream cut"), false},
		{"other exit", nil, 128, nil, false},
	}
	for _, tc := range cases {
		if got := r.orgShellSaveBundle(tc.out, tc.code, tc.err); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}

var _ = sandboxbackend.BackendOpenShellOrg
