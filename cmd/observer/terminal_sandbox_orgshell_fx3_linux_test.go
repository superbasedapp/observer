//go:build linux && !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// lateReadyBox is a live-shaped fake of the OpenShell 0.1.6 create (G-L3 run
// 3, F-L3P4-1): CreateSandbox answers a box that is not yet ready, GetSandbox
// reports it ready only after readyAfter reads, and every exec before that
// answers the gateway's own "sandbox is not ready" refusal.
type lateReadyBox struct {
	sandboxremote.Client
	mu         sync.Mutex
	readyAfter int
	gets       int
	created    int
	early      []string // execs sent before the box was ready
	execs      []string
	stopAt     int // the exec number (1-based) that fails, ending prepare
}

func (b *lateReadyBox) Create(context.Context, sandboxremote.BoxSpec) (sandboxremote.BoxInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.created++
	return sandboxremote.BoxInfo{ID: "obsbox", Running: false}, nil
}

func (b *lateReadyBox) Get(context.Context, string) (sandboxremote.BoxInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gets++
	return sandboxremote.BoxInfo{ID: "obsbox", Running: b.gets > b.readyAfter}, nil
}

func (b *lateReadyBox) Exec(_ context.Context, _ string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cmd := strings.Join(spec.Argv, " ")
	if b.gets <= b.readyAfter {
		b.early = append(b.early, cmd)
		return nil, errors.New("openshellorg: FailedPrecondition: sandbox is not ready")
	}
	b.execs = append(b.execs, cmd)
	if len(b.execs) == b.stopAt {
		return nil, errors.New("stop here")
	}
	return doneProc{Reader: strings.NewReader("1000:1000\n"), code: 0}, nil
}

// TestOrgShellWaitsForReadyBeforeFirstExec (FX3 item 1, F-L3P4-1): after a
// create the gateway answered before the box was ready, the node polls the
// box (reads only) until it runs and sends no exec before that, on the
// clone-local path and on the clone-remote path (whose first exec is the
// clone).
func TestOrgShellWaitsForReadyBeforeFirstExec(t *testing.T) {
	old := hostedReadyFirstPoll
	hostedReadyFirstPoll = time.Millisecond
	t.Cleanup(func() { hostedReadyFirstPoll = old })
	for _, delivery := range []string{"", hostedDeliveryRemoteClone} {
		t.Run("delivery="+delivery, func(t *testing.T) {
			stop := 2 // the owner probe's failure is ignored; the setup is the first that ends prepare
			if delivery == hostedDeliveryRemoteClone {
				stop = 1
			}
			box := &lateReadyBox{readyAfter: 3, stopAt: stop}
			r := orgShellTestRun(t, box)
			r.plan.Delivery = delivery
			if err := r.create(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !r.notReady {
				t.Fatal("a create answered before ready was not marked to wait")
			}
			err := r.prepare(context.Background())
			if err == nil || !strings.Contains(err.Error(), "stop here") {
				t.Fatalf("prepare: %v (want the first real exec's error)", err)
			}
			if len(box.early) != 0 {
				t.Errorf("execs sent before the box was ready: %v", box.early)
			}
			// The wait is reads only: readyAfter not-ready answers, then the
			// ready one. None is one of the gateway's admitted mutations.
			if box.gets != box.readyAfter+1 {
				t.Errorf("gets %d, want %d", box.gets, box.readyAfter+1)
			}
			if delivery == hostedDeliveryRemoteClone && !strings.HasPrefix(box.execs[0], "git clone") {
				t.Errorf("the clone-remote run's first exec is %q, want the clone", box.execs[0])
			}
		})
	}
}

// TestOrgShellReadyWaitIsBounded: a box that never becomes ready ends the
// wait at the row's bounded deadline, with no exec sent.
func TestOrgShellReadyWaitIsBounded(t *testing.T) {
	oldFirst, oldCap := hostedReadyFirstPoll, hostedResumePoll
	hostedReadyFirstPoll, hostedResumePoll = time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { hostedReadyFirstPoll, hostedResumePoll = oldFirst, oldCap })
	box := &lateReadyBox{readyAfter: 1 << 30}
	r := orgShellTestRun(t, box)
	r.vendor.ReadyWaitSeconds = 0
	clock := time.Now()
	r.now = func() time.Time { clock = clock.Add(time.Minute); return clock }
	if err := r.create(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := r.prepare(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not become ready") {
		t.Fatalf("prepare: %v", err)
	}
	if len(box.early) != 0 || len(box.execs) != 0 {
		t.Errorf("execs %v early %v", box.execs, box.early)
	}
	if v, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg); v.ReadyWait() != 180*time.Second {
		t.Errorf("the org row's ready wait %s", v.ReadyWait())
	}
}

// TestHostedReadyBackoff: the waits double from the first poll up to the cap.
func TestHostedReadyBackoff(t *testing.T) {
	oldFirst, oldCap := hostedReadyFirstPoll, hostedResumePoll
	hostedReadyFirstPoll, hostedResumePoll = 250*time.Millisecond, 3*time.Second
	t.Cleanup(func() { hostedReadyFirstPoll, hostedResumePoll = oldFirst, oldCap })
	want := []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 3 * time.Second, 3 * time.Second}
	for i, w := range want {
		if got := hostedReadyBackoff(i); got != w {
			t.Errorf("attempt %d: %s, want %s", i, got, w)
		}
	}
}

// scriptBox answers each exec by its argv and records every exec (with its
// one-shot stdin size).
type scriptBox struct {
	sandboxremote.Client
	mu     sync.Mutex
	execs  []sandboxremote.ExecSpec
	answer func(argv []string) string
}

func (b *scriptBox) Exec(_ context.Context, _ string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	b.mu.Lock()
	b.execs = append(b.execs, spec)
	b.mu.Unlock()
	return doneProc{Reader: strings.NewReader(b.answer(spec.Argv)), code: 0}, nil
}

func (b *scriptBox) Get(context.Context, string) (sandboxremote.BoxInfo, error) {
	return sandboxremote.BoxInfo{ID: "obsbox", Running: true}, nil
}

// orgShellAnswers answers the in-box steps: the owner, the tools (no gzip,
// so the binary is sent raw), the version.
func orgShellAnswers(argv []string) string {
	all := strings.Join(argv, " ")
	switch {
	case strings.Contains(all, "id -u"):
		return "1000:1000\n"
	case strings.Contains(all, "sha256sum; do"):
		return "sha256sum\n"
	case slices.Contains(argv, "--version"):
		return "observer version " + version + "\n"
	}
	return ""
}

// TestOrgShellUploadUsesGatewaySizedParts (FX3 item 2b, F-L3P4-6): on the
// org row each part of the in-box observer is ONE exec of the largest stdin
// the gateway's message limit allows, never a tar of quarter-MiB parts, so
// the 76.6 MiB observer of G-L3 run 3 (about 300 execs then) takes 84. FX4
// item 2 (F-P6-2): the limit is the 0.1.6 gateway's 1 MiB decode limit,
// not the 4 MiB FX3 assumed (22 execs, every part refused live).
func TestOrgShellUploadUsesGatewaySizedParts(t *testing.T) {
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	if v.OneShotStdinBytes != osorg.MaxOneShotStdin || osorg.MaxOneShotStdin != 1<<20-64<<10 || osorg.GatewayDecodeBytes != 1<<20 {
		t.Fatalf("the row's part %d, the core's %d", v.OneShotStdinBytes, osorg.MaxOneShotStdin)
	}
	r := orgShellTestRun(t, &scriptBox{answer: orgShellAnswers})
	part := r.execPartBytes()
	const liveBinary = 80320102 // 76.6 MiB, as sent in G-L3 run 3
	if execs := 1 + (liveBinary+part-1)/part + 1; execs != 84 {
		t.Errorf("the live binary's upload takes %d execs, want 84 (tools probe, 82 parts, assemble)", execs)
	}
	// The same rule on a real upload, with small parts: probe, parts,
	// assemble, every part one exec under the part size.
	old := hostedExecPartOverride
	hostedExecPartOverride = 64 << 10
	t.Cleanup(func() { hostedExecPartOverride = old })
	bin := filepath.Join(t.TempDir(), "observer")
	data := make([]byte, 200<<10)
	for i := range data {
		data[i] = byte(i * 7)
	}
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}
	box := &scriptBox{answer: orgShellAnswers}
	r = orgShellTestRun(t, box)
	r.plan.BoxBinary = bin
	if err := r.uploadBoxBinary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(box.execs) != 1+4+1 {
		t.Errorf("upload execs %d, want 6", len(box.execs))
	}
	for _, e := range box.execs {
		if len(e.StdinData) > 64<<10 {
			t.Errorf("a part of %d bytes", len(e.StdinData))
		}
	}
}

// TestOrgShellImageBinaryUploadsNothing (FX3 item 2b): with the org's
// box_binary = "image" the node sends no part, probes no tool and no
// architecture, and only checks the version the image's observer reports;
// a clone-remote run's prepare is then five execs in all.
func TestOrgShellImageBinaryUploadsNothing(t *testing.T) {
	box := &scriptBox{answer: orgShellAnswers}
	r := orgShellTestRun(t, box)
	r.plan.Delivery = hostedDeliveryRemoteClone
	r.plan.BoxBinaryInImage = true
	r.rec.VendorID = "obsbox"
	if err := r.prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range box.execs {
		got = append(got, e.Argv[0]+" "+strings.Join(e.Argv[1:min(len(e.Argv), 3)], " "))
		if len(e.StdinData) > 0 || slices.Contains(e.Argv, "uname") {
			t.Errorf("an upload or arch exec with the binary in the image: %v", e.Argv)
		}
	}
	if len(box.execs) != 5 {
		t.Errorf("prepare execs %d, want 5 (clone, owner, setup, version, baseline): %v", len(box.execs), got)
	}
	// A box whose image carries another version is refused, naming it.
	bad := &scriptBox{answer: func(argv []string) string {
		if slices.Contains(argv, "--version") {
			return "observer version 0.0.1\n"
		}
		return orgShellAnswers(argv)
	}}
	r = orgShellTestRun(t, bad)
	r.plan.Delivery = hostedDeliveryRemoteClone
	r.plan.BoxBinaryInImage = true
	err := r.prepare(context.Background())
	if err == nil || !strings.Contains(err.Error(), verdictHostedBoxBinary) || !strings.Contains(err.Error(), "box_binary = image") {
		t.Fatalf("an image of another version: %v", err)
	}
}

// TestOrgShellImageComposes: the org's published box_binary = "image"
// reaches the row's provider table, which then needs no local Linux binary
// and says so on the consent screen.
func TestOrgShellImageComposes(t *testing.T) {
	o := &orgcontract.SandboxManagedOrgOpenShellV1{
		FrontURL: "https://sandbox.example.com", GatewayID: "gw1", Version: "0.1.6", Image: "r/box@sha256:00",
		BoxBinary: orgcontract.OrgOpenShellBoxBinaryImage,
	}
	var dst config.TerminalSandboxConfig
	if set, why := sandboxManagedComposePublished(&dst, orgcontract.SandboxManagedPolicyV1{OrgOpenShell: o}, sandboxManagedEnv{}); !set || why != "" {
		t.Fatalf("composed %v %q", set, why)
	}
	pc := dst.Hosted.OpenShellOrg.Provider
	if !pc.BoxBinaryInImage || hostedBoxBinaryCheck(pc, "") != nil || !strings.Contains(hostedBoxBinaryLabel(pc), "box image") {
		t.Errorf("provider %+v, check %v, label %q", pc, hostedBoxBinaryCheck(pc, ""), hostedBoxBinaryLabel(pc))
	}
	o.BoxBinary = "upload"
	dst = config.TerminalSandboxConfig{}
	sandboxManagedComposePublished(&dst, orgcontract.SandboxManagedPolicyV1{OrgOpenShell: o}, sandboxManagedEnv{})
	if dst.Hosted.OpenShellOrg.Provider.BoxBinaryInImage {
		t.Error("upload composed as image")
	}
}

// TestOrgShellCutStreamHoldsTheBox (FX3 item 9, F-L4P5-2): an agent stream
// that ended without the agent's exit is not the run's end: the node says
// the front's reason, asks the organization to hold the box as a disconnect
// (H2), and deletes nothing.
func TestOrgShellCutStreamHoldsTheBox(t *testing.T) {
	var got []orgclient.OpenShellEnded
	old := orgShellReport
	orgShellReport = func(_ context.Context, _ *orgclient.Client, _ string, rep orgclient.OpenShellEnded) (orgclient.OpenShellEndedAnswer, error) {
		got = append(got, rep)
		return orgclient.OpenShellEndedAnswer{Outcome: "hold"}, nil
	}
	t.Cleanup(func() { orgShellReport = old })
	box := &scriptBox{answer: orgShellAnswers}
	r := orgShellTestRun(t, box)
	var out strings.Builder
	r.t.out = &out
	r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, "https://sandbox.example.com", "", r.plan.RunID, r.now(), time.Hour)
	r.rec.VendorID = "obsbox"
	_ = r.rec.Apply(sandboxremote.EvCreateOK)
	r.rec.State = sandboxremote.StateGone // nothing to pull in this test
	orgShellRunState.Store(r.plan.RunID, &orgShellRun{tokens: &orgShellTokens{first: orgclient.OpenShellMint{ReturnToNode: true, HoldPolicy: "on_disconnect"}}})
	r.cutStream(errors.New("openshellorg: Unavailable: decision_unavailable"))
	if !orgShellEndRun(context.Background(), r) {
		t.Fatal("the end branch did not run")
	}
	if len(got) != 1 || !got[0].Hold || !got[0].Disconnected || got[0].Returned {
		t.Fatalf("end reports %+v, want one hold as a disconnect", got)
	}
	for _, e := range box.execs {
		if slices.Contains(e.Argv, "--diff") || strings.Contains(strings.Join(e.Argv, " "), "git add") {
			t.Errorf("a cut stream took the return path: %v", e.Argv)
		}
	}
	s := out.String()
	if !strings.Contains(s, "decision_unavailable") || !strings.Contains(s, "held by your organization") || strings.Contains(s, "deleted next") {
		t.Errorf("terminal said: %s", s)
	}
}

// TestOrgShellHeldWords (FX3 item 7, F-L3P4-7): on a row whose end rule
// keeps a box whose work did not come home, a diff that was not saved is
// never "deleted next"; and a cut whose end report is lost still names the
// hold and the resume command.
func TestOrgShellHeldWords(t *testing.T) {
	r := orgShellTestRun(t, &scriptBox{answer: orgShellAnswers})
	var out strings.Builder
	r.t.out = &out
	r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, "https://sandbox.example.com", "", r.plan.RunID, r.now(), time.Hour)
	r.diffNotSaved("staging the changes failed: %v", errors.New("box unreachable"))
	if s := out.String(); strings.Contains(s, "deleted next") || !strings.Contains(s, "does not delete the box") {
		t.Errorf("diff words: %s", s)
	}

	old := orgShellReport
	orgShellReport = func(context.Context, *orgclient.Client, string, orgclient.OpenShellEnded) (orgclient.OpenShellEndedAnswer, error) {
		return orgclient.OpenShellEndedAnswer{}, errors.New("connection refused")
	}
	t.Cleanup(func() { orgShellReport = old })
	out.Reset()
	_ = r.rec.Apply(sandboxremote.EvCreateOK)
	r.rec.VendorID, r.rec.State = "obsbox", sandboxremote.StateGone
	orgShellRunState.Store(r.plan.RunID, &orgShellRun{tokens: &orgShellTokens{first: orgclient.OpenShellMint{ReturnToNode: true, HoldPolicy: "on_disconnect"}}})
	r.cutStream(errors.New("openshellorg: Unavailable: connection reset"))
	if !orgShellEndRun(context.Background(), r) {
		t.Fatal("the end branch did not run")
	}
	if s := out.String(); !strings.Contains(s, "org-shell resume "+r.plan.RunID) || strings.Contains(s, "deleted next") {
		t.Errorf("lost-report words: %s", s)
	}
}

// TestHostedSeedsFirstRunState (FX3 item 7, F-L3P4-8): an interactive Claude
// Code in a box stops at its first-run screens, which call the provider
// directly (ECONNREFUSED in the box); a tool onboarded on this machine gets
// the row's non-secret seed keys in its state file in the box home, on a
// fresh prepare and on a resume; a tool not onboarded here gets nothing.
func TestHostedSeedsFirstRunState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	state := `{"hasCompletedOnboarding":true,"theme":"dark","userID":"u-secretish","oauthAccount":{"emailAddress":"dev@example.com"}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	box := &scriptBox{answer: orgShellAnswers}
	r := orgShellTestRun(t, box)
	r.plan.Tool = "claude-code"
	r.seedToolState(context.Background())
	if len(box.execs) != 1 {
		t.Fatalf("seed execs %d", len(box.execs))
	}
	argv := box.execs[0].Argv
	dst, seed := argv[len(argv)-2], argv[len(argv)-1]
	if dst != r.layout.Home+"/.claude.json" || !strings.Contains(seed, `"hasCompletedOnboarding":true`) || !strings.Contains(seed, `"theme":"dark"`) {
		t.Fatalf("seed %q to %q", seed, dst)
	}
	if strings.Contains(seed, "userID") || strings.Contains(seed, "dev@example.com") {
		t.Fatalf("a non-seed key reached the box: %s", seed)
	}
	if !strings.Contains(argv[2], `[ -e "$1" ] ||`) {
		t.Errorf("the seed overwrites a box's own state: %q", argv[2])
	}
	// The resume path seeds a box prepared before the seed existed.
	box.execs = nil
	r.rec.VendorID = "obsbox"
	if err := r.resumeBox(context.Background(), "obsbox"); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(box.execs, func(e sandboxremote.ExecSpec) bool { return slices.Contains(e.Argv, r.layout.Home+"/.claude.json") }) {
		t.Error("the resume did not seed the first-run state")
	}
	// FX4 item 4 (the F-L3P4-8 remainder): installed here but never started
	// interactively (no hasCompletedOnboarding), and with no state file at
	// all: the box is still seeded onboarded (its first-run screens cannot
	// work there), with this machine's theme when it has one.
	for _, tc := range []struct {
		name, state string
		theme       bool
	}{
		{"never started here", `{"theme":"dark","numStartups":0}`, true},
		{"onboarding false here", `{"hasCompletedOnboarding":false}`, false},
		{"no state file here", "", false},
	} {
		_ = os.Remove(filepath.Join(home, ".claude.json"))
		if tc.state != "" {
			if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(tc.state), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		box.execs = nil
		r.seedToolState(context.Background())
		if len(box.execs) != 1 {
			t.Fatalf("%s: seed execs %d", tc.name, len(box.execs))
		}
		seed := box.execs[0].Argv[len(box.execs[0].Argv)-1]
		if !strings.Contains(seed, `"hasCompletedOnboarding":true`) || strings.Contains(seed, `"theme":"dark"`) != tc.theme || strings.Contains(seed, "numStartups") {
			t.Errorf("%s: seed %s", tc.name, seed)
		}
	}
}

// TestOrgShellResumeSaysWhyNoSession (FX3 item 7): a resume whose box
// recorded no agent session says so, apart from a tool with no native
// resume; a recorded session resumes natively.
func TestOrgShellResumeSaysWhyNoSession(t *testing.T) {
	sessions := ""
	box := &scriptBox{answer: func(argv []string) string {
		if argv[0] == "cat" {
			return sessions
		}
		return orgShellAnswers(argv)
	}}
	r := orgShellTestRun(t, box)
	r.plan.Tool = "claude-code"
	r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, "https://sandbox.example.com", "", r.plan.RunID, r.now(), time.Hour)
	r.rec.VendorID = "obsbox"
	var out strings.Builder
	r.t.out = &out
	inner := []string{"observer", "claude"}
	if got := r.withResumeArgs(inner); !slices.Equal(got, inner) || !strings.Contains(out.String(), "the box recorded none") {
		t.Fatalf("no session: %v %s", got, out.String())
	}
	out.Reset()
	sessions = `{"last":"11111111-2222-3333-4444-555555555555"}`
	if got := r.withResumeArgs(inner); len(got) <= len(inner) || strings.Contains(out.String(), "cannot be resumed") {
		t.Fatalf("a recorded session did not resume natively: %v %s", got, out.String())
	}
}

// TestOrgShellReportsTheNodesMinutes (FX3 item 8, F-L3P4-3): a 30 s box is
// reported to the organization as 1 minute, the minute the node's own
// ledger settles, not 0.
func TestOrgShellReportsTheNodesMinutes(t *testing.T) {
	var got []orgclient.OpenShellEnded
	old := orgShellReport
	orgShellReport = func(_ context.Context, _ *orgclient.Client, _ string, rep orgclient.OpenShellEnded) (orgclient.OpenShellEndedAnswer, error) {
		got = append(got, rep)
		return orgclient.OpenShellEndedAnswer{Outcome: "hold"}, nil
	}
	t.Cleanup(func() { orgShellReport = old })
	r := orgShellTestRun(t, &scriptBox{answer: orgShellAnswers})
	r.start = r.now().Add(-30 * time.Second)
	r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, "https://sandbox.example.com", "", r.plan.RunID, r.now(), time.Hour)
	r.rec.VendorID, r.rec.State = "obsbox", sandboxremote.StateGone
	orgShellRunState.Store(r.plan.RunID, &orgShellRun{tokens: &orgShellTokens{first: orgclient.OpenShellMint{ReturnToNode: false}}})
	if !orgShellEndRun(context.Background(), r) {
		t.Fatal("the end branch did not run")
	}
	if len(got) != 1 || got[0].BoxMinutes != 1 || sandboxremote.RanMinutes(30*time.Second) != 1 {
		t.Fatalf("reported %+v", got)
	}
}

// TestOrgShellRefusalIsNotADisconnect (FX3-A3): a stream the front ended
// with a closed reason (max_run's run_unknown) is the run's end: the node
// does not ask for a hold as a disconnect. A transport cut still does.
func TestOrgShellRefusalIsNotADisconnect(t *testing.T) {
	for _, c := range []struct {
		name       string
		err        error
		disconnect bool
	}{
		{"max_run refusal", fmt.Errorf("openshellorg: PermissionDenied: run_unknown: %w", sandboxremote.ErrRefused), false},
		{"transport cut", errors.New("openshellorg: Unavailable: transport is closing"), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got []orgclient.OpenShellEnded
			old := orgShellReport
			orgShellReport = func(_ context.Context, _ *orgclient.Client, _ string, rep orgclient.OpenShellEnded) (orgclient.OpenShellEndedAnswer, error) {
				got = append(got, rep)
				return orgclient.OpenShellEndedAnswer{Outcome: "ended_unreturned"}, nil
			}
			t.Cleanup(func() { orgShellReport = old })
			r := orgShellTestRun(t, goneBox{&scriptBox{answer: orgShellAnswers}})
			r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, "https://sandbox.example.com", "", r.plan.RunID, r.now(), time.Hour)
			r.rec.VendorID, r.rec.State = "obsbox", sandboxremote.StateGone
			orgShellRunState.Store(r.plan.RunID, &orgShellRun{tokens: &orgShellTokens{first: orgclient.OpenShellMint{ReturnToNode: true, HoldPolicy: "on_disconnect"}}})
			r.cutStream(c.err)
			_ = orgShellEndRun(context.Background(), r)
			if len(got) == 0 {
				t.Fatal("no end report")
			}
			if got[0].Disconnected != c.disconnect || got[0].Hold != c.disconnect {
				t.Fatalf("end report %+v, want hold and disconnected %v", got[0], c.disconnect)
			}
		})
	}
}

// goneBox is a scriptBox whose delete is confirmed at once.
type goneBox struct{ *scriptBox }

func (goneBox) Delete(context.Context, string) error { return nil }
func (goneBox) Get(context.Context, string) (sandboxremote.BoxInfo, error) {
	return sandboxremote.BoxInfo{}, sandboxremote.ErrNotFound
}

// TestHostedReadToolStateStaysInItsFolder: the first-run state is read only
// inside the tool's folder (lint G703 on the first version): a name that
// climbs out, or a symlink out, is refused.
func TestHostedReadToolStateStaysInItsFolder(t *testing.T) {
	dir, out := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".claude.json"), []byte(`{"hasCompletedOnboarding":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "secret.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := hostedReadToolState(dir, ".claude.json"); err != nil || !strings.Contains(string(b), "hasCompletedOnboarding") {
		t.Fatalf("the state file: %q %v", b, err)
	}
	if err := os.Symlink(filepath.Join(out, "secret.json"), filepath.Join(dir, "link.json")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../" + filepath.Base(out) + "/secret.json", "link.json"} {
		if _, err := hostedReadToolState(dir, name); err == nil {
			t.Errorf("%s was read from outside the folder", name)
		}
	}
}
