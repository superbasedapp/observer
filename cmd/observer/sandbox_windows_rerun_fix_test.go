//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_windows_rerun_fix_test.go pins the fixes of the Windows 11 Pro
// rerun of 2026-10-22 (mxc-process, MXC 1.0.1): MXC names the AppContainer
// itself, so box detection compares against the SID the host read from the
// box process; refusals lead with their real cause; the host prints whole
// inner-log lines; an in-box launcher says attach is not available there.

const (
	rerunTokenSID = "S-1-15-2-377672063-2526458857-2708711055-2539526891-2453953282-1215201319-3423974728"
	rerunNameSID  = "S-1-15-2-1646696914-3659874966-3521681829-830165155-2590687638-1220726536-2661899589"
)

// rerunOwnBox is a process in run-7's box whose host answered with its SID.
func rerunOwnBox(t *testing.T) mxcBoxFacts {
	t.Helper()
	return mxcBoxFacts{
		AppContainer: true, TokenSID: rerunTokenSID,
		BoxDir: filepath.Join(t.TempDir(), mxcBoxDirPrefix+"run-7"), RecordRunID: "run-7",
		Identity:       &sandboxmxc.BoxIdentity{V: sandboxmxc.BoxIdentityVersion, RunID: "run-7", ContainerID: "observer-run-7", SID: rerunTokenSID},
		NameSID:        func(string) (string, error) { return rerunNameSID, nil },
		DriverSelected: func() bool { return true },
	}
}

// TestMXCBoxIdentityBinding (item 1): a process is our box only when its
// token SID is the SID the host read from that run's box process, never
// the SID derived from observer-<run id> (the rerun's live shape: MXC's
// SID differs from it on every run). A mismatch names the containerId and
// both SIDs.
func TestMXCBoxIdentityBinding(t *testing.T) {
	if id, why := mxcBoxRunIDWhy(rerunOwnBox(t)); id != "run-7" || why != "" {
		t.Fatalf("our own box (the rerun's live SIDs): %q %q", id, why)
	}
	lower := rerunOwnBox(t)
	lower.Identity.SID = strings.ToLower(rerunTokenSID)
	if id, _ := mxcBoxRunIDWhy(lower); id != "run-7" {
		t.Fatal("SIDs compare case-insensitively")
	}
	for name, c := range map[string]struct {
		mut  func(*mxcBoxFacts)
		want []string
	}{
		"the name-derived SID is no proof": {func(f *mxcBoxFacts) { f.TokenSID = rerunNameSID }, []string{rerunNameSID, rerunTokenSID, "observer-run-7", "host helper read"}},
		"another container":                {func(f *mxcBoxFacts) { f.TokenSID = "S-1-15-2-1-2-3" }, []string{"S-1-15-2-1-2-3", rerunTokenSID, "a profile named observer-run-7 would have SID " + rerunNameSID}},
		"no answer":                        {func(f *mxcBoxFacts) { f.Identity, f.IdentityErr = nil, errors.New("reach the sandbox port: refused") }, []string{"could not be asked", "refused"}},
		"no answer and no error":           {func(f *mxcBoxFacts) { f.Identity = nil }, []string{"no answer"}},
		"another version":                  {func(f *mxcBoxFacts) { f.Identity.V = 2 }, []string{"version 2"}},
		"another run's answer":             {func(f *mxcBoxFacts) { f.Identity.RunID = "run-8" }, []string{`"run-8"`, "run-7"}},
		"the host found no box":            {func(f *mxcBoxFacts) { f.Identity.SID, f.Identity.Error = "", "no AppContainer process yet" }, []string{"could not read the container", "no AppContainer process yet"}},
		"an empty answer":                  {func(f *mxcBoxFacts) { f.Identity.SID = "" }, []string{"named no SID"}},
		"no name derivation":               {func(f *mxcBoxFacts) { f.TokenSID, f.NameSID = "S-1-15-2-9", nil }, []string{"S-1-15-2-9", rerunTokenSID}},
		"the driver not selected":          {func(f *mxcBoxFacts) { f.DriverSelected = func() bool { return false } }, []string{mxcComponent}},
	} {
		f := rerunOwnBox(t)
		in := *f.Identity
		f.Identity = &in
		c.mut(&f)
		id, why := mxcBoxRunIDWhy(f)
		if id != "" {
			t.Errorf("%s: recognised as %q", name, id)
		}
		for _, w := range c.want {
			if !strings.Contains(why, w) {
				t.Errorf("%s: %q lacks %q", name, why, w)
			}
		}
	}
}

// TestMXCIdentityWatch (item 1): the host latches the first SID its scan
// names, refuses on any other scan error, gives up at the limit or when the
// run ends, and never changes a latched answer.
func TestMXCIdentityWatch(t *testing.T) {
	other := errors.New("wxc-exec (pid 9) is no longer running")
	for name, c := range map[string]struct {
		scans   []error
		sid     string
		cancel  bool
		wantSID string
		wantErr string
	}{
		"found after two looks": {scans: []error{sandboxmxc.ErrBoxNotStarted, sandboxmxc.ErrBoxNotStarted, nil}, sid: rerunTokenSID, wantSID: rerunTokenSID},
		"found at once":         {scans: []error{nil}, sid: rerunTokenSID, wantSID: rerunTokenSID},
		"ambiguous":             {scans: []error{fmt.Errorf("%w: a, b", sandboxmxc.ErrBoxAmbiguous)}, wantErr: "more than one AppContainer"},
		"wxc-exec gone":         {scans: []error{sandboxmxc.ErrBoxNotStarted, other}, wantErr: "no longer running"},
		"never found":           {scans: nil, wantErr: "searched for"},
		"the run ended":         {scans: nil, cancel: true, wantErr: "the run ended"},
	} {
		l := newMXCIdentityLatch()
		ctx, cancel := context.WithCancel(context.Background())
		if c.cancel {
			cancel()
		}
		i := 0
		scan := func() (string, error) {
			if i >= len(c.scans) {
				return "", sandboxmxc.ErrBoxNotStarted
			}
			err := c.scans[i]
			i++
			if err != nil {
				return "", err
			}
			return c.sid, nil
		}
		limit := time.Second
		if c.cancel {
			limit = time.Hour
		}
		mxcWatchBoxIdentity(ctx, l, scan, time.Millisecond, limit)
		cancel()
		sid, err := l.wait(context.Background())
		if sid != c.wantSID || (c.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("%s: sid %q err %v", name, sid, err)
		}
		l.set("S-1-15-2-later", nil)
		if sid2, _ := l.wait(context.Background()); sid2 != sid {
			t.Errorf("%s: a later set changed the latched answer to %q", name, sid2)
		}
	}
	l := newMXCIdentityLatch()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := l.wait(ctx); err == nil || !strings.Contains(err.Error(), "not known yet") {
		t.Fatalf("an unset latch: %v", err)
	}
	if ans := mxcIdentityAnswer(ctx, "run-7", l); ans.SID != "" || ans.Error == "" || ans.RunID != "run-7" || ans.ContainerID != "observer-run-7" || ans.V != sandboxmxc.BoxIdentityVersion {
		t.Fatalf("the answer of an unset latch: %+v", ans)
	}
	// A wait that times out names the host's latest look.
	l.note(fmt.Errorf("%w (2 processes under it)", sandboxmxc.ErrBoxNotStarted))
	if _, err := l.wait(ctx); err == nil || !strings.Contains(err.Error(), "last look") || !strings.Contains(err.Error(), "2 processes under it") {
		t.Fatalf("a timed-out wait: %v", err)
	}
}

// TestMXCIdentityOnThePort (item 1): the box reads the host's answer through
// the run's port with the run's token; another token, or a port with no
// identity, answers nothing, and no error carries the token.
func TestMXCIdentityOnThePort(t *testing.T) {
	tok, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("i", 32)))
	other, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("j", 32)))
	l := newMXCIdentityLatch()
	l.set(rerunTokenSID, nil)
	for _, tier := range sandboxmxc.Tiers() {
		port := startMXCPort(t, &mxcPort{Token: tok, Tier: tier, Identity: func(ctx context.Context) sandboxmxc.BoxIdentity { return mxcIdentityAnswer(ctx, "run-7", l) }})
		id, err := mxcFetchIdentity(context.Background(), mxcLoopback{V: 1, Port: port, Token: tok})
		if err != nil || id.SID != rerunTokenSID || id.RunID != "run-7" {
			t.Fatalf("%s: %+v %v", tier, id, err)
		}
		if _, err := mxcFetchIdentity(context.Background(), mxcLoopback{V: 1, Port: port, Token: other}); err == nil || strings.Contains(err.Error(), other) {
			t.Fatalf("%s: another token: %v", tier, err)
		}
	}
	bare := startMXCPort(t, &mxcPort{Token: tok, Tier: vocab.TierNone})
	if _, err := mxcFetchIdentity(context.Background(), mxcLoopback{V: 1, Port: bare, Token: tok}); err == nil {
		t.Fatal("a port without an identity answered")
	}
	// Through the box directory's loopback record, as box detection asks.
	port := startMXCPort(t, &mxcPort{Token: tok, Tier: vocab.TierProxyOnly, Identity: func(ctx context.Context) sandboxmxc.BoxIdentity { return mxcIdentityAnswer(ctx, "run-7", l) }})
	dir := t.TempDir()
	if err := writeMXCLoopback(dir, mxcLoopback{V: 1, Port: port, Token: tok}); err != nil {
		t.Fatal(err)
	}
	id, err := mxcAskBoxIdentity(dir)
	if err != nil || id == nil || id.SID != rerunTokenSID {
		t.Fatalf("asked through the box directory: %+v %v", id, err)
	}
	if got := redactBoxSecrets("token " + tok); strings.Contains(got, tok) {
		t.Fatal("the run's token was not registered as a box secret")
	}
	// An unreachable port: the error names no token.
	if _, err := mxcFetchIdentity(context.Background(), mxcLoopback{V: 1, Port: 1, Token: tok}); err == nil || strings.Contains(err.Error(), tok) {
		t.Fatalf("an unreachable port: %v", err)
	}
}

// TestMXCSameImage (item 1): the host matches the box process's image to the
// inner launch's executable by file, or by path case-insensitively.
func TestMXCSameImage(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "observer.exe")
	otherExe := filepath.Join(dir, "claude.exe")
	for _, p := range []string{exe, otherExe} {
		if err := os.WriteFile(p, []byte(p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	same := mxcSameImage(exe)
	for _, c := range []struct {
		p    string
		want bool
	}{
		{exe, true},
		{filepath.Join(dir, ".", "observer.exe"), true},
		{otherExe, false},
		{filepath.Join(dir, "missing.exe"), false},
	} {
		if got := same(c.p); got != c.want {
			t.Errorf("same(%q) = %v", c.p, got)
		}
	}
	missing := mxcSameImage(`C:\p6live\observer.exe`)
	if !missing(`c:\P6LIVE\observer.exe`) || missing(`C:\p6live\claude.exe`) {
		t.Fatal("the path fallback")
	}
}

// TestBoxGateRefusalsLeadWithTheCause (item 3): each in-box launch check
// refusal leads with the cause that happened. None of them tells the user to
// check the daemon any more: since Windows 11 Pro run 3 only the relay hop
// where the helper could not connect to the daemon does (boxGateHops,
// TestBoxGateHopRefusals).
func TestBoxGateRefusalsLeadWithTheCause(t *testing.T) {
	daemonHint := "check that the Observer daemon is running"
	for cause, c := range map[boxGateCause]struct {
		lead        string
		daemonCheck bool
	}{
		boxGateNotRecognised: {"did not recognise the sandbox it runs in", false},
		boxGateNoRecord:      {"launch record is missing or refused", false},
		boxGateUnreachable:   {"could not reach Observer's capture relay", false},
		boxGateRelayRefused:  {"capture relay refused the request", false},
	} {
		msg := boxGateRefusal(cause, "detail-x").Error()
		if !strings.Contains(msg, c.lead) || strings.Contains(msg, daemonHint) != c.daemonCheck || !strings.HasSuffix(msg, "(detail-x)") {
			t.Errorf("cause %d: %q", cause, msg)
		}
		if strings.Contains(boxGateRefusals[cause], daemonHint) != c.daemonCheck {
			t.Errorf("cause %d asks to check the daemon: %q", cause, boxGateRefusals[cause])
		}
	}
	if len(boxGateRefusals) != 4 {
		t.Fatalf("%d causes", len(boxGateRefusals))
	}
	// Through the gate: a failed detection leads with itself; a box with no
	// detection note and no record says the record is missing.
	t.Setenv(sandboxEnvMarker, "1")
	oldRec, oldNote := boxRecordPath, boxDetectNote
	t.Cleanup(func() { boxRecordPath, boxDetectNote = oldRec, oldNote })
	boxRecordPath = filepath.Join(t.TempDir(), "missing", sandboxrelayd.BoxRecordName)
	for note, want := range map[string]string{
		"this process's AppContainer SID A is not the SID B": "did not recognise the sandbox it runs in (this process's AppContainer SID A is not the SID B)",
		"": "launch record is missing or refused",
	} {
		boxDetectNote = note
		err, boxed := boxLaunchGate("claude-code", budgetLaunchEvidence{})
		if !boxed || err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), daemonHint) {
			t.Errorf("note %q: %v", note, err)
		}
	}
}

// TestMXCInnerLogWholeLines (item 4): the host prints whole lines only, the
// last mxcInnerLogLines of them, and a long diagnostic line is never cut.
func TestMXCInnerLogWholeLines(t *testing.T) {
	for name, c := range map[string]struct {
		in       string
		cut      bool
		max      int
		want     []string
		omitting int
	}{
		"all lines":           {"a\nb\n", false, 5, []string{"a", "b"}, 0},
		"a partial first one": {"tail of a\nb\nc\n", true, 5, []string{"b", "c"}, 1},
		"the last lines only": {"a\nb\nc\nd\n", false, 2, []string{"c", "d"}, 2},
		"partial and capped":  {"x\nb\nc\nd\n", true, 2, []string{"c", "d"}, 2},
		"one partial line":    {"no newline at all", true, 5, nil, 1},
		"empty":               {"", false, 5, nil, 0},
	} {
		got, omitted := mxcWholeLines([]byte(c.in), c.cut, c.max)
		if strings.Join(got, "|") != strings.Join(c.want, "|") || omitted != c.omitting {
			t.Errorf("%s: %q, %d omitted", name, got, omitted)
		}
	}
	// The rerun's refusal line (two full SIDs, over 400 bytes) survives the
	// writer and the host's tail whole.
	long := "observer claude: " + strings.Repeat("the sandbox's launch checks refused the launch ", 6) + "SID " + rerunTokenSID + " vs " + rerunNameSID
	if got := boxOneLine(long); got != long {
		t.Fatalf("the writer cut a %d-byte line: %q", len(long), got)
	}
	dir := t.TempDir()
	p := mxcInnerLogPath(dir)
	body := strings.Repeat("t pid 1: filler line of some length\n", 1000) + "t pid 2: " + long + "\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	mxcReportInnerLog(&w, p, 1)
	out := w.String()
	if !strings.Contains(out, long) || !strings.Contains(out, "earlier line(s) not shown") || strings.Contains(out, "...") {
		t.Fatalf("the tail:\n%s", out)
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n")[1:] {
		if !strings.HasPrefix(line, "  t pid ") && !strings.HasPrefix(line, "  (") {
			t.Errorf("a cut line: %q", line)
		}
	}
	if n := strings.Count(out, "\n"); n > mxcInnerLogLines+2 {
		t.Fatalf("%d lines printed", n)
	}
}

// TestDecideAttachInSandbox (item 5): inside a sandbox an unreachable attach
// socket says attach is not available there; on the host the daemon notice
// stays; scripted paths stay silent and a reachable socket still attaches.
func TestDecideAttachInSandbox(t *testing.T) {
	base := attachDecisionInputs{enabled: true, defaultOn: true, grounded: true, stdinTTY: true, stdoutTTY: true}
	for name, c := range map[string]struct {
		inBox, reach, tty bool
		verdict           attachVerdict
		notice            string
	}{
		"in a box, unreachable":    {true, false, true, verdictBare, attachInSandboxNotice},
		"on the host, unreachable": {false, false, true, verdictBare, attachDaemonUnreachableNotice},
		"in a box, reachable":      {true, true, true, verdictAttach, ""},
		"in a box, scripted":       {true, false, false, verdictBare, ""},
	} {
		in := base
		in.inSandbox, in.stdoutTTY = c.inBox, c.tty
		reach := c.reach
		in.reachable = func() bool { return reach }
		got := decideAttach(in)
		if got.verdict != c.verdict || got.notice != c.notice {
			t.Errorf("%s: %+v", name, got)
		}
	}
	if strings.Contains(attachInSandboxNotice, "unreachable") || strings.ContainsRune(attachInSandboxNotice, '\n') {
		t.Fatalf("notice %q", attachInSandboxNotice)
	}
}
