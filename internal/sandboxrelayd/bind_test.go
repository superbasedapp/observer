//go:build linux

package sandboxrelayd

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// bindHarness is a daemon serving several runs on one link, recording which
// requests reached the executor.
type bindHarness struct {
	obs, link string
	daemon    *Daemon
	mu        sync.Mutex
	ran       []string
	cwds      []string
}

func startBindHarness(t *testing.T, d *Daemon, runs ...RunRecord) *bindHarness {
	t.Helper()
	h := &bindHarness{obs: shortDir(t)}
	for _, rec := range runs {
		if err := WriteRun(h.obs, rec); err != nil {
			t.Fatal(err)
		}
	}
	d.ObserverDir, d.Rules, d.Peer = h.obs, testRules, PeerSameUser
	d.Exec = func(_ context.Context, run RunRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
		h.mu.Lock()
		h.ran = append(h.ran, run.RunID+":"+string(req.Stdin))
		h.cwds = append(h.cwds, req.Cwd)
		h.mu.Unlock()
		return sandboxrelay.HookResponse{Stdout: []byte("ok")}, nil
	}
	h.daemon = d
	h.link = filepath.Join(h.obs, "link.sock")
	ln, err := net.Listen("unix", h.link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = d.Serve(ctx, ln) }()
	return h
}

func (h *bindHarness) send(t *testing.T, run RunRecord, req sandboxrelay.HookRequest) sandboxrelay.HookResponse {
	t.Helper()
	if req.Kind == "" {
		req.Kind = sandboxrelay.KindHook
	}
	if len(req.Args) == 0 {
		req.Args = []string{"claude-code", "PostToolUse"}
	}
	msg, err := sandboxrelay.EncodeHookRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := LinkRoundTrip(ctx, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", h.link)
	}, run, msg, sandboxrelay.DefaultConnLimits)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	resp, err := sandboxrelay.DecodeHookResponse(out)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (h *bindHarness) executed() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.ran)
}

// bindTree is a workspace repository and another repository beside it.
type bindTree struct{ ws, other string }

func newBindTree(t *testing.T) bindTree {
	t.Helper()
	base := t.TempDir()
	tr := bindTree{ws: filepath.Join(base, "ws"), other: filepath.Join(base, "other")}
	for _, d := range []string{filepath.Join(tr.ws, "sub", ".git"), filepath.Join(tr.other, ".git")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return tr
}

func bindRun(t *testing.T, id string, tr bindTree) RunRecord {
	t.Helper()
	rec, err := NewRunRecord(RunRecord{RunID: id, Tool: "claude-code", ProjectRoot: tr.ws, WorkspaceDir: tr.ws, Roots: []string{tr.ws}})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestBindRefusesForeignWorkingDirectory (P-026 a): a payload that names
// another repository as its working directory, in any spelling a hook
// would decode, is refused with an answer and never reaches the executor.
func TestBindRefusesForeignWorkingDirectory(t *testing.T) {
	tr := newBindTree(t)
	if err := os.Symlink(tr.other, filepath.Join(tr.ws, "link")); err != nil {
		t.Fatal(err)
	}
	run := bindRun(t, "run-a", tr)
	h := startBindHarness(t, &Daemon{}, run)
	for _, tc := range []struct {
		name, payload string
		refused       bool
	}{
		{"own workspace", `{"cwd":"` + tr.ws + `"}`, false},
		{"own subdirectory", `{"cwd":"` + tr.ws + `/sub/"}`, false},
		{"a directory not yet created in the workspace", `{"cwd":"` + tr.ws + `/new/dir"}`, false},
		{"not JSON at all", `plain text`, false},
		{"another repository", `{"cwd":"` + tr.other + `"}`, true},
		{"another repository, key in capitals", `{"CWD":"` + tr.other + `"}`, true},
		{"duplicate spellings, the second foreign", `{"cwd":"` + tr.ws + `","Cwd":"` + tr.other + `"}`, true},
		{"through a link the box planted", `{"cwd":"` + tr.ws + `/link"}`, true},
		{"dot-dot out of the workspace", `{"cwd":"` + tr.ws + `/../other"}`, true},
		{"relative", `{"cwd":"other"}`, true},
		{"a workspace_roots array", `{"workspace_roots":["` + tr.ws + `","` + tr.other + `"]}`, true},
		{"new_cwd of a cd", `{"cwd":"` + tr.ws + `","new_cwd":"/etc"}`, true},
		{"a BOM and trailing garbage", "\xef\xbb\xbf" + `{"cwd":"` + tr.other + `"} trailing`, true},
	} {
		before := h.executed()
		resp := h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(tc.payload)})
		got := resp.Refused == sandboxrelay.RefusedPath
		if got != tc.refused {
			t.Errorf("%s: refused=%q, want refused %v", tc.name, resp.Refused, tc.refused)
		}
		if ran := h.executed() > before; ran == tc.refused {
			t.Errorf("%s: executor ran=%v", tc.name, ran)
		}
	}
}

// TestBindSessions (P-026 a): a box cannot write under a session another
// run spoke for, nor under a session the node records for another project;
// it may resume its own project's session; the per-run cap holds.
func TestBindSessions(t *testing.T) {
	tr := newBindTree(t)
	trB := newBindTree(t)
	runA, runB := bindRun(t, "run-a", tr), bindRun(t, "run-b", trB)
	known := map[string]string{"host-other": tr.other, "host-own": tr.ws + "/sub"}
	d := &Daemon{MaxSessions: 3, SessionOwner: func(_ context.Context, id string) (string, error) {
		if id == "lookup-fails" {
			return "", errors.New("db down")
		}
		return known[id], nil
	}}
	h := startBindHarness(t, d, runA, runB)
	sess := func(run RunRecord, ws, id string) sandboxrelay.Refusal {
		return h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + ws + `","session_id":"` + id + `"}`)}).Refused
	}
	if r := sess(runA, tr.ws, "s1"); r != "" {
		t.Fatalf("a fresh session: %q", r)
	}
	if r := sess(runA, tr.ws, "s1"); r != "" {
		t.Fatalf("the run's own session again: %q", r)
	}
	if r := sess(runB, trB.ws, "s1"); r != sandboxrelay.RefusedSession {
		t.Fatalf("run b spoke for run a's session: %q", r)
	}
	if r := h.send(t, runB, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + trB.ws + `","SessionId":"s1"}`)}).Refused; r != sandboxrelay.RefusedSession {
		t.Fatalf("run b spoke for run a's session under another spelling: %q", r)
	}
	if r := sess(runA, tr.ws, "host-other"); r != sandboxrelay.RefusedSession {
		t.Fatalf("a session the node records for another project: %q", r)
	}
	if r := sess(runA, tr.ws, "lookup-fails"); r != sandboxrelay.RefusedSession {
		t.Fatalf("a failed lookup must refuse: %q", r)
	}
	if r := sess(runA, tr.ws, "host-own"); r != "" {
		t.Fatalf("resuming the run's own project's session: %q", r)
	}
	if r := sess(runA, tr.ws, "s3"); r != "" {
		t.Fatalf("the third session: %q", r)
	}
	if r := sess(runA, tr.ws, "s4"); r != sandboxrelay.RefusedSessionCap {
		t.Fatalf("over the cap: %q", r)
	}
}

// TestBindReplay (P-026 b): the daemon refuses a replayed gate event and
// answers a replayed capture-only one; a launch gate is never replayable.
func TestBindReplay(t *testing.T) {
	tr := newBindTree(t)
	run := bindRun(t, "run-a", tr)
	d := &Daemon{Gated: func(req sandboxrelay.HookRequest) bool { return req.Args[1] == "PreToolUse" }}
	h := startBindHarness(t, d, run)
	if r := h.send(t, run, sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}, Replay: true}); r.Refused != sandboxrelay.RefusedReplay {
		t.Fatalf("a replayed gate event: %q", r.Refused)
	}
	if r := h.send(t, run, sandboxrelay.HookRequest{Args: []string{"claude-code", "PostToolUse"}, Replay: true}); r.Refused != "" {
		t.Fatalf("a replayed capture-only event: %q", r.Refused)
	}
	if st, _ := d.Run("run-a"); st.Replayed.Load() != 1 || st.Bound.Load() != 1 {
		t.Fatalf("replayed %d bound %d", st.Replayed.Load(), st.Bound.Load())
	}
	msg, _ := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{Kind: sandboxrelay.KindLaunchGate, Args: []string{"claude-code"}, Replay: true})
	if _, err := sandboxrelay.DecodeHookRequest(msg, testRules); err == nil {
		t.Fatal("a replayed launch gate decoded")
	}
	// No Gated hook: nothing is replayable.
	h2 := startBindHarness(t, &Daemon{}, run)
	if r := h2.send(t, run, sandboxrelay.HookRequest{Replay: true}); r.Refused != sandboxrelay.RefusedReplay {
		t.Fatalf("without a gate table a replay must be refused: %q", r.Refused)
	}
}

// TestBindRate (P-026 e): one box cannot start host children faster than
// its bucket, by request count or by payload bytes; the bucket refills.
func TestBindRate(t *testing.T) {
	tr := newBindTree(t)
	run := bindRun(t, "run-a", tr)
	now := time.Unix(1000, 0)
	var mu sync.Mutex
	d := &Daemon{Rate: RunRate{Requests: 1, Burst: 2, Bytes: 100, BurstBytes: 150}, Now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}}
	h := startBindHarness(t, d, run)
	small := sandboxrelay.HookRequest{Stdin: []byte("x")}
	for i := range 2 {
		if r := h.send(t, run, small).Refused; r != "" {
			t.Fatalf("request %d inside the burst: %q", i, r)
		}
	}
	if r := h.send(t, run, small).Refused; r != sandboxrelay.RefusedRate {
		t.Fatalf("over the burst: %q", r)
	}
	if h.executed() != 2 {
		t.Fatalf("executor ran %d times", h.executed())
	}
	mu.Lock()
	now = now.Add(2 * time.Second)
	mu.Unlock()
	if r := h.send(t, run, sandboxrelay.HookRequest{Stdin: make([]byte, 200)}).Refused; r != sandboxrelay.RefusedRate {
		t.Fatalf("a payload over the byte burst: %q", r)
	}
	if r := h.send(t, run, small).Refused; r != "" {
		t.Fatalf("after the refill: %q", r)
	}
	st, _ := d.Run("run-a")
	if st.RateLimited.Load() != 2 {
		t.Fatalf("rate limited %d", st.RateLimited.Load())
	}
}

// TestRootsContain: symlinks are resolved on both sides before the check.
func TestRootsContain(t *testing.T) {
	tr := newBindTree(t)
	link := filepath.Join(tr.ws, "out")
	if err := os.Symlink(tr.other, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(tr.ws, "dangling")
	if err := os.Symlink(filepath.Join(tr.other, "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(t.TempDir(), "wslink")
	if err := os.Symlink(tr.ws, rootLink); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		roots []string
		path  string
		want  bool
	}{
		{[]string{tr.ws}, tr.ws, true},
		{[]string{tr.ws}, filepath.Join(tr.ws, "sub"), true},
		{[]string{tr.ws}, filepath.Join(tr.ws, "nope", "deeper"), true},
		{[]string{tr.ws}, link, false},
		{[]string{tr.ws}, filepath.Join(link, "x"), false},
		{[]string{tr.ws}, filepath.Join(dangling, "x"), false},
		{[]string{tr.ws}, tr.other, false},
		{[]string{rootLink}, filepath.Join(tr.ws, "sub"), true},
		{[]string{tr.ws}, "relative", false},
		{nil, tr.ws, false},
	} {
		if got := RootsContain(tc.roots, tc.path); got != tc.want {
			t.Errorf("RootsContain(%v, %q) = %v, want %v", tc.roots, tc.path, got, tc.want)
		}
	}
}

// TestBindSessionReleasedWhenRunEnds (P-032): a session run A spoke for is
// released once run A ends, so run B resuming it is accepted; a session the
// node records under a managed clone of B's project counts as B's project;
// another project's session is still refused.
func TestBindSessionReleasedWhenRunEnds(t *testing.T) {
	tr := newBindTree(t)
	trOther := newBindTree(t)
	clones := t.TempDir()
	cloneA := filepath.Join(clones, "idA", "ws")
	if err := os.MkdirAll(cloneA, 0o700); err != nil {
		t.Fatal(err)
	}
	runA, runB := bindRun(t, "run-a", tr), bindRun(t, "run-b", tr)
	recorded := map[string]string{"in-clone": cloneA, "foreign": trOther.ws}
	d := &Daemon{
		SweepInterval: -1,
		SessionOwner:  func(_ context.Context, id string) (string, error) { return recorded[id], nil },
		CloneOrigin: func(root string) string {
			if root == cloneA {
				return tr.ws
			}
			return ""
		},
	}
	h := startBindHarness(t, d, runA, runB)
	sess := func(run RunRecord, id string) sandboxrelay.Refusal {
		return h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + tr.ws + `","session_id":"` + id + `"}`)}).Refused
	}
	if r := sess(runA, "s1"); r != "" {
		t.Fatalf("run a speaks for s1: %q", r)
	}
	if r := sess(runB, "s1"); r != sandboxrelay.RefusedSession {
		t.Fatalf("run b while run a is live: %q", r)
	}
	// Run A ends: its helper removes the record.
	if err := RemoveRun(h.obs, runA.RunID); err != nil {
		t.Fatal(err)
	}
	if r := sess(runB, "s1"); r != "" {
		t.Fatalf("run b resuming s1 after run a ended: %q", r)
	}
	if _, ok := d.Run(runA.RunID); ok {
		t.Fatal("run a's handler state was not released")
	}
	if r := sess(runB, "in-clone"); r != "" {
		t.Fatalf("a session recorded under a clone of the same project: %q", r)
	}
	if r := sess(runB, "foreign"); r != sandboxrelay.RefusedSession {
		t.Fatalf("another project's session: %q", r)
	}
	// The sweep releases an ended run's claims without any other request.
	runC := bindRun(t, "run-c", tr)
	if err := WriteRun(h.obs, runC); err != nil {
		t.Fatal(err)
	}
	if r := sess(runC, "s9"); r != "" {
		t.Fatalf("run c speaks for s9: %q", r)
	}
	if err := RemoveRun(h.obs, runC.RunID); err != nil {
		t.Fatal(err)
	}
	if n := d.Sweep(); n != 1 {
		t.Fatalf("sweep ended %d runs", n)
	}
	d.mu.Lock()
	_, held := d.sessions["s9"]
	d.mu.Unlock()
	if held {
		t.Fatal("the sweep kept an ended run's session")
	}
}

// TestBindNestedAndSecondaryFields (P-032): the keys a host hook reads a
// file or a session from are bound wherever they sit in the payload, a
// parent session and a transcript included; a tool's own operands are not
// (a tool call may name any path inside the box).
func TestBindNestedAndSecondaryFields(t *testing.T) {
	tr := newBindTree(t)
	state := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	rec, err := NewRunRecord(RunRecord{RunID: "run-n", Tool: "claude-code", ProjectRoot: tr.ws, WorkspaceDir: tr.ws, Roots: []string{tr.ws, state}})
	if err != nil {
		t.Fatal(err)
	}
	other := newBindTree(t)
	recorded := map[string]string{"foreign": other.ws}
	d := &Daemon{SweepInterval: -1, SessionOwner: func(_ context.Context, id string) (string, error) { return recorded[id], nil }}
	h := startBindHarness(t, d, rec)
	own := filepath.Join(state, "projects", "p", "s.jsonl")
	foreign := filepath.Join(other.ws, "s.jsonl")
	deep := `{"a":` + strings.Repeat(`{"a":`, 70) + `1` + strings.Repeat(`}`, 71)
	for _, tc := range []struct {
		name, payload string
		want          sandboxrelay.Refusal
	}{
		{"transcript under the run's state", `{"transcript_path":"` + own + `"}`, ""},
		{"transcript in another repository", `{"transcript_path":"` + foreign + `"}`, sandboxrelay.RefusedPath},
		{"transcript, other spelling", `{"transcriptPath":"/etc/passwd"}`, sandboxrelay.RefusedPath},
		{"agent transcript outside", `{"agent_transcript_path":"` + foreign + `"}`, sandboxrelay.RefusedPath},
		{"agent transcript, camel case", `{"AgentTranscriptPath":"` + foreign + `"}`, sandboxrelay.RefusedPath},
		{"relative transcript", `{"transcript_path":"s.jsonl"}`, sandboxrelay.RefusedPath},
		{"home-relative transcript outside", `{"transcriptPath":"~/.ssh/id_rsa"}`, sandboxrelay.RefusedPath},
		{"parent session of another project", `{"parent_session_id":"foreign"}`, sandboxrelay.RefusedSession},
		{"parent session, camel case", `{"parentSessionId":"foreign"}`, sandboxrelay.RefusedSession},
		{"nested cwd outside", `{"taskStart":{"cwd":"` + other.ws + `"}}`, sandboxrelay.RefusedPath},
		{"cwd in an array of objects", `{"events":[{"cwd":"` + tr.ws + `"},{"cwd":"` + other.ws + `"}]}`, sandboxrelay.RefusedPath},
		{"nested session of another project", `{"meta":{"session":{"session_id":"foreign"}}}`, sandboxrelay.RefusedSession},
		{"nested transcript outside", `{"extra":{"transcript_path":"` + foreign + `"}}`, sandboxrelay.RefusedPath},
		{"a tool operand naming any path", `{"cwd":"` + tr.ws + `","tool_input":{"file_path":"/usr/include/stdio.h","cwd":"/etc","session_id":"foreign"}}`, ""},
		{"a tool response naming any path", `{"tool_response":{"transcript_path":"/etc/passwd"}}`, ""},
		{"nested past the depth bound", deep, sandboxrelay.RefusedPath},
	} {
		before := h.executed()
		resp := h.send(t, rec, sandboxrelay.HookRequest{Stdin: []byte(tc.payload)})
		if resp.Refused != tc.want {
			t.Errorf("%s: refused %q, want %q", tc.name, resp.Refused, tc.want)
		}
		if ran := h.executed() > before; ran != (tc.want == "") {
			t.Errorf("%s: executor ran=%v", tc.name, ran)
		}
	}
}
