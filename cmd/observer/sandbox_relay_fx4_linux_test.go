//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// fx4A1Home is a test home holding this machine's Claude Code login and a
// private session transcript: what a hosted box must never reach.
func fx4A1Home(t *testing.T) string {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	setTestHome(t, home)
	if err := os.MkdirAll(filepath.Join(home, ".claude", "projects", "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	login := `{"hasCompletedOnboarding":true,"oauthAccount":{"emailAddress":"dev@example.com","displayName":"Dev","accountUuid":"acct-sentinel-0000"}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(login), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "projects", "a", "b.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// TestRemoteRunRecordRootsAreTheRunsOwn (FX4-A1): a hosted (remote-box)
// run's record lists the run's directory and its mapped host directories
// only, never this machine's tool state (~/.claude, ~/.claude.json and its
// backup), and says RemoteBox; a local sandbox run keeps its StateRW roots
// exactly as before.
func TestRemoteRunRecordRootsAreTheRunsOwn(t *testing.T) {
	home := fx4A1Home(t)
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	obs := relayShortDir(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run := termsvc.SandboxRun{ID: "AbCdEfGhIjKlMnOpQrStUw", Tool: "claude-code", Dir: dir, ProjectRoot: dir}
	quar := hostedQuarantineDir(obs, run.ID)
	pm := hostedPathMap(hostedPathInput{vendor: v, runDir: dir, quarantine: quar, stateRel: []string{".claude"}})
	if err := (&sandboxRuntime{observerDir: obs}).writeRemoteRunRecord(run, pm); err != nil {
		t.Fatal(err)
	}
	rec, err := sandboxrelayd.ReadRun(obs, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{dir, filepath.Join(quar, "0")}; !slices.Equal(rec.Roots, want) || !rec.RemoteBox || rec.HomeIsThisMachines() {
		t.Fatalf("remote record roots %v remote %v, want %v and remote", rec.Roots, rec.RemoteBox, want)
	}
	for _, p := range []string{".claude/projects/a/b.jsonl", ".claude.json", ".claude.json.backup"} {
		if sandboxrelayd.RootsContain(rec.Roots, filepath.Join(home, p)) {
			t.Errorf("this machine's %s is a read root of a hosted run", p)
		}
	}
	// A local sandbox run: unchanged.
	local := termsvc.SandboxRun{ID: "LocalRunAAAAAAAAAAAAAA", Tool: "claude-code", Dir: dir, ProjectRoot: dir}
	if err := (&sandboxRuntime{observerDir: obs}).writeRunRecord(local); err != nil {
		t.Fatal(err)
	}
	lrec, err := sandboxrelayd.ReadRun(obs, local.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{dir, filepath.Join(home, ".claude"), filepath.Join(home, ".claude.json"), filepath.Join(home, ".claude.json.backup")}
	if !slices.Equal(lrec.Roots, want) || lrec.RemoteBox || !lrec.HomeIsThisMachines() {
		t.Fatalf("local record roots %v remote %v, want %v", lrec.Roots, lrec.RemoteBox, want)
	}
}

// startRecordHarness is startRelayHarness over a given record.
func startRecordHarness(t *testing.T, bin string, rec sandboxrelayd.RunRecord) *relayHarness {
	t.Helper()
	h := &relayHarness{obs: relayShortDir(t), rec: rec}
	h.cfg = writeRelayConfig(t, h.obs, "")
	if err := sandboxrelayd.WriteRun(h.obs, rec); err != nil {
		t.Fatal(err)
	}
	h.link = filepath.Join(h.obs, "link.sock")
	ln, err := net.Listen("unix", h.link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.daemon = &sandboxrelayd.Daemon{ObserverDir: h.obs, Exec: relayExecutor(h.cfg, bin), Rules: relayRules, Peer: sandboxrelayd.PeerSameUser}
	go func() { _ = h.daemon.Serve(ctx, ln) }()
	return h
}

// TestCraftedPayloadCannotReadThisMachinesLogin (FX4-A1, end to end through
// the real relay daemon, executor and observer binary): a process in a
// hosted box pipes a PreToolUse payload whose transcript_path is
// ~/.claude/projects/a/b.jsonl into the in-box hook. On the hosted record it
// is refused path_outside_run and no tool-account observation is written, so
// this machine's ~/.claude.json login never reaches the org run's session.
// Under the binding, the run's confined reader cannot open the login from
// the hosted record's roots, while a local record's roots can (the read the
// leak needed): the control that the reader check has teeth.
func TestCraftedPayloadCannotReadThisMachinesLogin(t *testing.T) {
	bin := probeHookTestBinary(t)
	fx4A1Home(t)
	ws, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	payload := []byte(`{"session_id":"sess-crafted","hook_event_name":"PreToolUse","cwd":"` + v.BoxWorkspace + `","transcript_path":"~/.claude/projects/a/b.jsonl","tool_name":"Bash","tool_use_id":"toolu_crafted","tool_input":{"command":"true"}}`)
	args := []string{"claude-code", "PreToolUse"}

	obs := relayShortDir(t)
	run := termsvc.SandboxRun{ID: "RemoteRunAAAAAAAAAAAAA", Tool: "claude-code", Dir: ws, ProjectRoot: ws}
	pm := hostedPathMap(hostedPathInput{vendor: v, runDir: ws, quarantine: hostedQuarantineDir(obs, run.ID), stateRel: []string{".claude"}})
	if err := (&sandboxRuntime{observerDir: obs}).writeRemoteRunRecord(run, pm); err != nil {
		t.Fatal(err)
	}
	remote, err := sandboxrelayd.ReadRun(obs, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	h := startRecordHarness(t, bin, remote)
	resp, err := h.relayed(t, sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: args, Cwd: v.BoxWorkspace, Stdin: payload})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Refused != sandboxrelay.RefusedPath {
		t.Fatalf("the crafted payload on a hosted record: %+v, want path_outside_run", resp)
	}
	if n := tableCounts(t, filepath.Join(h.obs, "observer.db")); n["tool_account_observations"] != 0 {
		t.Fatalf("a tool-account observation was written: %v", n)
	}

	// The second barrier, under the binding: the run's confined reader (the
	// relay child's hookctx Files) cannot open this machine's login from a
	// hosted record's roots, while a local record's roots, which list this
	// machine's tool state, can (the read the leak needed).
	home := os.Getenv("HOME")
	private := filepath.Join(home, ".claude", "projects", "a", "b.jsonl")
	for _, p := range []string{filepath.Join(home, ".claude.json"), private} {
		if _, err := sandboxrelayd.ConfinedFiles(remote.Roots).ReadFile(p); err == nil {
			t.Errorf("the hosted record's confined reader opened this machine's %s", p)
		}
	}
	local := []string{ws, filepath.Join(home, ".claude"), filepath.Join(home, ".claude.json")}
	if _, err := sandboxrelayd.ConfinedFiles(local).ReadFile(private); err != nil {
		t.Errorf("control: a local record's reader cannot open a private transcript (%v), so the check above proves nothing", err)
	}
}

// TestHostedPathClassesEveryVendor (FX4-A7): the agent-state class applies
// to every hosted row with a box home (E2B, Modal, Vercel, Daytona and the
// org's gateway), not only the org's: each maps the tool's state dir in its own
// box home onto the run's quarantine, where the transcript pull copies the
// same file, and leaves the rest of the box home (the home itself, its other
// dot files, the tool's login file) unmapped, so the binding refuses it.
func TestHostedPathClassesEveryVendor(t *testing.T) {
	for _, row := range []struct {
		id, home string
	}{
		{sandboxremote.VendorE2B, "/home/user"},
		{sandboxremote.VendorModal, "/root"},
		{sandboxremote.VendorVercel, "/vercel/sandbox"},
		{sandboxremote.VendorOpenShellOrg, "/home/sandbox"},
		{sandboxremote.VendorDockerSandboxes, "/root"},
		{sandboxremote.VendorInstaBox, "/data/home"},
		{sandboxremote.VendorDaytona, "/home/daytona"},
	} {
		t.Run(row.id, func(t *testing.T) {
			v, ok := sandboxremote.VendorFor(row.id)
			if !ok || v.BoxHome != row.home {
				t.Fatalf("vendor %s: found %v, box home %q, want %q", row.id, ok, v.BoxHome, row.home)
			}
			dir := t.TempDir()
			quar := hostedQuarantineDir(relayShortDir(t), "AbCdEfGhIjKlMnOpQrStUw")
			pm := hostedPathMap(hostedPathInput{vendor: v, runDir: dir, quarantine: quar, stateRel: []string{".claude"}})
			state := sandboxrelayd.PathPrefix{Box: row.home + "/.claude", Host: filepath.Join(quar, "0")}
			if !slices.Contains(pm, state) {
				t.Fatalf("path map %+v has no agent-state row %+v", pm, state)
			}
			if v.BoxWorkspace != "" && !slices.Contains(pm, sandboxrelayd.PathPrefix{Box: v.BoxWorkspace, Host: dir}) {
				t.Fatalf("path map %+v has no workspace row", pm)
			}
			box := row.home + "/.claude/projects/-w/s.jsonl"
			items, _ := sandboxremote.PlanPull([]string{row.home + "/.claude"}, []sandboxremote.BoxFile{{Path: box, Size: 10, Regular: true}}, sandboxremote.PullLimits{})
			mapped, ok := sandboxrelayd.MapBoxPath(pm, box)
			if len(items) != 1 || !ok || mapped != filepath.Join(quar, filepath.FromSlash(items[0].LocalRel)) {
				t.Fatalf("the map (%q %v) and the pull (%+v) disagree", mapped, ok, items)
			}
			for _, p := range []string{row.home, row.home + "/.ssh/id_ed25519", row.home + "/.claude.json", row.home + "/.claudex/x"} {
				if m, ok := sandboxrelayd.MapBoxPath(pm, p); ok && !strings.HasPrefix(m, dir) {
					t.Errorf("%s maps to %s", p, m)
				}
			}
		})
	}
}

// TestHostedSeedApprovesTheRunSentinel (FX4 fix round 1, F-P6B-2a): Claude
// Code asked "use this API key?" (No preselected) on every interactive
// start in a hosted box, for the run's sentinel in ANTHROPIC_API_KEY; a
// member who pressed Enter ran without the relayed key. The seed now
// approves the run's sentinel (its last 20 characters, the tool's record)
// in a fresh box, and merges the approval into a state file the box already
// has (a resume: each run's sentinel is new), keeping every other key. A
// real key in the variable is never approved (its suffix would be written).
func TestHostedSeedApprovesTheRunSentinel(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	sentinel, err := sandboxcred.MintSentinel(rand.Reader, "anthropic")
	if err != nil {
		t.Fatal(err)
	}
	suffix := sentinel[len(sentinel)-20:]
	run := func(t *testing.T, keyValue string, existing []byte) (seed string, after []byte, said string) {
		t.Helper()
		oldEnv, oldIs := hostedCredEnvHook, hostedCredIsSentinelHook
		hostedCredEnvHook = func(_ hostedPlanFile, env map[string]string) { env["ANTHROPIC_API_KEY"] = keyValue }
		hostedCredIsSentinelHook = sandboxcred.IsSentinel
		t.Cleanup(func() { hostedCredEnvHook, hostedCredIsSentinelHook = oldEnv, oldIs })
		v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
		c := newFakeBoxClient()
		info, err := c.Create(context.Background(), sandboxremote.BoxSpec{})
		if err != nil {
			t.Fatal(err)
		}
		lay := v.Layout(t.TempDir())
		dst := path.Join(lay.Home, ".claude.json")
		if existing != nil {
			c.boxes[info.ID].files[dst] = existing
		}
		c.execs = func(_ *fakeBox, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
			if len(spec.Argv) == 6 && spec.Argv[2] == hostedSeedStateScript {
				seed = spec.Argv[5]
			}
			return newFakeProcess("", 0), nil
		}
		var out strings.Builder
		r := &hostedRun{plan: hostedPlanFile{RunID: "RunSeedAAAAAAAAAAAAAAA", Provider: v.ID, Tool: "claude-code"}, client: c, layout: lay, vendor: v, now: time.Now, t: hostedTerm{out: &out}}
		r.rec.VendorID = info.ID
		r.seedToolState(context.Background())
		return seed, c.boxes[info.ID].files[dst], out.String()
	}
	approves := func(doc []byte) bool {
		var d struct {
			R struct {
				Approved []string `json:"approved"`
				Rejected []string `json:"rejected"`
			} `json:"customApiKeyResponses"`
		}
		return json.Unmarshal(doc, &d) == nil && slices.Contains(d.R.Approved, suffix) && !slices.Contains(d.R.Rejected, suffix)
	}

	t.Run("fresh box", func(t *testing.T) {
		seed, _, _ := run(t, sentinel, nil)
		if !approves([]byte(seed)) || !strings.Contains(seed, `"hasCompletedOnboarding":true`) {
			t.Fatalf("the seed does not approve the run's sentinel: %s", seed)
		}
	})
	t.Run("a box with its own state (resume)", func(t *testing.T) {
		own := []byte(`{"hasCompletedOnboarding":true,"projects":{"/sandbox/workspace":{"allowedTools":[]}},"customApiKeyResponses":{"approved":["olderrunsentinelxxx1"],"rejected":["` + suffix + `"]}}`)
		_, after, said := run(t, sentinel, own)
		if !approves(after) {
			t.Fatalf("the box's state does not approve the run's sentinel: %s (%s)", after, said)
		}
		if !strings.Contains(string(after), `"projects":{"/sandbox/workspace"`) || !strings.Contains(string(after), "olderrunsentinelxxx1") {
			t.Fatalf("the merge dropped the box's own keys: %s", after)
		}
	})
	// FX4-R3: a state file over hostedStateFileCap is said, never merged
	// silently, and left as it is.
	t.Run("a state file over the cap", func(t *testing.T) {
		big := []byte(`{"hasCompletedOnboarding":true,"pad":"` + strings.Repeat("x", hostedStateFileCap) + `"}`)
		_, after, said := run(t, sentinel, big)
		if !strings.Contains(said, "API key question was not pre-answered") || !strings.Contains(said, "could not be read") {
			t.Fatalf("an oversized state file was not said: %q", said)
		}
		if string(after) != string(big) {
			t.Fatal("an oversized state file was rewritten")
		}
	})
	t.Run("a real key is never approved", func(t *testing.T) {
		seed, after, _ := run(t, "sk-ant-api03-REALKEYREALKEYREALKEYREALKEY", []byte(`{"hasCompletedOnboarding":true}`))
		if strings.Contains(seed, "customApiKeyResponses") || strings.Contains(string(after), "customApiKeyResponses") || strings.Contains(seed, "REALKEY") {
			t.Fatalf("a real key's suffix was written: seed %s, box %s", seed, after)
		}
	})
}
