package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/govern/sidecar"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// orgLockNode is a managed node directory staged for the audit's a3b chain
// and the a1 local weakening: config.toml with [guard] off, the daemon's key,
// posture and MAC'd org lock, a cached org bundle, and a migrated database.
type orgLockNode struct {
	dir, cfgPath, dbPath, bundlePath string
	env                              string
}

// orgLockBundleTOML is any valid org bundle: on a managed node the bundle's
// mere presence locks every rule.
const orgLockBundleTOML = "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\n"

func newOrgLockNode(t *testing.T, managed bool) orgLockNode {
	t.Helper()
	dir := t.TempDir()
	n := orgLockNode{
		dir:        dir,
		cfgPath:    filepath.Join(dir, "config.toml"),
		dbPath:     filepath.Join(dir, "observer.db"),
		bundlePath: filepath.Join(dir, "org-policy-bundle.json"),
	}
	// a1: the developer switched the guard off locally.
	writeFileT(t, n.cfgPath, fmt.Sprintf(
		"[observer]\ndb_path = %q\n[guard]\nenabled = false\nmode = \"off\"\n[guard.rules]\norg_bundle = %q\n",
		filepath.ToSlash(n.dbPath), filepath.ToSlash(n.bundlePath)))
	sign, pin := bundleSigner(t)
	n.env = sign(29, orgLockBundleTOML)
	writeFileT(t, n.bundlePath, n.env)

	key, err := guardposture.LoadOrCreateKey(guardposture.KeyPath(n.cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	p := enforcedPosture
	p.OrgLock, p.WrittenAt = true, time.Now()
	// The tenancy anchor a daemon of this release records (T-864).
	p.Managed, p.TenancyRecorded = managed, true
	if _, err := guardposture.Write(guardposture.PosturePath(n.cfgPath), p, key); err != nil {
		t.Fatal(err)
	}
	lock := guardposture.OrgLock{
		Managed:    managed,
		Floor:      guardposture.DeriveFloor(guardposture.FloorInputs{Managed: managed, OrgLayer: true, Pinned: map[string]any{"guard.mode": "enforce"}}),
		KeyPinHash: pin, Bundle: n.env, BundleExpected: true, WrittenAt: time.Now(),
	}
	if _, err := guardposture.WriteOrgLock(guardposture.OrgLockPath(n.cfgPath), lock, key); err != nil {
		t.Fatal(err)
	}
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: n.dbPath})
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	return n
}

// breakBundle is the audit's b2: edit the bundle body, keep its version (the
// signature no longer verifies).
func (n orgLockNode) breakBundle(t *testing.T) {
	t.Helper()
	tampered := strings.Replace(n.env, "R-110", "R-111", 1)
	if tampered == n.env {
		t.Fatal("breakBundle: no change")
	}
	writeFileT(t, n.bundlePath, tampered)
}

// deleteBundle is the re-test's b1 (T-864 gap 1): delete the cached org
// bundle.
func (n orgLockNode) deleteBundle(t *testing.T) {
	t.Helper()
	if err := os.Remove(n.bundlePath); err != nil {
		t.Fatal(err)
	}
}

// deleteBundleAndLock deletes the cached bundle AND the daemon's MAC'd org
// lock, the last verified copy the bundle falls back to (T-864 gap 1, the
// "both deleted" case).
func (n orgLockNode) deleteBundleAndLock(t *testing.T) {
	t.Helper()
	n.deleteBundle(t)
	if err := os.Remove(guardposture.OrgLockPath(n.cfgPath)); err != nil {
		t.Fatal(err)
	}
}

// bundleTampers are the org-bundle tamper shapes every chain test runs:
// the audit's b2 (edit), the re-test's b1 (delete) and the delete of both the
// bundle and the org lock. On a managed node each must leave the org's
// locked rules locked.
var bundleTampers = []struct {
	name  string
	apply func(n orgLockNode, t *testing.T)
}{
	{"edited bundle", orgLockNode.breakBundle},
	{"deleted bundle", orgLockNode.deleteBundle},
	{"deleted bundle and org lock", orgLockNode.deleteBundleAndLock},
}

// approveEverything is the developer's self-exception for every catalog
// rule, written straight into the register the way an approval made before
// the tamper (or by any path that bypasses the CLI gate) sits there.
func (n orgLockNode) approveEverything(t *testing.T) {
	t.Helper()
	d, err := db.Open(context.Background(), db.Options{Path: n.dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	st := store.New(d)
	for _, info := range policy.Catalog() {
		if _, err := st.InsertGuardApproval(context.Background(), store.GuardApprovalRow{
			TS: time.Now().UTC(), RuleID: info.ID, Scope: "global", GrantedBy: "dev1",
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestA3bChainClaudeCodePreToolUse pins audit row a3b (and the re-test's b1,
// T-864 gap 1) through the real Claude Code PreToolUse receiver: break or
// delete the bundle (and, in the last shape, the org lock too), self-approve
// R-101 (the CLI refuses; a register row written anyway is inert), and
// `rm -rf /` is still denied, with the local [guard] switched off (a1)
// floored by the org lock. The individual-node control rows keep full local
// control.
func TestA3bChainClaudeCodePreToolUse(t *testing.T) {
	type chainCase struct {
		name     string
		managed  bool
		wantDeny bool
		tamper   func(n orgLockNode, t *testing.T)
	}
	var cases []chainCase
	for _, bt := range bundleTampers {
		cases = append(cases,
			chainCase{"managed node, " + bt.name + ": denied", true, true, bt.apply},
			chainCase{"individual node, " + bt.name + ": local control stands", false, false, bt.apply})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := newOrgLockNode(t, tc.managed)
			tc.tamper(n, t)
			out, err := runGuardCmd(t, "approve", "R-101", "--global", "--config", n.cfgPath)
			if tc.managed && (err == nil || !strings.Contains(err.Error(), "locked by org policy")) {
				t.Fatalf("self-approval on a managed node with a broken bundle = %q, %v; want refused", out, err)
			}
			n.approveEverything(t)

			body := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`
			h := newFailureHarness(t, resolveHookFailurePlan("claude-code", "pre-tool", n.cfgPath))
			var errBuf bytes.Buffer
			handleClaudeCodePreTool(strings.NewReader(body), &h.stdout, &errBuf, "claude-code:pre-tool", n.cfgPath)
			got := h.stdout.String()
			denied := strings.Contains(got, `"permissionDecision":"deny"`)
			if denied != tc.wantDeny {
				t.Fatalf("PreToolUse reply = %q (stderr %s), want deny=%v", got, errBuf.String(), tc.wantDeny)
			}
		})
	}
}

// TestOrgLockFloorsEveryToolGateMechanism is the registry-driven half
// (D-678: every adapter, not just Claude Code and Codex): for EVERY wired
// tool gate the registry serves, on a managed node whose developer switched
// the guard off, broke the org bundle and approved every rule, the real
// receiver still answers the destructive fixture with the dialect's block.
// The verdict path is shared (runToolGate -> config.Load floor ->
// buildHookGuard -> last verified org layer -> applyApprovals org lock), so
// a new vendor row is covered here with no edit to this test.
func TestOrgLockFloorsEveryToolGateMechanism(t *testing.T) {
	for _, g := range servedToolGates(t) {
		for _, bt := range bundleTampers {
			t.Run(g.tool+" "+g.b.NativeEvent+" "+bt.name, func(t *testing.T) {
				if g.b.NativeEvent == "pre_mcp_tool_use" {
					t.Skip("no builtin rule blocks an MCP call (TestToolGateReceiversAnswerEndToEnd skips it too)")
				}
				n := newOrgLockNode(t, true)
				bt.apply(n, t)
				n.approveEverything(t)
				body := toolGateE2EFixture(g.tool, g.b.NativeEvent, g.b.Dialect, n.dir)
				h := newFailureHarness(t, resolveHookFailurePlan(g.tool, g.b.NativeEvent, n.cfgPath))
				driveToolGateReceiver(t, g.tool, g.b.NativeEvent, body, n.cfgPath)
				out := h.stdout.String()
				if fc, _ := hook.BuildFailClosedReply(g.b.Dialect, "x"); fc.ExitCode != 0 {
					if codes := h.exitCodes(); out != "" || len(codes) == 0 || codes[0] != fc.ExitCode {
						t.Fatalf("stdout %q exits %v, want exit %d", out, codes, fc.ExitCode)
					}
					return
				}
				if !toolGateBlockWords.MatchString(out) {
					t.Fatalf("stdout %q, want the dialect's block", out)
				}
			})
		}
	}
}

// TestHookMechanismsWithoutAToolGate lists the registry rows that have a hook
// mechanism but no wired tool gate: their hooks never consult the guard
// before a tool runs, so the floor and the fail-closed org layer reach them
// only through the watcher's post-hoc verdicts. The list is logged for the
// hand-back, and every one of them must still have an observe path (no row
// may silently have neither).
func TestHookMechanismsWithoutAToolGate(t *testing.T) {
	var noGate []string
	for _, c := range integration.Capabilities() {
		if c.Hook.Mechanism == integration.HookNone {
			continue
		}
		gated := false
		for _, b := range c.Hook.Bindings {
			if b.Cap == integration.HookCapToolGate && b.Wired {
				gated = true
			}
		}
		if !gated {
			noGate = append(noGate, c.Tool+" ("+string(c.Hook.Mechanism)+")")
		}
	}
	t.Logf("hook mechanisms with no wired tool gate (guard reaches them post-hoc only): %s", strings.Join(noGate, ", "))
}

// TestGovernanceCopyRepairsAStripLoop pins T-845 on the daemon side: the
// governance file stripped on disk is restored from the verified copy and
// reported, and a forged exceptions file is removed.
func TestGovernanceCopyRepairsAStripLoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.GovernanceSidecarFilename)
	c := newGovernanceCopy(path)
	file := sidecar.File{Schema: 1, State: "applied", EffectiveHash: "h1", Pinned: map[string]any{"guard.mode": "enforce"}}
	c.write(func() ([]byte, []byte, bool) {
		raw, err := writeGovernanceSidecar(path, file)
		return raw, nil, err == nil
	})
	if repaired := c.repair(); len(repaired) != 0 {
		t.Fatalf("a clean file was repaired: %v", repaired)
	}
	for i := 0; i < 3; i++ {
		writeFileT(t, path, `{"schema":1,"state":"applied","effective_hash":"h1"}`)
		writeFileT(t, sidecar.ExceptionsPath(path), `{"schema":1,"effective_hash":"h1","exceptions":{"guard.mode":{"grant_id":1,"until":"2099-01-01T00:00:00Z"}}}`)
		repaired := c.repair()
		if len(repaired) != 2 {
			t.Fatalf("round %d: repaired %v, want the sidecar and the forged exceptions file", i, repaired)
		}
		disk, _ := os.ReadFile(path)
		if f, _ := sidecar.ReadBytes(disk, time.Now()); f == nil || f.Pinned["guard.mode"] != "enforce" {
			t.Fatalf("round %d: sidecar after repair = %s", i, disk)
		}
		if _, err := os.Stat(sidecar.ExceptionsPath(path)); !os.IsNotExist(err) {
			t.Fatalf("round %d: the forged exceptions file survived", i)
		}
	}
}

// TestGuardPostureWriterRepairsTheOrgLock: the lock is rewritten and reported
// when it is edited or deleted, like the posture.
func TestGuardPostureWriterRepairsTheOrgLock(t *testing.T) {
	cp := filepath.Join(t.TempDir(), "config.toml")
	w := &guardPostureWriter{}
	if _, err := w.publish(cp, guardposture.Posture{OrgLock: true, WrittenAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	lock := guardposture.OrgLock{Managed: true, Floor: guardposture.GuardFloor{Enabled: true, Mode: "enforce"}, WrittenAt: time.Now()}
	if changed, err := w.publishLock(cp, lock); err != nil || !changed {
		t.Fatalf("first lock publish = %v, %v", changed, err)
	}
	if changed, _ := w.publishLock(cp, lock); changed {
		t.Fatal("an unchanged lock was rewritten")
	}
	if err := os.Remove(guardposture.OrgLockPath(cp)); err != nil {
		t.Fatal(err)
	}
	if ld := guardposture.LoadOrgLock(cp); ld.State != guardposture.OrgLockTampered {
		t.Fatalf("deleted lock reads %v, want tampered (the posture anchors it)", ld.State)
	}
	if changed, err := w.publishLock(cp, lock); err != nil || !changed {
		t.Fatalf("repair publish = %v, %v", changed, err)
	}
	if ld := guardposture.LoadOrgLock(cp); ld.State != guardposture.OrgLockValid || !ld.Lock.Managed {
		t.Fatalf("after repair: %v %s", ld.State, ld.Detail)
	}
	got := w.takeExtraTampers()
	if len(got) != 1 || got[0].kind != tamperOrgLock {
		t.Fatalf("tampers = %+v, want one org lock tamper", got)
	}
	v := tamperVerdict(got[0], time.Now())
	if v.Verdict.Severity != policy.SeverityHigh || v.DegradedFrom != tamperOrgLock || !v.GuardError {
		t.Fatalf("tamper verdict = %+v", v)
	}
}

// TestGuardStatusShowsTheFloor: `observer guard status` names every local
// setting the organization's floor overrides (D-672: visible locally).
func TestGuardStatusShowsTheFloor(t *testing.T) {
	n := newOrgLockNode(t, true)
	out, err := runGuardCmd(t, "status", "--config", n.cfgPath)
	if err != nil {
		t.Fatalf("guard status: %v\n%s", err, out)
	}
	for _, want := range []string{"Org lock:     managed node", "OVERRIDDEN:   guard.enabled: local false, organization floor true", "OVERRIDDEN:   guard.mode: local off, organization floor enforce", "Guard:        on"} {
		if !strings.Contains(out, want) {
			t.Errorf("guard status missing %q:\n%s", want, out)
		}
	}
	n.breakBundle(t)
	out, _ = runGuardCmd(t, "status", "--config", n.cfgPath)
	if !strings.Contains(out, "enforcing the last verified org layer") {
		t.Errorf("guard status does not name the broken bundle:\n%s", out)
	}
}

// pluginShellTool is the native shell tool name a plugin host reports
// (TestPluginToolGateDialects' vocabulary); unlisted hosts use "bash".
var pluginShellTool = map[string]string{"hermes": "terminal", "command-code": "Bash"}

// TestOrgLockFloorsEveryPluginMechanism is the plugin-dialect half of the
// registry-driven proof: every wired tool gate the plugin receiver serves
// (TS plugin shims, the Hermes Python plugin, Command Code Mods) goes
// through the full `observer hook <tool> <event>` entry and is still
// blocked on a managed node with the guard switched off locally, the org
// bundle broken and every rule self-approved.
func TestOrgLockFloorsEveryPluginMechanism(t *testing.T) {
	setTestHome(t, t.TempDir())
	seen := 0
	for _, c := range integration.Capabilities() {
		for _, b := range c.Hook.Bindings {
			if b.Cap != integration.HookCapToolGate || !b.Wired || b.Dialect != hook.PluginDialectToolGate {
				continue
			}
			seen++
			for _, bt := range bundleTampers {
				t.Run(c.Tool+" "+b.NativeEvent+" "+bt.name, func(t *testing.T) {
					n := newOrgLockNode(t, true)
					bt.apply(n, t)
					n.approveEverything(t)
					native := pluginShellTool[c.Tool]
					if native == "" {
						native = "bash"
					}
					body := fmt.Sprintf(`{"host":%q,"event":%q,"session_id":"s1","cwd":"/tmp/proj","pid":4242,"tool_name":%q,"tool_input":{"command":"rm -rf ~/"},"call_id":"c1"}`,
						c.Tool, b.NativeEvent, native)
					out, _ := runPluginHook(t, c.Tool, b.NativeEvent, n.cfgPath, body)
					if r := pluginReplyOf(t, out); r.Decision != "deny" {
						t.Fatalf("decision = %q (%s), want deny", r.Decision, out)
					}
				})
			}
		}
	}
	if seen == 0 {
		t.Fatal("the registry has no wired plugin tool gate; this test no longer covers anything")
	}
}
