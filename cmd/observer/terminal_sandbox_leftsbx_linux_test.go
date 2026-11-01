//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestHostedCopyRecordReadsInBox (lane LEFT-SBX milestone 2, inventory
// L-08): a hosted run's workspace is always a copy. The run record the
// hosted Attach writes (writeRunRecord, the same function every row calls),
// the box record the home side's host services derive from it, and the
// bytes the in-box relay end writes into the box's own socket dir
// (writeGuestRecord, what relaymux's hello carries) chain to a box record
// the in-box hook reads (sandboxrelayd.ReadBoxRecord), with the copy
// delivery and the run id intact. Added as the check the inventory asked
// for; it passes, so no fix was needed.
func TestHostedCopyRecordReadsInBox(t *testing.T) {
	obs := relayShortDir(t)
	r := &sandboxRuntime{observerDir: obs}
	run := termsvc.SandboxRun{ID: "AbCdEfGhIjKlMnOpQrStUv", Tool: "claude-code", Dir: filepath.Join(t.TempDir(), "copy"), ProjectRoot: t.TempDir(), Copy: true}
	if err := r.writeRunRecord(run); err != nil {
		t.Fatal(err)
	}
	rec, err := sandboxrelayd.ReadRun(obs, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Delivery != sandboxrelayd.DeliveryCopy || rec.CopyHostPath != run.Dir {
		t.Fatalf("run record delivery %q copy %q", rec.Delivery, rec.CopyHostPath)
	}
	home := filepath.Join(relayShortDir(t), "s")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteBoxRecord(home, rec); err != nil {
		t.Fatal(err)
	}
	carried, err := os.ReadFile(filepath.Join(home, sandboxrelayd.BoxRecordName))
	if err != nil {
		t.Fatal(err)
	}
	box := filepath.Join(relayShortDir(t), "box")
	if err := os.Mkdir(box, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(box, sandboxrelayd.BoxRecordName)
	if err := writeGuestRecord(p, carried); err != nil {
		t.Fatal(err)
	}
	got, present, err := sandboxrelayd.ReadBoxRecord(p)
	if err != nil || !present {
		t.Fatalf("the in-box hook cannot read the hosted copy's box record: present %v, %v", present, err)
	}
	if got.Delivery != sandboxrelayd.DeliveryCopy || got.RunID != run.ID {
		t.Fatalf("in-box record: delivery %q run %q", got.Delivery, got.RunID)
	}
}

// TestSandboxAgentEgressHosts (lane LEFT-SBX, the agent-run allow-list): a
// run's gateway reads the host list from the daemon config its run record
// names; with a list only those hosts pass (no literal IP), with an org pin
// that left nothing in common nothing passes, and with no list the tier's
// own behaviour stands (nil rules). An unreadable record refuses (fail
// closed); a run with no relay keeps the old behaviour.
func TestSandboxAgentEgressHosts(t *testing.T) {
	if r, err := agentEgressRules(config.TerminalSandboxConfig{}); r != nil || err != nil {
		t.Fatalf("no list: %v %v", r, err)
	}
	r, err := agentEgressRules(config.TerminalSandboxConfig{EgressAllowHosts: []string{"registry.npmjs.org", "*.github.com"}})
	if err != nil {
		t.Fatal(err)
	}
	for host, ok := range map[string]bool{"registry.npmjs.org": true, "api.github.com": true, "github.com": false, "evil.example.com": false, "140.82.112.3": false} {
		if (r.Check(host) == "") != ok {
			t.Errorf("%s: allowed %v, want %v", host, r.Check(host) == "", ok)
		}
	}
	none, _ := agentEgressRules(config.TerminalSandboxConfig{PinnedNoEgressHost: "terminal.sandbox.egress_allow_hosts"})
	if none == nil || none.Check("registry.npmjs.org") == "" {
		t.Fatal("an emptied org pin did not refuse every host")
	}

	obs := relayShortDir(t)
	cfgPath := writeRelayConfig(t, obs, "[terminal.sandbox]\negress = \"internet\"\negress_allow_hosts = [\"registry.npmjs.org\"]\n")
	prevPath := daemonConfigPathSetting.Load()
	daemonConfigPathSetting.Store(&cfgPath)
	t.Cleanup(func() { daemonConfigPathSetting.Store(prevPath) })
	rr := &sandboxRuntime{observerDir: obs}
	run := termsvc.SandboxRun{ID: "AbCdEfGhIjKlMnOpQrStUv", Tool: "claude-code", Dir: t.TempDir()}
	if err := rr.writeRunRecord(run); err != nil {
		t.Fatal(err)
	}
	got, err := sandboxAgentEgressRules(obs, run.ID)
	if err != nil || got == nil || got.Check("registry.npmjs.org") != "" || got.Check("pypi.org") == "" {
		t.Fatalf("from the run record: %v %v", got, err)
	}
	if _, err := sandboxAgentEgressRules(obs, "NoSuchRunNoSuchRunNoSu"); err == nil {
		t.Fatal("a missing run record did not refuse")
	}
	if got, err := sandboxAgentEgressRules("", ""); got != nil || err != nil {
		t.Fatalf("no relay: %v %v", got, err)
	}
}
