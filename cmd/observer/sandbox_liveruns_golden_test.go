package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The goldens in testdata/liveruns_goldens are the output of the PRE-LANE
// binary (built at a4acb0d73, the base of lane SBX-UPD) with its own daemon
// running and no sandboxed run live, in a fresh HOME whose config sets only
// the database path, hooks auto-register off, the proxy port and the
// dashboard address: `observer service restart` (no observer unit on that
// host, so systemctl fails the same way for both), `observer update apply`
// (an unenrolled node), and `observer components remove terminals.sandbox
// --yes`, `add` and `remove --json` in that order. The merged binary run the
// same way, with its daemon running and nothing live, printed every file
// byte for byte (stdout, stderr and exit status), which is the "byte
// identical with no live run" claim of lane SBX-UPD made real (audit
// milestone "goldens"). These tests pin the part an in-process run can
// reproduce: stdout of the service restart and of the components change,
// with the daemon answering zero live runs, and stdout of the update apply
// against a real dashboard route and update runtime
// (sandbox_liveruns_golden_update_test.go).

func readLiveRunGolden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "liveruns_goldens", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestNoLiveRunGoldensServiceRestart: with a running daemon and nothing live,
// `observer service restart` prints what the pre-lane binary printed.
func TestNoLiveRunGoldensServiceRestart(t *testing.T) {
	stubServiceRestart(t, &fakeLiveClient{answered: true, drainAfter: -1})
	cmd := newServiceRestartCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	// Not nil: nil makes cobra read the test binary's own os.Args.
	cmd.SetArgs([]string{})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if want := readLiveRunGolden(t, "service-restart.stdout"); out.String() != want {
		t.Fatalf("stdout = %q, want the pre-lane %q", out.String(), want)
	}
}

// TestNoLiveRunGoldensComponentsRemove: with a running daemon and nothing
// live, `observer components remove terminals.sandbox --yes` and then `add`
// print what the pre-lane binary printed.
func TestNoLiveRunGoldensComponentsRemove(t *testing.T) {
	requireComponents(t, "terminals.sandbox", "terminals.sandbox.apple-container", "terminals.sandbox.e2b",
		"terminals.sandbox.landlock", "terminals.sandbox.modal", "terminals.sandbox.mxc", "terminals.sandbox.oci",
		"terminals.sandbox.seatbelt", "terminals.sandbox.vercel")
	home := t.TempDir()
	setTestHome(t, home)
	cfgPath := filepath.Join(home, ".observer", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(home, ".observer", "observer.db")) + "\"\n\n" +
		"[observer.hooks]\nauto_register = false\n\n[proxy]\nport = 18820\n\n[dashboard]\naddr = \"127.0.0.1:18781\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := newDaemonLiveRunsClient
	t.Cleanup(func() { newDaemonLiveRunsClient = saved })
	fc := &fakeLiveClient{answered: true, drainAfter: -1}
	newDaemonLiveRunsClient = func(string) daemonLiveRunsClient { return fc.client() }
	for _, step := range []struct{ verb, golden string }{{"remove", "components-remove.stdout"}, {"add", "components-add.stdout"}} {
		cmd := newComponentsChangeCmd(step.verb, step.verb, false)
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs([]string{"terminals.sandbox", "--yes", "--config", cfgPath})
		cmd.SetContext(context.Background())
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%s: %v", step.verb, err)
		}
		if want := readLiveRunGolden(t, step.golden); out.String() != want || errOut.Len() != 0 {
			t.Fatalf("%s stdout = %q (stderr %q), want the pre-lane %q", step.verb, out.String(), errOut.String(), want)
		}
	}
	if fc.queries == 0 {
		t.Fatal("the daemon was never asked, so the golden proves nothing")
	}
}
