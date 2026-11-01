//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_oci_p3c_test.go is lane SBX-P3C's walk against the
// fakes: one image pull by digest under a manifest signed with a test key,
// one consented first-start install followed by the agent's run on the
// cache, and one clone-remote return, each step's user-visible line checked.
func TestP3CWalk(t *testing.T) {
	// 1. The default image, pulled by its signed digest and read back.
	f := newP3CFake(t)
	store, tr, d := installTestImage(t)
	trust := ociResolveImage(config.TerminalSandboxOCIConfig{}, store, tr)
	f.pullStream = p3cPullStream(d.Digest)
	f.onPull[d.Ref()] = p3cDefaultImageInspect(d)
	c, err := ociEngineClient(f.sock, "1.52")
	if err != nil {
		t.Fatal(err)
	}
	obs := t.TempDir()
	var said []string
	if _, _, err := ociPullDefault(context.Background(), c, trust, obs, func(l string) { said = append(said, l) }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(said, "\n"), "pulled "+d.Ref()+" (42.0 MB)") {
		t.Fatalf("the pull said %q", said)
	}

	// 2. A consented first-start install, then the agent on the cache.
	tt := p3cInteractiveTerm()
	plan := p3cInstallPlan(t, f)
	done := make(chan int, 1)
	go func() {
		done <- driveOCIRun(context.Background(), plan, []string{"/usr/bin/observer", "tool-a"}, nil, tt.term)
	}()
	tt.waitFor(t, "Install it now? [y/N] ")
	_, _ = tt.inW.Write([]byte("yes\n"))
	tt.waitFor(t, "@vendor/tool-a@2.1.309 installed into "+plan.Install.Volume)
	tt.waitFor(t, "agent$ ")
	_, _ = tt.inW.Write([]byte("exit\n"))
	select {
	case code := <-done:
		if code != 42 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the run never ended")
	}

	// 3. A clone-remote return, said on the run's terminal.
	req, git, _ := remoteReturnFixture(t)
	_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("two\n"), 0o600)
	git(req.CopyDir, "add", "b.txt")
	git(req.CopyDir, "commit", "-qm", "two")
	rt := newOCITestTerm()
	ociReturn(context.Background(), req, nil, rt.term)
	ref := workspace.ReturnRefPrefix + req.RunID
	for _, want := range []string{"the return repository " + req.SourceRepo, workspace.ReturnFetchCommand(req.SourceRepo, ref), "nothing was pushed", "the copy is kept at " + req.CopyDir} {
		if !strings.Contains(rt.out.String(), want) {
			t.Fatalf("the return line does not say %q: %q", want, rt.out.String())
		}
	}
}
