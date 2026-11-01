//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_hosted_live2_host_test.go pins the fixes from the second
// live run of the hosted rows (2026-10-23, at faf43c28a).

// TestHostedHostGivesTheWorkspaceToTheBoxUser (finding F-A: on Vercel the
// workspace was uid 0 while its files and .git were uid 1000, git refused
// the repository and no diff came home): the box user's uid:gid is read
// from a non-root exec, the setup gives the run's directories to it, and
// after the uploads (a vendor's write may leave a directory root-owned) the
// whole workspace and binary directory are given back, as root and without
// following a link, before the baseline repository is made. On every row.
func TestHostedHostGivesTheWorkspaceToTheBoxUser(t *testing.T) {
	for _, vendor := range []string{sandboxremote.VendorE2B, sandboxremote.VendorModal, sandboxremote.VendorVercel} {
		t.Run(vendor, func(t *testing.T) {
			hh := newHostedHarness(t, vendor)
			code := make(chan int, 1)
			go func() { code <- hh.run.drive(context.Background()) }()
			waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return len(hh.ptys) > 0 })
			if c := hostedEndRun(t, hh, code); c != 5 {
				t.Errorf("exit %d, output %s", c, hh.out.String())
			}
			hh.client.mu.Lock()
			calls := append([]string(nil), hh.client.calls...)
			hh.client.mu.Unlock()
			at := func(pred func(string) bool) int { return slices.IndexFunc(calls, pred) }
			setup := at(func(c string) bool { return strings.Contains(c, "mkdir -p") })
			write := at(func(c string) bool { return c == "write" })
			own := at(func(c string) bool { return strings.Contains(c, "chown -R -h") })
			base := at(func(c string) bool { return strings.Contains(c, "observer-baseline") })
			if setup < 0 || write < 0 || own < 0 || base < 0 || !(setup < write && write < own && own < base) {
				t.Fatalf("order setup %d write %d own %d baseline %d: %v", setup, write, own, base, calls)
			}
			hh.mu.Lock()
			specs := append([]sandboxremote.ExecSpec(nil), hh.specs...)
			hh.mu.Unlock()
			var probed, setupOK, ownOK bool
			for _, s := range specs {
				if len(s.Argv) < 3 || s.Argv[0] != "sh" {
					continue
				}
				if s.Argv[2] == hostedBoxOwnerProbe {
					probed = !s.AsRoot
				}
				if len(s.Argv) < 5 {
					continue
				}
				switch s.Argv[2] {
				case hostedBoxSetupScript:
					setupOK = s.AsRoot && s.Argv[4] == "1000:1000" && slices.Contains(s.Argv, hh.run.plan.Root)
				case hostedBoxOwnScript:
					ownOK = s.AsRoot && s.Argv[4] == "1000:1000" && slices.Contains(s.Argv, hh.run.plan.Root)
				}
			}
			if !probed || !setupOK || !ownOK {
				t.Errorf("owner probe as the box user %v, setup %v, own %v", probed, setupOK, ownOK)
			}
		})
	}
}

// hostedDiffHarness is a harness whose run has a box, for calling one step.
func hostedDiffHarness(t *testing.T) *hostedHarness {
	t.Helper()
	hh := newHostedHarness(t, sandboxremote.VendorVercel)
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorVercel)
	hh.run.vendor, hh.run.client, hh.run.layout = v, hh.client, v.Layout(hh.run.plan.Root)
	info, err := hh.client.Create(context.Background(), sandboxremote.BoxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	hh.run.rec = sandboxremote.NewIntent("run-h1", v.ID, v.DefaultEndpoint, v.Regions.Default, "run-h1", time.Now(), time.Hour)
	hh.run.rec.VendorID, hh.run.rec.State = info.ID, sandboxremote.StateRunning
	return hh
}

// TestHostedHostSaysWhenTheDiffIsNotSaved (finding F-A: a failed diff pull
// was dropped silently): every way the box's changes fail to come home is
// said on the terminal and kept on the run record; a box that changed
// nothing says so, and is not a failure.
func TestHostedHostSaysWhenTheDiffIsNotSaved(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(hh *hostedHarness)
		want string
	}{
		{"no git", func(hh *hostedHarness) { hh.stageCode = hostedStageNoGit }, "the box has no git"},
		{"git add refused", func(hh *hostedHarness) {
			hh.stageCode, hh.stageOut = 128, "fatal: detected dubious ownership in repository at '/w'\n"
		}, "git add exited 128: fatal: detected dubious ownership"},
		{"staged diff refused", func(hh *hostedHarness) {
			hh.diffCode, hh.diffOut = 125, "Not a git repository\n"
		}, "the staged diff exited 125: Not a git repository"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hh := hostedDiffHarness(t)
			tc.set(hh)
			hh.run.saveStagedDiff(context.Background())
			out := hh.out.String()
			if !strings.Contains(out, "NOT saved as a diff") || !strings.Contains(out, tc.want) {
				t.Errorf("terminal %q lacks %q", out, tc.want)
			}
			recs := hostedLoadRecords(hh.run.plan.ObserverDir)
			if len(recs) != 1 || !strings.Contains(recs[0].DiffError, tc.want) {
				t.Errorf("run record %+v lacks %q", recs, tc.want)
			}
		})
	}
	hh := hostedDiffHarness(t)
	hh.run.saveStagedDiff(context.Background())
	if out := hh.out.String(); !strings.Contains(out, "unchanged") || strings.Contains(out, "NOT saved") {
		t.Errorf("an unchanged workspace: %q", out)
	}
	if recs := hostedLoadRecords(hh.run.plan.ObserverDir); len(recs) != 0 {
		t.Errorf("a record was written for an unchanged workspace: %+v", recs)
	}
}

// TestHostedHostFailedDiffSaidAtTeardown: the whole run says it too.
func TestHostedHostFailedDiffSaidAtTeardown(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorVercel)
	hh.diffCode, hh.diffOut = 125, "Not a git repository\n"
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return len(hh.ptys) > 0 })
	hostedEndRun(t, hh, code)
	if out := hh.out.String(); !strings.Contains(out, "NOT saved as a diff (the staged diff exited 125") {
		t.Errorf("output %s", out)
	}
}

// TestHostedRelayedProxyNamesTheRun (finding N5: relayed api_turns rows had
// no session): the home side passes each relayed model request to the
// proxy socket with the run named in sandboxremote.RelayRunHeader, a value
// the box sent replaced; with no proxy socket the stream is refused as
// before.
func TestHostedRelayedProxyNamesTheRun(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	ctx := context.Background()
	if _, err := hh.run.dialHome(ctx, relaymux.KindProxy); err == nil {
		t.Fatal("a model stream was opened with no proxy socket")
	}
	ln, err := net.Listen("unix", filepath.Join(hh.run.h.SockDir, sandbox.ProxySocketName))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan []string, 4)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		seen <- r.Header.Values(sandboxremote.RelayRunHeader)
		_, _ = w.Write([]byte("ok"))
	}), ReadHeaderTimeout: time.Minute}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	c, err := hh.run.dialHome(ctx, relaymux.KindProxy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	for i := 0; i < 2; i++ {
		req := "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:8820\r\n" + sandboxremote.RelayRunHeader + ": another-run\r\nContent-Length: 2\r\n\r\n{}"
		go func() { _, _ = c.Write([]byte(req)) }()
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Fatalf("request %d: %d %q", i, resp.StatusCode, body)
		}
		select {
		case v := <-seen:
			if len(v) != 1 || v[0] != "run-h1" {
				t.Errorf("request %d: the proxy saw run %v, want [run-h1]", i, v)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the proxy saw no request")
		}
	}
}

// TestHostedAgentEnvNamesTheTier (finding N2): the agent's environment
// carries the box's tier, which the in-box launcher reads for its notice.
func TestHostedAgentEnvNamesTheTier(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	hh.run.layout = v.Layout(hh.run.plan.Root)
	for _, tier := range []string{"none", "proxy_only", "internet"} {
		hh.run.plan.Tier = tier
		if got := hh.run.agentEnv()[sandbox.EnvEgress]; got != tier {
			t.Errorf("tier %s: env %q", tier, got)
		}
		if fwd := hostedForwardsProxy(vocab.Tier(tier)); fwd == (tier == "none") {
			t.Errorf("tier %s: forwards the proxy %v", tier, fwd)
		}
	}
}
