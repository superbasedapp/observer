//go:build !sbo_omit_terminals_sandbox_mxc_appcontainer && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox_wslc && !sbo_omit_terminals_sandbox_hcs && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"io"
	"net"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestWindowsRowsRegisteredOptIn: the three rows are registered drivers,
// opt-in like every driver (an install with no [components] block selects
// none), explicit-only beta registry rows.
func TestWindowsRowsRegisteredOptIn(t *testing.T) {
	for id, comp := range map[string]string{
		sandboxbackend.BackendMXCAppContainer: mxcWeakComponent,
		sandboxbackend.BackendWSLC:            wslcComponent,
		sandboxbackend.BackendHCS:             hcsComponent,
	} {
		reg, ok := sandboxDriverRegs[id]
		if !ok || reg.component != comp {
			t.Fatalf("%s: registration %+v", id, reg)
		}
		if governs, active := sandboxDriverOptIn(componentstate.Snapshot{}, comp); !governs || active {
			t.Fatalf("%s: opt-in governs=%v active=%v on a legacy install", comp, governs, active)
		}
		row, _ := sandboxbackend.Get(id)
		if !row.ExplicitOnly || row.Maturity != sandboxbackend.MaturityPreview || len(row.Net.Egress) != 1 || row.Net.Egress[0] != vocab.TierNone {
			t.Fatalf("%s: row %+v", id, row)
		}
	}
}

// TestWindowsRowsProbeAndRefuse: unlisted rows probe nothing; listed off
// Windows they stop at the platform row; every launch is refused by name.
func TestWindowsRowsProbeAndRefuse(t *testing.T) {
	for _, id := range []string{sandboxbackend.BackendMXCAppContainer, sandboxbackend.BackendWSLC, sandboxbackend.BackendHCS} {
		r := &sandboxRuntime{cfg: config.TerminalSandboxConfig{Enabled: true, Backends: []string{"bwrap"}}}
		d := sandboxDriverRegs[id].build(r, config.Config{})
		if p := d.probe(context.Background()); p.Verdict != sandboxselect.VerdictDisabledByConfig {
			t.Fatalf("%s unlisted: %+v", id, p)
		}
		r.cfg.Backends = []string{id}
		p := d.probe(context.Background())
		if runtime.GOOS != "windows" && p.Verdict == sandboxselect.VerdictAvailable {
			t.Fatalf("%s listed off Windows: %+v", id, p)
		}
		if _, err := d.Create(context.Background(), termsvc.PrepareRequest{}); err == nil || !strings.Contains(err.Error(), "not built in this release") {
			t.Fatalf("%s: launch = %v", id, err)
		}
	}
}

// TestMXCWeakJudge: the org pin keeps a node off the weaker tier, the DACL
// tier is refused, and an offered appcontainer-bfs tier is reported but
// probe-only.
func TestMXCWeakJudge(t *testing.T) {
	bfs := sandboxmxc.ProbeResult{Tier: sandboxmxc.TierAppContainerBFS, Version: "1.0.1", Verdict: sandboxmxc.Verdict{Code: sandboxmxc.VerdictPSECUnavailable}}
	if p := mxcWeakJudge(sandboxmxc.PinProcessContainer, bfs); p.Verdict != sandboxselect.VerdictBackendNotAllowed {
		t.Fatalf("pinned: %+v", p)
	}
	if p := mxcWeakJudge("", sandboxmxc.ProbeResult{Tier: sandboxmxc.TierAppContainerDACL}); p.Verdict != sandboxmxc.VerdictPSECUnavailable || !strings.Contains(p.Reason, "ACL") {
		t.Fatalf("dacl: %+v", p)
	}
	if p := mxcWeakJudge("", sandboxmxc.ProbeResult{Tier: sandboxmxc.TierBaseContainer}); p.Verdict != sandboxmxc.VerdictPSECUnavailable {
		t.Fatalf("base-container on the weak row: %+v", p)
	}
	if p := mxcWeakJudge("", bfs); p.Verdict != sandboxselect.VerdictBackendVersionUntested || !strings.Contains(p.Reason, "appcontainer-bfs") {
		t.Fatalf("bfs: %+v", p)
	}
	noTier := sandboxmxc.ProbeResult{Verdict: sandboxmxc.Verdict{Code: sandboxmxc.VerdictUnsupportedPlatform, Reason: "not windows"}}
	if p := mxcWeakJudge("", noTier); p.Verdict != sandboxmxc.VerdictUnsupportedPlatform {
		t.Fatalf("no tier: %+v", p)
	}
}

// TestWSLCRelayOverFakeStdio: the home side of the run's relay over a fake
// exec stdio (a pipe standing in for wslc exec's stdin and stdout): the
// none tier opens the capture relay and nothing else.
func TestWSLCRelayOverFakeStdio(t *testing.T) {
	hostEnd, guestEnd := net.Pipe()
	secret := []byte(strings.Repeat("s", 32))
	dial := func(context.Context, string) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		go func() { _, _ = io.Copy(b, b); _ = b.Close() }()
		return a, nil
	}
	type res struct {
		h   *relaymux.Host
		err error
	}
	ch := make(chan res, 1)
	go func() {
		h, err := wslcServeRelay(context.Background(), hostEnd, "run-wslc-1", secret, vocab.TierNone, dial)
		ch <- res{h, err}
	}()
	g, err := relaymux.DialGuest(context.Background(), wslcMuxConn(guestEnd), relaymux.Options{RunID: "run-wslc-1", Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer func() { r.h.Close(); g.Close() }()
	c, err := g.Connect(context.Background(), relaymux.KindRelay)
	if err != nil {
		t.Fatalf("relay stream: %v", err)
	}
	if _, err := c.Write([]byte("hook")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "hook" {
		t.Fatalf("relay echo %q %v", b, err)
	}
	if _, err := g.Connect(context.Background(), relaymux.KindProxy); err == nil {
		t.Fatal("the none tier opened the model proxy")
	}
}

// TestMXCTierPinWired (R-034, replacing audit F7's unwired check): the
// windows.mxc_tier floor is read from [terminal.sandbox.windows] (where
// config.Load applies an organization pin), the old unwired field stays
// gone, and the judge refuses the AppContainer row under process_container.
func TestMXCTierPinWired(t *testing.T) {
	if _, ok := reflect.TypeOf(config.TerminalSandboxConfig{}).FieldByName("MXCAppContainer"); ok {
		t.Fatal("the unwired MXCAppContainer pin field is back; the floor lives in [terminal.sandbox.windows]")
	}
	for _, c := range []struct {
		tier    string
		refused bool
	}{
		{"", false},
		{"appcontainer", false},
		{"process_container", true},
	} {
		cfg := config.TerminalSandboxConfig{Windows: config.TerminalSandboxWindowsConfig{MXCTier: c.tier}}
		p := mxcWeakJudge(mxcTierPinInForce(cfg), sandboxmxc.ProbeResult{Tier: sandboxmxc.TierAppContainerBFS})
		if got := p.Verdict == sandboxselect.VerdictBackendNotAllowed; got != c.refused {
			t.Errorf("mxc_tier %q: verdict %q (%s), want refused %v", c.tier, p.Verdict, p.Reason, c.refused)
		}
	}
}
