//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// sandbox_live_apply.go is the ONE seam through which a local
// [terminal.sandbox] write takes effect in a running daemon without a
// restart. The daemon holds the sandbox config for launches in the
// sandboxHolder (terminal_sandbox.go), which rebuilds its runtime when the
// config file's stamp moves, and the capture relay waits for the sandbox to
// be switched on (sandbox_relay.go). Both also follow processSandboxLocal: a
// bump makes the holder rebuild on its next probe or launch whatever the file
// stamp says, and wakes the relay's wait so it reads the config again.
//
// Writers reach it in one of three ways, never another:
//
//   - in the daemon, the setup service's ApplyLive (the Settings > Sandbox
//     isolation save calls it after its write, and the setup route's Enable
//     and its undo call it after theirs);
//   - in a CLI process, setup asks the running daemon over loopback with
//     POST /api/terminal/sandbox/setup/<backend>/apply, which calls the
//     daemon's ApplyLive;
//   - with no daemon listening there is nothing to apply: the next start
//     reads the file.

// sandboxApplySignal is a change counter with a wake channel (the shape of
// the managed overlay's own generation, sandbox_managed.go).
type sandboxApplySignal struct {
	gen    atomic.Uint64
	waitMu sync.Mutex
	wait   chan struct{}
}

// generation reports the signal's change counter.
func (s *sandboxApplySignal) generation() uint64 { return s.gen.Load() }

// bump moves the generation and wakes every waiter.
func (s *sandboxApplySignal) bump() {
	s.gen.Add(1)
	s.waitMu.Lock()
	if s.wait != nil {
		close(s.wait)
		s.wait = nil
	}
	s.waitMu.Unlock()
}

// changed returns a channel closed on the next generation move. A waiter
// takes it BEFORE reading the state it guards, so no move is missed.
func (s *sandboxApplySignal) changed() <-chan struct{} {
	s.waitMu.Lock()
	defer s.waitMu.Unlock()
	if s.wait == nil {
		s.wait = make(chan struct{})
	}
	return s.wait
}

// processSandboxLocal is this process's local-apply signal.
var processSandboxLocal = &sandboxApplySignal{}

// sandboxLocalChanged reports whether the local-apply signal moved since
// *seen, and records the current generation.
func sandboxLocalChanged(seen *uint64) bool {
	g := processSandboxLocal.generation()
	if *seen == g {
		return false
	}
	*seen = g
	return true
}

// applySandboxConfigLive makes this process's sandbox seams read
// [terminal.sandbox] again now, and drops every cached probe (the drivers'
// caches outlive a runtime rebuild).
func applySandboxConfigLive() {
	dropSandboxProbeCache()
	processSandboxLocal.bump()
}

// sandboxProbeRefreshFor is how a setup record that settled reaches the
// daemon's sandbox probe: the daemon (the dashboard surface) drops its own
// probe cache; a CLI asks the running daemon through the same apply route
// Enable uses, so the next GET /api/terminal/sandbox reads the host again.
func sandboxProbeRefreshFor(surface, configPath string) func(ctx context.Context, backend string) string {
	if surface == "dashboard" {
		return func(context.Context, string) string {
			dropSandboxProbeCache()
			return sandboxLiveApplied
		}
	}
	return sandboxLiveApplyFor(surface, configPath)
}

// ApplyLive implements dashapi.SandboxSetupLiveApplier: this process's
// sandbox seams read [terminal.sandbox] again now.
func (s *sandboxSetupService) ApplyLive(context.Context) { applySandboxConfigLive() }

// The closed outcomes of a live apply after a setup step wrote
// [terminal.sandbox].
const (
	// sandboxLiveApplied: this process is the daemon and applied it.
	sandboxLiveApplied = "applied"
	// sandboxLiveDaemonApplied: the running daemon was asked and applied it.
	sandboxLiveDaemonApplied = "daemon_applied"
	// sandboxLiveNoDaemon: no daemon listens; the next start reads the file.
	sandboxLiveNoDaemon = "no_daemon"
	// sandboxLiveNoAnswer: a daemon listens but did not confirm the apply.
	sandboxLiveNoAnswer = "no_answer"
)

// sandboxLiveApplyNotes is what a step says after each outcome ("": nothing
// to say, the change is in force or no daemon runs to hold it). The one case
// that still needs a restart is a daemon that did not confirm.
var sandboxLiveApplyNotes = map[string]string{
	sandboxLiveApplied:       "",
	sandboxLiveDaemonApplied: "",
	sandboxLiveNoDaemon:      "",
	sandboxLiveNoAnswer:      "The running Observer did not confirm it picked this change up, so it may need a restart to use it: run `observer service restart` when Observer runs as a service, otherwise stop `observer start` and run it again.",
}

// The double-submit pair the setup routes require (the dashboard's
// requireJSONConfirm): the same fresh value as cookie and header.
const (
	setupApplyConfirmCookie = "sb_remote_confirm"
	setupApplyConfirmHeader = "X-Observer-Confirm" //nolint:gosec // G101: a header name, not a credential
)

// sandboxLiveApplyFor is the live apply of a setup service on surface: the
// dashboard runs in the daemon and applies in-process; any other surface (the
// CLI) asks the daemon at configPath's dashboard address.
func sandboxLiveApplyFor(surface, configPath string) func(ctx context.Context, backend string) string {
	if surface == "dashboard" {
		return func(context.Context, string) string {
			applySandboxConfigLive()
			return sandboxLiveApplied
		}
	}
	return func(ctx context.Context, backend string) string {
		// Only the daemon serving this config's database applies it
		// (daemon_handoff.go, L-125): another one would re-read its own
		// config and the CLI would report an apply that did not happen here.
		t := resolveDaemonHandoff(ctx, configPath)
		switch {
		case t.Use:
		case t.Match == dashapi.DBUnknown:
			// Something listens that may be this database's daemon but
			// cannot be confirmed: it is not asked, so it may need a restart.
			return sandboxLiveNoAnswer
		default:
			return sandboxLiveNoDaemon
		}
		return askDaemonSandboxApplyFor(ctx, t.Base+"/api/terminal/sandbox/setup/"+url.PathEscape(backend)+"/apply", t.DBIdentity)
	}
}

// askDaemonSandboxApply asks the daemon at u to apply [terminal.sandbox]
// now: refused means no daemon, {"applied": true} means applied, anything
// else means it did not confirm.
func askDaemonSandboxApply(ctx context.Context, u string) string {
	return askDaemonSandboxApplyFor(ctx, u, "")
}

// askDaemonSandboxApplyFor is askDaemonSandboxApply naming this CLI's
// database (dbIdentity, "" = none): a daemon serving another one refuses,
// which reads as no daemon for this database.
func askDaemonSandboxApplyFor(ctx context.Context, u, dbIdentity string) string {
	ctx, cancel := context.WithTimeout(ctx, liveRunsDaemonTimeout)
	defer cancel()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return sandboxLiveNoAnswer
	}
	token := hex.EncodeToString(b)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader("{}")) //nolint:gosec // G704: false positive; u is this node's own dashboard address from its config, never input
	if err != nil {
		return sandboxLiveNoAnswer
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(setupApplyConfirmHeader, token)
	req.AddCookie(&http.Cookie{Name: setupApplyConfirmCookie, Value: token}) //nolint:gosec // G124: a request cookie (the double-submit half), not one this process sets
	daemonTarget{DBIdentity: dbIdentity}.setDBIdentity(req)
	resp, err := (&http.Client{Timeout: liveRunsDaemonTimeout}).Do(req) //nolint:gosec // G704: false positive; the request to the node's own dashboard built above
	if err != nil {
		if isConnRefused(err) {
			return sandboxLiveNoDaemon
		}
		return sandboxLiveNoAnswer
	}
	defer func() { _ = resp.Body.Close() }()
	if isDBIdentityRefusal(resp, dbIdentity) {
		return sandboxLiveNoDaemon
	}
	var body struct {
		Applied bool `json:"applied"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body) != nil || !body.Applied {
		return sandboxLiveNoAnswer
	}
	return sandboxLiveDaemonApplied
}
