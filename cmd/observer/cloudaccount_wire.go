package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
)

// cloudaccount_wire.go is the ONE seam between the node dashboard and the
// Cloud Intelligence account lane (operator directive 2026-09-03: "the sign-in
// button on the local dashboard should be there somewhere prominent").
//
// It injects three plain funcs into dashboard.Options.CloudAccount:
//
//   - the sign-in PROBE — the same local keychain read `observer cloud status`
//     does (cloudgateway.WorkOSSignInPresent / APITokenPresent /
//     CredentialBackend), plus whether a WorkOS client id resolves. No network.
//   - the RUNNER — spawns `<self> cloud <verb> <args...> [--config <path>]` as
//     a SUBPROCESS, exactly the way cloudautosync.go spawns `cloud sync`. The
//     daemon links nothing new from the cloud network lane: the child is the
//     consent-gated CLI a human types (login/logout/sync plus, since the
//     session-card buttons arc, preview/consent/delete-account), and it
//     inherits the daemon's environment (WORKOS_CLIENT_ID, SBO_CLOUD_BASE_URL,
//     the OS keychain) and reads the same config file, so
//     `[cloud].workos_client_id` resolves in the child through
//     resolveWorkOSClientID like a manual run.
//   - the GRANTABLE PROBE — cloudGrantableProbe, a pure lookup over
//     internal/cloudgateway's purpose-rule table (StandingGrantable + LaneFor),
//     the same one cloudconsent.go's cloudPrintGrantableHelp reads, so
//     GET /api/cloud/consent/grants can say which purposes are standing-
//     grantable without the dashboard package importing cloudgateway itself.
//
// The dashboard package itself stays import-clean (it sees only these funcs;
// tests/invariant/cloud_egress_test.go keeps pinning the daemon packages).

// cloudAccountProbeTTL bounds how often the status poll re-opens the credential
// store: the dashboard polls /api/cloud/status every 15s and the header chip
// every 30s, and a keychain probe per poll is pointless churn. The runner
// invalidates the cache after every login/logout so a fresh sign-in shows on
// the very next poll.
const cloudAccountProbeTTL = 5 * time.Second

// cloudAccountWire owns the probe cache. One instance per dashboard server.
type cloudAccountWire struct {
	configPath string
	spawn      cloudCommandSpawner

	mu       sync.Mutex
	cached   dashboard.CloudSignInState
	cachedAt time.Time
	cacheErr error
}

// cloudCommandSpawner runs one `observer cloud <verb>` with its combined output
// streamed to out. Injectable so tests exercise the wire without a process.
type cloudCommandSpawner func(ctx context.Context, argv []string, out io.Writer) error

// newCloudAccountSeams builds the dashboard seams for the daemon (`observer
// start`) and the standalone `observer dashboard` command.
func newCloudAccountSeams(configPath string) *dashboard.CloudAccountSeams {
	w := &cloudAccountWire{configPath: configPath, spawn: defaultCloudCommandSpawner}
	return dashboard.NewCloudAccountSeams(w.probe, w.run, cloudGrantableProbe)
}

// cloudCommandArgs composes the child argv for a verb: `cloud <verb>` plus the
// verb's own args (verbatim — cobra accepts flags after subcommand tokens)
// plus the config path LAST when one is set, mirroring defaultCloudSyncSpawner
// and how a human would type `observer cloud consent grant --purpose p --yes
// --config x`.
func cloudCommandArgs(verb string, args []string, configPath string) []string {
	out := make([]string, 0, len(args)+4)
	out = append(out, "cloud", verb)
	out = append(out, args...)
	if configPath != "" {
		out = append(out, "--config", configPath)
	}
	return out
}

// cloudGrantableProbe implements dashboard.CloudGrantableProbe: it reports
// every FEATURE-lane purpose's standing-grant eligibility, mirroring
// cloudconsent.go's cloudPrintGrantableHelp exactly (same skip of the
// bootstrap lane, same two calls into internal/cloudgateway's purpose-rule
// table). It is a pure lookup over cloudcontract's closed purpose vocabulary —
// no config, no I/O — so it needs no receiver on cloudAccountWire.
func cloudGrantableProbe() []dashboard.CloudGrantable {
	var out []dashboard.CloudGrantable
	for _, p := range cloudcontract.AllPurposes() {
		if lane, ok := cloudgateway.LaneFor(p); !ok || lane == cloudgateway.LaneBootstrap {
			continue
		}
		ok, reason := cloudgateway.StandingGrantable(p)
		out = append(out, dashboard.CloudGrantable{Purpose: string(p), OK: ok, Reason: reason})
	}
	return out
}

// defaultCloudCommandSpawner self-execs the running binary. Stdout and stderr
// both go to out so the login state machine sees the authorize URL and any
// error line; ctx bounds the child (a timeout or daemon shutdown kills it).
func defaultCloudCommandSpawner(ctx context.Context, argv []string, out io.Writer) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve observer binary: %w", err)
	}
	cmd := exec.CommandContext(ctx, self, argv...) //nolint:gosec // G204: argv is a fixed `cloud <verb> [--config <path>]` composed by cloudCommandArgs from the daemon's own config path, never request input.
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

// probe reports the local sign-in state, cached for cloudAccountProbeTTL.
func (w *cloudAccountWire) probe() (dashboard.CloudSignInState, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.cachedAt.IsZero() && time.Since(w.cachedAt) < cloudAccountProbeTTL {
		return w.cached, w.cacheErr
	}
	st, err := probeCloudSignIn(w.configPath)
	w.cached, w.cacheErr, w.cachedAt = st, err, time.Now()
	return st, err
}

// probeCloudSignIn is the uncached read: load config (so a client id saved
// from the dashboard a moment ago counts), resolve the same cloud host as the
// login subprocess, and read its scoped credentials. Gateway construction and
// presence checks are local; providing the host does not make a network call.
func probeCloudSignIn(configPath string) (dashboard.CloudSignInState, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return dashboard.CloudSignInState{}, fmt.Errorf("load config: %w", err)
	}
	gw, err := openCloudGateway(cfg, resolveCloudBaseURL("", cfg), "", nil, nil)
	if err != nil {
		return dashboard.CloudSignInState{}, err
	}
	return dashboard.CloudSignInState{
		APITokenPresent:     gw.APITokenPresent(),
		WorkOSSignInPresent: gw.WorkOSSignInPresent(),
		CredentialBackend:   gw.CredentialBackend(),
		ClientIDConfigured:  resolveWorkOSClientID(cfg) != "",
	}, nil
}

// run spawns `observer cloud <verb> <args...>` and drops the probe cache
// afterwards so the next status poll reflects the new credential state
// immediately — this covers every verb the dashboard spawns (login, logout,
// sync, preview, consent, delete-account included), so a change that flips
// local sign-in state (delete-account's local clear, same as login/logout) is
// always picked up on the next poll without a special case per verb.
func (w *cloudAccountWire) run(ctx context.Context, verb string, args []string, out io.Writer) error {
	err := w.spawn(ctx, cloudCommandArgs(verb, args, w.configPath), out)
	w.mu.Lock()
	w.cachedAt = time.Time{}
	w.mu.Unlock()
	return err
}
