package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
)

// otelLoopComponent is the catalog component the in-sandbox receiver
// belongs to: it is the OTLP receiver (internal/ingest/otlp) on a sandbox
// loopback port, so it runs only while that component is active.
const otelLoopComponent = "ingest.otlp"

// otelLoopRefused is the component gate of `otel-receiver ensure|serve`:
// nil while ingest.otlp is active for configPath, else it prints the
// component state's refusal line and returns the refusal exit code (3), the
// same answer the CLI verb gate gives an inactive component's verb. The
// `cloud-session` verb itself is core, so the verb gate never reaches here.
func otelLoopRefused(cmd *cobra.Command, configPath string) error {
	snap := componentSnapshotFor(configPath)
	if snap.Active(otelLoopComponent) {
		return nil
	}
	fmt.Fprintln(cmd.ErrOrStderr(), snap.RefusalLine(otelLoopComponent))
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	if r := cmd.Root(); r != nil {
		r.SilenceErrors = true
	}
	return exitErr(componentstate.RefusalExitCode)
}

// cloudsession_otelloop.go is the in-sandbox loopback OTLP receiver of
// `observer cloud-session` (cloud-agents lane CA-C7, part 2): the
// `otel-receiver ensure|serve` verbs the committed hooks run inside the
// vendor's VM, and the one helper `cloud-session init --otel-loopback` calls.
// The receiver half (serve) lives in cloudsession_otelloop_serve.go, beside
// the vendor OTLP ingest it reuses, with an off side for builds without
// ingest.otlp. Nothing here dials anything but the loopback address it is
// given (the egress-lane invariant is unchanged), and nothing runs outside a
// cloud sandbox: ensure checks the agent's cloud marker before doing
// anything but the component gate (otelLoopRefused, which only reads the
// config). While ingest.otlp is inactive serve refuses with exit 3, and
// ensure (a non-gate hook) prints the same refusal line and exits 0.

// Bounds of the ensure verb and the receiver's lifetime.
const (
	// otelLoopProbeTimeout bounds one "is it listening" connect.
	otelLoopProbeTimeout = 300 * time.Millisecond
	// otelLoopStartWait is how long ensure waits for a fresh receiver to
	// accept connections before it reports and returns (the hook's own
	// timeout is cloudsession.OTelLoopbackHookTimeoutSeconds).
	otelLoopStartWait = 5 * time.Second
	// otelLoopDefaultIdle stops a receiver that saw no export for this long.
	// The prompt hook re-ensures it, so an idle exit loses nothing.
	otelLoopDefaultIdle = 2 * time.Hour
	// otelLoopMaxLifetime stops a receiver regardless, so a forgotten one
	// never outlives a sandbox's working day.
	otelLoopMaxLifetime = 24 * time.Hour
)

// applyOTelLoopback is the ONE call `cloud-session init` makes for this
// lane: with the option off the plan is returned untouched (byte-identical
// files), with it on cloudsession.AddOTelLoopback adds the ensure hooks and
// the cloud-environment step.
func applyOTelLoopback(plan cloudsession.RepoPlan, opts cloudsession.PlanOptions, enabled bool, addr string) (cloudsession.RepoPlan, error) {
	if !enabled {
		return plan, nil
	}
	return cloudsession.AddOTelLoopback(plan, opts, addr)
}

// newCloudSessionOTelReceiverCmd is `observer cloud-session otel-receiver`.
func newCloudSessionOTelReceiverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "otel-receiver",
		Short: "Run a loopback OTLP receiver inside a cloud agent's sandbox (opt-in, init --otel-loopback)",
		Long: "The committed hooks run `ensure` at session start and on each prompt:\n" +
			"inside the agent's cloud sandbox it starts a loopback-only OTLP/HTTP\n" +
			"receiver when none answers, writing into the sandbox's own Observer\n" +
			"database so the flush hooks ship its rows. A no-op anywhere else.\n" +
			"Part of component ingest.otlp: while it is not active serve is refused\n" +
			"(exit 3) and ensure prints the refusal and exits 0.\n" +
			"See docs/cloud-agents.md \"Claude Code cloud sessions over OpenTelemetry\".",
	}
	cmd.AddCommand(newOTelLoopEnsureCmd(), newOTelLoopServeCmd())
	return cmd
}

func newOTelLoopEnsureCmd() *cobra.Command {
	var agent, addr, configPath string
	cmd := &cobra.Command{
		Use:   "ensure",
		Short: "Start the loopback receiver if this is the agent's cloud sandbox and none is running",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// ensure runs from a non-gate hook on every session start and
			// prompt: with ingest.otlp inactive it prints the refusal line
			// and exits 0, so the agent never shows a hook error for an
			// optional receiver. serve keeps the exit-3 refusal.
			if err := otelLoopRefused(cmd, configPath); err != nil {
				return nil
			}
			exe, err := os.Executable()
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "otel-receiver: %v\n", err)
				return nil
			}
			var markers []string
			if a, err := cloudsession.AgentByID(agent); err == nil {
				markers = cloudsession.MarkerEnvNames(a)
			}
			r := runOTelLoopEnsure(otelLoopEnsureInput{
				Agent: agent, Addr: addr, Env: os.LookupEnv,
				Probe: probeLoopback, Wait: otelLoopStartWait,
				Spawn: func(a string) error {
					argv := []string{exe, "cloud-session", "otel-receiver", "serve", "--addr", a}
					if configPath != "" {
						argv = append(argv, "--config", configPath)
					}
					p, err := spawnDetached(argv, "", otelLoopServeEnv(os.Environ(), markers))
					if err != nil {
						return err
					}
					return p.Release()
				},
			})
			printOTelLoopEnsure(cmd.ErrOrStderr(), r)
			return nil // a hook never fails the session
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "the cloud agent whose sandbox this is ("+agentFlagHelp()+")")
	_ = cmd.MarkFlagRequired("agent")
	cmd.Flags().StringVar(&addr, "addr", cloudsession.DefaultOTelLoopbackAddr, "loopback host:port the receiver binds")
	cmd.Flags().StringVar(&configPath, "config", "", "observer config path (default: the standard one)")
	return cmd
}

func newOTelLoopServeCmd() *cobra.Command {
	var addr, configPath string
	var idle time.Duration
	cmd := &cobra.Command{
		Use:    "serve",
		Short:  "Serve the loopback receiver in the foreground (ensure starts it detached)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := otelLoopRefused(cmd, configPath); err != nil {
				return err
			}
			a, err := cloudsession.ValidOTelLoopbackAddr(addr)
			if err != nil {
				return err
			}
			return runOTelLoopbackServe(cmd.Context(), otelLoopServeOptions{
				ConfigPath: configPath, Addr: a, Idle: idle, MaxLifetime: otelLoopMaxLifetime,
			})
		},
	}
	cmd.Flags().StringVar(&addr, "addr", cloudsession.DefaultOTelLoopbackAddr, "loopback host:port to bind")
	cmd.Flags().StringVar(&configPath, "config", "", "observer config path (default: the standard one)")
	cmd.Flags().DurationVar(&idle, "idle", otelLoopDefaultIdle, "stop after this long with no export")
	return cmd
}

// otelLoopServeEnvNames are the variables the detached receiver keeps by
// exact name (compared case-insensitively, as Windows names are): where home,
// the config and the database resolve, the search path and temp dirs, and
// the locale. Everything else the hook was started with (the ship token
// SBO_CLOUD_SESSION_TOKEN, provider keys, GITHUB_TOKEN) stays out of a
// process that can live for a day (ledger CLOUDTEL-3).
var otelLoopServeEnvNames = []string{
	"HOME", "USERPROFILE", "PATH", "TMPDIR", "TMP", "TEMP",
	"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
	"APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "LANG", "LC_ALL", "TZ",
}

// otelLoopServeEnvPrefix carries observer's own config overrides
// (OBSERVER_<SECTION>_<KEY>, e.g. OBSERVER_OBSERVER_DB_PATH), so the receiver
// writes the database the flush reads; a name holding one of
// otelLoopServeSecretWords is still dropped.
const otelLoopServeEnvPrefix = "OBSERVER_"

// otelLoopServeSecretWords mark a credential-bearing name under the prefix
// (OBSERVER_CI_CREDENTIAL and the like).
var otelLoopServeSecretWords = []string{"TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY", "APIKEY", "PRIVATE"}

// otelLoopServeEnv is the minimal environment ensure starts the receiver
// with: the allow-listed names above, the OBSERVER_ config overrides that are
// not secrets, and the agent's cloud marker variables (markers, from
// cloudsession.MarkerEnvNames). Order follows environ.
func otelLoopServeEnv(environ, markers []string) []string {
	keep := func(name string) bool {
		for _, n := range otelLoopServeEnvNames {
			if strings.EqualFold(name, n) {
				return true
			}
		}
		for _, n := range markers {
			if name == n {
				return true
			}
		}
		upper := strings.ToUpper(name)
		if !strings.HasPrefix(upper, otelLoopServeEnvPrefix) {
			return false
		}
		for _, w := range otelLoopServeSecretWords {
			if strings.Contains(upper, w) {
				return false
			}
		}
		return true
	}
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" || !keep(name) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// otelLoopServeOptions are the receiver's inputs.
type otelLoopServeOptions struct {
	ConfigPath  string
	Addr        string
	Idle        time.Duration
	MaxLifetime time.Duration
}

// otelLoopEnsureInput is ensure's injected I/O, so the decision is testable.
type otelLoopEnsureInput struct {
	Agent string
	Addr  string
	Env   cloudsession.LookupEnv
	// Probe reports whether something accepts connections on addr.
	Probe func(addr string) bool
	// Spawn starts the detached receiver on addr.
	Spawn func(addr string) error
	// Wait bounds the wait for a fresh receiver.
	Wait time.Duration
}

// otelLoopEnsureState is what ensure did.
type otelLoopEnsureState string

const (
	otelLoopNotCloud    otelLoopEnsureState = "not_cloud"
	otelLoopBadInput    otelLoopEnsureState = "invalid"
	otelLoopRunning     otelLoopEnsureState = "running"
	otelLoopStarted     otelLoopEnsureState = "started"
	otelLoopSpawnFailed otelLoopEnsureState = "spawn_failed"
	otelLoopNoAnswer    otelLoopEnsureState = "no_answer"
)

type otelLoopEnsureResult struct {
	State otelLoopEnsureState
	Addr  string
	Err   error
}

// runOTelLoopEnsure decides and acts: outside the agent's cloud sandbox it
// does nothing; a receiver already answering is left alone; otherwise it
// spawns one and waits for it to answer. Two concurrent ensures may both
// spawn: the second receiver's bind fails and it exits, which is harmless.
func runOTelLoopEnsure(in otelLoopEnsureInput) otelLoopEnsureResult {
	a, err := cloudsession.AgentByID(in.Agent)
	if err != nil {
		return otelLoopEnsureResult{State: otelLoopBadInput, Err: err}
	}
	if _, err := cloudsession.OTelLoopbackFor(a.ID); err != nil {
		return otelLoopEnsureResult{State: otelLoopBadInput, Err: err}
	}
	if !cloudsession.Detect(a, in.Env).InCloud {
		return otelLoopEnsureResult{State: otelLoopNotCloud}
	}
	addr, err := cloudsession.ValidOTelLoopbackAddr(in.Addr)
	if err != nil {
		return otelLoopEnsureResult{State: otelLoopBadInput, Err: err}
	}
	if in.Probe(addr) {
		return otelLoopEnsureResult{State: otelLoopRunning, Addr: addr}
	}
	if err := in.Spawn(addr); err != nil {
		return otelLoopEnsureResult{State: otelLoopSpawnFailed, Addr: addr, Err: err}
	}
	deadline := time.Now().Add(in.Wait)
	for {
		if in.Probe(addr) {
			return otelLoopEnsureResult{State: otelLoopStarted, Addr: addr}
		}
		if !time.Now().Before(deadline) {
			return otelLoopEnsureResult{State: otelLoopNoAnswer, Addr: addr, Err: errors.New("the receiver did not answer in time; see otel-receiver.log in the cloud-session state directory")}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// printOTelLoopEnsure reports a non-trivial outcome on stderr (a hook's
// stderr is shown to the developer only in verbose views). Silent outside a
// cloud sandbox and when the receiver already runs.
func printOTelLoopEnsure(w io.Writer, r otelLoopEnsureResult) {
	switch r.State {
	case otelLoopNotCloud, otelLoopRunning:
	case otelLoopStarted:
		fmt.Fprintf(w, "otel-receiver: listening on %s\n", r.Addr)
	default:
		fmt.Fprintf(w, "otel-receiver: %s: %v\n", r.State, r.Err)
	}
}

// probeLoopback reports whether addr accepts a TCP connection.
func probeLoopback(addr string) bool {
	d := net.Dialer{Timeout: otelLoopProbeTimeout}
	c, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
