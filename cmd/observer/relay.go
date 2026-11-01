// relay.go: `observer relay serve|status`, the fail-open Windows route relay
// (surface-gap finding CC-9, decision D12). The decisions live in the pure
// internal/winrelay, the listener and the bypass journal in
// internal/winrelaysvc; this file only parses flags, applies the live-check
// gate and renders. Nothing here starts on its own: no daemon loop, init
// step, dashboard action or maintenance pass runs the relay, and `serve`
// refuses to start while the gate waits (DEC-12).

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/routeattest"
	"github.com/marmutapp/superbased-observer/internal/winrelay"
	"github.com/marmutapp/superbased-observer/internal/winrelaysvc"
)

// runLiveGatedRelay lets this package's tests run the relay below its gate.
// Production code never sets it: switching the relay on is the commit that
// clears winrelay's gate once LC6 and LC14 pass.
var runLiveGatedRelay = false

// relayGateRefusal is the refusal `observer relay serve` answers while the
// relay waits on its live checks, nil once it may run.
func relayGateRefusal() error {
	if g := winrelay.Gate(); g.Waiting() && !runLiveGatedRelay {
		return fmt.Errorf("observer relay: not started: the fail-open Windows route relay is %s; it stays switched off until those checks pass", g.Text())
	}
	return nil
}

// relayServeOptions are `observer relay serve`'s flags. There is no journal
// flag: the journal lives where every reader reads it (relayJournalPath).
type relayServeOptions struct {
	configPath string
	port       int
	proxyPort  int
}

// relayHome resolves the home the journal lives under (diag.RelayOwnHome,
// the one rule the readers use too). A var so tests can point it at a
// scratch home.
var relayHome = diag.RelayOwnHome

func newRelayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "The fail-open Windows route relay (built, switched off until live checks LC6 and LC14)",
		Long: "The relay runs on the Windows host of a WSL daemon. A Windows tool's settings\n" +
			"route points at it (127.0.0.1:" + fmt.Sprint(winrelay.DefaultPort) + " on the Windows host), and it forwards each\n" +
			"request to Observer's proxy when that proxy answers. When WSL or the daemon is\n" +
			"down it forwards straight to the provider instead, so the session keeps\n" +
			"working; every such forward is recorded in a metadata-only bypass journal\n" +
			"first (never a header, credential, query or body), shown by `observer doctor`,\n" +
			"and judged as unproxied traffic by the route gate. A forward that cannot be\n" +
			"recorded is refused. It binds the IPv4 loopback only.\n\n" +
			"It is built and switched off until live checks LC6 and LC14 pass: `serve`\n" +
			"refuses to start, and the Windows route keeps pointing at the WSL proxy.",
	}
	var opts relayServeOptions
	cmd.PersistentFlags().StringVar(&opts.configPath, "config", "", "observer config.toml path (default ~/.observer/config.toml)")
	serve := &cobra.Command{
		Use:   "serve",
		Short: "Run the relay in the foreground (refused until live checks LC6 and LC14 pass)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			return runRelayServe(ctx, opts, cmd.ErrOrStderr())
		},
	}
	serve.Flags().IntVar(&opts.port, "port", winrelay.DefaultPort, "the relay's own loopback port (never the proxy's)")
	serve.Flags().IntVar(&opts.proxyPort, "proxy-port", 0, "Observer's proxy port (default [proxy].port, else 8820)")
	status := &cobra.Command{
		Use:   "status",
		Short: "Show the relay's gate, route URL and recorded bypasses",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRelayStatus(time.Now(), cmd.OutOrStdout())
		},
	}
	cmd.AddCommand(serve, status)
	return cmd
}

// loadRelayConfig loads the config for the relay. The Windows host of a WSL
// daemon usually has no config of its own; the defaults then apply.
// A config that does not load is reported and the proxy's default port
// applies (the config supplies nothing else the relay uses).
func loadRelayConfig(path string, stderr io.Writer) config.Config {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err == nil {
		return cfg
	}
	fmt.Fprintf(stderr, "observer relay: config not loaded (%v); using defaults\n", err)
	cfg = config.Default()
	cfg.Proxy.Port = winrelay.DefaultProxyPort
	return cfg
}

// relayJournalPath is the journal the relay writes: bypass.jsonl in
// winrelay.JournalDirUnder(relayHome()), the directory the doctor, the
// managed report and `observer relay status` read. Neither a flag nor the
// database path moves it (audit of 492f8b0ab item 4).
func relayJournalPath() (string, error) {
	home, err := relayHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(winrelay.JournalDirUnder(home), winrelay.JournalFile), nil
}

// runRelayServe applies the gate, then serves until ctx ends.
func runRelayServe(ctx context.Context, opts relayServeOptions, stderr io.Writer) error {
	if err := relayGateRefusal(); err != nil {
		return err
	}
	cfg := loadRelayConfig(opts.configPath, stderr)
	proxyPort := opts.proxyPort
	if proxyPort == 0 {
		proxyPort = cfg.Proxy.Port
	}
	journalPath, err := relayJournalPath()
	if err != nil {
		return fmt.Errorf("observer relay: not started: %w (the bypass journal must live where the doctor and the managed report read it)", err)
	}
	journal := winrelaysvc.NewJournal(journalPath, 0)
	r, err := winrelaysvc.New(winrelaysvc.Options{
		ListenPort: opts.port,
		ProxyPort:  proxyPort,
		Journal:    journal,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(stderr, "%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
		},
	})
	if err != nil {
		return fmt.Errorf("observer relay: %w", err)
	}
	ln, err := r.Listen()
	if err != nil {
		return fmt.Errorf("observer relay: %w", err)
	}
	fmt.Fprintf(stderr, "observer relay: listening on %s, forwarding to the proxy on port %d; bypasses are recorded in %s\n",
		ln.Addr(), proxyPort, journal.Path())
	return r.Serve(ctx, ln)
}

// runRelayStatus prints the gate, the route URL a Windows Claude Code route
// would carry, and the bypasses this node can read inside the observed
// window.
func runRelayStatus(now time.Time, w io.Writer) error {
	if g := winrelay.Gate(); g.Waiting() {
		fmt.Fprintf(w, "relay: %s (switched off; Windows routes keep the WSL proxy target)\n", g.Text())
	} else {
		fmt.Fprintln(w, "relay: switched on")
	}
	if u, ok := winrelay.RouteURL(winrelay.DefaultPort, "claude-code"); ok {
		fmt.Fprintf(w, "route URL (claude-code, once switched on): %s\n", u)
	}
	j := diag.RelayBypassSince("", now.Add(-routeattest.ObservedWindow))
	days := int(routeattest.ObservedWindow / (24 * time.Hour))
	switch {
	case !j.Found:
		fmt.Fprintln(w, "bypass journal: none found")
	case j.Summary.Total() == 0:
		fmt.Fprintf(w, "bypasses in the last %dd: none\n", days)
	default:
		fmt.Fprintf(w, "bypasses in the last %dd: %d\n", days, j.Summary.Total())
		for _, t := range j.Summary.Tools {
			fmt.Fprintf(w, "  %s: %d, %s to %s\n", t.Tool, t.Count, t.First.UTC().Format(time.RFC3339), t.Last.UTC().Format(time.RFC3339))
		}
	}
	for _, p := range j.Unreadable {
		fmt.Fprintf(w, "bypass journal unreadable: %s\n", p)
	}
	return nil
}
