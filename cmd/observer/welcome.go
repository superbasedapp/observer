package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/frontdoor"
)

// printWelcome renders the bare-`observer` greeting (usability arc
// P1.13): a short status-oriented welcome instead of the full cobra
// help wall — orientation first, `--help` one flag away. Probes the
// daemon's two ports with short dials so the first line answers the
// first question ("is it running?") without opening the DB.
func printWelcome(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()

	proxyPort := 8820
	dbPath := ""
	if cfg, err := config.Load(config.LoadOptions{}); err == nil {
		if cfg.Proxy.Port > 0 {
			proxyPort = cfg.Proxy.Port
		}
		dbPath = cfg.Observer.DBPath
	}
	dashAddr := defaultDashboardAddr
	dashUp := portUp(dashAddr)
	proxyUp := portUp(fmt.Sprintf("127.0.0.1:%d", proxyPort))
	proxyInBuild := !proxyNotInBuild()

	fmt.Fprintf(out, "SuperBased Observer %s\n\n", version)
	switch {
	case dashUp && proxyInBuild:
		fmt.Fprintf(out, "  daemon      running - dashboard at http://%s (proxy :%d)\n", dashAddr, proxyPort)
	case dashUp:
		fmt.Fprintf(out, "  daemon      running - dashboard at http://%s (%s)\n", dashAddr, proxyNotInBuildReason())
	case proxyUp && !dashboardInBuild:
		fmt.Fprintf(out, "  daemon      proxy up on :%d (%s)\n", proxyPort, dashboardNotInBuildNote())
	case proxyUp:
		fmt.Fprintf(out, "  daemon      proxy up on :%d (dashboard not detected on %s)\n", proxyPort, dashAddr)
	default:
		// REVIEW-4 P4-19: a headless daemon without the proxy answers no
		// port, so the start lock beside the database decides.
		if lock, live := liveDaemonFor(dbPath); live {
			fmt.Fprintf(out, "  daemon      running (pid %d) with no dashboard or proxy listener%s\n", lock.PID, welcomeBuildNote())
		} else {
			fmt.Fprintf(out, "  daemon      not detected - start it with `observer start`\n")
		}
	}
	if line := welcomeSignInLine(connectIdentityState(""), welcomeConnected()); line != "" {
		fmt.Fprintf(out, "\n  %s\n", line)
	}
	fmt.Fprint(out, "\n")
	fmt.Fprint(out, "  observer usage     one-shot cost table (no daemon, temp DB)\n")
	fmt.Fprintf(out, "  observer start     %s\n", welcomeStartLine(dashAddr))
	if proxyInBuild {
		fmt.Fprint(out, "  observer init      wire hooks / MCP / proxy routing into your AI tools\n")
	} else {
		fmt.Fprint(out, "  observer init      wire hooks / MCP into your AI tools\n")
	}
	fmt.Fprint(out, "  observer connect   sign in and see this machine online\n")
	fmt.Fprint(out, "  observer doctor    health checks\n")
	fmt.Fprint(out, "  observer --help    every command\n")
	return nil
}

// welcomeSignInLine is the bare-`observer` sign-in nudge (Getting started
// v2): one line when this machine is signed out and not connected anywhere,
// "" otherwise (signed in, connected to a server, or a build with no
// SuperBased sign-in, whose identity reads as unknown). Never blocking.
func welcomeSignInLine(id frontdoor.Identity, connected bool) string {
	if id != frontdoor.IdentitySignedOut || connected {
		return ""
	}
	return "Not signed in. Run `observer connect` to see this machine online."
}

// welcomeConnected reports whether this machine is connected (enrolled)
// anywhere, without creating the database. An unreadable state reads as not
// connected: the nudge is a hint, never a gate.
func welcomeConnected() bool {
	enr, err := loadConnectEnrolment(context.Background(), "")
	return err == nil && enr != nil
}

// welcomeStartLine describes what `observer start` runs in THIS build
// (REVIEW-4 P4-19): it never names a proxy or a dashboard the binary lacks.
func welcomeStartLine(dashAddr string) string {
	parts := []string{}
	if !proxyNotInBuild() {
		parts = append(parts, "proxy")
	}
	parts = append(parts, "watcher")
	if dashboardInBuild {
		parts = append(parts, fmt.Sprintf("dashboard (http://%s)", dashAddr))
	}
	return strings.Join(parts, " + ") + welcomeBuildNote()
}

// welcomeBuildNote is " (the API proxy and the dashboard are not in this
// build)" or the one-component variant; "" for a build carrying both.
func welcomeBuildNote() string {
	var missing []string
	if proxyNotInBuild() {
		missing = append(missing, "the API proxy")
	}
	if !dashboardInBuild {
		missing = append(missing, "the dashboard")
	}
	switch len(missing) {
	case 0:
		return ""
	case 1:
		return " (" + missing[0] + " is not in this build)"
	default:
		return " (" + strings.Join(missing, " and ") + " are not in this build)"
	}
}

// defaultDashboardAddr is where `observer start` serves the dashboard unless
// --dashboard-addr says otherwise. The welcome screen and `observer setup
// launch` probe it to tell whether a daemon is already up.
const defaultDashboardAddr = "127.0.0.1:8081"

// portUp reports whether something is listening on a loopback addr.
// Short timeout — this runs on every bare `observer` invocation.
func portUp(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond) //nolint:gosec // G704: false positive; a loopback liveness probe of the dashboard address, nothing is sent
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
