package diag

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// checkProcessObservability reports the process-observability feature's
// posture in `observer doctor` (docs/process-observability.md §13.2).
//
// This is a one-shot CLI check: it reads DB + config facts directly, and it
// CANNOT read the running daemon's memory. The runtime half (backend up,
// queue depth, and — the one that fails silently — whether per-process
// network byte accounting actually attached) therefore arrives via the
// health record the daemon publishes next to the DB (see ProcessHealth), and
// is reported AS a report: "pid N said X, T ago". If no daemon is running,
// we say that instead of inferring a state.
//
// The feature is opt-in, so a disabled install reports a clean informational
// OK rather than a warning.
func checkProcessObservability(ctx context.Context, database *sql.DB, cfg config.Config) Check {
	p := cfg.Observer.Process
	if !p.Enabled {
		return Check{
			Name:    "process observability",
			Status:  StatusOK,
			Message: "[observer.process] disabled (opt-in; OS-level process capture off)",
		}
	}

	var runs int64
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM process_runs`).Scan(&runs); err != nil {
		return Check{
			Name:    "process observability",
			Status:  StatusFail,
			Message: "could not read process_runs table",
			Details: []string{err.Error()},
		}
	}

	details := []string{
		fmt.Sprintf("backend:       %s", p.Backend),
		fmt.Sprintf("argv mode:     %s", p.Argv.Mode),
		fmt.Sprintf("retention:     %d days", p.RetentionDays),
		fmt.Sprintf("rows retained: %d process runs", runs),
	}
	now := time.Now()
	health, haveHealth := LatestProcessHealth(ProcessHealthDir(cfg.Observer.DBPath))
	details = append(details, processHealthDetails(health, haveHealth, now)...)

	// A dial-in capture transport whose every connection was refused is the
	// single most actionable thing this check can report: something IS dialling
	// the daemon and nothing is getting through, so every event that capturer
	// produces is being discarded. It outranks the network-accounting warning
	// below, which on this topology is only its downstream symptom ("no
	// capturer connected → bytes unmeasured").
	//
	// It reports the daemon's VERBATIM refusal reason and stops there. The
	// counter conflates a bad token, a protocol version this daemon does not
	// speak, and a stray local process probing the port — naming one of those
	// as the cause would send an operator whose token is already correct to
	// fix the token, which is the failure mode this line exists to prevent.
	if haveHealth && health.TransportConfigured() &&
		health.TransportAuthFailures > 0 && health.TransportConnections == 0 {
		return Check{
			Name:   "process observability",
			Status: StatusWarn,
			Message: staleQualified(health, now, fmt.Sprintf(
				"enabled (%s backend) — the cross-OS capturer link is REFUSING every connection: %d refused at the handshake, none authenticated; %s",
				p.Backend, health.TransportAuthFailures, health.authReasonClause(),
			)),
			Details: details,
		}
	}

	// A transport the operator ASKED for and that never came up is the other
	// half of the same honesty rule: without this branch the whole capturer
	// surface prints nothing, which is exactly what an install that never
	// enabled ETW prints. "Requested and broken" must not render as "not
	// requested".
	if haveHealth && health.TransportState == processobs.TransportStateUnavailable {
		reason := health.TransportUnavailableReason
		if reason == "" {
			reason = "no reason reported by the daemon"
		}
		return Check{
			Name:   "process observability",
			Status: StatusWarn,
			Message: staleQualified(health, now, fmt.Sprintf(
				"enabled (%s backend) — the cross-OS capture transport was REQUESTED but is NOT running, so no elevated capturer can connect: %s",
				p.Backend, reason,
			)),
			Details: details,
		}
	}

	// Runs the daemon captured and then THREW AWAY because the sink kept
	// refusing writes. This outranks every accounting warning below it: an
	// unmeasured byte total is a missing column on a row that exists, whereas
	// this is the row itself never landing — process history that cannot be
	// reconstructed from anything else on the box.
	//
	// It fires only on the exhausted counter, never on a non-zero retention:
	// retained runs are BUFFERED, not lost, and warning about a sink that is
	// successfully riding out a busy database would train the operator to
	// ignore the line that means real loss.
	if haveHealth && health.Dropped[string(processobs.DropSinkRetryExhausted)] > 0 {
		lost := health.Dropped[string(processobs.DropSinkRetryExhausted)]
		return Check{
			Name:   "process observability",
			Status: StatusWarn,
			Message: staleQualified(health, now, fmt.Sprintf(
				"enabled (%s backend), %d process runs retained — %d captured run(s) were LOST: the sink kept failing and the retry retention overflowed. Process history for that window is gone; check for a competing writer holding the SQLite write lock (another daemon, a long backfill, a hook storm)",
				p.Backend, runs, lost,
			)),
			Details: details,
		}
	}

	// A backend that was ASKED for per-process network bytes and could not
	// attach is the loudest thing this check knows: the charts silently show
	// nothing, and only the reason makes it actionable. It outranks the
	// no-rows-yet warning below.
	if haveHealth && health.NetworkAccountingMode == processobs.NetworkAccountingUnavailable {
		return Check{
			Name:   "process observability",
			Status: StatusWarn,
			Message: staleQualified(health, now, fmt.Sprintf(
				"enabled (%s backend), %d process runs retained — per-process network accounting UNAVAILABLE (bytes are unmeasured, not zero)",
				p.Backend, runs,
			)),
			Details: details,
		}
	}

	// Enabled but no rows yet: not an error (the backend may be unsupported
	// on this host, or simply nothing has spawned).
	if runs == 0 {
		msg := "enabled but no process runs captured yet — start the daemon (`observer start`) and check the backend line below"
		if haveHealth {
			msg = fmt.Sprintf("enabled but no process runs captured yet — daemon pid %d is running with the %s backend",
				health.PID, health.Backend)
		}
		return Check{
			Name:    "process observability",
			Status:  StatusWarn,
			Message: msg,
			Details: details,
		}
	}
	return Check{
		Name:    "process observability",
		Status:  StatusOK,
		Message: fmt.Sprintf("enabled (%s backend), %d process runs retained", p.Backend, runs),
		Details: details,
	}
}

// processHealthDetails renders the daemon-reported runtime half of the check.
// It is deliberately explicit about provenance and age: everything here is a
// report from another process, so a missing daemon says so, and a daemon that
// stopped refreshing is labelled STALE rather than presented as current.
func processHealthDetails(h ProcessHealth, ok bool, now time.Time) []string {
	if !ok {
		return []string{
			"daemon health: no running daemon has published process-observability health",
			"               (start `observer start` with [observer.process].enabled to populate it;",
			"                the same record backs the observer_process_* live gauges on /metrics)",
		}
	}
	up := "down"
	if h.BackendUp {
		up = "up"
	}
	age := h.Age(now).Round(time.Second)
	stamp := fmt.Sprintf("reported %s ago", age)
	if h.Stale(now) {
		stamp = fmt.Sprintf("last reported %s ago — STALE, the daemon is alive but has stopped refreshing; the values below are its last report", age)
	}
	out := []string{
		fmt.Sprintf("daemon health: pid %d, backend %s (%s), queue %d, %s",
			h.PID, h.Backend, up, h.QueueDepth, stamp),
		fmt.Sprintf("network bytes: %s", h.NetworkAccountingLine()),
		// Always rendered, zeroes included — see ProcessHealth.CaptureLine.
		// The row count above says what SURVIVED; this says what the running
		// daemon resolved and discarded, which is the only way to tell an idle
		// box from one whose every batch is being thrown away.
		fmt.Sprintf("capture:       %s", h.CaptureLine()),
	}
	// Only rendered when a dial-in transport actually exists — an install
	// without one must not grow a line about a capturer it never configured.
	if line := h.TransportLine(now); line != "" {
		out = append(out, fmt.Sprintf("capturer link: %s", line))
	}
	if h.LastError != "" {
		out = append(out, fmt.Sprintf("last error:    %s", h.LastError))
	}
	return out
}
