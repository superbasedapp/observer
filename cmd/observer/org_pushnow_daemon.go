package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// org_pushnow_daemon.go: `observer org push-now` against a RUNNING daemon.
//
// The CLI used to push from its own process with its own org client, so the
// daemon never heard of it: its push loop stayed parked on a failure pause
// (the oversized-batch circuit holds it an hour) and its policy polls kept
// their hourly cadence. The daemon already serves the same verb on its
// owner-local dashboard route POST /api/enrolment/push-now (the Settings >
// Enrolment Push now button), which pushes and then wakes the daemon's own
// policy polls and push loop. The CLI now drives that route when a daemon
// answers, and keeps its in-process push when none does. No new IPC: the
// address is the one the daemon recorded (dashboard_listen_record.go), and the
// confirm token is the route's existing double-submit protocol, minted by
// GET /api/enrolment/manage.
//
// Only a daemon serving THIS config's database is asked (decisions log L-125:
// a throwaway HOME with no listen record reached the operator's live daemon
// on the default port, which pushed its own rows). The caller resolves the
// daemon through resolveDaemonHandoff, and every request here names this
// database, so a daemon serving another one refuses it and the CLI pushes in
// this process instead.

// daemonPushNowTimeout bounds the whole loopback exchange (the daemon's push
// itself included).
const daemonPushNowTimeout = 2 * time.Minute

// The double-submit pair the dashboard's enrolment routes require
// (requireJSONConfirm): the same fresh value as cookie and header. Declared
// here rather than reusing remote.go's pair because that file leaves the
// build with sbo_omit_remote (the minimal edition) and push-now does not.
const (
	pushNowConfirmCookie = "sb_remote_confirm"
	pushNowConfirmHeader = "X-Observer-Confirm" //nolint:gosec // G101: a header name, not a credential
)

// daemonPushNowOutcome is what asking the daemon produced.
type daemonPushNowOutcome struct {
	// Answered: a daemon took the request (Report or Err is set). False: no
	// daemon listens (or none serves the route), so the CLI pushes itself.
	Answered bool
	Report   dashapi.PushNowReport
	// Err is the daemon's refusal of the push (not enrolled, rejected
	// credential, upstream failure), already worded for the operator.
	Err error
}

// daemonPushNow asks the daemon whose dashboard listens at base
// ("http://host:port") to push now, naming this CLI's database (dbIdentity)
// on both requests. A refused connection, a dashboard that does not serve the
// enrolment routes, or a daemon that serves another database is "no daemon":
// the caller falls back.
var daemonPushNow = func(ctx context.Context, base, dbIdentity string) daemonPushNowOutcome {
	ctx, cancel := context.WithTimeout(ctx, daemonPushNowTimeout)
	defer cancel()
	client := &http.Client{}
	target := daemonTarget{DBIdentity: dbIdentity}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/enrolment/manage", nil)
	if err != nil {
		return daemonPushNowOutcome{}
	}
	target.setDBIdentity(req)
	resp, err := client.Do(req)
	if err != nil {
		return daemonPushNowOutcome{}
	}
	var manage struct {
		ConfirmToken string `json:"confirm_token"`
	}
	decErr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&manage)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || decErr != nil || manage.ConfirmToken == "" {
		// A dashboard without the enrolment manager (501), one an org has
		// hidden the page on, or something that is not our dashboard.
		return daemonPushNowOutcome{}
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/enrolment/push-now", bytes.NewReader([]byte("{}")))
	if err != nil {
		return daemonPushNowOutcome{}
	}
	req.Header.Set("Content-Type", "application/json")
	target.setDBIdentity(req)
	req.Header.Set(pushNowConfirmHeader, manage.ConfirmToken)
	req.AddCookie(&http.Cookie{Name: pushNowConfirmCookie, Value: manage.ConfirmToken})
	resp, err = client.Do(req)
	if err != nil {
		return daemonPushNowOutcome{Answered: true, Err: fmt.Errorf("the daemon at %s did not finish the push: %w", req.URL.Host, err)}
	}
	defer func() { _ = resp.Body.Close() }()
	if isDBIdentityRefusal(resp, dbIdentity) {
		// The address changed hands after the GET: this database has no
		// daemon there, so nothing was pushed and the caller pushes itself.
		return daemonPushNowOutcome{}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var fail struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		msg := strings.TrimSpace(string(body))
		if json.Unmarshal(body, &fail) == nil {
			if fail.Message != "" {
				msg = fail.Message
			} else if fail.Error != "" {
				msg = fail.Error
			}
		}
		return daemonPushNowOutcome{Answered: true, Err: fmt.Errorf("the running daemon refused the push (HTTP %d): %s", resp.StatusCode, msg)}
	}
	var rep dashapi.PushNowReport
	if err := json.Unmarshal(body, &rep); err != nil {
		return daemonPushNowOutcome{Answered: true, Err: fmt.Errorf("the running daemon's push report could not be read: %w", err)}
	}
	return daemonPushNowOutcome{Answered: true, Report: rep}
}

// printDaemonPushNowReport renders the daemon's report the way the CLI renders
// its own (the same lines: the dashboard built them with printPushNowReport).
func printDaemonPushNowReport(out io.Writer, rep dashapi.PushNowReport) {
	fmt.Fprintln(out, rep.Message)
	for _, n := range rep.Notes {
		fmt.Fprintln(out, "  "+n.Text)
	}
	fmt.Fprintln(out, "Ran in the running daemon; its push loop and policy polls were woken.")
}
