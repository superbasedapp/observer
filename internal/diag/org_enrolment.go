package diag

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// org_enrolment.go holds the org (Teams) enrolment family of `observer
// doctor`: checkOrgEnrolment and the daemon reports it reads (oversized push
// rows, the machine proof). Moved out of doctor.go unchanged.

// checkOrgEnrolment surfaces the Teams (org) side of the agent in
// doctor: enrolment state, share mode (the per-node v1.8.0 opt-in),
// any scope filters, the last push status, and a clock-skew estimate
// against the org server. None of these failure modes hurt anything
// silently — they just mean the operator's expectations don't match
// what the agent will do — but they are exactly the questions the
// 2026-06-02 teams test couldn't answer without reading source.
func checkOrgEnrolment(ctx context.Context, database *sql.DB, cfg config.Config) Check {
	if !cfg.OrgClient.Enabled {
		// Tracker #41: "disabled" is only innocuous on a machine that never
		// enrolled. An enrolment row with the rail off means the node LOOKS
		// enrolled to its operator (and to the org that minted the token)
		// while pushing nothing and polling no policy — silently ungoverned.
		var enrolled int
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_enrolment`).Scan(&enrolled); err == nil && enrolled > 0 {
			return Check{
				Name: "org enrolment", Status: StatusWarn,
				Message:      "enrolled but [org_client] enabled = false - the org rail is NOT running (no push, no policy poll); set enabled = true in config.toml or run " + remedy.Quote(remedy.Of(remedy.OrgUnenroll, "")),
				Remediations: []remedy.Remediation{remedy.Of(remedy.OrgClientEnable, ""), remedy.Of(remedy.OrgUnenroll, "")},
			}
		}
		return Check{Name: "org enrolment", Status: StatusOK, Message: "[org_client] disabled (solo-local mode)"}
	}
	// Schema-meta-driven enrolment / cursor / last-push readout. We
	// avoid pulling internal/store here to keep diag standalone.
	var enrolled int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_enrolment`).Scan(&enrolled); err != nil {
		return Check{
			Name: "org enrolment", Status: StatusFail, Message: "could not read org_enrolment table",
			Details: []string{err.Error()},
		}
	}
	if enrolled == 0 {
		return Check{
			Name: "org enrolment", Status: StatusWarn,
			Message:      "[org_client] enabled but not enrolled - run " + remedy.Quote(remedy.Of(remedy.OrgEnroll, "")) + " to enrol",
			Remediations: []remedy.Remediation{remedy.Of(remedy.OrgEnroll, "")},
		}
	}
	var orgID, orgName, orgURL, userEmail string
	if err := database.QueryRowContext(ctx,
		`SELECT org_id, org_name, org_server_url, user_email FROM org_enrolment LIMIT 1`).
		Scan(&orgID, &orgName, &orgURL, &userEmail); err != nil {
		return Check{
			Name: "org enrolment", Status: StatusFail, Message: "could not read enrolment row",
			Details: []string{err.Error()},
		}
	}

	details := []string{
		fmt.Sprintf("org:           %s (%s)", orgName, orgID),
		fmt.Sprintf("user:          %s", userEmail),
		fmt.Sprintf("server:        %s", orgURL),
	}
	// Share mode (v1.8.0): mention loudly when full_content is on, so a
	// node operator that intended to ship metadata-only sees their
	// config drift immediately.
	shareMsg := "metadata-only (default; raws withheld)"
	shareStatus := StatusOK
	if cfg.OrgClient.Share.FullContent {
		shareMsg = "FULL CONTENT (raw command bodies + assistant prose + raw paths SHIPPED)"
		shareStatus = StatusWarn
	}
	details = append(details, "share mode:    "+shareMsg)
	// Tracker #41 second half — REVISED after a code review (BLOCK-1)
	// rejected the prior version of this check, which treated a blank
	// [org_client].org_server_url as "NOT enrolled" full stop. That was
	// wrong for a real, live shape: this function only reaches here when
	// an org_enrolment row already exists (see the `enrolled == 0` early
	// return above), and cmd/observer/start.go's construction gate
	// (orgClientShouldStart) starts the WHOLE org client — push, guard-
	// policy poll, announcement/routing-policy fetch, grant renewal —
	// whenever EITHER the config carries a URL OR a persisted row exists.
	// A row existing here means the node IS active: the push loop dials
	// the ROW's own server URL (orgURL below), which
	// internal/orgclient.Client.PushOnce reads from the store, never from
	// this config field. `ensureOrgClientBlock` (cmd/observer/org.go) is
	// header-idempotent — an existing [org_client] table header means
	// org_server_url is never (re)written — so a node enrolled before that
	// field existed, or re-enrolled without a full `observer unenroll`
	// first, can carry a blank org_server_url indefinitely while staying
	// genuinely, fully enrolled.
	//
	// What a blank org_server_url DOES still affect: it is NOT the guard
	// policy-bundle poll's dial target — that poll (like every other org
	// loop) reads enr.OrgServerURL from the PERSISTED row via
	// internal/orgclient's FetchPolicyBundle (LoadEnrolment →
	// genClient(enr.OrgServerURL)), never from this config field. A code
	// review corrected an earlier version of this check that claimed
	// otherwise. The one real, cosmetic effect: cmd/observer/start.go
	// passes this config field into newPolicyBundleRunner purely as R-205
	// audit metadata (policybundle.go's orgURL field), used only to build
	// the Target string on a bundle-REJECTED guard finding
	// (orgURL+"/api/v1/policy-bundle"). With this field blank, that one
	// Target string loses its server-URL prefix (becomes just
	// "/api/v1/policy-bundle") — the finding itself, the R-205 rule, and
	// every loop's actual behavior are all unaffected. That is cosmetic,
	// not a degradation, so it does not raise this check's status.
	orgServerURLUnset := strings.TrimSpace(cfg.OrgClient.OrgServerURL) == ""
	if orgServerURLUnset {
		details = append(details, fmt.Sprintf(
			"config gap:    [org_client].org_server_url is unset - the node stays fully ACTIVE (push/announcement/routing-policy/guard-policy-poll all dial the persisted enrolment's server, %q, directly); the only effect is cosmetic - an R-205 bundle-rejection finding's Target string loses its server-URL prefix. Add org_server_url = %q to config.toml to restore that prefix", orgURL, orgURL,
		))
	}
	if len(cfg.OrgClient.Share.TargetActionAllowlist) > 0 {
		details = append(details, fmt.Sprintf("target allow:  %v", cfg.OrgClient.Share.TargetActionAllowlist))
	}
	if len(cfg.OrgClient.Scope.ProjectRootAllowlist) > 0 {
		details = append(details, fmt.Sprintf("scope allow:   %v", cfg.OrgClient.Scope.ProjectRootAllowlist))
	}
	if len(cfg.OrgClient.Scope.ProjectRootDenylist) > 0 {
		details = append(details, fmt.Sprintf("scope deny:    %v", cfg.OrgClient.Scope.ProjectRootDenylist))
	}
	// Last push: only flag a non-OK status (the cron-style push loop
	// can transiently fail on a captive-portal lunch break without
	// indicating a real problem).
	var lastStatus, lastPushedAt, lastErr string
	var lastRows int64
	err := database.QueryRowContext(ctx,
		`SELECT pushed_at, row_count, status, COALESCE(error,'') FROM org_push_log
		   ORDER BY id DESC LIMIT 1`).
		Scan(&lastPushedAt, &lastRows, &lastStatus, &lastErr)
	switch {
	case err == sql.ErrNoRows:
		details = append(details, "last push:     (none yet)")
	case err != nil:
		details = append(details, "last push:     could not read org_push_log: "+err.Error())
		shareStatus = worseStatus(shareStatus, StatusWarn)
	default:
		summary := fmt.Sprintf("last push:     %s - %s, %d rows", lastPushedAt, lastStatus, lastRows)
		if lastErr != "" {
			summary += fmt.Sprintf(" (err: %s)", lastErr)
		}
		details = append(details, summary)
		if lastStatus != "ok" {
			shareStatus = worseStatus(shareStatus, StatusWarn)
		}
	}
	// Snapshot rows too large for any push: the daemon's report
	// (store.OrgPushOversizedKey; family names and sizes only, never row
	// content). Read here with this file's own SQL, like org_push_log above.
	var rems []remedy.Remediation
	for _, line := range oversizedPushLines(ctx, database) {
		details = append(details, "oversized:     "+line)
		shareStatus = worseStatus(shareStatus, StatusWarn)
		if len(rems) == 0 {
			rems = append(rems, remedy.Of(remedy.OpenSettings, "org"))
		}
	}
	if line, unavailable := machineProofLine(ctx, database); line != "" {
		details = append(details, "machine proof: "+line)
		if unavailable {
			shareStatus = worseStatus(shareStatus, StatusWarn)
		}
	}
	msg := "enrolled - " + shareMsg
	if orgServerURLUnset {
		msg = fmt.Sprintf(
			"enrolled - ACTIVE, dialing the persisted server %s (org_server_url is unset in config; see the config gap detail for the one cosmetic thing that affects) - %s",
			orgURL, shareMsg,
		)
	}
	return Check{
		Name:         "org enrolment",
		Status:       shareStatus,
		Message:      msg,
		Details:      details,
		Remediations: rems,
	}
}

// orgPushOversizedKey mirrors store.OrgPushOversizedKey (this file keeps its
// own SQL); TestOrgEnrolmentReportsOversizedPushRows pins the shape.
const orgPushOversizedKey = "org_push_oversized_rows"

// oversizedPushLines renders the daemon's oversized snapshot row report, one
// line per family. A missing or unreadable report yields nothing.
func oversizedPushLines(ctx context.Context, database *sql.DB) []string {
	var raw string
	if err := database.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = ?`, orgPushOversizedKey).Scan(&raw); err != nil || raw == "" {
		return nil
	}
	var rows []struct {
		Family       string `json:"family"`
		Rows         int64  `json:"rows"`
		LargestBytes int64  `json:"largest_bytes"`
		BudgetBytes  int64  `json:"budget_bytes"`
		LastSeen     string `json:"last_seen"`
	}
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%s: %d row(s) larger than the %d-byte snapshot budget (largest %d bytes, last %s); raise [org_client] max_push_bytes (Settings > Org sharing) to ship them",
			r.Family, r.Rows, r.BudgetBytes, r.LargestBytes, r.LastSeen))
	}
	return out
}

// orgMachineProofKey mirrors store.OrgMachineProofKey (this file keeps its
// own SQL); TestOrgMachineProofReport pins the shape.
const orgMachineProofKey = "org_machine_proof"

// machineProofLine renders the daemon's machine-proof report (WINNODE item 4):
// the daemon records it only for a managed enrolment, at its first request
// that names the machine. unavailable is true when the daemon signs nothing.
// A missing or unreadable report yields "".
func machineProofLine(ctx context.Context, database *sql.DB) (line string, unavailable bool) {
	var tenancy, raw string
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(tenancy,'') FROM org_enrolment LIMIT 1`).Scan(&tenancy); err != nil || tenancy != "managed" {
		return "", false // only a managed enrolment signs with a machine key
	}
	if err := database.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = ?`, orgMachineProofKey).Scan(&raw); err != nil || raw == "" {
		return "", false
	}
	var r struct {
		Available bool   `json:"available"`
		Reason    string `json:"reason"`
		At        string `json:"at"`
	}
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return "", false
	}
	if r.Available {
		return "available (daemon, since " + r.At + ")", false
	}
	return "machine proof unavailable: " + r.Reason + " (daemon, since " + r.At + "); machine-scoped grants and the machine's budget binding are withheld until the daemon runs in the developer's sign-in", true
}
