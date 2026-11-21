package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/attachrule"
	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/frontdoor"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/managedconfig"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// connect_request.go is `observer connect [team]` with no server address
// (Getting started v2, shared contracts A and B): one browser approval that
// signs this machine in AND picks where its data goes, then the existing
// attach owner (`observer enroll`) against the approved target, with the
// consent already given on the approval page.
//
//  1. Create a connect request for this machine's device key (the cloud
//     seam, connect_request_cloud.go; the wire lives in internal/cloudclient).
//  2. Open the approval page in a browser, or print the short code and the
//     code-entry page when there is no browser (--no-browser, or no display).
//  3. Poll until the person answers. An approved answer completes device
//     sign-in. "Not now" (approved, no target) ends signed in with nothing
//     sent.
//  4. Check the target against the company attach policy (attachrule), find
//     its address, record the consent receipt, and attach through `observer
//     enroll`: with the attach grant the approval carries (on standard input,
//     signed for by this machine's device key: no second browser step), else
//     the one-time code when there is one, else the org's own sign-in (an
//     older cloud), which the text then says.
//
// --json prints one JSON object per line (contract B) and nothing else on
// standard output; the attach owner's own lines go to standard error. The
// dashboard and the VS Code extension run `observer connect --json
// --no-browser [team]` and open approve_url themselves.
//
// A cloud that does not offer connect requests yet (404 on create) falls back
// to the older path: sign in, then list organizations (connect_discover.go),
// in text mode only.

// connectRequestInput describes this machine for the approval page.
type connectRequestInput struct {
	MachineName, OS, Arch, ObserverVersion, TargetHint string
}

// connectRequestInfo is the cloud's answer to the create call.
type connectRequestInfo struct {
	RequestID, UserCode, ApproveURL, VerifyURL string
	// ExpiresIn and Interval are seconds.
	ExpiresIn, Interval int
}

// connectTargetInfo is where an approved request sends this machine's data
// (contract A's target, plus the optional server_url / dashboard_url).
type connectTargetInfo struct {
	OrgID        string `json:"org_id"`
	Slug         string `json:"slug"`
	Kind         string `json:"kind"`
	DisplayName  string `json:"display_name"`
	ShareLevel   string `json:"share_level"`
	ServerURL    string `json:"-"`
	DashboardURL string `json:"-"`
}

// connectApproval is one poll's answer. EnrolCode and AttachGrant are
// secrets: handed to the attach owner on standard input, never printed.
type connectApproval struct {
	Status           string
	Target           *connectTargetInfo
	ConsentReceiptID string
	SignedIn         bool
	EnrolCode        string
	// AttachGrant is the one-step attach grant (contract A section 11): the
	// attach then needs no second browser step.
	AttachGrant string
}

// connectAttachVia is how the attach owner is asked to join the target.
type connectAttachVia int

const (
	// attachViaIdP: the target's own sign-in (`observer enroll --idp`), a
	// second browser approval on the target's host. The fallback.
	attachViaIdP connectAttachVia = iota
	// attachViaCode: a one-time enrolment code on standard input.
	attachViaCode
	// attachViaGrant: the attach grant on standard input, signed for by
	// this machine's device key; no second browser step.
	attachViaGrant
)

// connectAttachRule is one row of connectAttachRules.
type connectAttachRule struct {
	via  connectAttachVia
	when func(ap connectApproval) bool
}

// connectAttachRules pick how to attach, top-down: the grant when the
// approval carries one, else the one-time code, else the target's own
// sign-in (an older cloud that sends neither).
var connectAttachRules = []connectAttachRule{
	{via: attachViaGrant, when: func(ap connectApproval) bool { return ap.AttachGrant != "" }},
	{via: attachViaCode, when: func(ap connectApproval) bool { return ap.EnrolCode != "" }},
	{via: attachViaIdP, when: func(connectApproval) bool { return true }},
}

// connectAttachFor walks connectAttachRules.
func connectAttachFor(ap connectApproval) connectAttachVia {
	for _, r := range connectAttachRules {
		if r.when(ap) {
			return r.via
		}
	}
	return attachViaIdP
}

// Poll and create outcomes the cloud seam maps its own errors onto.
var (
	errConnectRequestGone = errors.New("the approval request expired")
	errConnectSlowDown    = errors.New("polled too fast")
	// errConnectProofRefused: the cloud refused this machine's proof of its
	// key even on the server's clock (L-142).
	errConnectProofRefused = errors.New("the superbased cloud refused this machine's signed check-in. " +
		"If this machine's clock is wrong, set it (for example `sudo timedatectl set-ntp true`; `date -u` shows it) " +
		"and run `observer connect` again")
	errConnectUnsupported = errors.New("this cloud does not offer connect requests")
)

// Connect request statuses (contract A).
const (
	connectStatusPending  = "pending"
	connectStatusApproved = "approved"
	connectStatusDeclined = "declined"
	connectStatusExpired  = "expired"
)

// Defaults when the cloud answers without a cadence or a lifetime, and the
// back-off ceiling after a rate-limited poll.
const (
	connectRequestDefaultInterval = 3 * time.Second
	connectRequestDefaultLifetime = 15 * time.Minute
	connectRequestSlowDownStep    = 5 * time.Second
	connectRequestMaxInterval     = 30 * time.Second
)

// connectRequestSeams are the cloud seams of the flow; all nil in a build
// without Cloud Intelligence.
type connectRequestSeams struct {
	start func(ctx context.Context, o connectCloudOpts, in connectRequestInput) (connectRequestInfo, error)
	poll  func(ctx context.Context, o connectCloudOpts, requestID string) (connectApproval, error)
	// onlineBase is the cloud origin the user signs in to (the "Online
	// dashboard" line). Never a personal dashboard's own host.
	onlineBase func(o connectCloudOpts) string
}

// connectRequestAvailable reports whether this build and these deps can run
// the connect request flow.
func connectRequestAvailable(deps connectDeps) bool {
	return deps.request.start != nil && deps.request.poll != nil
}

// connectTeamSlug matches a team slug argument (`observer connect acme`), as
// opposed to a server address: lowercase letters, digits and hyphens, no
// dot, colon or slash.
var connectTeamSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// isConnectTeamSlug reports whether arg names a team rather than a server.
func isConnectTeamSlug(arg string) bool { return connectTeamSlug.MatchString(arg) }

// Contract B's error codes: a closed set the dashboard and VS Code branch on.
const (
	connectErrRequestFailed   = "request_failed"
	connectErrExpired         = "expired"
	connectErrDeclined        = "declined"
	connectErrSignIn          = "sign_in_incomplete"
	connectErrRefused         = "refused"
	connectErrNeedsConfirm    = "needs_confirmation"
	connectErrTargetNotReady  = "target_not_ready"
	connectErrAttachFailed    = "attach_failed"
	connectErrUnsupportedHere = "unsupported"
)

// connectEvent is one contract B progress line. Only the fields of its
// state are set; Target is a pointer to a pointer so "approved" can print
// "target":null for "Not now".
type connectEvent struct {
	State       string              `json:"state"`
	ApproveURL  string              `json:"approve_url,omitempty"`
	VerifyURL   string              `json:"verify_url,omitempty"`
	UserCode    string              `json:"user_code,omitempty"`
	Target      **connectTargetInfo `json:"target,omitempty"`
	DisplayName string              `json:"display_name,omitempty"`
	Kind        string              `json:"kind,omitempty"`
	OnlineURL   string              `json:"online_url,omitempty"`
	Code        string              `json:"code,omitempty"`
	Message     string              `json:"message,omitempty"`
}

// connectEmitter writes contract B lines in --json mode and nothing in text
// mode. text is where human lines go: standard output in text mode, standard
// error in --json mode, so standard output stays one JSON object per line.
type connectEmitter struct {
	json bool
	out  io.Writer
	text io.Writer
}

func (e connectEmitter) emit(ev connectEvent) {
	if !e.json {
		return
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	fmt.Fprintln(e.out, string(b))
}

// fail emits an error line and returns the error the command exits with.
func (e connectEmitter) fail(code string, err error) error {
	e.emit(connectEvent{State: "error", Code: code, Message: err.Error()})
	return err
}

// runConnectRequest runs the flow for teamHint ("" for none). It is called
// only after planConnect decided there is no address and no company pre-set
// (or the argument named a team).
func runConnectRequest(cmd *cobra.Command, deps connectDeps, f connectFlags, pol managedconfig.AttachResult, enr *store.Enrolment, teamHint string) error {
	ctx := cmd.Context()
	em := connectEmitter{json: f.jsonOut, out: cmd.OutOrStdout(), text: cmd.OutOrStdout()}
	if f.jsonOut {
		em.text = cmd.ErrOrStderr()
	}
	opts := connectCloudOpts{configPath: f.configPath, baseURL: f.baseURL, devToken: f.devToken}
	machine := connectMachineName(deps)

	req, err := deps.request.start(ctx, opts, connectRequestInput{
		MachineName: machine, OS: runtime.GOOS, Arch: runtime.GOARCH,
		ObserverVersion: version, TargetHint: teamHint,
	})
	if errors.Is(err, errConnectUnsupported) {
		if f.jsonOut || !connectDiscoveryAvailable(deps) {
			return em.fail(connectErrUnsupportedHere, errors.New("observer connect: this superbased cloud does not offer browser approval yet; update Observer, or run `observer connect` in a terminal"))
		}
		target, derr := runConnectDiscovery(cmd, deps, f, pol, enr)
		if derr != nil || target == "" {
			return derr
		}
		return deps.runEnroll(cmd, connectEnrollArgv(f, target, attachViaIdP, f.acceptGovernance), strings.NewReader(""))
	}
	if err != nil {
		return em.fail(connectErrRequestFailed, fmt.Errorf("observer connect: could not start: %w", err))
	}

	em.emit(connectEvent{State: "waiting_approval", ApproveURL: req.ApproveURL, VerifyURL: req.VerifyURL, UserCode: req.UserCode})
	browser := !f.noBrowser && deps.hasBrowser != nil && deps.hasBrowser()
	if browser {
		fmt.Fprintf(em.text, "Opening your browser to approve %s.\n", machine)
		fmt.Fprintf(em.text, "If it does not open, go to %s\n", req.ApproveURL)
		fmt.Fprintf(em.text, "or open %s on any phone or computer and enter %s\n", req.VerifyURL, req.UserCode)
		if deps.openURL != nil {
			deps.openURL(req.ApproveURL)
		}
	} else {
		fmt.Fprintf(em.text, "On any phone or computer, open %s\n", req.VerifyURL)
		fmt.Fprintf(em.text, "and enter this code: %s\n", req.UserCode)
	}
	fmt.Fprintln(em.text, "Nothing leaves this machine until you approve.")

	ap, err := waitForConnectApproval(ctx, deps, opts, req)
	if err != nil {
		code := connectErrRequestFailed
		if errors.Is(err, errConnectRequestGone) {
			code = connectErrExpired
		}
		return em.fail(code, err)
	}
	switch ap.Status {
	case connectStatusDeclined:
		return em.fail(connectErrDeclined, errors.New("observer connect: the request was declined; nothing changed"))
	case connectStatusExpired:
		return em.fail(connectErrExpired, errors.New("observer connect: the request expired; run `observer connect` again"))
	}
	if !ap.SignedIn && deps.identity(f.configPath) != frontdoor.IdentitySignedIn {
		return em.fail(connectErrSignIn, errors.New("observer connect: approved, but sign-in did not complete; run `observer connect` again"))
	}
	em.emit(connectEvent{State: "approved", Target: &ap.Target})

	if ap.Target == nil {
		em.emit(connectEvent{State: "signed_in_only"})
		fmt.Fprintln(em.text, "Signed in. Nothing is sent from this machine.")
		fmt.Fprintln(em.text, "Connect it any time: observer connect")
		return nil
	}
	t := *ap.Target
	name := connectTargetName(t)

	// Belt: the company attach policy decides, as for every attach.
	in := attachrule.Input{Current: currentDestination(enr), Lock: pol.Lock(), Intent: attachrule.IntentAttach, Requested: connectTargetDestination(t)}
	switch d := attachrule.Decide(in); d.Outcome {
	case attachrule.OutcomeAllow:
	case attachrule.OutcomeAllowWithConfirmation:
		q := fmt.Sprintf("This machine is managed by %s. Switch it to %s? Rows still waiting for %s are sent there first.", d.ConfirmOrgName, name, d.ConfirmOrgName)
		if !f.yes && (f.jsonOut || !deps.confirm(cmd, q)) {
			return em.fail(connectErrNeedsConfirm, fmt.Errorf("observer connect: signed in, but not switched; this machine stays with %s (run `observer connect --yes` to switch)", d.ConfirmOrgName))
		}
	default:
		return em.fail(connectErrRefused, connectRefusal(pol, d, name))
	}

	server, err := resolveConnectTargetServer(cmd, deps, opts, t, em.text)
	if err != nil {
		return em.fail(connectErrTargetNotReady, err)
	}
	if deps.recordConsent != nil {
		rec := connectConsentRecord{
			RequestID: req.RequestID, ConsentReceiptID: ap.ConsentReceiptID,
			OrgID: t.OrgID, Slug: t.Slug, Kind: t.Kind, ShareLevel: t.ShareLevel,
			ApprovedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if rerr := deps.recordConsent(f.configPath, rec); rerr != nil {
			fmt.Fprintf(em.text, "Warning: could not save the approval receipt on this machine: %v\n", rerr)
		}
	}

	em.emit(connectEvent{State: "attaching"})
	fmt.Fprintf(em.text, "Connecting %s to %s.\n", machine, name)
	if err := attachConnectTarget(cmd, deps, f, em, ap, server, name); err != nil {
		return em.fail(connectErrAttachFailed, err)
	}

	online := firstNonEmpty(t.DashboardURL, server, deps.request.onlineBase(opts))
	// Job 2 of lane 8: the connection's name and online address are kept
	// with the enrolment, so the local status reads them after a restart.
	if deps.recordConnection != nil {
		if rerr := deps.recordConnection(cmd.Context(), f.configPath, t.OrgID, name, online); rerr != nil {
			fmt.Fprintf(em.text, "Warning: could not save the connection's name on this machine: %v\n", rerr)
		}
	}
	em.emit(connectEvent{State: "connected", DisplayName: name, Kind: t.Kind, OnlineURL: online})
	printConnectedLines(em.text, deps, f, machine, name, t.Kind, deps.request.onlineBase(opts))
	return nil
}

// attachConnectTarget runs the attach owner for an approved target: with the
// attach grant when the approval carries one (no second browser step), else
// the one-time code, else the target's own sign-in. A target that does not
// take the grant (an older server, or one that pins no cloud key) falls back
// to its own sign-in, and the text says so. The approval page showed what is
// shared and who can read it: that is the consent, so the attach records an
// offered governance grant without a second prompt (--accept-governance).
func attachConnectTarget(cmd *cobra.Command, deps connectDeps, f connectFlags, em connectEmitter, ap connectApproval, server, name string) error {
	via := connectAttachFor(ap)
	switch via {
	case attachViaGrant:
		err := runConnectEnrollTo(cmd, deps, em.text, connectEnrollArgv(f, server, attachViaGrant, true), strings.NewReader(ap.AttachGrant+"\n"))
		if !errors.Is(err, orgclient.ErrAttachGrantNotAccepted) {
			return err
		}
		fmt.Fprintf(em.text, "%s does not take the one-step approval yet; finishing with its own sign-in.\n", name)
		via = attachViaIdP
	case attachViaIdP:
		fmt.Fprintln(em.text, "This superbased cloud sent no one-step approval; finishing with the dashboard's own sign-in.")
	}
	stdin := strings.NewReader("")
	if via == attachViaCode {
		stdin = strings.NewReader(ap.EnrolCode + "\n")
	}
	return runConnectEnrollTo(cmd, deps, em.text, connectEnrollArgv(f, server, via, true), stdin)
}

// waitForConnectApproval polls until the request is no longer pending, the
// lifetime runs out, or the context ends. A rate-limited poll waits longer.
func waitForConnectApproval(ctx context.Context, deps connectDeps, opts connectCloudOpts, req connectRequestInfo) (connectApproval, error) {
	interval := time.Duration(req.Interval) * time.Second
	if interval <= 0 {
		interval = connectRequestDefaultInterval
	}
	lifetime := time.Duration(req.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = connectRequestDefaultLifetime
	}
	var waited time.Duration
	for {
		ap, err := deps.request.poll(ctx, opts, req.RequestID)
		switch {
		case errors.Is(err, errConnectSlowDown):
			interval = min(interval+connectRequestSlowDownStep, connectRequestMaxInterval)
		case errors.Is(err, errConnectRequestGone):
			return connectApproval{}, fmt.Errorf("observer connect: %w; run `observer connect` again", errConnectRequestGone)
		case errors.Is(err, errConnectProofRefused):
			return connectApproval{}, fmt.Errorf("observer connect: %w", errConnectProofRefused)
		case err != nil:
			return connectApproval{}, fmt.Errorf("observer connect: check on the approval: %w", err)
		case ap.Status != connectStatusPending:
			return ap, nil
		}
		if waited+interval > lifetime {
			return connectApproval{}, fmt.Errorf("observer connect: %w after %s; run `observer connect` again", errConnectRequestGone, lifetime)
		}
		if err := deps.sleep(ctx, interval); err != nil {
			return connectApproval{}, err
		}
		waited += interval
	}
}

// resolveConnectTargetServer returns the approved target's own address: the
// one the approval named, else the organization list's entry for its org id
// (waiting while a new personal dashboard or team is still being created).
func resolveConnectTargetServer(cmd *cobra.Command, deps connectDeps, opts connectCloudOpts, t connectTargetInfo, progress io.Writer) (string, error) {
	if t.ServerURL != "" {
		return t.ServerURL, nil
	}
	name := connectTargetName(t)
	if deps.listOrgs == nil {
		return "", fmt.Errorf("observer connect: signed in, but %s's address is not known to this build", name)
	}
	list, err := deps.listOrgs(cmd.Context(), opts)
	if err != nil {
		return "", fmt.Errorf("observer connect: signed in, but could not look up %s: %w", name, err)
	}
	for _, o := range list.Orgs {
		if o.OrgID != t.OrgID {
			continue
		}
		ready, err := waitForConnectOrg(cmd, deps, opts, o, progress)
		if err != nil {
			return "", err
		}
		if ready.ServerURL == "" {
			return "", fmt.Errorf("observer connect: signed in; %s is not ready yet, run `observer connect` again later", name)
		}
		return ready.ServerURL, nil
	}
	return "", fmt.Errorf("observer connect: signed in, but %s is not listed for your account yet; run `observer connect` again", name)
}

// connectTargetDestination is attachrule's view of an approved target. Full
// detail is a team's managed sharing; summary only is individual.
func connectTargetDestination(t connectTargetInfo) attachrule.Destination {
	o := cloudcontract.DeviceOrg{OrgID: t.OrgID, Slug: t.Slug, DisplayName: t.DisplayName, Kind: cloudcontract.DeviceOrgTeam, Tenancy: "individual"}
	if t.Kind == "personal" {
		o.Kind = cloudcontract.DeviceOrgPersonal
	} else if t.ShareLevel == "full" {
		o.Tenancy = "managed"
	}
	return connectOrgDestination(o)
}

// connectTargetName is the target's display name, else its slug. A personal
// dashboard is always "your personal dashboard": its slug is never shown.
func connectTargetName(t connectTargetInfo) string {
	if n := strings.TrimSpace(t.DisplayName); n != "" {
		return n
	}
	if t.Kind == "personal" {
		return "your personal dashboard"
	}
	return t.Slug
}

// connectMachineName is this machine's name for the approval page.
func connectMachineName(deps connectDeps) string {
	if deps.hostname != nil {
		if h, err := deps.hostname(); err == nil && strings.TrimSpace(h) != "" {
			return strings.TrimSpace(h)
		}
	}
	return "this machine"
}

// connectEnrollArgv is `observer enroll`'s argv for an attach: the server
// with the grant on standard input (--attach-grant-file -) or the code on
// standard input (--token-file -), else the organization's own sign-in
// (--idp). Neither secret is ever an argument.
func connectEnrollArgv(f connectFlags, server string, via connectAttachVia, acceptGovernance bool) []string {
	var args []string
	switch via {
	case attachViaGrant:
		args = []string{server, "--attach-grant-file", "-"}
	case attachViaCode:
		args = []string{server, "--token-file", "-"}
	default:
		args = []string{"--idp", server}
	}
	if f.configPath != "" {
		args = append(args, "--config", f.configPath)
	}
	args = append(args,
		fmt.Sprintf("--write-block=%t", f.writeBlock),
		fmt.Sprintf("--wire-clients=%t", f.wireClients),
	)
	if f.dropUnsent {
		args = append(args, "--drop-unsent")
	}
	if acceptGovernance {
		args = append(args, "--accept-governance")
	}
	if f.acceptIntel {
		args = append(args, "--accept-intel-consent")
	}
	return args
}

// runConnectEnrollTo runs the attach owner with its standard output sent to
// w (standard error in --json mode), restoring the command's own output.
func runConnectEnrollTo(cmd *cobra.Command, deps connectDeps, w io.Writer, args []string, stdin io.Reader) error {
	orig := cmd.OutOrStdout()
	cmd.SetOut(w)
	defer cmd.SetOut(orig)
	return deps.runEnroll(cmd, args, stdin)
}

// The two dashboards' role lines. The installer, the online approval page
// (webcloud connectModel) and the local dashboard (shared/lib/twoDashboards)
// say the same words: the local dashboard keeps everything on this computer,
// the online one receives what this machine shares (a summary for the
// personal dashboard, full detail for a team, whose admins can read it).
const (
	connectRoleLocal    = "everything Observer records on this computer, in full; it stays here"
	connectRolePersonal = "a summary from each machine you connect"
	connectRoleTeam     = "full detail (prompts, responses, file paths); the team's admins can read it"
)

// connectOnlineRow is the online dashboard's label and role line for an
// approved target's kind: the personal dashboard, else a team.
func connectOnlineRow(kind string) (label, role string) {
	if kind == "personal" {
		return "Online dashboard", connectRolePersonal
	}
	return "Team dashboard", connectRoleTeam
}

// connectDashboardLabelWidth aligns the dashboards' addresses in one column.
const connectDashboardLabelWidth = 18

// printConnectedLines is the text ending of a successful connect: each
// dashboard with its address and, under it, what it holds. It never prints a
// personal dashboard's own address: the online line is the cloud origin the
// person signs in to.
func printConnectedLines(w io.Writer, deps connectDeps, f connectFlags, machine, name, kind, onlineBase string) {
	fmt.Fprintf(w, "\nConnected: %s -> %s\n", machine, name)
	if deps.dashboardURL != nil {
		if u := deps.dashboardURL(f.configPath); u != "" {
			printDashboardRow(w, "Local dashboard", u, connectRoleLocal)
		}
	}
	if onlineBase != "" {
		label, role := connectOnlineRow(kind)
		printDashboardRow(w, label, onlineBase, role)
	}
	fmt.Fprintln(w, "Undo any time: observer disconnect")
}

// printDashboardRow prints one dashboard: its label and address on one line,
// what it holds indented under it.
func printDashboardRow(w io.Writer, label, address, role string) {
	fmt.Fprintf(w, "%-*s%s\n  %s\n", connectDashboardLabelWidth, label, address, role)
}

// connectLocalDashboardURL is the local dashboard's address from config (the
// same resolution `observer start` uses, without its flag), or "" in a build
// without the dashboard.
func connectLocalDashboardURL(configPath string) string {
	if !dashboardInBuild {
		return ""
	}
	addr := defaultDashboardAddr
	if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil {
		addr = resolveDashboardAddr("", cfg.Dashboard.Addr, defaultDashboardAddr)
	}
	return "http://" + addr
}

// connectConsentRecord is this machine's copy of an approval: which request,
// which cloud consent receipt, and the target and share level the person
// chose. It holds no credential.
type connectConsentRecord struct {
	RequestID        string `json:"request_id"`
	ConsentReceiptID string `json:"consent_receipt_id"`
	OrgID            string `json:"org_id"`
	Slug             string `json:"slug"`
	Kind             string `json:"kind"`
	ShareLevel       string `json:"share_level"`
	ApprovedAt       string `json:"approved_at"`
}

// connectConsentFile is the approval record's name, beside config.toml.
const connectConsentFile = "connect-consent.json"

// writeConnectConsent records rec beside config.toml (owner-only), replacing
// the previous approval: the record says what this machine was last
// connected under.
func writeConnectConsent(configPath string, rec connectConsentRecord) error {
	cfgPath, err := resolveConfigPath(configPath)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode approval record: %w", err)
	}
	dir := filepath.Dir(cfgPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return fsatomic.WriteFile(filepath.Join(dir, connectConsentFile), append(b, '\n'), fsatomic.Options{FilePerm: 0o600})
}

// readConnectKind is the online dashboard kind ("personal" or "team") this
// machine was last connected to, from the approval record writeConnectConsent
// keeps beside config.toml, when that record is for orgID. "" when there is
// no record, it is for another organization, or it names no known kind (an
// enrolment made by invite or `observer enroll` records none). The
// dashboard reads it to word an org-level status for the person who can
// change it: on a personal dashboard that is the person themselves.
func readConnectKind(configPath, orgID string) string {
	if strings.TrimSpace(orgID) == "" {
		return ""
	}
	cfgPath, err := resolveConfigPath(configPath)
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(cfgPath), connectConsentFile)) //nolint:gosec // G703: false positive; a fixed file name beside this node's own config.toml, read only
	if err != nil {
		return ""
	}
	var rec connectConsentRecord
	if json.Unmarshal(b, &rec) != nil || rec.OrgID != orgID {
		return ""
	}
	switch rec.Kind {
	case "personal", "team":
		return rec.Kind
	}
	return ""
}

// connectHasBrowser reports whether a browser can plausibly open here: the
// desktop OSes always, Linux only with a display or under WSL.
func connectHasBrowser() bool {
	switch runtime.GOOS {
	case "windows", "darwin":
		return true
	}
	for _, k := range []string{"DISPLAY", "WAYLAND_DISPLAY", "WSL_DISTRO_NAME"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// recordConnectConnection is connectDeps.recordConnection in production: it
// opens this machine's database (the same path `observer enroll` just wrote
// the enrolment to) and records the connection's display name and online
// address on that enrolment (store.SetEnrolmentConnection). An enrolment for
// another organization is left as it is.
func recordConnectConnection(ctx context.Context, configPath, orgID, displayName, onlineURL string) error {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = database.Close() }()
	if _, err := store.New(database).SetEnrolmentConnection(ctx, orgID, displayName, onlineURL); err != nil {
		return err
	}
	return nil
}
