package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/frontdoor"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// requestFake scripts the connect request seams (contract A).
type requestFake struct {
	t        *testing.T
	startErr error
	polls    []connectApproval
	pollErrs []error
	started  []connectRequestInput
	polled   int
	opened   []string
	recorded []connectConsentRecord
	slept    []time.Duration
	browser  bool
	// connections are the recorded (org id, display name, online URL).
	connections [][3]string
}

func (f *requestFake) wire(d *connectDeps) {
	d.request = connectRequestSeams{
		start: func(_ context.Context, _ connectCloudOpts, in connectRequestInput) (connectRequestInfo, error) {
			f.started = append(f.started, in)
			if f.startErr != nil {
				return connectRequestInfo{}, f.startErr
			}
			return connectRequestInfo{
				RequestID: "req-1", UserCode: "KTRW-4821",
				ApproveURL: "https://cloud.superbased.app/connect/req-1", VerifyURL: "https://cloud.superbased.app/connect",
				ExpiresIn: 900, Interval: 3,
			}, nil
		},
		poll: func(context.Context, connectCloudOpts, string) (connectApproval, error) {
			i := f.polled
			f.polled++
			if i < len(f.pollErrs) && f.pollErrs[i] != nil {
				return connectApproval{}, f.pollErrs[i]
			}
			if i >= len(f.polls) {
				i = len(f.polls) - 1
			}
			return f.polls[i], nil
		},
		onlineBase: func(connectCloudOpts) string { return "https://cloud.superbased.app" },
	}
	d.openURL = func(u string) { f.opened = append(f.opened, u) }
	d.hasBrowser = func() bool { return f.browser }
	d.hostname = func() (string, error) { return "laptop", nil }
	d.recordConsent = func(_ string, rec connectConsentRecord) error {
		f.recorded = append(f.recorded, rec)
		return nil
	}
	d.dashboardURL = func(string) string { return "http://127.0.0.1:8081" }
	d.recordConnection = func(_ context.Context, _ string, orgID, name, online string) error {
		f.connections = append(f.connections, [3]string{orgID, name, online})
		return nil
	}
	d.sleep = func(_ context.Context, dur time.Duration) error {
		f.slept = append(f.slept, dur)
		return nil
	}
	d.isTerminal = func(*cobra.Command) bool { return false }
}

func (h *connectHarness) withRequest(f *requestFake) connectDeps {
	d := h.deps()
	f.wire(&d)
	return d
}

func (h *connectHarness) execWith(t *testing.T, d connectDeps, args ...string) (string, string, error) {
	t.Helper()
	cmd := newConnectCmdWith(d)
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	err := cmd.ExecuteContext(context.Background())
	return out.String(), errb.String(), err
}

func approvedTeam(code string) connectApproval {
	return connectApproval{
		Status: connectStatusApproved, SignedIn: true, ConsentReceiptID: "rcpt-1", EnrolCode: code,
		Target: &connectTargetInfo{OrgID: "org-acme", Slug: "acme", Kind: "team", DisplayName: "Acme", ShareLevel: "full", ServerURL: "https://acme.superbased.app"},
	}
}

func TestConnectRequestTeamWithCodeAttachesNonInteractively(t *testing.T) {
	h := newConnectHarness()
	f := &requestFake{t: t, browser: true, polls: []connectApproval{{Status: connectStatusPending}, approvedTeam("ONE-TIME-CODE")}}
	out, _, err := h.execWith(t, h.withRequest(f), "acme")
	if err != nil {
		t.Fatalf("connect acme: %v\n%s", err, out)
	}
	if len(f.started) != 1 || f.started[0].TargetHint != "acme" || f.started[0].MachineName != "laptop" {
		t.Fatalf("started = %+v", f.started)
	}
	if len(f.opened) != 1 || f.opened[0] != "https://cloud.superbased.app/connect/req-1" {
		t.Fatalf("opened = %v", f.opened)
	}
	want := []string{"https://acme.superbased.app", "--token-file", "-"}
	if strings.Join(h.run.enrollArgs[:3], " ") != strings.Join(want, " ") {
		t.Fatalf("enroll args = %v", h.run.enrollArgs)
	}
	if !contains(h.run.enrollArgs, "--accept-governance") {
		t.Fatalf("the approval page's consent was not passed on: %v", h.run.enrollArgs)
	}
	if h.run.enrollStdin != "ONE-TIME-CODE\n" {
		t.Fatalf("enroll stdin = %q", h.run.enrollStdin)
	}
	if strings.Contains(out, "ONE-TIME-CODE") {
		t.Fatal("the one-time code was printed")
	}
	if len(f.recorded) != 1 || f.recorded[0].ConsentReceiptID != "rcpt-1" || f.recorded[0].ShareLevel != "full" {
		t.Fatalf("consent record = %+v", f.recorded)
	}
	// A team: the team dashboard's row says what the team receives.
	lines := "\nConnected: laptop -> Acme\n" +
		"Local dashboard   http://127.0.0.1:8081\n" +
		"  everything Observer records on this computer, in full; it stays here\n" +
		"Team dashboard    https://cloud.superbased.app\n" +
		"  full detail (prompts, responses, file paths); the team's admins can read it\n" +
		"Undo any time: observer disconnect\n"
	if !strings.Contains(out, lines) {
		t.Fatalf("output lacks the connected lines\n%s\nin:\n%s", lines, out)
	}
}

// TestPrintConnectedLinesPerKind pins each dashboard's role line: the
// personal dashboard gets a summary, a team full detail its admins can read,
// and a build without the local dashboard prints no local row.
func TestPrintConnectedLinesPerKind(t *testing.T) {
	local := func(string) string { return "http://127.0.0.1:8081" }
	for _, tc := range []struct {
		name, kind, target string
		dashboard          func(string) string
		want               string
	}{
		{
			name: "personal", kind: "personal", target: "your personal dashboard", dashboard: local,
			want: "\nConnected: laptop -> your personal dashboard\n" +
				"Local dashboard   http://127.0.0.1:8081\n" +
				"  everything Observer records on this computer, in full; it stays here\n" +
				"Online dashboard  https://cloud.superbased.app\n" +
				"  a summary from each machine you connect\n" +
				"Undo any time: observer disconnect\n",
		},
		{
			name: "team", kind: "team", target: "Acme", dashboard: local,
			want: "\nConnected: laptop -> Acme\n" +
				"Local dashboard   http://127.0.0.1:8081\n" +
				"  everything Observer records on this computer, in full; it stays here\n" +
				"Team dashboard    https://cloud.superbased.app\n" +
				"  full detail (prompts, responses, file paths); the team's admins can read it\n" +
				"Undo any time: observer disconnect\n",
		},
		{
			name: "no local dashboard in this build", kind: "personal", target: "your personal dashboard",
			dashboard: func(string) string { return "" },
			want: "\nConnected: laptop -> your personal dashboard\n" +
				"Online dashboard  https://cloud.superbased.app\n" +
				"  a summary from each machine you connect\n" +
				"Undo any time: observer disconnect\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			printConnectedLines(&b, connectDeps{dashboardURL: tc.dashboard}, connectFlags{}, "laptop", tc.target, tc.kind, "https://cloud.superbased.app")
			if b.String() != tc.want {
				t.Fatalf("got:\n%s\nwant:\n%s", b.String(), tc.want)
			}
		})
	}
}

func TestConnectRequestJSONLinesAndNoBrowser(t *testing.T) {
	h := newConnectHarness()
	f := &requestFake{t: t, browser: true, polls: []connectApproval{approvedTeam("")}}
	out, errOut, err := h.execWith(t, h.withRequest(f), "--json", "--no-browser")
	if err != nil {
		t.Fatalf("connect --json: %v\n%s\n%s", err, out, errOut)
	}
	if len(f.opened) != 0 {
		t.Fatalf("--no-browser opened %v", f.opened)
	}
	var states []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("stdout line is not JSON: %q", line)
		}
		states = append(states, ev["state"].(string))
		if ev["state"] == "connected" && (ev["online_url"] != "https://acme.superbased.app" || ev["kind"] != "team" || ev["display_name"] != "Acme") {
			t.Fatalf("connected = %v", ev)
		}
		if ev["state"] == "waiting_approval" && (ev["user_code"] != "KTRW-4821" || ev["verify_url"] == "" || ev["approve_url"] == "") {
			t.Fatalf("waiting = %v", ev)
		}
	}
	if got := strings.Join(states, ","); got != "waiting_approval,approved,attaching,connected" {
		t.Fatalf("states = %s", got)
	}
	// No code: the attach falls back to the server's own sign-in.
	if h.run.enrollArgs[0] != "--idp" {
		t.Fatalf("enroll args = %v", h.run.enrollArgs)
	}
	if !strings.Contains(errOut, "KTRW-4821") {
		t.Fatalf("the code entry text belongs on stderr in --json mode: %q", errOut)
	}
}

func TestConnectRequestNotNowSignsInOnly(t *testing.T) {
	h := newConnectHarness()
	f := &requestFake{t: t, polls: []connectApproval{{Status: connectStatusApproved, SignedIn: true}}}
	out, _, err := h.execWith(t, h.withRequest(f), "--json")
	if err != nil {
		t.Fatalf("not now: %v", err)
	}
	if h.run.enrolled {
		t.Fatal("Not now attached the machine")
	}
	if !strings.Contains(out, `{"state":"approved","target":null}`) || !strings.Contains(out, `{"state":"signed_in_only"}`) {
		t.Fatalf("out = %s", out)
	}
}

func TestConnectRequestErrors(t *testing.T) {
	cases := []struct {
		name  string
		fake  requestFake
		code  string
		ident frontdoor.Identity
	}{
		{"declined", requestFake{polls: []connectApproval{{Status: connectStatusDeclined}}}, connectErrDeclined, frontdoor.IdentitySignedOut},
		{"expired", requestFake{polls: []connectApproval{{Status: connectStatusExpired}}}, connectErrExpired, frontdoor.IdentitySignedOut},
		{"gone", requestFake{pollErrs: []error{errConnectRequestGone}, polls: []connectApproval{{}}}, connectErrExpired, frontdoor.IdentitySignedOut},
		{"start failed", requestFake{startErr: errors.New("boom")}, connectErrRequestFailed, frontdoor.IdentitySignedOut},
		{"no sign-in", requestFake{polls: []connectApproval{{Status: connectStatusApproved}}}, connectErrSignIn, frontdoor.IdentitySignedOut},
		{"unsupported cloud", requestFake{startErr: errConnectUnsupported}, connectErrUnsupportedHere, frontdoor.IdentitySignedOut},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newConnectHarness()
			h.id = tc.ident
			f := tc.fake
			f.t = t
			out, _, err := h.execWith(t, h.withRequest(&f), "--json")
			if err == nil {
				t.Fatal("no error")
			}
			if !strings.Contains(out, `"state":"error"`) || !strings.Contains(out, `"code":"`+tc.code+`"`) {
				t.Fatalf("out = %s", out)
			}
			if h.run.enrolled {
				t.Fatal("attached after an error")
			}
		})
	}
}

func TestConnectRequestSlowDownBacksOff(t *testing.T) {
	h := newConnectHarness()
	f := &requestFake{t: t, pollErrs: []error{errConnectSlowDown, nil}, polls: []connectApproval{{}, {Status: connectStatusApproved, SignedIn: true}}}
	if _, _, err := h.execWith(t, h.withRequest(f)); err != nil {
		t.Fatal(err)
	}
	if len(f.slept) != 1 || f.slept[0] != 3*time.Second+connectRequestSlowDownStep {
		t.Fatalf("slept = %v", f.slept)
	}
}

func TestConnectRequestLockedMachineIsRefused(t *testing.T) {
	h := newConnectHarness()
	h.pol = lockedTo("https://corp.example.test")
	h.enr = enrolledIn("https://corp.example.test", "Corp", true)
	f := &requestFake{t: t, polls: []connectApproval{approvedTeam("CODE")}}
	// A bare team name on a machine company config pre-sets is ignored:
	// the company destination wins and SuperBased is never asked.
	_, _, _ = h.execWith(t, h.withRequest(f), "acme")
	if len(f.started) != 0 {
		t.Fatal("a company-configured machine asked superbased for a connect request")
	}
}

func TestConnectServerArgumentStillEnrolsDirectly(t *testing.T) {
	h := newConnectHarness()
	f := &requestFake{t: t}
	if _, _, err := h.execWith(t, h.withRequest(f), "https://observer.corp.example"); err != nil {
		t.Fatal(err)
	}
	if len(f.started) != 0 {
		t.Fatal("a server address started a connect request")
	}
	if !h.run.enrolled || h.run.enrollArgs[0] != "--idp" || h.run.enrollArgs[1] != "https://observer.corp.example" {
		t.Fatalf("enroll args = %v", h.run.enrollArgs)
	}
}

func TestConnectRequestResolvesTargetFromOrgList(t *testing.T) {
	h := newConnectHarness()
	h.disc = &discoveryFake{t: t, lists: [][]cloudcontract.DeviceOrg{{
		{OrgID: "org-p", Slug: "u-abcdefgh", Kind: cloudcontract.DeviceOrgPersonal, Status: cloudcontract.DeviceOrgActive, Tenancy: "individual", ServerURL: "https://u-abcdefgh.superbased.app"},
	}}}
	ap := connectApproval{
		Status: connectStatusApproved, SignedIn: true, ConsentReceiptID: "r",
		Target: &connectTargetInfo{OrgID: "org-p", Slug: "u-abcdefgh", Kind: "personal", ShareLevel: "summary"},
	}
	f := &requestFake{t: t, polls: []connectApproval{ap}}
	out, _, err := h.execWith(t, h.withRequest(f))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if h.run.enrollArgs[1] != "https://u-abcdefgh.superbased.app" {
		t.Fatalf("enroll args = %v", h.run.enrollArgs)
	}
	// Text never prints a personal dashboard's own address.
	if strings.Contains(out, "u-abcdefgh") {
		t.Fatalf("printed the personal dashboard's address:\n%s", out)
	}
	if !strings.Contains(out, "Connected: laptop -> your personal dashboard") {
		t.Fatalf("out = %s", out)
	}
	if !strings.Contains(out, "Online dashboard  https://cloud.superbased.app\n  a summary from each machine you connect\n") {
		t.Fatalf("the personal dashboard's role line is missing:\n%s", out)
	}
}

func TestIsConnectTeamSlug(t *testing.T) {
	for arg, want := range map[string]bool{
		"acme": true, "acme-eu": true, "a1": true,
		"https://acme.example": false, "acme.example.com": false, "host:8443": false, "Acme": false, "": false,
	} {
		if got := isConnectTeamSlug(arg); got != want {
			t.Errorf("isConnectTeamSlug(%q) = %t, want %t", arg, got, want)
		}
	}
}

// approvedTeamGrant is approvedTeam with an attach grant instead of a code.
func approvedTeamGrant(grant string) connectApproval {
	ap := approvedTeam("")
	ap.AttachGrant = grant
	return ap
}

// TestConnectRequestGrantAttachesWithNoSecondBrowserStep: an approval that
// carries an attach grant attaches with it on standard input
// (--attach-grant-file -), never with --idp, never printing it, and records
// the connection's name and online address.
func TestConnectRequestGrantAttachesWithNoSecondBrowserStep(t *testing.T) {
	h := newConnectHarness()
	f := &requestFake{t: t, browser: true, polls: []connectApproval{approvedTeamGrant("sbag1.GRANT.SIG")}}
	out, _, err := h.execWith(t, h.withRequest(f), "acme")
	if err != nil {
		t.Fatalf("connect acme: %v\n%s", err, out)
	}
	if len(h.run.enrollCalls) != 1 {
		t.Fatalf("attach attempts = %d, want 1", len(h.run.enrollCalls))
	}
	want := []string{"https://acme.superbased.app", "--attach-grant-file", "-"}
	if strings.Join(h.run.enrollArgs[:3], " ") != strings.Join(want, " ") || contains(h.run.enrollArgs, "--idp") {
		t.Fatalf("enroll args = %v", h.run.enrollArgs)
	}
	if h.run.enrollStdin != "sbag1.GRANT.SIG\n" {
		t.Fatalf("enroll stdin = %q", h.run.enrollStdin)
	}
	if strings.Contains(out, "sbag1") || strings.Contains(out, "own sign-in") {
		t.Fatalf("output printed the grant or a fallback note:\n%s", out)
	}
	if len(f.connections) != 1 || f.connections[0] != [3]string{"org-acme", "Acme", "https://acme.superbased.app"} {
		t.Fatalf("recorded connection = %v", f.connections)
	}
}

// TestConnectRequestGrantNotAcceptedFallsBackToSignIn: a target that does
// not take the grant (an older server, or one pinning no cloud key) is
// joined through its own sign-in, and the text says so.
func TestConnectRequestGrantNotAcceptedFallsBackToSignIn(t *testing.T) {
	h := newConnectHarness()
	h.run.enrollErrs = []error{fmt.Errorf("observer enroll: %w", orgclient.ErrAttachGrantNotAccepted)}
	f := &requestFake{t: t, polls: []connectApproval{approvedTeamGrant("sbag1.GRANT.SIG")}}
	out, _, err := h.execWith(t, h.withRequest(f), "acme")
	if err != nil {
		t.Fatalf("connect acme: %v\n%s", err, out)
	}
	if len(h.run.enrollCalls) != 2 || h.run.enrollCalls[1].args[0] != "--idp" || h.run.enrollCalls[1].stdin != "" {
		t.Fatalf("attach attempts = %+v", h.run.enrollCalls)
	}
	if !strings.Contains(out, "Acme does not take the one-step approval yet; finishing with its own sign-in.") {
		t.Fatalf("no fallback note:\n%s", out)
	}
}

// TestConnectRequestGrantRefusedIsAnAttachFailure: a grant the target checked
// and refused is not retried through another rail; contract B reports
// attach_failed with the reason.
func TestConnectRequestGrantRefusedIsAnAttachFailure(t *testing.T) {
	h := newConnectHarness()
	h.run.enrollErrs = []error{fmt.Errorf("observer enroll: %w: your account is not a member of this team", orgclient.ErrAttachGrantRefused)}
	f := &requestFake{t: t, polls: []connectApproval{approvedTeamGrant("sbag1.GRANT.SIG")}}
	out, _, err := h.execWith(t, h.withRequest(f), "--json", "acme")
	if err == nil {
		t.Fatal("a refused grant succeeded")
	}
	if len(h.run.enrollCalls) != 1 {
		t.Fatalf("attach attempts = %d, want 1 (no fallback after a refusal)", len(h.run.enrollCalls))
	}
	if !strings.Contains(out, `"code":"attach_failed"`) || !strings.Contains(out, "not a member of this team") {
		t.Fatalf("out = %s", out)
	}
}

// TestConnectRequestWithoutGrantSaysItFallsBack: an older cloud sends no
// grant and no code; the text says the attach finishes with the
// dashboard's own sign-in.
func TestConnectRequestWithoutGrantSaysItFallsBack(t *testing.T) {
	h := newConnectHarness()
	f := &requestFake{t: t, polls: []connectApproval{approvedTeam("")}}
	out, _, err := h.execWith(t, h.withRequest(f), "acme")
	if err != nil {
		t.Fatalf("connect acme: %v\n%s", err, out)
	}
	if h.run.enrollArgs[0] != "--idp" {
		t.Fatalf("enroll args = %v", h.run.enrollArgs)
	}
	if !strings.Contains(out, "sent no one-step approval; finishing with the dashboard's own sign-in") {
		t.Fatalf("no fallback note:\n%s", out)
	}
}

// TestConnectAttachRules is one case per connectAttachRules row.
func TestConnectAttachRules(t *testing.T) {
	cases := []struct {
		ap   connectApproval
		want connectAttachVia
	}{
		{ap: connectApproval{AttachGrant: "g", EnrolCode: "c"}, want: attachViaGrant},
		{ap: connectApproval{EnrolCode: "c"}, want: attachViaCode},
		{ap: connectApproval{}, want: attachViaIdP},
	}
	for _, tc := range cases {
		if got := connectAttachFor(tc.ap); got != tc.want {
			t.Errorf("connectAttachFor(%+v) = %v, want %v", tc.ap, got, tc.want)
		}
	}
}
