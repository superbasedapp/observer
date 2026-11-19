package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
	"github.com/marmutapp/superbased-observer/internal/termcore"
)

// needsBody is the part of a "needs a setting" refusal every client reads.
type needsBody struct {
	Error         string `json:"error"`
	Message       string `json:"message"`
	Settings      string `json:"settings"`
	SettingsLabel string `json:"settings_label"`
	Command       string `json:"command"`
	Component     string `json:"component"`
}

func decodeNeeds(t *testing.T, rec *httptest.ResponseRecorder) needsBody {
	t.Helper()
	var b needsBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("body is not JSON: %v: %s", err, rec.Body.String())
	}
	return b
}

func placeHref(t *testing.T, p settingslink.Place) string {
	t.Helper()
	l, ok := settingslink.For(p)
	if !ok {
		t.Fatalf("place %q not in the table", p)
	}
	return l.Href
}

// TestNeedsSettingWriters is one case per writer: the status, the error
// value older clients read (unchanged), a plain message, and the deep link
// from the one table. A writer whose fix is not a setting carries no link.
func TestNeedsSettingWriters(t *testing.T) {
	cases := []struct {
		name       string
		write      func(w http.ResponseWriter)
		status     int
		wantError  string
		wantPlace  settingslink.Place // "" = no link
		wantNoLink bool
	}{
		{"guided install off", writeGuidedInstallOff, http.StatusForbidden, errGuidedInstallOff, settingslink.TerminalLaunchPolicy, false},
		{"guided uninstall off", writeGuidedUninstallOff, http.StatusForbidden, errGuidedUninstallOff, settingslink.TerminalLaunchPolicy, false},
		{"terminal off", func(w http.ResponseWriter) { writeTerminalUnavailable(w, "") }, http.StatusServiceUnavailable, errTerminalUnavailable, settingslink.SessionAttach, false},
		{"launch terminal off", func(w http.ResponseWriter) { writeTerminalUnavailable(w, "launch unavailable: ") }, http.StatusServiceUnavailable, "launch unavailable: " + errTerminalUnavailable, settingslink.SessionAttach, false},
		{"terminal off with an alternative", func(w http.ResponseWriter) { writeTerminalUnavailableOr(w, "x", "Or do it yourself.") }, http.StatusServiceUnavailable, "x", settingslink.SessionAttach, false},
		{"sandbox setup install off", func(w http.ResponseWriter) {
			writeSandboxSetupCode(w, http.StatusForbidden, dashapi.SandboxSetupCodeInstallDisabled, "guided installs are turned off", nil)
		}, http.StatusForbidden, "guided installs are turned off", settingslink.TerminalLaunchPolicy, false},
		{"sandbox setup elevation off", func(w http.ResponseWriter) {
			writeSandboxSetupCode(w, http.StatusForbidden, dashapi.SandboxSetupCodeElevationDisabled, "elevated steps are off", nil)
		}, http.StatusForbidden, "elevated steps are off", settingslink.TerminalSandbox, false},
		{"sandbox setup plan changed", func(w http.ResponseWriter) {
			writeSandboxSetupCode(w, http.StatusConflict, dashapi.SandboxSetupCodePlanChanged, "the plan changed", nil)
		}, http.StatusConflict, "the plan changed", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.write(rec)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			b := decodeNeeds(t, rec)
			if b.Error != tc.wantError {
				t.Fatalf("error = %q, want %q", b.Error, tc.wantError)
			}
			if tc.wantNoLink {
				if b.Settings != "" || b.SettingsLabel != "" {
					t.Fatalf("a refusal not fixed by a setting carries a link: %+v", b)
				}
				return
			}
			if b.Settings != placeHref(t, tc.wantPlace) || b.SettingsLabel == "" || b.Message == "" {
				t.Fatalf("body = %+v, want the %s link and a message", b, tc.wantPlace)
			}
		})
	}
}

// TestCompiledOutCarriesComponentLink: a compiled-out component's 404 opens
// its row on Settings > Components and offers no command (it cannot be
// added in this build).
func TestCompiledOutCarriesComponentLink(t *testing.T) {
	b := compiledOutBody("codeintel")
	if b.Settings != settingslink.Component("codeintel").Href || b.Command != "" {
		t.Fatalf("compiled-out link = %+v", b.Fields)
	}
}

// TestGuidedInstallIsNotGatedOnRemote pins the operator report (2026-11-18):
// clicking Install for pi in the New Terminal popover showed a raw, cut-off
// component_not_installed body for the REMOTE component. The install route
// itself belongs to terminals; the refusal came from the confirm-token read
// the popover made from /api/remote/config, a route of the Remote dashboard
// component, which is off by default in the developer edition. The popover
// now reads its token from the core command-job list (/api/jobs), which no
// component turns off. Rows: the route each step of the install flow
// reaches, and the component that owns it.
func TestGuidedInstallIsNotGatedOnRemote(t *testing.T) {
	cases := []struct {
		route, owner string
	}{
		{"/api/terminal/install", "terminals"},
		{"/api/terminal/installs", "terminals"},
		{"/api/terminal/uninstall", "terminals"},
		// The confirm-token source of every owner-local write.
		{"/api/jobs", coreComponent},
		// The old token source: a Remote dashboard route, never to be read
		// by a local write.
		{"/api/remote/config", "remote"},
	}
	for _, tc := range cases {
		if got := routeComponent(tc.route); got != tc.owner {
			t.Errorf("routeComponent(%q) = %q, want %q", tc.route, got, tc.owner)
		}
	}

	// With the Remote dashboard turned off, the token source still answers
	// and mints the cookie, and the remote route's refusal carries the deep
	// link to its own row (so even a surface that does hit it can say what
	// to turn on and where).
	svc, _ := componentsTestService(t, "[components]\nremove = [\"remote\"]\n")
	s := newRemoteTestServer(t, Options{Components: svc})
	h := s.guardedHandler("127.0.0.1:8081")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/jobs?mode=confirm-mint"))
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/jobs with remote off = %d %s", rec.Code, rec.Body.String())
	}
	var jobs struct {
		ConfirmToken string `json:"confirm_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &jobs); err != nil || jobs.ConfirmToken == "" {
		t.Fatalf("/api/jobs minted no confirm token: %v %s", err, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/remote/config"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/api/remote/config with remote off = %d %s", rec.Code, rec.Body.String())
	}
	b := decodeNeeds(t, rec)
	// A build that compiles remote out answers the stub's body: the same
	// link, and no command (it cannot be added in that build).
	wantCommand := "observer components add remote --yes"
	if compiledOutInTest("remote") {
		wantCommand = ""
	}
	if b.Error != "component_not_installed" || b.Component != "remote" ||
		b.Settings != "/settings/components?component=remote" || b.SettingsLabel != "Settings > Components" ||
		b.Command != wantCommand || b.Message == "" {
		t.Fatalf("remote refusal = %+v", b)
	}
}

// TestSettingRefusals is one case per settingRefusals row (dead-end sweep,
// 2026-11-18): the route's error text stays as it was (wrapped sentinels
// included), the sentence names the switch, and the link is the row's.
func TestSettingRefusals(t *testing.T) {
	cases := []struct {
		err       error
		place     settingslink.Place
		component string
	}{
		{ErrLaunchFreshDisabled, settingslink.TerminalLaunchPolicy, ""},
		{ErrLaunchShellDisabled, settingslink.TerminalLaunchPolicy, ""},
		{ErrLaunchToolNotAllowed, settingslink.TerminalLaunchPolicy, ""},
		{ErrLaunchSSHDisabled, settingslink.TerminalRemoteSystems, ""},
		{ErrInstancesDisabled, settingslink.TerminalRemoteSystems, ""},
		{dashapi.ErrExplainNotSelected, "", "security.feedback"},
	}
	if len(cases) != len(settingRefusals) {
		t.Fatalf("table has %d rows, test covers %d", len(settingRefusals), len(cases))
	}
	for _, c := range cases {
		t.Run(c.err.Error(), func(t *testing.T) {
			wrapped := fmt.Errorf("termsvc: %w", c.err)
			rec := httptest.NewRecorder()
			if !writeSettingRefusal(rec, wrapped, http.StatusForbidden) {
				t.Fatal("no row matched")
			}
			b := decodeNeeds(t, rec)
			if rec.Code != http.StatusForbidden || b.Error != wrapped.Error() || b.Message == "" {
				t.Fatalf("got %d %+v", rec.Code, b)
			}
			want := settingslink.Component(c.component).Href
			if c.component == "" {
				want = placeHref(t, c.place)
			}
			if b.Settings != want {
				t.Fatalf("settings = %q, want %q", b.Settings, want)
			}
		})
	}
	if writeSettingRefusal(httptest.NewRecorder(), errors.New("other"), http.StatusForbidden) {
		t.Fatal("an unrelated error matched a row")
	}
}

// TestSandboxUnavailableLink: only a verdict this machine can lift links to
// Sandbox isolation; the platform and build verdicts stay plain text.
func TestSandboxUnavailableLink(t *testing.T) {
	cases := []struct {
		verdict string
		link    bool
	}{
		{"disabled_by_config", true},
		{"backend_missing", true},
		{"backend_too_old", true},
		{"unsupported_platform", false},
		{"userns_denied", false},
		{VerdictNotInBuild, false},
		{"custody_unsatisfiable", true},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		writeSandboxUnavailable(rec, "sandbox unavailable ("+c.verdict+"): r", c.verdict, "r")
		if rec.Code != statusForSandboxVerdict(c.verdict) {
			t.Fatalf("%s: status %d", c.verdict, rec.Code)
		}
		if !c.link {
			if strings.Contains(rec.Body.String(), "settings") {
				t.Fatalf("%s: unexpected link %s", c.verdict, rec.Body.String())
			}
			continue
		}
		if b := decodeNeeds(t, rec); b.Settings != placeHref(t, settingslink.TerminalSandbox) || b.Error != "sandbox unavailable ("+c.verdict+"): r" {
			t.Fatalf("%s: %+v", c.verdict, b)
		}
	}
}

// TestSandboxCustodyReasonIsTheSentence: the custody verdict's probe reason
// is a whole plain sentence, said as it is with the place after it, never
// after "The sandbox cannot start on this machine:".
func TestSandboxCustodyReasonIsTheSentence(t *testing.T) {
	rec := httptest.NewRecorder()
	reason := "The agent's model key is set to stay on this machine. Choose how the agent gets its model key."
	writeSandboxUnavailable(rec, "sandbox backend daytona unavailable (custody_unsatisfiable): x", "custody_unsatisfiable", reason)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d", rec.Code)
	}
	b := decodeNeeds(t, rec)
	if !strings.HasPrefix(b.Message, reason) || strings.Contains(b.Message, "cannot start on this machine:") {
		t.Fatalf("message %q", b.Message)
	}
}

// TestSandboxStepRefusalBody: a typed step refusal answers 409 with the
// closed code, the plain sentence and the link, and keeps the technical
// detail in its own field (a surface shows it only as technical details).
func TestSandboxStepRefusalBody(t *testing.T) {
	rec := httptest.NewRecorder()
	writeSandboxStepRefusal(rec, &dashapi.SandboxStepRefusal{Code: "custody_unsatisfiable", Message: "Choose how the agent gets its model key.", Technical: "nothing_serves_home_key: key custody home_relay needs a key the proxy adds itself"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d", rec.Code)
	}
	var b settingslink.Body
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.Error != "custody_unsatisfiable" || !strings.HasPrefix(b.Message, "Choose how") || strings.Contains(b.Message, "home_relay") {
		t.Fatalf("body %+v", b)
	}
	if !strings.Contains(b.Technical, "home_relay") || b.Settings != placeHref(t, settingslink.TerminalSandbox) {
		t.Fatalf("body %+v", b)
	}
}

// TestSandboxConsentRefusalBody: a hosted launch refused for a changed
// consent (the live-run report: the upload scope changed) answers 409 with
// the closed code, the row and the verdict, so the New Terminal dialog can
// show the consent again; the raw sentence stays only in Technical. The
// refusal reaches the handler wrapped the way termsvc wraps it, so the
// consent case must win over the workspace-preparation 500.
func TestSandboxConsentRefusalBody(t *testing.T) {
	cases := []struct {
		name, verdict, msgPrefix string
	}{
		{"changed scope", "consent_changed_scope", "What this launch sends"},
		{"missing", "consent_required", "Agree to what this launch sends"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			refusal := &dashapi.SandboxConsentRefusal{Provider: "daytona", Verdict: c.verdict}
			wrapped := fmt.Errorf("%w: %w", termcore.ErrWorkspacePrepFailed, refusal)
			s := newLaunchTestServer(t, &fakeLaunchManager{freshErr: wrapped})
			rec := postTerminalLaunch(t, s.Handler(), "claude-code", "")
			if rec.Code != http.StatusConflict {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
			var b struct {
				settingslink.Body
				Provider string `json:"provider"`
				Verdict  string `json:"verdict"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
				t.Fatal(err)
			}
			if b.Error != dashapi.SandboxConsentRefusalCode || b.Provider != "daytona" || b.Verdict != c.verdict {
				t.Fatalf("body %+v", b)
			}
			if !strings.HasPrefix(b.Message, c.msgPrefix) || strings.Contains(b.Message, "consent_") || strings.Contains(b.Message, "termsvc") {
				t.Fatalf("message %q", b.Message)
			}
			if !strings.Contains(b.Technical, c.verdict) || b.Settings != placeHref(t, settingslink.TerminalSandboxHosted) {
				t.Fatalf("body %+v", b)
			}
		})
	}
	// The CLI and log wording is unchanged by the type.
	e := &dashapi.SandboxConsentRefusal{Provider: "e2b", Verdict: "consent_changed_scope"}
	if !strings.HasPrefix(e.Error(), "terminal_sandbox: consent_required (consent_changed_scope): review what leaves this machine") || !strings.Contains(e.Error(), "observer sandbox hosted consent e2b") {
		t.Fatalf("Error() = %q", e.Error())
	}
	if !errors.As(fmt.Errorf("x: %w", e), new(*dashapi.SandboxConsentRefusal)) {
		t.Fatal("not unwrappable")
	}
}
