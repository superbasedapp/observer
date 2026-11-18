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
