package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sshLaunchManager is a fakeLaunchManager that ALSO satisfies the optional
// sshLauncher seam. Keeping it separate from fakeLaunchManager is the point of
// the optional-interface design: the dozens of existing fakes that do NOT
// implement it must keep compiling and must degrade honestly.
type sshLaunchManager struct {
	fakeLaunchManager
	enabled  bool
	profiles []SSHProfileInfo
	lastSpec SSHLaunchSpec
	calls    int
	err      error
}

func (m *sshLaunchManager) CreateSSH(spec SSHLaunchSpec) (string, error) {
	m.calls++
	m.lastSpec = spec
	if m.err != nil {
		return "", m.err
	}
	return "SSH-token", nil
}

func (m *sshLaunchManager) SSHProfiles() (bool, []SSHProfileInfo) {
	return m.enabled, m.profiles
}

func newSSHManager() *sshLaunchManager {
	return &sshLaunchManager{
		enabled: true,
		profiles: []SSHProfileInfo{
			{Name: "demo-box", Label: "Client demo", Target: "ubuntu@demo.example.com:2222", HasKey: true, KeyHint: "id_demo"},
		},
	}
}

// TestSSHProfiles_Listed pins the picker payload.
func TestSSHProfiles_Listed(t *testing.T) {
	t.Parallel()
	s := newLaunchTestServer(t, newSSHManager())
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/terminal/ssh", nil))
	if rr.Code != 200 {
		t.Fatalf("GET /api/terminal/ssh = %d: %s", rr.Code, rr.Body)
	}
	var resp sshProfilesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Enabled || len(resp.Profiles) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Profiles[0].KeyHint != "id_demo" {
		t.Errorf("key hint = %q", resp.Profiles[0].KeyHint)
	}
	// The full key PATH must never appear in the payload — the picker gets a
	// basename so the dashboard does not disclose the filesystem layout.
	if strings.Contains(rr.Body.String(), "/") && strings.Contains(rr.Body.String(), ".ssh/") {
		t.Errorf("payload leaked a key path: %s", rr.Body)
	}
}

// TestSSHProfiles_FailSoftWhenUnwired pins the honest-absent degrade: a daemon
// whose LaunchManager does NOT implement the optional seam answers 200 with
// enabled:false, so the New Terminal dialog simply omits the system selector
// instead of rendering an error.
func TestSSHProfiles_FailSoftWhenUnwired(t *testing.T) {
	t.Parallel()
	// A plain fakeLaunchManager — deliberately NOT an sshLauncher.
	s := newLaunchTestServer(t, &fakeLaunchManager{})
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/terminal/ssh", nil))
	if rr.Code != 200 {
		t.Fatalf("GET = %d, want a fail-soft 200: %s", rr.Code, rr.Body)
	}
	var resp sshProfilesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Enabled {
		t.Error("an unwired daemon reported the SSH feature as enabled")
	}
	if resp.Profiles == nil {
		t.Error("profiles marshalled as null; want [] so the client can iterate")
	}
}

// TestSSHLaunch_Success pins that ONLY a profile name crosses the seam.
func TestSSHLaunch_Success(t *testing.T) {
	t.Parallel()
	lm := newSSHManager()
	s := newLaunchTestServer(t, lm)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/terminal/ssh", strings.NewReader(`{"profile":"demo-box"}`))
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("POST = %d: %s", rr.Code, rr.Body)
	}
	var resp sshLaunchResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token != "SSH-token" || resp.Tool != "ssh" || resp.Profile != "demo-box" {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Label != "Client demo" {
		t.Errorf("label = %q — the tab header must name the system", resp.Label)
	}
	if lm.lastSpec.Profile != "demo-box" {
		t.Fatalf("spec = %+v", lm.lastSpec)
	}
}

// TestSSHLaunch_IgnoresClientSuppliedConnectionFields is the core security pin:
// a body that tries to smuggle host/user/key/port must have those fields
// SILENTLY DROPPED at the JSON boundary, because the request type has exactly
// one field. If someone ever widens sshLaunchRequest, this fails.
func TestSSHLaunch_IgnoresClientSuppliedConnectionFields(t *testing.T) {
	t.Parallel()
	lm := newSSHManager()
	s := newLaunchTestServer(t, lm)
	body := `{"profile":"demo-box","host":"evil.example.com","user":"root","port":2200,` +
		`"key_path":"/etc/shadow","jump":"evil","argv":["ssh","evil"],"ssh_argv":["ssh","evil"]}`
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/terminal/ssh", strings.NewReader(body)))
	if rr.Code != 200 {
		t.Fatalf("POST = %d: %s", rr.Code, rr.Body)
	}
	if lm.lastSpec.Profile != "demo-box" {
		t.Fatalf("profile = %q", lm.lastSpec.Profile)
	}
	// SSHLaunchSpec has no connection fields at all, so there is nothing an
	// extra JSON key could land in. Assert the spec is exactly what we expect.
	if lm.lastSpec != (SSHLaunchSpec{Profile: "demo-box"}) {
		t.Fatalf("client-supplied connection data reached the spec: %+v", lm.lastSpec)
	}
}

// TestSSHLaunch_ErrorMapping pins the fail-CLOSED statuses. There is no
// "connect anyway" degradation: the caller named a machine, and reaching a
// different one — or none — silently would be worse than refusing.
func TestSSHLaunch_ErrorMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"feature disabled", ErrLaunchSSHDisabled, http.StatusForbidden},
		{"unknown profile", ErrLaunchSSHProfileUnknown, http.StatusBadRequest},
		{"invalid profile", ErrLaunchSSHProfileInvalid, http.StatusBadRequest},
		{"too many sessions", ErrLaunchTooMany, http.StatusTooManyRequests},
		{"platform unsupported", ErrLaunchUnsupported, http.StatusNotImplemented},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lm := newSSHManager()
			lm.err = tc.err
			s := newLaunchTestServer(t, lm)
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/terminal/ssh", strings.NewReader(`{"profile":"demo-box"}`)))
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tc.want, rr.Body)
			}
		})
	}
}

// TestSSHLaunch_RejectsEmptyProfile pins that a missing name is a 400 and never
// falls through to "the first configured profile".
func TestSSHLaunch_RejectsEmptyProfile(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{}`, `{"profile":""}`, `{"profile":"   "}`} {
		lm := newSSHManager()
		s := newLaunchTestServer(t, lm)
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/terminal/ssh", strings.NewReader(body)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("body %s → %d, want 400", body, rr.Code)
		}
		if lm.calls != 0 {
			t.Fatalf("body %s reached the launcher", body)
		}
	}
}

// TestSSHLaunch_Unwired pins the 501 when the daemon has no SSH seam.
func TestSSHLaunch_Unwired(t *testing.T) {
	t.Parallel()
	s := newLaunchTestServer(t, &fakeLaunchManager{})
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/terminal/ssh", strings.NewReader(`{"profile":"x"}`)))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501: %s", rr.Code, rr.Body)
	}
}

// TestSSHRouteIsLocalOnly pins the route CLASSIFICATION (plan §6.2). Both verbs
// must be CapabilityLocal — refused over the remote-exposed listener — because
// GET discloses internal hostnames and POST opens a shell on a third-party
// machine. Expressing that as route class (rather than an in-handler check)
// is what stops a future refactor silently dropping it.
func TestSSHRouteIsLocalOnly(t *testing.T) {
	t.Parallel()
	s := newLaunchTestServer(t, newSSHManager())
	_, capMap, _ := s.registerRoutes(nil)
	got, ok := capMap["/api/terminal/ssh"]
	if !ok {
		t.Fatal("/api/terminal/ssh is not in the route-capability registry")
	}
	if got != CapabilityLocal {
		t.Fatalf("/api/terminal/ssh capability = %v, want CapabilityLocal — an SSH shell into a third-party machine must not be remote-drivable", got)
	}
	// Contrast pin: the ordinary terminal launch really is EXECUTE, so this
	// test asserts a genuine difference rather than a tautology.
	if launchCap, ok := capMap["/api/terminal/launch"]; !ok || launchCap != CapabilityExecute {
		t.Fatalf("/api/terminal/launch capability = %v, want CapabilityExecute (the class this test contrasts against)", launchCap)
	}
}
