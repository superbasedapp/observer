package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/govern"
)

// componentsWriteRoutes is the pin row set of the Settings > Components
// writes: every one is Local, SectionNone and refuses a request without the
// confirm token.
var componentsWriteRoutes = []string{
	"/api/components/preview",
	"/api/components/apply",
	"/api/components/teardown",
	"/api/components/purge/preview",
	"/api/components/purge/execute",
}

// componentsTestService builds a real componentsvc.Service over a throwaway
// config.toml holding block (no teardown, no purge store: nothing outside
// the temp dir can be touched).
func componentsTestService(t *testing.T, block string) (*componentsvc.Service, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(block), 0o600); err != nil {
		t.Fatal(err)
	}
	svc, err := componentsvc.New(componentsvc.Options{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	return svc, path
}

const testConfirm = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func componentsPost(h http.Handler, path, body string, withToken bool) *httptest.ResponseRecorder {
	req := loopbackRequest(http.MethodPost, path)
	req.Body = http.NoBody
	if body != "" {
		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Host = "127.0.0.1:8081"
		req.Header.Set("Origin", "http://127.0.0.1:8081")
	}
	req.Header.Set("Content-Type", "application/json")
	if withToken {
		req.Header.Set(remoteConfirmHeader, testConfirm)
		req.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: testConfirm})
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestComponentGuardOffWithoutService: no service wired means no route is
// gated, so every existing embedder answers exactly as before.
func TestComponentGuardOffWithoutService(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	rec := httptest.NewRecorder()
	s.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/shell-wrap/status"))
	// In a build without shell-wrap the route's own stub answers not_compiled
	// (D-535); that is the build, not the guard gating.
	if strings.Contains(rec.Body.String(), componentstate.NotActiveError) && !answeredCompiledOut(rec.Code, rec.Body.Bytes()) {
		t.Fatalf("an unwired dashboard gated a route: %d %s", rec.Code, rec.Body.String())
	}
}

// TestComponentGuardLegacyConfigGatesNothing: a wired service over a config
// with no [components] block resolves every component active.
func TestComponentGuardLegacyConfigGatesNothing(t *testing.T) {
	svc, _ := componentsTestService(t, "")
	s := newRemoteTestServer(t, Options{Components: svc})
	rec := httptest.NewRecorder()
	s.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/shell-wrap/status"))
	if strings.Contains(rec.Body.String(), componentstate.NotActiveError) && !answeredCompiledOut(rec.Code, rec.Body.Bytes()) {
		t.Fatalf("legacy config gated a route: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/components/state"))
	var st componentsStateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Wired || st.View.Configured || len(st.InactiveRoutes) != 0 || len(st.Pending) != 0 {
		t.Fatalf("legacy state = %+v", st)
	}
}

// TestComponentGuardAnswersNotInstalled: a route of an inactive component
// answers 404 with the shared NotActiveBody (plan 7.3), and the state read
// lists the route so the SPA skips it.
func TestComponentGuardAnswersNotInstalled(t *testing.T) {
	svc, _ := componentsTestService(t, "[components]\nremove = [\"integration.shell-wrap\"]\n")
	s := newRemoteTestServer(t, Options{Components: svc})
	h := s.guardedHandler("127.0.0.1:8081")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/shell-wrap/status"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("inactive route = %d %s", rec.Code, rec.Body.String())
	}
	var body componentstate.NotActiveBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != componentstate.NotActiveError || body.Component != "integration.shell-wrap" ||
		body.State != components.StateAvailable || !strings.Contains(body.Message, "Settings > Components") {
		t.Fatalf("body = %+v", body)
	}
	// A core route is never gated.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/governance"))
	if rec.Code != http.StatusOK {
		t.Fatalf("core route = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/components/state"))
	var st componentsStateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.View.Configured || !containsStr(st.InactiveRoutes, "/api/shell-wrap/status") {
		t.Fatalf("state = configured %v inactive %v", st.View.Configured, st.InactiveRoutes)
	}
	if containsStr(st.InactiveRoutes, "/api/governance") {
		t.Fatal("a core route was listed inactive")
	}
}

// TestComponentsApplyFlow drives preview -> apply with the fingerprint, then
// a stale fingerprint, and checks the pending-restart report and that the
// guard follows the new selection at once.
func TestComponentsApplyFlow(t *testing.T) {
	svc, path := componentsTestService(t, "# kept comment\n")
	s := newRemoteTestServer(t, Options{Components: svc})
	h := s.guardedHandler("127.0.0.1:8081")

	rr := componentsPost(h, "/api/components/preview", `{"change":{"remove":["integration.shell-wrap"]}}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("preview = %d %s", rr.Code, rr.Body.String())
	}
	var p componentsvc.Preview
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Fingerprint == "" || !containsStr(p.Deactivated, "integration.shell-wrap") {
		t.Fatalf("preview = %+v", p)
	}
	// No fingerprint: refused, nothing written.
	if rr := componentsPost(h, "/api/components/apply", `{"change":{"remove":["integration.shell-wrap"]}}`, true); rr.Code != http.StatusBadRequest {
		t.Fatalf("apply without fingerprint = %d", rr.Code)
	}
	// Wrong fingerprint: stale.
	if rr := componentsPost(h, "/api/components/apply", `{"change":{"remove":["integration.shell-wrap"]},"fingerprint":"nope"}`, true); rr.Code != http.StatusConflict ||
		!strings.Contains(rr.Body.String(), "stale_preview") {
		t.Fatalf("stale apply = %d %s", rr.Code, rr.Body.String())
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "[components]") {
		t.Fatal("a refused apply wrote the block")
	}
	rr = componentsPost(h, "/api/components/apply", `{"change":{"remove":["integration.shell-wrap"]},"fingerprint":"`+p.Fingerprint+`"}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("apply = %d %s", rr.Code, rr.Body.String())
	}
	raw, _ = os.ReadFile(path)
	if !strings.Contains(string(raw), "integration.shell-wrap") || !strings.Contains(string(raw), "# kept comment") {
		t.Fatalf("config after apply:\n%s", raw)
	}
	// The guard follows at once (the apply invalidated the cache).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/shell-wrap/status"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("route after removal = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/components/state"))
	var st componentsStateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Pending) != 1 || st.Pending[0] != (componentPending{ID: "integration.shell-wrap", Change: "deactivate"}) {
		t.Fatalf("pending = %+v", st.Pending)
	}
}

// TestComponentsWritesRequireConfirmToken: every write refuses a missing
// token (403), a non-JSON body (415) and a GET (405) before the service.
func TestComponentsWritesRequireConfirmToken(t *testing.T) {
	svc, path := componentsTestService(t, "")
	s := newRemoteTestServer(t, Options{Components: svc})
	h := s.guardedHandler("127.0.0.1:8081")
	for _, p := range componentsWriteRoutes {
		if rr := componentsPost(h, p, `{}`, false); rr.Code != http.StatusForbidden {
			t.Errorf("%s without token = %d, want 403", p, rr.Code)
		}
		req := httptest.NewRequest(http.MethodPost, p, strings.NewReader("x"))
		req.Host = "127.0.0.1:8081"
		req.Header.Set("Origin", "http://127.0.0.1:8081")
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set(remoteConfirmHeader, testConfirm)
		req.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: testConfirm})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%s text/plain = %d, want 415", p, rr.Code)
		}
		get := httptest.NewRecorder()
		h.ServeHTTP(get, loopbackRequest(http.MethodGet, p))
		if get.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", p, get.Code)
		}
	}
	raw, _ := os.ReadFile(path)
	if len(raw) != 0 {
		t.Fatalf("a refused request wrote config: %q", raw)
	}
}

// TestComponentsRoutesClassification pins capability and section: the state
// read is View, every write Local, all SectionNone, so governance can never
// hide the page every NotInstalled state points at.
func TestComponentsRoutesClassification(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	_, caps, sections := s.registerRoutes(nil)
	if caps["/api/components/state"] != CapabilityView {
		t.Errorf("state capability = %v", caps["/api/components/state"])
	}
	for _, p := range append([]string{"/api/components/state"}, componentsWriteRoutes...) {
		if sections[p] != SectionNone {
			t.Errorf("%s section = %v, want SectionNone", p, sections[p])
		}
	}
	for _, p := range componentsWriteRoutes {
		if caps[p] != CapabilityLocal {
			t.Errorf("%s capability = %v, want Local", p, caps[p])
		}
	}
	// Governance that hides every hideable section still serves the state.
	eff := govern.Effective{
		Active: true, State: govern.StateApplied, Version: 3,
		HiddenSections: []string{"settings", "privacy", "terminals", "security"},
	}
	gs := newRemoteTestServer(t, Options{Governance: func(context.Context) govern.Effective { return eff }})
	rec := httptest.NewRecorder()
	gs.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/components/state"))
	if rec.Code != http.StatusOK {
		t.Fatalf("state under governance = %d", rec.Code)
	}
}

// TestComponentsUnwiredAnswers503: without a service the writes say so.
func TestComponentsUnwiredAnswers503(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	h := s.guardedHandler("127.0.0.1:8081")
	if rr := componentsPost(h, "/api/components/preview", `{"change":{}}`, true); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired preview = %d", rr.Code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/components/state"))
	var st componentsStateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Wired || st.View.CompiledCount == 0 {
		t.Fatalf("unwired state = wired %v compiled %d", st.Wired, st.View.CompiledCount)
	}
}

// TestComponentsPurgeWithoutStore: a service without a purge store answers
// 503 purge_unavailable, never a fake plan.
func TestComponentsPurgeWithoutStore(t *testing.T) {
	svc, _ := componentsTestService(t, "[components]\nremove = [\"adapter.zed\"]\n")
	s := newRemoteTestServer(t, Options{Components: svc})
	h := s.guardedHandler("127.0.0.1:8081")
	rr := componentsPost(h, "/api/components/purge/preview", `{"component":"adapter.zed"}`, true)
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "purge_unavailable") {
		t.Fatalf("purge preview = %d %s", rr.Code, rr.Body.String())
	}
	if rr := componentsPost(h, "/api/components/purge/execute", `{"plan_id":""}`, true); rr.Code != http.StatusBadRequest {
		t.Fatalf("execute without plan id = %d", rr.Code)
	}
}

// TestEveryRegisteredRouteHasAKnownComponent (plan 3.2 item 4): every
// registered route resolves to core or a catalogued node component.
func TestEveryRegisteredRouteHasAKnownComponent(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	s.registerRoutes(nil)
	m := s.routeComponents.Load()
	if m == nil || len(*m) == 0 {
		t.Fatal("no route components recorded")
	}
	for pattern, id := range *m {
		if id == coreComponent {
			continue
		}
		c, ok := components.Get(id)
		if !ok || c.Binary != components.BinaryNode {
			t.Errorf("route %s names %q, which is not a node component", pattern, id)
		}
	}
}

// TestRoutePrefixOwnersAreRegistered: every catalog route prefix (the
// former override rows now live in the catalog, T-670) owns at least one
// registered route (or a Plane A ExtraRoute prefix), so a stale row fails
// here.
func TestRoutePrefixOwnersAreRegistered(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	_, caps, _ := s.registerRoutes(nil)
	// ExtraRoutes registered only by the obs wiring.
	extraOnly := map[string]bool{"/api/obs": true}
	for prefix := range routePrefixOwners() {
		if extraOnly[prefix] {
			continue
		}
		found := false
		for pattern := range caps {
			if pathHasPrefix(strings.TrimSuffix(pattern, "/"), prefix) || pathHasPrefix(pattern, prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("route prefix %s owns no registered route", prefix)
		}
	}
}

// TestRouteComponentResolution pins the resolver's table rows.
func TestRouteComponentResolution(t *testing.T) {
	for _, tc := range []struct{ pattern, want string }{
		{"/api/status", "ui.dashboard"},
		{"/api/governance", "core"},
		{"/api/cache/status", "analytics"},
		{"/api/terminal/launch", "terminals"},
		{"/api/terminal/ssh/profiles", "terminals.ssh"},
		{"/api/terminal/sandbox/config", "terminals.sandbox"},
		{"/api/projects/guidance/file", "analytics"},
		{"/api/project/{id}/commits", "projects"},
		{"GET /api/obs/egress/status", "obs"},
		{"/api/export.xlsx", "ui.export-xlsx"},
		{"/api/components/state", "core"},
		// Command jobs follow the owner of the verb they spawn (T-671).
		{"/api/jobs/mcp-wrap", "agentaccess.relay"},
		{"/api/jobs/mcp-relay-enable", "agentaccess.relay"},
		{"/api/jobs/mcp-doctor", "agentaccess.relay"},
		{"/api/jobs/pricing-sync", "egress.pricing-feed"},
		{"/api/jobs/calibration", "proxy.routing"},
		{"/api/jobs/score", "analytics"},
		{"/api/jobs/reclaim-cleanup/cancel", "archive"},
		{"/api/jobs/doctor-integrity", "core"},
		// summarize is analytics' verb since T-674.
		{"/api/jobs/summarize", "analytics"},
		{"/api/jobs", "core"},
		// The proxy route writers belong to integration.proxy-route.
		{"/api/setup/claude", "integration.proxy-route"},
		{"/api/setup/codex", "integration.proxy-route"},
		{"/api/setup/codex-hooks", "core"},
	} {
		if got := routeComponent(tc.pattern); got != tc.want {
			t.Errorf("routeComponent(%q) = %q, want %q", tc.pattern, got, tc.want)
		}
	}
}

// TestPlaneSplitRouteOwners (T-671) pins route ownership to the plane split
// in CLAUDE.md and docs/deployment-models.md: Plane B developer guardrails
// (internal/guard + internal/policy, served under /api/guard) belong to the
// guard component, which every distro compiles; Plane A observability
// (internal/obs, served under /api/obs, including the node-local Egress
// audit and the Policies authoring of [observability.admission] and
// [observability.egress]) belongs to obs, which D-389 removes from the
// developer distro. A guard route owned by obs would vanish from the
// developer distro; an obs route owned by anything else would outlive obs.
func TestPlaneSplitRouteOwners(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	s.registerRoutes(nil)
	m := s.routeComponents.Load()
	guardRoutes := 0
	for pattern, id := range *m {
		path := pattern
		if _, rest, ok := strings.Cut(pattern, " "); ok {
			path = rest
		}
		switch {
		case pathHasPrefix(path, "/api/guard"):
			guardRoutes++
			if id != "guard" {
				t.Errorf("Plane B route %s is owned by %q, want guard", pattern, id)
			}
		case id == "obs":
			t.Errorf("route %s is owned by obs but is not a Plane A /api/obs route", pattern)
		}
	}
	if guardRoutes == 0 {
		t.Fatal("no /api/guard route registered: the plane split test lost its subject")
	}
	// The Plane A routes arrive through ExtraRoutes from the obs wiring;
	// resolve them directly.
	for _, p := range []string{"GET /api/obs/egress/status", "GET /api/obs/egress/decisions", "POST /api/obs/egress/policy", "GET /api/obs/admission/policy", "GET /api/obs/egress/lint"} {
		if got := routeComponent(p); got != "obs" {
			t.Errorf("routeComponent(%q) = %q, want obs", p, got)
		}
	}
	// The guard row owns the Plane B policy package.
	g, ok := components.Get("guard")
	if !ok || !containsStr(g.Packages, "internal/guard") || !containsStr(g.Packages, "internal/policy") {
		t.Fatalf("guard row must own internal/guard and internal/policy, got %v", g.Packages)
	}
	if o, _ := components.Get("obs"); containsStr(o.Packages, "internal/policy") || containsStr(o.Packages, "internal/guard") {
		t.Fatal("obs must not own a Plane B guard package")
	}
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// TestComponentsStateListsSelectedSecurity: GET /api/components/state lists
// the security components the daemon's opt-in rule selects. An install with
// no [components] block lists no opt-in child even though each is compiled
// and resolves active, so the Settings card shows none of their rows; a
// block naming one lists it. No rule wired lists none.
func TestComponentsStateListsSelectedSecurity(t *testing.T) {
	// A stand-in for cmd/observer securitySelected with the same shape.
	optIn := map[string]bool{
		"security.trust": true, "security.deps": true, "security.scan.custom": true,
		"security.githooks": true, "security.scan.scalibr": true, "security.scan.osv": true,
	}
	rule := func(snap componentstate.Snapshot, id string) bool {
		if optIn[id] && !snap.Configured {
			return false
		}
		return snap.ModuleActive(id)
	}
	read := func(t *testing.T, block string, sel func(componentstate.Snapshot, string) bool) []string {
		t.Helper()
		svc, _ := componentsTestService(t, block)
		s := newRemoteTestServer(t, Options{Components: svc, SecuritySelected: sel})
		rec := httptest.NewRecorder()
		s.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/components/state"))
		var st componentsStateResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		if st.SecuritySelected == nil {
			t.Fatal("security_selected is null, want a list")
		}
		return st.SecuritySelected
	}
	legacy := read(t, "", rule)
	for id := range optIn {
		if containsStr(legacy, id) {
			t.Errorf("no [components] block: %s listed as selected (%v)", id, legacy)
		}
	}
	if snap := componentstate.Legacy(); snap.ModuleActive("security") && !containsStr(legacy, "security") {
		t.Errorf("the security root is active but not listed: %v", legacy)
	}
	named := read(t, "[components]\nadd = [\"security.scan.custom\"]\n", rule)
	if snap := componentstate.Legacy(); snap.ModuleActive("security.scan.custom") && !containsStr(named, "security.scan.custom") {
		t.Errorf("a block naming security.scan.custom: not listed (%v)", named)
	}
	if none := read(t, "", nil); len(none) != 0 {
		t.Errorf("no rule wired lists %v, want none", none)
	}
}

// TestComponentsStateUsesTheDaemonView: GET /api/components/state serves the
// daemon's component view (Options.ComponentStateView) when it is wired, so a
// module root its own rule switches off (the sandbox root under
// `remove = ["terminals.sandbox"]`, plans decision log P-057) reads as off on
// the Components page as in `observer components status`, and the routes of
// such a component are listed inactive. Unwired, the page keeps core's view.
func TestComponentsStateUsesTheDaemonView(t *testing.T) {
	read := func(t *testing.T, view func(componentstate.Snapshot) componentstate.View) componentsStateResponse {
		t.Helper()
		svc, _ := componentsTestService(t, "")
		s := newRemoteTestServer(t, Options{Components: svc, ComponentStateView: view})
		s.registerRoutes(nil)
		rec := httptest.NewRecorder()
		s.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/components/state"))
		var st componentsStateResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	core := read(t, nil)
	var target string
	for _, r := range core.View.Components {
		if r.State == components.StateActive && r.ID != coreComponent {
			target = r.ID
			break
		}
	}
	if target == "" {
		t.Skip("no active component in this build to switch off")
	}
	off := func(snap componentstate.Snapshot) componentstate.View {
		v := snap.View()
		for i, r := range v.Components {
			if r.ID == target {
				v.Components[i].State = components.StateAvailable
				v.Components[i].Reason = components.ReasonNotSelected
				v.ActiveCount--
			}
		}
		return v
	}
	got := read(t, off)
	for _, r := range got.View.Components {
		if r.ID == target && r.State == components.StateActive {
			t.Fatalf("%s still active with the daemon view wired", target)
		}
	}
	if got.View.ActiveCount != core.View.ActiveCount-1 {
		t.Errorf("active count %d, want %d", got.View.ActiveCount, core.View.ActiveCount-1)
	}
}
