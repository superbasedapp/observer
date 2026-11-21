package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxadvise"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// testEgressHostCheck is the gateway's host check as cmd/observer wires it
// (sandboxEgressHostCheckSeam over agentEgressRules), rebuilt from the same
// sandboxnet functions so the dashboard tests ask the real list semantics.
func testEgressHostCheck(ts config.TerminalSandboxConfig, host string) string {
	if ts.PinnedNoEgressHost != "" {
		return sandboxnet.DenyAllHosts().Check(host)
	}
	if len(ts.EgressAllowHosts) == 0 {
		return ""
	}
	rules, err := sandboxnet.ParseHostRules(ts.EgressAllowHosts)
	if err != nil {
		return "host-list-invalid"
	}
	return rules.Check(host)
}

// refusalAllowServer is a manage server whose config carries sandboxTOML
// and, when pins is not empty, a governance sidecar pinning them.
func refusalAllowServer(t *testing.T, sandboxTOML, pins string, check func(config.TerminalSandboxConfig, string) string) (*Server, http.Handler) {
	t.Helper()
	s := newManageServerOpts(t, Options{SandboxEgressHostCheck: check})
	path := s.opts.ConfigPath
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, []byte("\n[terminal.sandbox]\n"+sandboxTOML)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if pins != "" {
		sidecar := filepath.Join(filepath.Dir(path), config.GovernanceSidecarFilename)
		if err := os.WriteFile(sidecar, []byte(`{"schema":1,"state":"applied","pinned":{`+pins+`}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return s, s.Handler()
}

// insertRefusals stores rows and returns their ids by host.
func insertRefusals(t *testing.T, s *Server, rows []store.SandboxEgressRefusal) map[string]int64 {
	t.Helper()
	st := store.New(s.db())
	ids := map[string]int64{}
	for i, r := range rows {
		r.RunID, r.ProjectRoot, r.Backend, r.Tier = "run-1", "/p/one", "bwrap", "internet"
		r.At = time.Now().UTC().Add(time.Duration(i-len(rows)) * time.Minute)
		if r.Port == 0 {
			r.Port = 443
		}
		if ok, err := st.InsertSandboxEgressRefusal(context.Background(), r); err != nil || !ok {
			t.Fatalf("insert %+v: %v %v", r, ok, err)
		}
	}
	stored, err := st.ListSandboxEgressRefusals(context.Background(), store.SandboxEgressRefusalQuery{Limit: store.SandboxEgressRefusalMaxPage})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range stored {
		ids[r.Host+"/"+r.Rule] = r.ID
	}
	return ids
}

type refusalAllowGet struct {
	ConfirmToken string                `json:"confirm_token"`
	Scope        string                `json:"scope"`
	ScopeLabel   string                `json:"scope_label"`
	Key          string                `json:"key"`
	Offers       []sandboxRefusalOffer `json:"offers"`
}

func getRefusalOffers(t *testing.T, h http.Handler, query string) (refusalAllowGet, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/sandbox/refusals/allow"+query, nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET offers = %d: %s", rec.Code, rec.Body.String())
	}
	var got refusalAllowGet
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var ck *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			ck = c
		}
	}
	if got.ConfirmToken == "" || ck == nil {
		t.Fatal("GET offers minted no confirm token")
	}
	return got, ck
}

func offersByID(g refusalAllowGet) map[int64]sandboxRefusalOffer {
	m := map[int64]sandboxRefusalOffer{}
	for _, o := range g.Offers {
		m[o.RefusalID] = o
	}
	return m
}

// putRefusalAllow applies one refusal's offer; confirm false sends no token.
func putRefusalAllow(t *testing.T, h http.Handler, id int64, query string, confirm bool) (int, string) {
	t.Helper()
	g, ck := getRefusalOffers(t, h, "")
	req := httptest.NewRequest(http.MethodPut, "/api/sandbox/refusals/allow"+query, strings.NewReader(`{"refusal_id":`+strconv.FormatInt(id, 10)+`}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	if confirm {
		req.Header.Set(remoteConfirmHeader, g.ConfirmToken)
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// ownHosts reads the file's own host list (no governance).
func ownHosts(t *testing.T, s *Server) []string {
	t.Helper()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath, GovernanceSidecar: config.NoGovernanceSidecar})
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Terminal.Sandbox.EgressAllowHosts
}

// TestSandboxRefusalOffersPerRule: one row per refusal shape on the GET.
// Only an allow-list miss the gateway would then let through is offered;
// provider-host, private-range and SSRF-floor refusals never are, and a
// host the current list already allows is not offered either.
func TestSandboxRefusalOffersPerRule(t *testing.T) {
	s, h := refusalAllowServer(t, `egress_allow_hosts = ["a.example.com"]`+"\n", "", testEgressHostCheck)
	ids := insertRefusals(t, s, []store.SandboxEgressRefusal{
		{Host: "B.Example.com", Rule: "allow-list-miss", Key: sandboxnet.KeyEgressAllowHosts},
		{Host: "a.example.com", Rule: "allow-list-miss", Key: sandboxnet.KeyEgressAllowHosts},
		{Host: "api.anthropic.com", Rule: "provider-host", Key: sandboxnet.KeyProviderDirect},
		{Host: "10.0.0.5", Rule: "private-range", Key: sandboxnet.KeyEgressAllowCIDRs},
		{Host: "169.254.169.254", Rule: "ssrf-floor"},
		{Host: "bad_host", Rule: "allow-list-miss", Key: sandboxnet.KeyEgressAllowHosts},
	})
	g, _ := getRefusalOffers(t, h, "?run_id=run-1")
	if g.Scope != string(sandboxadvise.ScopeNode) || g.ScopeLabel == "" || g.Key != sandboxadvise.HostListKey {
		t.Fatalf("scope fields: %+v", g)
	}
	offers := offersByID(g)
	cases := []struct {
		key  string
		want sandboxadvise.Reason
	}{
		{"B.Example.com/allow-list-miss", sandboxadvise.ReasonOfferable},
		{"a.example.com/allow-list-miss", sandboxadvise.ReasonAlreadyAllowed},
		{"api.anthropic.com/provider-host", sandboxadvise.ReasonRuleNotOfferable},
		{"10.0.0.5/private-range", sandboxadvise.ReasonRuleNotOfferable},
		{"169.254.169.254/ssrf-floor", sandboxadvise.ReasonRuleNotOfferable},
		{"bad_host/allow-list-miss", sandboxadvise.ReasonHostNotListable},
	}
	for _, c := range cases {
		o, ok := offers[ids[c.key]]
		if !ok {
			t.Fatalf("%s: no offer", c.key)
		}
		if o.Reason != c.want || o.Offerable != (c.want == sandboxadvise.ReasonOfferable) {
			t.Fatalf("%s: offer %+v, want %s", c.key, o, c.want)
		}
	}
	if o := offers[ids["B.Example.com/allow-list-miss"]]; o.Host != "b.example.com" {
		t.Fatalf("host not normalized: %q", o.Host)
	}
}

// TestSandboxRefusalOfferEmptyListIsAlreadyAllowed: with no host list (and
// no pin) the tier's own behaviour already lets the host through, so
// nothing is offered; adding it would narrow every run to that one host.
func TestSandboxRefusalOfferEmptyListIsAlreadyAllowed(t *testing.T) {
	s, h := refusalAllowServer(t, "", "", testEgressHostCheck)
	ids := insertRefusals(t, s, []store.SandboxEgressRefusal{{Host: "b.example.com", Rule: "allow-list-miss"}})
	o := offersByID(mustOffers(t, h))[ids["b.example.com/allow-list-miss"]]
	if o.Offerable || o.Reason != sandboxadvise.ReasonAlreadyAllowed {
		t.Fatalf("offer %+v", o)
	}
	if code, _ := putRefusalAllow(t, h, ids["b.example.com/allow-list-miss"], "", true); code != http.StatusConflict {
		t.Fatalf("PUT answered %d, want 409", code)
	}
	if got := ownHosts(t, s); len(got) != 0 {
		t.Fatalf("list written: %v", got)
	}
}

func mustOffers(t *testing.T, h http.Handler) refusalAllowGet {
	g, _ := getRefusalOffers(t, h, "")
	return g
}

// TestSandboxRefusalOfferOrgPin: under an org pin of the host list a host
// the pin leaves out is never offered and its PUT is refused, while a host
// the pin includes is offered and saved to the OWNER's list (never the
// pinned intersection).
func TestSandboxRefusalOfferOrgPin(t *testing.T) {
	s, h := refusalAllowServer(t, `egress_allow_hosts = ["a.example.com", "own-only.example.com"]`+"\n",
		`"terminal.sandbox.egress_allow_hosts":["a.example.com","c.example.com"]`, testEgressHostCheck)
	ids := insertRefusals(t, s, []store.SandboxEgressRefusal{
		{Host: "b.example.com", Rule: "allow-list-miss"},
		{Host: "c.example.com", Rule: "allow-list-miss"},
		{Host: "own-only.example.com", Rule: "allow-list-miss"},
	})
	offers := offersByID(mustOffers(t, h))
	for key, want := range map[string]sandboxadvise.Reason{
		"b.example.com/allow-list-miss":        sandboxadvise.ReasonOrgPinRefuses,
		"c.example.com/allow-list-miss":        sandboxadvise.ReasonOfferable,
		"own-only.example.com/allow-list-miss": sandboxadvise.ReasonOrgPinRefuses,
	} {
		if o := offers[ids[key]]; o.Reason != want {
			t.Fatalf("%s: offer %+v, want %s", key, o, want)
		}
	}
	if code, body := putRefusalAllow(t, h, ids["b.example.com/allow-list-miss"], "", true); code != http.StatusConflict || !strings.Contains(body, string(sandboxadvise.ReasonOrgPinRefuses)) {
		t.Fatalf("PUT of a pinned-out host answered %d: %s", code, body)
	}
	if code, body := putRefusalAllow(t, h, ids["c.example.com/allow-list-miss"], "", true); code != http.StatusOK {
		t.Fatalf("PUT answered %d: %s", code, body)
	}
	want := []string{"a.example.com", "own-only.example.com", "c.example.com"}
	if got := ownHosts(t, s); !reflect.DeepEqual(got, want) {
		t.Fatalf("own list %v, want %v", got, want)
	}
}

// TestSandboxRefusalAllowPut: the apply's owner-local and pipeline checks.
func TestSandboxRefusalAllowPut(t *testing.T) {
	s, h := refusalAllowServer(t, `egress_allow_hosts = ["a.example.com"]`+"\n", "", testEgressHostCheck)
	ids := insertRefusals(t, s, []store.SandboxEgressRefusal{
		{Host: "b.example.com", Rule: "allow-list-miss"},
		{Host: "api.openai.com", Rule: "provider-host"},
	})
	id := ids["b.example.com/allow-list-miss"]
	if code, _ := putRefusalAllow(t, h, id, "", false); code != http.StatusForbidden {
		t.Fatalf("no confirm token answered %d, want 403", code)
	}
	if code, _ := putRefusalAllow(t, h, id+1000, "", true); code != http.StatusNotFound {
		t.Fatalf("unknown id answered %d, want 404", code)
	}
	if code, _ := putRefusalAllow(t, h, ids["api.openai.com/provider-host"], "", true); code != http.StatusConflict {
		t.Fatalf("provider host answered %d, want 409", code)
	}
	if code, body := putRefusalAllow(t, h, id, "?dry_run=1", true); code != http.StatusOK {
		t.Fatalf("dry run answered %d: %s", code, body)
	}
	if got := ownHosts(t, s); !reflect.DeepEqual(got, []string{"a.example.com"}) {
		t.Fatalf("dry run wrote: %v", got)
	}
	code, body := putRefusalAllow(t, h, id, "", true)
	if code != http.StatusOK {
		t.Fatalf("PUT answered %d: %s", code, body)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(body), &out)
	if out["host"] != "b.example.com" || out["scope"] != string(sandboxadvise.ScopeNode) || out["restart_required"] != false {
		t.Fatalf("PUT response %v", out)
	}
	if got := ownHosts(t, s); !reflect.DeepEqual(got, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("own list %v", got)
	}
	// Applied once, the host is allowed: the same refusal is no longer offered.
	if o := offersByID(mustOffers(t, h))[id]; o.Offerable || o.Reason != sandboxadvise.ReasonAlreadyAllowed {
		t.Fatalf("offer after the save %+v", o)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/sandbox/refusals/allow", strings.NewReader(`{}`))
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST answered %d, want 405", rec.Code)
	}
	_, capMap, _ := s.registerRoutes(nil)
	if c := capMap["/api/sandbox/refusals/allow"]; c != CapabilityLocal {
		t.Fatalf("route class %v, want Local", c)
	}
	if got := routeComponent("/api/sandbox/refusals/allow"); got != "terminals.sandbox" {
		t.Fatalf("route owner %q, want terminals.sandbox", got)
	}
}

// TestSandboxRefusalAllowRestartFieldsAgree (lane FU10, F-049): the N5-L1
// live pass saw restart_required false beside restart_required_keys
// ["terminal.sandbox.egress_allow_hosts"]. The key binds at the next run
// (its restart class is next_spawn), so both the preview and the save say
// no restart, list no restart key and list the key as next-spawn; and a
// listed restart key always makes the boolean true.
func TestSandboxRefusalAllowRestartFieldsAgree(t *testing.T) {
	cases := []struct {
		name  string
		query string
	}{
		{"preview", "?dry_run=1"},
		{"save", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, h := refusalAllowServer(t, `egress_allow_hosts = ["a.example.com"]`+"\n", "", testEgressHostCheck)
			ids := insertRefusals(t, s, []store.SandboxEgressRefusal{{Host: "b.example.com", Rule: "allow-list-miss"}})
			code, body := putRefusalAllow(t, h, ids["b.example.com/allow-list-miss"], c.query, true)
			if code != http.StatusOK {
				t.Fatalf("PUT answered %d: %s", code, body)
			}
			var out struct {
				RestartRequired     bool     `json:"restart_required"`
				RestartRequiredKeys []string `json:"restart_required_keys"`
				NextSpawnKeys       []string `json:"next_spawn_keys"`
			}
			if err := json.Unmarshal([]byte(body), &out); err != nil {
				t.Fatal(err)
			}
			if out.RestartRequired != (len(out.RestartRequiredKeys) > 0) {
				t.Fatalf("restart_required %v contradicts restart_required_keys %v", out.RestartRequired, out.RestartRequiredKeys)
			}
			if out.RestartRequired || !reflect.DeepEqual(out.NextSpawnKeys, []string{"terminal.sandbox.egress_allow_hosts"}) {
				t.Fatalf("restart fields %+v, want no restart and the key as next_spawn", out)
			}
		})
	}
}

// TestKeepRestartRequiredHonest: a route extra may raise restart_required,
// never lower it below a listed restart key. One case per rule outcome.
func TestKeepRestartRequiredHonest(t *testing.T) {
	cases := []struct {
		name    string
		extra   any
		restart []string
		want    bool
	}{
		{"a listed key overrides an extra's false", false, []string{"terminal.sandbox.egress"}, true},
		{"an extra may raise it with no key listed", true, nil, true},
		{"nothing to restart stays false", false, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := map[string]any{"restart_required": c.extra}
			keepRestartRequiredHonest(resp, restartClasses{restart: c.restart})
			if resp["restart_required"] != c.want {
				t.Fatalf("restart_required = %v, want %v", resp["restart_required"], c.want)
			}
		})
	}
}

// TestSandboxRefusalAllowNotInBuild: a build without the sandbox's gateway
// check offers nothing and refuses the apply with 501.
func TestSandboxRefusalAllowNotInBuild(t *testing.T) {
	s, h := refusalAllowServer(t, `egress_allow_hosts = ["a.example.com"]`+"\n", "", nil)
	ids := insertRefusals(t, s, []store.SandboxEgressRefusal{{Host: "b.example.com", Rule: "allow-list-miss"}})
	if o := offersByID(mustOffers(t, h))[ids["b.example.com/allow-list-miss"]]; o.Offerable || o.Reason != sandboxadvise.ReasonNotInBuild {
		t.Fatalf("offer %+v", o)
	}
	if code, _ := putRefusalAllow(t, h, ids["b.example.com/allow-list-miss"], "", true); code != http.StatusNotImplemented {
		t.Fatalf("PUT answered %d, want 501", code)
	}
}

// testProviderHost is the gateway's provider-block name match as
// cmd/observer wires it (sandboxProviderHostSeam), over the closed provider
// list only (these tests configure no proxy upstreams).
func testProviderHost(_ config.Config, host string) bool {
	return sandboxvocab.MatchesHost(host, sandboxvocab.ModelProviderHosts())
}

// TestSandboxRefusalOfferProviderHostStoredAsAllowListMiss (audit finding
// N5-A1): the gateway checks the host list before the provider block, so an
// unlisted provider host is stored as allow-list-miss. It is never offered
// and its PUT is refused with the reason, leaving the owner's list as it was.
func TestSandboxRefusalOfferProviderHostStoredAsAllowListMiss(t *testing.T) {
	s := newManageServerOpts(t, Options{SandboxEgressHostCheck: testEgressHostCheck, SandboxProviderHost: testProviderHost})
	path := s.opts.ConfigPath
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, []byte("\n[terminal.sandbox]\negress_allow_hosts = [\"a.example.com\"]\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	ids := insertRefusals(t, s, []store.SandboxEgressRefusal{
		{Host: "api.anthropic.com", Rule: "allow-list-miss", Key: sandboxnet.KeyEgressAllowHosts},
		{Host: "EU.API.Anthropic.com", Rule: "allow-list-miss", Key: sandboxnet.KeyEgressAllowHosts},
		{Host: "b.example.com", Rule: "allow-list-miss", Key: sandboxnet.KeyEgressAllowHosts},
	})
	offers := offersByID(mustOffers(t, h))
	for key, want := range map[string]sandboxadvise.Reason{
		"api.anthropic.com/allow-list-miss":    sandboxadvise.ReasonProviderHost,
		"EU.API.Anthropic.com/allow-list-miss": sandboxadvise.ReasonProviderHost,
		"b.example.com/allow-list-miss":        sandboxadvise.ReasonOfferable,
	} {
		if o := offers[ids[key]]; o.Reason != want || o.Offerable != (want == sandboxadvise.ReasonOfferable) {
			t.Fatalf("%s: offer %+v, want %s", key, o, want)
		}
	}
	code, out := putRefusalAllow(t, h, ids["api.anthropic.com/allow-list-miss"], "", true)
	if code != http.StatusConflict || !strings.Contains(out, string(sandboxadvise.ReasonProviderHost)) {
		t.Fatalf("PUT of a provider host answered %d: %s", code, out)
	}
	if got := ownHosts(t, s); !reflect.DeepEqual(got, []string{"a.example.com"}) {
		t.Fatalf("own list written: %v", got)
	}
}
