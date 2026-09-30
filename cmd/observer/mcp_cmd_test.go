package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/mcpaccess"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	famcp "github.com/marmutapp/superbased-observer/internal/policyfam/mcpaccess"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// updateMCPHelp regenerates testdata/mcp_help/*.golden:
//
//	go test ./cmd/observer -run TestMCPCmd_HelpGolden -update-mcp-help
var updateMCPHelp = flag.Bool("update-mcp-help", false, "rewrite the observer mcp help goldens instead of comparing")

// mcpNodeTree15_0 is doc3 §15.0's node tree, copied verbatim:
//
//	observer mcp {status|relay|wrap|unwrap|connect|doctor}
var mcpNodeTree15_0 = []string{"status", "relay", "wrap", "unwrap", "connect", "doctor"}

// runMCPCLI executes `observer <args...>` against a fresh minimal root that
// carries only the mcp tree (so goldens and outputs never depend on the
// rest of the CLI), returning combined output and the error.
func runMCPCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := &cobra.Command{Use: "observer", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(newMCPCmd())
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return buf.String(), err
}

// mcpCLIEnv is a private node: temp HOME (the registrar and ~ expansion
// never see the developer's real client configs), a config.toml and a DB
// path that does not exist yet.
type mcpCLIEnv struct {
	home, cfgPath, dbPath string
}

func newMCPCLIEnv(t *testing.T, enabled bool) mcpCLIEnv {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	mcpRelayHomeOverride = home
	t.Cleanup(func() { mcpRelayHomeOverride = "" })
	e := mcpCLIEnv{home: home, cfgPath: filepath.Join(home, ".observer", "config.toml"), dbPath: filepath.Join(home, ".observer", "observer.db")}
	e.writeConfig(t, enabled, "")
	return e
}

func (e mcpCLIEnv) writeConfig(t *testing.T, enabled bool, extra string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(e.cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("[observer]\ndb_path = %q\n\n[mcp_relay]\nenabled = %v\n%s", e.dbPath, enabled, extra)
	if err := os.WriteFile(e.cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e mcpCLIEnv) writeClient(t *testing.T, rel, body string) string {
	t.Helper()
	p := filepath.Join(e.home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func (e mcpCLIEnv) loadCfg(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: e.cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// mcpCmdTestSpec is a one-vserver tools.mcp_access body whose issuer is the
// given (fake) org and whose gh server uses credMode.
func mcpCmdTestSpec(t *testing.T, issuer, credMode string) famcp.PolicySpec {
	t.Helper()
	b := famcp.Body{Mode: "enforce", Registry: mcpaccess.Registry{
		Issuer: issuer, Org: "acme", GatewayBaseURI: "https://gw.acme", PolicyGen: 5,
		VServers: []mcpaccess.VServer{{
			ID: "vs-gh", Slug: "github", SenderConstraint: "bearer",
			Servers: []mcpaccess.Server{{ID: "gh", Target: "https://mcp.github.com/mcp", CredentialMode: credMode}},
		}},
	}, Grants: []mcpaccess.Grant{
		{
			ID: "g-allow", Ord: 1, Subject: mcpaccess.Subject{Kind: mcpaccess.SubjectAny},
			Resource: mcpaccess.Resource{VServer: "vs-gh", Name: "create_issue"}, Action: mcpaccess.ActionCall,
			Effect: mcpaccess.EffectAllow, Enabled: true,
		},
	}}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	spec, _, err := famcp.CompileBody(raw, famcp.DefaultMaxBytes)
	if err != nil {
		t.Fatalf("CompileBody: %v", err)
	}
	return spec
}

// seedTable persists an accepted table in the node cache the CLI loads.
func (e mcpCLIEnv) seedTable(t *testing.T, issuer, credMode string) {
	t.Helper()
	h := newMCPRelayHandle(e.loadCfg(t), nil, nil, slog.New(slog.DiscardHandler))
	h.Apply(orgclient.PolicyResourceResult{
		Status: orgclient.PRApplied, Version: 3, BodyHash: strings.Repeat("b", 64),
		OrgKey: "org", Generation: 1, EnforceAllowed: true, Spec: mcpCmdTestSpec(t, issuer, credMode),
	})
	if h.Table() == nil {
		t.Fatalf("table not applied: %+v", h.State())
	}
}

func mcpReadFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestMCPCmd_TreeMatchesCanonical15_0 walks the cobra tree against §15.0:
// exactly the six verbs, registered on the real root, with the older
// mcp-relay spelling and the nested guard mcp left intact.
func TestMCPCmd_TreeMatchesCanonical15_0(t *testing.T) {
	var got []string
	for _, c := range newMCPCmd().Commands() {
		got = append(got, c.Name())
	}
	want := append([]string(nil), mcpNodeTree15_0...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("observer mcp verbs = %v, §15.0 = %v", got, want)
	}
	for _, c := range newMCPCmd().Commands() {
		if c.Hidden {
			t.Errorf("canonical verb %s is hidden", c.Name())
		}
	}
	root := newRootCmd()
	names := map[string]*cobra.Command{}
	for _, c := range root.Commands() {
		names[c.Name()] = c
	}
	if names["mcp"] == nil {
		t.Fatal("observer mcp not registered on the root")
	}
	relay := names["mcp-relay"]
	if relay == nil {
		t.Fatal("observer mcp-relay (older spelling) was removed")
	}
	sub := map[string]bool{}
	for _, c := range relay.Commands() {
		sub[c.Name()] = true
	}
	for _, v := range []string{"status", "enable", "disable", "restore", "wrap"} {
		if !sub[v] {
			t.Errorf("mcp-relay lost %s", v)
		}
	}
	var guardMCP bool
	if g := names["guard"]; g != nil {
		for _, c := range g.Commands() {
			guardMCP = guardMCP || c.Name() == "mcp"
		}
	}
	if !guardMCP {
		t.Error("the nested `observer guard mcp` is gone")
	}
}

// TestMCPCmd_HelpGolden pins `observer mcp --help` and every verb's help.
func TestMCPCmd_HelpGolden(t *testing.T) {
	cases := append([]string{""}, mcpNodeTree15_0...)
	for _, verb := range cases {
		name := "mcp"
		args := []string{"mcp", "--help"}
		if verb != "" {
			name = "mcp_" + verb
			args = []string{"mcp", verb, "--help"}
		}
		t.Run(name, func(t *testing.T) {
			out, err := runMCPCLI(t, args...)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "mcp_help", name+".golden")
			if *updateMCPHelp {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v (run `go test ./cmd/observer -run TestMCPCmd_HelpGolden -update-mcp-help`)", err)
			}
			if out != string(want) {
				t.Fatalf("help drifted from %s:\n--- got ---\n%s\n--- want ---\n%s", path, out, want)
			}
		})
	}
}

// TestMCPCmd_DisabledIsInert pins the kill switch: with [mcp_relay].enabled
// = false no verb creates the node DB, rewrites a client config or reaches
// the network; relay / wrap refuse with the typed error.
func TestMCPCmd_DisabledIsInert(t *testing.T) {
	e := newMCPCLIEnv(t, false)
	cursorPath := e.writeClient(t, ".cursor/mcp.json", projTestCursor)
	prev := mcpDoctorDepsFor
	mcpDoctorDepsFor = func(config.Config, *store.Store, *slog.Logger) mcpDoctorDeps {
		t.Error("doctor built network deps with the relay disabled")
		return mcpDoctorDeps{}
	}
	t.Cleanup(func() { mcpDoctorDepsFor = prev })

	for _, verb := range []string{"wrap", "relay"} {
		args := []string{"mcp", verb, "--config", e.cfgPath}
		if verb == "relay" {
			args = append(args, "--server", "gh", "--client", "cursor")
		}
		_, err := runMCPCLI(t, args...)
		if !errors.Is(err, errMCPNodeDisabled) {
			t.Errorf("%s with the relay disabled: err = %v, want errMCPNodeDisabled", verb, err)
		}
	}

	out, err := runMCPCLI(t, "mcp", "status", "--config", e.cfgPath, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var s mcpRelayStatus
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatalf("status json: %v\n%s", err, out)
	}
	if s.Enabled || s.PointStatus != "ineffective" || s.TableLoaded || s.RemoteForwarding.Wired || !strings.Contains(s.RemoteForwarding.Reason, "disabled") || s.LaunchSpecs != 0 {
		t.Fatalf("disabled status %+v", s)
	}
	if out, err = runMCPCLI(t, "mcp", "status", "--config", e.cfgPath); err != nil || !strings.Contains(out, "relay DISABLED") {
		t.Fatalf("disabled text status: %v\n%s", err, out)
	}

	out, err = runMCPCLI(t, "mcp", "doctor", "--config", e.cfgPath, "--json")
	if err != nil {
		t.Fatalf("doctor disabled: %v\n%s", err, out)
	}
	var rep mcpDoctorReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Enabled || rep.Failed != 0 {
		t.Fatalf("doctor disabled report %+v", rep)
	}
	for _, c := range rep.Checks {
		if strings.HasPrefix(c.Name, "org.") || strings.HasPrefix(c.Name, "sts.") || strings.HasPrefix(c.Name, "client") {
			t.Errorf("disabled doctor ran %s", c.Name)
		}
	}

	if out, err = runMCPCLI(t, "mcp", "unwrap", "--config", e.cfgPath); err != nil || !strings.Contains(out, "nothing to restore") {
		t.Fatalf("unwrap on a fresh node: %v\n%s", err, out)
	}
	if out, err = runMCPCLI(t, "mcp", "connect", "--config", e.cfgPath, "--dashboard-url", "https://org.acme"); err != nil || !strings.Contains(out, "https://org.acme/agent-access/connections") {
		t.Fatalf("connect: %v\n%s", err, out)
	}

	if _, err := os.Stat(e.dbPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a disabled verb created the node DB (%v)", err)
	}
	if got := mcpReadFile(t, cursorPath); got != projTestCursor {
		t.Fatal("a disabled verb rewrote a client config")
	}
}

// TestMCPCmd_WrapUnwrapByteIdentical drives wrap -> status -> unwrap
// through the CLI in a private HOME: the configs are rewritten through the
// relay, status --json reports the projection in the mcp-relay shape, and
// unwrap restores every config byte-identically.
func TestMCPCmd_WrapUnwrapByteIdentical(t *testing.T) {
	e := newMCPCLIEnv(t, true)
	cursorPath := e.writeClient(t, ".cursor/mcp.json", projTestCursor)
	opencodePath := e.writeClient(t, ".config/opencode/opencode.json", projTestOpenCode)
	codexPath := e.writeClient(t, ".codex/config.toml", projTestCodex)
	e.seedTable(t, "https://auth.acme", "service")

	out, err := runMCPCLI(t, "mcp", "wrap", "--config", e.cfgPath, "--no-remote")
	if err != nil {
		t.Fatalf("wrap: %v\n%s", err, out)
	}
	if !strings.Contains(out, "projected 2 client config(s), 0 failed") {
		t.Fatalf("wrap report:\n%s", out)
	}
	for _, p := range []string{cursorPath, opencodePath} {
		if got := mcpReadFile(t, p); !strings.Contains(got, "mcp-relay") || !strings.Contains(got, `"wrap"`) {
			t.Fatalf("%s not wrapped:\n%s", p, got)
		}
	}
	if mcpReadFile(t, codexPath) != projTestCodex {
		t.Fatal("codex's unbound fs entry was rewritten")
	}
	// Idempotent.
	if out, err = runMCPCLI(t, "mcp", "wrap", "--config", e.cfgPath, "--no-remote"); err != nil || !strings.Contains(out, "projected 0 client config(s)") {
		t.Fatalf("re-wrap: %v\n%s", err, out)
	}

	out, err = runMCPCLI(t, "mcp", "status", "--config", e.cfgPath, "--json", "--no-remote")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("status json: %v\n%s", err, out)
	}
	for _, k := range []string{"enabled", "mode", "audit_mode", "table_loaded", "table_version", "cache_path", "effective_hash", "point_status", "approved_vservers", "chain_head", "pending_loss", "launch_specs", "projected_clients", "remote_forwarding", "coverage"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("status --json lacks %q", k)
		}
	}
	var s mcpRelayStatus
	_ = json.Unmarshal([]byte(out), &s)
	if !s.Enabled || !s.TableLoaded || strings.Join(s.ApprovedVServers, ",") != "vs-gh" || s.LaunchSpecs != 2 ||
		strings.Join(s.ProjectedClients, ",") != "cursor,opencode" || s.PointStatus != "effective" || len(s.EffectiveHash) != 64 ||
		s.RemoteForwarding.Wired || s.Coverage["mediated"] == 0 {
		t.Fatalf("status %+v", s)
	}

	out, err = runMCPCLI(t, "mcp", "unwrap", "--config", e.cfgPath)
	if err != nil {
		t.Fatalf("unwrap: %v\n%s", err, out)
	}
	if !strings.Contains(out, "restored 2 client config(s), 0 failed") || !strings.Contains(out, "still enabled") {
		t.Fatalf("unwrap report:\n%s", out)
	}
	for p, want := range map[string]string{cursorPath: projTestCursor, opencodePath: projTestOpenCode, codexPath: projTestCodex} {
		if got := mcpReadFile(t, p); got != want {
			t.Fatalf("%s not byte-identical after unwrap:\n%s", p, got)
		}
	}
	// The stdio relay verb IS the mcp-relay wrap body: with the relay on it
	// passes the pre-check and the wrapper's own validation answers.
	if _, err := runMCPCLI(t, "mcp", "relay", "--config", e.cfgPath); err == nil || !strings.Contains(err.Error(), "--server is required") {
		t.Fatalf("relay without --server: %v", err)
	}
}

// TestMCPCmd_ConnectOrigin is the origin table, one case per row plus the
// refusals.
func TestMCPCmd_ConnectOrigin(t *testing.T) {
	src := func(flagV, enr, cfgV string) []mcpConnectOriginSource {
		return []mcpConnectOriginSource{
			{name: "--dashboard-url", value: func() string { return flagV }},
			{name: "enrolment", value: func() string { return enr }},
			{name: "[org_client].org_server_url", value: func() string { return cfgV }},
		}
	}
	cases := []struct {
		name, flagV, enr, cfgV string
		origin, source, errSub string
	}{
		{name: "flag wins", flagV: "https://dash.acme/x/y", enr: "https://org.acme", cfgV: "https://cfg.acme", origin: "https://dash.acme", source: "--dashboard-url"},
		{name: "enrolment", enr: "https://org.acme:9443/", cfgV: "https://cfg.acme", origin: "https://org.acme:9443", source: "enrolment"},
		{name: "config", cfgV: "http://127.0.0.1:9443", origin: "http://127.0.0.1:9443", source: "[org_client].org_server_url"},
		{name: "none", errSub: "not enrolled"},
		{name: "not absolute", flagV: "org.acme", errSub: "absolute http(s)"},
		{name: "bad scheme", flagV: "ftp://org.acme", errSub: "absolute http(s)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origin, source, err := resolveMCPConnectOrigin(src(tc.flagV, tc.enr, tc.cfgV))
			if tc.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("err = %v, want %q", err, tc.errSub)
				}
				return
			}
			if err != nil || origin != tc.origin || source != tc.source {
				t.Fatalf("got (%q, %q, %v), want (%q, %q)", origin, source, err, tc.origin, tc.source)
			}
		})
	}
}

// TestMCPCmd_ConnectPrintsDashboardURL: the enrolled org's dashboard origin
// + the My Connections route, the table's per-user servers, no network.
func TestMCPCmd_ConnectPrintsDashboardURL(t *testing.T) {
	e := newMCPCLIEnv(t, true)
	e.seedTable(t, "https://auth.acme", "vault_user")
	st := openMCPRelayTestStore(t, e.loadCfg(t))
	if err := st.WriteEnrolment(context.Background(), store.Enrolment{OrgID: "acme", OrgServerURL: "https://org.acme:9443/api", UserID: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	out, err := runMCPCLI(t, "mcp", "connect", "--config", e.cfgPath, "--server", "gh", "--json")
	if err != nil {
		t.Fatalf("connect: %v\n%s", err, out)
	}
	var res mcpConnectResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if res.URL != "https://org.acme:9443/agent-access/connections" || res.OriginSource != "enrolment" || !res.ServerKnown ||
		res.ServerCredential != "vault_user" || len(res.ConnectableServers) != 1 || res.ConnectableServers[0].ServerID != "gh" ||
		strings.Join(res.ConnectableServers[0].VServers, ",") != "vs-gh" || len(res.Notes) != 0 {
		t.Fatalf("connect result %+v", res)
	}
	// An unknown server still gets the URL, with an honest note.
	out, err = runMCPCLI(t, "mcp", "connect", "--config", e.cfgPath, "--server", "nope")
	if err != nil || !strings.Contains(out, "https://org.acme:9443/agent-access/connections") || !strings.Contains(out, "not in this node's accepted") {
		t.Fatalf("unknown server: %v\n%s", err, out)
	}
	// --dashboard-url wins over the enrolment (split dashboard host).
	out, err = runMCPCLI(t, "mcp", "connect", "--config", e.cfgPath, "--dashboard-url", "https://dash.acme/ignored/path", "--json")
	res = mcpConnectResult{}
	if err != nil || json.Unmarshal([]byte(out), &res) != nil || res.URL != "https://dash.acme/agent-access/connections" || res.OriginSource != "--dashboard-url" {
		t.Fatalf("flag origin: %v %+v\n%s", err, res, out)
	}
	// A server the table marks service-credentialed is not a per-user
	// target: it is not listed, and naming it gets the honest note.
	e.seedTable(t, "https://auth.acme", "service")
	out, err = runMCPCLI(t, "mcp", "connect", "--config", e.cfgPath, "--server", "gh", "--json")
	res = mcpConnectResult{}
	if err != nil || json.Unmarshal([]byte(out), &res) != nil || len(res.ConnectableServers) != 0 || !res.ServerKnown ||
		len(res.Notes) != 1 || !strings.Contains(res.Notes[0], `credential_mode "service"`) {
		t.Fatalf("service server: %v %+v\n%s", err, res, out)
	}
}

// TestMCPCmd_DoctorClientRules is the per-client rule table, one case per
// row.
func TestMCPCmd_DoctorClientRules(t *testing.T) {
	cases := []struct {
		name   string
		f      mcpDoctorClientFacts
		status string
		sub    string
	}{
		{"config_gone", mcpDoctorClientFacts{tool: "cursor", verified: true, rows: 1}, mcpDoctorFail, "no longer exists"},
		{"direct_entries", mcpDoctorClientFacts{tool: "cursor", configExists: true, verified: true, unmediated: 2, rows: 1}, mcpDoctorWarn, "2 stdio entries run DIRECT"},
		{"edited_since", mcpDoctorClientFacts{tool: "cursor", configExists: true, rows: 1}, mcpDoctorWarn, "edited since"},
		{"wrapped", mcpDoctorClientFacts{tool: "cursor", configExists: true, verified: true, rows: 2}, mcpDoctorPass, "2 journaled entries"},
	}
	if len(cases) != len(mcpDoctorClientRules) {
		t.Fatalf("%d cases for %d rules", len(cases), len(mcpDoctorClientRules))
	}
	for i, tc := range cases {
		if mcpDoctorClientRules[i].name != tc.name {
			t.Fatalf("row %d is %s, case %s", i, mcpDoctorClientRules[i].name, tc.name)
		}
		c := mcpDoctorClientCheck(tc.f)
		if c.Status != tc.status || c.Name != "client:cursor" || !strings.Contains(c.Detail, tc.sub) {
			t.Errorf("%s: %+v", tc.name, c)
		}
	}
}

// fakeOrg is an httptest TLS org server: /healthz and the STS token
// endpoint, each switchable to a failure.
type fakeOrg struct {
	srv          *httptest.Server
	healthStatus int
	tokenStatus  int
	mints        int
}

func newFakeOrg(t *testing.T) *fakeOrg {
	t.Helper()
	f := &fakeOrg{healthStatus: http.StatusOK, tokenStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(f.healthStatus) })
	mux.HandleFunc("POST /oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		f.mints++
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("DPoP") == "" || r.FormValue("resource") != "https://gw.acme/mcp/github" || r.FormValue("subject_token") != "bearer" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
			return
		}
		if f.tokenStatus != http.StatusOK {
			w.WriteHeader(f.tokenStatus)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at-SECRET-VALUE","token_type":"DPoP","expires_in":300,"issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}`))
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOrg) deps(t *testing.T) func(config.Config, *store.Store, *slog.Logger) mcpDoctorDeps {
	key := testAAKey(t)
	return func(config.Config, *store.Store, *slog.Logger) mcpDoctorDeps {
		reg := orgclient.AgentAccessRegistration{CredentialID: "cred_1", MachineFP: "fp_abc", CredGen: 2, CreatedAt: "2026-09-25T10:00:00Z"}
		return mcpDoctorDeps{
			remote: mcpRelayRemoteDeps{
				keys: func() (orgclient.AgentAccessKeyStore, error) { return fakeAAKeys{key: key}, nil },
				register: func(context.Context, orgclient.AgentAccessKeyStore) (orgclient.AgentAccessRegistration, error) {
					return reg, nil
				},
				bearer: func() (string, error) { return "bearer", nil },
				egress: func(string, *store.Enrolment) *http.Client { return f.srv.Client() },
			},
			health: func(ctx context.Context, orgURL string, _ *store.Enrolment) error {
				return mcpOrgHealth(ctx, f.srv.Client(), orgURL)
			},
		}
	}
}

func doctorJSON(t *testing.T, cfgPath string) (mcpDoctorReport, map[string]mcpDoctorCheck, string, error) {
	t.Helper()
	// The JSON is printed before a non-zero exit.
	out, err := runMCPCLI(t, "mcp", "doctor", "--config", cfgPath, "--json")
	var rep mcpDoctorReport
	if jerr := json.Unmarshal([]byte(out), &rep); jerr != nil {
		t.Fatalf("doctor json: %v\n%s", jerr, out)
	}
	by := map[string]mcpDoctorCheck{}
	for _, c := range rep.Checks {
		by[c.Name] = c
	}
	return rep, by, out, err
}

// TestMCPCmd_DoctorFakeOrg runs the doctor end to end against an httptest
// org: all green after a wrap, then each failure the probes exist to catch.
func TestMCPCmd_DoctorFakeOrg(t *testing.T) {
	e := newMCPCLIEnv(t, true)
	org := newFakeOrg(t)
	cursorPath := e.writeClient(t, ".cursor/mcp.json", projTestCursor)
	e.writeClient(t, ".config/opencode/opencode.json", projTestOpenCode)
	e.seedTable(t, org.srv.URL, "service")
	st := openMCPRelayTestStore(t, e.loadCfg(t))
	if err := st.WriteEnrolment(context.Background(), store.Enrolment{OrgID: "acme", OrgServerURL: org.srv.URL, UserID: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	prev := mcpDoctorDepsFor
	mcpDoctorDepsFor = org.deps(t)
	t.Cleanup(func() { mcpDoctorDepsFor = prev })

	// Before any wrap: the clients row warns, nothing fails.
	rep, by, out, err := doctorJSON(t, e.cfgPath)
	if err != nil || rep.Failed != 0 || by["clients.wrapped"].Status != mcpDoctorWarn {
		t.Fatalf("pre-wrap doctor: %v\n%s", err, out)
	}
	if out, err := runMCPCLI(t, "mcp", "wrap", "--config", e.cfgPath, "--no-remote"); err != nil {
		t.Fatalf("wrap: %v\n%s", err, out)
	}

	rep, by, out, err = doctorJSON(t, e.cfgPath)
	if err != nil || rep.Failed != 0 || rep.Warned != 0 {
		t.Fatalf("green doctor: %v\n%s", err, out)
	}
	for _, name := range []string{"relay.config", "relay.enabled", "org.enrolled", "org.reachable", "table.loaded", "sts.registered", "sts.mint", "client:cursor", "client:opencode", "journal.consistent", "record.chain"} {
		if by[name].Status != mcpDoctorPass {
			t.Errorf("%s = %+v", name, by[name])
		}
	}
	if strings.Contains(out, "at-SECRET-VALUE") {
		t.Fatal("doctor printed the minted token")
	}
	if org.mints == 0 {
		t.Fatal("sts.mint never reached the STS")
	}

	// Each failure row, table-driven: break -> expect -> restore.
	cursorBytes := mcpReadFile(t, cursorPath)
	rows := journalRows(t, e)
	var backup string
	for _, r := range rows {
		if r.Client == "cursor" {
			backup = r.BackupPath
		}
	}
	backupBytes := mcpReadFile(t, backup)
	cases := []struct {
		name    string
		break_  func()
		restore func()
		check   string
		status  string
		sub     string
	}{
		{
			"org down", func() { org.healthStatus = http.StatusServiceUnavailable }, func() { org.healthStatus = http.StatusOK },
			"org.reachable", mcpDoctorFail, "503",
		},
		{
			"sts refuses", func() { org.tokenStatus = http.StatusBadRequest }, func() { org.tokenStatus = http.StatusOK },
			"sts.mint", mcpDoctorFail, "invalid_grant",
		},
		{
			"backup tampered", func() { _ = os.WriteFile(backup, []byte("tampered"), 0o600) }, func() { _ = os.WriteFile(backup, []byte(backupBytes), 0o600) },
			"journal.consistent", mcpDoctorFail, "hash mismatch",
		},
		{
			"config removed", func() { _ = os.Remove(cursorPath) }, func() { _ = os.WriteFile(cursorPath, []byte(cursorBytes), 0o644) },
			"client:cursor", mcpDoctorFail, "no longer exists",
		},
		{
			"config edited", func() {
				_ = os.WriteFile(cursorPath, []byte(strings.Replace(cursorBytes, `"theme": "dark"`, `"theme": "light"`, 1)), 0o644)
			}, func() { _ = os.WriteFile(cursorPath, []byte(cursorBytes), 0o644) },
			"client:cursor", mcpDoctorWarn, "edited since",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.break_()
			defer tc.restore()
			rep, by, out, err := doctorJSON(t, e.cfgPath)
			c := by[tc.check]
			if c.Status != tc.status || !strings.Contains(c.Detail, tc.sub) {
				t.Fatalf("%s = %+v\n%s", tc.check, c, out)
			}
			if (tc.status == mcpDoctorFail) != (err != nil) || (tc.status == mcpDoctorFail) != (rep.Failed > 0) {
				t.Fatalf("exit %v failed=%d for a %s row", err, rep.Failed, tc.status)
			}
		})
	}
	// An unreachable org skips the STS probes (never a guessed result).
	org.healthStatus = http.StatusServiceUnavailable
	_, by, _, _ = doctorJSON(t, e.cfgPath)
	if by["sts.registered"].Status != mcpDoctorSkip || by["sts.mint"].Status != mcpDoctorSkip {
		t.Fatalf("an unreachable org must skip the STS probes: %+v / %+v", by["sts.registered"], by["sts.mint"])
	}
	org.healthStatus = http.StatusOK

	// Switched off by hand without unwrap: the stranded journal fails the
	// doctor, with no network probe at all.
	e.writeConfig(t, false, "")
	mcpDoctorDepsFor = func(config.Config, *store.Store, *slog.Logger) mcpDoctorDeps {
		t.Error("doctor built network deps with the relay disabled")
		return mcpDoctorDeps{}
	}
	_, by, out, err = doctorJSON(t, e.cfgPath)
	if err == nil || by["journal.consistent"].Status != mcpDoctorFail || !strings.Contains(by["journal.consistent"].Detail, "observer mcp unwrap") {
		t.Fatalf("stranded journal: %v\n%s", err, out)
	}
	if out, err := runMCPCLI(t, "mcp", "status", "--config", e.cfgPath); err != nil || !strings.Contains(out, "WARNING: the launch journal still holds 2 row(s)") {
		t.Fatalf("disabled status with a stranded journal: %v\n%s", err, out)
	}
}

// journalRows lists the launch journal of the env's node DB.
func journalRows(t *testing.T, e mcpCLIEnv) []mcpLaunchRow {
	t.Helper()
	_, database, cleanup, err := loadConfigAndDB(context.Background(), e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	specs, err := record.NewSQLStore(database, "").ListLaunchSpecs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := make([]mcpLaunchRow, 0, len(specs))
	for _, s := range specs {
		out = append(out, mcpLaunchRow{Client: s.Client, BackupPath: s.BackupPath})
	}
	return out
}

// mcpLaunchRow is the slice of a journal row the doctor test mutates.
type mcpLaunchRow struct{ Client, BackupPath string }

// TestMCPCmd_DoctorVerifyChainIdentities pins the record.chain probe's two
// legitimate genesis identities: a chain begun BEFORE enrolment verifies
// from "node:<db path>" after the node enrols, and a tampered row fails
// under both.
func TestMCPCmd_DoctorVerifyChainIdentities(t *testing.T) {
	ctx := context.Background()
	e := newMCPCLIEnv(t, true)
	cfg, database, cleanup, err := loadConfigAndDB(ctx, e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	st := store.New(database)
	env := &mcpDoctorEnv{ctx: ctx, cfg: cfg, database: database, st: st}
	pre := record.NewSQLStore(database, mcpRelayNodeKey(ctx, cfg, st)) // not enrolled yet
	for i := int64(1); i <= 2; i++ {
		if _, err := pre.Append(ctx, record.Record{Kind: record.KindGap, TS: 1_700_000_000 + i, GapFrom: record.Int(i), GapTo: record.Int(i), LostCount: record.Int(1), GapReason: "local_append_failed"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.WriteEnrolment(ctx, store.Enrolment{OrgID: "acme", OrgServerURL: "https://org.acme", UserID: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	vr, key, err := mcpDoctorVerifyChain(env)
	if err != nil || !vr.OK() || vr.Records != 2 || key != "node:"+cfg.Observer.DBPath {
		t.Fatalf("pre-enrolment chain: ok=%v records=%d key=%q err=%v", vr.OK(), vr.Records, key, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE mcp_relay_record SET lost_count = 99 WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	vr, key, err = mcpDoctorVerifyChain(env)
	if err != nil || vr.OK() || key != "member:usr_1" {
		t.Fatalf("tampered chain verified: ok=%v key=%q err=%v", vr.OK(), key, err)
	}
}

// TestMCPRelayStatus_VerifiesChainWithNodeKey pins the status fix: the
// record store is opened with the node's REAL genesis identity
// (mcpRelayNodeKey), so a chain the relay wrote verifies ("ok",
// chain_ok=true) and a tampered one reports TAMPER - under both spellings.
// With the old empty key Verify returned ErrNoNodeKey and status always
// printed "unverified" with no chain_ok.
func TestMCPRelayStatus_VerifiesChainWithNodeKey(t *testing.T) {
	ctx := context.Background()
	e := newMCPCLIEnv(t, true)
	cfg, database, cleanup, err := loadConfigAndDB(ctx, e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(database)
	if err := st.WriteEnrolment(ctx, store.Enrolment{OrgID: "acme", OrgServerURL: "https://org.acme", UserID: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	rs := record.NewSQLStore(database, mcpRelayNodeKey(ctx, cfg, st))
	for i := int64(1); i <= 2; i++ {
		if _, err := rs.Append(ctx, record.Record{Kind: record.KindGap, TS: 1_700_000_000 + i, GapFrom: record.Int(i), GapTo: record.Int(i), LostCount: record.Int(1), GapReason: "local_append_failed"}); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, error) {
		root := &cobra.Command{Use: "observer", SilenceUsage: true, SilenceErrors: true}
		root.AddCommand(newMCPCmd(), newMCPRelayCmd())
		var buf bytes.Buffer
		root.SetOut(&buf)
		root.SetErr(&buf)
		root.SetArgs(args)
		err := root.ExecuteContext(ctx)
		return buf.String(), err
	}
	check := func(wantOK bool, wantText string) {
		t.Helper()
		for _, spelling := range [][]string{{"mcp", "status"}, {"mcp-relay", "status"}} {
			out, err := run(append(spelling, "--config", e.cfgPath, "--json", "--no-remote")...)
			if err != nil {
				t.Fatalf("%v: %v\n%s", spelling, err, out)
			}
			var s mcpRelayStatus
			if err := json.Unmarshal([]byte(out), &s); err != nil {
				t.Fatalf("%v json: %v\n%s", spelling, err, out)
			}
			if s.ChainHead != 2 || s.ChainOK == nil || *s.ChainOK != wantOK {
				t.Fatalf("%v: chain_head=%d chain_ok=%v, want head 2 ok %v", spelling, s.ChainHead, s.ChainOK, wantOK)
			}
			out, err = run(append(spelling, "--config", e.cfgPath, "--no-remote", "--no-matrix")...)
			if err != nil || !strings.Contains(out, "record chain: head=2 verify="+wantText) {
				t.Fatalf("%v text: %v\n%s", spelling, err, out)
			}
		}
	}
	check(true, "ok")
	if _, err := database.ExecContext(ctx, `UPDATE mcp_relay_record SET lost_count = 99 WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	cleanup()
	check(false, "TAMPER")
}
