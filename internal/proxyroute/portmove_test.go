package proxyroute

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// portmove_test.go: moving a route Observer wrote to the daemon's new proxy
// port after a [proxy].port change (D-745). One test per rule row: the own
// route is moved and the drift clears; a foreign route, or an own route with
// any other difference, is untouched and still reported; the release and
// unset postures make no write.

// portRegistrar is a managed registrar on another proxy port.
func portRegistrar(t *testing.T, home string, port int) *Registrar {
	t.Helper()
	r, err := NewRegistrar(RegisterOptions{ProxyPort: port, HomeDir: home, Writer: routeprov.WriterManaged})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// onPort9100 is the maintained drift reading after the port moved to 9100.
var onPort9100 = DriftPolicy{Mode: DriftModeMaintained, ProxyPort: 9100}

// TestMaintainRoutesMovesItsOwnRouteToTheNewPort: routes the managed daemon
// wrote on :8820 are moved to :9100 in place, nothing else changes, the
// drift clears, and Leave still owns them.
func TestMaintainRoutesMovesItsOwnRouteToTheNewPort(t *testing.T) {
	home := maintainHome(t)
	claudePath := filepath.Join(home, ".claude", "settings.json")
	codexPath := filepath.Join(home, ".codex", "config.toml")
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", claudeSettingsFixture)
	writeFile(t, filepath.Join(home, ".codex"), "config.toml", codexConfigFixture)
	maintainRegistrar(t, home).MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)})
	claudeBefore, codexBefore := readBytes(t, claudePath), readBytes(t, codexPath)

	for _, tool := range []string{"claude-code", "codex"} {
		if st := statusFor(InspectRoutes(home), tool); st.Port != 8820 || !st.OrgWrittenExact {
			t.Fatalf("%s before the move: %+v, want port 8820 and OrgWrittenExact", tool, st)
		}
	}
	if d := DriftedTools(InspectRoutes(home), onPort9100); !reflect.DeepEqual(d, []string{"claude-code", "codex"}) {
		t.Fatalf("drift after the port change = %v, want [claude-code codex]", d)
	}

	at := time.Now().UTC().Truncate(time.Second)
	r := portRegistrar(t, home, 9100)
	got := r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true), Now: func() time.Time { return at }})
	for _, tool := range []string{"claude-code", "codex"} {
		res := resultFor(got, tool)
		if !res.Written || res.Repaired || res.Error != nil || res.Decision.Reason != ReasonPortMoved {
			t.Fatalf("%s: %+v, want a port_moved write", tool, res)
		}
	}
	// Only the port changed, byte for byte.
	if b := readBytes(t, claudePath); b != strings.ReplaceAll(claudeBefore, "127.0.0.1:8820", "127.0.0.1:9100") {
		t.Fatalf("claude-code after the move:\n%s\nbefore:\n%s", b, claudeBefore)
	}
	if b := readBytes(t, codexPath); b != strings.ReplaceAll(codexBefore, "127.0.0.1:8820", "127.0.0.1:9100") {
		t.Fatalf("codex after the move:\n%s\nbefore:\n%s", b, codexBefore)
	}
	if d := DriftedTools(InspectRoutes(home), onPort9100); len(d) != 0 {
		t.Fatalf("drift after the move = %v, want none", d)
	}
	for _, tool := range []string{"claude-code", "codex"} {
		if st := statusFor(InspectRoutes(home), tool); st.State != RouteOurs || st.Port != 9100 || !st.OrgWrittenExact {
			t.Fatalf("%s after the move: %+v, want ours on 9100", tool, st)
		}
	}
	// The record follows the route: the move is reported as a write, and
	// turning maintenance off still removes both routes.
	acts := RecentRouteActs(home, at.Add(time.Minute), 24*time.Hour)
	if len(acts) != 2 || !acts[0].At.Equal(at) || !acts[1].At.Equal(at) {
		t.Fatalf("RecentRouteActs = %+v, want two acts at %v", acts, at)
	}
	plan, err := r.ReleaseManagedRoutes(false)
	if err != nil || len(plan) != 2 {
		t.Fatalf("release plan = %+v, %v", plan, err)
	}
	for _, lr := range plan {
		if lr.Action != routeprov.ActionRemove {
			t.Fatalf("release plan for %s = %+v, want remove", lr.Tool, lr)
		}
	}
	// A second pass changes nothing.
	for _, res := range r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)}) {
		if res.Written || res.Error != nil {
			t.Fatalf("second pass touched %s: %+v", res.Tool, res)
		}
	}
}

// TestMaintainRoutesMovesALaneRoute: a third-party provider lane route keeps
// its lane id and provider path; only the port changes, and release still
// restores the original provider host byte for byte.
func TestMaintainRoutesMovesALaneRoute(t *testing.T) {
	home := maintainHome(t)
	path := filepath.Join(home, ".kimi-code", "config.toml")
	writeFile(t, filepath.Join(home, ".kimi-code"), "config.toml", kimiLaneFixture)
	install := func(string, string) error { return nil }
	maintainRegistrar(t, home).MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true), InstallLane: install})

	r := portRegistrar(t, home, 9100)
	res := resultFor(r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true), InstallLane: install}), "kimi-code")
	if !res.Written || res.Error != nil || res.Decision.Reason != ReasonPortMoved {
		t.Fatalf("kimi-code: %+v, want a port_moved write", res)
	}
	want := strings.Replace(kimiLaneFixture, `base_url = "https://llm.example.com/v1"`, `base_url = "http://127.0.0.1:9100/up/route-llm-example-com/v1"`, 1)
	if b := readBytes(t, path); b != want {
		t.Fatalf("kimi-code after the move:\n%s\nwant\n%s", b, want)
	}
	if d := DriftedTools(InspectRoutes(home), onPort9100); len(d) != 0 {
		t.Fatalf("drift after the move = %v, want none", d)
	}
	if lanes, err := r.RouteLanes(); err != nil || !reflect.DeepEqual(lanes, map[string]string{"route-llm-example-com": "https://llm.example.com"}) {
		t.Fatalf("RouteLanes = %v, %v", lanes, err)
	}
	if out, err := r.ReleaseManagedRoutes(true); err != nil || len(out) != 1 || !out[0].Removed {
		t.Fatalf("release = %+v, %v", out, err)
	}
	if b := readBytes(t, path); b != kimiLaneFixture {
		t.Fatalf("kimi-code after release:\n%s\nwant\n%s", b, kimiLaneFixture)
	}
}

// TestMaintainRoutesMovesAQwenLaneRoute: qwen-code's move also retargets the
// openai-lane provider entries the lane write retargeted, and only those.
func TestMaintainRoutesMovesAQwenLaneRoute(t *testing.T) {
	home := maintainHome(t)
	const body = `{"model":{"name":"qwen/qwen3-coder","baseUrl":"https://openrouter.ai/api/v1"},"modelProviders":{"openai":[{"id":"qwen/qwen3-coder","baseUrl":"https://openrouter.ai/api/v1","envKey":"OPENROUTER_API_KEY"},{"id":"other","baseUrl":"https://dashscope.example.com/v1","envKey":"DASH"}]}}`
	path := filepath.Join(home, ".qwen", "settings.json")
	writeFile(t, filepath.Join(home, ".qwen"), "settings.json", body)
	install := func(string, string) error { return nil }
	maintainRegistrar(t, home).MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true), InstallLane: install})
	before := readBytes(t, path)

	res := resultFor(portRegistrar(t, home, 9100).MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true), InstallLane: install}), "qwen-code")
	if !res.Written || res.Error != nil || res.Decision.Reason != ReasonPortMoved {
		t.Fatalf("qwen-code: %+v, want a port_moved write", res)
	}
	var got, want any
	if err := json.Unmarshal([]byte(readBytes(t, path)), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(strings.ReplaceAll(before, "127.0.0.1:8820", "127.0.0.1:9100")), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("qwen-code after the move:\n%s\nbefore:\n%s", readBytes(t, path), before)
	}
	if d := DriftedTools(InspectRoutes(home), onPort9100); len(d) != 0 {
		t.Fatalf("drift after the move = %v, want none", d)
	}
}

// TestPortMoveNeedsProof: a route at another local port that Observer did
// not provably write is never overwritten and stays other_port drift.
func TestPortMoveNeedsProof(t *testing.T) {
	record := func(value string, writer routeprov.Writer) func(t *testing.T, home string) {
		return func(t *testing.T, home string) {
			t.Helper()
			f := routeprov.File{}
			f.Note(routeprov.Record{
				Tool: "claude-code", ConfigPath: filepath.Join(home, ".claude", "settings.json"),
				Value: value, Writer: writer, WrittenAt: "2026-10-01T00:00:00Z",
			}, routeprov.OutcomeWrote)
			if err := saveProvenance(filepath.Join(home, ".observer", ProvenanceFileName), f); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []struct {
		name  string
		route string
		prov  func(t *testing.T, home string)
	}{
		{"foreign: no record", "http://127.0.0.1:8820", func(*testing.T, string) {}},
		{"the developer's own observer init route", "http://127.0.0.1:8820", record("http://127.0.0.1:8820", routeprov.WriterInit)},
		{"edited since the organization wrote it", "http://127.0.0.1:8820/v1", record("http://127.0.0.1:8820", routeprov.WriterManaged)},
		{"differs from what Observer writes besides the port", "http://localhost:8820", record("http://localhost:8820", routeprov.WriterEnrolment)},
		{"unreadable provenance proves nothing", "http://127.0.0.1:8820", func(t *testing.T, home string) {
			writeFile(t, filepath.Join(home, ".observer"), ProvenanceFileName, "{not json")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := maintainHome(t)
			body := `{"env":{"ANTHROPIC_BASE_URL":"` + tc.route + `"}}`
			writeFile(t, filepath.Join(home, ".claude"), "settings.json", body)
			tc.prov(t, home)
			if st := statusFor(InspectRoutes(home), "claude-code"); st.OrgWrittenExact {
				t.Fatalf("status = %+v, want no proof of ownership", st)
			}
			res := resultFor(portRegistrar(t, home, 9100).MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)}), "claude-code")
			if res.Written || res.Decision.Reason != ReasonOtherPort {
				t.Fatalf("claude-code: %+v, want other_port", res)
			}
			if readBytes(t, filepath.Join(home, ".claude", "settings.json")) != body {
				t.Fatal("maintenance overwrote a route it cannot prove it wrote")
			}
			if d := DriftedTools(InspectRoutes(home), onPort9100); !reflect.DeepEqual(d, []string{"claude-code"}) {
				t.Fatalf("drift = %v, want [claude-code]", d)
			}
		})
	}
}

// TestPortMoveOnlyUnderMaintain: the release and unset postures keep R6's
// behaviour. Maintenance is not required there, so the own route at the old
// port is not moved; release reads nothing as drift and unset reads the
// organization's route at another port as drift, as before.
func TestPortMoveOnlyUnderMaintain(t *testing.T) {
	home := maintainHome(t)
	path := filepath.Join(home, ".claude", "settings.json")
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", claudeSettingsFixture)
	maintainRegistrar(t, home).MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)})
	before := readBytes(t, path)

	res := resultFor(portRegistrar(t, home, 9100).MaintainRoutes(MaintainOptions{Required: false, ProxyHealthy: always(true)}), "claude-code")
	if res.Written || res.Decision.Reason != ReasonNotRequired {
		t.Fatalf("claude-code: %+v, want not_required", res)
	}
	if readBytes(t, path) != before {
		t.Fatal("a pass that is not required moved a route")
	}
	if d := DriftedTools(InspectRoutes(home), DriftPolicy{Mode: DriftModeOff, ProxyPort: 9100}); len(d) != 0 {
		t.Fatalf("release: drift = %v, want none", d)
	}
	if d := DriftedTools(InspectRoutes(home), DriftPolicy{Mode: DriftModeOrgRoutes, ProxyPort: 9100}); !reflect.DeepEqual(d, []string{"claude-code"}) {
		t.Fatalf("unset: drift = %v, want [claude-code]", d)
	}
}

// TestPortMoveKeepsTheClientToken: a route the managed daemon wrote in the
// proxy client token form is still provably its own after a port change and
// moves with its token; only the port differs (OSH-R-009, audit F4).
func TestPortMoveKeepsTheClientToken(t *testing.T) {
	home := maintainHome(t)
	claudePath := filepath.Join(home, ".claude", "settings.json")
	codexPath := filepath.Join(home, ".codex", "config.toml")
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", claudeSettingsFixture)
	writeFile(t, filepath.Join(home, ".codex"), "config.toml", codexConfigFixture)
	tokenReg := func(port int) *Registrar {
		r, err := NewRegistrar(RegisterOptions{ProxyPort: port, HomeDir: home, Writer: routeprov.WriterManaged, ClientToken: testClientToken})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	tokenReg(8820).MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)})
	claudeBefore, codexBefore := readBytes(t, claudePath), readBytes(t, codexPath)
	for _, b := range []string{claudeBefore, codexBefore} {
		if !strings.Contains(b, "127.0.0.1:8820/t/"+testClientToken) {
			t.Fatalf("route not written in the token form:\n%s", b)
		}
	}
	for _, tool := range []string{"claude-code", "codex"} {
		if st := statusFor(InspectRoutes(home), tool); !st.OrgWrittenExact || !st.ClientAuth {
			t.Fatalf("%s: %+v, want OrgWrittenExact on the token form", tool, st)
		}
	}
	got := tokenReg(9100).MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)})
	for _, tool := range []string{"claude-code", "codex"} {
		if res := resultFor(got, tool); !res.Written || res.Error != nil || res.Decision.Reason != ReasonPortMoved {
			t.Fatalf("%s: %+v, want a port_moved write", tool, res)
		}
	}
	if b := readBytes(t, claudePath); b != strings.ReplaceAll(claudeBefore, "127.0.0.1:8820", "127.0.0.1:9100") {
		t.Fatalf("claude-code after the move:\n%s", b)
	}
	if b := readBytes(t, codexPath); b != strings.ReplaceAll(codexBefore, "127.0.0.1:8820", "127.0.0.1:9100") {
		t.Fatalf("codex after the move:\n%s", b)
	}
}
