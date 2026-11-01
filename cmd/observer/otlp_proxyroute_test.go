//go:build !sbo_omit_ingest_otlp

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/diag"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/otlpvendor"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/store"

	"google.golang.org/protobuf/proto"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// TestOTLPProxyOwnsTokens is T-536 end to end over the live codex capture
// with the codex transcript adapter OFF (so the export would otherwise own
// every kind): when the codex proxy route is active, either from the
// persisted route or from the launcher's resource marker, the export's
// token rows are dropped and its tool calls still land; with no route the
// turns land as before.
func TestOTLPProxyOwnsTokens(t *testing.T) {
	codexFx := liveOTLPFixtures[0]
	body, ctype := wireBody(t, codexFx)
	marked := markCodexExport(t, body)
	for _, tc := range []struct {
		name      string
		routed    func(string) bool
		body      []byte
		wantTurns int
	}{
		{"no route: the export owns its tokens", nil, body, codexFx.turns},
		{"persisted route active: the proxy owns them", func(tool string) bool { return tool == "codex" }, body, 0},
		{"another tool routed: codex keeps its tokens", func(tool string) bool { return tool == "qwen-code" }, body, codexFx.turns},
		{"launcher marker on the export: the proxy owns them", nil, marked, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = database.Close() })
			ing := newOTLPIngest(store.New(database), slog.New(slog.NewTextHandler(io.Discard, nil)), true,
				config.DefaultIngestOTelContentMaxBytes, func(string) bool { return false }).withProxyRoutes(tc.routed)
			recv, err := otlpingest.New(otlpingest.Options{HTTPAddr: "127.0.0.1:0", Handler: ing.logs, TraceHandler: ing.traces(nil)})
			if err != nil {
				t.Fatal(err)
			}
			recv.Start()
			t.Cleanup(func() {
				sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = recv.Shutdown(sctx)
			})
			postOTLP(t, "http://"+recv.HTTPAddr()+codexFx.path, tc.body, ctype)
			if got := countRows(t, database, `SELECT COUNT(*) FROM api_turns WHERE session_id = ?`, codexFx.session); got != tc.wantTurns {
				t.Errorf("api_turns = %d, want %d", got, tc.wantTurns)
			}
			if got := countRows(t, database, `SELECT COUNT(*) FROM actions WHERE session_id = ? AND source_file = 'otlp:codex'`, codexFx.session); got != codexFx.tools {
				t.Errorf("tool-call actions = %d, want %d (the export still adds what the proxy cannot see)", got, codexFx.tools)
			}
		})
	}
}

// markCodexExport adds the launcher's route marker to every resource of a
// protobuf logs export.
func markCodexExport(t *testing.T, body []byte) []byte {
	t.Helper()
	var req collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	for _, rl := range req.GetResourceLogs() {
		rl.Resource.Attributes = append(rl.Resource.Attributes, &commonpb.KeyValue{
			Key: otlpvendor.RouteResourceAttr, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: otlpvendor.RouteProxy}},
		}, &commonpb.KeyValue{
			Key: otlpvendor.RouteToolResourceAttr, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "codex"}},
		})
	}
	out, err := proto.Marshal(&req)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestProxyRouteResolverCaches pins the boundary resolver: only an Observer
// route counts, a disabled proxy never routes, and one inspection is reused
// for otlpRouteTTL so a burst of exports does not re-read config files.
func TestProxyRouteResolverCaches(t *testing.T) {
	calls := 0
	now := time.Unix(1000, 0)
	r := &proxyRouteResolver{
		enabled: true,
		now:     func() time.Time { return now },
		inspect: func() []proxyroute.RouteStatus {
			calls++
			return []proxyroute.RouteStatus{
				{Tool: "codex", State: proxyroute.RouteOurs},
				{Tool: "qwen-code", State: proxyroute.RouteDrifted},
				{Tool: "claude-code", State: proxyroute.RouteAbsent},
			}
		},
	}
	if !r.Routed("codex") || r.Routed("qwen-code") || r.Routed("claude-code") || r.Routed("gemini-cli") {
		t.Fatal("only the tool whose route points at an Observer proxy is routed")
	}
	if calls != 1 {
		t.Fatalf("inspections = %d, want 1 (cached)", calls)
	}
	now = now.Add(otlpRouteTTL)
	_ = r.Routed("codex")
	if calls != 2 {
		t.Fatalf("inspections after the TTL = %d, want 2", calls)
	}
	off := &proxyRouteResolver{enabled: false, inspect: r.inspect, now: r.now}
	if off.Routed("codex") {
		t.Fatal("a node whose proxy is off never routes a tool")
	}
}

// TestWithOTelRouteMarker pins the launcher marker's env edit: appended to
// what the user set, added when absent, never duplicated, scoped to the
// launched tool, and an outer launch's marker replaced (P3-36).
func TestWithOTelRouteMarker(t *testing.T) {
	marker := otlpvendor.RouteResourceAttr + "=" + otlpvendor.RouteProxy + "," + otlpvendor.RouteToolResourceAttr + "=codex"
	for _, tc := range []struct {
		name string
		in   []string
		want string
	}{
		{"absent", []string{"PATH=/bin"}, marker},
		{"user attributes kept", []string{"OTEL_RESOURCE_ATTRIBUTES=team=a,env=dev"}, "team=a,env=dev," + marker},
		{"already marked", []string{"OTEL_RESOURCE_ATTRIBUTES=team=a," + marker}, "team=a," + marker},
		{"empty value", []string{"OTEL_RESOURCE_ATTRIBUTES="}, marker},
		{"outer launch's marker replaced", []string{"OTEL_RESOURCE_ATTRIBUTES=sbo.route=proxy,team=a,sbo.route.tool=gemini-cli"}, "team=a," + marker},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := withOTelRouteMarker(tc.in, "codex")
			got, n := "", 0
			for _, e := range out {
				if strings.HasPrefix(e, "OTEL_RESOURCE_ATTRIBUTES=") {
					got = strings.TrimPrefix(e, "OTEL_RESOURCE_ATTRIBUTES=")
					n++
				}
			}
			if n != 1 || got != tc.want {
				t.Fatalf("OTEL_RESOURCE_ATTRIBUTES = %q (%d entries), want %q once", got, n, tc.want)
			}
		})
	}
}

// TestOTLPTokenOwnerCheck pins the doctor row that explains T-536.
func TestOTLPTokenOwnerCheck(t *testing.T) {
	routed := []proxyroute.RouteStatus{{Tool: "codex", State: proxyroute.RouteOurs}, {Tool: "claude-code", State: proxyroute.RouteOurs}}
	var on, offProxy, offIngest config.Config
	on.Ingest.OTel.Enabled, on.Proxy.Enabled = true, true
	offProxy.Ingest.OTel.Enabled = true
	offIngest.Proxy.Enabled = true

	// The serving fact is passed in (proxyServingReason, pinned below), so
	// this row's own logic is the same in every build.
	const proxyOffReason = "the proxy is off on this node ([proxy].enabled = false)"
	c := otlpTokenOwnerCheck(on, "", routed)
	if c.Status != diag.StatusOK || !strings.Contains(c.Message, "codex") || strings.Contains(c.Message, "claude-code") {
		t.Errorf("routed codex: %+v (claude code merges by request id and must not be listed)", c)
	}
	if !strings.Contains(strings.Join(c.Details, "\n"), "codex: proxy route active") {
		t.Errorf("details do not explain codex: %v", c.Details)
	}
	if c := otlpTokenOwnerCheck(offProxy, proxyOffReason, routed); strings.Contains(c.Message, "owns token rows for") {
		t.Errorf("proxy off: %+v", c)
	}
	if c := otlpTokenOwnerCheck(offIngest, proxyOffReason, routed); !strings.Contains(c.Message, "OTLP ingest is off") {
		t.Errorf("ingest off: %+v", c)
	}
	if c := otlpTokenOwnerCheck(on, "", nil); strings.Contains(c.Message, "owns token rows for") {
		t.Errorf("nothing routed: %+v", c)
	}
	// REVIEW-4 P4-18: [proxy].enabled on, but this node serves no proxy
	// (capture.proxy inactive or not in the build): the export keeps its
	// token rows and the row names why.
	reason := proxyServingReason(on, false)
	if reason == "" {
		t.Fatal("capture.proxy inactive must yield a reason")
	}
	if c := otlpTokenOwnerCheck(on, reason, routed); strings.Contains(c.Message, "owns token rows for") || !strings.Contains(c.Message, "capture.proxy") {
		t.Errorf("capture.proxy inactive: %+v", c)
	}
	if newProxyRouteResolver(reason == "", t.TempDir()).Routed("codex") {
		t.Error("a resolver for a node that serves no proxy must never hand token ownership to it")
	}
}

// TestProxyRouteResolverInactiveProvider pins CLI-3 on the OTLP token owner:
// a Qwen Code route in settings.json whose selected auth type is another
// provider does not reach the proxy, so the proxy does not own its tokens.
// On the old code Routed answered true from the base URL alone.
func TestProxyRouteResolverInactiveProvider(t *testing.T) {
	cases := []struct {
		name, authType string
		want           bool
	}{
		{"openai: routed", "openai", true},
		{"another provider: the route is not used", "gemini", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := pinToolHomes(t)
			p := filepath.Join(home, ".qwen", "settings.json")
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			body := `{"model":{"baseUrl":"http://127.0.0.1:8820/v1"},"security":{"auth":{"selectedType":"` + tc.authType + `"}}}`
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			r := newProxyRouteResolver(true, home)
			if got := r.Routed("qwen-code"); got != tc.want {
				t.Fatalf("Routed(qwen-code) = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestProxyServingReason pins proxyServingReason's ordered table: the build
// first, then the component, then [proxy].enabled.
func TestProxyServingReason(t *testing.T) {
	var on, off config.Config
	on.Proxy.Enabled = true
	if proxyNotInBuild() {
		if r := proxyServingReason(on, true); !strings.Contains(r, "not in this build") {
			t.Errorf("no proxy in the build: reason %q", r)
		}
		return
	}
	for _, tc := range []struct {
		cfg    config.Config
		active bool
		want   string
	}{
		{on, true, ""},
		{on, false, "capture.proxy) is inactive"},
		{off, true, "[proxy].enabled = false"},
		{off, false, "capture.proxy) is inactive"},
	} {
		got := proxyServingReason(tc.cfg, tc.active)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("enabled=%v active=%v: reason %q, want %q", tc.cfg.Proxy.Enabled, tc.active, got, tc.want)
		}
	}
}
