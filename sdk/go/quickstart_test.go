package superbased

// Go-side tests of the service name and the first-trace line beyond the
// shared cases (quickstart_contract_test.go): the ladder's edges and the
// line through real exports. Fakes only.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestServiceNameLadderEdges(t *testing.T) {
	cases := []struct {
		name     string
		explicit string
		env      map[string]string
		module   string
		want     string
		source   string
	}{
		{"argument is trimmed, never normalised", "  Checkout API ", nil, "", "Checkout API", "argument"},
		{"a blank argument is unset", "  ", nil, "github.com/acme/bot", "bot", "manifest"},
		{"a blank env is unset", "", map[string]string{"SUPERBASED_SERVICE_NAME": "  "}, "github.com/acme/bot", "bot", "manifest"},
		{"normalised", "", nil, "example.com/Acme/My Bot!!", "my-bot", "manifest"},
		{"underscores kept inside, trimmed outside", "", nil, "example.com/_support_bot_", "support_bot", "manifest"},
		{"a v1 element is a version too", "", nil, "github.com/acme/ledger/v1", "ledger", "manifest"},
		{"a lone version element is a name", "", nil, "v2", "v2", "manifest"},
		{"no build info", "", nil, "", "custom-app", "default"},
		{"nothing left after normalising", "", nil, "example.com/--", "custom-app", "default"},
	}
	for _, c := range cases {
		name, source := serviceNameLadder(c.explicit, mapEnv(c.env), moduleServiceName(c.module))
		if name != c.want || source != c.source {
			t.Errorf("%s: (%q, %s), want (%q, %s)", c.name, name, source, c.want, c.source)
		}
	}
	if got := normaliseServiceName(strings.Repeat("ab", 40)); len(got) != serviceNameMax {
		t.Fatalf("not cut: %d", len(got))
	}
	if got := normaliseServiceName(strings.Repeat("a", 63) + "_b"); got != strings.Repeat("a", 63) {
		t.Fatalf("an underscore after the cut: %q", got)
	}
}

func TestServiceNameFromBuildInfo(t *testing.T) {
	setup(t)
	prev := mainModulePath
	mainModulePath = func() string { return "github.com/acme/support-bot/v2" }
	t.Cleanup(func() { mainModulePath = prev })
	memInit(t, Options{})
	d := GetDiagnostics()
	if d.ServiceName != "support-bot" || d.ServiceNameSource != "manifest" {
		t.Fatalf("%q %q", d.ServiceName, d.ServiceNameSource)
	}
	t.Setenv("OTEL_SERVICE_NAME", "from-env")
	memInit(t, Options{})
	if d := GetDiagnostics(); d.ServiceName != "from-env" || d.ServiceNameSource != "env" {
		t.Fatalf("env: %q %q", d.ServiceName, d.ServiceNameSource)
	}
}

func TestFirstTraceAllowed(t *testing.T) {
	cases := []struct {
		terminal bool
		env      map[string]string
		want     bool
	}{
		{true, nil, true},
		{false, nil, false},
		{true, map[string]string{"CI": "true"}, false},
		{true, map[string]string{"CI": "1"}, false},
		{true, map[string]string{"CI": ""}, true},
		{true, map[string]string{"CI": "0"}, true},
		{true, map[string]string{"CI": "False"}, true},
		{true, map[string]string{EnvFirstTraceLink: "0"}, false},
		{true, map[string]string{EnvFirstTraceLink: "off"}, false},
		{true, map[string]string{EnvFirstTraceLink: "FALSE"}, false},
		{true, map[string]string{EnvFirstTraceLink: "1"}, true},
		{true, map[string]string{EnvFirstTraceLink: ""}, true},
	}
	for i, c := range cases {
		if got := firstTraceAllowed(c.terminal, mapEnv(c.env)); got != c.want {
			t.Errorf("%d %+v: %t", i, c, got)
		}
	}
}

func TestFirstTraceTrackerOrder(t *testing.T) {
	const a, b = "4bf92f3577b34da6a3ce929d0e0e4736", "0af7651916cd43dd8448eb211c80319c"
	both := firstTraceBases{local: "http://127.0.0.1:8081", online: "https://o", waitOnline: true}
	yes := func() bool { return true }
	for _, c := range []struct {
		name  string
		steps func(tr *firstTraceTracker, out *bytes.Buffer)
		want  string
	}{
		{"both: online fails first, then local succeeds", func(tr *firstTraceTracker, out *bytes.Buffer) {
			tr.note(both, DestinationOnline, a, false, nil, yes, out)
			tr.note(both, DestinationLocal, a, true, nil, yes, out)
		}, "http://127.0.0.1:8081/apps/traces?trace=" + a},
		{"both: local waits, online succeeds later for the same trace", func(tr *firstTraceTracker, out *bytes.Buffer) {
			tr.note(both, DestinationLocal, a, true, nil, yes, out)
			tr.note(both, DestinationOnline, a, true, nil, yes, out)
		}, "https://o/trajectories?trace=" + a},
		{"both: the first local success is the one kept", func(tr *firstTraceTracker, out *bytes.Buffer) {
			tr.note(both, DestinationLocal, a, true, nil, yes, out)
			tr.note(both, DestinationLocal, b, true, nil, yes, out)
			tr.note(both, DestinationOnline, b, false, nil, yes, out)
		}, "http://127.0.0.1:8081/apps/traces?trace=" + a},
		{"a gate that says no ends it for good", func(tr *firstTraceTracker, out *bytes.Buffer) {
			tr.note(firstTraceBases{local: "http://l"}, DestinationLocal, a, true, nil, func() bool { return false }, out)
			tr.note(firstTraceBases{local: "http://l"}, DestinationLocal, b, true, nil, yes, out)
		}, ""},
	} {
		tr := &firstTraceTracker{}
		var out bytes.Buffer
		c.steps(tr, &out)
		got := strings.TrimSpace(out.String())
		if c.want == "" && got != "" || c.want != "" && got != firstTracePrefix+c.want {
			t.Errorf("%s: %q", c.name, got)
		}
		if tr.printed() != c.want {
			t.Errorf("%s: printed %q", c.name, tr.printed())
		}
	}
}

// failingExporter refuses every export with err.
type failingExporter struct{ err error }

func (f failingExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error { return f.err }
func (failingExporter) Shutdown(context.Context) error                               { return nil }

// syncBuffer is a bytes.Buffer safe for the exporter goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, l := range strings.Split(s.b.String(), "\n") {
		if strings.HasPrefix(l, "superbased: ") {
			out = append(out, l)
		}
	}
	return out
}

func TestFirstTraceLineThroughExports(t *testing.T) {
	refused := fmt.Errorf("failed to send to %s/v1/traces: 403 Forbidden (%w)", fakeHeldGW, errors.New("body: "+planRequiredBody))
	if r := planRefusalInExportError(refused); r == nil {
		t.Fatal("the test's export error is not a plan refusal")
	}
	cases := []struct {
		name     string
		terminal bool
		env      map[string]string
		exp      func() sdktrace.SpanExporter
		roots    int
		want     string // "link", "refused" or "" (no line)
	}{
		{"a terminal: one line for three traces", true, nil, func() sdktrace.SpanExporter { return tracetest.NewInMemoryExporter() }, 3, "link"},
		{"not a terminal", false, nil, func() sdktrace.SpanExporter { return tracetest.NewInMemoryExporter() }, 1, ""},
		{"under CI", true, map[string]string{"CI": "true"}, func() sdktrace.SpanExporter { return tracetest.NewInMemoryExporter() }, 1, ""},
		{"opted out", true, map[string]string{EnvFirstTraceLink: "0"}, func() sdktrace.SpanExporter { return tracetest.NewInMemoryExporter() }, 1, ""},
		{"a failed export", true, nil, func() sdktrace.SpanExporter { return failingExporter{errors.New("connection refused")} }, 2, ""},
		{"a plan refusal", true, nil, func() sdktrace.SpanExporter { return failingExporter{refused} }, 2, "refused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			skipOnWindows(t)
			lc := setup(t)
			t.Setenv("CI", "")
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			prevTerm, prevOut := stderrIsTerminal, firstTraceOut
			out := &syncBuffer{}
			stderrIsTerminal, firstTraceOut = func() bool { return c.terminal }, out
			t.Cleanup(func() { stderrIsTerminal, firstTraceOut = prevTerm, prevOut })
			t.Setenv(EnvCredentialFile, heldFile(t, heldBody("gateway_url="+fakeHeldGW, "destination=online", "dashboard_url=https://u-k7x2.superbased.app"), 0o600))
			if _, err := Init(context.Background(), Options{Exporter: c.exp()}); err != nil {
				t.Fatal(err)
			}
			var first string
			for i := 0; i < c.roots; i++ {
				ctx, sp := StartSpan(context.Background(), "root", SpanOptions{})
				if i == 0 {
					first = sp.SpanContext().TraceID().String()
				}
				_, child := StartSpan(ctx, "child", SpanOptions{})
				child.End()
				sp.End()
				Flush(context.Background())
			}
			lines := out.lines()
			switch c.want {
			case "":
				if len(lines) != 0 {
					t.Fatalf("lines %q", lines)
				}
			case "link":
				link := "https://u-k7x2.superbased.app/trajectories?trace=" + first
				if len(lines) != 1 || lines[0] != firstTracePrefix+link || GetDiagnostics().FirstTraceLink != link {
					t.Fatalf("lines %q, diagnostics %q", lines, GetDiagnostics().FirstTraceLink)
				}
			case "refused":
				if len(lines) != 1 || !strings.HasPrefix(lines[0], firstTraceRefusedPrefix) || GetDiagnostics().FirstTraceLink != "" {
					t.Fatalf("lines %q", lines)
				}
			}
			lc.mu.Lock()
			logged := append([]string{}, lc.lines...)
			lc.mu.Unlock()
			for _, l := range append(lines, logged...) {
				if strings.Contains(l, fakeHeldSecret) {
					t.Fatal("a line carries the key")
				}
			}
			for _, l := range logged {
				if strings.Contains(l, "first trace") {
					t.Fatalf("the line went to the logger: %q", l)
				}
			}
		})
	}
}

func TestFirstTraceLineIgnoresChildOnlyBatches(t *testing.T) {
	if firstRootTraceID(nil) != "" {
		t.Fatal("empty batch")
	}
	setup(t)
	mem := tracetest.NewInMemoryExporter()
	memInit(t, Options{Exporter: mem})
	ctx, root := StartSpan(context.Background(), "root", SpanOptions{})
	_, child := StartSpan(ctx, "child", SpanOptions{})
	child.End()
	Flush(context.Background())
	spans := mem.GetSpans().Snapshots()
	if len(spans) != 1 || firstRootTraceID(spans) != "" {
		t.Fatalf("a child-only batch has a root: %d", len(spans))
	}
	root.End()
	Flush(context.Background())
	if id := firstRootTraceID(mem.GetSpans().Snapshots()); id != root.SpanContext().TraceID().String() {
		t.Fatalf("root %q", id)
	}
}
