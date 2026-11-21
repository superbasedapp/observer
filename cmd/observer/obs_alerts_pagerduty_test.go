package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/alertspec"
	"github.com/marmutapp/superbased-observer/internal/config"
)

const testPDKeyCLI = "abcdefABCDEF0123456789abcdefABCD"

// pdStandIn is a local Events API v2 stand-in (never real PagerDuty).
func pdStandIn(t *testing.T, status int) (*[]map[string]any, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var events []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var ev map[string]any
		_ = json.Unmarshal(b, &ev)
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	old := pagerDutyEndpoint
	pagerDutyEndpoint = srv.URL + "/v2/enqueue"
	t.Cleanup(func() { pagerDutyEndpoint = old })
	return &events, &mu
}

func TestMachinePagerDutyDelivery(t *testing.T) {
	events, mu := pdStandIn(t, http.StatusAccepted)
	ctx := context.Background()
	f := obsFiredAlert{
		RuleName: "api errors", Metric: "error_rate", Comparator: "gt", Threshold: 0.1, Value: 0.5,
		WindowMinutes: 60, FiredAt: time.Now(), Dimensions: alertspec.Dimensions{Service: "api"},
	}
	deliverPagerDutyFired(ctx, testPDKeyCLI, []obsFiredAlert{f}, nil, slog.Default())
	deliverPagerDutyResolved(ctx, testPDKeyCLI, []obsClearedAlert{{RuleName: "api errors", DedupKey: machineDedupKey("api errors", f.Dimensions)}, {RuleName: "no key"}}, slog.Default())
	deliverPagerDutyFired(ctx, "", []obsFiredAlert{f}, nil, slog.Default()) // no key: nothing sent
	if err := testPagerDuty(ctx, testPDKeyCLI, time.Now()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*events) != 4 {
		t.Fatalf("events %v", *events)
	}
	ev := *events
	if ev[0]["event_action"] != "trigger" || ev[1]["event_action"] != "resolve" || ev[0]["dedup_key"] != ev[1]["dedup_key"] {
		t.Fatalf("trigger/resolve %v", ev[:2])
	}
	if ev[2]["event_action"] != "trigger" || ev[3]["event_action"] != "resolve" || ev[2]["dedup_key"] != ev[3]["dedup_key"] {
		t.Fatalf("test pair %v", ev[2:])
	}
}

func TestMachinePagerDutyErrorsCarryNoKey(t *testing.T) {
	pdStandIn(t, http.StatusBadRequest)
	err := postPagerDuty(context.Background(), testPDKeyCLI, "sbo-x", alertspec.SlackAlert{Event: "fired"})
	if err == nil || strings.Contains(err.Error(), testPDKeyCLI) {
		t.Fatalf("status error %v", err)
	}
	pagerDutyEndpoint = "http://127.0.0.1:1/v2/enqueue"
	err = postPagerDuty(context.Background(), testPDKeyCLI, "sbo-x", alertspec.SlackAlert{Event: "fired"})
	if err == nil || strings.Contains(err.Error(), testPDKeyCLI) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("transport error %v", err)
	}
}

func writeAlertsConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[observability]\nenabled = true\n[observability.alerts]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestObsAlertsPagerDutyAndRulesCLI(t *testing.T) {
	path := writeAlertsConfig(t)
	run := func(cmdArgs []string, stdin string) (string, error) {
		cmd := newObsAlertsCmd()
		var out strings.Builder
		cmd.SetOut(&out)
		cmd.SetErr(io.Discard)
		cmd.SetIn(strings.NewReader(stdin))
		cmd.SetArgs(append(cmdArgs, "--config", path))
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		err := cmd.Execute()
		return out.String(), err
	}
	if _, err := run([]string{"pagerduty", "set"}, "nope-secretish\n"); err == nil || strings.Contains(err.Error(), "secretish") {
		t.Fatalf("bad key: %v", err)
	}
	if _, err := run([]string{"pagerduty", "set"}, testPDKeyCLI+"\n"); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil || cfg.Observability.Alerts.PagerDutyRoutingKey != testPDKeyCLI {
		t.Fatalf("stored key: %v", err)
	}
	rules := `{"rules":[{"name":"errs","metric":"error_rate","threshold":0.1,"window_minutes":60,"dimensions":{"service":"api"}}]}`
	if _, err := run([]string{"rules", "set"}, rules); err != nil {
		t.Fatal(err)
	}
	out, err := run([]string{"rules", "list"}, "")
	if err != nil || !strings.Contains(out, `"service": "api"`) || !strings.Contains(out, `"errs"`) {
		t.Fatalf("list %q %v", out, err)
	}
	for _, bad := range []string{
		`{"rules":[{"name":"x","metric":"p99"}]}`,
		`{"rules":[{"name":"x","metric":"cost_usd"},{"name":"x","metric":"cost_usd"}]}`,
		`{"rules":[{"name":"","metric":"cost_usd"}]}`,
		`{"rules":[{"name":"x","metric":"cost_usd","extra":1}]}`,
		`not json`,
	} {
		if _, err := run([]string{"rules", "set"}, bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := run([]string{"pagerduty", "clear"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := run([]string{"pagerduty", "test"}, ""); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("test unconfigured: %v", err)
	}
	cfg, _ = config.Load(config.LoadOptions{GlobalPath: path})
	if cfg.Observability.Alerts.PagerDutyRoutingKey != "" || len(cfg.Observability.Alerts.Rules) != 1 {
		t.Fatalf("after clear: %+v", cfg.Observability.Alerts)
	}
}

func TestReadViewJSON(t *testing.T) {
	if _, err := readViewJSON(strings.NewReader(`{"name":"v","filters":{"service":"api"}}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"name":"v","scope":"org"}`, `{"filters":{}}`, `[`} {
		if _, err := readViewJSON(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
