package superbased

// sdk/contract/sdk-behaviour-cases.json: the behaviours every superbased SDK
// shares (review R-B19). The Python SDK runs the same file in
// sdk/python/tests/test_behaviour_cases.py, TypeScript in
// sdk/typescript/test/behaviour.test.mjs; TestEverySectionHasARunner fails
// when a section has no Go runner.

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

var runners = map[string]func(*testing.T){
	"compile_values":              runCompileValues,
	"score_target":                runScoreTarget,
	"score_ok":                    runScoreOK,
	"destination":                 runDestination,
	"control_targets":             runControlTargets,
	"admit_identity":              runAdmitIdentity,
	"admit_credential":            runAdmitCredential,
	"admit_redirect":              runAdmitRedirect,
	"local_export_credential":     runLocalExportCredential,
	"experiment_pass_rate":        runExperimentPassRate,
	"literal_item_ids":            runLiteralItemIDs,
	"sampling_env":                runSamplingEnv,
	"pending_per_destination":     runPendingPerDestination,
	"admit_degraded":              runAdmitDegraded,
	"control_before_discovery":    runControlBeforeDiscovery,
	"experiment_snapshot_version": runExperimentSnapshotVersion,
	"experiment_create_id":        runExperimentCreateID,
	"llm_span_prompt":             runLLMSpanPrompt,
	"local_receiver_discovery":    runLocalReceiverDiscovery,
	"vendor_self_tracing":         runVendorSelfTracing,
	"set_usage_net_input":         runSetUsageNetInput,
	"admit_org_off":               runAdmitOrgOff,
	"experiment_strict_gate":      runExperimentStrictGate,
	"get_dataset_missing":         runGetDatasetMissing,
}

func TestEverySectionHasARunner(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(contractDir(), "sdk-behaviour-cases.json"))
	if err != nil {
		t.Skipf("sdk/contract is not present: %v", err)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	var missing, extra []string
	for k := range all {
		if !strings.HasPrefix(k, "_") && runners[k] == nil {
			missing = append(missing, k)
		}
	}
	for k := range runners {
		if _, ok := all[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("sections without a Go runner: %v; runners without a section: %v", missing, extra)
	}
}

func TestBehaviourCases(t *testing.T) {
	names := make([]string, 0, len(runners))
	for k := range runners {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		t.Run(n, runners[n])
	}
}

// eachCase runs fn for every case of a section, isolated.
func eachCase[T any](t *testing.T, section string, fn func(t *testing.T, c T)) {
	for i, c := range cases[T](t, section) {
		t.Run(strings.ReplaceAll(section, "_", "-")+"/"+itoa(i), func(t *testing.T) { fn(t, c) })
	}
}

func itoa(i int) string { return string(rune('0'+i/10)) + string(rune('0'+i%10)) }

func memInit(t *testing.T, o Options) *tracetest.InMemoryExporter {
	t.Helper()
	mem := tracetest.NewInMemoryExporter()
	if o.Exporter == nil {
		o.Exporter = mem
	}
	if o.Destination == "" {
		o.Destination = DestinationLocal
	}
	if _, err := Init(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	return mem
}

func lastSpanAttrs(t *testing.T, mem *tracetest.InMemoryExporter) map[string]any {
	t.Helper()
	Flush(context.Background())
	spans := mem.GetSpans()
	if len(spans) == 0 {
		t.Fatal("no span exported")
	}
	out := map[string]any{}
	for _, kv := range spans[len(spans)-1].Attributes {
		out[string(kv.Key)] = kv.Value.AsInterface()
	}
	return out
}

// --- compile_values -----------------------------------------------------------

func runCompileValues(t *testing.T) {
	sec := loadSection(t, "compile_values")
	var prompt string
	_ = json.Unmarshal(sec["prompt"], &prompt)
	eachCase(t, "compile_values", func(t *testing.T, c struct {
		Value json.RawMessage `json:"value"`
		Want  string          `json:"want"`
	}) {
		got, err := compileText(prompt, map[string]any{"v": c.Value})
		if err != nil || got != c.Want {
			t.Fatalf("compile %s = %q, %v; want %q", c.Value, got, err, c.Want)
		}
	})
	for _, v := range []float64{math.NaN(), math.Inf(-1), math.Inf(1)} {
		if got, _ := compileText("{{v}}", map[string]any{"v": v}); got != "null" {
			t.Fatalf("non-finite %v rendered %q, want null", v, got)
		}
	}
}

// --- score_target / score_ok -------------------------------------------------------

func runScoreTarget(t *testing.T) {
	eachCase(t, "score_target", func(t *testing.T, c struct {
		InSpan bool              `json:"in_span"`
		Args   map[string]string `json:"args"`
		Want   map[string]string `json:"want"`
	}) {
		setup(t)
		st := newStub(t)
		st.route("POST", "/api/obs/scores", func(stubReq) (int, any, map[string]string) {
			return 200, map[string]any{"accepted": []any{map[string]any{"index": 0, "id": "sc_1"}}, "rejected": []any{}}, nil
		})
		memInit(t, Options{NodeURL: st.URL})
		ctx := context.Background()
		var sp trace.Span
		if c.InSpan {
			ctx, sp = StartSpan(ctx, "req", SpanOptions{})
			defer sp.End()
		}
		o := ScoreOptions{}
		if c.Args["span_id"] == "current" {
			o.SpanID = CurrentSpanID(ctx)
		}
		res := Score(ctx, "accuracy", 1.0, o)
		if e := c.Want["error"]; e != "" {
			if res.OK || !strings.Contains(strings.Join(res.Errors, ";"), e) {
				t.Fatalf("want error %s, got %+v", e, res)
			}
			return
		}
		reqs := st.seen("/api/obs/scores")
		body := reqs[len(reqs)-1].Body
		if body["trace_id"] != CurrentTraceID(ctx) {
			t.Fatalf("trace_id %v, want %s", body["trace_id"], CurrentTraceID(ctx))
		}
		wantSpan := ""
		if c.Want["span_id"] == "current" {
			wantSpan = CurrentSpanID(ctx)
		}
		gotSpan, _ := body["span_id"].(string)
		if gotSpan != wantSpan {
			t.Fatalf("span_id %q, want %q", gotSpan, wantSpan)
		}
	})
}

func runScoreOK(t *testing.T) {
	eachCase(t, "score_ok", func(t *testing.T, c struct {
		Destinations map[string]bool `json:"destinations"`
		Want         bool            `json:"want"`
	}) {
		r := &ScoreResult{ClientID: "sdk_x", Destinations: map[string]DestinationResult{}}
		for name, ok := range c.Destinations {
			st := 500
			if ok {
				st = 200
			}
			r.Destinations[name] = DestinationResult{OK: ok, Status: st}
		}
		if resultOK(r) != c.Want {
			t.Fatalf("%v: ok %v, want %v", c.Destinations, !c.Want, c.Want)
		}
	})
}

// --- destination ----------------------------------------------------------------------

func runDestination(t *testing.T) {
	eachCase(t, "destination", func(t *testing.T, c struct {
		Args    map[string]string `json:"args"`
		Env     map[string]string `json:"env"`
		Machine map[string]string `json:"machine"`
		Want    map[string]string `json:"want"`
	}) {
		setup(t)
		st := newStub(t)
		env := map[string]string{"SUPERBASED_DISCOVER": "1"}
		for k, v := range c.Env {
			env[k] = v
		}
		var mu sync.Mutex
		var asked []string
		real := discover
		discover = func(nodeURL string) (map[string]any, string) {
			mu.Lock()
			asked = append(asked, nodeURL)
			mu.Unlock()
			if c.Machine != nil && nodeURL == st.URL {
				return real(nodeURL)
			}
			return nil, "no machine (test)"
		}
		t.Cleanup(func() { discover = real })
		if c.Machine != nil {
			st.routeBody("GET", "/api/sdk/destination", map[string]any{"api_version": 1, "destination": c.Machine["destination"], "source": "config",
				"configured": "", "signed_in": false, "local": map[string]any{"enabled": true}, "online": map[string]any{}, "warnings": []any{}})
			env["SUPERBASED_NODE_URL"] = st.URL
		} else if _, ok := env["SUPERBASED_MACHINE_URL"]; !ok {
			env["SUPERBASED_NODE_URL"] = "http://127.0.0.1:1"
		}
		e := mapEnv(env)
		s, err := resolveSettings(e, Options{OrgURL: c.Args["org_url"], APIKey: c.Args["api_key"], Destination: c.Args["destination"]})
		if err != nil {
			t.Fatal(err)
		}
		p := resolvePlan(s, e, explicitInputs{destination: c.Args["destination"], apiKey: c.Args["api_key"]})
		if p.destination != c.Want["destination"] || p.source != c.Want["source"] {
			t.Fatalf("(%s, %s), want (%s, %s)", p.destination, p.source, c.Want["destination"], c.Want["source"])
		}
		if n, ok := c.Want["node_url"]; ok {
			if p.nodeURL != n {
				t.Fatalf("node url %s, want %s", p.nodeURL, n)
			}
			for _, a := range asked {
				if a == env["SUPERBASED_MACHINE_URL"] {
					t.Fatal("SUPERBASED_MACHINE_URL was asked")
				}
			}
		}
	})
}

func sideNames(ss []side) []string {
	out := []string{}
	for _, s := range ss {
		out = append(out, s.name)
	}
	return out
}

func runControlTargets(t *testing.T) {
	eachCase(t, "control_targets", func(t *testing.T, c struct {
		Destination string   `json:"destination"`
		OnlineReady bool     `json:"online_ready"`
		Want        []string `json:"want"`
	}) {
		setup(t)
		gw, key := "", ""
		if c.OnlineReady {
			gw, key = "https://gw.example.com", "ik_1.s"
		}
		e := mapEnv(map[string]string{"SUPERBASED_DISCOVER": "0", "SUPERBASED_DESTINATION": c.Destination, "SUPERBASED_ORG_URL": gw, "SUPERBASED_API_KEY": key})
		s, _ := resolveSettings(e, Options{})
		got := sideNames(sides(resolvePlan(s, e, explicitInputs{})))
		if strings.Join(got, ",") != strings.Join(c.Want, ",") {
			t.Fatalf("sides %v, want %v", got, c.Want)
		}
	})
}

// --- admit --------------------------------------------------------------------------

func runAdmitIdentity(t *testing.T) {
	eachCase(t, "admit_identity", func(t *testing.T, c struct {
		Args  map[string]string `json:"args"`
		Scope map[string]string `json:"scope"`
		Init  map[string]string `json:"init"`
		Want  map[string]string `json:"want"`
	}) {
		setup(t)
		cap := &captured{}
		cap.install()
		if len(c.Init) > 0 {
			memInit(t, Options{Tenant: c.Init["tenant"], User: c.Init["user"], SessionID: c.Init["session_id"]})
		}
		ctx := context.Background()
		if len(c.Scope) > 0 {
			ctx = PropagateAttributes(ctx, Attributes{Tenant: c.Scope["tenant"], User: c.Scope["user"], SessionID: c.Scope["session_id"]})
		}
		Admit(ctx, "hi", AdmitOptions{Endpoint: "http://127.0.0.1:9/check", Tenant: c.Args["tenant"], User: c.Args["user"], Session: c.Args["session"]})
		body := cap.last().Body
		for _, k := range []string{"tenant", "user", "session"} {
			if body[k] != c.Want[k] {
				t.Fatalf("%s = %v, want %q (body %v)", k, body[k], c.Want[k], body)
			}
		}
	})
}

var admitHosts = map[string]string{"loopback": "http://127.0.0.1:9", "remote": "https://admit.example.com"}

func runAdmitCredential(t *testing.T) {
	eachCase(t, "admit_credential", func(t *testing.T, c struct {
		Via     string `json:"via"`
		Host    string `json:"host"`
		Key     string `json:"key"`
		WantKey bool   `json:"want_key"`
	}) {
		setup(t)
		cap := &captured{}
		cap.install()
		host := admitHosts[c.Host]
		o := AdmitOptions{}
		switch c.Key {
		case "argument":
			o.APIKey = "ik_arg"
		case "init":
			memInit(t, Options{APIKey: "ik_init"})
		default:
			t.Setenv("SUPERBASED_API_KEY", "ik_env")
		}
		switch c.Via {
		case "endpoint":
			o.Endpoint = host + "/check"
		case "env_endpoint":
			t.Setenv("SUPERBASED_ADMISSION_ENDPOINT", host+"/check")
		case "org_url":
			o.OrgURL = host
		case "env_org_url":
			t.Setenv("SUPERBASED_ORG_URL", host)
		}
		Admit(context.Background(), "hi", o)
		call := cap.last()
		if (call.Headers.Get("Authorization") != "") != c.WantKey {
			t.Fatalf("Authorization sent = %v, want %v (%s)", !c.WantKey, c.WantKey, call.URL)
		}
		if call.Loopback != (c.Host == "loopback") {
			t.Fatalf("loopback transport = %v for %s", call.Loopback, call.URL)
		}
	})
}

func runAdmitRedirect(t *testing.T) {
	eachCase(t, "admit_redirect", func(t *testing.T, c struct {
		Status int `json:"status"`
		Want   struct {
			Requests   int    `json:"requests"`
			Degraded   string `json:"degraded"`
			HTTPStatus int    `json:"http_status"`
		} `json:"want"`
	}) {
		setup(t)
		st, st2 := newStub(t), newStub(t)
		st.reply(map[string]any{}, c.Status, map[string]string{"Location": st2.URL + "/stolen"})
		v := Admit(context.Background(), "hi", AdmitOptions{Endpoint: st.URL + "/check", APIKey: "ik_1.s"})
		if len(st.seen("")) != c.Want.Requests || len(st2.seen("")) != 0 {
			t.Fatalf("requests %d / %d, want %d / 0", len(st.seen("")), len(st2.seen("")), c.Want.Requests)
		}
		if v.Degraded != c.Want.Degraded || v.HTTPStatus != c.Want.HTTPStatus {
			t.Fatalf("(%s, %d), want (%s, %d)", v.Degraded, v.HTTPStatus, c.Want.Degraded, c.Want.HTTPStatus)
		}
	})
}

func TestAdmitOnLoopbackBypassesAnEnvironmentProxy(t *testing.T) {
	setup(t)
	st := newStub(t)
	dead := deadURL(t)
	t.Setenv("NO_PROXY", "")
	t.Setenv("HTTP_PROXY", dead)
	t.Setenv("http_proxy", dead)
	st.reply(map[string]any{"allowed": true, "decision": "allow"}, 200, nil)
	v := Admit(context.Background(), "hi", AdmitOptions{Endpoint: st.URL + "/check"})
	if v.Degraded != "" || len(st.seen("")) != 1 {
		t.Fatalf("degraded %q, requests %d", v.Degraded, len(st.seen("")))
	}
}

func runLocalExportCredential(t *testing.T) {
	eachCase(t, "local_export_credential", func(t *testing.T, c struct {
		EndpointFrom string `json:"endpoint_from"`
		Endpoint     string `json:"endpoint"`
		WantKey      bool   `json:"want_key"`
	}) {
		setup(t)
		env := map[string]string{"SUPERBASED_DISCOVER": "0", "SUPERBASED_DESTINATION": "local", "SUPERBASED_API_KEY": "ik_1.s"}
		explicit := ""
		switch c.EndpointFrom {
		case "argument":
			explicit = c.Endpoint
		case "superbased_env":
			env["SUPERBASED_OTLP_ENDPOINT"] = c.Endpoint
		case "otel_env":
			env["OTEL_EXPORTER_OTLP_ENDPOINT"] = c.Endpoint
		}
		e := mapEnv(env)
		s, _ := resolveSettings(e, Options{Endpoint: explicit})
		p := resolvePlan(s, e, explicitInputs{endpoint: explicit})
		if len(p.exporters) != 1 {
			t.Fatalf("exporters %v", p.exporters)
		}
		if hasAuthorization(p.exporters[0].headers) != c.WantKey {
			t.Fatalf("key on the local exporter = %v, want %v", !c.WantKey, c.WantKey)
		}
	})
}

// --- experiments --------------------------------------------------------------------

type caseItem struct {
	Error  string `json:"error"`
	Scores []struct {
		Name  string `json:"name"`
		Value any    `json:"value"`
	} `json:"scores"`
	EvaluatorErrors int `json:"evaluator_errors"`
}

func resultFromCase(items []caseItem) *ExperimentResult {
	r := &ExperimentResult{Name: "r", Runs: map[string]string{}, Server: map[string]map[string]any{}}
	for n, it := range items {
		ir := ItemResult{ItemID: "it_" + itoa(n), Input: "x", Error: it.Error}
		for _, s := range it.Scores {
			ir.Scores = append(ir.Scores, Evaluation{Name: s.Name, Value: s.Value})
		}
		for i := 0; i < it.EvaluatorErrors; i++ {
			ir.EvaluatorErrors = append(ir.EvaluatorErrors, "boom")
		}
		r.Items = append(r.Items, ir)
	}
	return r
}

func runExperimentPassRate(t *testing.T) {
	eachCase(t, "experiment_pass_rate", func(t *testing.T, c struct {
		Sides     []map[string]any `json:"sides"`
		Items     []caseItem       `json:"items"`
		FailUnder *float64         `json:"fail_under"`
		Want      struct {
			Scored     int      `json:"scored"`
			PassRate   *float64 `json:"pass_rate"`
			GateFailed bool     `json:"gate_failed"`
		} `json:"want"`
	}) {
		r := resultFromCase(c.Items)
		for n, body := range c.Sides {
			r.Server[serverOrder[n]] = body
		}
		if r.Scored() != c.Want.Scored {
			t.Fatalf("scored %d, want %d", r.Scored(), c.Want.Scored)
		}
		pr := r.PassRate()
		if c.Want.PassRate == nil {
			if !math.IsNaN(pr) {
				t.Fatalf("pass rate %v, want NaN", pr)
			}
		} else if math.Abs(pr-*c.Want.PassRate) > 1e-9 {
			t.Fatalf("pass rate %v, want %v", pr, *c.Want.PassRate)
		}
		if gateFails(r, c.FailUnder, false) != c.Want.GateFailed {
			t.Fatalf("gate failed = %v, want %v", !c.Want.GateFailed, c.Want.GateFailed)
		}
	})
}

func runExperimentStrictGate(t *testing.T) {
	eachCase(t, "experiment_strict_gate", func(t *testing.T, c struct {
		Items        []caseItem `json:"items"`
		SkippedSides []string   `json:"skipped_sides"`
		FailedPosts  int        `json:"failed_posts"`
		Strict       *bool      `json:"strict"`
		FailUnder    *float64   `json:"fail_under"`
		Want         struct {
			GateFailed bool `json:"gate_failed"`
			Reasons    int  `json:"reasons"`
		} `json:"want"`
	}) {
		r := resultFromCase(c.Items)
		r.SkippedSides, r.FailedPosts = c.SkippedSides, c.FailedPosts
		strict := c.Strict == nil || *c.Strict
		failed, reasons := ExperimentGate(r, c.FailUnder, strict)
		if len(reasons) != c.Want.Reasons || failed != c.Want.GateFailed {
			t.Fatalf("(failed %v, %d reasons %v), want (%v, %d)", failed, len(reasons), reasons, c.Want.GateFailed, c.Want.Reasons)
		}
	})
}

func runLiteralItemIDs(t *testing.T) {
	eachCase(t, "literal_item_ids", func(t *testing.T, c struct {
		Items []map[string]any `json:"items"`
		Want  []string         `json:"want"`
	}) {
		var got []string
		for _, it := range literalItems(c.Items) {
			got = append(got, it.ID)
		}
		if strings.Join(got, ",") != strings.Join(c.Want, ",") {
			t.Fatalf("ids %v, want %v", got, c.Want)
		}
	})
}

func goldenStub(t *testing.T, create func(stubReq) (int, any, map[string]string)) *stub {
	st := newStub(t)
	st.routeBody("GET", "/api/obs/eval/datasets", map[string]any{"datasets": []any{map[string]any{"id": "7", "name": "golden"}}})
	st.route("POST", "/api/obs/eval/experiments", create)
	st.routeBody("GET", "/api/obs/eval/datasets/7/items", map[string]any{"items": []any{}, "next_cursor": ""})
	return st
}

func identityTask(_ context.Context, it Item) (any, error) { return it.Input, nil }

func runExperimentSnapshotVersion(t *testing.T) {
	eachCase(t, "experiment_snapshot_version", func(t *testing.T, c struct {
		SnapshotVersion *int `json:"snapshot_version"`
		Want            int  `json:"want"`
	}) {
		setup(t)
		var mu sync.Mutex
		var created []map[string]any
		st := goldenStub(t, func(r stubReq) (int, any, map[string]string) {
			mu.Lock()
			created = append(created, r.Body)
			mu.Unlock()
			return 201, map[string]any{"id": "1", "snapshot_version": r.Body["snapshot_version"]}, nil
		})
		memInit(t, Options{NodeURL: st.URL})
		if _, err := RunExperiment(context.Background(), ExperimentOptions{Dataset: "golden", Task: identityTask, SnapshotVersion: c.SnapshotVersion}); err != nil {
			t.Fatal(err)
		}
		if got, _ := created[0]["snapshot_version"].(float64); int(got) != c.Want {
			t.Fatalf("snapshot_version %v, want %d", created[0]["snapshot_version"], c.Want)
		}
	})
}

var createIDRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

func runExperimentCreateID(t *testing.T) {
	eachCase(t, "experiment_create_id", func(t *testing.T, c struct {
		FirstStatus int `json:"first_status"`
		WantCreates int `json:"want_creates"`
	}) {
		setup(t)
		var mu sync.Mutex
		var created []map[string]any
		st := goldenStub(t, func(r stubReq) (int, any, map[string]string) {
			mu.Lock()
			defer mu.Unlock()
			created = append(created, r.Body)
			if len(created) == 1 && c.FirstStatus != 201 {
				return c.FirstStatus, map[string]any{"error": "x", "message": "x"}, nil
			}
			return 201, map[string]any{"id": "1", "snapshot_version": 1}, nil
		})
		memInit(t, Options{NodeURL: st.URL})
		_, err := RunExperiment(context.Background(), ExperimentOptions{Dataset: "golden", Task: identityTask})
		retried := c.FirstStatus == 201 || c.FirstStatus == 429 || c.FirstStatus >= 500
		var ee *ExperimentError
		if retried && err != nil {
			t.Fatalf("unexpected error %v", err)
		}
		if !retried && !errors.As(err, &ee) {
			t.Fatalf("want an *ExperimentError, got %v", err)
		}
		if len(created) != c.WantCreates {
			t.Fatalf("creates %d, want %d", len(created), c.WantCreates)
		}
		ids := map[any]bool{}
		for _, b := range created {
			ids[b["id"]] = true
		}
		if len(ids) != 1 {
			t.Fatalf("ids %v, want one", ids)
		}
		cid, _ := created[0]["id"].(string)
		if !createIDRe.MatchString(cid) {
			t.Fatalf("id %q", cid)
		}
		if c.FirstStatus == 201 {
			if _, err := RunExperiment(context.Background(), ExperimentOptions{Dataset: "golden", Task: identityTask}); err != nil {
				t.Fatal(err)
			}
			if created[len(created)-1]["id"] == cid {
				t.Fatal("a second call reused the create id")
			}
		}
	})
}

func runGetDatasetMissing(t *testing.T) {
	eachCase(t, "get_dataset_missing", func(t *testing.T, c struct {
		Datasets any    `json:"datasets"`
		Name     string `json:"name"`
		Want     struct {
			Found bool `json:"found"`
		} `json:"want"`
	}) {
		setup(t)
		if c.Datasets == "no_destination" {
			memInit(t, Options{Destination: DestinationOnline})
		} else {
			st := newStub(t)
			var listed []any
			for n, name := range c.Datasets.([]any) {
				listed = append(listed, map[string]any{"id": itoa(n + 7), "name": name, "item_count": 0, "latest_snapshot": 1})
			}
			st.routeBody("GET", "/api/obs/eval/datasets", map[string]any{"api_version": "v1", "datasets": listed})
			st.reply(map[string]any{"items": []any{}, "next_cursor": ""}, 200, nil)
			memInit(t, Options{NodeURL: st.URL})
		}
		d, err := GetDataset(context.Background(), c.Name)
		if c.Want.Found {
			if err != nil || d.Name != c.Name {
				t.Fatalf("dataset %+v, %v", d, err)
			}
			return
		}
		var ee *ExperimentError
		if !errors.As(err, &ee) {
			t.Fatalf("want an *ExperimentError, got %v (%+v)", err, d)
		}
	})
}

// --- sampling, pending, degraded admit -------------------------------------------

func runSamplingEnv(t *testing.T) {
	eachCase(t, "sampling_env", func(t *testing.T, c struct {
		Env      map[string]string `json:"env"`
		Explicit *float64          `json:"explicit"`
		Want     struct {
			Rate        float64  `json:"rate"`
			ParentBased bool     `json:"parent_based"`
			Ignored     []string `json:"ignored"`
			Error       bool     `json:"error"`
		} `json:"want"`
	}) {
		e := mapEnv(c.Env)
		rate, parent, err := resolveSampling(c.Explicit, e)
		if c.Want.Error {
			if err == nil {
				t.Fatal("want an error")
			}
			return
		}
		if err != nil || rate != c.Want.Rate || parent != c.Want.ParentBased {
			t.Fatalf("(%v, %v, %v), want (%v, %v)", rate, parent, err, c.Want.Rate, c.Want.ParentBased)
		}
		problem := samplingEnvProblem(e)
		named := []string{}
		for _, v := range []string{"SUPERBASED_SAMPLE_RATE", "OTEL_TRACES_SAMPLER_ARG"} {
			if strings.Contains(problem, v+"=") {
				named = append(named, v)
			}
		}
		if strings.Join(named, ",") != strings.Join(c.Want.Ignored, ",") {
			t.Fatalf("ignored %v, want %v (%q)", named, c.Want.Ignored, problem)
		}
	})
}

func runPendingPerDestination(t *testing.T) {
	eachCase(t, "pending_per_destination", func(t *testing.T, c struct {
		Destination string   `json:"destination"`
		Held        []string `json:"held"`
		WantPending int64    `json:"want_pending"`
	}) {
		setup(t)
		stubs := map[string]*stub{"local": newStub(t), "online": newStub(t)}
		for _, h := range c.Held {
			stubs[h].setDelay(time.Second)
		}
		t.Setenv("SUPERBASED_OTLP_ENDPOINT", stubs["local"].URL+"/v1/traces")
		o := Options{Destination: c.Destination, ShutdownTimeout: 5 * time.Second, ExportTimeout: 5 * time.Second}
		if c.Destination == DestinationBoth {
			o.OrgURL, o.APIKey = stubs["online"].URL, "ik_1.s"
		}
		if _, err := Init(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		_, sp := StartSpan(context.Background(), "x", SpanOptions{})
		sp.End()
		done := make(chan struct{})
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			Flush(ctx)
			close(done)
		}()
		legs := int64(1)
		if c.Destination == DestinationBoth {
			legs = 2
		}
		answered := legs - int64(len(c.Held))
		deadline := time.Now().Add(3 * time.Second)
		for GetDiagnostics().ExportedSpans < answered && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if len(c.Held) > 0 {
			if d := GetDiagnostics(); d.PendingSpans != c.WantPending {
				t.Fatalf("pending %d, want %d (%+v)", d.PendingSpans, c.WantPending, d)
			}
		}
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Fatal("flush did not return")
		}
		if d := GetDiagnostics(); d.PendingSpans != 0 {
			t.Fatalf("pending after flush %d (%+v)", d.PendingSpans, d)
		}
		if len(c.Held) == 0 && c.WantPending != 0 {
			t.Fatalf("want_pending %d with nothing held", c.WantPending)
		}
	})
}

func runAdmitDegraded(t *testing.T) {
	eachCase(t, "admit_degraded", func(t *testing.T, c struct {
		Status     any    `json:"status"`
		Path       string `json:"path"`
		FailClosed bool   `json:"fail_closed"`
		Want       struct {
			Allowed  bool   `json:"allowed"`
			Degraded string `json:"degraded"`
			Warnings int    `json:"warnings"`
			Counted  int64  `json:"counted"`
			Fix      string `json:"fix"`
		} `json:"want"`
	}) {
		lc := setup(t)
		var u string
		if c.Status == "transport" {
			u = deadURL(t) + "/check"
		} else {
			st := newStub(t)
			status := int(c.Status.(float64))
			var body any = map[string]any{}
			if status == 200 {
				body = map[string]any{"allowed": true, "decision": "allow"}
			}
			st.reply(body, status, nil)
			path := c.Path
			if path == "" {
				path = "/check"
			}
			u = st.URL + path
		}
		for i := 0; i < 2; i++ {
			v := Admit(context.Background(), "hi", AdmitOptions{Endpoint: u, Timeout: time.Second, FailClosed: Bool(c.FailClosed)})
			if v.Allowed != c.Want.Allowed || v.Degraded != c.Want.Degraded {
				t.Fatalf("(%v, %q), want (%v, %q)", v.Allowed, v.Degraded, c.Want.Allowed, c.Want.Degraded)
			}
		}
		lines := lc.warnings("admit()")
		if len(lines) != c.Want.Warnings {
			t.Fatalf("warnings %v, want %d", lines, c.Want.Warnings)
		}
		for _, ln := range lines {
			if !strings.Contains(ln, "Fix:") || !strings.Contains(ln, c.Want.Fix) {
				t.Fatalf("warning %q lacks the fix %q", ln, c.Want.Fix)
			}
		}
		if got := GetDiagnostics().AdmissionDegraded; got != c.Want.Counted {
			t.Fatalf("counted %d, want %d", got, c.Want.Counted)
		}
	})
}

func runAdmitOrgOff(t *testing.T) {
	eachCase(t, "admit_org_off", func(t *testing.T, c struct {
		Destination string         `json:"destination"`
		Via         string         `json:"via"`
		FailClosed  bool           `json:"fail_closed"`
		Org         map[string]any `json:"org"`
		Machine     any            `json:"machine"`
		Want        struct {
			Allowed      bool   `json:"allowed"`
			Decision     string `json:"decision"`
			Degraded     string `json:"degraded"`
			AskedMachine bool   `json:"asked_machine"`
			Counted      int64  `json:"counted"`
		} `json:"want"`
	}) {
		setup(t)
		machine, gateway := newStub(t), newStub(t)
		gateway.routeBody("POST", "/v1/sdk/admit", c.Org)
		nodeURL := deadURL(t)
		if c.Machine != "transport" {
			machine.routeBody("POST", "/api/obs/admission/check", c.Machine)
			nodeURL = machine.URL
		}
		memInit(t, Options{Destination: c.Destination, NodeURL: nodeURL, OrgURL: gateway.URL, APIKey: "ik_1.s"})
		o := AdmitOptions{Timeout: time.Second, FailClosed: Bool(c.FailClosed)}
		if c.Via == "org_url" {
			o.OrgURL = gateway.URL
		}
		v := Admit(context.Background(), "hi", o)
		if v.Allowed != c.Want.Allowed || v.Decision != c.Want.Decision || v.Degraded != c.Want.Degraded {
			t.Fatalf("(%v, %s, %q), want (%v, %s, %q)", v.Allowed, v.Decision, v.Degraded, c.Want.Allowed, c.Want.Decision, c.Want.Degraded)
		}
		asked := machine.seen("/api/obs/admission/check")
		if (len(asked) > 0) != c.Want.AskedMachine {
			t.Fatalf("machine asked %d times, want %v", len(asked), c.Want.AskedMachine)
		}
		for _, r := range asked {
			if r.Headers.Get("Authorization") != "" {
				t.Fatal("the key went to the machine")
			}
		}
		if got := GetDiagnostics().AdmissionDegraded; got != c.Want.Counted {
			t.Fatalf("counted %d, want %d", got, c.Want.Counted)
		}
	})
}

// --- discovery ordering --------------------------------------------------------------

func runControlBeforeDiscovery(t *testing.T) {
	eachCase(t, "control_before_discovery", func(t *testing.T, c struct {
		Discovery string `json:"discovery"`
		DelayMS   int    `json:"delay_ms"`
		Want      string `json:"want"`
	}) {
		setup(t)
		machine, gateway := newStub(t), newStub(t)
		machine.route("GET", "/api/sdk/destination", func(stubReq) (int, any, map[string]string) {
			time.Sleep(time.Duration(c.DelayMS) * time.Millisecond)
			return 200, map[string]any{"api_version": 1, "destination": c.Discovery, "source": "config", "configured": "", "signed_in": true,
				"local": map[string]any{"enabled": true}, "online": map[string]any{}, "warnings": []any{}}, nil
		})
		accepted := func(stubReq) (int, any, map[string]string) {
			return 200, map[string]any{"accepted": []any{map[string]any{"index": 0, "id": "sc_1"}}, "rejected": []any{}}, nil
		}
		machine.route("POST", "/api/obs/scores", accepted)
		gateway.route("POST", "/v1/sdk/scores", accepted)
		t.Setenv("SUPERBASED_DISCOVER", "1")
		mem := tracetest.NewInMemoryExporter()
		if _, err := Init(context.Background(), Options{NodeURL: machine.URL, APIKey: "ik_1.s", OrgURL: gateway.URL, Exporter: mem}); err != nil {
			t.Fatal(err)
		}
		ctx, sp := StartSpan(context.Background(), "req", SpanOptions{})
		res := Score(ctx, "accuracy", 1.0, ScoreOptions{})
		sp.End()
		if !res.OK || len(res.Destinations) != 1 {
			t.Fatalf("%+v", res)
		}
		if _, ok := res.Destinations[c.Want]; !ok {
			t.Fatalf("destinations %v, want %s", res.Destinations, c.Want)
		}
	})
}

func runLocalReceiverDiscovery(t *testing.T) {
	sec := loadSection(t, "local_receiver_discovery")
	var receiver string
	_ = json.Unmarshal(sec["machine_receiver"], &receiver)
	eachCase(t, "local_receiver_discovery", func(t *testing.T, c struct {
		Destination  string `json:"destination"`
		EndpointFrom string `json:"endpoint_from"`
		Endpoint     string `json:"endpoint"`
		Discover     bool   `json:"discover"`
		Want         struct {
			Local *string `json:"local"`
			Asked bool    `json:"asked"`
		} `json:"want"`
	}) {
		setup(t)
		st := newStub(t)
		st.routeBody("GET", "/api/sdk/destination", map[string]any{"api_version": 1, "destination": "local", "source": "config", "configured": "", "signed_in": false,
			"local": map[string]any{"enabled": true, "otlp_traces_url": receiver}, "online": map[string]any{}, "warnings": []any{}})
		disc := "0"
		if c.Discover {
			disc = "1"
		}
		env := map[string]string{"SUPERBASED_DISCOVER": disc, "SUPERBASED_DESTINATION": c.Destination, "SUPERBASED_NODE_URL": st.URL,
			"SUPERBASED_ORG_URL": "https://gw.example.com", "SUPERBASED_API_KEY": "ik_1.s"}
		explicit, named := "", c.Endpoint
		switch c.EndpointFrom {
		case "argument":
			explicit = named
		case "superbased_env":
			env["SUPERBASED_OTLP_ENDPOINT"] = named
		case "otel_env":
			env["OTEL_EXPORTER_OTLP_ENDPOINT"] = named
			named = strings.TrimRight(named, "/") + "/v1/traces"
		}
		e := mapEnv(env)
		s, _ := resolveSettings(e, Options{Endpoint: explicit})
		p := resolvePlan(s, e, explicitInputs{endpoint: explicit})
		var local []string
		for _, x := range p.exporters {
			if x.name == DestinationLocal {
				local = append(local, x.endpoint)
			}
		}
		var want []string
		if c.Want.Local != nil {
			want = []string{map[string]string{"machine": receiver, "named": named, "default": DefaultEndpoint}[*c.Want.Local]}
		}
		if strings.Join(local, ",") != strings.Join(want, ",") {
			t.Fatalf("local %v, want %v", local, want)
		}
		if (len(st.seen("/api/sdk/destination")) > 0) != c.Want.Asked {
			t.Fatalf("machine asked = %v, want %v", !c.Want.Asked, c.Want.Asked)
		}
	})
}

// --- spans --------------------------------------------------------------------------

func runLLMSpanPrompt(t *testing.T) {
	eachCase(t, "llm_span_prompt", func(t *testing.T, c struct {
		Fixture string `json:"fixture"`
		Want    struct {
			Name    string `json:"name"`
			Version int64  `json:"version"`
			Content bool   `json:"content"`
		} `json:"want"`
	}) {
		setup(t)
		raw, err := os.ReadFile(filepath.Join(contractDir(), c.Fixture))
		if err != nil {
			t.Fatal(err)
		}
		var fx struct {
			Body json.RawMessage `json:"body"`
		}
		_ = json.Unmarshal(raw, &fx)
		p, err := parsePrompt(decodeJSON(fx.Body), "online", "production")
		if err != nil {
			t.Fatal(err)
		}
		mem := memInit(t, Options{})
		_ = WithLLMSpan(context.Background(), "chat", LLMOptions{Prompt: p}, func(context.Context, trace.Span) error { return nil })
		attrs := lastSpanAttrs(t, mem)
		if attrs["sbo.prompt.name"] != c.Want.Name || attrs["sbo.prompt.version"] != c.Want.Version {
			t.Fatalf("stamp %v / %v, want %s / %d", attrs["sbo.prompt.name"], attrs["sbo.prompt.version"], c.Want.Name, c.Want.Version)
		}
		_, a := attrs["input.value"]
		_, b := attrs["gen_ai.input.messages"]
		if (a || b) != c.Want.Content {
			t.Fatalf("content recorded = %v, want %v", a || b, c.Want.Content)
		}
	})
}

func runVendorSelfTracing(t *testing.T) {
	eachCase(t, "vendor_self_tracing", func(t *testing.T, c struct {
		Env  map[string]string `json:"env"`
		Want struct {
			Status   map[string]string `json:"status"`
			EnvAfter map[string]string `json:"env_after"`
			Exported map[string]bool   `json:"exported"`
		} `json:"want"`
	}) {
		setup(t)
		for k := range c.Want.EnvAfter {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
		for k, v := range c.Env {
			t.Setenv(k, v)
		}
		mem := memInit(t, Options{})
		d := GetDiagnostics()
		for k, v := range c.Want.Status {
			if d.VendorTracing[k] != v {
				t.Fatalf("vendor_tracing %v, want %v", d.VendorTracing, c.Want.Status)
			}
		}
		for k, v := range c.Want.EnvAfter {
			if os.Getenv(k) != v {
				t.Fatalf("%s = %q, want %q", k, os.Getenv(k), v)
			}
		}
		mu.Lock()
		tp := provider
		mu.Unlock()
		for scope := range c.Want.Exported {
			_, sp := tp.Tracer(scope).Start(context.Background(), "call "+scope)
			sp.End()
		}
		Flush(context.Background())
		got := map[string]bool{}
		for _, s := range mem.GetSpans() {
			got[s.InstrumentationScope.Name] = true
		}
		dropped := int64(0)
		for scope, want := range c.Want.Exported {
			if got[scope] != want {
				t.Fatalf("scope %s exported = %v, want %v", scope, got[scope], want)
			}
			if !want {
				dropped++
			}
		}
		if n := GetDiagnostics().VendorSpansDropped; n != dropped {
			t.Fatalf("vendor_spans_dropped %d, want %d", n, dropped)
		}
	})
}

func runSetUsageNetInput(t *testing.T) {
	eachCase(t, "set_usage_net_input", func(t *testing.T, c struct {
		Usage map[string]int `json:"usage"`
		Want  struct {
			InputTokens *int64 `json:"input_tokens"`
			Corrected   int64  `json:"corrected"`
		} `json:"want"`
	}) {
		setup(t)
		mem := memInit(t, Options{})
		before := GetDiagnostics().UsageNetInputCorrected
		ptr := func(k string) *int {
			if v, ok := c.Usage[k]; ok {
				return &v
			}
			return nil
		}
		u := Usage{InputTokens: ptr("input_tokens"), OutputTokens: ptr("output_tokens"), CacheReadTokens: ptr("cache_read_tokens"), CacheWriteTokens: ptr("cache_write_tokens")}
		err := WithLLMSpan(context.Background(), "chat", LLMOptions{}, func(_ context.Context, sp trace.Span) error { return SetUsage(sp, u) })
		if err != nil {
			t.Fatal(err)
		}
		attrs := lastSpanAttrs(t, mem)
		got, has := attrs["gen_ai.usage.input_tokens"]
		if c.Want.InputTokens == nil {
			if has {
				t.Fatalf("input_tokens %v, want absent", got)
			}
		} else if got != *c.Want.InputTokens {
			t.Fatalf("input_tokens %v, want %d", got, *c.Want.InputTokens)
		}
		if d := GetDiagnostics().UsageNetInputCorrected - before; d != c.Want.Corrected {
			t.Fatalf("corrected %d, want %d", d, c.Want.Corrected)
		}
	})
}

var _ sdktrace.SpanExporter = (*tracetest.InMemoryExporter)(nil)
