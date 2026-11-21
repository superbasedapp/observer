package superbased

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// fakeEval is a fake eval API (the machine's or the gateway's): one dataset,
// literal uploads answered with item ids, runs, results and finish.
type fakeEval struct {
	mu      sync.Mutex
	prefix  string // "/api/obs/eval" or "/v1/sdk"
	results []map[string]any
	creates []map[string]any
	uploads []map[string]any
	items   []any
}

func (f *fakeEval) install(st *stub, online bool) {
	ds := f.prefix + "/datasets"
	st.route("GET", ds, func(stubReq) (int, any, map[string]string) {
		return 200, map[string]any{"datasets": []any{map[string]any{"id": "ds_1", "name": "golden"}}}, nil
	})
	st.route("POST", ds, func(r stubReq) (int, any, map[string]string) {
		return 201, map[string]any{"dataset": map[string]any{"id": "ds_1", "name": r.Body["name"]}}, nil
	})
	upload := func(r stubReq) (int, any, map[string]string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.uploads = append(f.uploads, r.Body)
		var ids []any
		f.items = nil
		for i, x := range r.Body["items"].([]any) {
			it := x.(map[string]any)
			ids = append(ids, fmt.Sprintf("srv-%d", i))
			f.items = append(f.items, map[string]any{"item_id": fmt.Sprintf("srv-%d", i), "client_id": it["id"], "input": it["input"], "expected": it["expected"]})
		}
		return 201, map[string]any{"version": 2, "item_ids": ids}, nil
	}
	if online {
		st.route("POST", ds+"/ds_1/snapshots", upload)
		st.route("GET", ds+"/ds_1/snapshots/2/items", func(stubReq) (int, any, map[string]string) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return 200, map[string]any{"items": f.items, "next_cursor": ""}, nil
		})
	} else {
		st.route("POST", ds+"/ds_1/items", upload)
		st.route("GET", ds+"/ds_1/items", func(stubReq) (int, any, map[string]string) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return 200, map[string]any{"items": f.items, "next_cursor": ""}, nil
		})
	}
	st.route("POST", f.prefix+"/experiments", func(r stubReq) (int, any, map[string]string) {
		f.mu.Lock()
		f.creates = append(f.creates, r.Body)
		f.mu.Unlock()
		return 201, map[string]any{"id": "run_1", "snapshot_version": 2}, nil
	})
	st.route("POST", f.prefix+"/experiments/run_1/results", func(r stubReq) (int, any, map[string]string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, x := range r.Body["results"].([]any) {
			f.results = append(f.results, x.(map[string]any))
		}
		return 200, map[string]any{"accepted": len(r.Body["results"].([]any)), "rejected": []any{}}, nil
	})
	st.routeBody("POST", f.prefix+"/experiments/run_1/finish", map[string]any{})
	st.routeBody("GET", f.prefix+"/experiments/run_1", map[string]any{"id": "run_1", "total": 3, "passed": 2, "pass_rate": 2.0 / 3})
}

func TestRunExperimentLiteralBoth(t *testing.T) {
	setup(t)
	machine, gw := newStub(t), newStub(t)
	local, online := &fakeEval{prefix: "/api/obs/eval"}, &fakeEval{prefix: "/v1/sdk"}
	local.install(machine, false)
	online.install(gw, true)
	mem := memInit(t, Options{Destination: DestinationBoth, NodeURL: machine.URL, OrgURL: gw.URL, APIKey: "ik_1.s"})
	items := []Item{{ID: "a", Input: "2+2", Expected: "4"}, {Input: "3+3", Expected: "6"}, {Input: "boom", Expected: "x"}}
	task := func(_ context.Context, it Item) (any, error) {
		switch it.Input {
		case "2+2":
			return "4", nil
		case "3+3":
			return "7", nil
		}
		return nil, errors.New("task failed")
	}
	evals := []Evaluator{
		EvaluatorFunc("Exact Match!", func(_ context.Context, in EvalInput) (any, error) { return in.Output == in.Expected, nil }),
		VersionedEvaluatorFunc("multi", "2", func(context.Context, EvalInput) (any, error) {
			return []any{0.75, map[string]any{"name": "label", "value": "good", "comment": "c"}, Evaluation{Name: "e", Value: 1}}, nil
		}),
		EvaluatorFunc("broken", func(context.Context, EvalInput) (any, error) { panic("x") }),
	}
	res, err := RunExperiment(context.Background(), ExperimentOptions{Dataset: items, Task: task, Evaluators: evals, DatasetName: "golden",
		Name: "math", Metadata: map[string]any{"k": "v"}, FailUnder: Float(0.9), MaxConcurrency: 3})
	var gate *ExperimentGateFailed
	if !errors.As(err, &gate) || len(gate.Reasons) != 0 || !strings.Contains(gate.Error(), "below") {
		t.Fatalf("want a rate gate failure, got %v", err)
	}
	if res.RunID != "run_1" || res.Runs[DestinationOnline] != "run_1" || res.Runs[DestinationLocal] != "run_1" {
		t.Fatalf("runs %v", res.Runs)
	}
	if math.Abs(res.PassRate()-2.0/3) > 1e-9 || res.Scored() != 3 {
		t.Fatalf("server rate %v scored %d", res.PassRate(), res.Scored())
	}
	// Both sides got the same create id, the machine the upload's item ids.
	if local.creates[0]["id"] != online.creates[0]["id"] || local.creates[0]["item_ids"] == nil || online.creates[0]["item_ids"] != nil {
		t.Fatalf("creates %v / %v", local.creates, online.creates)
	}
	if len(local.results) != 3 || len(online.results) != 3 {
		t.Fatalf("results %d / %d", len(local.results), len(online.results))
	}
	if gw.seen("/v1/sdk/experiments")[0].Headers.Get("Authorization") == "" || machine.seen("/api/obs/eval/experiments")[0].Headers.Get("Authorization") != "" {
		t.Fatal("the key goes to the gateway only")
	}
	byInput := map[any]ItemResult{}
	for _, it := range res.Items {
		byInput[it.Input] = it
	}
	ok := byInput["2+2"]
	if ok.Error != "" || len(ok.Scores) != 4 || len(ok.EvaluatorErrors) != 1 || ok.Scores[0].Name != "exact_match" || ok.Scores[1].ScorerVersion != "2" {
		t.Fatalf("%+v", ok)
	}
	if byInput["boom"].Error == "" || len(byInput["boom"].Scores) != 0 {
		t.Fatalf("%+v", byInput["boom"])
	}
	sum := res.Summary()
	if sum["exact_match"].Count != 2 || sum["exact_match"].Passed != 1 || sum["exact_match"].Mean != 0.5 {
		t.Fatalf("summary %+v", sum)
	}
	// Each item's span is its own trace, stamped with the run and item ids.
	Flush(context.Background())
	traces := map[string]bool{}
	for _, s := range mem.GetSpans() {
		if s.Name == "experiment math" {
			traces[s.SpanContext.TraceID().String()] = true
			if attrsOf(s)[keyExperimentRunID] != "run_1" {
				t.Fatalf("%v", attrsOf(s))
			}
		}
	}
	if len(traces) != 3 {
		t.Fatalf("item traces %d", len(traces))
	}
	var row map[string]any
	for _, r := range local.results {
		if r["item_id"] == "srv-0" {
			row = r
		}
	}
	if row == nil || row["output"] != "4" || row["trace_id"] == nil || len(row["scores"].([]any)) != 4 {
		t.Fatalf("row %v", row)
	}
}

func TestRunExperimentInProcessAndSkippedSide(t *testing.T) {
	setup(t)
	memInit(t, Options{})
	res, err := RunExperiment(context.Background(), ExperimentOptions{Dataset: []any{"x", "x"}, Task: identityTask,
		Evaluators: []Evaluator{EvaluatorFunc("t", func(context.Context, EvalInput) (any, error) { return true, nil })}, FailUnder: Float(0.5)})
	if err != nil || res.RunID != "" || len(res.Items) != 2 || res.PassRate() != 1 || res.Items[0].ItemID == res.Items[1].ItemID {
		t.Fatalf("%+v %v", res, err)
	}
	// A destination refusing for want of a scope is skipped; strict fails the gate.
	setup(t)
	gw := newStub(t)
	gw.route("GET", "/v1/sdk/datasets", func(stubReq) (int, any, map[string]string) {
		return 403, map[string]any{"error": "insufficient_scope", "message": "sdk:eval"}, nil
	})
	memInit(t, Options{Destination: DestinationOnline, OrgURL: gw.URL, APIKey: "ik_1.s"})
	res, err = RunExperiment(context.Background(), ExperimentOptions{Dataset: "golden", Task: identityTask, FailUnder: Float(0.5)})
	var gate *ExperimentGateFailed
	if !errors.As(err, &gate) || len(res.SkippedSides) != 1 || len(gate.Reasons) != 2 {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := RunExperiment(context.Background(), ExperimentOptions{Dataset: "golden"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("a nil task is an argument error")
	}
}

func TestMiscSurface(t *testing.T) {
	setup(t)
	// Identify and headers.
	ctx := Identify(context.Background(), Attributes{SessionID: "s"})
	if CurrentAttributes(ctx)["session_id"] != "s" {
		t.Fatal("identify")
	}
	if !IsExactCost(CostGatewayExact) || IsExactCost(CostComputed) {
		t.Fatal("IsExactCost")
	}
	// The advertised admit timeout is remembered per URL.
	st := newStub(t)
	st.reply(map[string]any{"allowed": true, "recommended_client_timeout_ms": 3000}, 200, map[string]string{"X-SBO-Recommended-Timeout-Ms": "2500"})
	Admit(context.Background(), "hi", AdmitOptions{Endpoint: st.URL + "/check"})
	if advertisedTimeout(st.URL+"/check") != 3*time.Second {
		t.Fatalf("advertised %v", advertisedTimeout(st.URL+"/check"))
	}
	// A bad body is a degraded verdict.
	st.reply([]byte("not json"), 200, nil)
	if v := Admit(context.Background(), "hi", AdmitOptions{Endpoint: st.URL + "/check"}); v.Degraded != DegradedBadResponse {
		t.Fatalf("%+v", v)
	}
	// Attached-mode export ratio, and the timeout accounting of a flush.
	if keepByRatio([16]byte{}, 0) || !keepByRatio([16]byte{}, 1) {
		t.Fatal("ratio")
	}
	stats.mu.Lock()
	stats.handed = 3
	stats.mu.Unlock()
	noteTimeout("flush", time.Second)
	if d := GetDiagnostics(); d.PendingSpans != 0 || d.DroppedSpans != 3 || !strings.Contains(d.LastError, "timed out") {
		t.Fatalf("%+v", d)
	}
	if !maybeLogFailures(time.Now().Add(2 * time.Minute)) {
		t.Fatal("the failure summary is due")
	}
	if fromAny("k", struct{}{}).Value.AsString() != "{}" || fromAny("k", 2).Value.AsInt64() != 2 || fromAny("k", []string{"a"}).Value.AsStringSlice()[0] != "a" {
		t.Fatal("fromAny")
	}
	if s := newSwitchableSampler(); !strings.HasPrefix(s.Description(), "SuperbasedSampler") {
		t.Fatal(s.Description())
	}
	if (&ExperimentError{"x"}).Error() != "superbased: x" {
		t.Fatal("error text")
	}
}

func TestConsoleAndEnvOptions(t *testing.T) {
	setup(t)
	t.Setenv("SUPERBASED_METADATA", "team=core,owner=a%20b")
	t.Setenv("SUPERBASED_TAGS", "x, y")
	t.Setenv("SUPERBASED_EXPORT_TIMEOUT_MS", "1500")
	t.Setenv("OTEL_SERVICE_NAME", "from-otel")
	var buf strings.Builder
	old := stderr
	stderr = &buf
	t.Cleanup(func() { stderr = old })
	mem := memInit(t, Options{Console: Bool(true)})
	s := CurrentSettings()
	if s.Metadata["owner"] != "a b" || strings.Join(s.Tags, ",") != "x,y" || s.ExportTimeout != 1500*time.Millisecond || s.ServiceName != "from-otel" {
		t.Fatalf("%v", s)
	}
	_, sp := StartSpan(context.Background(), "printed", SpanOptions{})
	sp.End()
	Flush(context.Background())
	if !strings.Contains(buf.String(), `"name":"printed"`) || len(mem.GetSpans()) != 1 {
		t.Fatalf("console %q", buf.String())
	}
}

var _ = tracetest.NewInMemoryExporter
