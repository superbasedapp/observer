package superbased

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	resultsPerPost = 200
	itemsPage      = 500
)

var failWords = map[string]bool{"fail": true, "false": true, "no": true, "bad": true}

// ExperimentError is an experiment that could not be set up (dataset, run
// creation), or GetDataset finding no dataset. When the org's plan refused
// it, it wraps the *PlanRefusalError (errors.As finds it; errors.Is matches
// ErrPlanRequired or ErrAllowanceExceeded).
type ExperimentError struct {
	Msg     string
	refusal *PlanRefusalError
}

func (e *ExperimentError) Error() string { return "superbased: " + e.Msg }

// Unwrap is the org's plan refusal behind the error, or nil.
func (e *ExperimentError) Unwrap() error {
	if e.refusal == nil {
		return nil
	}
	return e.refusal
}

// sideSkipped is a destination that refused for want of a scope (403
// insufficient_scope): the run treats it as skipped.
type sideSkipped struct{ ExperimentError }

// ExperimentGateFailed is a FailUnder gate that failed. Result has the
// details; Reasons is why the strict gate failed before the rate was compared
// (empty when the pass rate itself is below FailUnder). A CI program exits 1
// on it (errors.As).
type ExperimentGateFailed struct {
	Result    *ExperimentResult
	FailUnder float64
	Reasons   []string
}

func (e *ExperimentGateFailed) Error() string {
	if len(e.Reasons) > 0 {
		return fmt.Sprintf("experiment %q: the fail_under gate cannot pass: %s (strict; set Strict to false to gate on the pass rate alone)", e.Result.Name, strings.Join(e.Reasons, "; "))
	}
	return fmt.Sprintf("experiment %q: pass rate %.3f is below %.3f", e.Result.Name, e.Result.PassRate(), e.FailUnder)
}

// Evaluation is one evaluator result: Value is a number, a bool or a short label.
type Evaluation struct {
	Name          string
	Value         any
	Comment       string
	ScorerVersion string // default "1"
}

// Passed is the contract's pass rule: true, a number >= 0.5, or a label not
// in fail/false/no/bad.
func (e Evaluation) Passed() bool { return passes(e.Value) }

func passes(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return !failWords[strings.ToLower(strings.TrimSpace(t))]
	}
	if f, ok := numberOf(v); ok {
		return f >= 0.5
	}
	return !failWords[strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))]
}

func numberOf(v any) (float64, bool) {
	switch t := v.(type) {
	case int:
		return float64(t), true
	case int32:
		return float64(t), true
	case int64:
		return float64(t), true
	case uint:
		return float64(t), true
	case uint64:
		return float64(t), true
	case float32:
		return float64(t), true
	}
	return jsonFloat(v)
}

// Dataset is a dataset on one destination.
type Dataset struct {
	ID             string
	Name           string
	Side           string
	ItemCount      int
	LatestSnapshot int
	Raw            map[string]any
}

// Item is one experiment item: a literal one, or one read from a dataset.
type Item struct {
	ID       string
	Input    any
	Expected any
	Metadata any
}

// ItemResult is one item's outcome.
type ItemResult struct {
	ItemID          string
	Input           any
	Expected        any
	Metadata        any
	Output          any
	TraceID         string
	Scores          []Evaluation
	Error           string
	EvaluatorErrors []string
}

// Passed: no error and every score passing.
func (r ItemResult) Passed() bool {
	if r.Error != "" {
		return false
	}
	for _, s := range r.Scores {
		if !s.Passed() {
			return false
		}
	}
	return true
}

// ScorerSummary is one evaluator's totals.
type ScorerSummary struct {
	Count  int
	Passed int
	Mean   float64 // of the numeric and boolean values
}

// ExperimentResult is a run's outcome.
type ExperimentResult struct {
	Name             string
	RunID            string            // the first destination's run
	Runs             map[string]string // destination -> run id
	Items            []ItemResult
	SkippedNoContent int
	Server           map[string]map[string]any // destination -> GET experiment body
	Errors           []string
	// SkippedSides are the destinations skipped for want of a scope.
	SkippedSides []string
	// FailedPosts counts results a destination did not accept.
	FailedPosts int
	// PlanRefusal is set when the org's plan refused a post or the finish
	// (the reason is in Errors too).
	PlanRefusal *PlanRefusalError
}

var serverOrder = []string{DestinationOnline, DestinationLocal}

func isCount(v any) (int64, bool) {
	if _, b := v.(bool); b {
		return 0, false
	}
	n, ok := jsonInt(v)
	return n, ok && n >= 0
}

func localScored(items []ItemResult) []ItemResult {
	var out []ItemResult
	for _, it := range items {
		if it.Error != "" || len(it.Scores) > 0 {
			out = append(out, it)
		}
	}
	return out
}

// Scored is how many items were scored: the first side's total, else the
// local count of items with a score or a task error.
func (r *ExperimentResult) Scored() int {
	local := localScored(r.Items)
	for _, sd := range serverOrder {
		body, ok := r.Server[sd]
		if !ok {
			continue
		}
		if n, ok := isCount(body["total"]); ok && (n > 0 || len(local) == 0) {
			return int(n)
		}
	}
	return len(local)
}

// PassRate is the first side's pass rate, else the local rate over scored
// items; NaN when nothing was scored.
func (r *ExperimentResult) PassRate() float64 {
	for _, sd := range serverOrder {
		body, ok := r.Server[sd]
		if !ok {
			continue
		}
		pr, isNum := jsonFloat(body["pass_rate"])
		if !isNum {
			continue
		}
		if n, ok := isCount(body["total"]); ok && n == 0 {
			continue // an older server's 0 for "nothing scored"
		}
		return pr
	}
	scored := localScored(r.Items)
	if len(scored) == 0 {
		return math.NaN()
	}
	passed := 0
	for _, it := range scored {
		if it.Passed() {
			passed++
		}
	}
	return float64(passed) / float64(len(scored))
}

// Summary is, per evaluator, the count, passed count and mean.
func (r *ExperimentResult) Summary() map[string]ScorerSummary {
	type acc struct {
		count, passed, numeric int
		sum                    float64
	}
	accs := map[string]*acc{}
	for _, it := range r.Items {
		for _, s := range it.Scores {
			a := accs[s.Name]
			if a == nil {
				a = &acc{}
				accs[s.Name] = a
			}
			a.count++
			if s.Passed() {
				a.passed++
			}
			if b, ok := s.Value.(bool); ok {
				a.numeric++
				if b {
					a.sum++
				}
			} else if f, ok := numberOf(s.Value); ok {
				a.numeric++
				a.sum += f
			}
		}
	}
	out := map[string]ScorerSummary{}
	for k, a := range accs {
		m := 0.0
		if a.numeric > 0 {
			m = a.sum / float64(a.numeric)
		}
		out[k] = ScorerSummary{a.count, a.passed, m}
	}
	return out
}

// gateProblems: why a strict FailUnder gate fails before the rate is compared.
func gateProblems(r *ExperimentResult) []string {
	var out []string
	if r.Scored() == 0 {
		out = append(out, "no item was scored (no evaluator returned a score)")
	}
	for _, sd := range r.SkippedSides {
		out = append(out, fmt.Sprintf("the %s destination was skipped", sd))
	}
	if r.FailedPosts > 0 {
		out = append(out, fmt.Sprintf("%d result(s) were not accepted, so the recorded pass rate covers only part of the run", r.FailedPosts))
	}
	return out
}

func gateFails(r *ExperimentResult, failUnder *float64, strict bool) bool {
	if failUnder == nil {
		return false
	}
	if strict && len(gateProblems(r)) > 0 {
		return true
	}
	if r.Scored() == 0 {
		return false
	}
	return !(r.PassRate() >= *failUnder)
}

// ExperimentGate says whether failUnder fails r and why the strict gate fails
// before the rate is compared (TS experimentGate). nil failUnder is no gate.
func ExperimentGate(r *ExperimentResult, failUnder *float64, strict bool) (bool, []string) {
	return gateFails(r, failUnder, strict), gateProblems(r)
}

// --- evaluators ---------------------------------------------------------------

// EvalInput is what an evaluator sees.
type EvalInput struct {
	Input, Output, Expected, Metadata any
}

// Evaluator scores one item's output. Evaluate may return a number, a bool, a
// label, an Evaluation (or a slice of them), a map {name, value, comment,
// version}, a []any of those, or nil (no score).
type Evaluator interface {
	Name() string
	Version() string
	Evaluate(ctx context.Context, in EvalInput) (any, error)
}

type funcEvaluator struct {
	name, version string
	fn            func(context.Context, EvalInput) (any, error)
}

func (f funcEvaluator) Name() string    { return f.name }
func (f funcEvaluator) Version() string { return f.version }
func (f funcEvaluator) Evaluate(ctx context.Context, in EvalInput) (any, error) {
	return f.fn(ctx, in)
}

// EvaluatorFunc makes an Evaluator (version "1") from a function.
func EvaluatorFunc(name string, fn func(context.Context, EvalInput) (any, error)) Evaluator {
	return funcEvaluator{name, "1", fn}
}

// VersionedEvaluatorFunc is EvaluatorFunc with a scorer version.
func VersionedEvaluatorFunc(name, version string, fn func(context.Context, EvalInput) (any, error)) Evaluator {
	return funcEvaluator{name, version, fn}
}

var evalNameBad = regexp.MustCompile(`[^a-z0-9_.-]+`)

func evaluatorName(e Evaluator) string {
	n := strings.Trim(evalNameBad.ReplaceAllString(strings.ToLower(strings.TrimSpace(e.Name())), "_"), "_")
	if n == "" {
		n = "evaluator"
	}
	if len(n) > 64 {
		n = n[:64]
	}
	return n
}

func evaluatorVersion(e Evaluator) string {
	if v := e.Version(); v != "" {
		return v
	}
	return "1"
}

func normalizeEval(e Evaluator, out any) []Evaluation {
	name, version := evaluatorName(e), evaluatorVersion(e)
	switch t := out.(type) {
	case nil:
		return nil
	case Evaluation:
		if t.ScorerVersion == "" {
			t.ScorerVersion = "1"
		}
		return []Evaluation{t}
	case *Evaluation:
		if t == nil {
			return nil
		}
		return normalizeEval(e, *t)
	case []Evaluation:
		var res []Evaluation
		for _, x := range t {
			res = append(res, normalizeEval(e, x)...)
		}
		return res
	case []any:
		var res []Evaluation
		for _, x := range t {
			res = append(res, normalizeEval(e, x)...)
		}
		return res
	case map[string]any:
		n := jsonText(t["name"])
		if n == "" {
			n = name
		}
		v := jsonText(t["version"])
		if v == "" {
			v = version
		}
		return []Evaluation{{Name: n, Value: t["value"], Comment: jsonText(t["comment"]), ScorerVersion: v}}
	}
	return []Evaluation{{Name: name, Value: out, ScorerVersion: version}}
}

// --- destinations ---------------------------------------------------------------

type expRun struct {
	sd              side
	datasetID       string
	runID           string
	snapshotVersion int
	items           []map[string]any
	itemMap         map[int]string // our item index -> this side's item id
	itemIDs         []string       // a literal upload's ids on the machine
}

func scopeRefused(r *response) bool { return r.status == 403 && r.errorCode() == "insufficient_scope" }

func okBody(r *response, what, sideName string) (map[string]any, error) {
	if !r.ok() {
		if scopeRefused(r) {
			return nil, &sideSkipped{ExperimentError{Msg: fmt.Sprintf("%s: skipped, %s refused: %s (an SDK key from sign-in has no sdk:eval scope; run experiments on the org with a CI credential that has it)", sideName, what, r.describe())}}
		}
		return nil, &ExperimentError{Msg: fmt.Sprintf("%s: %s failed: %s", sideName, what, r.describe()), refusal: r.planRefusal()}
	}
	if m := r.obj(); m != nil {
		return m, nil
	}
	return map[string]any{}, nil
}

func findDataset(ctx context.Context, sd side, ref string) (*Dataset, error) {
	var q []queryParam
	if sd.name == DestinationOnline && !strings.HasPrefix(ref, "ds_") {
		q = []queryParam{{"name", ref}}
	}
	body, err := okBody(sd.call(ctx, "GET", "datasets", nil, q, nil, nil), "dataset list", sd.name)
	if err != nil {
		return nil, err
	}
	list, _ := body["datasets"].([]any)
	for _, x := range list {
		d, ok := x.(map[string]any)
		if !ok {
			continue
		}
		if jsonText(d["id"]) == ref || jsonStr(d, "name") == ref {
			ic, _ := jsonInt(d["item_count"])
			ls, _ := jsonInt(d["latest_snapshot"])
			return &Dataset{ID: jsonText(d["id"]), Name: jsonStr(d, "name"), Side: sd.name, ItemCount: int(ic), LatestSnapshot: int(ls), Raw: d}, nil
		}
	}
	return nil, nil
}

// GetDataset returns a dataset by name or id from the first destination that
// has it (the gateway first under both); an *ExperimentError when none does
// (wrapping the *PlanRefusalError when the org's plan refused the read).
func GetDataset(ctx context.Context, nameOrID string) (*Dataset, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var errs []string
	var refused *PlanRefusalError
	targets := sides(nil)
	if len(targets) == 0 {
		errs = append(errs, unavailableReason(nil))
	}
	for _, sd := range targets {
		d, err := findDataset(ctx, sd, nameOrID)
		if err != nil {
			errs = append(errs, strings.TrimPrefix(err.Error(), "superbased: "))
			var pr *PlanRefusalError
			if refused == nil && errors.As(err, &pr) {
				refused = pr
			}
			continue
		}
		if d != nil {
			return d, nil
		}
	}
	msg := fmt.Sprintf("dataset %q not found", nameOrID)
	if len(errs) > 0 {
		msg += ": " + strings.Join(errs, "; ")
	}
	return nil, &ExperimentError{Msg: msg, refusal: refused}
}

// literalItemID is the default id of a literal item: "item-" + the first 16
// hex of SHA-256 over the canonical JSON of [input, expected, metadata]
// (review E-75; the same id in every SDK).
func literalItemID(input, expected, metadata any) string {
	h := sha256.Sum256([]byte(jsJSON([]any{input, expected, metadata}, true)))
	return "item-" + hex.EncodeToString(h[:])[:16]
}

// literalItems turns the Dataset value of a literal run into items with ids.
func literalItems(v any) []Item {
	var raw []any
	switch t := v.(type) {
	case []Item:
		for _, it := range t {
			raw = append(raw, it)
		}
	case []map[string]any:
		for _, it := range t {
			raw = append(raw, it)
		}
	case []any:
		raw = t
	case []string:
		for _, s := range t {
			raw = append(raw, s)
		}
	}
	out := []Item{}
	seen := map[string]int{}
	for _, x := range raw {
		var it Item
		switch t := x.(type) {
		case Item:
			it = t
		case map[string]any:
			it.ID = jsonText(t["id"])
			it.Input = t["input"]
			if e, ok := t["expected"]; ok && e != nil {
				it.Expected = e
			} else {
				it.Expected = t["expected_output"]
			}
			it.Metadata = t["metadata"]
		default:
			it.Input = x
		}
		if it.ID == "" {
			id := literalItemID(it.Input, it.Expected, it.Metadata)
			seen[id]++
			if seen[id] > 1 {
				id = fmt.Sprintf("%s-%d", id, seen[id])
			}
			it.ID = id
		}
		out = append(out, it)
	}
	return out
}

func itemRow(it Item) map[string]any {
	row := map[string]any{"id": it.ID, "input": it.Input, "expected": it.Expected}
	if it.Metadata != nil {
		row["metadata"] = it.Metadata
	}
	return row
}

func uploadLiteral(ctx context.Context, sd side, datasetName string, items []Item) (string, int, []string, error) {
	rows := make([]map[string]any, 0, len(items))
	for _, it := range items {
		rows = append(rows, itemRow(it))
	}
	if sd.name == DestinationLocal {
		body, err := okBody(sd.call(ctx, "POST", "datasets", map[string]any{"name": datasetName}, nil, nil, nil), "dataset create", sd.name)
		if err != nil {
			return "", 0, nil, err
		}
		ds := body
		if inner, ok := body["dataset"].(map[string]any); ok {
			ds = inner
		}
		id := jsonText(ds["id"])
		if id == "" {
			return "", 0, nil, &ExperimentError{Msg: "local: dataset create answered no id"}
		}
		body, err = okBody(sd.call(ctx, "POST", "dataset_snapshot", map[string]any{"items": rows}, nil, nil, map[string]string{"id": id}), "dataset items", sd.name)
		if err != nil {
			return "", 0, nil, err
		}
		var ids []string
		if arr, ok := body["item_ids"].([]any); ok {
			for _, x := range arr {
				if _, b := x.(bool); !b && x != nil {
					ids = append(ids, jsonText(x))
				}
			}
		}
		v, _ := jsonInt(body["version"])
		if v == 0 {
			v, _ = jsonInt(body["snapshot_version"])
		}
		return id, int(v), ids, nil
	}
	d, err := findDataset(ctx, sd, datasetName)
	if err != nil {
		return "", 0, nil, err
	}
	if d == nil {
		return "", 0, nil, &ExperimentError{Msg: fmt.Sprintf("online: dataset %q does not exist on the org (create it on the dashboard first)", datasetName)}
	}
	body, err := okBody(sd.call(ctx, "POST", "dataset_snapshot", map[string]any{"items": rows}, nil, nil, map[string]string{"id": d.ID}), "dataset snapshot", sd.name)
	if err != nil {
		return "", 0, nil, err
	}
	v, _ := jsonInt(body["version"])
	return d.ID, int(v), nil, nil
}

func readItems(ctx context.Context, r *expRun) ([]map[string]any, error) {
	var out []map[string]any
	cursor := ""
	for i := 0; i < 10000; i++ {
		q := []queryParam{{"limit", strconv.Itoa(itemsPage)}, {"cursor", cursor}}
		if r.sd.name == DestinationLocal {
			if r.snapshotVersion != 0 {
				q = append(q, queryParam{"version", strconv.Itoa(r.snapshotVersion)})
			}
			if r.runID != "" {
				q = append(q, queryParam{"run", r.runID})
			}
		}
		body, err := okBody(r.sd.call(ctx, "GET", "dataset_items", nil, q, nil, map[string]string{"id": r.datasetID, "version": strconv.Itoa(r.snapshotVersion)}), "dataset items", r.sd.name)
		if err != nil {
			return nil, err
		}
		if arr, ok := body["items"].([]any); ok {
			for _, x := range arr {
				if m, ok := x.(map[string]any); ok {
					out = append(out, m)
				}
			}
		}
		cursor = jsonText(body["next_cursor"])
		if cursor == "" {
			break
		}
	}
	return out, nil
}

func inputKey(item map[string]any) string { return jsJSON(item["input"], true) }

func mapItems(primary, other []map[string]any) map[int]string {
	byClient := map[string]string{}
	byInput := map[string][]string{}
	for _, i := range other {
		if c := jsonText(i["client_id"]); c != "" {
			byClient[c] = jsonText(i["item_id"])
		}
		k := inputKey(i)
		byInput[k] = append(byInput[k], jsonText(i["item_id"]))
	}
	out := map[int]string{}
	for n, it := range primary {
		if c := jsonText(it["client_id"]); c != "" {
			if id, ok := byClient[c]; ok {
				out[n] = id
				continue
			}
		}
		k := inputKey(it)
		if ids := byInput[k]; len(ids) > 0 {
			out[n] = ids[0]
			byInput[k] = ids[1:]
		}
	}
	return out
}

// --- the run --------------------------------------------------------------------

// Task runs one item and returns its output.
type Task func(ctx context.Context, item Item) (any, error)

// ExperimentOptions are RunExperiment's options.
type ExperimentOptions struct {
	// Dataset is a dataset name or id (string), a Dataset / *Dataset, or the
	// literal items ([]Item, []map[string]any with input / expected |
	// expected_output / metadata / id, or []any of bare inputs). A literal item
	// with no id gets one derived from its content.
	Dataset    any
	Task       Task
	Evaluators []Evaluator
	Name       string // default "experiment"
	Metadata   map[string]any
	// MaxConcurrency is the number of items run at once (default 4).
	MaxConcurrency int
	// SnapshotVersion pins the dataset snapshot (nil: freeze a new one).
	SnapshotVersion *int
	// DatasetName uploads literal items to that dataset (created on the
	// machine; on the org it must exist). Without it a literal run stays
	// in-process: nothing is posted.
	DatasetName string
	// FailUnder (0..1) fails the run (an *ExperimentGateFailed error) below
	// that pass rate. Strict (default true) also fails it when nothing was
	// scored, a destination was skipped or a result was not accepted.
	FailUnder *float64
	Strict    *bool
}

// RunExperiment runs Task over every item of Dataset, scores each output with
// the evaluators and records the run on the destination(s) chosen at Init
// (each item in its own trace; results posted as they finish; the run
// finished and read back). It returns an *ExperimentError when the dataset is
// not found or a run cannot be created, and the result with an
// *ExperimentGateFailed when FailUnder fails.
func RunExperiment(ctx context.Context, o ExperimentOptions) (*ExperimentResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if o.Task == nil {
		return nil, fmt.Errorf("%w: ExperimentOptions.Task is nil", ErrInvalidArgument)
	}
	strict := o.Strict == nil || *o.Strict
	name := o.Name
	if name == "" {
		name = "experiment"
	}
	res := &ExperimentResult{Name: name, Runs: map[string]string{}, Server: map[string]map[string]any{}, Errors: []string{}}
	scorers := []map[string]any{}
	for _, e := range o.Evaluators {
		scorers = append(scorers, map[string]any{"name": evaluatorName(e), "version": evaluatorVersion(e)})
	}
	snapshot := 0
	if o.SnapshotVersion != nil {
		snapshot = *o.SnapshotVersion
	}
	var runs []*expRun
	var items []map[string]any
	targets := sides(nil)
	skip := func(err error) bool {
		var sk *sideSkipped
		return errors.As(err, &sk)
	}

	var ref string
	var ds *Dataset
	switch t := o.Dataset.(type) {
	case string:
		ref = t
	case Dataset:
		ds, ref = &t, t.ID
	case *Dataset:
		ds, ref = t, t.ID
	}
	if ds != nil || ref != "" {
		if len(targets) == 0 {
			return nil, &ExperimentError{Msg: fmt.Sprintf("dataset %q: %s", ref, unavailableReason(nil))}
		}
		skipped := 0
		for _, sd := range targets {
			var d *Dataset
			var err error
			if ds != nil && ds.Side != "" && ds.Side != sd.name {
				if ds.Name != "" {
					d, err = findDataset(ctx, sd, ds.Name)
				}
			} else {
				d, err = findDataset(ctx, sd, ref)
			}
			if err != nil {
				if skip(err) {
					res.Errors = append(res.Errors, strings.TrimPrefix(err.Error(), "superbased: "))
					res.SkippedSides = append(res.SkippedSides, sd.name)
					skipped++
					continue
				}
				return nil, err
			}
			if d != nil {
				runs = append(runs, &expRun{sd: sd, datasetID: d.ID, snapshotVersion: snapshot})
			}
		}
		if len(runs) == 0 && skipped == 0 {
			return nil, &ExperimentError{Msg: fmt.Sprintf("dataset %q not found on any destination", ref)}
		}
	} else {
		lit := literalItems(o.Dataset)
		if o.DatasetName != "" && len(targets) == 0 {
			res.Errors = append(res.Errors, fmt.Sprintf("dataset %q not uploaded, the run is in-process only: %s", o.DatasetName, unavailableReason(nil)))
		}
		if o.DatasetName != "" {
			for _, sd := range targets {
				id, version, ids, err := uploadLiteral(ctx, sd, o.DatasetName, lit)
				if err != nil {
					if skip(err) {
						res.Errors = append(res.Errors, strings.TrimPrefix(err.Error(), "superbased: "))
						res.SkippedSides = append(res.SkippedSides, sd.name)
						continue
					}
					return nil, err
				}
				runs = append(runs, &expRun{sd: sd, datasetID: id, snapshotVersion: version, itemIDs: ids})
			}
		}
		for _, it := range lit {
			items = append(items, map[string]any{"item_id": it.ID, "client_id": it.ID, "input": it.Input, "expected": it.Expected, "metadata": it.Metadata, "has_content": true})
		}
	}

	// One idempotency id per call (review E-79): every side's create carries
	// it, and a retried create carries it again.
	createID := randomHex(16)
	var started []*expRun
	for _, r := range runs {
		create := map[string]any{"id": createID, "name": name, "dataset_id": r.datasetID, "snapshot_version": r.snapshotVersion, "metadata": metadataOrEmpty(o.Metadata), "scorers": scorers}
		if len(r.itemIDs) > 0 {
			create["item_ids"] = r.itemIDs
		}
		resp := r.sd.call(ctx, "POST", "experiments", create, nil, nil, nil)
		if retryable(resp) {
			resp = r.sd.call(ctx, "POST", "experiments", create, nil, nil, nil)
		}
		body, err := okBody(resp, "experiment create", r.sd.name)
		if err == nil {
			r.runID = jsonText(body["id"])
			if v, ok := jsonInt(body["snapshot_version"]); ok && v != 0 {
				r.snapshotVersion = int(v)
			}
			if r.runID == "" {
				err = &ExperimentError{Msg: r.sd.name + ": experiment create answered no id"}
			}
		}
		if err == nil {
			r.items, err = readItems(ctx, r)
		}
		if err != nil {
			if skip(err) {
				res.Errors = append(res.Errors, strings.TrimPrefix(err.Error(), "superbased: "))
				res.SkippedSides = append(res.SkippedSides, r.sd.name)
				continue
			}
			return nil, err
		}
		res.Runs[r.sd.name] = r.runID
		started = append(started, r)
	}
	runs = started
	if len(runs) > 0 {
		items = runs[0].items
		runs[0].itemMap = map[int]string{}
		for n, it := range items {
			runs[0].itemMap[n] = jsonText(it["item_id"])
		}
		for _, r := range runs[1:] {
			r.itemMap = mapItems(items, r.items)
			if un := len(items) - len(r.itemMap); un > 0 {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: %d item(s) have no match there; their results go to %s only", r.sd.name, un, runs[0].sd.name))
			}
		}
		res.RunID = runs[0].runID
	}

	var runnable []int
	for n, it := range items {
		if hc, ok := it["has_content"].(bool); ok && !hc {
			continue
		}
		runnable = append(runnable, n)
	}
	res.SkippedNoContent = len(items) - len(runnable)
	var lock sync.Mutex
	done := make([]*ItemResult, len(items))
	pending := map[string][]map[string]any{}
	firstRun := ""
	if len(runs) > 0 {
		firstRun = runs[0].runID
	}
	capture, _ := contentRules()
	flushPending := func() {
		for _, r := range runs {
			lock.Lock()
			batch := pending[r.sd.name]
			pending[r.sd.name] = nil
			lock.Unlock()
			for start := 0; start < len(batch); start += resultsPerPost {
				chunk := batch[start:min(start+resultsPerPost, len(batch))]
				resp := r.sd.call(ctx, "POST", "experiment_results", map[string]any{"results": chunk}, nil, nil, map[string]string{"id": r.runID})
				lock.Lock()
				if !resp.ok() {
					res.FailedPosts += len(chunk)
					res.Errors = append(res.Errors, fmt.Sprintf("%s: posting %d result(s) failed: %s", r.sd.name, len(chunk), resp.describe()))
					if res.PlanRefusal == nil {
						res.PlanRefusal = resp.planRefusal()
					}
				} else if m := resp.obj(); m != nil {
					if rej, ok := m["rejected"].([]any); ok {
						for _, x := range rej {
							if rm, ok := x.(map[string]any); ok {
								res.FailedPosts++
								res.Errors = append(res.Errors, fmt.Sprintf("%s: result rejected: %s: %s", r.sd.name, jsonText(rm["error"]), jsonText(rm["message"])))
							}
						}
					}
				}
				lock.Unlock()
			}
		}
	}
	one := func(n int) {
		ir := runItem(ctx, o.Task, o.Evaluators, items[n], name, firstRun)
		done[n] = &ir
		for _, r := range runs {
			if id, ok := r.itemMap[n]; ok {
				row := resultRow(ctx, id, done[n], capture)
				lock.Lock()
				pending[r.sd.name] = append(pending[r.sd.name], row)
				lock.Unlock()
			}
		}
		flushPending()
	}
	workers := o.MaxConcurrency
	if workers <= 0 {
		workers = 4
	}
	if workers == 1 || len(runnable) <= 1 {
		for _, n := range runnable {
			one(n)
		}
	} else {
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for _, n := range runnable {
			wg.Add(1)
			sem <- struct{}{}
			go func(n int) {
				defer wg.Done()
				defer func() { <-sem }()
				one(n)
			}(n)
		}
		wg.Wait()
	}
	flushPending()
	for _, d := range done {
		if d != nil {
			res.Items = append(res.Items, *d)
		}
	}

	Flush(ctx) // the items' traces, before the run is read back
	for _, r := range runs {
		if resp := r.sd.call(ctx, "POST", "experiment_finish", map[string]any{}, nil, nil, map[string]string{"id": r.runID}); !resp.ok() {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: finish failed: %s", r.sd.name, resp.describe()))
			if res.PlanRefusal == nil {
				res.PlanRefusal = resp.planRefusal()
			}
		}
		got := r.sd.call(ctx, "GET", "experiment", nil, nil, nil, map[string]string{"id": r.runID})
		if m := got.obj(); got.ok() && m != nil {
			res.Server[r.sd.name] = m
		}
	}
	for _, e := range res.Errors {
		logf(slog.LevelWarn, "experiment %s: %s", name, e)
	}
	if o.FailUnder != nil && strict {
		if problems := gateProblems(res); len(problems) > 0 {
			for _, p := range problems {
				res.Errors = append(res.Errors, "gate: "+p)
			}
			return res, &ExperimentGateFailed{Result: res, FailUnder: *o.FailUnder, Reasons: problems}
		}
	}
	if o.FailUnder != nil && res.Scored() == 0 {
		msg := "no scores: no item was scored (no evaluator ran), so FailUnder was not applied (Strict false)"
		res.Errors = append(res.Errors, msg)
		logf(slog.LevelWarn, "experiment %s: %s", name, msg)
	}
	if gateFails(res, o.FailUnder, strict) {
		return res, &ExperimentGateFailed{Result: res, FailUnder: *o.FailUnder}
	}
	return res, nil
}

func metadataOrEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func runItem(ctx context.Context, task Task, evaluators []Evaluator, it map[string]any, runName, runID string) (res ItemResult) {
	res = ItemResult{ItemID: jsonText(it["item_id"]), Input: it["input"], Expected: it["expected"], Metadata: it["metadata"]}
	attrs := []attribute.KeyValue{}
	if runID != "" {
		attrs = append(attrs, attribute.String(keyExperimentRunID, runID))
	}
	if res.ItemID != "" {
		attrs = append(attrs, attribute.String(keyExperimentItemID, res.ItemID))
	}
	// A fresh root: every item is its own trace, with no request scope.
	base := baggage.ContextWithoutBaggage(context.WithValue(ctx, scopeKey{}, &scope{}))
	ictx, sp := tracer().Start(base, "experiment "+runName, trace.WithNewRoot(), trace.WithAttributes(append([]attribute.KeyValue{attribute.String(keySpanKind, KindChain)}, attrs...)...))
	if sc := sp.SpanContext(); sc.IsValid() {
		res.TraceID = sc.TraceID().String()
	}
	SetInput(sp, res.Input)
	out, err := callTask(ictx, task, Item{ID: res.ItemID, Input: res.Input, Expected: res.Expected, Metadata: res.Metadata})
	if err != nil {
		res.Error = clip(err.Error(), 500)
		sp.RecordError(err)
		sp.SetStatus(codes.Error, res.Error)
	} else {
		res.Output = out
		SetOutput(sp, out)
	}
	sp.End()
	if res.Error != "" {
		return res
	}
	in := EvalInput{Input: res.Input, Output: res.Output, Expected: res.Expected, Metadata: res.Metadata}
	for _, e := range evaluators {
		v, err := callEvaluator(ctx, e, in)
		if err != nil {
			res.EvaluatorErrors = append(res.EvaluatorErrors, clip(evaluatorName(e)+": "+err.Error(), 300))
			continue
		}
		res.Scores = append(res.Scores, normalizeEval(e, v)...)
	}
	return res
}

func callTask(ctx context.Context, task Task, it Item) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("panic: %v", r)
		}
	}()
	return task(ctx, it)
}

func callEvaluator(ctx context.Context, e Evaluator, in EvalInput) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("panic: %v", r)
		}
	}()
	return e.Evaluate(ctx, in)
}

func resultRow(ctx context.Context, itemID string, res *ItemResult, capture bool) map[string]any {
	row := map[string]any{"item_id": itemID}
	if res.TraceID != "" {
		row["trace_id"] = res.TraceID
	}
	if res.Error != "" {
		row["error"] = res.Error
	} else if capture && res.Output != nil {
		row["output"] = contentText(res.Output)
	}
	scores := []map[string]any{}
	tid := res.TraceID
	if tid == "" {
		tid = strings.Repeat("1", 32)
	}
	for _, s := range res.Scores {
		obj, serr := buildScore(ctx, scoreInput{name: s.Name, value: s.Value, traceID: tid, comment: s.Comment, source: SourceSDK, scorer: s.Name, scorerVersion: s.ScorerVersion})
		if serr != nil {
			res.EvaluatorErrors = append(res.EvaluatorErrors, s.Name+": "+serr.Error())
			continue
		}
		for _, k := range []string{"id", "trace_id", "span_id", "source"} {
			delete(obj, k)
		}
		scores = append(scores, obj)
	}
	row["scores"] = scores
	return row
}
