package superbased

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Score sources and kinds (contract scores.md section 1).
const (
	SourceSDK           = "sdk"
	SourceFeedback      = "feedback"
	DefaultFeedbackName = "user_feedback"
)

var (
	scoreNameRe  = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)
	scoreIDRe    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	traceIDRe    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	spanIDRe     = regexp.MustCompile(`^[0-9a-f]{16}$`)
	scoreKinds   = map[string]bool{"numeric": true, "boolean": true, "categorical": true}
	zeroTraceID  = strings.Repeat("0", 32)
	zeroSpanID   = strings.Repeat("0", 16)
	maxScoreText = 120
)

// DestinationResult is one destination's answer to a score write.
type DestinationResult struct {
	OK     bool   `json:"ok"`
	Status int    `json:"status"`
	ID     string `json:"id"`
	Error  string `json:"error"`
}

// ScoreResult is the outcome of one score write. OK is true only when every
// destination the call went to accepted it (no destination at all is not OK).
type ScoreResult struct {
	OK           bool                         `json:"ok"`
	ID           string                       `json:"id"`        // the first sc_… id returned
	ClientID     string                       `json:"client_id"` // the idempotency id sent
	Destinations map[string]DestinationResult `json:"destinations"`
	Errors       []string                     `json:"errors"`
}

// ScoreError is a score the rules refuse; Code is the contract's error code.
type ScoreError struct {
	Code    string
	Message string
}

func (e *ScoreError) Error() string { return e.Code + ": " + e.Message }

// ScoreOptions are Score's options.
type ScoreOptions struct {
	// TraceID defaults to the current trace; with neither TraceID nor SpanID
	// the score is trace-level. Pass SpanID: CurrentSpanID(ctx) to score the span.
	TraceID, SpanID string
	Comment         string
	// Kind (numeric, boolean, categorical) is inferred from the value; a
	// disagreeing Kind is refused.
	Kind                  string
	Scorer, ScorerVersion string
	RunID                 string
	// ScoreID is the idempotency id (sdk_<32 hex> by default).
	ScoreID   string
	Timestamp string
}

// FeedbackOptions are Feedback's options.
type FeedbackOptions struct {
	TraceID, SpanID string
	Comment         string
	Name            string // default user_feedback
	ScoreID         string
	Timestamp       string
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func scoreKindOf(v any) (string, any, *ScoreError) {
	switch t := v.(type) {
	case bool:
		return "boolean", t, nil
	case string:
		return "categorical", t, nil
	case nil:
		return "", nil, &ScoreError{"invalid_value", "value must be a number, a bool or a string, got nil"}
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "numeric", rv.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "numeric", rv.Uint(), nil
	case reflect.Float32, reflect.Float64:
		return "numeric", rv.Float(), nil
	}
	if f, ok := jsonFloat(v); ok {
		return "numeric", f, nil
	}
	return "", nil, &ScoreError{"invalid_value", fmt.Sprintf("value must be a number, a bool or a string, got %T", v)}
}

type scoreInput struct {
	name, kind, source, comment, scorer, scorerVersion, runID, scoreID, timestamp, traceID, spanID string
	value                                                                                          any
	useCurrentTrace                                                                                bool
}

// buildScore is the validated wire score object (contract scores.md section 1).
func buildScore(ctx context.Context, in scoreInput) (map[string]any, *ScoreError) {
	n := strings.ToLower(strings.TrimSpace(in.name))
	if !scoreNameRe.MatchString(n) {
		return nil, &ScoreError{"invalid_name", fmt.Sprintf("name %q must be 1-64 chars of a-z 0-9 _ . -", in.name)}
	}
	inferred, value, serr := scoreKindOf(in.value)
	if serr != nil {
		return nil, serr
	}
	if in.kind != "" && in.kind != inferred {
		if !scoreKinds[in.kind] {
			return nil, &ScoreError{"kind_mismatch", fmt.Sprintf("kind %q is not numeric, boolean or categorical", in.kind)}
		}
		return nil, &ScoreError{"kind_mismatch", fmt.Sprintf("kind %s does not match a %T value", in.kind, in.value)}
	}
	if f, ok := value.(float64); ok && (math.IsNaN(f) || math.IsInf(f, 0)) {
		return nil, &ScoreError{"invalid_value", fmt.Sprintf("value %v is not a finite number", f)}
	}
	if inferred == "categorical" {
		s := strings.TrimSpace(value.(string))
		if s == "" || len(s) > maxScoreText || strings.ContainsAny(s, "\r\n") {
			return nil, &ScoreError{"invalid_value", fmt.Sprintf("a categorical value must be 1-%d bytes on one line", maxScoreText)}
		}
		value = s
	}
	tid := in.traceID
	if tid == "" && in.useCurrentTrace {
		tid = CurrentTraceID(ctx)
	}
	tid = strings.ToLower(strings.TrimSpace(tid))
	if tid == "" {
		return nil, &ScoreError{"invalid_trace_id", "no TraceID given and no current span"}
	}
	if !traceIDRe.MatchString(tid) || tid == zeroTraceID {
		return nil, &ScoreError{"invalid_trace_id", fmt.Sprintf("trace id %q must be 32 hex characters, not all zero", in.traceID)}
	}
	sid := strings.ToLower(strings.TrimSpace(in.spanID))
	if sid != "" && (!spanIDRe.MatchString(sid) || sid == zeroSpanID) {
		return nil, &ScoreError{"invalid_span_id", fmt.Sprintf("span id %q must be 16 hex characters", in.spanID)}
	}
	if len(in.comment) > 2000 {
		return nil, &ScoreError{"comment_too_long", "comment is over 2000 bytes"}
	}
	cid := in.scoreID
	if cid == "" {
		cid = "sdk_" + randomHex(16)
	}
	if !scoreIDRe.MatchString(cid) {
		return nil, &ScoreError{"invalid_id", fmt.Sprintf("score id %q must be 1-128 chars of A-Z a-z 0-9 _ . : -", in.scoreID)}
	}
	if in.source != SourceSDK && in.source != SourceFeedback {
		return nil, &ScoreError{"invalid_source", fmt.Sprintf("source %q must be sdk or feedback", in.source)}
	}
	out := map[string]any{"id": cid, "trace_id": tid, "name": n, "value": value, "kind": inferred, "source": in.source}
	if sid != "" {
		out["span_id"] = sid
	}
	if in.comment != "" {
		out["comment"] = in.comment
	}
	if in.scorer != "" {
		if len(in.scorer) > 64 || len(in.scorerVersion) > 32 {
			return nil, &ScoreError{"bad_request", "scorer name is 1-64 chars and version 1-32"}
		}
		ver := in.scorerVersion
		if ver == "" {
			ver = "1"
		}
		out["scorer"] = map[string]any{"name": in.scorer, "version": ver}
	}
	if in.runID != "" {
		out["run_id"] = in.runID
	}
	if in.timestamp != "" {
		out["timestamp"] = in.timestamp
	}
	return out, nil
}

// resultOK: every destination the score went to accepted it; none is not ok.
func resultOK(r *ScoreResult) bool {
	if len(r.Destinations) == 0 {
		return false
	}
	for _, d := range r.Destinations {
		if !d.OK {
			return false
		}
	}
	return true
}

// retryable: no answer, 429 or a 5xx is worth one more try.
func retryable(r *response) bool { return r.status == 0 || r.status == 429 || r.status >= 500 }

var (
	scoreLogMu sync.Mutex
	scoreLogAt time.Time
)

func logScoreFailure(r *ScoreResult) {
	scoreLogMu.Lock()
	now := time.Now()
	due := now.Sub(scoreLogAt) >= time.Minute
	if due {
		scoreLogAt = now
	}
	scoreLogMu.Unlock()
	if due {
		msg := strings.Join(r.Errors, "; ")
		if msg == "" {
			msg = "unknown"
		}
		logf(slog.LevelWarn, "a score was not stored: %s", msg)
	}
}

// postScores writes built score objects to every destination (one request per
// destination; with both the gateway first, then the machine).
func postScores(ctx context.Context, objs []map[string]any) []*ScoreResult {
	results := make([]*ScoreResult, len(objs))
	for i, o := range objs {
		results[i] = &ScoreResult{ClientID: o["id"].(string), Destinations: map[string]DestinationResult{}, Errors: []string{}}
	}
	var body any = map[string]any{"scores": objs}
	if len(objs) == 1 {
		body = objs[0]
	}
	targets := sides(nil)
	if len(targets) == 0 {
		reason := unavailableReason(nil)
		for _, r := range results {
			r.Destinations[DestinationOnline] = DestinationResult{Error: reason}
			r.Errors = append(r.Errors, "online: "+reason)
		}
	}
	for _, sd := range targets {
		resp := sd.call(ctx, "POST", "scores", body, nil, nil, nil)
		if retryable(resp) {
			// Once, with the same ids: a repeat is a no-op on the server.
			resp = sd.call(ctx, "POST", "scores", body, nil, nil, nil)
		}
		accepted, rejected := map[int64]string{}, map[int64]string{}
		if m := resp.obj(); m != nil {
			if arr, ok := m["accepted"].([]any); ok {
				for _, a := range arr {
					if am, ok := a.(map[string]any); ok {
						if idx, ok := jsonInt(am["index"]); ok {
							accepted[idx] = jsonText(am["id"])
						}
					}
				}
			}
			if arr, ok := m["rejected"].([]any); ok {
				for _, a := range arr {
					if am, ok := a.(map[string]any); ok {
						if idx, ok := jsonInt(am["index"]); ok {
							e := jsonStr(am, "error")
							if e == "" {
								e = "rejected"
							}
							rejected[idx] = strings.Trim(e+": "+jsonStr(am, "message"), ": ")
						}
					}
				}
			}
		}
		for i, r := range results {
			if id, ok := accepted[int64(i)]; ok && (resp.status == 200 || resp.status == 201) {
				r.Destinations[sd.name] = DestinationResult{OK: true, Status: resp.status, ID: id}
				if r.ID == "" {
					r.ID = id
				}
				continue
			}
			e, ok := rejected[int64(i)]
			if !ok {
				e = resp.describe()
			}
			r.Destinations[sd.name] = DestinationResult{Status: resp.status, Error: e}
			r.Errors = append(r.Errors, sd.name+": "+e)
		}
	}
	for _, r := range results {
		r.OK = resultOK(r)
		if !r.OK {
			logScoreFailure(r)
		}
	}
	return results
}

func writeScore(ctx context.Context, in scoreInput) ScoreResult {
	if ctx == nil {
		ctx = context.Background()
	}
	obj, serr := buildScore(ctx, in)
	if serr != nil {
		r := &ScoreResult{Destinations: map[string]DestinationResult{}, Errors: []string{serr.Error()}}
		logScoreFailure(r)
		return *r
	}
	return *postScores(ctx, []map[string]any{obj})[0]
}

// Score records a score (source sdk) on a trace or span: value is a number
// (numeric), a bool (boolean) or a short string (categorical). It is written
// to the destination(s) chosen at Init and never fails: check
// ScoreResult.OK and Errors. A write that gets no answer, a 429 or a 5xx is
// retried once with the same id.
func Score(ctx context.Context, name string, value any, o ScoreOptions) ScoreResult {
	return writeScore(ctx, scoreInput{
		name: name, value: value, traceID: o.TraceID, spanID: o.SpanID, comment: o.Comment, kind: o.Kind,
		source: SourceSDK, scorer: o.Scorer, scorerVersion: o.ScorerVersion, runID: o.RunID,
		scoreID: o.ScoreID, timestamp: o.Timestamp, useCurrentTrace: true,
	})
}

// Feedback records an end user's feedback (source feedback): thumbs as a
// bool, stars as a number, or a short label. Every call is its own row.
func Feedback(ctx context.Context, value any, o FeedbackOptions) ScoreResult {
	name := o.Name
	if name == "" {
		name = DefaultFeedbackName
	}
	return writeScore(ctx, scoreInput{
		name: name, value: value, traceID: o.TraceID, spanID: o.SpanID, comment: o.Comment,
		source: SourceFeedback, scoreID: o.ScoreID, timestamp: o.Timestamp, useCurrentTrace: true,
	})
}
