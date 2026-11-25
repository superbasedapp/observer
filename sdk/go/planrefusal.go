package superbased

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The AI Apps gateway's plan refusal (sdk/contract/plan-refusal-cases.json).
// The org's gateway (OTLP /v1/traces and the SDK control API /v1/sdk/*)
// refuses ingest when the organization's plan does not include AI Apps
// (HTTP 403 plan_required) or this month's allowance is used up (HTTP 429
// planea_events_quota_exceeded or planea_bytes_quota_exceeded). The AI
// gateway's own plan refusals have the same shape (403 plan_required, 429
// aigw_requests_quota_exceeded; ParseGatewayRefusal carries them). Every such
// refusal carries UpgradeURL: where the organization's billing owner changes
// the plan.

// The gateway's plan refusal codes.
const (
	CodePlanRequired        = "plan_required"
	CodeEventsQuotaExceeded = "planea_events_quota_exceeded"
	CodeBytesQuotaExceeded  = "planea_bytes_quota_exceeded"
)

// The PlanRefusalError kinds.
const (
	PlanRefusalPlanRequired      = "plan_required"
	PlanRefusalAllowanceExceeded = "allowance_exceeded"
)

// Sentinels a *PlanRefusalError matches with errors.Is: ErrPlanRequired for
// a 403 plan_required, ErrAllowanceExceeded for a 429 over the plan's monthly
// allowance.
var (
	ErrPlanRequired      = errors.New("superbased: the organization's plan does not include AI Apps ingest")
	ErrAllowanceExceeded = errors.New("superbased: the organization's monthly AI Apps allowance is used up")
)

// planRefusalCodes: code -> the status it rides on and the kind. One row per
// code.
var planRefusalCodes = map[string]struct {
	status int
	kind   string
}{
	CodePlanRequired:           {403, PlanRefusalPlanRequired},
	CodeEventsQuotaExceeded:    {429, PlanRefusalAllowanceExceeded},
	CodeBytesQuotaExceeded:     {429, PlanRefusalAllowanceExceeded},
	CodeAIGatewayQuotaExceeded: {429, PlanRefusalAllowanceExceeded},
}

// PlanAllowance is a plan's allowance: AI Apps events and GB a month, and
// the AI gateway's requests a month and concurrent calls. A nil axis has no
// cap (or the refusal did not name it).
type PlanAllowance struct {
	EventsMonthly   *int64 `json:"events_monthly,omitempty"`
	GBMonthly       *int64 `json:"gb_monthly,omitempty"`
	RequestsMonthly *int64 `json:"requests_monthly,omitempty"`
	Concurrency     *int64 `json:"concurrency,omitempty"`
}

// PlanInfo is a catalog plan: the plan in force, or one on offer (with its
// Allowance).
type PlanInfo struct {
	Name      string         `json:"name"`
	Version   int            `json:"version"`
	Label     string         `json:"label"`
	Allowance *PlanAllowance `json:"allowance,omitempty"`
}

// PlanQuota is the monthly quota a 429 refusal is about. ResetsAt is RFC 3339.
type PlanQuota struct {
	Quota    string `json:"quota"`
	Unit     string `json:"unit"`
	Used     int64  `json:"used"`
	Limit    int64  `json:"limit"`
	ResetsAt string `json:"resets_at"`
}

// PlanRefusalError is the organization's plan refusing AI Apps ingest. Kind
// is PlanRefusalPlanRequired (HTTP 403) or PlanRefusalAllowanceExceeded (HTTP
// 429); Code the gateway's error code; Message its explanation; UpgradeURL
// where the organization's billing owner changes the plan. Capability names
// what was refused; Plan is the plan in force, Allowance the org's monthly
// allowance and Plans the plans that include more (each may be absent). A
// 429 also carries Quota and RetryAfter (the Retry-After header).
//
// It matches ErrPlanRequired or ErrAllowanceExceeded with errors.Is. The
// calls that return an error wrap it (GetPrompt's error also wraps
// ErrPromptFetch; GetDataset's and RunExperiment's is still an
// *ExperimentError), so errors.As finds it; the calls that never fail carry
// it (ScoreResult.PlanRefusal, Verdict.PlanRefusal,
// ExperimentResult.PlanRefusal), and GetDiagnostics().PlanRefusal keeps the
// last one, export included.
type PlanRefusalError struct {
	Kind       string         `json:"kind"`
	Code       string         `json:"code"`
	Status     int            `json:"status"`
	Message    string         `json:"message"`
	UpgradeURL string         `json:"upgrade_url"`
	Capability string         `json:"capability"`
	Plan       *PlanInfo      `json:"plan"`
	Allowance  *PlanAllowance `json:"allowance"`
	Plans      []PlanInfo     `json:"plans"`
	Quota      *PlanQuota     `json:"quota"`
	// RetryAfter is the Retry-After header (0 when none; nanoseconds in JSON).
	RetryAfter time.Duration `json:"retry_after"`
}

// Error is the gateway's message (it names the plan and how to change it).
func (e *PlanRefusalError) Error() string { return e.Message }

// Is matches ErrPlanRequired or ErrAllowanceExceeded by Kind.
func (e *PlanRefusalError) Is(target error) bool {
	switch target {
	case ErrPlanRequired:
		return e.Kind == PlanRefusalPlanRequired
	case ErrAllowanceExceeded:
		return e.Kind == PlanRefusalAllowanceExceeded
	}
	return false
}

// ParsePlanRefusal is the plan refusal in one HTTP answer, or nil: a 403
// plan_required, or a 429 planea_events_quota_exceeded /
// planea_bytes_quota_exceeded / aigw_requests_quota_exceeded, whose JSON body
// carries a non-empty upgrade_url. Anything else, malformed input included, is nil. header may
// be nil (no Retry-After). It never panics.
func ParsePlanRefusal(status int, body []byte, header http.Header) (out *PlanRefusalError) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	if status != 403 && status != 429 {
		return nil
	}
	obj, ok := decodeJSON(bytes.TrimSpace(body)).(map[string]any)
	if !ok {
		return nil
	}
	code := jsonStr(obj, "error")
	row, known := planRefusalCodes[code]
	upgrade := strings.TrimSpace(jsonStr(obj, "upgrade_url"))
	if !known || row.status != status || upgrade == "" {
		return nil
	}
	e := &PlanRefusalError{
		Kind:       row.kind,
		Code:       code,
		Status:     status,
		Message:    strings.TrimSpace(jsonStr(obj, "message")),
		UpgradeURL: upgrade,
		Capability: jsonStr(obj, "capability"),
		Plan:       planInfoFrom(obj["plan"], false),
		Allowance:  planAllowanceFrom(obj["allowance"]),
		Plans:      []PlanInfo{},
		Quota:      planQuotaFrom(obj["quota"]),
		RetryAfter: retryAfterOf(header),
	}
	if e.Message == "" {
		e.Message = defaultPlanRefusalMessage(code, upgrade)
	}
	if list, ok := obj["plans"].([]any); ok {
		for _, x := range list {
			if p := planInfoFrom(x, true); p != nil {
				e.Plans = append(e.Plans, *p)
			}
		}
	}
	return e
}

func defaultPlanRefusalMessage(code, upgradeURL string) string {
	if code == CodeAIGatewayQuotaExceeded {
		return "AI gateway calls were refused by the organization's plan (" + code + "); its billing owner can change the plan at " + upgradeURL
	}
	return "AI Apps ingest was refused by the organization's plan (" + code + "); its billing owner can change the plan at " + upgradeURL
}

// planInt reads an integer (never a bool, never a fraction).
func planInt(v any) (int64, bool) {
	if _, isBool := v.(bool); isBool {
		return 0, false
	}
	return jsonInt(v)
}

func planAllowanceFrom(v any) *PlanAllowance {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	a := &PlanAllowance{}
	if n, ok := planInt(m["events_monthly"]); ok {
		a.EventsMonthly = &n
	}
	if n, ok := planInt(m["gb_monthly"]); ok {
		a.GBMonthly = &n
	}
	if n, ok := planInt(m["requests_monthly"]); ok {
		a.RequestsMonthly = &n
	}
	if n, ok := planInt(m["concurrency"]); ok {
		a.Concurrency = &n
	}
	return a
}

func planInfoFrom(v any, withAllowance bool) *PlanInfo {
	m, ok := v.(map[string]any)
	if !ok || jsonStr(m, "name") == "" {
		return nil
	}
	p := &PlanInfo{Name: jsonStr(m, "name"), Label: jsonStr(m, "label")}
	if n, ok := planInt(m["version"]); ok {
		p.Version = int(n)
	}
	if withAllowance {
		p.Allowance = planAllowanceFrom(m["allowance"])
	}
	return p
}

func planQuotaFrom(v any) *PlanQuota {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	q := &PlanQuota{Quota: jsonStr(m, "quota"), Unit: jsonStr(m, "unit"), ResetsAt: jsonStr(m, "resets_at")}
	q.Used, _ = planInt(m["used"])
	q.Limit, _ = planInt(m["limit"])
	return q
}

// retryAfterOf is the Retry-After header in integer seconds (0 otherwise).
func retryAfterOf(h http.Header) time.Duration {
	if h == nil {
		return 0
	}
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" || strings.Trim(v, "0123456789") != "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n > int64(1<<62)/int64(time.Second) {
		return 0
	}
	return time.Duration(n) * time.Second
}

// planRefusal is the org's plan refusal in a control call's answer, or nil.
func (r *response) planRefusal() *PlanRefusalError {
	if r.status != 403 && r.status != 429 {
		return nil
	}
	return ParsePlanRefusal(r.status, r.raw, r.headers)
}

// withPlanRefusal is err (its text and its chain) that also unwraps to the
// plan refusal: errors.Is keeps matching err's sentinels, and errors.As
// finds the *PlanRefusalError.
type withPlanRefusal struct {
	err     error
	refusal *PlanRefusalError
}

func (w *withPlanRefusal) Error() string   { return w.err.Error() }
func (w *withPlanRefusal) Unwrap() []error { return []error{w.err, w.refusal} }

// --- the OTLP exporter's error ----------------------------------------------------

// exportStatusRe finds the status otlptracehttp writes before a failed
// export's body ("...: 403 Forbidden (body: {...})"). A retried failure
// (429, 502, 503, 504) names none.
var exportStatusRe = regexp.MustCompile(`\b([1-5][0-9][0-9]) [^():]*\($`)

// planRefusalInExportError reads the plan refusal in a failed OTLP export's
// error: otlptracehttp puts the answer's body in its error text
// ("body: {...}") but keeps neither the headers nor, for a retried status,
// the status itself; a quota code is then read as the 429 it rides on.
func planRefusalInExportError(err error) *PlanRefusalError {
	if err == nil {
		return nil
	}
	text := err.Error()
	i := strings.Index(text, "body: ")
	if i < 0 {
		return nil
	}
	var raw json.RawMessage
	if json.NewDecoder(strings.NewReader(text[i+len("body: "):])).Decode(&raw) != nil {
		return nil
	}
	status := 0
	if m := exportStatusRe.FindStringSubmatch(text[:i]); m != nil {
		status, _ = strconv.Atoi(m[1])
	} else if obj, ok := decodeJSON(raw).(map[string]any); ok && strings.Contains(text[:i], "retry-able") {
		if row, known := planRefusalCodes[jsonStr(obj, "error")]; known && row.status == 429 {
			status = 429
		}
	}
	return ParsePlanRefusal(status, raw, nil)
}

// --- the last refusal, for Diagnostics ---------------------------------------------

const planRefusalLogInterval = time.Minute

var lastPlanRefusal struct {
	mu       sync.Mutex
	refusal  *PlanRefusalError
	at       time.Time
	loggedAt time.Time
}

// notePlanRefusal keeps r as the last refusal (Diagnostics.PlanRefusal). With
// logAs (what was refused, e.g. "trace export") it writes ONE warning line,
// at most once a minute: the message and the upgrade URL. True when it logged.
func notePlanRefusal(r *PlanRefusalError, logAs string) bool {
	now := time.Now()
	lastPlanRefusal.mu.Lock()
	lastPlanRefusal.refusal, lastPlanRefusal.at = r, now
	due := logAs != "" && now.Sub(lastPlanRefusal.loggedAt) >= planRefusalLogInterval
	if due {
		lastPlanRefusal.loggedAt = now
	}
	lastPlanRefusal.mu.Unlock()
	if due {
		logf(slog.LevelWarn, "%s refused by the organization's plan: %s (upgrade: %s)", logAs, strings.Join(strings.Fields(r.Message), " "), r.UpgradeURL)
	}
	return due
}

// planRefusalSnapshot is a copy of the last refusal and when it was seen.
func planRefusalSnapshot() (*PlanRefusalError, time.Time) {
	lastPlanRefusal.mu.Lock()
	defer lastPlanRefusal.mu.Unlock()
	if lastPlanRefusal.refusal == nil {
		return nil, time.Time{}
	}
	c := *lastPlanRefusal.refusal
	c.Plans = append([]PlanInfo(nil), c.Plans...)
	return &c, lastPlanRefusal.at
}

func resetPlanRefusal() {
	lastPlanRefusal.mu.Lock()
	lastPlanRefusal.refusal, lastPlanRefusal.at, lastPlanRefusal.loggedAt = nil, time.Time{}, time.Time{}
	lastPlanRefusal.mu.Unlock()
}
