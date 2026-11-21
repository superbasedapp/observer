package superbased

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// DefaultAdmissionEndpoint is the local machine's admission check.
const DefaultAdmissionEndpoint = "http://127.0.0.1:8081/api/obs/admission/check"

// DefaultAdmitTimeout: the client waits longer than the server's judge budget
// (10 s). A server-advertised recommended timeout overrides it for later calls.
const DefaultAdmitTimeout = 12 * time.Second

// Client-side degraded reasons (Verdict.Degraded). A server may send its own
// values; those pass through unchanged.
const (
	DegradedUnavailable  = "admission-unavailable" // 403 / 404
	DegradedTimeout      = "client-timeout"
	DegradedTransport    = "client-transport"
	DegradedHTTPError    = "client-http-error"
	DegradedBadResponse  = "client-bad-response"
	DegradedAdmissionOff = "admission-off" // the org answered mode off (no policy)
)

var (
	timeoutHeaders = []string{"X-SBO-Recommended-Timeout-Ms", "X-Superbased-Admit-Timeout-Ms"}
	timeoutFields  = []string{"recommended_client_timeout_ms", "recommended_timeout_ms"}
)

// Verdict is the result of an Admit check. Allowed is what the app should
// honour; Degraded is empty for a clean decision.
type Verdict struct {
	Allowed         bool   `json:"allowed"`
	Decision        string `json:"decision"`
	Severity        string `json:"severity"`
	Criterion       string `json:"criterion"`
	Reason          string `json:"reason"`
	Mode            string `json:"mode"`
	JudgeUsed       bool   `json:"judge_used"`
	Degraded        string `json:"degraded"`
	EnforceDecision string `json:"enforce_decision"`
	LatencyMS       int64  `json:"latency_ms"`
	VerdictID       string `json:"verdict_id"`
	HTTPStatus      int    `json:"http_status"`
	Error           string `json:"error"`
}

func verdictFrom(d map[string]any) Verdict {
	v := Verdict{Allowed: true}
	if a, ok := d["allowed"]; ok {
		b, isBool := a.(bool)
		v.Allowed = isBool && b
	}
	v.Decision = jsonStr(d, "decision")
	if v.Decision == "" {
		v.Decision = "deny"
		if v.Allowed {
			v.Decision = "allow"
		}
	}
	v.Severity, v.Criterion, v.Reason = jsonStr(d, "severity"), jsonStr(d, "criterion"), jsonStr(d, "reason")
	v.Mode, v.Degraded, v.EnforceDecision = jsonStr(d, "mode"), jsonStr(d, "degraded"), jsonStr(d, "enforce_decision")
	v.JudgeUsed, _ = d["judge_used"].(bool)
	if n, ok := jsonFloat(d["latency_ms"]); ok {
		v.LatencyMS = int64(n)
	}
	id, ok := d["verdict_id"]
	if !ok {
		id = d["id"]
	}
	switch t := id.(type) {
	case string:
		v.VerdictID = t
	case json.Number:
		v.VerdictID = t.String()
	}
	return v
}

func degradedVerdict(cause string, failClosed bool, status int, errText string, started time.Time) Verdict {
	v := Verdict{Allowed: !failClosed, Decision: "allow", Degraded: cause, HTTPStatus: status, Error: clip(errText, 300), LatencyMS: time.Since(started).Milliseconds()}
	if failClosed {
		v.Decision, v.Reason = "deny", "admission check unavailable"
	}
	return v
}

// --- saying so when Admit could not decide (review E-39) ---------------------------

// degradedFixes: (cause, lowest status, highest status, what to fix, where).
// The first matching row wins; where is "machine" (the check went to a
// machine's admission path) or "" for any address. The other SDKs have the
// same table.
var degradedFixes = []struct {
	cause    string
	lo, hi   int
	fix      string
	machine  bool
	anyWhere bool
}{
	{DegradedUnavailable, 404, 404, "this machine has no admission check: update Observer (a current machine answers allow while no admission policy is set), or turn admission on", true, false},
	{DegradedHTTPError, 300, 399, "the address redirects, and admit() never follows a redirect (the key must not move hosts): use the final URL", false, true},
	{DegradedHTTPError, 401, 401, "the SDK key was refused: check APIKey / SUPERBASED_API_KEY, or sign in again", false, true},
	{DegradedUnavailable, 403, 403, "the key may not run admission checks, or admission is off for this app", false, true},
	{DegradedUnavailable, 404, 404, "no admission check at this address: point OrgURL / SUPERBASED_ORG_URL at the AI Apps gateway (not the dashboard), or turn admission on", false, true},
	{DegradedHTTPError, 429, 429, "the server is rate limiting admission checks", false, true},
	{DegradedHTTPError, 0, 999, "the admission server answered with an error", false, true},
	{DegradedTimeout, 0, 999, "no answer within the timeout: raise Timeout, or check the server", false, true},
	{DegradedTransport, 0, 999, "nothing answered at this address: check the URL and that Observer is running", false, true},
	{DegradedBadResponse, 0, 999, "the address did not answer like an admission check: check the URL", false, true},
	{DegradedAdmissionOff, 0, 999, "your organization has no admission policy for AI Apps (mode off): ask an admin to turn admission on, or use destination both so this machine's policy applies", false, true},
}

func isMachineAdmission(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.HasSuffix(strings.TrimRight(u.Path, "/"), admissionPath)
}

func degradedFix(cause string, status int, rawURL string) string {
	machine := isMachineAdmission(rawURL)
	for _, r := range degradedFixes {
		if r.cause == cause && r.lo <= status && status <= r.hi && (r.anyWhere || r.machine == machine) {
			return r.fix
		}
	}
	return ""
}

// where is scheme://host[:port]/path of a URL: no user info, no query.
func where(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "the admission address"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

type admitCounters struct {
	mu          sync.Mutex
	degraded    int64
	lastError   string
	lastErrorAt time.Time
	loggedAt    map[string]time.Time
}

func (a *admitCounters) reset() {
	a.mu.Lock()
	a.degraded, a.lastError, a.lastErrorAt, a.loggedAt = 0, "", time.Time{}, map[string]time.Time{}
	a.mu.Unlock()
}

var admitStats = &admitCounters{loggedAt: map[string]time.Time{}}

const degradedLogInterval = time.Minute

// noteDegraded counts a degraded verdict and warns once a minute per cause.
func noteDegraded(v Verdict, rawURL string) {
	detail := v.Error
	if v.HTTPStatus != 0 {
		detail = fmt.Sprintf("HTTP %d", v.HTTPStatus)
	} else if detail == "" {
		detail = v.Degraded
	}
	fix := degradedFix(v.Degraded, v.HTTPStatus, rawURL)
	outcome := "admitted (fail open)"
	if !v.Allowed {
		outcome = "denied (fail_closed)"
	}
	from := ""
	if rawURL != "" {
		from = " from " + where(rawURL)
	}
	msg := fmt.Sprintf("admit() got no decision%s (%s: %s); the message was %s", from, v.Degraded, detail, outcome)
	if fix != "" {
		msg += ". Fix: " + fix
	}
	key := fmt.Sprintf("%s:%d", v.Degraded, v.HTTPStatus)
	now := time.Now()
	admitStats.mu.Lock()
	admitStats.degraded++
	admitStats.lastError = clip(msg, 500)
	admitStats.lastErrorAt = now
	due := now.Sub(admitStats.loggedAt[key]) >= degradedLogInterval
	if due {
		admitStats.loggedAt[key] = now
	}
	admitStats.mu.Unlock()
	if due {
		logf(slog.LevelWarn, "%s", msg)
	}
}

// --- advertised timeout ------------------------------------------------------------

var (
	advertisedMu sync.Mutex
	advertised   = map[string]time.Duration{}
)

func resetAdvertised() {
	advertisedMu.Lock()
	advertised = map[string]time.Duration{}
	advertisedMu.Unlock()
}

func rememberTimeout(rawURL string, v any) {
	var ms float64
	switch t := v.(type) {
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err != nil {
			return
		}
		ms = f
	case nil, bool:
		return
	default:
		f, ok := jsonFloat(t)
		if !ok {
			return
		}
		ms = f
	}
	if ms < 100 || ms > 120000 {
		return
	}
	advertisedMu.Lock()
	advertised[rawURL] = time.Duration(ms * float64(time.Millisecond))
	advertisedMu.Unlock()
}

func advertisedTimeout(rawURL string) time.Duration {
	advertisedMu.Lock()
	defer advertisedMu.Unlock()
	return advertised[rawURL]
}

// --- service name ------------------------------------------------------------------

var serviceSeen atomic.Pointer[string]

// noteServiceName keeps the service.name of the resource the app's spans
// carry (the provider holding the SDK's spans), which Admit sends.
func noteServiceName(s sdktrace.ReadWriteSpan) {
	if serviceSeen.Load() != nil || s.Resource() == nil {
		return
	}
	if v, ok := s.Resource().Set().Value(attribute.Key(keyServiceName)); ok {
		name := strings.TrimSpace(v.AsString())
		if name != "" && !strings.HasPrefix(name, "unknown_service") {
			serviceSeen.Store(&name)
		}
	}
}

func admitServiceName() string {
	if p := serviceSeen.Load(); p != nil {
		return *p
	}
	if s := CurrentSettings(); s != nil {
		return s.ServiceName
	}
	return resolveServiceName("", osEnv)
}

// --- Admit -------------------------------------------------------------------------

// AdmitOptions are the options of Admit.
type AdmitOptions struct {
	// Tenant, User and Session: the argument, else the request scope
	// (PropagateAttributes), else Init's value.
	Tenant, User, Session string
	TraceID, RequestID    string
	// Endpoint is a full admission URL; OrgURL an organization gateway base
	// (+ /v1/sdk/admit). Both win over the destination plan.
	Endpoint, OrgURL string
	// APIKey is sent as Authorization: Bearer (an explicit key goes even to a
	// loopback endpoint).
	APIKey  string
	Headers map[string]string
	// Timeout defaults to the server-advertised recommended timeout once one
	// was seen, else 12 s.
	Timeout time.Duration
	// FailClosed denies when no decision could be obtained
	// (SUPERBASED_ADMISSION_FAIL_CLOSED); the default admits.
	FailClosed *bool
}

// where the admit URL came from decides whether a credential may ride along.
const (
	originOrg      = "org"
	originPlanOrg  = "plan-org" // the org chosen by Init's destination
	originExplicit = "explicit"
	originMachine  = "machine"
)

func resolveAdmitURL(endpoint, orgURL string, env envFunc) (string, string, string) {
	p := activePlan()
	initKey := ""
	if p != nil {
		initKey = p.key
	}
	if endpoint != "" {
		return endpoint, originExplicit, initKey
	}
	if orgURL != "" {
		return strings.TrimRight(orgURL, "/") + sdkAdmitPath, originOrg, initKey
	}
	if v := strings.TrimSpace(env.get("SUPERBASED_ADMISSION_ENDPOINT")); v != "" {
		return v, originExplicit, initKey
	}
	if p != nil && p.admitURL != "" {
		if p.onlineEnabled() && p.gatewayURL != "" && strings.HasPrefix(p.admitURL, p.gatewayURL) {
			return p.admitURL, originPlanOrg, initKey
		}
		return p.admitURL, originMachine, ""
	}
	if org := strings.TrimSpace(env.get("SUPERBASED_ORG_URL")); org != "" {
		return strings.TrimRight(org, "/") + sdkAdmitPath, originOrg, initKey
	}
	return DefaultAdmissionEndpoint, originMachine, ""
}

func machineAdmissionURL() string {
	p := activePlan()
	if p == nil {
		return DefaultAdmissionEndpoint
	}
	if p.machineAdmit != "" {
		return p.machineAdmit
	}
	return strings.TrimRight(p.nodeURL, "/") + admissionPath
}

// Admit checks an incoming user message against the app's admission policy
// BEFORE running the agent and returns an allow/flag/ask/deny verdict. It
// never fails: with no decision it admits (or denies under FailClosed), counts
// the verdict in Diagnostics.AdmissionDegraded and warns once a minute per
// cause with the fix.
//
// Address: Endpoint, else OrgURL + /v1/sdk/admit, else
// SUPERBASED_ADMISSION_ENDPOINT, else the destination plan of Init (the org
// gateway under a usable online or both, else this machine), else
// SUPERBASED_ORG_URL + /v1/sdk/admit, else the local machine. The credential
// rides only to an org address or a remote explicit endpoint; an explicit
// APIKey also goes to a loopback endpoint. Redirects are never followed. An org
// verdict with mode off is no decision: under destination both this machine
// is asked (without the key); otherwise the verdict is degraded admission-off.
func Admit(ctx context.Context, message string, o AdmitOptions) (v Verdict) {
	started := time.Now()
	// Resolve fail-closed before any other work, so the last-resort panic
	// handler below honours the option and the environment (review FR-S02).
	env := osEnv
	failClosed := false
	if o.FailClosed != nil {
		failClosed = *o.FailClosed
	} else {
		failClosed = !falseWords[strings.ToLower(strings.TrimSpace(env.get("SUPERBASED_ADMISSION_FAIL_CLOSED")))]
	}
	defer func() {
		if r := recover(); r != nil {
			v = degradedVerdict(DegradedBadResponse, failClosed, 0, fmt.Sprintf("panic: %v", r), started)
			noteDegraded(v, "")
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	rawURL, origin, initKey := resolveAdmitURL(o.Endpoint, o.OrgURL, env)

	scope := currentScope(ctx).public()
	base := CurrentSettings()
	pickID := func(arg, scopeName string, init func(*Settings) string) string {
		if arg != "" {
			return arg
		}
		if s, ok := scope[scopeName].(string); ok && s != "" {
			return s
		}
		if base != nil {
			return init(base)
		}
		return ""
	}
	traceID := o.TraceID
	if traceID == "" {
		traceID = CurrentTraceID(ctx)
	}
	payload, _ := marshalCompact(map[string]any{
		"text":       message,
		"tenant":     pickID(o.Tenant, "tenant", func(s *Settings) string { return s.Tenant }),
		"user":       pickID(o.User, "user", func(s *Settings) string { return s.User }),
		"session":    pickID(o.Session, "session_id", func(s *Settings) string { return s.SessionID }),
		"service":    admitServiceName(),
		"trace_id":   traceID,
		"request_id": o.RequestID,
	})
	v = admitPost(ctx, rawURL, origin, initKey, payload, o, env, failClosed, started)
	if (origin == originOrg || origin == originPlanOrg) && v.Degraded == "" && v.Mode == "off" {
		p := activePlan()
		if origin == originPlanOrg && p != nil && p.destination == DestinationBoth {
			// This machine's policy decides; the key never goes to it.
			mo := o
			mo.APIKey = ""
			mo.Headers = map[string]string{}
			for k, val := range o.Headers {
				if !strings.EqualFold(k, "authorization") {
					mo.Headers[k] = val
				}
			}
			v = admitPost(ctx, machineAdmissionURL(), originMachine, "", payload, mo, env, failClosed, started)
		} else {
			v = degradedVerdict(DegradedAdmissionOff, failClosed, v.HTTPStatus, "the organization answered mode off", started)
			noteDegraded(v, rawURL)
		}
	}
	stampVerdict(ctx, v)
	return v
}

func stampVerdict(ctx context.Context, v Verdict) {
	sp := trace.SpanFromContext(ctx)
	if !sp.IsRecording() {
		return
	}
	sp.SetAttributes(attribute.Bool(keyAdmissionAllowed, v.Allowed), attribute.String(keyAdmissionDecision, v.Decision))
	if v.VerdictID != "" {
		sp.SetAttributes(attribute.String(keyAdmissionVerdictID, v.VerdictID))
	}
	if v.Degraded != "" {
		sp.SetAttributes(attribute.String(keyAdmissionDegraded, v.Degraded))
	}
}

func admitPost(ctx context.Context, rawURL, origin, initKey string, payload []byte, o AdmitOptions, env envFunc, failClosed bool, started time.Time) Verdict {
	fail := func(cause string, status int, errText string) Verdict {
		v := degradedVerdict(cause, failClosed, status, errText, started)
		noteDegraded(v, rawURL)
		return v
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = advertisedTimeout(rawURL)
	}
	if timeout <= 0 {
		timeout = DefaultAdmitTimeout
	}
	req, err := http.NewRequestWithContext(ctx, "POST", rawURL, strings.NewReader(string(payload)))
	if err != nil {
		return fail(DegradedTransport, 0, err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	key := o.APIKey
	if key == "" && (origin == originOrg || origin == originPlanOrg || (origin == originExplicit && !isLoopbackURL(rawURL))) {
		key = initKey
		if key == "" {
			key = env.get("SUPERBASED_API_KEY")
		}
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for k, val := range o.Headers {
		req.Header.Set(k, val)
	}
	resp, err := clientFor(rawURL, timeout).Do(req)
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return fail(DegradedTimeout, 0, err.Error())
		}
		return fail(DegradedTransport, 0, err.Error())
	}
	defer resp.Body.Close()
	for _, h := range timeoutHeaders {
		if val := resp.Header.Get(h); val != "" {
			rememberTimeout(rawURL, val)
			break
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == 403 || resp.StatusCode == 404 {
			return fail(DegradedUnavailable, resp.StatusCode, fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
		return fail(DegradedHTTPError, resp.StatusCode, fmt.Sprintf("HTTP %d", resp.StatusCode))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fail(DegradedTransport, 0, err.Error())
	}
	data, ok := decodeJSON(raw).(map[string]any)
	if !ok {
		return fail(DegradedBadResponse, resp.StatusCode, "the response body is not a JSON object")
	}
	if _, isBool := data["allowed"].(bool); !isBool {
		return fail(DegradedBadResponse, resp.StatusCode, "response field 'allowed' is missing or not a boolean")
	}
	for _, f := range timeoutFields {
		if val, ok := data[f]; ok && val != nil {
			rememberTimeout(rawURL, val)
			break
		}
	}
	v := verdictFrom(data)
	v.HTTPStatus = resp.StatusCode
	return v
}
