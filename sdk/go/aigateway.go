package superbased

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// AI gateway helpers (hosted AI gateway arc L-172, lane L8; the shared cases
// are sdk/contract/ai-gateway-cases.json). The AI gateway is the proxy an
// app's model calls go through on their way to the provider: it prices each
// call exactly, holds the app's budgets, and applies the organization's model,
// egress and admission rules. It runs in three places with one client shape:
//
//   - the organization's address, https://<org host>/ai/<upstream> (hosted,
//     or a self-hosted server with its path lane);
//   - any address you name (a self-hosted gateway on its own listener);
//   - this machine's app lane, http://127.0.0.1:8820/up/<lane>.
//
// GatewayBaseURL resolves which one applies; GatewayEndpoint.HTTPClient is
// the http.Client to give the model SDK; ParseGatewayRefusal reads a refusal.

// The client families the helpers build a base URL for (seam S4's
// upstreams[].client). Each client adds its own API path after the base.
const (
	// GatewayProviderOpenAI is the OpenAI client and every OpenAI-compatible
	// one (OpenRouter included): the base URL ends in /v1.
	GatewayProviderOpenAI = "openai"
	// GatewayProviderAnthropic is the Anthropic client: the base URL is the
	// gateway address as it is (the client adds /v1/messages).
	GatewayProviderAnthropic = "anthropic"
	// GatewayProviderAzureOpenAI is the Azure OpenAI client: the base URL is
	// its azure_endpoint (the deployment path follows). It has no default
	// upstream.
	GatewayProviderAzureOpenAI = "azure_openai"
)

// The AI gateway's environment and headers.
const (
	// EnvAIGatewayURL names the gateway's address for the client, without
	// the provider's API path (for example https://ai.example.com).
	EnvAIGatewayURL = "SUPERBASED_AI_GATEWAY_URL"
	// EnvAIGatewayKey is the AI gateway key (sbo-vk-...) GatewayKey reads.
	EnvAIGatewayKey = "SUPERBASED_AI_GATEWAY_KEY"
	// HeaderUpstream selects the upstream on a gateway without a path lane.
	HeaderUpstream = "X-SBO-Upstream"
	// HeaderTraceparent is the W3C trace context header the helpers send.
	HeaderTraceparent = "traceparent"
)

// Where a gateway base URL came from (GatewayEndpoint.Source).
const (
	GatewaySourceArgument = "argument"
	GatewaySourceEnv      = "env"
	GatewaySourceOrg      = "org"
	GatewaySourceMachine  = "machine"
)

// Why no gateway base URL could be resolved (GatewayAddressError.Problem).
const (
	GatewayProblemUnknownProvider  = "unknown_provider"
	GatewayProblemBadUpstream      = "bad_upstream"
	GatewayProblemUpstreamRequired = "upstream_required"
	GatewayProblemBadURL           = "bad_url"
	GatewayProblemNotConfigured    = "not_configured"
	// GatewayProblemNoKey: the endpoint is a remote gateway and no AI
	// gateway key is set (GatewayEndpoint.APIKey), so the provider's own key
	// would be sent there.
	GatewayProblemNoKey = "no_key"
)

// aiPathLane is the organization's AI gateway path lane (S6 path_prefix).
const aiPathLane = "/ai"

// gatewayProviders: client family -> the path its base URL ends in and the
// upstream id it uses when none is named. One row per family.
var gatewayProviders = map[string]struct{ suffix, upstream string }{
	GatewayProviderOpenAI:      {"/v1", "openai"},
	GatewayProviderAnthropic:   {"", "anthropic"},
	GatewayProviderAzureOpenAI: {"", ""},
}

// upstreamIDRe is a pooled upstream id (plan section 3.4); v1 and v1beta are
// reserved because they would read as provider paths.
var upstreamIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

var reservedUpstreamIDs = map[string]bool{"v1": true, "v1beta": true}

// ErrGatewayNotConfigured matches every *GatewayAddressError (errors.Is).
var ErrGatewayNotConfigured = errors.New("superbased: no usable AI gateway address")

// GatewayAddressError is why GatewayBaseURL resolved no address. Problem is
// one of the GatewayProblem* values.
type GatewayAddressError struct {
	Problem string
	Message string
}

func (e *GatewayAddressError) Error() string { return "superbased: " + e.Message }

// Is matches ErrGatewayNotConfigured.
func (e *GatewayAddressError) Is(target error) bool { return target == ErrGatewayNotConfigured }

// GatewayEndpoint is where a model client sends its calls.
type GatewayEndpoint struct {
	// BaseURL is the value of the client's base URL option.
	BaseURL string
	// Source is where it came from: argument, env, org or machine.
	Source string
	// Upstream is the upstream id the call is for ("" when the address
	// names none and the gateway picks its only enabled upstream).
	Upstream string
	// UpstreamHeader is the X-SBO-Upstream value the client must send: the
	// upstream you named with an explicit or environment address, which
	// carries none in its path. "" otherwise.
	UpstreamHeader string
}

// GatewayOptions are GatewayBaseURL's optional inputs.
type GatewayOptions struct {
	// Upstream is the upstream id (default: the provider's, openai or
	// anthropic).
	Upstream string
	// URL is the gateway's address for the client, without the provider's
	// API path. It wins over everything else.
	URL string
}

// gatewayInputs are the pure resolver's inputs; local loads the machine's
// discovery answer's local object only when it is needed.
type gatewayInputs struct {
	provider    string
	upstream    string
	url         string
	env         string
	destination string
	orgURL      string
	local       func() any
}

// gatewayURLProblem is "" when raw is a usable gateway address: http(s), a
// host, no user info, query or fragment, plain http only to a loopback host
// (the AI gateway key travels with every call).
func gatewayURLProblem(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Sprintf("%q is not a URL", raw)
	}
	switch {
	case (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "":
		return fmt.Sprintf("%q is not an http(s) address with a host", raw)
	case u.User != nil:
		return fmt.Sprintf("%q carries a user name or password", raw)
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return fmt.Sprintf("%q carries a query or fragment", raw)
	case u.Scheme == "http" && !isLoopbackURL(raw):
		return fmt.Sprintf("%q is plain http to a remote host", raw)
	}
	return ""
}

// withSuffix is base (its trailing slashes dropped) plus suffix, unless base
// already ends in it.
func withSuffix(base, suffix string) string {
	base = strings.TrimRight(base, "/")
	if suffix == "" || strings.HasSuffix(base, suffix) {
		return base
	}
	return base + suffix
}

// machineLane is the base URL of the lane named upstream in the discovery
// answer's local.app_lanes ("" when none is usable).
func machineLane(local any, upstream string) string {
	m, _ := local.(map[string]any)
	lanes, _ := m["app_lanes"].([]any)
	for _, l := range lanes {
		lane, ok := l.(map[string]any)
		if !ok {
			continue
		}
		id, _ := lane["id"].(string)
		base, _ := lane["base_url"].(string)
		if id != upstream || base == "" || gatewayURLProblem(base) != "" || !isLoopbackURL(base) {
			continue
		}
		return strings.TrimRight(base, "/")
	}
	return ""
}

// resolveGatewayEndpoint is the pure resolver (contract base_url cases): the
// endpoint, or ("", problem, message).
func resolveGatewayEndpoint(in gatewayInputs) (GatewayEndpoint, string, string) {
	provider := strings.ToLower(strings.TrimSpace(in.provider))
	row, known := gatewayProviders[provider]
	if !known {
		return GatewayEndpoint{}, GatewayProblemUnknownProvider,
			fmt.Sprintf("the AI gateway helpers know the clients openai, anthropic and azure_openai, not %q", in.provider)
	}
	named := strings.TrimSpace(in.upstream)
	if named != "" && (!upstreamIDRe.MatchString(named) || reservedUpstreamIDs[named]) {
		return GatewayEndpoint{}, GatewayProblemBadUpstream,
			fmt.Sprintf("upstream %q is not an upstream id (lower-case letters, digits and -, at most 32, not v1 or v1beta)", named)
	}
	upstream := named
	if upstream == "" {
		upstream = row.upstream
	}
	for _, c := range []struct{ value, source, origin string }{
		{in.url, GatewaySourceArgument, "the AI gateway URL"},
		{in.env, GatewaySourceEnv, EnvAIGatewayURL},
	} {
		v := strings.TrimSpace(c.value)
		if v == "" {
			continue
		}
		if p := gatewayURLProblem(v); p != "" {
			return GatewayEndpoint{}, GatewayProblemBadURL, fmt.Sprintf("%s is not usable: %s", c.origin, p)
		}
		return GatewayEndpoint{BaseURL: withSuffix(v, row.suffix), Source: c.source, Upstream: named, UpstreamHeader: named}, "", ""
	}
	notConfigured := fmt.Sprintf("no AI gateway address for %s: pass the URL, set %s, use destination online with the organization's address (SUPERBASED_ORG_URL or `observer sdk sign-in`), or add an app lane on this machine (`observer apps lane add`)", provider, EnvAIGatewayURL)
	switch in.destination {
	case DestinationOnline:
		org := strings.TrimRight(strings.TrimSpace(in.orgURL), "/")
		if org == "" || gatewayURLProblem(org) != "" {
			return GatewayEndpoint{}, GatewayProblemNotConfigured, notConfigured
		}
		if upstream == "" {
			return GatewayEndpoint{}, GatewayProblemUpstreamRequired, fmt.Sprintf("the %s client has no default upstream: name one", provider)
		}
		return GatewayEndpoint{BaseURL: org + aiPathLane + "/" + upstream + row.suffix, Source: GatewaySourceOrg, Upstream: upstream}, "", ""
	case DestinationLocal, DestinationBoth:
		if upstream == "" {
			return GatewayEndpoint{}, GatewayProblemUpstreamRequired, fmt.Sprintf("the %s client has no default upstream: name one", provider)
		}
		var local any
		if in.local != nil {
			local = in.local()
		}
		if base := machineLane(local, upstream); base != "" {
			return GatewayEndpoint{BaseURL: base + row.suffix, Source: GatewaySourceMachine, Upstream: upstream}, "", ""
		}
	}
	return GatewayEndpoint{}, GatewayProblemNotConfigured, notConfigured
}

// ResolveGateway resolves where a model client of the given family
// (GatewayProviderOpenAI, GatewayProviderAnthropic, GatewayProviderAzureOpenAI)
// sends its calls, first set wins:
//
//  1. o.URL;
//  2. SUPERBASED_AI_GATEWAY_URL;
//  3. the organization's address, <org url>/ai/<upstream>, when the
//     destination is online (the org url is the trace gateway address the
//     SDK already uses: SUPERBASED_ORG_URL, Options.OrgURL or the sign-in
//     key file);
//  4. this machine's app lane for the upstream, from its loopback discovery
//     answer, when the destination is local or both.
//
// The destination is Init's, or the one the environment resolves before
// Init. It returns a *GatewayAddressError (errors.Is ErrGatewayNotConfigured)
// when nothing applies; it never falls back to the provider itself, which
// would skip every rule the gateway applies.
func ResolveGateway(provider string, o GatewayOptions) (GatewayEndpoint, error) {
	p := currentPlan()
	in := gatewayInputs{
		provider:    provider,
		upstream:    o.Upstream,
		url:         o.URL,
		env:         osEnv.get(EnvAIGatewayURL),
		destination: p.destination,
		orgURL:      p.gatewayURL,
		local: func() any {
			if !gatewayDiscoveryAllowed() {
				return nil
			}
			body, _ := discover(p.nodeURL)
			return body["local"]
		},
	}
	ep, problem, msg := resolveGatewayEndpoint(in)
	if problem != "" {
		return GatewayEndpoint{}, &GatewayAddressError{Problem: problem, Message: msg}
	}
	return ep, nil
}

// gatewayDiscoveryAllowed is Init's Discover setting, or the environment's
// before Init (SUPERBASED_DISCOVER=0 turns it off).
func gatewayDiscoveryAllowed() bool {
	if s := CurrentSettings(); s != nil {
		return s.Discover
	}
	s, err := resolveSettings(osEnv, Options{})
	if err != nil {
		s, _ = resolveSettings(osEnv, Options{SampleRate: Float(1)})
	}
	return s.Discover
}

// GatewayBaseURL is the base URL to give a model client of the given family
// for upstream ("" for the provider's default): ResolveGateway's BaseURL.
//
//	base, err := superbased.GatewayBaseURL(superbased.GatewayProviderOpenAI, "")
//
// A full client, with the key rule (GatewayEndpoint.APIKey):
//
//	ep, err := superbased.ResolveGateway(superbased.GatewayProviderOpenAI, superbased.GatewayOptions{})
//	if err != nil {
//		return err
//	}
//	key, err := ep.APIKey()
//	if err != nil {
//		return err // a remote gateway and no SUPERBASED_AI_GATEWAY_KEY
//	}
//	opts := []option.RequestOption{option.WithBaseURL(ep.BaseURL), option.WithHTTPClient(ep.HTTPClient(nil))}
//	if key != "" {
//		opts = append(opts, option.WithAPIKey(key)) // "": the client's own provider key
//	}
//	client := openai.NewClient(opts...)
func GatewayBaseURL(provider, upstream string) (string, error) {
	ep, err := ResolveGateway(provider, GatewayOptions{Upstream: upstream})
	return ep.BaseURL, err
}

// GatewayKey is the AI gateway key from SUPERBASED_AI_GATEWAY_KEY, trimmed
// ("" when unset). Prefer GatewayEndpoint.APIKey, which applies the key rule.
func GatewayKey() string { return strings.TrimSpace(osEnv.get(EnvAIGatewayKey)) }

// APIKey is the key the model client must send to this endpoint, by the rule
// every SDK shares (sdk/contract/ai-gateway-cases.json, api_key):
//
//   - on this machine's app lane (source machine): "" and no error. Leave the
//     client's key option unset, so it sends the provider's own key
//     (OPENAI_API_KEY, ANTHROPIC_API_KEY), which the lane forwards;
//   - SUPERBASED_AI_GATEWAY_KEY when it is set;
//   - on a loopback address with no gateway key: "" and no error (the
//     provider's own key, to a gateway on this machine);
//   - otherwise a *GatewayAddressError with Problem no_key (it matches
//     ErrGatewayNotConfigured): a remote gateway never receives the
//     provider's own key.
//
// A key the caller already holds for the gateway wins over all of this; pass
// it to the client directly.
func (e GatewayEndpoint) APIKey() (string, error) {
	if e.Source == GatewaySourceMachine {
		return "", nil
	}
	if k := GatewayKey(); k != "" {
		return k, nil
	}
	if isLoopbackURL(e.BaseURL) {
		return "", nil
	}
	return "", &GatewayAddressError{
		Problem: GatewayProblemNoKey,
		Message: "no AI gateway key for " + e.BaseURL + ": set " + EnvAIGatewayKey,
	}
}

// HTTPClient is the http.Client to give the model SDK for this endpoint:
// GatewayTransport over base (nil: http.DefaultTransport), plus the
// X-SBO-Upstream header when the endpoint needs one. It follows no redirect,
// because every call carries the AI gateway key.
func (e GatewayEndpoint) HTTPClient(base http.RoundTripper) *http.Client {
	rt := GatewayTransport(base)
	if e.UpstreamHeader != "" {
		rt = &upstreamTransport{base: rt, upstream: e.UpstreamHeader}
	}
	return &http.Client{
		Transport:     rt,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// upstreamTransport sets X-SBO-Upstream when the request carries none.
type upstreamTransport struct {
	base     http.RoundTripper
	upstream string
}

func (u *upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get(HeaderUpstream) != "" {
		return u.base.RoundTrip(req)
	}
	r := req.Clone(req.Context())
	r.Header.Set(HeaderUpstream, u.upstream)
	return u.base.RoundTrip(r)
}

// --- refusals -----------------------------------------------------------------------

// The AI gateway's refusal kinds (GatewayRefusalError.Kind).
const (
	GatewayRefusalBudgetExceeded  = "budget_exceeded"
	GatewayRefusalModelNotAllowed = "model_not_allowed"
	GatewayRefusalAdmissionDenied = "admission_denied"
	GatewayRefusalPlanRequired    = "plan_required"
	GatewayRefusalQuotaExceeded   = "quota_exceeded"
	GatewayRefusalOther           = "other"
)

// CodeAIGatewayQuotaExceeded is the AI gateway's 429 when the organization's
// monthly request allowance is used up.
const CodeAIGatewayQuotaExceeded = "aigw_requests_quota_exceeded"

// gatewayRefusalCodes: code -> the status it rides on and the kind. One row
// per code; any other code, or a code on another status, is
// GatewayRefusalOther.
var gatewayRefusalCodes = map[string]struct {
	status int
	kind   string
}{
	"budget_exceeded":          {402, GatewayRefusalBudgetExceeded},
	"model_not_allowed":        {403, GatewayRefusalModelNotAllowed},
	"admission_denied":         {403, GatewayRefusalAdmissionDenied},
	CodePlanRequired:           {403, GatewayRefusalPlanRequired},
	CodeAIGatewayQuotaExceeded: {429, GatewayRefusalQuotaExceeded},
}

// Sentinels a *GatewayRefusalError matches with errors.Is by Kind. A plan
// refusal (403 plan_required, 429 aigw_requests_quota_exceeded with the plan
// detail) also matches ErrPlanRequired or ErrAllowanceExceeded through its
// PlanRefusal.
var (
	ErrBudgetExceeded       = errors.New("superbased: an AI gateway budget cap refused the call")
	ErrModelNotAllowed      = errors.New("superbased: the organization's model rules refused the call")
	ErrAdmissionDenied      = errors.New("superbased: the organization's admission policy refused the call")
	ErrGatewayQuotaExceeded = errors.New("superbased: the organization's monthly AI gateway allowance is used up")
)

// GatewayBudget is the cap a 402 refusal names, in the cap's own unit (usd
// or tokens). A nil Remaining or Cap was absent; a Remaining below zero is
// how far calls already let through went past the cap.
type GatewayBudget struct {
	Level     string   `json:"level"`
	ScopeID   string   `json:"scope_id"`
	Unit      string   `json:"unit"`
	Remaining *float64 `json:"remaining"`
	Cap       *float64 `json:"cap"`
	Estimated bool     `json:"estimated"`
}

// GatewayRefusalError is the AI gateway refusing a model call. Kind is one of
// the GatewayRefusal* values; Code the gateway's reason; RequestID its
// X-SBO-Request-Id; RetryAfter the Retry-After header. Budget is set for
// budget_exceeded, PlanRefusal for a plan refusal with an upgrade URL.
type GatewayRefusalError struct {
	Kind        string            `json:"kind"`
	Code        string            `json:"code"`
	Status      int               `json:"status"`
	Message     string            `json:"message"`
	RequestID   string            `json:"request_id"`
	RetryAfter  time.Duration     `json:"retry_after"`
	Budget      *GatewayBudget    `json:"budget"`
	PlanRefusal *PlanRefusalError `json:"plan_refusal"`
}

// Error is the gateway's message and code.
func (e *GatewayRefusalError) Error() string {
	return fmt.Sprintf("superbased: the AI gateway refused the call (%d %s): %s", e.Status, e.Code, e.Message)
}

// Is matches the sentinel of the refusal's Kind.
func (e *GatewayRefusalError) Is(target error) bool {
	switch target {
	case ErrBudgetExceeded:
		return e.Kind == GatewayRefusalBudgetExceeded
	case ErrModelNotAllowed:
		return e.Kind == GatewayRefusalModelNotAllowed
	case ErrAdmissionDenied:
		return e.Kind == GatewayRefusalAdmissionDenied
	case ErrGatewayQuotaExceeded:
		return e.Kind == GatewayRefusalQuotaExceeded
	}
	return false
}

// Unwrap is the plan refusal, when there is one (errors.As finds it).
func (e *GatewayRefusalError) Unwrap() error {
	if e.PlanRefusal == nil {
		return nil
	}
	return e.PlanRefusal
}

// gatewayRefusalCode is the refusal's code: the top-level reason, else a
// top-level string error that is a known code ("" when neither).
func gatewayRefusalCode(obj map[string]any) string {
	if r := strings.TrimSpace(jsonStr(obj, "reason")); r != "" {
		return r
	}
	if e := strings.TrimSpace(jsonStr(obj, "error")); e != "" {
		if _, known := gatewayRefusalCodes[e]; known {
			return e
		}
	}
	return ""
}

// gatewayRefusalMessage is error.message (an object error), else the
// top-level message, else a string error that is not the code.
func gatewayRefusalMessage(obj map[string]any, code string) string {
	if eo, ok := obj["error"].(map[string]any); ok {
		if m := strings.TrimSpace(jsonStr(eo, "message")); m != "" {
			return m
		}
	}
	if m := strings.TrimSpace(jsonStr(obj, "message")); m != "" {
		return m
	}
	if e := strings.TrimSpace(jsonStr(obj, "error")); e != "" && e != code {
		return e
	}
	return ""
}

// gatewayRequestID is X-SBO-Request-Id, else request-id, else x-request-id.
func gatewayRequestID(h http.Header) string {
	for _, k := range []string{HeaderRequestID, "Request-Id", "X-Request-Id"} {
		if v := strings.TrimSpace(h.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

// gatewayBudgetFrom reads the cap fields of a budget refusal.
func gatewayBudgetFrom(obj map[string]any) *GatewayBudget {
	b := &GatewayBudget{Level: jsonStr(obj, "level"), ScopeID: jsonStr(obj, "scope_id"), Unit: jsonStr(obj, "unit")}
	b.Estimated, _ = obj["estimated"].(bool)
	num := func(k string) *float64 {
		if _, isBool := obj[k].(bool); isBool {
			return nil
		}
		if f, ok := jsonFloat(obj[k]); ok {
			return &f
		}
		return nil
	}
	switch b.Unit {
	case "usd":
		b.Remaining, b.Cap = num("remaining_usd"), num("cap_usd")
	case "tokens":
		b.Remaining, b.Cap = num("remaining_tokens"), num("cap_tokens")
	}
	return b
}

// ParseGatewayRefusal is the AI gateway refusal in one HTTP answer, or nil: a
// non-2xx answer whose JSON object body carries the gateway's top-level
// reason (or a plan refusal's code as a top-level string error). A provider's
// own error the gateway relays as is, malformed input included, is nil.
// header may be nil. It never panics.
func ParseGatewayRefusal(status int, body []byte, header http.Header) (out *GatewayRefusalError) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	if status < 400 {
		return nil
	}
	obj, ok := decodeJSON(bytes.TrimSpace(body)).(map[string]any)
	if !ok {
		return nil
	}
	code := gatewayRefusalCode(obj)
	if code == "" {
		return nil
	}
	if header == nil {
		header = http.Header{}
	}
	e := &GatewayRefusalError{
		Kind:       GatewayRefusalOther,
		Code:       code,
		Status:     status,
		Message:    gatewayRefusalMessage(obj, code),
		RequestID:  gatewayRequestID(header),
		RetryAfter: retryAfterOf(header),
	}
	if row, known := gatewayRefusalCodes[code]; known && row.status == status {
		e.Kind = row.kind
	}
	if e.Message == "" {
		e.Message = fmt.Sprintf("the AI gateway refused the call (%s)", code)
	}
	if code == "budget_exceeded" {
		e.Budget = gatewayBudgetFrom(obj)
	}
	if code == CodePlanRequired || code == CodeAIGatewayQuotaExceeded {
		// The plan detail is the planrefusal body's top-level fields; its
		// parser reads the code from a string error.
		norm := make(map[string]any, len(obj)+1)
		for k, v := range obj {
			norm[k] = v
		}
		norm["error"] = code
		if jsonStr(norm, "message") == "" {
			norm["message"] = e.Message
		}
		if raw, err := json.Marshal(norm); err == nil {
			e.PlanRefusal = ParsePlanRefusal(status, raw, header)
		}
	}
	return e
}

// gatewayRefusalPeek is how much of a refused response's body
// GatewayRefusalFromResponse reads.
const gatewayRefusalPeek = 64 << 10

// GatewayRefusalFromResponse is ParseGatewayRefusal over a response, or nil.
// It reads at most 64 KiB of the body and puts back what it read, so the
// caller (or the model SDK) can still read the whole body.
func GatewayRefusalFromResponse(resp *http.Response) *GatewayRefusalError {
	if resp == nil || resp.StatusCode < 400 {
		return nil
	}
	if resp.Body == nil {
		return ParseGatewayRefusal(resp.StatusCode, nil, resp.Header)
	}
	head, _ := io.ReadAll(io.LimitReader(resp.Body, gatewayRefusalPeek))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
	return ParseGatewayRefusal(resp.StatusCode, head, resp.Header)
}
