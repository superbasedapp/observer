package superbased

import (
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Built-in defaults (contract sdk-api-surface.md section 8).
const (
	DefaultEndpoint        = "http://127.0.0.1:4318/v1/traces"
	DefaultServiceName     = "custom-app"
	DefaultMaxContentChars = 8000
	DefaultExportTimeout   = 5 * time.Second
	DefaultShutdownTimeout = 2 * time.Second
	DefaultNodeURL         = "http://127.0.0.1:8081"
	DefaultAPITimeout      = 5 * time.Second
	DefaultPromptCacheTTL  = 60 * time.Second
	tracesPath             = "/v1/traces"
)

// envFunc looks up one environment variable (os.LookupEnv, or a map in tests).
type envFunc func(string) (string, bool)

// osEnv is the process environment.
var osEnv envFunc = os.LookupEnv

// get is one variable's value ("" when unset).
func (e envFunc) get(name string) string {
	v, _ := e(name)
	return v
}

// mapEnv is an environment held in a map (tests, and the cases' env objects).
func mapEnv(m map[string]string) envFunc {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// Options are Init's settings. A zero field is unset: the SUPERBASED_*
// environment variable, then the standard OTEL_* one where it exists, then the
// machine's default (only Destination) and the built-in default apply. Pointer
// fields are the ones whose zero value is a real choice (false, 0); use Bool,
// Int and Float to set them.
type Options struct {
	// Endpoint is the local destination's OTLP traces URL
	// (SUPERBASED_OTLP_ENDPOINT; under destination local also
	// OTEL_EXPORTER_OTLP_TRACES_ENDPOINT and OTEL_EXPORTER_OTLP_ENDPOINT +
	// /v1/traces; else the machine's advertised receiver; else
	// http://127.0.0.1:4318/v1/traces).
	Endpoint string
	// Tenant, User and SessionID identify every trace (SUPERBASED_TENANT,
	// SUPERBASED_USER, SUPERBASED_SESSION_ID).
	Tenant, User, SessionID string
	// ServiceName (SUPERBASED_SERVICE_NAME, OTEL_SERVICE_NAME, service.name in
	// OTEL_RESOURCE_ATTRIBUTES, else the last element of the main module's
	// path from the build info, its /vN suffix dropped and normalised, else
	// custom-app). Settings.ServiceNameSource says which.
	ServiceName string
	// Headers are added to every OTLP export (over SUPERBASED_OTLP_HEADERS).
	Headers map[string]string
	// APIKey is the SDK credential (SUPERBASED_API_KEY, else the machine's
	// credential file named by discovery). Sent only to the gateway.
	APIKey string
	// Console also prints every span to stderr (SUPERBASED_CONSOLE).
	Console *bool
	// CaptureContent records prompt, response and tool bodies
	// (SUPERBASED_CAPTURE_CONTENT, default on).
	CaptureContent *bool
	// MaxContentChars clips each content body (SUPERBASED_MAX_CONTENT_CHARS,
	// default 8000; 0 means no limit).
	MaxContentChars *int
	// ExportTimeout bounds one export request (SUPERBASED_EXPORT_TIMEOUT_MS,
	// OTEL_EXPORTER_OTLP_TRACES_TIMEOUT, OTEL_EXPORTER_OTLP_TIMEOUT; 5 s).
	ExportTimeout time.Duration
	// ShutdownTimeout bounds Flush and Shutdown (SUPERBASED_SHUTDOWN_TIMEOUT_MS; 2 s).
	ShutdownTimeout time.Duration
	// Quiet keeps exporter errors out of the OpenTelemetry error handler; they
	// are counted in Diagnostics and summarised once a minute (SUPERBASED_QUIET,
	// default on).
	Quiet *bool
	// Release, Environment, Tags and Metadata are process-wide trace identity
	// (SUPERBASED_RELEASE, SUPERBASED_ENVIRONMENT, SUPERBASED_TAGS comma list,
	// SUPERBASED_METADATA k=v,k2=v2).
	Release, Environment string
	Tags                 []string
	Metadata             map[string]any
	// SampleRate is the head-sampling ratio in 0..1 (SUPERBASED_SAMPLE_RATE,
	// else OTEL_TRACES_SAMPLER / OTEL_TRACES_SAMPLER_ARG; default 1). A value
	// outside 0..1 makes Init return an error.
	SampleRate *float64
	// ShouldExport drops a finished span when it returns false. A hook that
	// panics keeps the span.
	ShouldExport func(sdktrace.ReadOnlySpan) bool
	// Mask rewrites each content attribute before export; return nil to drop
	// it. A hook that returns an error or panics drops that attribute, never
	// the span. A value that is not a string, bool, number or slice of those
	// is stringified.
	Mask func(value any, key string) (any, error)
	// Destination is local, online or both (SUPERBASED_DESTINATION, else the
	// machine's default over loopback, else local).
	Destination string
	// OrgURL is the organization's gateway base (SUPERBASED_ORG_URL, else the
	// gateway_url line of the machine's credential file).
	OrgURL string
	// NodeURL is this machine's dashboard API (SUPERBASED_NODE_URL, default
	// http://127.0.0.1:8081). Only a loopback address is asked.
	NodeURL string
	// Discover asks the machine for its default (SUPERBASED_DISCOVER, default on).
	Discover *bool
	// APITimeout bounds score, prompt, dataset, experiment and trace-cost calls
	// (SUPERBASED_API_TIMEOUT_MS; 5 s). Discovery is fixed at 500 ms.
	APITimeout time.Duration
	// PromptCacheTTL is how long a fetched prompt is fresh
	// (SUPERBASED_PROMPT_CACHE_TTL_MS; 60 s). A negative value means 0.
	PromptCacheTTL time.Duration
	// Exporter replaces the OTLP/HTTP exporter of every destination (tests, a
	// custom transport). Exporters gives each destination ("local", "online")
	// its own and wins over Exporter.
	Exporter  sdktrace.SpanExporter
	Exporters map[string]sdktrace.SpanExporter
	// TracerProvider is an SDK provider to attach to instead of the global one.
	TracerProvider *sdktrace.TracerProvider
}

// Bool returns a pointer to v (for the Options fields whose zero value is a choice).
func Bool(v bool) *bool { return &v }

// Int returns a pointer to v.
func Int(v int) *int { return &v }

// Float returns a pointer to v.
func Float(v float64) *float64 { return &v }

// Settings are the options Init resolved. String never shows the credential
// or the headers.
type Settings struct {
	Endpoint          string
	Headers           map[string]string `json:"-"`
	APIKey            string            `json:"-"`
	ServiceName       string
	ServiceNameSource string // argument | env | manifest | default
	ResourceAttrs     map[string]string
	Tenant            string
	User              string
	SessionID         string
	CaptureContent    bool
	MaxContentChars   int
	ExportTimeout     time.Duration
	ShutdownTimeout   time.Duration
	Quiet             bool
	Console           bool
	Release           string
	Environment       string
	Tags              []string
	Metadata          map[string]string
	SampleRate        float64
	SampleParentBased bool
	Destination       string
	OrgURL            string
	NodeURL           string
	Discover          bool
	APITimeout        time.Duration
	PromptCacheTTL    time.Duration
}

// String describes the settings without the credential or the headers.
func (s Settings) String() string {
	key := ""
	if s.APIKey != "" {
		key = "<set>"
	}
	return fmt.Sprintf("Settings{Endpoint:%q ServiceName:%q Destination:%q OrgURL:%q NodeURL:%q APIKey:%s CaptureContent:%t MaxContentChars:%d SampleRate:%g}",
		s.Endpoint, s.ServiceName, s.Destination, s.OrgURL, s.NodeURL, key, s.CaptureContent, s.MaxContentChars, s.SampleRate)
}

// Format redacts the credential and the headers under every fmt verb
// (%v, %+v, %#v, %s), so a log line or an error message never carries them.
func (s Settings) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// GoString is the %#v form, redacted.
func (s Settings) GoString() string { return s.String() }

// LogValue is how slog renders Settings: the redacted summary, not the fields.
func (s Settings) LogValue() slog.Value { return slog.StringValue(s.String()) }

var falseWords = map[string]bool{"0": true, "false": true, "no": true, "off": true, "": true}

func envFlag(env envFunc, def bool, names ...string) bool {
	for _, n := range names {
		if raw, ok := env(n); ok {
			return !falseWords[strings.ToLower(strings.TrimSpace(raw))]
		}
	}
	return def
}

func envStr(env envFunc, names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(env.get(n)); v != "" {
			return v
		}
	}
	return ""
}

func envMS(env envFunc, names ...string) (time.Duration, bool) {
	for _, n := range names {
		raw := strings.TrimSpace(env.get(n))
		if raw == "" {
			continue
		}
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			continue
		}
		d := time.Duration(f * float64(time.Millisecond))
		if d < time.Millisecond {
			d = time.Millisecond
		}
		return d, true
	}
	return 0, false
}

// parseKVList parses the OTel key1=value1,key2=value2 format (percent-decoded).
func parseKVList(raw string) map[string]string {
	out := map[string]string{}
	for _, member := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(member, "=")
		if !ok {
			continue
		}
		key, err := url.PathUnescape(strings.TrimSpace(k))
		if err != nil {
			key = strings.TrimSpace(k)
		}
		if key == "" {
			continue
		}
		val, err := url.PathUnescape(strings.TrimSpace(v))
		if err != nil {
			val = strings.TrimSpace(v)
		}
		out[key] = val
	}
	return out
}

func resolveEndpoint(explicit string, env envFunc) string {
	if explicit != "" {
		return explicit
	}
	if v := envStr(env, "SUPERBASED_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"); v != "" {
		return v
	}
	if base := envStr(env, "OTEL_EXPORTER_OTLP_ENDPOINT"); base != "" {
		return strings.TrimRight(base, "/") + tracesPath
	}
	return DefaultEndpoint
}

// resolveServiceName is the service name the ladder gives (servicename.go)
// for this process.
func resolveServiceName(explicit string, env envFunc) string {
	name, _ := serviceNameLadder(explicit, env, moduleServiceName(mainModulePath()))
	return name
}

type samplerRow struct {
	rate     float64
	parent   bool
	takesArg bool
}

var samplers = map[string]samplerRow{
	"always_on":                {1, false, false},
	"always_off":               {0, false, false},
	"traceidratio":             {1, false, true},
	"parentbased_always_on":    {1, true, false},
	"parentbased_always_off":   {0, true, false},
	"parentbased_traceidratio": {1, true, true},
}

func ratio(raw string) (float64, bool) {
	if raw == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(v) || v < 0 || v > 1 {
		return 0, false
	}
	return v, true
}

// resolveSampling returns (rate, parent-based): the explicit rate, then
// SUPERBASED_SAMPLE_RATE (parent-based), then OTEL_TRACES_SAMPLER(+_ARG),
// else (1, true). An explicit rate outside 0..1 is an error; a bad env value is
// ignored (samplingEnvProblem names it).
func resolveSampling(explicit *float64, env envFunc) (float64, bool, error) {
	if explicit != nil {
		v := *explicit
		if math.IsNaN(v) || v < 0 || v > 1 {
			return 0, false, fmt.Errorf("superbased: sample rate must be a number in 0..1, got %v", v)
		}
		return v, true, nil
	}
	if v, ok := ratio(envStr(env, "SUPERBASED_SAMPLE_RATE")); ok {
		return v, true, nil
	}
	row, ok := samplers[strings.ToLower(envStr(env, "OTEL_TRACES_SAMPLER"))]
	if ok {
		rate := row.rate
		if row.takesArg {
			if arg, ok := ratio(envStr(env, "OTEL_TRACES_SAMPLER_ARG")); ok {
				rate = arg
			} else {
				rate = 1
			}
		}
		return rate, row.parent, nil
	}
	return 1, true, nil
}

// samplingEnvProblem says which environment sampling value was ignored ("" when
// none was): SUPERBASED_SAMPLE_RATE or OTEL_TRACES_SAMPLER_ARG that is not a
// number in 0..1 (review E-38).
func samplingEnvProblem(env envFunc) string {
	var bad []string
	raw := envStr(env, "SUPERBASED_SAMPLE_RATE")
	_, rawOK := ratio(raw)
	if raw != "" && !rawOK {
		bad = append(bad, fmt.Sprintf("SUPERBASED_SAMPLE_RATE=%q", raw))
	}
	if raw == "" || !rawOK {
		row, ok := samplers[strings.ToLower(envStr(env, "OTEL_TRACES_SAMPLER"))]
		arg := envStr(env, "OTEL_TRACES_SAMPLER_ARG")
		if _, argOK := ratio(arg); ok && row.takesArg && arg != "" && !argOK {
			bad = append(bad, fmt.Sprintf("OTEL_TRACES_SAMPLER_ARG=%q", arg))
		}
	}
	if len(bad) == 0 {
		return ""
	}
	return strings.Join(bad, " and ") + " is not a number in 0..1; ignored"
}

func clampStr(s string, n int) string {
	s = strings.TrimSpace(s)
	if n > 0 && len([]rune(s)) > n {
		return string([]rune(s)[:n])
	}
	return s
}

// resolveSettings builds Settings from explicit options over env.
func resolveSettings(env envFunc, o Options) (Settings, error) {
	rate, parent, err := resolveSampling(o.SampleRate, env)
	if err != nil {
		return Settings{}, err
	}
	hdrs := map[string]string{}
	for _, n := range []string{"OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS", "SUPERBASED_OTLP_HEADERS"} {
		for k, v := range parseKVList(env.get(n)) {
			hdrs[k] = v
		}
	}
	for k, v := range o.Headers {
		hdrs[k] = v
	}
	var tags []string
	if o.Tags != nil {
		tags = normalizeTags(o.Tags)
	} else {
		tags = normalizeTags(strings.Split(envStr(env, "SUPERBASED_TAGS"), ","))
	}
	var meta map[string]string
	if o.Metadata != nil {
		meta = normalizeMetadata(o.Metadata)
	} else {
		m := map[string]any{}
		for k, v := range parseKVList(env.get("SUPERBASED_METADATA")) {
			m[k] = v
		}
		meta = normalizeMetadata(m)
	}
	pick := func(explicit string, names ...string) string {
		if explicit != "" {
			return explicit
		}
		return envStr(env, names...)
	}
	s := Settings{
		Endpoint:          resolveEndpoint(o.Endpoint, env),
		Headers:           hdrs,
		APIKey:            pick(o.APIKey, "SUPERBASED_API_KEY"),
		ResourceAttrs:     parseKVList(env.get("OTEL_RESOURCE_ATTRIBUTES")),
		Tenant:            pick(o.Tenant, "SUPERBASED_TENANT"),
		User:              pick(o.User, "SUPERBASED_USER"),
		SessionID:         pick(o.SessionID, "SUPERBASED_SESSION_ID"),
		CaptureContent:    envFlag(env, true, "SUPERBASED_CAPTURE_CONTENT", "OBSERVER_CAPTURE_CONTENT"),
		MaxContentChars:   DefaultMaxContentChars,
		ExportTimeout:     DefaultExportTimeout,
		ShutdownTimeout:   DefaultShutdownTimeout,
		Quiet:             envFlag(env, true, "SUPERBASED_QUIET"),
		Console:           envFlag(env, false, "SUPERBASED_CONSOLE"),
		Release:           clampStr(pick(o.Release, "SUPERBASED_RELEASE"), maxValueLen),
		Environment:       clampStr(pick(o.Environment, "SUPERBASED_ENVIRONMENT"), maxValueLen),
		Tags:              tags,
		Metadata:          meta,
		SampleRate:        rate,
		SampleParentBased: parent,
		Destination:       strings.ToLower(strings.TrimSpace(pick(o.Destination, "SUPERBASED_DESTINATION"))),
		OrgURL:            strings.TrimRight(strings.TrimSpace(pick(o.OrgURL, "SUPERBASED_ORG_URL")), "/"),
		NodeURL:           strings.TrimRight(strings.TrimSpace(pick(o.NodeURL, "SUPERBASED_NODE_URL")), "/"),
		Discover:          envFlag(env, true, "SUPERBASED_DISCOVER"),
		APITimeout:        DefaultAPITimeout,
		PromptCacheTTL:    DefaultPromptCacheTTL,
	}
	s.ServiceName, s.ServiceNameSource = serviceNameLadder(o.ServiceName, env, moduleServiceName(mainModulePath()))
	if s.NodeURL == "" {
		s.NodeURL = DefaultNodeURL
	}
	if o.CaptureContent != nil {
		s.CaptureContent = *o.CaptureContent
	}
	if o.MaxContentChars != nil {
		s.MaxContentChars = *o.MaxContentChars
	} else if raw := envStr(env, "SUPERBASED_MAX_CONTENT_CHARS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			s.MaxContentChars = n
		}
	}
	if o.ExportTimeout > 0 {
		s.ExportTimeout = o.ExportTimeout
	} else if d, ok := envMS(env, "SUPERBASED_EXPORT_TIMEOUT_MS", "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", "OTEL_EXPORTER_OTLP_TIMEOUT"); ok {
		s.ExportTimeout = d
	}
	if o.ShutdownTimeout > 0 {
		s.ShutdownTimeout = o.ShutdownTimeout
	} else if d, ok := envMS(env, "SUPERBASED_SHUTDOWN_TIMEOUT_MS"); ok {
		s.ShutdownTimeout = d
	}
	if o.Quiet != nil {
		s.Quiet = *o.Quiet
	}
	if o.Console != nil {
		s.Console = *o.Console
	}
	if o.Discover != nil {
		s.Discover = *o.Discover
	}
	if o.APITimeout > 0 {
		s.APITimeout = o.APITimeout
	} else if d, ok := envMS(env, "SUPERBASED_API_TIMEOUT_MS"); ok {
		s.APITimeout = d
	}
	switch {
	case o.PromptCacheTTL > 0:
		s.PromptCacheTTL = o.PromptCacheTTL
	case o.PromptCacheTTL < 0:
		s.PromptCacheTTL = 0
	default:
		if d, ok := envMS(env, "SUPERBASED_PROMPT_CACHE_TTL_MS"); ok {
			s.PromptCacheTTL = d
		}
	}
	return s, nil
}

// identity is the process-wide identity, written on the resource (or stamped
// per span when the SDK is attached to the host's provider).
func (s Settings) identity() []attribute.KeyValue {
	out := []attribute.KeyValue{attribute.String(keySDK, sdkMarker)}
	add := func(k, v string) {
		if v != "" {
			out = append(out, attribute.String(k, v))
		}
	}
	add(keyTenant, s.Tenant)
	add(keyUser, s.User)
	add(keySession, s.SessionID)
	add(keyResourceRelease, s.Release)
	add(keyResourceEnvironment, s.Environment)
	if len(s.Tags) > 0 {
		out = append(out, attribute.StringSlice(keyTags, s.Tags))
	}
	keys := make([]string, 0, len(s.Metadata))
	for k := range s.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, attribute.String(keyMetaPrefix+k, s.Metadata[k]))
	}
	return out
}
