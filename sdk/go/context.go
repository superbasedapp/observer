package superbased

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Attributes are per-request values (contract sdk-api-surface.md section 2).
// An empty string or nil field keeps the outer scope's value; Clear names the
// options to clear for the inner scope ("user", "session_id", "tenant",
// "release", "environment").
type Attributes struct {
	User        string
	SessionID   string
	Tenant      string
	Release     string
	Environment string
	// Tags are unioned with the outer scope's (trimmed, empty dropped, sorted,
	// at most 32 of at most 128 characters).
	Tags []string
	// Metadata merges per key over the outer scope's, a nil value deleting the
	// key; a value that is not a string is JSON-encoded (compact, sorted keys).
	Metadata map[string]any
	// Clear removes these options (by name) from the inner scope.
	Clear []string
	// AsBaggage also puts the values into W3C baggage, so Inject carries them.
	AsBaggage bool
}

// option name -> span attribute (the scalar options), in a fixed order.
var scalarKeys = []struct{ name, key string }{
	{"user", keyUser},
	{"session_id", keySession},
	{"tenant", keyTenant},
	{"release", keyRelease},
	{"environment", keyEnvironment},
}

func (a Attributes) scalar(name string) string {
	switch name {
	case "user":
		return a.User
	case "session_id":
		return a.SessionID
	case "tenant":
		return a.Tenant
	case "release":
		return a.Release
	case "environment":
		return a.Environment
	}
	return ""
}

// normalizeTags is otelident.NormalizeTags: trimmed, clamped, de-duplicated,
// sorted, capped.
func normalizeTags(lists ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, l := range lists {
		for _, t := range l {
			s := clampStr(t, maxTagLen)
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	if len(out) > maxTags {
		out = out[:maxTags]
	}
	return out
}

func metaValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v) // maps are written with sorted keys
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// normalizeMetadata merges maps (later wins), a nil value deleting the key,
// clamps keys and values and keeps the lexically smallest maxMetadataKeys keys.
func normalizeMetadata(maps ...map[string]any) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			key := clampStr(k, maxMetadataKeyLen)
			if key == "" {
				continue
			}
			if v == nil {
				delete(out, key)
				continue
			}
			out[key] = clampStr(metaValue(v), maxMetadataValueLen)
		}
	}
	if len(out) > maxMetadataKeys {
		keys := make([]string, 0, len(out))
		for k := range out {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[maxMetadataKeys:] {
			delete(out, k)
		}
	}
	return out
}

// scope is one immutable level of per-request values.
type scope struct {
	scalars  map[string]string // by attribute key
	tags     []string
	metadata map[string]string
	baggage  bool
}

type scopeKey struct{}

func currentScope(ctx context.Context) *scope {
	if ctx != nil {
		if s, ok := ctx.Value(scopeKey{}).(*scope); ok {
			return s
		}
	}
	return &scope{}
}

func (s *scope) merged(a Attributes) *scope {
	scalars := map[string]string{}
	for k, v := range s.scalars {
		scalars[k] = v
	}
	for _, c := range a.Clear {
		for _, sk := range scalarKeys {
			if sk.name == c {
				delete(scalars, sk.key)
			}
		}
	}
	for _, sk := range scalarKeys {
		if v := clampStr(a.scalar(sk.name), maxValueLen); v != "" {
			scalars[sk.key] = v
		}
	}
	prev := map[string]any{}
	for k, v := range s.metadata {
		prev[k] = v
	}
	return &scope{
		scalars:  scalars,
		tags:     normalizeTags(s.tags, a.Tags),
		metadata: normalizeMetadata(prev, a.Metadata),
		baggage:  s.baggage || a.AsBaggage,
	}
}

func (s *scope) attributes() []attribute.KeyValue {
	var out []attribute.KeyValue
	for _, sk := range scalarKeys {
		if v, ok := s.scalars[sk.key]; ok {
			out = append(out, attribute.String(sk.key, v))
		}
	}
	if len(s.tags) > 0 {
		out = append(out, attribute.StringSlice(keyTags, s.tags))
	}
	keys := make([]string, 0, len(s.metadata))
	for k := range s.metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, attribute.String(keyMetaPrefix+k, s.metadata[k]))
	}
	return out
}

// public is the option-named view.
func (s *scope) public() map[string]any {
	out := map[string]any{}
	for _, sk := range scalarKeys {
		if v, ok := s.scalars[sk.key]; ok {
			out[sk.name] = v
		}
	}
	if len(s.tags) > 0 {
		out["tags"] = append([]string(nil), s.tags...)
	}
	if len(s.metadata) > 0 {
		m := map[string]string{}
		for k, v := range s.metadata {
			m[k] = v
		}
		out["metadata"] = m
	}
	return out
}

func withBaggage(ctx context.Context, s *scope) context.Context {
	b := baggage.FromContext(ctx)
	set := func(k, v string) {
		if m, err := baggage.NewMemberRaw(k, v); err == nil {
			if nb, err := b.SetMember(m); err == nil {
				b = nb
			}
		}
	}
	for _, sk := range scalarKeys {
		if v, ok := s.scalars[sk.key]; ok {
			set(sk.key, v)
		}
	}
	if len(s.tags) > 0 {
		set(keyTags, strings.Join(s.tags, ","))
	}
	for k, v := range s.metadata {
		set(keyMetaPrefix+k, v)
	}
	return baggage.ContextWithBaggage(ctx, b)
}

// PropagateAttributes returns a context whose spans carry a's values (the
// current span in ctx is tagged too). Nested calls merge: the inner value
// wins, tags union, metadata merges per key. A value a span already carries
// is never overwritten.
func PropagateAttributes(ctx context.Context, a Attributes) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	s := currentScope(ctx).merged(a)
	ctx = context.WithValue(ctx, scopeKey{}, s)
	if s.baggage {
		ctx = withBaggage(ctx, s)
	}
	applyToCurrentSpan(ctx, s, a)
	return ctx
}

// Identify is PropagateAttributes: a Go context is a value, so the identity
// lasts as long as the returned context is used (the contract's identify()
// and reset()).
func Identify(ctx context.Context, a Attributes) context.Context { return PropagateAttributes(ctx, a) }

func applyToCurrentSpan(ctx context.Context, s *scope, a Attributes) {
	sp := trace.SpanFromContext(ctx)
	if !sp.IsRecording() {
		return
	}
	for _, sk := range scalarKeys {
		if a.scalar(sk.name) != "" {
			if v, ok := s.scalars[sk.key]; ok {
				sp.SetAttributes(attribute.String(sk.key, v))
			}
		}
	}
	if len(a.Tags) > 0 && len(s.tags) > 0 {
		var existing []string
		if ro, ok := sp.(sdktrace.ReadOnlySpan); ok {
			for _, kv := range ro.Attributes() {
				if string(kv.Key) == keyTags {
					existing = kv.Value.AsStringSlice()
				}
			}
		}
		sp.SetAttributes(attribute.StringSlice(keyTags, normalizeTags(existing, s.tags)))
	}
	for k := range a.Metadata {
		key := clampStr(k, maxMetadataKeyLen)
		if v, ok := s.metadata[key]; ok {
			sp.SetAttributes(attribute.String(keyMetaPrefix+key, v))
		}
	}
}

// CurrentAttributes are the per-request values in effect in ctx, by option
// name (user, session_id, tenant, release, environment, tags, metadata),
// present keys only.
func CurrentAttributes(ctx context.Context) map[string]any { return currentScope(ctx).public() }

// --- trace context -------------------------------------------------------------

var propagator = propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})

// CurrentTraceID is the trace id of the span in ctx (32 lowercase hex), or "".
func CurrentTraceID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

// CurrentSpanID is the span id of the span in ctx (16 lowercase hex), or "".
func CurrentSpanID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.SpanID().String()
}

// Inject writes traceparent (and tracestate and baggage when present) for ctx
// into carrier (a new map when nil) and returns it. Always W3C, whatever
// propagator the host registered.
func Inject(ctx context.Context, carrier map[string]string) map[string]string {
	if carrier == nil {
		carrier = map[string]string{}
	}
	propagator.Inject(ctx, propagation.MapCarrier(carrier))
	return carrier
}

// InjectHeader writes the same headers into an http.Header.
func InjectHeader(ctx context.Context, h http.Header) {
	propagator.Inject(ctx, propagation.HeaderCarrier(h))
}

// Traceparent is the W3C traceparent of the span in ctx, or "".
func Traceparent(ctx context.Context) string { return Inject(ctx, nil)["traceparent"] }

// foldCarrier reads a map case-insensitively.
type foldCarrier map[string]string

func (c foldCarrier) Get(key string) string {
	for k, v := range c {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}
func (c foldCarrier) Set(key, value string) { c[key] = value }
func (c foldCarrier) Keys() []string {
	out := make([]string, 0, len(c))
	for k := range c {
		out = append(out, k)
	}
	return out
}

// Extract returns ctx with the remote span context and baggage carried by W3C
// headers in carrier (names case-insensitive). A malformed header gives no
// remote parent.
func Extract(ctx context.Context, carrier map[string]string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return propagator.Extract(ctx, foldCarrier(carrier))
}

// ExtractHeader is Extract over an http.Header.
func ExtractHeader(ctx context.Context, h http.Header) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return propagator.Extract(ctx, propagation.HeaderCarrier(h))
}

// ContinueTrace is Extract plus the per-request values the caller sent as
// sbo.* baggage, restored into the attribute scope. Spans started from the
// returned context join the caller's trace.
func ContinueTrace(ctx context.Context, carrier map[string]string) context.Context {
	ctx = Extract(ctx, carrier)
	return restoreBaggageScope(ctx)
}

func restoreBaggageScope(ctx context.Context) context.Context {
	members := baggage.FromContext(ctx).Members()
	if len(members) == 0 {
		return ctx
	}
	var a Attributes
	meta := map[string]any{}
	found := false
	for _, m := range members {
		k, v := m.Key(), m.Value()
		switch {
		case k == keyTags:
			a.Tags = strings.Split(v, ",")
			found = true
		case strings.HasPrefix(k, keyMetaPrefix):
			meta[strings.TrimPrefix(k, keyMetaPrefix)] = v
			found = true
		default:
			for _, sk := range scalarKeys {
				if sk.key == k {
					found = true
					switch sk.name {
					case "user":
						a.User = v
					case "session_id":
						a.SessionID = v
					case "tenant":
						a.Tenant = v
					case "release":
						a.Release = v
					case "environment":
						a.Environment = v
					}
				}
			}
		}
	}
	if !found {
		return ctx
	}
	if len(meta) > 0 {
		a.Metadata = meta
	}
	a.AsBaggage = true
	return context.WithValue(ctx, scopeKey{}, currentScope(ctx).merged(a))
}
