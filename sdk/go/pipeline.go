package superbased

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

const truncatedMark = "…[truncated]"

// pipeline is what happens to a finished span before the SDK exports it: the
// vendor scope filter, the attached-mode sample filter, the ShouldExport hook
// and the content rules (CaptureContent, Mask, MaxContentChars). The original
// span is never changed: a rewritten span is exported as a copy, so a host's
// other processors see the original.
type pipeline struct {
	captureContent    bool
	maxContentChars   int
	mask              func(any, string) (any, error)
	shouldExport      func(sdktrace.ReadOnlySpan) bool
	exportRatio       float64 // < 1 only when the host's sampler decided (attached mode)
	ratioSet          bool
	dropScopePrefixes []string
}

// counters are the pipeline's diagnostics counters.
type counters struct {
	mu                     sync.Mutex
	sampledOutSpans        int64
	filteredSpans          int64
	maskErrors             int64
	shouldExportErrors     int64
	vendorSpansDropped     int64
	usageNetInputCorrected int64
	lastHookError          string
}

var pipeCounters = &counters{}

func (c *counters) add(field *int64, err string) {
	c.mu.Lock()
	*field++
	if err != "" {
		if len(err) > 500 {
			err = err[:500]
		}
		c.lastHookError = err
	}
	c.mu.Unlock()
}

func (c *counters) reset() {
	c.mu.Lock()
	c.sampledOutSpans, c.filteredSpans, c.maskErrors, c.shouldExportErrors = 0, 0, 0, 0
	c.vendorSpansDropped, c.usageNetInputCorrected, c.lastHookError = 0, 0, ""
	c.mu.Unlock()
}

// keepByRatio is the OpenTelemetry TraceIDRatioBased decision for a trace id,
// so every service sampling at the same rate agrees.
func keepByRatio(id [16]byte, rate float64) bool {
	r := sdktrace.TraceIDRatioBased(rate).ShouldSample(sdktrace.SamplingParameters{TraceID: id})
	return r.Decision == sdktrace.RecordAndSample
}

func truncateText(s string, limit int) string {
	if limit > 0 && utf8.RuneCountInString(s) > limit {
		return string([]rune(s)[:limit]) + truncatedMark
	}
	return s
}

// fromAny turns a hook's return into an attribute value: a string, bool,
// number or slice of those as is, anything else stringified.
func fromAny(key string, v any) attribute.KeyValue {
	switch t := v.(type) {
	case string:
		return attribute.String(key, t)
	case bool:
		return attribute.Bool(key, t)
	case int:
		return attribute.Int(key, t)
	case int64:
		return attribute.Int64(key, t)
	case float64:
		return attribute.Float64(key, t)
	case []string:
		return attribute.StringSlice(key, t)
	case []bool:
		return attribute.BoolSlice(key, t)
	case []int64:
		return attribute.Int64Slice(key, t)
	case []float64:
		return attribute.Float64Slice(key, t)
	case attribute.Value:
		return attribute.KeyValue{Key: attribute.Key(key), Value: t}
	}
	return attribute.String(key, fmt.Sprint(v))
}

// contentValue is (keep, new value) for one content attribute.
func (p *pipeline) contentValue(kv attribute.KeyValue) (bool, attribute.KeyValue) {
	if !p.captureContent {
		return false, kv
	}
	key := string(kv.Key)
	if p.mask != nil {
		out, err := callMask(p.mask, kv.Value.AsInterface(), key)
		if err != nil {
			pipeCounters.add(&pipeCounters.maskErrors, fmt.Sprintf("mask(%s): %v", key, err))
			return false, kv
		}
		if out == nil {
			return false, kv
		}
		kv = fromAny(key, out)
	}
	if kv.Value.Type() == attribute.STRING && p.maxContentChars > 0 {
		kv = attribute.String(key, truncateText(kv.Value.AsString(), p.maxContentChars))
	}
	return true, kv
}

func callMask(fn func(any, string) (any, error), v any, key string) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("panic: %v", r)
		}
	}()
	return fn(v, key)
}

// rewrite returns new attributes when a content rule changes attrs (nil: no change).
func (p *pipeline) rewrite(attrs []attribute.KeyValue) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(attrs))
	changed := false
	for _, kv := range attrs {
		if !IsContentKey(string(kv.Key)) {
			out = append(out, kv)
			continue
		}
		keep, nkv := p.contentValue(kv)
		if !keep {
			changed = true
			continue
		}
		if nkv.Value != kv.Value {
			changed = true
		}
		out = append(out, nkv)
	}
	if !changed {
		return nil
	}
	return out
}

func (p *pipeline) needsContentRules() bool {
	return !p.captureContent || p.mask != nil || p.maxContentChars > 0
}

func (p *pipeline) applyContentRules(s sdktrace.ReadOnlySpan) sdktrace.ReadOnlySpan {
	if !p.needsContentRules() {
		return s
	}
	newAttrs := p.rewrite(s.Attributes())
	events := s.Events()
	var newEvents []sdktrace.Event
	for i, ev := range events {
		if ea := p.rewrite(ev.Attributes); ea != nil {
			if newEvents == nil {
				newEvents = append([]sdktrace.Event(nil), events...)
			}
			newEvents[i].Attributes = ea
		}
	}
	if newAttrs == nil && newEvents == nil {
		return s
	}
	stub := tracetest.SpanStubFromReadOnlySpan(s)
	if newAttrs != nil {
		stub.Attributes = newAttrs
	}
	if newEvents != nil {
		stub.Events = newEvents
	}
	return stub.Snapshot()
}

func callShouldExport(fn func(sdktrace.ReadOnlySpan) bool, s sdktrace.ReadOnlySpan) (ok bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			ok, err = true, fmt.Errorf("panic: %v", r)
		}
	}()
	return fn(s), nil
}

// decide is the span to hand to the exporter, or nil to drop it (counted).
func (p *pipeline) decide(s sdktrace.ReadOnlySpan) sdktrace.ReadOnlySpan {
	if len(p.dropScopePrefixes) > 0 {
		scope := s.InstrumentationScope().Name
		for _, pre := range p.dropScopePrefixes {
			if scope != "" && strings.HasPrefix(scope, pre) {
				pipeCounters.add(&pipeCounters.vendorSpansDropped, "")
				return nil
			}
		}
	}
	if p.ratioSet && p.exportRatio < 1 && !keepByRatio(s.SpanContext().TraceID(), p.exportRatio) {
		pipeCounters.add(&pipeCounters.sampledOutSpans, "")
		return nil
	}
	if p.shouldExport != nil {
		ok, err := callShouldExport(p.shouldExport, s)
		if err != nil {
			pipeCounters.add(&pipeCounters.shouldExportErrors, "ShouldExport: "+err.Error())
		}
		if !ok {
			pipeCounters.add(&pipeCounters.filteredSpans, "")
			return nil
		}
	}
	return p.applyContentRules(s)
}

// switchableSampler is the sampler of a provider the SDK owns: parent-based
// (or not) trace-id ratio, swappable by a later Init.
type switchableSampler struct {
	inner atomic.Pointer[sdktrace.Sampler]
}

func newSwitchableSampler() *switchableSampler {
	s := &switchableSampler{}
	s.set(1, true)
	return s
}

func (s *switchableSampler) set(rate float64, parentBased bool) {
	var root sdktrace.Sampler
	switch {
	case rate >= 1:
		root = sdktrace.AlwaysSample()
	case rate <= 0:
		root = sdktrace.NeverSample()
	default:
		root = sdktrace.TraceIDRatioBased(rate)
	}
	if parentBased {
		root = sdktrace.ParentBased(root)
	}
	s.inner.Store(&root)
}

func (s *switchableSampler) ShouldSample(p sdktrace.SamplingParameters) sdktrace.SamplingResult {
	return (*s.inner.Load()).ShouldSample(p)
}

func (s *switchableSampler) Description() string {
	return "SuperbasedSampler{" + (*s.inner.Load()).Description() + "}"
}
