package cloudmetrics

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Process selects which metric families a Registry renders: the serve
// process's (audit events, webhook deliveries, binding refusals) or the
// worker's (deletion blocks). One registry per process; a family the process
// never feeds is not rendered, so a scrape of the worker shows no audit zeros.
type Process string

// The two processes.
const (
	ProcessAPI    Process = "api"
	ProcessWorker Process = "worker"
)

// The metric names (the closed set; HELP and TYPE in metricInfo).
const (
	MetricAuditEvents          = "sbci_audit_events_total"
	MetricAuditRowsSuppressed  = "sbci_audit_rows_suppressed_total"
	MetricWebhookDeliveries    = "sbci_paddle_webhook_deliveries_total"
	MetricBindingRefused       = "sbci_paddle_binding_refused_total"
	MetricDeletionBlocked      = "sbci_deletion_blocked_total"
	MetricDeletionBlockedOpen  = "sbci_deletion_blocked_open"
	MetricDeletionOpenReadOK   = "sbci_deletion_blocked_open_read_ok"
	metricLabelEvent           = "event"
	metricLabelResult          = "result"
	metricLabelReason          = "reason"
	metricLabelPriceKnown      = "price_known"
	metricLabelKind            = "kind"
	metricTypeCounter          = "counter"
	metricTypeGauge            = "gauge"
	deletionOpenReadUnknownVal = -1
)

type metricInfo struct {
	name, help, typ string
	process         Process
}

// metrics is the render order and the HELP/TYPE of every family.
var metrics = []metricInfo{
	{MetricAuditEvents, "Security audit events the API recorded through audit(), by event name (closed vocabulary; suppressed rows included).", metricTypeCounter, ProcessAPI},
	{MetricAuditRowsSuppressed, "Audit rows not written because an identical row from the same source was written inside the event's window (counted in sbci_audit_events_total and carried on the next written row).", metricTypeCounter, ProcessAPI},
	{MetricWebhookDeliveries, "Paddle webhook deliveries by result (accepted, refused, failed) and closed reason.", metricTypeCounter, ProcessAPI},
	{MetricBindingRefused, "Paddle subscription bindings refused, by closed reason and whether the price is one this deployment sells.", metricTypeCounter, ProcessAPI},
	{MetricDeletionBlocked, "Org deletions and account follow-ups the deletion driver blocked, by kind and closed reason.", metricTypeCounter, ProcessWorker},
	{MetricDeletionBlockedOpen, "Deletion requests currently blocked, by kind (refreshed every driver pass).", metricTypeGauge, ProcessWorker},
	{MetricDeletionOpenReadOK, "1 when the last blocked-deletion count read succeeded, 0 when it failed, -1 before the first read.", metricTypeGauge, ProcessWorker},
}

// series is one rendered line's identity: the metric and its label pairs.
type series struct {
	metric string
	labels string // rendered `k="v",...`, already escaped
}

// Registry is one process's counters and gauges. The zero value is not
// usable; build it with New. Every method is safe for concurrent use and
// a no-op on a nil *Registry, so an unwired caller needs no guard.
type Registry struct {
	process Process
	mu      sync.Mutex
	values  map[series]float64
	// seeded is the render order of the zero-seeded series (built once).
	seeded []series
}

// New returns the registry of p with every closed series seeded at zero.
func New(p Process) *Registry {
	r := &Registry{process: p, values: map[series]float64{}}
	add := func(metric string, kv ...string) {
		s := series{metric: metric, labels: renderLabels(kv...)}
		r.seeded = append(r.seeded, s)
		r.values[s] = 0
	}
	switch p {
	case ProcessAPI:
		for _, e := range AuditEventLabels() {
			add(MetricAuditEvents, metricLabelEvent, e)
		}
		for _, e := range AuditEventLabels() {
			add(MetricAuditRowsSuppressed, metricLabelEvent, e)
		}
		for _, res := range webhookResults {
			for _, reason := range webhookReasons[res] {
				add(MetricWebhookDeliveries, metricLabelResult, res, metricLabelReason, reason)
			}
		}
		for _, reason := range bindingRefusalReasons {
			for _, known := range []string{"false", "true"} {
				add(MetricBindingRefused, metricLabelReason, reason, metricLabelPriceKnown, known)
			}
		}
	case ProcessWorker:
		for _, k := range deletionKinds {
			for _, reason := range deletionBlockReasons {
				add(MetricDeletionBlocked, metricLabelKind, k, metricLabelReason, reason)
			}
		}
		for _, k := range deletionKinds {
			add(MetricDeletionBlockedOpen, metricLabelKind, k)
		}
		add(MetricDeletionOpenReadOK)
		r.values[series{metric: MetricDeletionOpenReadOK}] = deletionOpenReadUnknownVal
	}
	return r
}

func (r *Registry) inc(metric string, kv ...string) {
	if r == nil {
		return
	}
	s := series{metric: metric, labels: renderLabels(kv...)}
	r.mu.Lock()
	r.values[s]++
	r.mu.Unlock()
}

func (r *Registry) set(metric string, v float64, kv ...string) {
	if r == nil {
		return
	}
	s := series{metric: metric, labels: renderLabels(kv...)}
	r.mu.Lock()
	r.values[s] = v
	r.mu.Unlock()
}

// AuditEvent counts one audit() event (written or suppressed).
func (r *Registry) AuditEvent(event string) {
	r.inc(MetricAuditEvents, metricLabelEvent, AuditEventLabel(event))
}

// AuditRowSuppressed counts one audit row the rate limit did not write.
func (r *Registry) AuditRowSuppressed(event string) {
	r.inc(MetricAuditRowsSuppressed, metricLabelEvent, AuditEventLabel(event))
}

// WebhookDelivery counts one Paddle webhook delivery (labels normalized by
// WebhookLabels).
func (r *Registry) WebhookDelivery(result, reason string) {
	res, why := WebhookLabels(result, reason)
	r.inc(MetricWebhookDeliveries, metricLabelResult, res, metricLabelReason, why)
}

// BindingRefused counts one refused Paddle binding.
func (r *Registry) BindingRefused(reason string, priceKnown bool) {
	r.inc(MetricBindingRefused, metricLabelReason, BindingRefusalLabel(reason), metricLabelPriceKnown, strconv.FormatBool(priceKnown))
}

// DeletionBlocked counts one request the deletion driver blocked.
func (r *Registry) DeletionBlocked(kind, reason string) {
	k, why := DeletionBlockLabels(kind, reason)
	r.inc(MetricDeletionBlocked, metricLabelKind, k, metricLabelReason, why)
}

// SetDeletionsBlockedOpen records the current blocked counts (a successful
// read).
func (r *Registry) SetDeletionsBlockedOpen(orgs, followups int) {
	r.set(MetricDeletionBlockedOpen, float64(orgs), metricLabelKind, "org")
	r.set(MetricDeletionBlockedOpen, float64(followups), metricLabelKind, "account")
	r.set(MetricDeletionOpenReadOK, 1)
}

// DeletionsBlockedOpenReadFailed records a failed count read; the counts keep
// their last value.
func (r *Registry) DeletionsBlockedOpenReadFailed() {
	r.set(MetricDeletionOpenReadOK, 0)
}

// Value returns one series' current value (for tests and diagnostics); the
// label pairs are given as k, v, ... and are not normalized.
func (r *Registry) Value(metric string, kv ...string) float64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.values[series{metric: metric, labels: renderLabels(kv...)}]
}

// Render writes the Prometheus text exposition of the process's families:
// the seeded series in table order, then any other series a normalized
// input produced (an "other" kind, say), sorted.
func (r *Registry) Render(w io.Writer) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	vals := make(map[series]float64, len(r.values))
	for k, v := range r.values {
		vals[k] = v
	}
	r.mu.Unlock()

	seen := make(map[series]bool, len(r.seeded))
	var b strings.Builder
	for _, m := range metrics {
		if m.process != r.process {
			continue
		}
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", m.name, m.help, m.name, m.typ)
		for _, s := range r.seeded {
			if s.metric == m.name {
				writeSample(&b, s, vals[s])
				seen[s] = true
			}
		}
		var extra []series
		for s := range vals {
			if s.metric == m.name && !seen[s] {
				extra = append(extra, s)
			}
		}
		slices.SortFunc(extra, func(a, c series) int { return strings.Compare(a.labels, c.labels) })
		for _, s := range extra {
			writeSample(&b, s, vals[s])
		}
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("cloudmetrics.Render: %w", err)
	}
	return nil
}

func writeSample(b *strings.Builder, s series, v float64) {
	b.WriteString(s.metric)
	if s.labels != "" {
		b.WriteByte('{')
		b.WriteString(s.labels)
		b.WriteByte('}')
	}
	if v == float64(int64(v)) {
		fmt.Fprintf(b, " %d\n", int64(v))
		return
	}
	fmt.Fprintf(b, " %g\n", v)
}

// renderLabels renders k, v, ... pairs as `k="v",...`, escaping each value
// (the ONE escape point). Label names are this package's constants.
func renderLabels(kv ...string) string {
	if len(kv) == 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, kv[i], escapeLabelValue(kv[i+1]))
	}
	return b.String()
}

// escapeLabelValue escapes a label value per the text exposition format:
// backslash first, then double quote, then newline.
func escapeLabelValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return strings.ReplaceAll(v, "\n", `\n`)
}
