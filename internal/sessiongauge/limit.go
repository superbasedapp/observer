package sessiongauge

import (
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Limit gauge sources, the vocabulary of LimitGauge.Source.
const (
	// LimitSourceProxy: the provider's own rate-limit response headers, read
	// by the Observer proxy (the node's limit_snapshots).
	LimitSourceProxy = "proxy"
	// LimitSourceTranscript: the tool's own session log (codex token_count
	// rate_limits).
	LimitSourceTranscript = "transcript"
)

// Window is one observation of a provider's subscription windows. The
// pointer fields are nil where the provider sent no such window.
type Window struct {
	ObservedAt    time.Time
	Window5hUtil  *float64
	Window5hReset *int64
	Window7dUtil  *float64
	Window7dReset *int64
}

// hasWindow reports whether the observation carries either window.
func (w *Window) hasWindow() bool {
	return w != nil && (w.Window5hUtil != nil || w.Window7dUtil != nil)
}

// LimitInput is everything the limit ladder reads.
type LimitInput struct {
	// Tool is the session's tool; its internal/integration Limit capability
	// decides the audited no-source short-circuit.
	Tool string
	// Proxy is the newest proxy-captured observation for the session tool's
	// provider, attributed to that tool (nil = none recorded).
	Proxy *Window
	// Transcript is the newest window the tool's own transcript recorded
	// (nil = none, or a surface that cannot read transcript windows).
	Transcript *Window
	// Now anchors ObservedAge.
	Now time.Time
}

// LimitGauge is the rate-limit / subscription-window gauge.
//
// Three, mutually exclusive, unavailable outcomes - each with a DIFFERENT
// remedy, so each gets its own flag rather than one shared "unavailable":
//   - NeedsProxy: no observation at all yet, but routing this tool through
//     the Observer proxy WOULD produce one.
//   - NoWindow: an observation exists but carried no subscription window
//     (classic per-minute headers only). Nothing the operator does unlocks
//     it.
//   - NoSource: an AUDITED registry finding (internal/integration
//     Capability.Limit) that no local signal can ever exist for this tool;
//     SourceNote carries the reason. Never falls into NeedsProxy.
type LimitGauge struct {
	Available  bool   `json:"available"`
	NeedsProxy bool   `json:"needs_proxy"`
	NoWindow   bool   `json:"no_window,omitempty"`
	NoSource   bool   `json:"no_source,omitempty"`
	SourceNote string `json:"source_note,omitempty"`
	// ObservedAge is a human-readable staleness hint ("2m ago").
	ObservedAge string `json:"observed_age,omitempty"`
	// Source is LimitSourceProxy or LimitSourceTranscript; empty while
	// unavailable.
	Source         string   `json:"source,omitempty"`
	Window5hUtil   *float64 `json:"window_5h_util,omitempty"`
	Window5hReset  *int64   `json:"window_5h_reset,omitempty"`
	Window7dUtil   *float64 `json:"window_7d_util,omitempty"`
	Window7dReset  *int64   `json:"window_7d_reset,omitempty"`
	ObservedAtUnix *int64   `json:"observed_at_unix,omitempty"`
}

// Limit walks the gauge ladder:
//
//  1. an audited no-local-source registry finding short-circuits to NoSource;
//  2. the newest proxy observation with a window is the gauge (source proxy);
//  3. otherwise the newest transcript observation with a window is (source
//     transcript);
//  4. otherwise a proxy observation without a window is NoWindow, and no
//     observation at all is NeedsProxy.
func Limit(in LimitInput) LimitGauge {
	if ic, ok := integration.For(in.Tool); ok && ic.Limit.Source != integration.LimitSourceUnaudited {
		return LimitGauge{NoSource: true, SourceNote: ic.Limit.Note}
	}
	if in.Proxy.hasWindow() {
		return available(LimitSourceProxy, in.Proxy, in.Now)
	}
	if in.Transcript.hasWindow() {
		return available(LimitSourceTranscript, in.Transcript, in.Now)
	}
	if in.Proxy != nil {
		return LimitGauge{NoWindow: true, ObservedAge: observedAge(in.Proxy.ObservedAt, in.Now)}
	}
	return LimitGauge{NeedsProxy: true}
}

// available is the populated gauge for one observation.
func available(source string, w *Window, now time.Time) LimitGauge {
	g := LimitGauge{
		Available:     true,
		Source:        source,
		Window5hUtil:  w.Window5hUtil,
		Window5hReset: w.Window5hReset,
		Window7dUtil:  w.Window7dUtil,
		Window7dReset: w.Window7dReset,
		ObservedAge:   observedAge(w.ObservedAt, now),
	}
	if !w.ObservedAt.IsZero() {
		u := w.ObservedAt.Unix()
		g.ObservedAtUnix = &u
	}
	return g
}

// observedAge is HumanizeAge of now-t, "" when t is unknown.
func observedAge(t, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	return HumanizeAge(now.Sub(t))
}

// HumanizeAge renders a short staleness string for the gauge.
func HumanizeAge(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

// ProviderForTool maps a tool to the upstream provider its limit
// observations are keyed by: the OpenAI-family tools, else anthropic (the
// common proxied case). This is the mapping the node gauge has always used,
// moved here so the node and the org share ONE copy of it.
func ProviderForTool(tool string) string {
	switch tool {
	case "codex", "copilot", "copilot-cli":
		return "openai"
	default:
		return "anthropic"
	}
}
