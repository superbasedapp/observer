package ratelimitstate

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Window is one reported rate-limit window.
type Window struct {
	// Name identifies the window within its snapshot ("primary" /
	// "secondary" for the codex envelope; the rateLimitType for cowork).
	Name string
	// UsedPercent is 0..100. HasUsed is false when the source reported
	// no utilisation for this window (cowork reports status only).
	UsedPercent float64
	HasUsed     bool
	// WindowMinutes is the declared window length, 0 when unreported.
	WindowMinutes int64
	// ResetsAt is the window's reset instant, unix seconds, 0 when
	// unreported.
	ResetsAt int64
}

// Snapshot is one observed rate-limit state, normalised across source
// shapes. The zero value is a valid, empty snapshot.
type Snapshot struct {
	// LimitID is the rate-limit family (codex limit_id / cowork
	// rateLimitType).
	LimitID string
	// Plan is the subscription plan (codex plan_type). "" when the source
	// reported null or has no plan field.
	Plan string
	// Status is the throttle status: "" / "ok" / "allowed" while not
	// limited, the reached window or a rejected status otherwise.
	Status string
	// OverageStatus / Overage are cowork's overageStatus / isUsingOverage;
	// zero for codex.
	OverageStatus string
	Overage       bool
	// Windows are the reported windows, sorted by Name.
	Windows []Window
}

// UsedPercentEpsilon is the smallest used_percent movement (in percentage
// points) that counts as a change. Codex reports whole percents (every one
// of 53,479 live rows on 2026-09-30 was an integer), so any real tick
// clears it; it exists to absorb float noise if a source ever reports
// fractions.
const UsedPercentEpsilon = 0.5

// ResetTolerance is how far a window's resets_at may move before it counts
// as a change. Codex derives resets_at from a server-side remaining-seconds
// figure, so the same window's reset instant jitters by seconds (and
// occasionally a few minutes) from one token_count to the next — on the
// live corpus 13,096 consecutive same-percent pairs differed by <= 60s and
// 862 more by <= 5 min. A genuine window roll moves it by the window's own
// length (5h / 7d), far beyond this bound.
const ResetTolerance = 10 * time.Minute

// Heartbeat is the longest capture keeps quiet about an UNCHANGED state.
// The limit gauges (internal/sessiongauge via store.LatestRateLimitWindows)
// read the newest rate_limit row and show its age ("observed 3m ago"); a
// change-only stream would let that age grow for hours on a session whose
// limit simply did not move. One row per Heartbeat bounds the reported age
// without reintroducing a row per inference.
const Heartbeat = 15 * time.Minute

// Parse decodes a stored/raw rate-limit envelope into a Snapshot,
// recognising the codex and cowork shapes by their fields. ok is false when
// raw is not JSON or carries neither shape.
func Parse(raw string) (Snapshot, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw[0] != '{' {
		return Snapshot{}, false
	}
	var env struct {
		// codex token_count.rate_limits
		LimitID              *string    `json:"limit_id"`
		Primary              *rawWindow `json:"primary"`
		Secondary            *rawWindow `json:"secondary"`
		PlanType             *string    `json:"plan_type"`
		RateLimitReachedType *string    `json:"rate_limit_reached_type"`
		// cowork rate_limit_info
		Status         *string `json:"status"`
		ResetsAt       *int64  `json:"resetsAt"`
		RateLimitType  *string `json:"rateLimitType"`
		OverageStatus  *string `json:"overageStatus"`
		IsUsingOverage *bool   `json:"isUsingOverage"`
	}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return Snapshot{}, false
	}
	switch {
	case env.LimitID != nil || env.Primary != nil || env.Secondary != nil || env.PlanType != nil:
		s := Snapshot{LimitID: deref(env.LimitID), Plan: deref(env.PlanType), Status: deref(env.RateLimitReachedType)}
		for _, w := range []struct {
			name string
			w    *rawWindow
		}{{"primary", env.Primary}, {"secondary", env.Secondary}} {
			if w.w == nil {
				continue
			}
			s.Windows = append(s.Windows, Window{
				Name: w.name, UsedPercent: w.w.UsedPercent, HasUsed: true,
				WindowMinutes: w.w.WindowMinutes, ResetsAt: w.w.ResetsAt,
			})
		}
		return s, true
	case env.Status != nil || env.RateLimitType != nil:
		s := Snapshot{
			LimitID:       deref(env.RateLimitType),
			OverageStatus: deref(env.OverageStatus),
			Status:        deref(env.Status),
		}
		if env.IsUsingOverage != nil {
			s.Overage = *env.IsUsingOverage
		}
		if env.ResetsAt != nil || env.RateLimitType != nil {
			w := Window{Name: deref(env.RateLimitType)}
			if env.ResetsAt != nil {
				w.ResetsAt = *env.ResetsAt
			}
			s.Windows = []Window{w}
		}
		return s, true
	}
	return Snapshot{}, false
}

type rawWindow struct {
	UsedPercent   float64 `json:"used_percent"`
	WindowMinutes int64   `json:"window_minutes"`
	ResetsAt      int64   `json:"resets_at"`
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// changeRule is one row of the change table: Reason names the rule, Test
// reports whether prev -> cur changed under it.
type changeRule struct {
	Reason string
	Test   func(prev, cur Snapshot) bool
}

// Change reasons, in table order.
const (
	ReasonStatus      = "status"
	ReasonLimit       = "limit"
	ReasonPlan        = "plan"
	ReasonOverage     = "overage"
	ReasonWindows     = "windows"
	ReasonUsedPercent = "used_percent"
	ReasonReset       = "reset"
)

// changeRules is walked top-down; the first matching row names the change.
var changeRules = []changeRule{
	{ReasonStatus, func(p, c Snapshot) bool { return normStatus(p.Status) != normStatus(c.Status) }},
	{ReasonLimit, func(p, c Snapshot) bool { return p.LimitID != c.LimitID }},
	{ReasonPlan, func(p, c Snapshot) bool { return p.Plan != c.Plan }},
	{ReasonOverage, func(p, c Snapshot) bool { return p.Overage != c.Overage || p.OverageStatus != c.OverageStatus }},
	{ReasonWindows, windowSetChanged},
	{ReasonUsedPercent, func(p, c Snapshot) bool {
		return anyWindowPair(p, c, func(a, b Window) bool {
			return a.HasUsed != b.HasUsed || math.Abs(a.UsedPercent-b.UsedPercent) >= UsedPercentEpsilon
		})
	}},
	{ReasonReset, func(p, c Snapshot) bool {
		return anyWindowPair(p, c, func(a, b Window) bool {
			d := a.ResetsAt - b.ResetsAt
			if d < 0 {
				d = -d
			}
			return time.Duration(d)*time.Second > ResetTolerance
		})
	}},
}

// normStatus folds the "not limited" spellings ("" from a JSON null, codex's
// synthesized "ok") onto one value so a null-vs-"ok" difference is never a
// change. Cowork's "allowed" is kept distinct because cowork always reports
// it; a cowork snapshot is never compared against a codex one in practice.
func normStatus(s string) string {
	if s == "ok" {
		return ""
	}
	return s
}

// Change reports the first rule under which cur differs meaningfully from
// prev, or "" when it does not.
func Change(prev, cur Snapshot) string {
	for _, r := range changeRules {
		if r.Test(prev, cur) {
			return r.Reason
		}
	}
	return ""
}

func windowSetChanged(p, c Snapshot) bool {
	pw, cw := windowsByName(p), windowsByName(c)
	if len(pw) != len(cw) {
		return true
	}
	for name, a := range pw {
		b, ok := cw[name]
		if !ok || a.WindowMinutes != b.WindowMinutes {
			return true
		}
	}
	return false
}

func anyWindowPair(p, c Snapshot, differ func(a, b Window) bool) bool {
	cw := windowsByName(c)
	for _, a := range p.Windows {
		if b, ok := cw[a.Name]; ok && differ(a, b) {
			return true
		}
	}
	return false
}

func windowsByName(s Snapshot) map[string]Window {
	m := make(map[string]Window, len(s.Windows))
	for _, w := range s.Windows {
		m[w.Name] = w
	}
	return m
}

// Emit reasons beyond the change reasons.
const (
	ReasonFirst     = "first"
	ReasonHeartbeat = "heartbeat"
)

// emitInput is what one emit rule sees.
type emitInput struct {
	have          bool
	prev, cur     Snapshot
	prevAt, curAt time.Time
}

// emitRule is one row of the capture table. Reason returns the emit reason
// for the row, or "" when it does not fire.
type emitRule struct {
	Name   string
	Reason func(in emitInput) string
}

// emitRules is walked top-down: the first rule with a reason decides.
var emitRules = []emitRule{
	{ReasonFirst, func(in emitInput) string {
		if !in.have {
			return ReasonFirst
		}
		return ""
	}},
	{"change", func(in emitInput) string { return Change(in.prev, in.cur) }},
	{ReasonHeartbeat, func(in emitInput) string {
		if in.prevAt.IsZero() || in.curAt.IsZero() {
			return ""
		}
		if in.curAt.Sub(in.prevAt) >= Heartbeat {
			return ReasonHeartbeat
		}
		return ""
	}},
}

// Tracker is the capture-side emission state: the last EMITTED snapshot
// and its time per stream. A stream is (key, the snapshot's LimitID): key
// is a session id or a capture file, and each limit family is its own
// stream because Codex reports several (codex, codex_bengalfox for the
// Spark model, base_model_inference) and a session mixing models
// alternates between them line by line - comparing across families would
// read every alternation as a change. The zero value is ready to use. A parse that resumes mid-file must seed its Tracker by
// replaying the same Observe calls over the prefix (state only) so the
// resumed parse makes the decisions an uninterrupted one would.
type Tracker struct {
	last map[string]kept
}

type kept struct {
	snap Snapshot
	at   time.Time
}

// Observe decides whether cur (observed at `at`) should be emitted as a
// rate-limit row for key, and records it as the new baseline when it is.
// reason is ReasonFirst, a change reason, ReasonHeartbeat, or "" (skip).
func (t *Tracker) Observe(key string, cur Snapshot, at time.Time) (emit bool, reason string) {
	if t.last == nil {
		t.last = map[string]kept{}
	}
	stream := StreamKey(key, cur)
	prev, have := t.last[stream]
	in := emitInput{have: have, prev: prev.snap, cur: cur, prevAt: prev.at, curAt: at}
	for _, r := range emitRules {
		if reason = r.Reason(in); reason != "" {
			t.last[stream] = kept{snap: cur, at: at}
			return true, reason
		}
	}
	return false, ""
}

// StreamKey names the independent reading stream a snapshot belongs to
// under key: one per limit family (see Tracker).
func StreamKey(key string, s Snapshot) string {
	return key + "\x00" + s.LimitID
}

// Summary renders a snapshot as a short human line, e.g.
// "5h 12% · 7d 40% · plan pro" or "five_hour allowed". Windows are ordered
// shortest first.
func Summary(s Snapshot) string {
	ws := append([]Window(nil), s.Windows...)
	sort.SliceStable(ws, func(i, j int) bool { return ws[i].WindowMinutes < ws[j].WindowMinutes })
	var parts []string
	for _, w := range ws {
		label := w.Name
		if w.WindowMinutes > 0 {
			label = formatMinutes(w.WindowMinutes)
		}
		if w.HasUsed {
			parts = append(parts, fmt.Sprintf("%s %s%%", label, trimFloat(w.UsedPercent)))
		}
	}
	if st := normStatus(s.Status); st != "" {
		if len(parts) == 0 && s.LimitID != "" {
			parts = append(parts, s.LimitID+" "+st)
		} else {
			parts = append(parts, "status "+st)
		}
	}
	if s.Plan != "" {
		parts = append(parts, "plan "+s.Plan)
	}
	if s.OverageStatus != "" {
		parts = append(parts, "overage "+s.OverageStatus)
	}
	if s.Overage {
		parts = append(parts, "using overage")
	}
	return strings.Join(parts, " · ")
}

func formatMinutes(m int64) string {
	switch {
	case m%1440 == 0:
		return fmt.Sprintf("%dd", m/1440)
	case m%60 == 0:
		return fmt.Sprintf("%dh", m/60)
	default:
		return fmt.Sprintf("%dm", m)
	}
}

func trimFloat(f float64) string {
	if f == math.Trunc(f) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%.1f", f)
}
