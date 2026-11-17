package budgetwarn

import (
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Window is one org-authored budget window the node composed, with the spend
// the node measures against it (local spend plus the org's cross-machine
// baseline when that baseline is in force).
type Window struct {
	// Window is "daily" or "monthly"; Unit is "usd" or "tokens".
	Window, Unit string
	// Cap is the org's authored number in Unit.
	Cap float64
	// Spent is the measured spend in Unit for the current period.
	Spent float64
	// Scope is the org scope id ("member:<id>", "team:<id>", "org").
	Scope string
	// Enforcement is the org mode: report | soft | hard.
	Enforcement string
	// Thresholds is the org's warn ladder (fractions of Cap). Empty means
	// the single 100% rung.
	Thresholds []float64
	// Timezone anchors the period (IANA; "" = UTC).
	Timezone string
	// Subject narrows the window to one tool or one model ("tool:<id>",
	// "model:<id>"); empty is the whole caller. A per-tool / per-model org
	// cap is warned at its own rungs, with its own memory (Sol A5-04).
	Subject string
}

// Notice is one crossing of one rung.
type Notice struct {
	// ID is stable for (window, unit, subject, period, threshold): the same
	// crossing always has the same id, so a surface can dedup on it.
	ID          string    `json:"id"`
	Window      string    `json:"window"`
	Unit        string    `json:"unit"`
	Subject     string    `json:"subject,omitempty"`
	Period      string    `json:"period"`
	Threshold   float64   `json:"threshold"`
	Ratio       float64   `json:"ratio"`
	Spent       float64   `json:"spent"`
	Cap         float64   `json:"cap"`
	Scope       string    `json:"scope"`
	Enforcement string    `json:"enforcement"`
	CrossedAt   time.Time `json:"crossed_at"`
	// Level is "warning" below 100% and "exceeded" at or above it.
	Level string `json:"level"`
	// Message is the one-line, developer-facing text every surface shows.
	Message string `json:"message"`
}

// WindowStatus is one window's current reading.
type WindowStatus struct {
	Window  string `json:"window"`
	Unit    string `json:"unit"`
	Subject string `json:"subject,omitempty"`
	Period  string `json:"period"`
	// Timezone is the IANA zone Period is named in ("UTC" for a UTC cap,
	// never empty from Evaluate), so a reader can place the period on the
	// cap's own calendar instead of guessing UTC.
	Timezone    string  `json:"timezone,omitempty"`
	Cap         float64 `json:"cap"`
	Spent       float64 `json:"spent"`
	Ratio       float64 `json:"ratio"`
	Scope       string  `json:"scope"`
	Enforcement string  `json:"enforcement"`
	// Level is "ok", "warning" or "exceeded".
	Level string `json:"level"`
	// Crossed is the highest rung the CURRENT reading is at (0 = none). It is
	// not the announcement memory: a reading that dipped, or a cap an admin
	// raised, reads its current rung here, so no surface calls a window under
	// its cap exceeded or blocked.
	Crossed float64 `json:"crossed"`
}

// State is the node-wide memory of which rung each window already announced
// this period. The boundary persists it beside the status so a restart does
// not re-announce. Key: window|unit|period, plus |subject for a per-tool or
// per-model cap.
type State struct {
	Notified map[string]Notified `json:"notified,omitempty"`
}

// Notified is the highest rung announced for one window-period, and the
// notice that announced it (kept so surfaces can still show the active one).
type Notified struct {
	Threshold float64 `json:"threshold"`
	Notice    Notice  `json:"notice"`
}

// Status is the evaluation result.
type Status struct {
	Windows []WindowStatus `json:"windows"`
	// Active is the highest announced notice of every window in its CURRENT
	// period, highest level first. This is what banners/statuslines show.
	Active []Notice `json:"active,omitempty"`
	// New are the notices first crossed by this evaluation (announce these).
	New []Notice `json:"-"`
}

// defaultLadder is the rung set when the org authored none.
var defaultLadder = []float64{1}

// Evaluate walks every window's ladder. prev is the persisted State; the
// returned State replaces it. now decides the period.
func Evaluate(windows []Window, prev State, now time.Time) (Status, State) {
	next := State{Notified: map[string]Notified{}}
	var st Status
	for _, w := range windows {
		if w.Cap <= 0 || (w.Unit != "usd" && w.Unit != "tokens") {
			continue
		}
		period := PeriodKey(w.Window, w.Timezone, now)
		if period == "" {
			continue
		}
		key := w.Window + "|" + w.Unit + "|" + period
		if w.Subject != "" {
			key += "|" + w.Subject
		}
		ratio := w.Spent / w.Cap
		if math.IsNaN(ratio) || math.IsInf(ratio, 0) || ratio < 0 {
			ratio = 0
		}
		crossed := highestRung(ladder(w.Thresholds), w.Unit, w.Spent, w.Cap)
		ws := WindowStatus{
			Window: w.Window, Unit: w.Unit, Subject: w.Subject, Period: period, Timezone: zoneName(w.Timezone),
			Cap: w.Cap, Spent: w.Spent, Ratio: ratio, Scope: w.Scope, Enforcement: w.Enforcement,
			Level: levelOf(crossed), Crossed: crossed,
		}
		had, seen := prev.Notified[key]
		if seen && crossed < had.Threshold && had.Notice.Cap != w.Cap {
			// The admin moved the cap since the rung was announced (node 1,
			// 2026-10-06: a team cap raised from 1,000,000 to 10,000,000 tokens
			// kept announcing "exceeded" at 11%). The announced rung measured a
			// cap that no longer exists, so the memory follows the CURRENT cap:
			// it drops to the rung the reading is at now, and the higher rungs
			// re-arm against the new cap. A dip with the SAME cap (a baseline
			// that went stale) keeps its memory below, so it never re-announces.
			seen = false
			if crossed > 0 {
				n := noticeFor(w, period, crossed, ratio, now)
				n.CrossedAt = had.Notice.CrossedAt
				next.Notified[key] = Notified{Threshold: crossed, Notice: n}
			}
		}
		switch {
		case crossed > 0 && (!seen || crossed > had.Threshold):
			if _, rearmed := next.Notified[key]; rearmed {
				break
			}
			n := noticeFor(w, period, crossed, ratio, now)
			st.New = append(st.New, n)
			next.Notified[key] = Notified{Threshold: crossed, Notice: n}
		case seen:
			// Keep what was announced this period (a dip in measured spend -
			// a baseline that went stale - must not re-arm the same rung).
			next.Notified[key] = had
		}
		if cur, ok := next.Notified[key]; ok && crossed > 0 {
			// The level, the rung and the sentence every surface shows come
			// from the reading as it is NOW, never from the memory: a window
			// below its cap is never "exceeded", and a hard cap the reading is
			// under is never described as blocking. The memory only decides
			// what is announced (toasts, desktop notices), so a dip does not
			// announce the same rung twice.
			active := cur.Notice
			if crossed < cur.Threshold {
				active = noticeFor(w, period, crossed, ratio, now)
				active.CrossedAt = cur.Notice.CrossedAt
			}
			// The active notice reads the window as it is NOW (an admin may
			// have moved the cap or the mode since the rung was announced),
			// so every surface re-rendering it (RenderMessage under the
			// developer cost display) gets the same sentence.
			active.Ratio, active.Spent = ratio, w.Spent
			active.Cap, active.Scope, active.Enforcement = w.Cap, w.Scope, w.Enforcement
			active.Message = RenderMessage(active, DisplayUSD)
			st.Active = append(st.Active, active)
		}
		st.Windows = append(st.Windows, ws)
	}
	sort.SliceStable(st.Active, func(i, j int) bool {
		if st.Active[i].Threshold != st.Active[j].Threshold {
			return st.Active[i].Threshold > st.Active[j].Threshold
		}
		return st.Active[i].Ratio > st.Active[j].Ratio
	})
	if len(next.Notified) == 0 {
		next.Notified = nil
	}
	return st, next
}

// PeriodKey names the budget period now falls in: the calendar day
// ("2026-10-02") for a daily window, the calendar month ("2026-10") for a
// monthly one, in the window's own timezone (an unknown zone falls back to
// UTC). Any other window has no period here ("").
func PeriodKey(window, tz string, now time.Time) string {
	loc := time.UTC
	if tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		}
	}
	t := now.In(loc)
	switch window {
	case "daily":
		return t.Format("2006-01-02")
	case "monthly":
		return t.Format("2006-01")
	default:
		return ""
	}
}

// zoneName is the zone a period is reported in: "" (the contract's UTC) is
// written out as "UTC", so an empty value on disk can only mean a file from a
// daemon that predates the field.
func zoneName(tz string) string {
	if tz == "" {
		return "UTC"
	}
	return tz
}

// ladder normalises an authored ladder: positive fractions only, ascending,
// de-duplicated; empty means the single 100% rung.
func ladder(in []float64) []float64 {
	out := make([]float64, 0, len(in))
	seen := map[float64]bool{}
	for _, t := range in {
		if t <= 0 || math.IsNaN(t) || math.IsInf(t, 0) || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	if len(out) == 0 {
		return defaultLadder
	}
	sort.Float64s(out)
	return out
}

// highestRung is the largest rung spent has reached against capV (0 = none
// reached), compared exactly (see reachesRung).
func highestRung(rungs []float64, unit string, spent, capV float64) float64 {
	var best float64
	for _, r := range rungs {
		if reachesRung(unit, spent, capV, r) {
			best = r
		}
	}
	return best
}

// unitScale is how many integer units one unit of a window's amount holds for
// the exact comparison: dollars compare in microdollars, tokens are already
// integers.
var unitScale = map[string]float64{"usd": 1e6, "tokens": 1}

// rungScale is the fixed-point resolution of a threshold fraction (parts per
// million: 0.75 is 750000).
const rungScale = 1e6

// reachesRung reports spent >= rung*capV EXACTLY, in fixed point (Sol A5-05).
//
// The float form `spent/capV >= rung` misses exact decimal boundaries: $0.075
// of a $0.10 cap divides to 0.7499999999999999 in binary floating point, so
// the 75% rung announced only after more spend. Each amount is rounded ONCE to
// its canonical integer unit (microdollars, tokens) and the rung to parts per
// million, then the comparison spent*1e6 >= rung*cap runs on integers (big, so
// a large token cap cannot overflow).
func reachesRung(unit string, spent, capV, rung float64) bool {
	scale, ok := unitScale[unit]
	if !ok || !(capV > 0) || !(rung > 0) || math.IsInf(capV, 0) || math.IsInf(rung, 0) ||
		math.IsNaN(spent) || math.IsInf(spent, 0) || spent < 0 {
		return false
	}
	lhs := new(big.Int).Mul(fixedPoint(spent*scale), big.NewInt(rungScale))
	rhs := new(big.Int).Mul(fixedPoint(rung*rungScale), fixedPoint(capV*scale))
	return lhs.Cmp(rhs) >= 0
}

// fixedPoint rounds v to the nearest integer as a big.Int (no int64 overflow
// for an extreme amount). v must be finite.
func fixedPoint(v float64) *big.Int {
	out, _ := new(big.Float).SetFloat64(math.Round(v)).Int(nil)
	return out
}

func levelOf(crossed float64) string {
	switch {
	case crossed >= 1:
		return "exceeded"
	case crossed > 0:
		return "warning"
	default:
		return "ok"
	}
}

func noticeFor(w Window, period string, rung, ratio float64, now time.Time) Notice {
	id := w.Window + "-" + w.Unit + "-"
	if w.Subject != "" {
		id += w.Subject + "-"
	}
	n := Notice{
		ID:     id + period + "-" + strconv.FormatFloat(rung, 'f', -1, 64),
		Window: w.Window, Unit: w.Unit, Subject: w.Subject, Period: period, Threshold: rung, Ratio: ratio,
		Spent: w.Spent, Cap: w.Cap, Scope: w.Scope, Enforcement: w.Enforcement,
		CrossedAt: now.UTC(), Level: levelOf(rung),
	}
	n.Message = RenderMessage(n, DisplayUSD)
	return n
}

// The developer cost-display vocabulary (orgcontract.DisplayCostUSD /
// DisplayCostTokens, restated: this package is pure). The org admin chooses
// whether developers see dollar costs or only token usage (operator ruling
// 2026-10-02); the node resolves that choice once
// (store.ResolveDeveloperCostDisplay) and every developer surface renders
// through RenderMessage / StatusLabel with it.
const (
	DisplayUSD    = "usd"
	DisplayTokens = "tokens"
)

// hidesAmount reports whether a figure in unit must not be shown under
// display: token mode hides DOLLAR amounts. A token cap's amounts are token
// usage, which is exactly what token mode shows, so they stay.
func hidesAmount(unit, display string) bool {
	return display == DisplayTokens && unit != "tokens"
}

// RenderMessage renders the developer-facing line for a notice under the
// node's cost display:
//
//	usd:    "Org daily budget (you, warning only): 96% used - $0.72 of $0.75. Requests are not blocked."
//	tokens: "Org daily budget (you, warning only): 96% used of the budget. Requests are not blocked."
//
// A token-denominated cap reads the same in both modes ("960,000 tokens of
// 1,200,000 tokens"). A dollar amount is never converted into tokens: that
// would fabricate a number.
func RenderMessage(n Notice, display string) string {
	var b strings.Builder
	b.WriteString("Org ")
	b.WriteString(n.Window)
	b.WriteString(" budget")
	if label := SubjectLabel(n.Subject); label != "" {
		b.WriteString(" for ")
		b.WriteString(label)
	}
	b.WriteString(" (")
	b.WriteString(ScopeLabel(n.Scope))
	b.WriteString(", ")
	b.WriteString(EnforcementLabel(n.Enforcement))
	b.WriteString("): ")
	b.WriteString(strconv.Itoa(int(math.Round(n.Ratio * 100))))
	if hidesAmount(n.Unit, display) {
		b.WriteString("% used of the budget. ")
	} else {
		b.WriteString("% used - ")
		b.WriteString(Amount(n.Unit, n.Spent))
		b.WriteString(" of ")
		b.WriteString(Amount(n.Unit, n.Cap))
		b.WriteString(". ")
	}
	rung := n.Threshold
	switch {
	case n.Enforcement == "hard" && rung >= 1:
		b.WriteString("Further proxied requests, and the next prompt or tool call in tools with a pre-send hook, are blocked until the period resets or an admin raises the cap.")
	case n.Enforcement == "hard":
		b.WriteString("Requests will be blocked at 100%.")
	default:
		b.WriteString("Requests are not blocked.")
	}
	return b.String()
}

// StatusLabel renders the short statusline form of one window at a warn rung
// under the node's cost display:
//
//	usd:    "budget 168% of $0.75/day"
//	tokens: "budget 168%" (a dollar cap), "budget 80% of 1,200,000 tokens/day" (a token cap)
//
// with " (blocked)" when a hard cap is exhausted.
func StatusLabel(window, unit string, capV, ratio float64, enforcement string, crossed float64, display string) string {
	label := "budget " + strconv.Itoa(int(math.Round(ratio*100))) + "%"
	if !hidesAmount(unit, display) {
		per := "/day"
		if window == "monthly" {
			per = "/mo"
		}
		label += " of " + Amount(unit, capV) + per
	}
	if enforcement == "hard" && crossed >= 1 {
		label += " (blocked)"
	}
	return label
}

// Amount renders a spend in its unit ("$0.72", "960,000 tokens").
func Amount(unit string, v float64) string {
	if unit == "tokens" {
		return groupThousands(int64(math.Round(v))) + " tokens"
	}
	// no-bare-usd:allow (dollar view only; the token display renders shares of the cap)
	return "$" + strconv.FormatFloat(v, 'f', 2, 64)
}

func groupThousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

// SubjectLabel renders a window subject ("tool:claude-code" -> "tool
// claude-code", "model:gpt-5" -> "model gpt-5"); "" for the whole caller.
func SubjectLabel(subject string) string {
	kind, id, ok := strings.Cut(subject, ":")
	if !ok || id == "" {
		return subject
	}
	return kind + " " + id
}

// ScopeLabel renders an org scope id in the developer's terms.
func ScopeLabel(scope string) string {
	kind := scope
	if i := strings.IndexByte(scope, ':'); i >= 0 {
		kind = scope[:i]
	}
	switch kind {
	case "member", "developer":
		return "you"
	case "team":
		return "your team"
	case "", "org", "organization":
		return "your organization"
	default:
		return kind
	}
}

// EnforcementLabel renders the org enforcement mode.
func EnforcementLabel(mode string) string {
	switch mode {
	case "hard":
		return "blocking"
	case "soft":
		return "warning only"
	default:
		return "report only"
	}
}
