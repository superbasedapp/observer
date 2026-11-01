package planlimits

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"
)

// Rung is the D-640 collection ladder rung a number came from.
type Rung string

// The ladder rungs. Rung 1 is the default; rungs 2 and 3 are per-provider
// opt-in and labelled experimental. Rung 3 is a browser session the user
// pastes (D-640 "then codexbar"); Observer never reads a browser's own cookie
// store.
const (
	RungOfficial     Rung = "official"
	RungExperimental Rung = "experimental"
	RungBrowser      Rung = "browser"
)

// SourceKind is the concrete collection method (closed set).
type SourceKind string

// The closed set of source kinds.
const (
	KindOfficialAPI   SourceKind = "official_api"   // the user's own key, documented endpoint
	KindAdminAPI      SourceKind = "admin_api"      // a management key, documented endpoint
	KindStatusLine    SourceKind = "status_line"    // Claude Code status line stdin JSON (documented)
	KindVendorRPC     SourceKind = "vendor_rpc"     // a vendor's documented local RPC (codex app-server)
	KindVendorCLI     SourceKind = "vendor_cli"     // a vendor CLI prints its own usage
	KindPassiveProxy  SourceKind = "passive_proxy"  // headers Observer's proxy already captured
	KindPassiveLog    SourceKind = "passive_log"    // limits a tool already wrote into its own logs
	KindManual        SourceKind = "manual"         // plan facts the user typed (estimated)
	KindLocalState    SourceKind = "local_state"    // rung 2: a vendor app's non-credential local state
	KindBorrowedToken SourceKind = "borrowed_token" // rung 2: another app's token, read-only
	KindUndocumented  SourceKind = "undocumented"   // rung 2: the user's own key, undocumented endpoint
	KindBrowser       SourceKind = "browser"        // rung 3: a browser session the user pastes
)

// rungOf binds each source kind to its ladder rung. A source never picks its
// own rung: this table decides (CLAUDE.md rule 5).
var rungOf = map[SourceKind]Rung{
	KindOfficialAPI:   RungOfficial,
	KindAdminAPI:      RungOfficial,
	KindStatusLine:    RungOfficial,
	KindVendorRPC:     RungOfficial,
	KindVendorCLI:     RungOfficial,
	KindPassiveProxy:  RungOfficial,
	KindPassiveLog:    RungOfficial,
	KindManual:        RungOfficial,
	KindLocalState:    RungExperimental, // D-642: Windsurf cached plan info stays experimental opt-in
	KindBorrowedToken: RungExperimental,
	KindUndocumented:  RungExperimental,
	KindBrowser:       RungBrowser,
}

// RungOf returns the ladder rung for a source kind, or "" when unknown.
func RungOf(k SourceKind) Rung { return rungOf[k] }

// AllKinds lists every source kind, for coverage tests.
func AllKinds() []SourceKind {
	return []SourceKind{
		KindOfficialAPI, KindAdminAPI, KindStatusLine, KindVendorRPC, KindVendorCLI,
		KindPassiveProxy, KindPassiveLog, KindManual, KindLocalState, KindBorrowedToken, KindUndocumented, KindBrowser,
	}
}

// Confidence says how exact a number is.
type Confidence string

// Confidence values.
const (
	ConfExact       Confidence = "exact"
	ConfEstimated   Confidence = "estimated"
	ConfPercentOnly Confidence = "percent_only"
	ConfUnknown     Confidence = "unknown"
)

// Unit is the unit of a window, balance or spend. Units never mix in one sum.
type Unit string

// Units. Money is integer micros of one currency; credits are never
// converted to money.
const (
	UnitPercent    Unit = "percent"
	UnitCredits    Unit = "credits"
	UnitUSDMicros  Unit = "usd_micros"
	UnitCNYMicros  Unit = "cny_micros"
	UnitEURMicros  Unit = "eur_micros"
	UnitJPYMicros  Unit = "jpy_micros"
	UnitRequests   Unit = "requests"
	UnitTokens     Unit = "tokens"
	UnitAICredits  Unit = "ai_credits"
	UnitPoints     Unit = "points"
	UnitCharacters Unit = "characters"
	UnitKWh        Unit = "kwh"
	UnitHours      Unit = "hours"
)

// AllUnits lists every unit, for vocabulary tests.
func AllUnits() []Unit {
	return []Unit{
		UnitPercent, UnitCredits, UnitUSDMicros, UnitCNYMicros, UnitEURMicros, UnitJPYMicros,
		UnitRequests, UnitTokens, UnitAICredits, UnitPoints, UnitCharacters, UnitKWh, UnitHours,
	}
}

// moneyUnits are the units that are an amount of money.
var moneyUnits = map[Unit]bool{UnitUSDMicros: true, UnitCNYMicros: true, UnitEURMicros: true, UnitJPYMicros: true}

// IsMoney reports whether u is an amount of money (integer micros).
func IsMoney(u Unit) bool { return moneyUnits[u] }

// Status codes of a snapshot or an account. Codes, never prose: the
// dashboard and the CLI own the words.
const (
	StatusOK           = "ok"
	StatusThrottled    = "throttled" // the vendor says the limit is reached
	StatusPlanOnly     = "plan_only" // the plan is known but has no meter (managed seat)
	StatusUnmetered    = "unmetered" // the plan reports no metered quota
	StatusBilledElse   = "billed_elsewhere"
	StatusAuthNeeded   = "auth_needed" // sign in again / replace the key
	StatusError        = "error"       // a transient failure; the last good reading stays
	StatusEndpointGone = "endpoint_changed"
	StatusStale        = "stale"
	StatusNotOptedIn   = "not_opted_in"
	StatusSkipped      = "skipped" // the ladder did not need this source
)

// Window is one usage window. A nil pointer means unknown, never zero.
type Window struct {
	// Key names the window: 5h | daily | weekly | monthly | cycle | key_cap |
	// spend_limit | extra_usage | model:<id> | <prefix>:<id>.
	Key       string         `json:"key"`
	Unit      Unit           `json:"unit"`
	Used      *float64       `json:"used,omitempty"`
	Limit     *float64       `json:"limit,omitempty"`
	Remaining *float64       `json:"remaining,omitempty"`
	UsedFrac  *float64       `json:"used_frac,omitempty"` // 0..1; may exceed 1 over a spend limit
	ResetsAt  *time.Time     `json:"resets_at,omitempty"`
	Length    *time.Duration `json:"length_ns,omitempty"`
	Rolling   bool           `json:"rolling,omitempty"`
}

// Balance is a prepaid, granted or pooled amount. Money is integer micros.
type Balance struct {
	// Kind is prepaid | granted | topup | voucher | cash | total | posted |
	// credits | workspace_pool | included_used.
	Kind   string `json:"kind"`
	Unit   Unit   `json:"unit"`
	Amount int64  `json:"amount"` // may be negative (a deficit)
}

// Spend is spend over a period (running or closed).
type Spend struct {
	Period string `json:"period"` // day | week | month | cycle | all_time
	Unit   Unit   `json:"unit"`
	Amount int64  `json:"amount"`
	Scope  string `json:"scope"` // key | account | team
}

// Snapshot is one observation of one provider account.
type Snapshot struct {
	Provider   string     `json:"provider"`
	Source     string     `json:"source"` // a Sources id ("" for an ad-hoc mapping)
	Kind       SourceKind `json:"kind"`
	Rung       Rung       `json:"rung"`
	Confidence Confidence `json:"confidence"`
	PlanLabel  string     `json:"plan_label,omitempty"` // vendor wording, sanitized and capped
	PlanCode   string     `json:"plan_code,omitempty"`
	ObservedAt time.Time  `json:"observed_at"`
	Windows    []Window   `json:"windows,omitempty"`
	Balances   []Balance  `json:"balances,omitempty"`
	Spend      []Spend    `json:"spend,omitempty"`
	Status     string     `json:"status"`
}

// newSnap returns a snapshot with the rung filled from the kind table.
func newSnap(provider, source string, kind SourceKind, conf Confidence, at time.Time) Snapshot {
	return Snapshot{Provider: provider, Source: source, Kind: kind, Rung: RungOf(kind), Confidence: conf, ObservedAt: at.UTC(), Status: StatusOK}
}

// F returns a pointer to v.
func F(v float64) *float64 { return &v }

// fracFromPercent converts a 0..100 percentage to a 0..1 fraction pointer.
func fracFromPercent(p float64) *float64 { return F(p / 100) }

// unixPtr converts epoch seconds to a time pointer; nil when sec <= 0.
func unixPtr(sec int64) *time.Time {
	if sec <= 0 {
		return nil
	}
	t := time.Unix(sec, 0).UTC()
	return &t
}

// dur returns a duration pointer.
func dur(d time.Duration) *time.Duration { return &d }

// microsFromFloat converts a decimal money float to integer micros.
func microsFromFloat(v float64) int64 { return int64(math.Round(v * 1e6)) }

// MicrosFromDecimal converts a decimal string ("110.00", "-4500") to micros
// without float rounding. scale is the power of ten the string is already in
// relative to the unit (0 for dollars, 2 for cents: "1000" cents = 10 dollars).
func MicrosFromDecimal(s string, scale int) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("planlimits.MicrosFromDecimal: empty")
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return 0, fmt.Errorf("planlimits.MicrosFromDecimal: bad decimal %q", s)
	}
	r.Mul(r, big.NewRat(1_000_000, 1))
	if scale > 0 {
		r.Quo(r, new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil)))
	}
	if !r.IsInt() {
		f, _ := r.Float64()
		return int64(math.Round(f)), nil
	}
	if !r.Num().IsInt64() {
		return 0, fmt.Errorf("planlimits.MicrosFromDecimal: %q out of range", s)
	}
	return r.Num().Int64(), nil
}

// CurrencyUnit maps an ISO currency code to a money unit; "" when unsupported.
func CurrencyUnit(code string) Unit {
	return currencyUnits[strings.ToUpper(strings.TrimSpace(code))]
}

// currencyUnits maps ISO currency codes to money units.
var currencyUnits = map[string]Unit{"USD": UnitUSDMicros, "CNY": UnitCNYMicros, "RMB": UnitCNYMicros, "EUR": UnitEURMicros, "JPY": UnitJPYMicros}

// maxPlanLabel caps a vendor-supplied plan label.
const maxPlanLabel = 64

// SanitizeLabel keeps a vendor-supplied label printable and short: control
// characters are dropped and the result is capped.
func SanitizeLabel(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= maxPlanLabel {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// Validate checks the invariants every mapping must keep: the rung matches
// the kind table, manual numbers are estimated, an ok snapshot carries
// numbers, windows are keyed, unique, in range and carry a reading.
func Validate(s Snapshot) error {
	if s.Provider == "" {
		return errors.New("planlimits.Validate: provider missing")
	}
	if s.Rung == "" || s.Rung != RungOf(s.Kind) {
		return fmt.Errorf("planlimits.Validate: rung %q does not match kind %q", s.Rung, s.Kind)
	}
	if s.Kind == KindManual && s.Confidence != ConfEstimated {
		return errors.New("planlimits.Validate: manual numbers must be estimated")
	}
	if len(s.Windows)+len(s.Balances)+len(s.Spend) == 0 && s.Status == StatusOK {
		return errors.New("planlimits.Validate: ok snapshot with no numbers")
	}
	seen := map[string]bool{}
	for _, w := range s.Windows {
		if w.Key == "" || w.Unit == "" {
			return fmt.Errorf("planlimits.Validate: window missing key/unit: %+v", w)
		}
		if seen[w.Key] {
			return fmt.Errorf("planlimits.Validate: duplicate window %q", w.Key)
		}
		seen[w.Key] = true
		if w.UsedFrac != nil && (math.IsNaN(*w.UsedFrac) || *w.UsedFrac < 0 || *w.UsedFrac > 2) {
			return fmt.Errorf("planlimits.Validate: window %q fraction %v out of range", w.Key, *w.UsedFrac)
		}
		if w.Used == nil && w.UsedFrac == nil && w.Remaining == nil && w.Limit == nil {
			return fmt.Errorf("planlimits.Validate: window %q carries no reading", w.Key)
		}
	}
	for _, b := range s.Balances {
		if b.Kind == "" || b.Unit == "" {
			return fmt.Errorf("planlimits.Validate: balance missing kind/unit: %+v", b)
		}
	}
	return nil
}

// FindWindow returns the window with key k.
func FindWindow(s Snapshot, k string) (Window, bool) {
	for _, w := range s.Windows {
		if w.Key == k {
			return w, true
		}
	}
	return Window{}, false
}

// FindBalance returns the first balance of kind k.
func FindBalance(s Snapshot, k string) (Balance, bool) {
	for _, b := range s.Balances {
		if b.Kind == k {
			return b, true
		}
	}
	return Balance{}, false
}

// usedFrac returns the window's used fraction, deriving it from amounts when
// the source gave amounts only. ok=false when it cannot be known.
func usedFrac(w Window) (float64, bool) {
	if w.UsedFrac != nil {
		return *w.UsedFrac, true
	}
	if w.Limit != nil && *w.Limit > 0 {
		if w.Used != nil {
			return *w.Used / *w.Limit, true
		}
		if w.Remaining != nil {
			return (*w.Limit - *w.Remaining) / *w.Limit, true
		}
	}
	return 0, false
}
