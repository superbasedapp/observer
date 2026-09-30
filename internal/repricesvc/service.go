package repricesvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/reprice"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// maxModels caps the per-model breakdown a plan reports (top by |delta|).
const maxModels = 20

// Pricing sources a [PricingInfo] names.
const (
	PricingSourceOrg  = "org"
	PricingSourceFeed = "feed"
	PricingSourceSeed = "seed"
)

// PricingInfo describes the price table a plan prices under. It is part of
// the digest: a price document that moved between the dry run and the apply
// changes the digest even when the totals happen not to.
type PricingInfo struct {
	// Source is org | feed | seed.
	Source string `json:"source"`
	// Version is the org document or public feed version (0 for seed).
	Version int64 `json:"version"`
	// Description is one honest human sentence naming the table in force.
	Description string `json:"description"`
}

// Store is the slice of *store.Store the service uses (so tests can fake it
// and the dependency direction stays visible).
type Store interface {
	ScanRepriceRows(ctx context.Context, f store.RepriceFilter, fn func(reprice.Row) error) error
	ApplyReprice(ctx context.Context, meta store.RepriceRunMeta, updates []reprice.Decision) (store.RepriceRun, error)
	RevertReprice(ctx context.Context, runID int64, actor string) (store.RepriceRun, error)
	ListRepriceRuns(ctx context.Context, limit int) ([]store.RepriceRun, error)
	RepriceOrgParityFor(ctx context.Context, changes []reprice.Decision) (store.RepriceOrgParity, error)
}

// Filter is a re-price window as the operator typed it. Since / Until accept
// "" (unbounded), YYYY-MM-DD, RFC3339, or "Nd" (N days before now). An
// instant Until is EXCLUSIVE; a bare-date Until covers that whole UTC day
// (since=until=2026-09-01 is that one day), the same reading the org's
// re-price gives a date, so one window means the same rows on both. Model is
// an exact stored model id.
type Filter struct {
	Since string `json:"since,omitempty"`
	Until string `json:"until,omitempty"`
	Model string `json:"model,omitempty"`
}

// ErrBadFilter wraps every filter parse failure.
var ErrBadFilter = errors.New("invalid re-price filter")

// ParseBound parses one window bound (see [Filter]). An empty string is the
// zero time (unbounded).
func ParseBound(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err == nil {
			if n < 0 {
				return time.Time{}, fmt.Errorf("%w: %q: a day count must not be negative", ErrBadFilter, s)
			}
			return now.UTC().AddDate(0, 0, -n), nil
		}
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("%w: %q is not YYYY-MM-DD, RFC3339 or Nd", ErrBadFilter, s)
}

// resolved is a parsed filter with its canonical display strings.
type resolved struct {
	filter       store.RepriceFilter
	since, until string
	model        string
}

func (f Filter) resolve(now time.Time) (resolved, error) {
	since, err := ParseBound(f.Since, now)
	if err != nil {
		return resolved{}, err
	}
	until, err := ParseBound(f.Until, now)
	if err != nil {
		return resolved{}, err
	}
	if _, derr := time.Parse("2006-01-02", strings.TrimSpace(f.Until)); derr == nil {
		until = until.AddDate(0, 0, 1) // a bare date names its whole day
	}
	if !since.IsZero() && !until.IsZero() && !until.After(since) {
		return resolved{}, fmt.Errorf("%w: until must be after since", ErrBadFilter)
	}
	r := resolved{filter: store.RepriceFilter{Since: since, Until: until, Model: strings.TrimSpace(f.Model)}}
	r.model = r.filter.Model
	// The display strings are the EXACT instants scanned (RFC3339Nano drops a
	// zero fraction, so a whole second still reads as plain RFC3339): a
	// caller that applies with the plan's own Since / Until - the CLI and the
	// Settings card both do - names the very rows the dry run counted, even
	// for a relative "Nd" window resolved against a clock that has moved on
	// (PRICE-REPRICE-1 review finding 9).
	if !since.IsZero() {
		r.since = since.Format(time.RFC3339Nano)
	}
	if !until.IsZero() {
		r.until = until.Format(time.RFC3339Nano)
	}
	return r, nil
}

// OrgNote is how the plan's changed proxy turns reach the org.
type OrgNote struct {
	Enrolled         bool   `json:"enrolled"`
	ResendQueued     int    `json:"resend_queued"`
	ResendBelowFloor int    `json:"resend_below_floor"`
	Note             string `json:"note"`
}

// Plan is one dry run.
type Plan struct {
	// Since / Until are the canonical RFC3339 bounds ("" = unbounded); Model
	// the exact model filter ("" = all).
	Since       string
	Until       string
	Model       string
	Pricing     PricingInfo
	Digest      string
	RuleVersion int
	Summary     reprice.Summary
	Org         OrgNote

	updates []reprice.Decision
	filter  store.RepriceFilter
}

// Updates returns the plan's update decisions (read only; for display).
func (p Plan) Updates() []reprice.Decision { return p.updates }

// Digest computes the canonical plan digest: hex sha256 over (since, until,
// model, pricing source, pricing version, rule version, changed, filled,
// old_usd and new_usd each rounded to 9 decimals). Exported so a test (and
// any second implementation) can pin the exact canonical string.
func Digest(since, until, model string, pricing PricingInfo, ruleVersion, changed, filled int, oldUSD, newUSD float64) string {
	canon := fmt.Sprintf("reprice-digest-v1\nsince=%s\nuntil=%s\nmodel=%s\npricing_source=%s\npricing_version=%d\nrule_version=%d\nchanged=%d\nfilled=%d\nold_usd=%.9f\nnew_usd=%.9f",
		since, until, model, pricing.Source, pricing.Version, ruleVersion, changed, filled, round9(oldUSD), round9(newUSD))
	sum := sha256.Sum256([]byte(canon))
	return hex.EncodeToString(sum[:])
}

func round9(v float64) float64 {
	r := math.Round(v*1e9) / 1e9
	if r == 0 {
		return 0 // never "-0.000000000"
	}
	return r
}

// PlanChangedError is returned by [Service.Apply] when the fresh plan's
// digest differs from the approved one. Plan is the fresh dry run to show.
type PlanChangedError struct {
	Plan Plan
}

func (e *PlanChangedError) Error() string {
	return "repricesvc.Apply: the plan changed since the dry run (prices or rows moved); review the new plan and apply again"
}

// Is makes errors.Is(err, ErrPlanChanged) match.
func (e *PlanChangedError) Is(target error) bool { return target == ErrPlanChanged }

// ErrPlanChanged is the sentinel [PlanChangedError] matches.
var ErrPlanChanged = errors.New("re-price plan changed")

// SettingsSection is the Settings section that owns pricing (the "pricing"
// entry of /api/config's editable_sections). An org that pins it read-only or
// hides it has also decided this node does not rewrite its stored costs by its
// own price table, so an APPLY is refused under that pin - from the dashboard
// and from `observer reprice --apply` alike, because the check lives here, in
// the one service both call (PRICE-REPRICE-1 review finding 5). A revert is
// never refused: a pin must not leave a developer unable to undo their own run.
const SettingsSection = "pricing"

// ErrGovernanceRefused is matched by [GovernanceRefusedError].
var ErrGovernanceRefused = errors.New("re-pricing is pinned by your organization")

// GovernanceRefusedError refuses an apply under the org's pricing pin. It
// carries the resolved posture so a surface can name the org and the policy
// version that pinned it.
type GovernanceRefusedError struct {
	Section   string
	Effective govern.Effective
}

func (e *GovernanceRefusedError) Error() string {
	org := e.Effective.Notice.OrgDisplayName
	if org == "" {
		org = e.Effective.OrgName
	}
	if org == "" {
		org = "your organization"
	}
	return fmt.Sprintf("pricing is pinned by %s, so stored costs cannot be re-priced on this machine", org)
}

// Is makes errors.Is(err, ErrGovernanceRefused) match.
func (e *GovernanceRefusedError) Is(target error) bool { return target == ErrGovernanceRefused }

// governanceRefusal returns the pin's refusal, or nil when nothing pins
// pricing (no provider, a dormant posture, or a section left editable).
func governanceRefusal(eff govern.Effective) error {
	if !eff.Active {
		return nil
	}
	if eff.IsSettingsSectionHidden(SettingsSection) || eff.IsSettingsSectionReadOnly(SettingsSection) {
		return &GovernanceRefusedError{Section: SettingsSection, Effective: eff}
	}
	return nil
}

// Request is one apply request: the filter the dry run used, who asked, and
// the digest of the plan they approved.
type Request struct {
	Filter Filter
	Actor  string
	Digest string
}

// Service is the re-price flow. Build one with [New].
type Service struct {
	st      Store
	price   reprice.PriceFunc
	pricing func(ctx context.Context) PricingInfo
	now     func() time.Time
	// governance resolves the node's governance posture for the apply pin;
	// nil = ungoverned (nothing pins pricing).
	governance func(ctx context.Context) govern.Effective
	mu         sync.Mutex
}

// WithGovernance installs the node's governance posture provider, whose
// pricing pin refuses an apply ([SettingsSection]). It returns s for chaining.
func (s *Service) WithGovernance(fn func(ctx context.Context) govern.Effective) *Service {
	if s != nil {
		s.governance = fn
	}
	return s
}

// New returns a service over st, pricing each row through price and
// describing the price table through pricing. now defaults to time.Now.
func New(st Store, price reprice.PriceFunc, pricing func(ctx context.Context) PricingInfo, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	if pricing == nil {
		pricing = func(context.Context) PricingInfo { return PricingInfo{Source: PricingSourceSeed} }
	}
	return &Service{st: st, price: price, pricing: pricing, now: now}
}

// Pricing describes the price table a plan made now would price under.
func (s *Service) Pricing(ctx context.Context) PricingInfo { return s.pricing(ctx) }

// Plan runs a dry run over f. It never writes.
func (s *Service) Plan(ctx context.Context, f Filter) (Plan, error) {
	if s == nil || s.st == nil || s.price == nil {
		return Plan{}, errors.New("repricesvc.Plan: service not configured")
	}
	r, err := f.resolve(s.now())
	if err != nil {
		return Plan{}, fmt.Errorf("repricesvc.Plan: %w", err)
	}
	info := s.pricing(ctx)
	planner := reprice.NewPlanner(s.price)
	if err := s.st.ScanRepriceRows(ctx, r.filter, func(row reprice.Row) error {
		planner.Add(row)
		return ctx.Err()
	}); err != nil {
		return Plan{}, fmt.Errorf("repricesvc.Plan: %w", err)
	}
	sum := planner.Summary()
	if len(sum.Models) > maxModels {
		sum.Models = sum.Models[:maxModels]
	}
	updates := planner.Updates()
	parity, err := s.st.RepriceOrgParityFor(ctx, updates)
	if err != nil {
		return Plan{}, fmt.Errorf("repricesvc.Plan: %w", err)
	}
	p := Plan{
		Since: r.since, Until: r.until, Model: r.model,
		Pricing: info, RuleVersion: reprice.RuleVersion, Summary: sum,
		Org:     orgNote(parity, s.now()),
		updates: updates, filter: r.filter,
	}
	p.Digest = Digest(p.Since, p.Until, p.Model, info, p.RuleVersion, sum.Changed, sum.Filled, sum.OldUSD, sum.NewUSD)
	return p, nil
}

// orgNote renders the org parity helper's counts as the plan's honest note.
func orgNote(p store.RepriceOrgParity, now time.Time) OrgNote {
	n := OrgNote{Enrolled: p.Enrolled, ResendQueued: p.Queued, ResendBelowFloor: p.BelowFloor}
	switch {
	case !p.Enrolled:
		n.Note = "This node is not enrolled in an org, so re-priced costs stay on this machine."
	case p.Queued == 0 && p.BelowFloor == 0:
		n.Note = "No proxy turn sent to the org changes, so the org sees nothing new."
	case !p.Tracked:
		n.Note = fmt.Sprintf("Org re-send tracking is not set up on this node yet (it starts with the first push), so the %d changed proxy turn(s) are not re-sent to the org automatically.", p.BelowFloor)
	default:
		parts := []string{}
		if p.Queued > 0 {
			parts = append(parts, fmt.Sprintf("%d changed proxy turn(s) are re-sent to the org automatically on the next push.", p.Queued))
		}
		if p.BelowFloor > 0 {
			parts = append(parts, fmt.Sprintf("%d are older than the org re-send floor; run `observer org resync --since %dh --confirm` after applying to send them too.",
				p.BelowFloor, resyncHours(p.OldestBelowFloor, now)))
		}
		n.Note = strings.Join(parts, " ")
	}
	return n
}

// resyncHours sizes an `observer org resync --since` window that reaches the
// oldest below-floor turn, with a day of margin.
func resyncHours(oldest string, now time.Time) int {
	t, ok := reprice.ParseTimestamp(oldest)
	if !ok {
		return 30 * 24
	}
	h := int(math.Ceil(now.Sub(t).Hours())) + 24
	if h < 24 {
		h = 24
	}
	return h
}

// Apply re-plans req.Filter and, when the fresh digest equals req.Digest,
// applies the plan's update decisions as one run. A differing (or empty)
// digest returns a *PlanChangedError carrying the fresh plan and writes
// nothing.
//
// An org pin on the pricing Settings section refuses the apply first
// (*GovernanceRefusedError, nothing planned or written).
func (s *Service) Apply(ctx context.Context, req Request) (store.RepriceRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.governance != nil {
		if err := governanceRefusal(s.governance(ctx)); err != nil {
			return store.RepriceRun{}, err
		}
	}
	p, err := s.Plan(ctx, req.Filter)
	if err != nil {
		return store.RepriceRun{}, fmt.Errorf("repricesvc.Apply: %w", err)
	}
	if strings.TrimSpace(req.Digest) == "" || req.Digest != p.Digest {
		return store.RepriceRun{}, &PlanChangedError{Plan: p}
	}
	meta := store.RepriceRunMeta{
		Actor: req.Actor, Since: p.Since, Until: p.Until, Model: p.Model,
		RuleVersion: p.RuleVersion, PricingSource: p.Pricing.Source, PricingVersion: p.Pricing.Version,
		Scanned: p.Summary.Scanned, TableScanned: map[string]int{}, Skipped: map[string]int{},
	}
	for _, t := range p.Summary.Tables {
		meta.TableScanned[t.Table] = t.Scanned
	}
	for k, v := range p.Summary.Skipped {
		meta.Skipped[string(k)] = v
	}
	run, err := s.st.ApplyReprice(ctx, meta, p.updates)
	if err != nil {
		return run, fmt.Errorf("repricesvc.Apply: %w", err)
	}
	return run, nil
}

// Revert undoes apply run runID (store.RevertReprice's typed refusals pass
// through unwrapped-comparable with errors.Is).
func (s *Service) Revert(ctx context.Context, runID int64, actor string) (store.RepriceRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, err := s.st.RevertReprice(ctx, runID, actor)
	if err != nil {
		return run, fmt.Errorf("repricesvc.Revert: %w", err)
	}
	return run, nil
}

// Runs lists up to limit runs, newest first.
func (s *Service) Runs(ctx context.Context, limit int) ([]store.RepriceRun, error) {
	runs, err := s.st.ListRepriceRuns(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("repricesvc.Runs: %w", err)
	}
	return runs, nil
}

// IsRefusal reports whether err is one of the refusals a caller should
// present as a conflict: an unknown run, a run already reverted, a revert run,
// a run still running, a run a later run supersedes (revert that one first),
// another run holding the claim, or the org's pricing pin.
func IsRefusal(err error) bool {
	return errors.Is(err, store.ErrRepriceRunNotFound) ||
		errors.Is(err, store.ErrRepriceRunReverted) ||
		errors.Is(err, store.ErrRepriceRunIsRevert) ||
		errors.Is(err, store.ErrRepriceRunRunning) ||
		errors.Is(err, store.ErrRepriceRunSuperseded) ||
		errors.Is(err, store.ErrRepriceBusy) ||
		errors.Is(err, ErrGovernanceRefused)
}
