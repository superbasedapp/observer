package secfeed

import (
	"context"
	"sync"
	"time"
)

// service.go is the daemon side of the online lane (security plan section
// 8.3): it answers the hook's asks, prefetches the names a project already
// declares, and owns the online-answer cache. It classifies every name with
// the project's own configuration first; a private or invalid name is
// answered "private, not asked" and goes nowhere. Every effect is injected:
// the lookup is the public client on an individual node or the org relay
// on a managed one (never both: the cmd layer hands it exactly one), and
// the cache persistence and the hook-readable file are funcs.

// Lookup asks the online source about public names within ctx.
type Lookup func(ctx context.Context, specs []InstallSpec) []OnlineAnswer

// ServiceOptions wires a service.
type ServiceOptions struct {
	// Classify builds the classifier for an ask's scope (the cmd layer
	// reads the fixed config paths of every directory the scope names,
	// under the daemon's own environment and under the scope's variables;
	// a name is public only when all of them say so). A scope with no
	// project root classifies nothing public.
	Classify func(scope Scope) Classifier
	// Confirmed is told, per ask (never per prefetch), the names this
	// service classified public for the ask's scope: the only names a
	// later prefetch of that project may send (X4).
	Confirmed func(scope Scope, public []InstallSpec)
	// Lookup is the online source; nil means none (online checks off).
	Lookup Lookup
	// Enabled reports, per ask, whether online checks may run now: the
	// setting is on, the org does not forbid them, and the disclosure has
	// been shown (P-011: no query before the disclosure).
	Enabled func() bool
	// EnabledFor, when set, decides per ask's scope instead of Enabled: the
	// org's floors per project (security plan section 7.11, lane sec-p3)
	// may forbid online checks in one project and not another. Nil keeps
	// Enabled alone.
	EnabledFor func(scope Scope) bool
	// Save persists new cache entries; WriteFile writes the hook-readable
	// cache file. Either may be nil.
	Save      func(ctx context.Context, entries []CacheEntry)
	WriteFile func(b []byte) error
	// Initial is the cache loaded at start.
	Initial []CacheEntry
	Now     func() time.Time
	// LookupTimeout bounds one lookup, which runs detached from the ask
	// that started it: when the ask's budget ends first, the lookup goes on
	// and its answer is cached for the next install of the same name.
	// Zero is DefaultLookupTimeout.
	LookupTimeout time.Duration
}

// DefaultLookupTimeout bounds a detached lookup.
const DefaultLookupTimeout = 10 * time.Second

// enabled is EnabledFor(scope) when set, else Enabled (nil: on).
func (s *Service) enabled(scope Scope) bool {
	if s.o.EnabledFor != nil {
		return s.o.EnabledFor(scope)
	}
	return s.o.Enabled == nil || s.o.Enabled()
}

// Service is the daemon's online lane.
type Service struct {
	o        ServiceOptions
	mu       sync.Mutex
	cache    map[string]CacheEntry
	inflight map[string]*flight
}

// flight is one detached lookup: done closes when answers holds every
// answer it got. quiet records the keys (ecosystem, name AND version) one
// ask already reported in flight (S-748): a retry of the same install
// while this same lookup still runs is answered not-asked, so a slow
// first lookup asks the developer once under enforce. The record lives
// on the flight, so it clears when the lookup lands, and a failed lookup
// never quiets the next ask, which starts a fresh flight (lane SEC-DEPS3
// item 1, P-029; before, a per-name record quieted every version for 30
// minutes, even after a failure, so a retry skipped the check). quiet is
// guarded by Service.mu.
type flight struct {
	done    chan struct{}
	answers map[string]OnlineAnswer
	quiet   map[string]bool
}

// NewService returns a service.
func NewService(o ServiceOptions) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.LookupTimeout <= 0 {
		o.LookupTimeout = DefaultLookupTimeout
	}
	s := &Service{o: o, cache: map[string]CacheEntry{}, inflight: map[string]*flight{}}
	now := o.Now()
	for _, e := range o.Initial {
		if now.Before(e.ExpiresAt) {
			s.cache[answerKey(e.Answer.Eco, e.Answer.Name, e.Answer.Version)] = e
		}
	}
	return s
}

// Answer answers one ask. Every spec gets an answer naming it.
func (s *Service) Answer(ctx context.Context, scope Scope, specs []InstallSpec) []OnlineAnswer {
	return s.answer(ctx, scope, specs, true)
}

func (s *Service) answer(ctx context.Context, scope Scope, specs []InstallSpec, ask bool) []OnlineAnswer {
	if len(specs) > MaxInstallSpecs {
		specs = specs[:MaxInstallSpecs]
	}
	var cls Classifier
	if s.o.Classify != nil && scope.Public() {
		cls = s.o.Classify(scope)
	}
	var public []InstallSpec
	now := s.o.Now()
	out := make([]OnlineAnswer, len(specs))
	var miss []int
	for i, sp := range specs {
		a := OnlineAnswer{Eco: sp.Eco, Name: Normalize(sp.Eco, sp.Name), Version: sp.Version, Status: OnlineNotAsked}
		if sp.Invalid || sp.Private || cls == nil || !cls(sp) {
			// No classifier means nothing is known to be public; a spec the
			// command made private (X4) stays private here too.
			a.Private = !sp.Invalid
			out[i] = a
			continue
		}
		public = append(public, sp)
		if e, ok := s.cached(sp, now); ok {
			out[i] = e
			continue
		}
		out[i] = a
		miss = append(miss, i)
	}
	if ask && len(public) > 0 && s.o.Confirmed != nil {
		s.o.Confirmed(scope, public)
	}
	if len(miss) == 0 || s.o.Lookup == nil || !s.enabled(scope) {
		return out
	}
	flights := s.start(miss, specs)
	for _, i := range miss {
		sp := specs[i]
		k := answerKey(sp.Eco, sp.Name, sp.Version)
		f := flights[k]
		select {
		case <-f.done:
		case <-ctx.Done():
		}
		select {
		case <-f.done:
			a, ok := f.answers[k]
			if !ok {
				a = OnlineAnswer{Eco: sp.Eco, Name: Normalize(sp.Eco, sp.Name), Version: sp.Version, Status: OnlineFailed, Reason: GateReasonNoAnswer}
			}
			out[i] = a
		default:
			out[i] = OnlineAnswer{Eco: sp.Eco, Name: Normalize(sp.Eco, sp.Name), Version: sp.Version, Status: OnlineFailed, Reason: ReasonInFlight}
			if ask && s.quietInFlight(f, k) {
				// Already answered in flight once by this same lookup:
				// the offline verdict stands, without a second S-748. A
				// prefetch is not an ask and never records the quiet.
				out[i].Status = OnlineNotAsked
			}
		}
	}
	return out
}

// quietInFlight reports whether an earlier ask already got an in-flight
// answer for key k from flight f while f is still the running lookup for
// k, and records this ask otherwise. A flight that has landed (no longer
// the in-flight lookup for k) never quiets.
func (s *Service) quietInFlight(f *flight, k string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[k] != f {
		return false
	}
	if f.quiet[k] {
		return true
	}
	f.quiet[k] = true
	return false
}

// start joins the lookups already running for these specs and starts one
// detached lookup for the rest, returning each spec's flight by key.
func (s *Service) start(miss []int, specs []InstallSpec) map[string]*flight {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]*flight{}
	var ask []InstallSpec
	f := &flight{done: make(chan struct{}), answers: map[string]OnlineAnswer{}, quiet: map[string]bool{}}
	for _, i := range miss {
		sp := specs[i]
		k := answerKey(sp.Eco, sp.Name, sp.Version)
		if g, ok := s.inflight[k]; ok {
			out[k] = g
			continue
		}
		if _, ok := out[k]; ok {
			continue
		}
		s.inflight[k] = f
		out[k] = f
		ask = append(ask, sp)
	}
	if len(ask) == 0 {
		return out
	}
	go s.run(f, ask)
	return out
}

// run is one detached lookup: it caches what it got, then releases its
// keys and wakes every ask waiting on it.
func (s *Service) run(f *flight, ask []InstallSpec) {
	ctx, cancel := context.WithTimeout(context.Background(), s.o.LookupTimeout)
	defer cancel()
	var got []OnlineAnswer
	func() {
		defer func() {
			if recover() != nil {
				got = nil
			}
		}()
		got = s.o.Lookup(ctx, ask)
	}()
	byKey := map[string]OnlineAnswer{}
	for _, a := range got {
		byKey[answerKey(a.Eco, a.Name, a.Version)] = a
	}
	now := s.o.Now()
	var fresh []CacheEntry
	for _, sp := range ask {
		k := answerKey(sp.Eco, sp.Name, sp.Version)
		a, ok := byKey[k]
		if !ok {
			a = OnlineAnswer{Eco: sp.Eco, Name: Normalize(sp.Eco, sp.Name), Version: sp.Version, Status: OnlineFailed, Reason: GateReasonNoAnswer}
		}
		f.answers[k] = a
		if e, ok := NewCacheEntry(a, now); ok {
			fresh = append(fresh, e)
		}
	}
	if len(fresh) > 0 {
		s.store(ctx, fresh, now)
	}
	s.mu.Lock()
	for _, sp := range ask {
		if s.inflight[answerKey(sp.Eco, sp.Name, sp.Version)] == f {
			delete(s.inflight, answerKey(sp.Eco, sp.Name, sp.Version))
		}
	}
	s.mu.Unlock()
	close(f.done)
}

// Prefetch looks up names a project declares, so the hook's later install
// finds them cached. It obeys the same classification and gate as an ask;
// the caller passes only names an ask already confirmed public (X4), and a
// prefetch confirms nothing.
func (s *Service) Prefetch(ctx context.Context, scope Scope, specs []InstallSpec) int {
	got := s.answer(ctx, scope, specs, false)
	n := 0
	for _, a := range got {
		if a.Status == OnlineAnswered || a.Status == OnlineNotFound {
			n++
		}
	}
	return n
}

func (s *Service) cached(sp InstallSpec, now time.Time) (OnlineAnswer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.cache[answerKey(sp.Eco, sp.Name, sp.Version)]
	if !ok || !now.Before(e.ExpiresAt) {
		return OnlineAnswer{}, false
	}
	return e.Answer, true
}

func (s *Service) store(ctx context.Context, fresh []CacheEntry, now time.Time) {
	s.mu.Lock()
	for _, e := range fresh {
		s.cache[answerKey(e.Answer.Eco, e.Answer.Name, e.Answer.Version)] = e
	}
	all := make([]CacheEntry, 0, len(s.cache))
	for k, e := range s.cache {
		if !now.Before(e.ExpiresAt) {
			delete(s.cache, k)
			continue
		}
		all = append(all, e)
	}
	s.mu.Unlock()
	if s.o.Save != nil {
		s.o.Save(ctx, fresh)
	}
	if s.o.WriteFile != nil {
		if b, err := EncodeCacheFile(all, now); err == nil {
			_ = s.o.WriteFile(b)
		}
	}
}

// CacheLen reports the live entries (status surfaces).
func (s *Service) CacheLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.cache)
}
