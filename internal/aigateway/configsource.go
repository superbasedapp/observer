package aigateway

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Cached document sources for the handler's hot-reloadable Rates / Policy
// funcs (gap register G1-RESIDUALS "gwstore-sourced model policy/rate card").
// Each source reads the admin-authored document from a ModelConfigStore at
// most once per ttl and serves the cached copy in between; when no document
// is stored (or the read fails) it serves the injected built-in fallback, so
// the gateway never runs without a policy or a price table. Failures are
// reported through the optional OnError hook (logging is the caller's), never
// surfaced on the request path.

// PolicySource is the cached ModelPolicy loader.
type PolicySource struct {
	store    ModelConfigStore
	orgID    string
	ttl      time.Duration
	fallback func() ModelPolicy
	now      func() time.Time
	OnError  func(error)

	mu        sync.Mutex
	cached    ModelPolicy
	cachedAt  time.Time
	haveCache bool
}

// NewPolicySource builds a PolicySource. store nil ⇒ always the fallback.
func NewPolicySource(store ModelConfigStore, orgID string, ttl time.Duration, fallback func() ModelPolicy, now func() time.Time) *PolicySource {
	if now == nil {
		now = time.Now
	}
	if ttl <= 0 {
		ttl = DefaultConfigSourceTTL
	}
	return &PolicySource{store: store, orgID: orgID, ttl: ttl, fallback: fallback, now: now}
}

// DefaultConfigSourceTTL bounds how stale an admin edit can be on the request
// path (hot reload without restart, per the handler's func seams).
const DefaultConfigSourceTTL = 15 * time.Second

// Get returns the effective policy (Handler.Policy).
func (s *PolicySource) Get() ModelPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.haveCache && now.Sub(s.cachedAt) < s.ttl {
		return s.cached
	}
	p := s.fallback()
	if s.store != nil {
		stored, _, found, err := s.store.GetModelPolicy(context.Background(), s.orgID)
		if err != nil {
			if s.OnError != nil {
				s.OnError(err)
			}
		} else if found {
			p = stored
		}
	}
	s.cached, s.cachedAt, s.haveCache = p, now, true
	return p
}

// Invalidate drops the cache so the next Get re-reads (an admin write path
// running in the same process calls this for zero-latency effect).
func (s *PolicySource) Invalidate() {
	s.mu.Lock()
	s.haveCache = false
	s.mu.Unlock()
}

// RateCardSource is the cached RateCard loader (same contract as PolicySource).
type RateCardSource struct {
	store    ModelConfigStore
	orgID    string
	ttl      time.Duration
	fallback func() RateCard
	now      func() time.Time
	OnError  func(error)

	mu        sync.Mutex
	cached    RateCard
	cachedAt  time.Time
	haveCache bool
}

// NewRateCardSource builds a RateCardSource. store nil ⇒ always the fallback.
func NewRateCardSource(store ModelConfigStore, orgID string, ttl time.Duration, fallback func() RateCard, now func() time.Time) *RateCardSource {
	if now == nil {
		now = time.Now
	}
	if ttl <= 0 {
		ttl = DefaultConfigSourceTTL
	}
	return &RateCardSource{store: store, orgID: orgID, ttl: ttl, fallback: fallback, now: now}
}

// Get returns the effective rate card (Handler.Rates). A stored card with an
// empty Version or no rates is treated as absent (the fallback serves) so a
// half-authored document can never make every model "unpriced" (G4 fail-closed
// would then refuse all traffic).
func (s *RateCardSource) Get() RateCard {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.haveCache && now.Sub(s.cachedAt) < s.ttl {
		return s.cached
	}
	c := s.fallback()
	if s.store != nil {
		stored, _, found, err := s.store.GetRateCard(context.Background(), s.orgID)
		if err != nil {
			if s.OnError != nil {
				s.OnError(err)
			}
		} else if found && stored.Version != "" && len(stored.Rates) > 0 {
			c = stored
		}
	}
	s.cached, s.cachedAt, s.haveCache = c, now, true
	return c
}

// Invalidate drops the cache so the next Get re-reads.
func (s *RateCardSource) Invalidate() {
	s.mu.Lock()
	s.haveCache = false
	s.mu.Unlock()
}

// ValidateRateCard is the admin-write gate for a rate card document: a
// version label and at least one model with non-negative rates that are not
// all zero unless the row says so.
//
// The all-zero guard catches a real misconfiguration -- a model key typed with
// no rates behind it, which would price every turn on that model at $0 and
// reserve no headroom against a USD cap. It is NOT a claim that zero cannot be
// a price: a row carrying ModelRate.Free is the org stating that it pays
// nothing for the model's TOKENS, and that row is accepted whatever its cache
// rates say (an org can negotiate free tokens and still pay a cache surcharge).
// The flag has to agree with the numbers it labels, so a free row carrying a
// non-zero input or output rate is refused as the contradiction it is.
func ValidateRateCard(c RateCard) error {
	if c.Version == "" {
		return errValidation("rate card needs a version label")
	}
	if len(c.Rates) == 0 {
		return errValidation("rate card needs at least one model rate")
	}
	for model, r := range c.Rates {
		if model == "" {
			return errValidation("rate card has an empty model key")
		}
		if r.InPerMTok < 0 || r.OutPerMTok < 0 || r.CacheReadPerMTok < 0 || r.CacheWritePerMTok < 0 {
			return errValidation("rate card model " + model + " has a negative rate")
		}
		if r.Free {
			if r.InPerMTok != 0 || r.OutPerMTok != 0 {
				return errValidation("rate card model " + model + " is marked free but carries a non-zero token rate")
			}
			continue
		}
		if r.InPerMTok == 0 && r.OutPerMTok == 0 {
			return errValidation("rate card model " + model + " prices both input and output at zero")
		}
	}
	return nil
}

// ValidateModelPolicy is the admin-write gate for a model policy document.
// An empty allow-set is LEGAL (it fails closed at resolve time, Luna L11) but
// negative caps are not.
func ValidateModelPolicy(p ModelPolicy) error {
	if p.DefaultMaxOutputTokens < 0 {
		return errValidation("default_max_output_tokens must not be negative")
	}
	for model, cap := range p.MaxOutputTokens {
		if cap < 0 {
			return errValidation("max_output_tokens for " + model + " must not be negative")
		}
	}
	return nil
}

// errValidation is a plain validation error type so admin handlers can map it
// to 400 without string matching.
type errValidation string

func (e errValidation) Error() string { return "aigateway: " + string(e) }

// IsValidationError reports whether err came from ValidateRateCard /
// ValidateModelPolicy.
func IsValidationError(err error) bool {
	var v errValidation
	return errors.As(err, &v)
}
