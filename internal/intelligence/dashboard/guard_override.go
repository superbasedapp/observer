package dashboard

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Org-granted per-rule override, node-dashboard read side (Track B of
// the org guardrail control wave,
// docs/plans/org-guardrail-control-wave-2026-09-21.md).
//
// Whether a rule may be overridden locally is a property of the ORG
// BUNDLE currently on disk, not of a historical event: guard_events is
// a hash-CHAINED append-only audit log with a fixed row shape, so the
// Security page derives the posture per rule ID from the live bundle
// instead of the wave adding columns to a chained log. That is also
// the more useful answer — "can I take this one NOW" is what the
// "Allow for this session" button needs.
//
// The lookup builds a guard from the SAME on-disk config the daemon
// binds (the handleGuardRules?effective=1 precedent) and caches the
// answer briefly, because the events timeline is polled.
//
// Two things this read must get right, both from the adversarial
// review:
//
//   - TENANCY (P2-8). How far the org bundle's lock reaches is a
//     property of the NODE, not of the bundle: org-authoritative on a
//     managed node, a floor over the rules it names on an individual
//     one. The dashboard resolves it through the daemon's OWN
//     governance handle (Options.Governance, govern.Effective.Managed)
//     - the same resolver cmd/observer/guardwire.go feeds the daemon's
//     live guard - so the creation gate below can never refuse a grant
//     the daemon would have honoured, or grant one it would ignore.
//   - LOCK SCOPE (P3-11). Constructing a guard means a config read, a
//     ProjectRoots query and a policy-bundle verify. None of that
//     happens under the cache mutex: the build runs on the request
//     goroutine with no lock held and the finished value is swapped in
//     under the mutex. A concurrent poll may duplicate one build; it
//     can never queue behind one.

// orgOverrideTTL bounds how stale the cached org-bundle posture may
// be. A bundle changes on an org publish + poll, never per request.
const orgOverrideTTL = 30 * time.Second

// orgOverrideSet is the cached answer: the live posture plus the
// instant it was built.
type orgOverrideSet struct {
	posture guard.OrgOverridePosture
	at      time.Time
}

// orgOverrideCache is the per-Server cache guarding orgOverrideSet.
type orgOverrideCache struct {
	mu  sync.Mutex
	set orgOverrideSet
}

// orgOverrides returns the live org-granted override posture. On any
// failure (no config path, unreadable config, guard construction
// error) it degrades to the zero posture - "no org bundle applies" -
// which is fail-open toward the pre-wave rendering, exactly like every
// other guard read surface.
func (s *Server) orgOverrides(ctx context.Context) guard.OrgOverridePosture {
	now := s.now()
	s.orgOverride.mu.Lock()
	if !s.orgOverride.set.at.IsZero() && now.Sub(s.orgOverride.set.at) < orgOverrideTTL {
		cached := s.orgOverride.set.posture
		s.orgOverride.mu.Unlock()
		return cached
	}
	s.orgOverride.mu.Unlock()

	// Build with NO lock held (P3-11): config read + ProjectRoots
	// query + bundle verification are all request-path I/O.
	fresh := orgOverrideSet{at: now}
	if s.opts.ConfigPath != "" {
		if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
			home, _ := os.UserHomeDir()
			roots, _ := store.New(s.opts.DB).ProjectRoots(ctx)
			if g, gerr := guard.New(guard.Options{
				Config:            cfg.Guard,
				Home:              home,
				KnownProjectRoots: roots,
				ManagedTenancy:    s.managedTenancy(ctx),
			}); gerr == nil {
				fresh.posture = g.OrgOverridePosture()
			}
		}
	}

	s.orgOverride.mu.Lock()
	s.orgOverride.set = fresh
	s.orgOverride.mu.Unlock()
	return fresh.posture
}

// managedTenancy adapts the daemon's governance handle to the guard's
// tenancy seam. A dashboard with no governance provider wired (tests,
// an ungoverned embedding) returns nil, which the guard reads as
// "tenancy unresolved" and answers conservatively - the same rule
// every other unwired process follows.
//
// ctx is captured deliberately: the guard calls this at most once per
// posture build, inside the same request.
func (s *Server) managedTenancy(ctx context.Context) func() bool {
	if s.opts.Governance == nil {
		return nil
	}
	return func() bool { return s.opts.Governance(ctx).Managed }
}

// orgOverrideFor answers the per-rule question the approvals POST and
// the event rows ask. Both false = the org layer does not reach this
// rule on this node, i.e. local approvals work exactly as before.
func (s *Server) orgOverrideFor(ctx context.Context, ruleID string) (overridable, orgLocked bool) {
	return s.orgOverrides(ctx).For(ruleID)
}
