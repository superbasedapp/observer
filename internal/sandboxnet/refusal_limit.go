package sandboxnet

import (
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// refusal_limit.go is the flood bound of the refusal audit (plan 05,
// section 3.1): a box that hammers the gateway with refused requests must
// not flood the daemon or its table. RefusalLimiter passes at most one
// refusal per (run, host) per wall-clock minute, and at most a fixed number
// per run per minute, so a box cycling through random host names is bounded
// too. The host helper applies it before it sends, the daemon again before
// it writes, and the store's unique key on the minute bucket is the last
// bound. Both use the one bucket definition, sandboxvocab.EgressRefusalMinute.

// DefaultRefusalsPerMinute is the per-run cap of a minute when the limiter
// is built with zero.
const DefaultRefusalsPerMinute = 30

// maxLimiterEntries bounds the hosts one run's minute remembers; past it
// nothing more of that run passes until its minute turns.
const maxLimiterEntries = 4096

// maxLimiterRuns bounds the runs the limiter keeps a minute for. A new run
// past it first evicts every run idle since an earlier minute; when none is,
// the new run's refusal does not pass.
const maxLimiterRuns = 256

// runWindow is one run's current minute and the hosts it passed in it.
type runWindow struct {
	minute int64
	hosts  map[string]struct{}
}

// RefusalLimiter is the per-minute bound, kept per run so one run's minute
// never drops another run's refusals (audit N1-A3). The zero value is not
// usable; build it with NewRefusalLimiter. Safe for concurrent use.
type RefusalLimiter struct {
	mu   sync.Mutex
	max  int
	runs map[string]*runWindow
}

// NewRefusalLimiter returns a limiter passing at most perRunPerMinute
// refusals per run per minute (zero or less: DefaultRefusalsPerMinute).
func NewRefusalLimiter(perRunPerMinute int) *RefusalLimiter {
	if perRunPerMinute <= 0 {
		perRunPerMinute = DefaultRefusalsPerMinute
	}
	return &RefusalLimiter{max: perRunPerMinute, runs: map[string]*runWindow{}}
}

// RefusalVerdict is what RefusalLimiter.Check decided for one refusal.
type RefusalVerdict int

const (
	// RefusalPass: the refusal may be passed on (and was counted).
	RefusalPass RefusalVerdict = iota
	// RefusalSeen: the run's minute already passed this host; nothing new
	// is lost by not passing it again.
	RefusalSeen
	// RefusalCapped: the run's minute already passed its cap of distinct
	// hosts (or the per-minute host table is full): a distinct refusal is
	// not passed.
	RefusalCapped
	// RefusalEarlier: the refusal is from a minute earlier than the one the
	// run's window is in.
	RefusalEarlier
	// RefusalRunsFull: the run is new and the run table is full of runs
	// active in this minute.
	RefusalRunsFull
)

// Lost reports whether the verdict drops a refusal that carried something
// not passed on already (every verdict but RefusalPass and RefusalSeen): a
// caller that keeps a dropped count counts these (lane OC, audit finding
// OC-A2).
func (v RefusalVerdict) Lost() bool { return v != RefusalPass && v != RefusalSeen }

// Allow reports whether a refusal of host for run at the given time may be
// passed on, and counts it when it may (Check is the same with the reason).
func (l *RefusalLimiter) Allow(run, host string, at time.Time) bool {
	return l.Check(run, host, at) == RefusalPass
}

// Check decides one refusal of host for run at the given time, and counts
// it when it passes. A refusal from a minute earlier than the one the run's
// window is in is not passed.
func (l *RefusalLimiter) Check(run, host string, at time.Time) RefusalVerdict {
	m := sandboxvocab.EgressRefusalMinute(at)
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.runs[run]
	if w == nil {
		if len(l.runs) >= maxLimiterRuns {
			for id, o := range l.runs {
				if o.minute < m {
					delete(l.runs, id)
				}
			}
			if len(l.runs) >= maxLimiterRuns {
				return RefusalRunsFull
			}
		}
		w = &runWindow{minute: m, hosts: map[string]struct{}{}}
		l.runs[run] = w
	}
	switch {
	case m > w.minute:
		w.minute = m
		clear(w.hosts)
	case m < w.minute:
		return RefusalEarlier
	}
	if _, seen := w.hosts[host]; seen {
		return RefusalSeen
	}
	if len(w.hosts) >= l.max || len(w.hosts) >= maxLimiterEntries {
		return RefusalCapped
	}
	w.hosts[host] = struct{}{}
	return RefusalPass
}
