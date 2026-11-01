package deliverysvc

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/deliverynet"
)

// The link statuses this package writes (delivery.ProviderLink.Status).
const (
	StatusOK           = "ok"
	StatusAuthFailed   = "auth_failed"
	StatusRateLimited  = "rate_limited"
	StatusUnreachable  = "unreachable"
	StatusRepoMoved    = "repo_moved"
	StatusWrongShape   = "wrong_shape"
	StatusDisabled     = "disabled"
	StatusNeverChecked = "never_checked"
)

// RunState is one provider link's polling state.
type RunState struct {
	Status   string
	Failures int
	NextRun  time.Time
	// Stopped means Run skips the link until the user tests or reconnects
	// it.
	Stopped bool
}

// Outcome is the result of one link pass: the worst Kind seen ("" for
// success) and a rate-limit reset when one was announced.
type Outcome struct {
	Kind    deliverynet.Kind
	ResetAt time.Time
}

// backoffStep returns 2, 4, 8 ... 60 minutes for the nth consecutive failure.
func backoffStep(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	if n > 6 {
		n = 6
	}
	d := time.Duration(1<<n) * time.Minute
	if d > time.Hour {
		d = time.Hour
	}
	return d
}

// cadenceRule is one row of the cadence table: the first row whose kind
// matches decides.
type cadenceRule struct {
	kind  deliverynet.Kind
	apply func(prev RunState, o Outcome, now time.Time, cadence time.Duration) RunState
}

// cadenceRules is THE cadence and backoff table (CLAUDE.md rule 5).
var cadenceRules = []cadenceRule{
	{"", func(_ RunState, _ Outcome, now time.Time, cadence time.Duration) RunState {
		return RunState{Status: StatusOK, NextRun: now.Add(cadence)}
	}},
	{deliverynet.KindAuthFailed, func(p RunState, _ Outcome, now time.Time, _ time.Duration) RunState {
		return RunState{Status: StatusAuthFailed, Failures: p.Failures + 1, Stopped: true, NextRun: now}
	}},
	{deliverynet.KindRateLimited, func(p RunState, o Outcome, now time.Time, _ time.Duration) RunState {
		n := p.Failures + 1
		next := now.Add(backoffStep(n))
		if o.ResetAt.After(now) {
			next = o.ResetAt.Add(time.Second)
		}
		return RunState{Status: StatusRateLimited, Failures: n, NextRun: next}
	}},
	// A moved repository is a per-repository fact: the link keeps its normal
	// cadence and shows the status until the user updates the remote.
	{deliverynet.KindRepoMoved, func(p RunState, _ Outcome, now time.Time, cadence time.Duration) RunState {
		return RunState{Status: StatusRepoMoved, Failures: p.Failures, NextRun: now.Add(cadence)}
	}},
	{deliverynet.KindWrongShape, func(p RunState, _ Outcome, now time.Time, _ time.Duration) RunState {
		n := p.Failures + 1
		return RunState{Status: StatusWrongShape, Failures: n, NextRun: now.Add(backoffStep(n))}
	}},
	{deliverynet.KindHostNotAllowed, func(p RunState, _ Outcome, now time.Time, _ time.Duration) RunState {
		return RunState{Status: StatusDisabled, Failures: p.Failures + 1, Stopped: true, NextRun: now}
	}},
}

// NextRun folds one outcome into a link's run state. A kind that matches no
// row is transient (unreachable): back off.
func NextRun(prev RunState, o Outcome, now time.Time, cadence time.Duration) RunState {
	for _, r := range cadenceRules {
		if r.kind == o.Kind {
			return r.apply(prev, o, now, cadence)
		}
	}
	n := prev.Failures + 1
	return RunState{Status: StatusUnreachable, Failures: n, NextRun: now.Add(backoffStep(n))}
}

// severity orders kinds when one pass sees several: the worst is recorded on
// the link. Kinds absent here (not_found, unprocessable, invalid) are
// per-repository facts that never change the link's status.
var severity = map[deliverynet.Kind]int{
	deliverynet.KindAuthFailed:     6,
	deliverynet.KindHostNotAllowed: 5,
	deliverynet.KindRateLimited:    4,
	deliverynet.KindWrongShape:     3,
	deliverynet.KindUnreachable:    2,
	deliverynet.KindUnavailable:    2,
	deliverynet.KindRepoMoved:      1,
}

// worse returns the more severe of two outcomes.
func worse(a, b Outcome) Outcome {
	if severity[b.Kind] > severity[a.Kind] {
		return b
	}
	return a
}

// stoppedStatuses are link statuses Run never polls.
var stoppedStatuses = map[string]bool{StatusAuthFailed: true, StatusDisabled: true}

// MinScheduleMinutes is the smallest mirror refresh schedule (plan 12.2).
const MinScheduleMinutes = 30

// scheduleOf returns a project's mirror refresh interval (0 = "Check now"
// only), clamped up to the minimum.
func scheduleOf(minutes int) time.Duration {
	if minutes <= 0 {
		return 0
	}
	if minutes < MinScheduleMinutes {
		minutes = MinScheduleMinutes
	}
	return time.Duration(minutes) * time.Minute
}
