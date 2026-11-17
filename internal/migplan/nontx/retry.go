package nontx

import "time"

// RetryPolicy bounds the attempts of a non-transactional step and spaces
// them: the wait before attempt n+1 is Base doubled n-1 times, capped at Cap.
type RetryPolicy struct {
	// MaxAttempts is the most attempts a step gets (at least 1).
	MaxAttempts int
	// Base is the wait after the first failed attempt.
	Base time.Duration
	// Cap is the longest wait.
	Cap time.Duration
}

// DefaultRetryPolicy is the runner's policy: five attempts, waiting 2s, 4s,
// 8s and 16s between them (30s cap).
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 5, Base: 2 * time.Second, Cap: 30 * time.Second}
}

// retryRule is one row of the retryable-failure table.
type retryRule struct {
	sqlstate string
	name     string
}

// retryRules is THE table of failures worth another attempt, by SQLSTATE.
// Every other failure (a unique violation, a syntax error, statement_timeout's
// query_canceled) fails the step at once: waiting would not change it.
var retryRules = []retryRule{
	// The step's SET lock_timeout expired while the statement queued for its
	// table lock behind a long transaction.
	{sqlstate: "55P03", name: "lock_not_available (lock_timeout expired)"},
	// Two concurrent index builds, or a build and a transaction, deadlocked
	// while waiting out each other's snapshots.
	{sqlstate: "40P01", name: "deadlock_detected"},
}

// Retry is the decision after a failed attempt.
type Retry struct {
	// Again reports that the runner should sleep Wait and attempt again.
	Again bool
	Wait  time.Duration
	// Rule names why.
	Rule string
}

// Next decides after attempt (1-based) failed with sqlstate ("" when the
// failure carried none). It is a pure function of its input.
func (p RetryPolicy) Next(attempt int, sqlstate string) Retry {
	rule := ""
	for _, r := range retryRules {
		if r.sqlstate == sqlstate {
			rule = r.name
			break
		}
	}
	if rule == "" {
		return Retry{Rule: "not retryable"}
	}
	if attempt >= p.MaxAttempts {
		return Retry{Rule: rule + ": attempts exhausted"}
	}
	wait := p.Base
	for n := 1; n < attempt && wait < p.Cap; n++ {
		wait *= 2
	}
	if wait > p.Cap {
		wait = p.Cap
	}
	return Retry{Again: true, Wait: wait, Rule: rule}
}
