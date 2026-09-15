package intervention

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Workload is one independently verified adapter process. It is not a whole
// session or a descendant tree. Discovery must exclude shared hosts and bind
// an installed entrypoint before supplying it to the supervisor.
type Workload struct {
	SurfaceID string
	SessionID string
	Identity  Identity
}

// PolicyDecision is an authority-scoped instruction for one workload. The
// issuer must resolve the live enrollment and policy on every call. Authority
// is an opaque binding to the org, member, enrollment generation and OS user;
// it is never a credential. A missing or expired grant cannot authorize a
// signal, even when Stop is true. Other policy triggers can use this same
// contract without importing budget arithmetic into the process controller.
type PolicyDecision struct {
	Authorized bool
	Stop       bool
	Authority  string
	// BudgetBinding identifies the enrollment that owns the applied budget.
	// It is supplied by the policy issuer, never interpreted by this package.
	BudgetBinding string
	// BudgetDocument* binds a budget decision to the exact durable cache state.
	// Known absence is valid; a present witness requires its SHA-256.
	BudgetDocumentKnown   bool
	BudgetDocumentPresent bool
	BudgetDocumentSHA256  string
	// PricingDocument* is present only when a measured USD decision consumed
	// the immutable pricing table. Required forces the command fence to prove
	// the corresponding durable org_pricing_cache state.
	PricingDocumentRequired bool
	PricingDocumentKnown    bool
	PricingDocumentPresent  bool
	PricingDocumentSHA256   string
	// PolicyRevision identifies the immutable policy which made this decision.
	// The command-layer fence validates it before invoking an OS operation.
	PolicyRevision uint64
	// AccountingFence verifies independently published accounting inputs during
	// the operation. It performs no discovery, pricing read or budget arithmetic.
	AccountingFence func(context.Context, func() error) error
	ValidUntil      time.Time
	RuleID          string
	Reason          string
}

// ControlHandle is the bounded process operation seam used by Supervisor.
// Process implements it with pidfds on Linux. Close releases custody only.
type ControlHandle interface {
	SignalTerminate(context.Context) (ExitResult, error)
	SignalKill(context.Context) (ExitResult, error)
	WaitExit(context.Context) (ExitResult, error)
	Close() error
}

// Supervisor executes policy decisions against verified processes. It has no
// network/IPC listener and accepts no remote PID commands. Each Reconcile call
// is synchronous; callers serialize calls and own discovery cadence/lifetime.
// This is process cutoff after discovery, not execution/request admission.
type Supervisor struct {
	Decide  func(context.Context, Workload) (PolicyDecision, error)
	Acquire func(context.Context, Identity) (ControlHandle, error)
	// Revalidate re-reads the workload's registry binding inside the authority
	// fence immediately before each signal callback. A failure must abstain.
	Revalidate func(context.Context, Workload) error
	// Fence revalidates authority and serializes the actual OS operation with
	// authority changes. The enrolled daemon always supplies it. The callback
	// must never invoke action when its current authority differs from expected.
	Fence       func(ctx context.Context, w Workload, expected PolicyDecision, action func(context.Context) (ExitResult, error)) (ExitResult, error)
	Now         func() time.Time
	GracePeriod time.Duration
	KillTimeout time.Duration
}

// Outcome reports the observed result of one process decision. Stopped is
// true only after the OS handle observed exit. An error or an unobserved
// signal is never reported as successful enforcement.
type Outcome struct {
	Workload                Workload
	RuleID                  string
	Reason                  string
	Status                  string
	Authority               string
	BudgetBinding           string
	BudgetDocumentKnown     bool
	BudgetDocumentPresent   bool
	BudgetDocumentSHA256    string
	PricingDocumentRequired bool
	PricingDocumentKnown    bool
	PricingDocumentPresent  bool
	PricingDocumentSHA256   string
	PolicyRevision          uint64
	// ControlVerified means a stable handle was acquired and its signal
	// permission checked. It does not mean a signal or exit occurred.
	ControlVerified bool
	AlreadyExited   bool
	Stopped         bool
	// TermAttempted and KillAttempted mean the corresponding OS operation
	// callback was invoked. They do not prove that a signal was sent or that the
	// process exited; Stopped, AlreadyExited and Status carry observed results.
	TermAttempted bool
	KillAttempted bool
	Err           error
}

// Reconcile checks every supplied workload, including sessions that predate
// the daemon. It rechecks policy authority before each signal, and explicitly
// escalates a timed-out TERM to KILL only while that same authority still
// requires a stop. A canceled daemon never sends a cleanup signal.
func (s *Supervisor) Reconcile(ctx context.Context, workloads []Workload) []Outcome {
	out := make([]Outcome, 0, len(workloads))
	counts := make(map[Identity]int, len(workloads))
	for _, w := range workloads {
		counts[w.Identity]++
	}
	for _, w := range workloads {
		if ctx.Err() != nil {
			break
		}
		if w.SurfaceID == "" || !validIdentity(w.Identity) || counts[w.Identity] != 1 {
			out = append(out, Outcome{Workload: w, Status: "identity_unavailable", Err: ErrInvalidIdentity})
			continue
		}
		out = append(out, s.reconcileOne(ctx, w))
	}
	return out
}

func (s *Supervisor) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Supervisor) decision(ctx context.Context, w Workload) (PolicyDecision, error) {
	if s.Decide == nil {
		return PolicyDecision{}, errors.New("intervention: policy resolver unavailable")
	}
	if err := ctx.Err(); err != nil {
		return PolicyDecision{}, err
	}
	d, err := s.Decide(ctx, w)
	if err != nil {
		return PolicyDecision{}, err
	}
	if !d.Authorized {
		return d, nil
	}
	if d.Authority == "" || !d.ValidUntil.After(s.now()) {
		return PolicyDecision{}, errors.New("intervention: policy authority missing or expired")
	}
	return d, ctx.Err()
}

func (s *Supervisor) reconcileOne(ctx context.Context, w Workload) (out Outcome) {
	out.Workload = w
	d, err := s.decision(ctx, w)
	if err != nil {
		out.Status, out.Err = "policy_unavailable", err
		return out
	}
	if !d.Authorized {
		out.Status = "not_authorized"
		return out
	}
	out.RuleID = d.RuleID
	out.Reason = d.Reason
	out.recordDecision(d)
	acquire := s.Acquire
	if acquire == nil {
		acquire = func(ctx context.Context, id Identity) (ControlHandle, error) { return Acquire(ctx, id) }
	}
	h, err := acquire(ctx, w.Identity)
	if err != nil {
		out.Status, out.Err = "control_unavailable", err
		return out
	}
	defer func() {
		if err := h.Close(); err != nil {
			out.Err = errors.Join(out.Err, fmt.Errorf("intervention: release handle: %w", err))
		}
	}()
	out.ControlVerified = true
	if !d.Stop {
		out.Status = "allowed"
		return out
	}
	latest, err := s.decision(ctx, w)
	if err != nil || !sameStopAuthority(d, latest) {
		out.Status, out.Err = "decision_changed", err
		return out
	}
	out.recordDecision(latest)
	grace := s.GracePeriod
	if grace <= 0 {
		grace = 2 * time.Second
	}
	termCtx, termCancel := context.WithTimeout(ctx, grace)
	result, termErr, attempted := s.act(termCtx, w, latest, h.SignalTerminate)
	out.TermAttempted = attempted
	result, termErr = observeSignaledExit(termCtx, h, result, termErr, attempted)
	termCancel()
	if !attempted {
		out.Status, out.Err = unavailableActionStatus(termErr), termErr
		return out
	}
	if result.Observed && termErr == nil {
		out.Status, out.Stopped = "terminated", !result.AlreadyExited
		out.AlreadyExited = result.AlreadyExited
		if result.AlreadyExited {
			out.Status = "already_exited"
		}
		return out
	}
	if result.Observed || termErr == nil || !errors.Is(termErr, context.DeadlineExceeded) || ctx.Err() != nil {
		out.Status, out.Err = "termination_unverified", termErr
		return out
	}
	// Escalation is a fresh policy action. Removal/reset/re-enrollment while
	// waiting for TERM must prevent the old decision from issuing KILL.
	latest, err = s.decision(ctx, w)
	if err != nil || !sameStopAuthority(d, latest) {
		out.Status, out.Err = "decision_changed", err
		return out
	}
	out.recordDecision(latest)
	deadline := s.KillTimeout
	if deadline <= 0 {
		deadline = time.Second
	}
	killCtx, killCancel := context.WithTimeout(ctx, deadline)
	result, err, attempted = s.act(killCtx, w, latest, h.SignalKill)
	out.KillAttempted = attempted
	result, err = observeSignaledExit(killCtx, h, result, err, attempted)
	killCancel()
	if !attempted {
		out.Status, out.Err = unavailableActionStatus(err), err
		return out
	}
	if result.Observed && err == nil {
		out.Status, out.Stopped = "killed", !result.AlreadyExited
		out.AlreadyExited = result.AlreadyExited
		if result.AlreadyExited {
			out.Status = "already_exited"
		}
	} else {
		out.Status, out.Err = "termination_unverified", err
	}
	return out
}

func observeSignaledExit(ctx context.Context, h ControlHandle, result ExitResult, err error, attempted bool) (ExitResult, error) {
	if attempted && err == nil && !result.Observed {
		return h.WaitExit(ctx)
	}
	return result, err
}

func (o *Outcome) recordDecision(d PolicyDecision) {
	o.RuleID = boundedInterventionText(d.RuleID, 128)
	o.Reason = boundedInterventionText(d.Reason, 512)
	o.Authority = boundedInterventionText(d.Authority, 128)
	o.BudgetBinding = boundedInterventionText(d.BudgetBinding, 128)
	o.BudgetDocumentKnown = d.BudgetDocumentKnown
	o.BudgetDocumentPresent = d.BudgetDocumentPresent
	o.BudgetDocumentSHA256 = boundedInterventionText(d.BudgetDocumentSHA256, 128)
	o.PricingDocumentRequired = d.PricingDocumentRequired
	o.PricingDocumentKnown = d.PricingDocumentKnown
	o.PricingDocumentPresent = d.PricingDocumentPresent
	o.PricingDocumentSHA256 = boundedInterventionText(d.PricingDocumentSHA256, 128)
	o.PolicyRevision = d.PolicyRevision
}

func boundedInterventionText(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}

func sameStopAuthority(previous, latest PolicyDecision) bool {
	return latest.Authorized && latest.Stop && latest.Authority == previous.Authority
}

var errActionRevalidation = errors.New("intervention: action binding revalidation failed")

func unavailableActionStatus(err error) string {
	if errors.Is(err, errActionRevalidation) {
		return "control_unavailable"
	}
	return "policy_unavailable"
}

func (s *Supervisor) act(ctx context.Context, w Workload, d PolicyDecision, action func(context.Context) (ExitResult, error)) (result ExitResult, err error, attempted bool) {
	invoke := func(actionCtx context.Context) (ExitResult, error) {
		if s.Revalidate != nil {
			if err := s.Revalidate(actionCtx, w); err != nil {
				return ExitResult{}, errors.Join(errActionRevalidation, err)
			}
		}
		attempted = true
		return action(actionCtx)
	}
	if s.Fence != nil {
		result, err = s.Fence(ctx, w, d, invoke)
		return result, err, attempted
	}
	result, err = invoke(ctx)
	return result, err, attempted
}
