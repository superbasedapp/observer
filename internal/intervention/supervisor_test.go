package intervention

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type supervisorTestHandle struct {
	termResult              ExitResult
	termErr                 error
	killResult              ExitResult
	killErr                 error
	waitResults             []ExitResult
	waitErrs                []error
	term, kill, wait, close int
}

func (h *supervisorTestHandle) SignalTerminate(context.Context) (ExitResult, error) {
	h.term++
	return h.termResult, h.termErr
}

func (h *supervisorTestHandle) SignalKill(context.Context) (ExitResult, error) {
	h.kill++
	return h.killResult, h.killErr
}

func (h *supervisorTestHandle) WaitExit(context.Context) (ExitResult, error) {
	idx := h.wait
	h.wait++
	var result ExitResult
	if idx < len(h.waitResults) {
		result = h.waitResults[idx]
	}
	var err error
	if idx < len(h.waitErrs) {
		err = h.waitErrs[idx]
	}
	return result, err
}
func (h *supervisorTestHandle) Close() error { h.close++; return nil }

func TestSupervisorPolicyAndExitProof(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	stop := PolicyDecision{Authorized: true, Stop: true, Authority: "org/member/generation/uid", ValidUntil: now.Add(time.Minute), RuleID: "B-602"}
	allow := stop
	allow.Stop = false
	newIdentity := stop
	newIdentity.Authority = "different-enrollment"
	expired := stop
	expired.ValidUntil = now
	for _, tc := range []struct {
		name                                      string
		decisions                                 []PolicyDecision
		handle                                    supervisorTestHandle
		wantStatus                                string
		wantStopped                               bool
		wantAcquire, wantTerm, wantKill, wantWait int
	}{
		{"under cap", []PolicyDecision{allow}, supervisorTestHandle{}, "allowed", false, 1, 0, 0, 0},
		{"unenrolled cannot stop", []PolicyDecision{{Stop: true}}, supervisorTestHandle{}, "not_authorized", false, 0, 0, 0, 0},
		{"expired authority", []PolicyDecision{expired}, supervisorTestHandle{}, "policy_unavailable", false, 0, 0, 0, 0},
		{"observed TERM", []PolicyDecision{stop}, supervisorTestHandle{waitResults: []ExitResult{{Observed: true}}}, "terminated", true, 1, 1, 0, 1},
		{"exited before TERM", []PolicyDecision{stop}, supervisorTestHandle{termResult: ExitResult{Observed: true, AlreadyExited: true}}, "already_exited", false, 1, 1, 0, 0},
		{"exited before KILL", []PolicyDecision{stop}, supervisorTestHandle{killResult: ExitResult{Observed: true, AlreadyExited: true}, waitErrs: []error{context.DeadlineExceeded}}, "already_exited", false, 1, 1, 1, 1},
		{"TERM ignored", []PolicyDecision{stop}, supervisorTestHandle{waitResults: []ExitResult{{}, {Observed: true}}, waitErrs: []error{context.DeadlineExceeded}}, "killed", true, 1, 1, 1, 2},
		{"no exit proof", []PolicyDecision{stop}, supervisorTestHandle{}, "termination_unverified", false, 1, 1, 0, 1},
		{"observed TERM with error", []PolicyDecision{stop}, supervisorTestHandle{waitResults: []ExitResult{{Observed: true}}, waitErrs: []error{ErrPermission}}, "termination_unverified", false, 1, 1, 0, 1},
		{"observed KILL with error", []PolicyDecision{stop}, supervisorTestHandle{waitResults: []ExitResult{{}, {Observed: true}}, waitErrs: []error{context.DeadlineExceeded, ErrPermission}}, "termination_unverified", false, 1, 1, 1, 2},
		{"permission error cannot trigger KILL", []PolicyDecision{stop}, supervisorTestHandle{termErr: ErrPermission}, "termination_unverified", false, 1, 1, 0, 0},
		{"removed before TERM", []PolicyDecision{stop, allow}, supervisorTestHandle{}, "decision_changed", false, 1, 0, 0, 0},
		{"removed before KILL", []PolicyDecision{stop, stop, allow}, supervisorTestHandle{waitErrs: []error{context.DeadlineExceeded}}, "decision_changed", false, 1, 1, 0, 1},
		{"re-enrolled before KILL", []PolicyDecision{stop, stop, newIdentity}, supervisorTestHandle{waitErrs: []error{context.DeadlineExceeded}}, "decision_changed", false, 1, 1, 0, 1},
		{"KILL unobserved", []PolicyDecision{stop}, supervisorTestHandle{waitErrs: []error{context.DeadlineExceeded, context.DeadlineExceeded}}, "termination_unverified", false, 1, 1, 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, acquired := 0, 0
			h := tc.handle
			s := Supervisor{
				Now: func() time.Time { return now },
				Decide: func(context.Context, Workload) (PolicyDecision, error) {
					i := calls
					calls++
					if i >= len(tc.decisions) {
						i = len(tc.decisions) - 1
					}
					return tc.decisions[i], nil
				},
				Acquire: func(context.Context, Identity) (ControlHandle, error) { acquired++; return &h, nil },
			}
			w := Workload{SurfaceID: "fixture/native", Identity: Identity{BootID: "boot", PID: 123, StartTicks: 10, UID: 1000, Executable: ExecutableIdentity{Device: 1, Inode: 2}}}
			got := s.Reconcile(context.Background(), []Workload{w})
			if len(got) != 1 || got[0].Status != tc.wantStatus || got[0].Stopped != tc.wantStopped {
				t.Fatalf("outcome=%+v", got)
			}
			if got[0].AlreadyExited != (tc.wantStatus == "already_exited") {
				t.Fatalf("already-exited evidence=%+v", got[0])
			}
			if got[0].TermAttempted != (tc.wantTerm > 0) || got[0].KillAttempted != (tc.wantKill > 0) {
				t.Fatalf("operation callback evidence=%+v", got[0])
			}
			if acquired != tc.wantAcquire || h.term != tc.wantTerm || h.kill != tc.wantKill || h.wait != tc.wantWait || h.close != acquired {
				t.Fatalf("acquire=%d term=%d kill=%d wait=%d close=%d", acquired, h.term, h.kill, h.wait, h.close)
			}
		})
	}
}

func TestSupervisorSignalFenceRefusalDoesNotEscalate(t *testing.T) {
	t.Parallel()
	for _, refuseAt := range []int{1, 2} {
		h := &supervisorTestHandle{waitErrs: []error{context.DeadlineExceeded}}
		calls := 0
		d := PolicyDecision{Authorized: true, Stop: true, Authority: "current-grant", ValidUntil: time.Now().Add(time.Minute)}
		s := Supervisor{
			Decide:  func(context.Context, Workload) (PolicyDecision, error) { return d, nil },
			Acquire: func(context.Context, Identity) (ControlHandle, error) { return h, nil },
			Fence: func(ctx context.Context, _ Workload, _ PolicyDecision, action func(context.Context) (ExitResult, error)) (ExitResult, error) {
				calls++
				if calls == refuseAt {
					return ExitResult{}, context.DeadlineExceeded
				}
				return action(ctx)
			},
		}
		w := Workload{SurfaceID: "fixture/native", Identity: Identity{BootID: "boot", PID: 123, StartTicks: 10, UID: 1000, Executable: ExecutableIdentity{Device: 1, Inode: 2}}}
		out := s.Reconcile(context.Background(), []Workload{w})
		if len(out) != 1 || out[0].Status != "policy_unavailable" || out[0].Stopped || h.term != refuseAt-1 || h.kill != 0 || h.wait != refuseAt-1 || calls != refuseAt {
			t.Fatalf("fence refusal %d: outcome=%+v term=%d kill=%d wait=%d fences=%d", refuseAt, out, h.term, h.kill, h.wait, calls)
		}
		if out[0].TermAttempted != (refuseAt == 2) || out[0].KillAttempted {
			t.Fatalf("fence refusal %d misstated callback invocation: %+v", refuseAt, out[0])
		}
	}
}

func TestSupervisorActionRevalidationAbstainsBeforeSignal(t *testing.T) {
	t.Parallel()
	h := &supervisorTestHandle{}
	d := PolicyDecision{Authorized: true, Stop: true, Authority: "current-grant", ValidUntil: time.Now().Add(time.Minute)}
	fenced := false
	s := Supervisor{
		Decide:  func(context.Context, Workload) (PolicyDecision, error) { return d, nil },
		Acquire: func(context.Context, Identity) (ControlHandle, error) { return h, nil },
		Revalidate: func(context.Context, Workload) error {
			return ErrBindingMismatch
		},
		Fence: func(ctx context.Context, _ Workload, _ PolicyDecision, action func(context.Context) (ExitResult, error)) (ExitResult, error) {
			fenced = true
			return action(ctx)
		},
	}
	w := Workload{SurfaceID: "fixture/native", Identity: Identity{BootID: "boot", PID: 123, StartTicks: 10, UID: 1000, Executable: ExecutableIdentity{Device: 1, Inode: 2}}}
	out := s.Reconcile(context.Background(), []Workload{w})
	if len(out) != 1 || out[0].Status != "control_unavailable" || !fenced ||
		out[0].TermAttempted || out[0].KillAttempted || h.term != 0 || h.kill != 0 || h.wait != 0 {
		t.Fatalf("revalidation outcome=%+v handle=%+v fenced=%v", out, h, fenced)
	}
}

func TestSupervisorBoundsPolicyEvidenceInOutcome(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	long := strings.Repeat("界", 1024)
	d := PolicyDecision{
		Authorized: true, Authority: long, BudgetBinding: long,
		BudgetDocumentKnown: true, BudgetDocumentPresent: true, BudgetDocumentSHA256: long,
		PricingDocumentRequired: true, PricingDocumentKnown: true, PricingDocumentPresent: true, PricingDocumentSHA256: long,
		ValidUntil: now.Add(time.Minute), RuleID: long, Reason: long,
	}
	h := &supervisorTestHandle{}
	s := Supervisor{
		Now:     func() time.Time { return now },
		Decide:  func(context.Context, Workload) (PolicyDecision, error) { return d, nil },
		Acquire: func(context.Context, Identity) (ControlHandle, error) { return h, nil },
	}
	w := Workload{SurfaceID: "fixture/native", Identity: Identity{BootID: "boot", PID: 123, StartTicks: 10, UID: 1000, Executable: ExecutableIdentity{Device: 1, Inode: 2}}}
	out := s.Reconcile(context.Background(), []Workload{w})
	if len(out) != 1 || len([]rune(out[0].Authority)) != 128 || len([]rune(out[0].BudgetBinding)) != 128 ||
		len([]rune(out[0].BudgetDocumentSHA256)) != 128 || len([]rune(out[0].PricingDocumentSHA256)) != 128 ||
		!out[0].PricingDocumentRequired || len([]rune(out[0].RuleID)) != 128 || len([]rune(out[0].Reason)) != 512 {
		t.Fatalf("unbounded outcome policy evidence: %+v", out)
	}
}

func TestSupervisorRefusesAmbiguousIdentityAndCanceledWork(t *testing.T) {
	t.Parallel()
	w := Workload{SurfaceID: "one", Identity: Identity{BootID: "boot", PID: 123, StartTicks: 10, UID: 1000, Executable: ExecutableIdentity{Device: 1, Inode: 2}}}
	s := Supervisor{Decide: func(context.Context, Workload) (PolicyDecision, error) {
		t.Fatal("ambiguous/canceled workload reached policy")
		return PolicyDecision{}, nil
	}}
	other := w
	other.SurfaceID = "other"
	got := s.Reconcile(context.Background(), []Workload{w, other})
	if len(got) != 2 || !errors.Is(got[0].Err, ErrInvalidIdentity) || !errors.Is(got[1].Err, ErrInvalidIdentity) {
		t.Fatalf("outcome=%+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := s.Reconcile(ctx, []Workload{w}); len(got) != 0 {
		t.Fatalf("canceled outcomes=%+v", got)
	}
}
