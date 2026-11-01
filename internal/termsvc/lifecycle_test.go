package termsvc

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// fakeLifecycle records the operations ComposePrepare drives.
type fakeLifecycle struct {
	attachErr error
	calls     []string
}

func (f *fakeLifecycle) Create(_ context.Context, req PrepareRequest) (CreateResult, error) {
	f.calls = append(f.calls, "create")
	return CreateResult{Run: SandboxRun{ID: "w1", Tool: req.Tool, Dir: req.ProjectRoot}, Note: "n", Isolation: termrun.Isolation{Class: "process"}}, nil
}

func (f *fakeLifecycle) Attach(context.Context, CreateResult) (AttachResult, error) {
	f.calls = append(f.calls, "attach")
	return AttachResult{WrapArgv: []string{"bwrap", "--"}}, f.attachErr
}

func (f *fakeLifecycle) Resize(context.Context, SandboxRun, uint16, uint16) (LifecycleResult, error) {
	return LifecycleResult{Verdict: VerdictPTYOwned}, nil
}

func (f *fakeLifecycle) Signal(context.Context, SandboxRun, string) (LifecycleResult, error) {
	return LifecycleResult{Verdict: VerdictPTYOwned}, nil
}

func (f *fakeLifecycle) Copy(context.Context, CopyRequest) (LifecycleResult, error) {
	return LifecycleResult{Verdict: VerdictNotSupported}, nil
}

func (f *fakeLifecycle) Checkpoint(context.Context, SandboxRun) (LifecycleResult, error) {
	return LifecycleResult{Verdict: VerdictNotSupported}, nil
}

func (f *fakeLifecycle) Stop(context.Context, SandboxRun, time.Duration) (LifecycleResult, error) {
	return LifecycleResult{Verdict: VerdictPTYOwned}, nil
}

func (f *fakeLifecycle) Destroy(context.Context, SandboxRun) (LifecycleResult, error) {
	f.calls = append(f.calls, "destroy")
	return LifecycleResult{Verdict: VerdictNothingToRelease}, nil
}

// TestComposePrepareIsCreateThenAttach: Prepare's result is exactly Create's
// workspace and evidence with Attach's argv, and an Attach failure destroys
// the created run.
func TestComposePrepareIsCreateThenAttach(t *testing.T) {
	f := &fakeLifecycle{}
	got, err := ComposePrepare(context.Background(), f, PrepareRequest{Tool: "claude-code", ProjectRoot: "/p"})
	if err != nil {
		t.Fatal(err)
	}
	want := PrepareResult{Dir: "/p", WrapArgv: []string{"bwrap", "--"}, Note: "n", Isolation: termrun.Isolation{Class: "process"}}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(f.calls, []string{"create", "attach"}) {
		t.Fatalf("got %+v calls %v", got, f.calls)
	}
	bad := &fakeLifecycle{attachErr: errors.New("no bwrap")}
	if _, err := ComposePrepare(context.Background(), bad, PrepareRequest{}); err == nil {
		t.Fatal("an attach failure was swallowed")
	}
	if !reflect.DeepEqual(bad.calls, []string{"create", "attach", "destroy"}) {
		t.Fatalf("calls %v: a failed attach must destroy the run", bad.calls)
	}
}
