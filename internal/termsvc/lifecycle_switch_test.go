package termsvc

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// switchLifecycle is a lifecycle whose Create records an own-sandbox state.
type switchLifecycle struct {
	fakeLifecycle
	state string
}

func (f *switchLifecycle) Create(_ context.Context, req PrepareRequest) (CreateResult, error) {
	f.calls = append(f.calls, "create")
	return CreateResult{Run: SandboxRun{ID: "w1", Tool: req.Tool, Dir: "/ws/w1"}, Isolation: termrun.Isolation{Class: "process", NativeSandboxState: f.state}}, nil
}

// TestComposePrepareDestroysOnASwitchError (SBX-P3D audit finding 9): a
// recorded own-sandbox state the tool has no per-run switch for is refused
// after Create and before Attach, and the created run (its workspace) is
// destroyed; a state with nothing to apply passes as before.
func TestComposePrepareDestroysOnASwitchError(t *testing.T) {
	f := &switchLifecycle{state: "disabled_by_observer"}
	_, err := ComposePrepare(context.Background(), f, PrepareRequest{Tool: "a-tool-with-no-switch", ProjectRoot: "/p"})
	if !errors.Is(err, integration.ErrNoNativeSwitch) {
		t.Fatalf("err %v, want ErrNoNativeSwitch", err)
	}
	if !reflect.DeepEqual(f.calls, []string{"create", "destroy"}) {
		t.Fatalf("calls %v: a refused switch must destroy the prepared run before any attach", f.calls)
	}
	ok := &switchLifecycle{}
	if _, err := ComposePrepare(context.Background(), ok, PrepareRequest{Tool: "a-tool-with-no-switch", ProjectRoot: "/p"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ok.calls, []string{"create", "attach"}) {
		t.Fatalf("calls %v", ok.calls)
	}
}
