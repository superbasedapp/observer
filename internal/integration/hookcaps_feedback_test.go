package integration

import (
	"reflect"
	"testing"
)

// TestRegisterWhenEvents pins the opt-in event lists (lane SEC-H): a
// RegisterWhen binding adds its event only while its component is selected,
// and an event another binding registers is never listed for removal.
func TestRegisterWhenEvents(t *testing.T) {
	h := HookSpec{Bindings: []HookBinding{
		{Cap: HookCapToolGate, Phase: HookPhasePre, NativeEvent: "BeforeTool", Registered: true},
		{Cap: HookCapToolObserve, Phase: HookPhasePost, NativeEvent: "AfterTool"},
		{Cap: HookCapContextInject, Phase: HookPhasePost, NativeEvent: "AfterTool", RegisterWhen: "security.feedback"},
		{Cap: HookCapContextInject, Phase: HookPhasePost, NativeEvent: "BeforeTool", RegisterWhen: "security.feedback"},
	}}
	on := func(string) bool { return true }
	off := func(string) bool { return false }
	if got := h.RegisteredEventsWith(nil); !reflect.DeepEqual(got, []string{"BeforeTool"}) {
		t.Errorf("nil selection: %v", got)
	}
	if got := h.RegisteredEventsWith(off); !reflect.DeepEqual(got, []string{"BeforeTool"}) {
		t.Errorf("not selected: %v", got)
	}
	if got := h.RegisteredEventsWith(on); !reflect.DeepEqual(got, []string{"BeforeTool", "AfterTool"}) {
		t.Errorf("selected: %v", got)
	}
	if got := h.OptInEvents(off); !reflect.DeepEqual(got, []string{"AfterTool"}) {
		t.Errorf("removal list: %v", got)
	}
	if got := h.OptInEvents(on); len(got) != 0 {
		t.Errorf("removal list while selected: %v", got)
	}
}

// TestRegisterWhenRowsAreNeverRegistered: an opt-in binding is never
// Registered (so no static surface and no `observer start` live rule
// counts it), and RegisteredEvents is unchanged by the opt-in rows on every
// registry row.
func TestRegisterWhenRowsAreNeverRegistered(t *testing.T) {
	for _, c := range Capabilities() {
		for _, b := range c.Hook.Bindings {
			if b.RegisterWhen != "" && b.Registered {
				t.Errorf("%s/%s: a RegisterWhen binding is Registered", c.Tool, b.NativeEvent)
			}
		}
		if !reflect.DeepEqual(c.Hook.RegisteredEvents(), c.Hook.RegisteredEventsWith(nil)) {
			t.Errorf("%s: RegisteredEventsWith(nil) differs", c.Tool)
		}
	}
}
