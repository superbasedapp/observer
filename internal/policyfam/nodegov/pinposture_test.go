package nodegov

import (
	"errors"
	"testing"
)

// TestPinPostureRegistry is the table test of the module posture-provider
// seam (N3): registration rules and which evaluator runs for which pins.
func TestPinPostureRegistry(t *testing.T) {
	refuse := func(axis string) PinPostureCheck {
		return func(map[string]any) (string, error) { return axis, errors.New("weaker") }
	}
	var seen map[string]any
	record := func(pins map[string]any) (string, error) { seen = pins; return "", nil }

	restore := SwapPinPostureForTest("test.a", []string{"terminal.sandbox.backends", "terminal.sandbox.mask_paths"}, record)
	defer restore()

	cases := []struct {
		name     string
		pins     map[string]any
		wantAxis string
		wantSeen int
	}{
		{"no pins runs nothing", nil, "", -1},
		{"pins the module does not own run nothing", map[string]any{"guard.enabled": true}, "", -1},
		{"the module sees only its own keys", map[string]any{"guard.enabled": true, "terminal.sandbox.mask_paths": []string{"/x"}}, "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen = nil
			axis, err := CheckPinPosture(tc.pins)
			if axis != tc.wantAxis || err != nil {
				t.Fatalf("axis %q err %v", axis, err)
			}
			if tc.wantSeen < 0 && seen != nil {
				t.Fatalf("the evaluator ran for %v", tc.pins)
			}
			if tc.wantSeen >= 0 && len(seen) != tc.wantSeen {
				t.Fatalf("evaluator saw %v, want %d keys", seen, tc.wantSeen)
			}
		})
	}

	r2 := SwapPinPostureForTest("test.b", []string{"terminal.sandbox.home_mode"}, refuse("home"))
	axis, err := CheckPinPosture(map[string]any{"terminal.sandbox.home_mode": "tmpfs"})
	if axis != "home" || err == nil {
		t.Fatalf("refusal not surfaced: %q %v", axis, err)
	}
	r2()
	if axis, err := CheckPinPosture(map[string]any{"terminal.sandbox.home_mode": "tmpfs"}); axis != "" || err != nil {
		t.Fatalf("restore left the refusing evaluator: %q %v", axis, err)
	}

	regs := []struct {
		name  string
		owner string
		keys  []string
		check PinPostureCheck
	}{
		{"unknown key", "test.c", []string{"terminal.sandbox.enabled"}, record},
		{"a key another owner holds", "test.c", []string{"terminal.sandbox.backends"}, record},
		{"duplicate owner", "test.a", []string{"terminal.sandbox.home_mode"}, record},
		{"nil check", "test.c", []string{"terminal.sandbox.home_mode"}, nil},
		{"no owner", "", []string{"terminal.sandbox.home_mode"}, record},
	}
	for _, r := range regs {
		if err := RegisterPinPosture(r.owner, r.keys, r.check); err == nil {
			t.Errorf("%s: registration accepted", r.name)
		}
	}
}

// TestSandboxPinRowsRefuseExpanding: a settings.pin body forcing an EXPANDS
// key (or another restrictive-only sandbox key) to its unsafe value is
// refused at compile, which the publish lint and every node's accept path
// both run (sandbox plan v2 section 13 P1b acceptance).
func TestSandboxPinRowsRefuseExpanding(t *testing.T) {
	unsafe := map[string]any{
		"terminal.sandbox.extra_rw_binds":           []any{"/srv"},
		"terminal.sandbox.extra_ro_binds":           []any{"/srv"},
		"terminal.sandbox.egress_allow_cidrs":       []any{"10.0.0.0/8"},
		"terminal.sandbox.allow_tool_config_writes": true,
		"terminal.sandbox.allow_remote_clone":       true,
		"terminal.sandbox.allow_worktree_source":    true,
		"terminal.sandbox.home_mode":                "readonly",
		"terminal.sandbox.default_on":               false,
		"terminal.sandbox.backends":                 []any{},
		"terminal.sandbox.remote_allowed_hosts":     []any{},
		"terminal.sandbox.workspace_retention_days": float64(-1),
		"terminal.sandbox.prep_timeout_seconds":     float64(5),
	}
	for k, v := range unsafe {
		if _, err := compilePinned(map[string]any{k: v}); err == nil {
			t.Errorf("pinned.%s = %v compiled; it must be refused", k, v)
		}
	}
	safe := map[string]any{
		"terminal.sandbox.extra_rw_binds":           []any{},
		"terminal.sandbox.egress_allow_cidrs":       []any{},
		"terminal.sandbox.allow_remote_clone":       false,
		"terminal.sandbox.home_mode":                "tmpfs",
		"terminal.sandbox.default_on":               true,
		"terminal.sandbox.backends":                 []any{"bwrap"},
		"terminal.sandbox.remote_allowed_hosts":     []any{"github.com"},
		"terminal.sandbox.mask_paths":               []any{},
		"terminal.sandbox.workspace_retention_days": float64(0),
		"terminal.sandbox.prep_timeout_seconds":     float64(600),
	}
	if _, err := compilePinned(safe); err != nil {
		t.Fatalf("safe sandbox pins refused: %v", err)
	}
}

// TestNotPinnableYetIsNotPinnable keeps the "not pinnable yet" list out of
// the pin rail, and its reasons free of dashes.
func TestNotPinnableYetIsNotPinnable(t *testing.T) {
	for _, k := range NotPinnableYet {
		if IsPinnableKey(k.Key) {
			t.Errorf("%s is listed as not pinnable yet but is a PinnableKeys row", k.Key)
		}
		if k.Reason == "" {
			t.Errorf("%s has no reason", k.Key)
		}
	}
	found := false
	for _, k := range Vocabulary().NotPinnableYet {
		found = found || k.Key == "terminal.sandbox.enabled"
	}
	if !found {
		t.Fatal("terminal.sandbox.enabled is not served as not pinnable yet (G48)")
	}
}

// TestPinPostureWarnings: the publish lint notes the list operators whose
// result depends on each node's own list, and nothing else.
func TestPinPostureWarnings(t *testing.T) {
	got := PinPostureWarnings(map[string]any{
		"terminal.sandbox.backends":             []string{"bwrap"},
		"terminal.sandbox.remote_allowed_hosts": []string{"github.com"},
		"terminal.sandbox.mask_paths":           []string{"/x"},
		"guard.enabled":                         true,
	})
	if len(got) != 2 {
		t.Fatalf("warnings = %v, want one for backends and one for the hosts", got)
	}
}
