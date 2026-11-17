package sandbox

import (
	"errors"
	"testing"
)

// TestBwrapUnsharesPID (lane ptrace): the strace switch's pid-namespace
// ground reads --unshare-pid (or --unshare-all) among the options only,
// never an operand or the inner argv, and an option the scan does not know
// is an error (the host helper then refuses, fail closed). Every plan
// BuildPlan builds carries it, on every egress tier.
func TestBwrapUnsharesPID(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		cmd  []string
		want bool
		err  bool
	}{
		{"the flag", []string{"/usr/bin/bwrap", "--ro-bind", "/", "/", "--unshare-pid", "--", "x"}, true, false},
		{"unshare-all", []string{"/usr/bin/bwrap", "--unshare-all", "--", "x"}, true, false},
		{"only in the inner argv", []string{"/usr/bin/bwrap", "--ro-bind", "/", "/", "--", "--unshare-pid"}, false, false},
		{"only as an operand", []string{"/usr/bin/bwrap", "--setenv", "X", "--unshare-pid", "--", "x"}, false, false},
		{"none", []string{"/usr/bin/bwrap", "--ro-bind", "/", "/", "--", "x"}, false, false},
		{"an unknown option first", []string{"/usr/bin/bwrap", "--frobnicate", "--unshare-pid", "--", "x"}, false, true},
		{"empty", nil, false, false},
	} {
		got, err := BwrapUnsharesPID(c.cmd)
		if got != c.want || (err != nil) != c.err || (c.err && !errors.Is(err, ErrBwrapFlagUnknown)) {
			t.Errorf("%s: %v, %v; want %v (err %v)", c.name, got, err, c.want, c.err)
		}
	}
	for _, mode := range []Egress{EgressHost, EgressInternet, EgressProxyOnly, EgressNone} {
		plan, err := BuildPlan(netReq(mode))
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if own, err := BwrapUnsharesPID(append([]string{"/usr/bin/bwrap"}, plan.Argv([]string{"true"})...)); err != nil || !own {
			t.Errorf("%s: the plan gives no pid namespace of its own (%v)", mode, err)
		}
	}
}
