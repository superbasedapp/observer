package notify

import "testing"

// TestNewDesktopInertInTestBinary pins TESTNOTIFY-1 (FU-235): a test binary
// never runs a real desktop helper, so a hook or guard test that drives a
// blocking verdict cannot pop a real toast on the developer's desktop. The
// probe is a helper name that cannot exist: the real runner fails to start
// it, the inert one reports success without starting anything.
func TestNewDesktopInertInTestBinary(t *testing.T) {
	t.Setenv(AllowRealNotifyInTestEnv, "")
	if err := NewDesktop().run("observer-no-such-notify-helper-tn1"); err != nil {
		t.Fatalf("NewDesktop in a test binary started a real helper: %v", err)
	}
}

// TestDesktopRunnerTable pins the runner choice, one row per case.
func TestDesktopRunnerTable(t *testing.T) {
	cases := []struct {
		name        string
		inTest      bool
		allowInTest bool
		wantReal    bool
	}{
		{"production binary runs the helper", false, false, true},
		{"production ignores the test escape hatch", false, true, true},
		{"test binary is inert", true, false, false},
		{"test binary that opted in runs the helper", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := desktopRunner(tc.inTest, tc.allowInTest)("observer-no-such-notify-helper-tn1")
			if gotReal := err != nil; gotReal != tc.wantReal {
				t.Fatalf("real runner = %v, want %v (err %v)", gotReal, tc.wantReal, err)
			}
		})
	}
}
