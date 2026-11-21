package gitroute

import "testing"

// TestEnvironmental walks the failure table: a failure of the Windows route
// itself falls back to the WSL git; git's own answer, and running out of
// time, do not.
func TestEnvironmental(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    Failure
		want bool
	}{
		{"interop off or git.exe gone", Failure{Unavailable: true, ExitCode: -1}, true},
		{"killed without an exit code", Failure{ExitCode: -1}, true},
		{"dubious ownership", Failure{ExitCode: 128, Stderr: "fatal: detected dubious ownership in repository at 'D:/x'"}, true},
		{"cannot change to the directory", Failure{ExitCode: 128, Stderr: "fatal: cannot change to 'D:\\x': No such file or directory"}, true},
		{"no repository seen", Failure{ExitCode: 128, Stderr: "fatal: not a git repository (or any of the parent directories): .git"}, true},
		{"its own timeout", Failure{TimedOut: true, ExitCode: -1}, false},
		{"the scan's budget", Failure{Canceled: true, Unavailable: true}, false},
		{"unborn HEAD is git's answer", Failure{ExitCode: 128, Stderr: "fatal: ambiguous argument 'HEAD': unknown revision"}, false},
		{"a missing object is git's answer", Failure{ExitCode: 128, Stderr: "fatal: bad object deadbeef"}, false},
		{"a quiet lookup miss is git's answer", Failure{ExitCode: 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, why := Environmental(tc.f)
			if got != tc.want || why == "" {
				t.Fatalf("Environmental(%+v) = %v (%q), want %v", tc.f, got, why, tc.want)
			}
		})
	}
}
