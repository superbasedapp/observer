package sandbox

import (
	"errors"
	"strings"
	"testing"
)

// TestCanaryReason (live checks 2026-10-22, InstaBox and Daytona, D3): the
// canary's refusal names the cause bwrap printed, and names a user-namespace
// sysctl only when it reads restrictive. The stderr strings are the live
// ones.
func TestCanaryReason(t *testing.T) {
	exit1 := errors.New("exit status 1")
	sysctls := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	instabox := sysctls(map[string]string{"user.max_user_namespaces": "31839"})
	daytona := sysctls(map[string]string{"kernel.unprivileged_userns_clone": "1", "user.max_user_namespaces": "2147483647", "kernel.apparmor_restrict_unprivileged_userns": "1"})
	locked := sysctls(map[string]string{"kernel.unprivileged_userns_clone": "0", "user.max_user_namespaces": "15000"})
	cases := []struct {
		name    string
		stderr  string
		sysctl  func(string) (string, bool)
		cause   string
		want    []string
		notWant []string
	}{
		{
			"instabox overmounted /proc", "bwrap: Can't mount proc on /proc: Operation not permitted\n", instabox, "proc_mount_denied",
			[]string{"Can't mount proc on /proc", "/proc/<pid>/root"},
			[]string{"kernel.unprivileged_userns_clone", "restrictive here"},
		},
		{
			"daytona uid map", "bwrap: setting up uid map: Permission denied\n", daytona, "uid_map_denied",
			[]string{"uid map", "kernel.apparmor_restrict_unprivileged_userns = 1"},
			[]string{"kernel.unprivileged_userns_clone", "user.max_user_namespaces"},
		},
		{
			"userns off", "bwrap: No permissions to creating new namespace, likely because the kernel does not allow non-privileged user namespaces. On e.g. debian this can be enabled with 'sysctl kernel.unprivileged_userns_clone=1'.", locked, "userns_denied",
			[]string{"kernel.unprivileged_userns_clone = 0"},
			[]string{"user.max_user_namespaces ="},
		},
		{
			"setuid bwrap missing", "bwrap: Creating new namespace failed, likely because the kernel does not support user namespaces.  bwrap must be installed setuid on such systems.", locked, "setuid_bwrap_required",
			[]string{"not setuid"},
			nil,
		},
		{"no stderr", "", nil, "unknown", []string{"smoke test failed (exit status 1)"}, []string{"restrictive"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var err error = exit1
			if c.stderr != "" {
				err = &CanaryFailure{Err: exit1, Stderr: c.stderr}
			}
			got := CanaryReason(err, c.sysctl)
			if !strings.HasSuffix(got, "["+c.cause+"]") {
				t.Fatalf("cause: %s", got)
			}
			for _, w := range c.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q: %s", w, got)
				}
			}
			for _, w := range c.notWant {
				if strings.Contains(got, w) {
					t.Errorf("names %q: %s", w, got)
				}
			}
		})
	}
	// Probe carries it.
	av := Probe(Env{
		GOOS: "linux", LookBwrap: func() (string, error) { return "/usr/bin/bwrap", nil },
		Version: func() (string, error) { return "bubblewrap 0.12.0", nil },
		Canary: func() error {
			return &CanaryFailure{Err: exit1, Stderr: "bwrap: Can't mount proc on /proc: Operation not permitted"}
		}, ReadSysctl: instabox,
	})
	if av.Verdict != VerdictUserNSDenied || !strings.Contains(av.Reason, "proc_mount_denied") || strings.Contains(av.Reason, "unprivileged_userns_clone") {
		t.Fatalf("probe %+v", av)
	}
}

// TestScrubCanaryStderr: paths outside the canary's plan are replaced, the
// plan's own are kept, and the text is bounded.
func TestScrubCanaryStderr(t *testing.T) {
	got := ScrubCanaryStderr("bwrap: Can't find source path /home/u/secret/x: No such file or directory\nbwrap: Can't mount proc on /proc: x")
	if strings.Contains(got, "/home/u") || !strings.Contains(got, "<path>") || !strings.Contains(got, "/proc:") && !strings.Contains(got, "on /proc") {
		t.Fatalf("scrubbed %q", got)
	}
	if long := ScrubCanaryStderr(strings.Repeat("x", 1000)); len(long) > maxCanaryStderr+3 {
		t.Fatalf("not bounded: %d", len(long))
	}
}
