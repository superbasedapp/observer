package host

import (
	"context"
	"errors"
	"testing"
	"time"
)

// allowFakeLoginShell opens the test-binary guard for one test that drives a
// fake shell it wrote itself, and restores it after.
func allowFakeLoginShell(t *testing.T) {
	t.Helper()
	prev := loginShellBlocked
	loginShellBlocked = false
	t.Cleanup(func() { loginShellBlocked = prev })
}

// TestLoginShellBlockedInTestBinary (tracker F-031): inside a test binary the
// production capture never starts a shell. The real runLoginShell refuses
// with ErrLoginShellInTest before any exec, and NewEnv's LoginPath and
// CaptureLoginEnv come back with that error (the "no login merge" path every
// caller already takes), so no test that reaches the capture through a
// production path starts the developer's login shell.
func TestLoginShellBlockedInTestBinary(t *testing.T) {
	if !loginShellBlocked {
		t.Skip(AllowLoginShellInTestEnv + " is set: the guard is open for this run")
	}
	// A shell that would fail the test if it ever ran: the path does not
	// exist, so only the guard can produce ErrLoginShellInTest.
	_, err := runLoginShell(context.Background(), []string{"/nonexistent/bash", "-lic", "true"}, nil)
	if !errors.Is(err, ErrLoginShellInTest) {
		t.Fatalf("runLoginShell: %v, want ErrLoginShellInTest", err)
	}
	if _, err := CaptureLoginPath("/nonexistent/bash", time.Second); !errors.Is(err, ErrLoginShellInTest) {
		t.Fatalf("CaptureLoginPath: %v, want ErrLoginShellInTest", err)
	}
	if _, err := CaptureLoginEnv("/nonexistent/zsh", []string{"PATH"}, time.Second); !errors.Is(err, ErrLoginShellInTest) {
		t.Fatalf("CaptureLoginEnv: %v, want ErrLoginShellInTest", err)
	}
	env := NewEnv(Options{Shell: "/nonexistent/bash"})
	if env.LoginPath != nil {
		if _, err := env.LoginPath(); !errors.Is(err, ErrLoginShellInTest) {
			t.Fatalf("NewEnv LoginPath: %v, want ErrLoginShellInTest", err)
		}
	}
}
