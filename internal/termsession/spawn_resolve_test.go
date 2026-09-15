package termsession

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// withLookProgram swaps the package-level PATH resolver for the duration of a
// test (restoring it on cleanup). These tests therefore must NOT run in
// parallel with each other.
func withLookProgram(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	prev := lookProgram
	lookProgram = fn
	t.Cleanup(func() { lookProgram = prev })
}

// TestResolveSpawnArgv pins the platform-neutral half of the Spec argv
// contract: argv[0] becomes the absolute program PATH resolution found, the
// arguments are untouched, a cwd-only hit is REFUSED, and a miss is an honest
// wrapped error rather than a silent launch attempt.
func TestResolveSpawnArgv(t *testing.T) {
	notFound := errors.New("not found in %PATH%")

	tests := []struct {
		name    string
		argv    []string
		look    func(string) (string, error)
		want    []string
		wantErr error  // errors.Is target ("" = none)
		wantMsg string // substring of the error message
	}{
		{
			name: "bare name resolves to the PATHEXT hit and keeps its args",
			argv: []string{"npm", "install", "-g", "@openai/codex"},
			look: func(string) (string, error) { return `C:\Program Files\nodejs\npm.cmd`, nil },
			want: []string{`C:\Program Files\nodejs\npm.cmd`, "install", "-g", "@openai/codex"},
		},
		{
			name: "absolute program passes through",
			argv: []string{"/usr/bin/observer", "claude"},
			look: func(p string) (string, error) { return p, nil },
			want: []string{"/usr/bin/observer", "claude"},
		},
		{
			name:    "not found is a wrapped, named error",
			argv:    []string{"definitely-not-a-real-program"},
			look:    func(string) (string, error) { return "", notFound },
			wantErr: notFound,
			wantMsg: `cannot find "definitely-not-a-real-program" on PATH`,
		},
		{
			name:    "a cwd-only hit is refused",
			argv:    []string{"npm"},
			look:    func(string) (string, error) { return "npm.cmd", exec.ErrDot },
			wantErr: exec.ErrDot,
			wantMsg: "working directory",
		},
		{
			name:    "empty argv is an invalid spec",
			argv:    nil,
			look:    func(string) (string, error) { return "", nil },
			wantErr: ErrInvalidSpec,
		},
		{
			name:    "blank argv[0] is an invalid spec",
			argv:    []string{"", "claude"},
			look:    func(string) (string, error) { return "", nil },
			wantErr: ErrInvalidSpec,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withLookProgram(t, tc.look)
			got, err := resolveSpawnArgv(tc.argv)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want errors.Is(%v)", err, tc.wantErr)
				}
				if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("err = %q, want it to mention %q", err, tc.wantMsg)
				}
				if got != nil {
					t.Fatalf("argv = %q on error, want nil", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveSpawnArgv: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("argv = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("argv[%d] = %q, want %q (full: %q)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

// TestResolveSpawnArgvDoesNotAliasInput pins that the resolved argv is a fresh
// slice: the Spec's own ExtraArgs/SetupArgv backing array must never be
// mutated through the value handed to the OS spawner.
func TestResolveSpawnArgvDoesNotAliasInput(t *testing.T) {
	withLookProgram(t, func(p string) (string, error) { return "/resolved/" + p, nil })
	src := []string{"prog", "arg"}
	got, err := resolveSpawnArgv(src)
	if err != nil {
		t.Fatalf("resolveSpawnArgv: %v", err)
	}
	got[1] = "mutated"
	if src[1] != "arg" {
		t.Fatal("resolveSpawnArgv returned a slice aliasing the caller's arguments")
	}
}
