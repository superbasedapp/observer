package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// writeFakeShell writes an executable script at <dir>/<name> whose body is the
// given shell code, and returns its path. filepath.Base(path) == name so
// loginArgv routes it correctly.
func writeFakeShell(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write fake shell: %v", err)
	}
	return p
}

// marked wraps a PATH in the marker pair the capture script emits.
func marked(path string) string {
	return toolresolve.PathMarkBegin + path + toolresolve.PathMarkEnd
}

func TestCaptureLoginPath_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake shell not applicable on Windows")
	}
	// A fake "bash" that ignores its args and prints a banner plus a fixed,
	// marker-wrapped PATH — the banner is exactly what the marker pair exists
	// to survive.
	shell := writeFakeShell(t, "bash", "echo 'Welcome to Ubuntu'\necho '"+marked("/opt/a:/opt/b")+"'")

	got, err := CaptureLoginPath(shell, time.Second)
	if err != nil {
		t.Fatalf("CaptureLoginPath: %v", err)
	}
	want := []string{"/opt/a", "/opt/b"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCaptureLoginPath_Timeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake shell not applicable on Windows")
	}
	shell := writeFakeShell(t, "bash", `sleep 5`)

	start := time.Now()
	_, err := CaptureLoginPath(shell, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("capture did not honor timeout: took %s", elapsed)
	}
}

func TestCaptureLoginPath_UnknownShell(t *testing.T) {
	_, err := CaptureLoginPath("/usr/bin/nu", time.Second)
	if !errors.Is(err, ErrUnsupportedShell) {
		t.Errorf("err = %v, want ErrUnsupportedShell", err)
	}
}

func TestCaptureLoginPath_EmptyShell(t *testing.T) {
	_, err := CaptureLoginPath("", time.Second)
	if !errors.Is(err, ErrUnsupportedShell) {
		t.Errorf("err = %v, want ErrUnsupportedShell", err)
	}
}

func TestCaptureLoginPath_Fish(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake shell not applicable on Windows")
	}
	// The fake fish ignores args and prints a colon-joined, marker-wrapped
	// PATH, matching what `printf … (string join : $PATH)` would emit.
	shell := writeFakeShell(t, "fish", "echo '"+marked("/usr/local/bin:/home/u/.local/bin")+"'")
	got, err := CaptureLoginPath(shell, time.Second)
	if err != nil {
		t.Fatalf("CaptureLoginPath(fish): %v", err)
	}
	if len(got) != 2 || got[1] != "/home/u/.local/bin" {
		t.Errorf("got %v", got)
	}
}

func TestNewEnv_Shape(t *testing.T) {
	env := NewEnv(Options{})
	if env.GOOS != runtime.GOOS {
		t.Errorf("GOOS = %q, want %q", env.GOOS, runtime.GOOS)
	}
	if env.Stat == nil || env.EvalSymlinks == nil || env.Glob == nil {
		t.Error("NewEnv left a filesystem probe nil")
	}
	// LoginPath is nil only on a Windows daemon.
	if runtime.GOOS == "windows" {
		if env.LoginPath != nil {
			t.Error("LoginPath should be nil on a Windows daemon")
		}
	} else if env.LoginPath == nil {
		t.Error("LoginPath should be set on a POSIX daemon")
	}
	// PathExt is populated only on a Windows daemon; nil on POSIX.
	if runtime.GOOS != "windows" && env.PathExt != nil {
		t.Errorf("PathExt should be nil off Windows, got %v", env.PathExt)
	}
	// The DI-04/DI-22 injections must all be wired: EnvRoot expansion, the npm
	// -g prefix probe and the shebang sniff.
	if env.Getenv == nil {
		t.Error("NewEnv left Getenv nil (ProbeDir.EnvRoot would never expand)")
	}
	if env.NpmPrefix == nil {
		t.Error("NewEnv left NpmPrefix nil (the npm -g prefix would never be probed)")
	}
	if env.ReadHead == nil {
		t.Error("NewEnv left ReadHead nil (the #!/usr/bin/env shim note would never fire)")
	}
}

// TestLoginShellTableShape pins the §4.1.4 attempt ladder as DATA: bash and zsh
// try the INTERACTIVE login shell first (that is where nvm/fnm/oh-my-zsh live —
// and on this project's WSL box `-lc` vs `-lic` flips a verdict), with the
// cheaper login-only shell as the fallback; every other shell gets exactly one
// attempt, fish deliberately so.
func TestLoginShellTableShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		shell        string
		wantAttempts [][]string
	}{
		{shell: "bash", wantAttempts: [][]string{{"-lic"}, {"-lc"}}},
		{shell: "zsh", wantAttempts: [][]string{{"-lic"}, {"-lc"}}},
		{shell: "sh", wantAttempts: [][]string{{"-lc"}}},
		{shell: "ksh", wantAttempts: [][]string{{"-lc"}}},
		{shell: "dash", wantAttempts: [][]string{{"-lc"}}},
		{shell: "fish", wantAttempts: [][]string{{"-lc"}}},
	}

	for _, tc := range tests {
		t.Run(tc.shell, func(t *testing.T) {
			plan, ok := loginShellTable[tc.shell]
			if !ok {
				t.Fatalf("no plan for %q", tc.shell)
			}
			if len(plan.attempts) != len(tc.wantAttempts) {
				t.Fatalf("attempts = %v, want %v", plan.attempts, tc.wantAttempts)
			}
			for i := range plan.attempts {
				if strings.Join(plan.attempts[i], " ") != strings.Join(tc.wantAttempts[i], " ") {
					t.Errorf("attempt %d = %v, want %v", i, plan.attempts[i], tc.wantAttempts[i])
				}
			}
			if !strings.Contains(plan.script, toolresolve.PathMarkBegin) ||
				!strings.Contains(plan.script, toolresolve.PathMarkEnd) {
				t.Errorf("script does not emit the marker pair: %q", plan.script)
			}
		})
	}
}

// swapRunLoginShell installs a fake capture runner for the duration of a test.
func swapRunLoginShell(t *testing.T, fn func(ctx context.Context, argv, env []string) (string, error)) {
	t.Helper()
	prev := runLoginShell
	runLoginShell = fn
	t.Cleanup(func() { runLoginShell = prev })
}

// TestCaptureLoginPathAttemptLadder drives the ladder without a subprocess: an
// attempt is accepted ONLY on exit 0 AND a well-formed marker pair, otherwise
// the next attempt runs; all failing yields an error (the caller then proceeds
// on the process PATH alone).
func TestCaptureLoginPathAttemptLadder(t *testing.T) {
	// captureReply is one fake attempt result, in ladder order.
	type captureReply struct {
		out string
		err error
	}
	tests := []struct {
		name         string
		replies      []captureReply
		wantDirs     []string
		wantErr      bool
		wantAttempts int
	}{
		{
			name:         "first attempt wins",
			replies:      []captureReply{{out: marked("/a:/b")}},
			wantDirs:     []string{"/a", "/b"},
			wantAttempts: 1,
		},
		{
			name:         "a non-zero exit falls through to the next attempt",
			replies:      []captureReply{{err: errors.New("exit 1")}, {out: marked("/a")}},
			wantDirs:     []string{"/a"},
			wantAttempts: 2,
		},
		{
			name:         "a markerless capture is rejected, not half-trusted",
			replies:      []captureReply{{out: "Welcome to Ubuntu\n/usr/bin:/bin\n"}, {out: marked("/a")}},
			wantDirs:     []string{"/a"},
			wantAttempts: 2,
		},
		{
			name:         "every attempt failing is an error",
			replies:      []captureReply{{err: errors.New("exit 1")}, {out: "no markers"}},
			wantErr:      true,
			wantAttempts: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := 0
			var sawEnv []string
			swapRunLoginShell(t, func(_ context.Context, argv, env []string) (string, error) {
				if len(argv) < 3 {
					t.Fatalf("argv = %v, want shell + flags + script", argv)
				}
				sawEnv = env
				r := tc.replies[n]
				n++
				return r.out, r.err
			})

			dirs, err := CaptureLoginPath("/bin/bash", time.Second)
			if n != tc.wantAttempts {
				t.Errorf("ran %d attempts, want %d", n, tc.wantAttempts)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %v", dirs)
				}
				return
			}
			if err != nil {
				t.Fatalf("CaptureLoginPath: %v", err)
			}
			if strings.Join(dirs, ":") != strings.Join(tc.wantDirs, ":") {
				t.Errorf("dirs = %v, want %v", dirs, tc.wantDirs)
			}
			// The guard vars let an operator short-circuit hostile rc lines.
			var guard, term bool
			for _, e := range sawEnv {
				switch e {
				case "OBSERVER_RESOLVING_ENVIRONMENT=1":
					guard = true
				case "TERM=dumb":
					term = true
				}
			}
			if !guard || !term {
				t.Errorf("capture env missing the guard vars (guard=%v term=%v)", guard, term)
			}
		})
	}
}

func TestReadHead(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("#!/usr/bin/env node\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := readHead(short, 256)
	if err != nil {
		t.Fatalf("readHead: %v", err)
	}
	// A file shorter than n is not an error — whatever was read comes back.
	if string(got) != "#!/usr/bin/env node\n" {
		t.Errorf("got %q", got)
	}
	if got, err := readHead(short, 2); err != nil || string(got) != "#!" {
		t.Errorf("readHead(n=2) = %q, %v", got, err)
	}
	if _, err := readHead(filepath.Join(dir, "missing"), 16); err == nil {
		t.Error("expected an error for a missing file")
	}
	if got, err := readHead(short, 0); err != nil || got != nil {
		t.Errorf("readHead(n=0) = %q, %v; want nil, nil", got, err)
	}
}

// TestNpmPrefix pins the injected `npm prefix -g` probe: npm is located on the
// MERGED PATH (not exec.LookPath's view of the daemon's frozen PATH), the
// output's last non-empty line is the prefix, and a missing npm is an error the
// resolver renders as a Note rather than a failure.
func TestNpmPrefix(t *testing.T) {
	dir := t.TempDir()
	npmName := "npm"
	if runtime.GOOS == "windows" {
		npmName = "npm.cmd"
	}
	if err := os.WriteFile(filepath.Join(dir, npmName), []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("write fake npm: %v", err)
	}

	prev := runNpmPrefix
	t.Cleanup(func() { runNpmPrefix = prev })

	var sawBin string
	runNpmPrefix = func(_ context.Context, npmBin string) (string, error) {
		sawBin = npmBin
		return "npm warn config global is deprecated\n/home/u/.hermes/node\n", nil
	}

	env := toolresolve.Env{ProcessPath: []string{dir}}
	got, err := npmPrefix(env, time.Second)
	if err != nil {
		t.Fatalf("npmPrefix: %v", err)
	}
	if got != "/home/u/.hermes/node" {
		t.Errorf("prefix = %q, want the last non-empty line", got)
	}
	if sawBin != filepath.Join(dir, npmName) {
		t.Errorf("npm resolved to %q, want the merged-PATH hit", sawBin)
	}

	// npm nowhere on the merged PATH: an error, never a panic or a guess.
	if _, err := npmPrefix(toolresolve.Env{ProcessPath: []string{t.TempDir()}}, time.Second); err == nil {
		t.Error("expected an error when npm is not on the merged PATH")
	}

	// The login-shell half of the merged PATH counts too — that is the whole
	// point of not using exec.LookPath here.
	loginEnv := toolresolve.Env{LoginPath: func() ([]string, error) { return []string{dir}, nil }}
	if _, err := npmPrefix(loginEnv, time.Second); err != nil {
		t.Errorf("npmPrefix via a login-only dir: %v", err)
	}
}
