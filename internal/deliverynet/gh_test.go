//go:build !windows

package deliverynet

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/shimguard"
)

// fakeGH writes a shell script standing in for gh: it records its argv, its
// environment and its stdin, prints stdout and stderr, and exits with code.
func fakeGH(t *testing.T, stdout, stderr string, code int) (bin, dir string) {
	t.Helper()
	dir = t.TempDir()
	for name, body := range map[string]string{"out": stdout, "err": stderr} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := "#!/bin/sh\n" +
		"D='" + dir + "'\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$D/argv\"\n" +
		"env > \"$D/env\"\n" +
		"cat > \"$D/stdin\"\n" +
		"cat \"$D/out\"\n" +
		"cat \"$D/err\" >&2\n" +
		"exit " + strconv.Itoa(code) + "\n"
	bin = filepath.Join(dir, "gh")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // G306: test script must be executable
		t.Fatal(err)
	}
	return bin, dir
}

func ghClient(bin string) *Client {
	env := map[string]string{"PATH": "/usr/bin:/bin", "HOME": "/home/u", "AWS_SECRET_ACCESS_KEY": "leak", "GIT_DIR": "/user/repo/.git"}
	return New(Options{
		Getenv:  func(k string) string { return env[k] },
		Resolve: func(string) (string, error) { return bin, nil },
	})
}

func TestGHModeFixedArgvEnvAndStdin(t *testing.T) {
	bin, dir := fakeGH(t, `{"login":"ghuser"}`, "", 0)
	acct, err := ghClient(bin).User(context.Background(), Auth{Mode: AuthGHCLI, Host: GitHubDotCom})
	if err != nil || acct.Login != "ghuser" {
		t.Fatalf("%+v %v", acct, err)
	}
	argv, _ := os.ReadFile(filepath.Join(dir, "argv"))
	got := strings.Split(strings.TrimSpace(string(argv)), "\n")
	want := []string{"api", "-H", "Accept:application/vnd.github+json", "user"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv %q want %q", got, want)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	for _, bad := range []string{"AWS_SECRET_ACCESS_KEY", "GIT_DIR"} {
		if strings.Contains(string(env), bad+"=") {
			t.Errorf("env leaked %s", bad)
		}
	}
	if !strings.Contains(string(env), "GH_PROMPT_DISABLED=1") {
		t.Errorf("GH_PROMPT_DISABLED missing")
	}
	if in, _ := os.ReadFile(filepath.Join(dir, "stdin")); len(in) != 0 {
		t.Errorf("stdin not empty: %q", in)
	}
}

func TestGHArgvGHES(t *testing.T) {
	got := GHArgv("GHE.corp.example", "/repos/o/r/pulls/3")
	want := []string{"gh", "api", "-H", "Accept:application/vnd.github+json", "--hostname", "ghe.corp.example", "repos/o/r/pulls/3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
}

func TestGHModeErrors(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		code   int
		want   Kind
	}{
		{"422 not in repo", "gh: No commit found for SHA: x (HTTP 422)", 1, ""},
		{"404", "gh: Not Found (HTTP 404)", 1, KindNotFound},
		{"401", "gh: Bad credentials (HTTP 401)", 1, KindAuthFailed},
		{"rate", "gh: API rate limit exceeded for user (HTTP 403)", 1, KindRateLimited},
		{"signed out", "To get started with GitHub CLI, please run:  gh auth login", 4, KindAuthFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, _ := fakeGH(t, `{"message":"x"}`, tc.stderr, tc.code)
			prs, inRepo, err := ghClient(bin).CommitPulls(context.Background(), Auth{Mode: AuthGHCLI, Host: GitHubDotCom}, "o/r", "abcdef1234567")
			if tc.want == "" {
				if err != nil || inRepo || len(prs) != 0 {
					t.Fatalf("%v %v %v", prs, inRepo, err)
				}
				return
			}
			if KindOf(err) != tc.want {
				t.Fatalf("kind %s want %s", KindOf(err), tc.want)
			}
			if strings.Contains(err.Error(), "gh:") {
				t.Fatalf("stderr text leaked into the error: %v", err)
			}
		})
	}
}

func TestGHModeHostAllowList(t *testing.T) {
	bin, dir := fakeGH(t, `{"login":"x"}`, "", 0)
	_, err := ghClient(bin).User(context.Background(), Auth{Mode: AuthGHCLI, Host: "evil.example"})
	if KindOf(err) != KindHostNotAllowed {
		t.Fatalf("kind %s", KindOf(err))
	}
	if _, err := os.Stat(filepath.Join(dir, "argv")); err == nil {
		t.Fatal("gh ran for a host that is not allowed")
	}
}

func TestLookPathSkipsShimsAndExcludedDirs(t *testing.T) {
	shimDir, excluded, real := t.TempDir(), t.TempDir(), t.TempDir()
	write := func(d, body string) {
		if err := os.WriteFile(filepath.Join(d, "gh"), []byte(body), 0o700); err != nil { //nolint:gosec // G306: test fixture must be executable
			t.Fatal(err)
		}
	}
	write(shimDir, "#!/bin/sh\n# "+shimguard.ShimMarker+"\nexec observer gh \"$@\"\n")
	write(excluded, "#!/bin/sh\nexit 0\n")
	write(real, "#!/bin/sh\nexit 0\n")
	path := strings.Join([]string{shimDir, excluded, real}, string(os.PathListSeparator))
	c := New(Options{Getenv: func(k string) string {
		if k == "PATH" {
			return path
		}
		return ""
	}, ExcludeDirs: []string{excluded}})
	got, err := c.lookPath("gh")
	if err != nil || got != filepath.Join(real, "gh") {
		t.Fatalf("got %s %v", got, err)
	}
}
