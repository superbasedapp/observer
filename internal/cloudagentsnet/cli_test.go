//go:build !windows

package cloudagentsnet

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/shimguard"
)

// fakeCLI writes a shell script standing in for a vendor CLI: it records
// its argv, its environment and its stdin, prints stdout and stderr, and
// exits with code.
func fakeCLI(t *testing.T, name, stdout, stderr string, code int, extra string) (bin, dir string) {
	t.Helper()
	dir = t.TempDir()
	for f, body := range map[string]string{"out": stdout, "err": stderr} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := "#!/bin/sh\n" +
		"D='" + dir + "'\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$D/argv\"\n" +
		"env > \"$D/env\"\n" +
		"pwd > \"$D/cwd\"\n" +
		"cat > \"$D/stdin\"\n" +
		extra +
		"cat \"$D/out\"\n" +
		"cat \"$D/err\" >&2\n" +
		"exit " + strconv.Itoa(code) + "\n"
	bin = filepath.Join(dir, name)
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // G306: test script must be executable
		t.Fatal(err)
	}
	return bin, dir
}

func cliClient(bin string, timeout time.Duration) *Client {
	env := map[string]string{
		"PATH": "/usr/bin:/bin", "HOME": "/home/u", "CODEX_HOME": "/home/u/.codex",
		"AWS_SECRET_ACCESS_KEY": "leak", "OPENAI_API_KEY": "sk-leak", "GIT_DIR": "/user/repo/.git",
	}
	return New(Options{
		Getenv:  func(k string) string { return env[k] },
		Resolve: func(string) (string, error) { return bin, nil },
		Timeout: timeout,
	})
}

func fixture(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cloudagents", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRunFixedArgvEnvAndStdin(t *testing.T) {
	codex, _ := cloudagents.ConnectorByID(cloudagents.ConnectorCodexCloud)
	req, err := codex.ListRequest("eyJvZmZzZXQiOjJ9")
	if err != nil {
		t.Fatal(err)
	}
	bin, dir := fakeCLI(t, "codex", fixture(t, "codex-cloud/list-page1.json"), "", 0, "")
	out, err := cliClient(bin, 0).Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cloudagents.ParseCodexList(out); err != nil {
		t.Fatalf("output did not round-trip: %v", err)
	}
	argv, _ := os.ReadFile(filepath.Join(dir, "argv"))
	if got := strings.Split(strings.TrimSpace(string(argv)), "\n"); !reflect.DeepEqual(got, req.Argv[1:]) {
		t.Fatalf("argv %q want %q", got, req.Argv[1:])
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	for _, bad := range []string{"AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "GIT_DIR"} {
		if strings.Contains(string(env), bad+"=") {
			t.Errorf("env leaked %s", bad)
		}
	}
	for _, want := range []string{"CODEX_HOME=/home/u/.codex", "NO_COLOR=1"} {
		if !strings.Contains(string(env), want) {
			t.Errorf("env missing %s", want)
		}
	}
	if in, _ := os.ReadFile(filepath.Join(dir, "stdin")); len(in) != 0 {
		t.Errorf("stdin not empty: %q", in)
	}
	if cwd, _ := os.ReadFile(filepath.Join(dir, "cwd")); strings.TrimSpace(string(cwd)) == "" {
		t.Error("no working directory recorded")
	}

	gh, _ := cloudagents.ConnectorByID(cloudagents.ConnectorCopilotAgent)
	req, _ = gh.ListRequest("")
	bin, dir = fakeCLI(t, "gh", fixture(t, "copilot-agent/list.json"), "", 0, "")
	if _, err := cliClient(bin, 0).Run(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	env, _ = os.ReadFile(filepath.Join(dir, "env"))
	if !strings.Contains(string(env), "GH_PROMPT_DISABLED=1") || strings.Contains(string(env), "CODEX_HOME=") {
		t.Errorf("gh env wrong:\n%s", env)
	}
}

func TestRunFailuresAreClassifiedNeverEchoed(t *testing.T) {
	codex, _ := cloudagents.ConnectorByID(cloudagents.ConnectorCodexCloud)
	req, _ := codex.ListRequest("")
	const secretish = "Not signed in. token=abc123 Please run 'codex login'"
	bin, _ := fakeCLI(t, "codex", "", secretish, 1, "")
	_, err := cliClient(bin, 0).Run(context.Background(), req)
	if cloudagents.ClassOf(err) != cloudagents.ErrNotSignedIn {
		t.Fatalf("class: %v", err)
	}
	if strings.Contains(err.Error(), "abc123") || strings.Contains(err.Error(), "token") {
		t.Errorf("stderr leaked into the error: %v", err)
	}

	bin, _ = fakeCLI(t, "codex", "", "", 0, "sleep 5\n")
	start := time.Now()
	_, err = cliClient(bin, 200*time.Millisecond).Run(context.Background(), req)
	if cloudagents.ClassOf(err) != cloudagents.ErrTimeout || time.Since(start) > 4*time.Second {
		t.Fatalf("timeout: %v after %s", err, time.Since(start))
	}

	bin, _ = fakeCLI(t, "codex", "", "", 0, "head -c "+strconv.Itoa(MaxOutput+10)+" /dev/zero\n")
	if _, err := cliClient(bin, 0).Run(context.Background(), req); cloudagents.ClassOf(err) != cloudagents.ErrOverCap {
		t.Fatalf("over cap: %v", err)
	}

	missing := New(Options{Resolve: func(string) (string, error) { return "", os.ErrNotExist }})
	if _, err := missing.Run(context.Background(), req); cloudagents.ClassOf(err) != cloudagents.ErrNotInstalled {
		t.Fatalf("not installed: %v", err)
	}
}

func TestRunRefusesForeignArgv(t *testing.T) {
	bin, dir := fakeCLI(t, "codex", "{}", "", 0, "")
	c := cliClient(bin, 0)
	cases := []cloudagents.Request{
		{Connector: cloudagents.ConnectorCodexCloud, Argv: []string{"sh", "-c", "id"}},
		{Connector: cloudagents.ConnectorCodexCloud, Argv: []string{"gh", "api", "user"}},
		{Connector: "made-up", Argv: []string{"codex"}},
		{Connector: cloudagents.ConnectorCodexCloud},
		{Connector: cloudagents.ConnectorCodexCloud, Argv: []string{"codex", "cloud\nlist"}},
	}
	for _, r := range cases {
		if _, err := c.Run(context.Background(), r); cloudagents.ClassOf(err) != cloudagents.ErrInvalid {
			t.Errorf("%+v: want invalid, got %v", r, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "argv")); err == nil {
		t.Error("a refused request still ran the binary")
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
	path := strings.Join([]string{"relative", shimDir, excluded, real}, string(os.PathListSeparator))
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
	if _, err := c.lookPath("codex"); err == nil {
		t.Error("a missing command resolved")
	}
}
