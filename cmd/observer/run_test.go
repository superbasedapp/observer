package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/compression/shell"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

func TestExitCodeFrom(t *testing.T) {
	if got := exitCodeFrom(nil); got != 0 {
		t.Fatalf("nil err: got %d want 0", got)
	}
	if got := exitCodeFrom(errors.New("boom")); got != 1 {
		t.Fatalf("generic err: got %d want 1", got)
	}
	if got := exitCodeFrom(exec.ErrNotFound); got != 127 {
		t.Fatalf("ErrNotFound: got %d want 127", got)
	}
	// Real ExitError by running sh -c 'exit 42'.
	c := exec.Command("sh", "-c", "exit 42")
	runErr := c.Run()
	if got := exitCodeFrom(runErr); got != 42 {
		t.Fatalf("ExitError: got %d want 42", got)
	}
}

func TestIsExcludedCommand(t *testing.T) {
	excluded := []string{"curl", "playwright"}
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"curl", "example.com"}, true},
		{[]string{"/usr/bin/curl", "example.com"}, true},
		{[]string{"playwright", "test"}, true},
		{[]string{"git", "status"}, false},
		{[]string{}, false},
	}
	for _, tc := range cases {
		if got := isExcludedCommand(excluded, tc.argv); got != tc.want {
			t.Errorf("argv %v: got %v want %v", tc.argv, got, tc.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0B"},
		{500, "500B"},
		{1024, "1.0KB"},
		{1536, "1.5KB"},
		{1024 * 1024, "1.0MB"},
		{int64(5 * 1024 * 1024), "5.0MB"},
	}
	for _, tc := range cases {
		if got := humanBytes(tc.in); got != tc.want {
			t.Errorf("humanBytes(%d): got %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestSpecDisplayName(t *testing.T) {
	cases := []struct {
		spec shell.FilterSpec
		want string
	}{
		{shell.FilterSpec{Command: "git"}, "git"},
		{shell.FilterSpec{Command: "go", Subcommands: []string{"test"}}, "go test"},
		{shell.FilterSpec{Command: "docker", Subcommands: []string{"build", "buildx"}}, "docker build|buildx"},
	}
	for _, tc := range cases {
		if got := specDisplayName(&tc.spec); got != tc.want {
			t.Errorf("spec=%+v got=%q want=%q", tc.spec, got, tc.want)
		}
	}
}

func TestRunFiltersStdoutAndRecordsStats(t *testing.T) {
	cfgPath, dbPath := writeRunConfig(t)

	// Produce a mix of lines; the generic git filter should drop the hint
	// line and leave the rest alone.
	//   echo 'line1' ; echo 'hint: noisy' ; echo 'line2'
	argv := []string{"sh", "-c", "printf 'line1\\nhint: noisy\\nline2\\n'"}

	var stdout, stderr bytes.Buffer
	// Swap argv[0] to "git" by using sh script + symlink? Simpler: craft a
	// filter argv where sh is the command and the filter engine sees "sh" —
	// which has no default filter, so result is pass-through. So instead
	// load a synthetic filter by using a user-dir override.
	userFilterDir := filepath.Join(filepath.Dir(dbPath), "filters")
	if err := os.MkdirAll(userFilterDir, 0o755); err != nil {
		t.Fatalf("mkdir filters: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(userFilterDir, "sh.toml"),
		[]byte("command = \"sh\"\n[[rule]]\ntype = \"line_drop\"\npattern = '^hint:'\n"),
		0o644,
	); err != nil {
		t.Fatalf("write sh.toml: %v", err)
	}

	err := runRun(context.Background(), argv, runOptions{
		configPath: cfgPath,
		stdout:     &stdout,
		stderr:     &stderr,
	})
	if err != nil {
		t.Fatalf("runRun: %v", err)
	}

	gotStdout := stdout.String()
	if !strings.Contains(gotStdout, "line1") || !strings.Contains(gotStdout, "line2") {
		t.Fatalf("expected both lines to survive, got: %q", gotStdout)
	}
	if strings.Contains(gotStdout, "hint: noisy") {
		t.Fatalf("hint line should have been dropped, got: %q", gotStdout)
	}
	if !strings.Contains(stderr.String(), "[observer run]") {
		t.Fatalf("expected summary on stderr, got: %q", stderr.String())
	}

	// observer_log row should exist with component="run".
	assertObserverLogRow(t, dbPath)
}

func TestRunPassesThroughWhenDisabled(t *testing.T) {
	cfgPath, dbPath := writeRunConfigShellDisabled(t)
	_ = dbPath

	argv := []string{"sh", "-c", "printf 'hint: keep me\\n'"}

	var stdout, stderr bytes.Buffer
	err := runRun(context.Background(), argv, runOptions{
		configPath: cfgPath,
		stdout:     &stdout,
		stderr:     &stderr,
	})
	if err != nil {
		t.Fatalf("runRun: %v", err)
	}
	if !strings.Contains(stdout.String(), "hint: keep me") {
		t.Fatalf("pass-through should have preserved hint line, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "bypass") {
		t.Fatalf("expected bypass label on stderr, got %q", stderr.String())
	}
}

func TestRunForwardsExitCode(t *testing.T) {
	cfgPath, _ := writeRunConfig(t)

	err := runRun(context.Background(), []string{"sh", "-c", "exit 7"}, runOptions{
		configPath: cfgPath,
		stdout:     &bytes.Buffer{},
		stderr:     &bytes.Buffer{},
		quiet:      true,
	})
	var ec exitErr
	if !errors.As(err, &ec) {
		t.Fatalf("expected exitErr, got %v", err)
	}
	if int(ec) != 7 {
		t.Fatalf("exit code: got %d want 7", int(ec))
	}
}

func TestRunHonorsExcludeCommands(t *testing.T) {
	cfgPath, dbPath := writeRunConfigExclude(t, "sh")
	_ = dbPath

	argv := []string{"sh", "-c", "printf 'hint: keep me\\n'"}

	// Even though a filter would normally match, the exclude_commands list
	// should force pass-through.
	userFilterDir := filepath.Join(filepath.Dir(dbPath), "filters")
	os.MkdirAll(userFilterDir, 0o755)
	os.WriteFile(
		filepath.Join(userFilterDir, "sh.toml"),
		[]byte("command = \"sh\"\n[[rule]]\ntype = \"line_drop\"\npattern = '^hint:'\n"),
		0o644,
	)

	var stdout, stderr bytes.Buffer
	if err := runRun(context.Background(), argv, runOptions{
		configPath: cfgPath,
		stdout:     &stdout,
		stderr:     &stderr,
		quiet:      true,
	}); err != nil {
		t.Fatalf("runRun: %v", err)
	}
	if !strings.Contains(stdout.String(), "hint: keep me") {
		t.Fatalf("excluded command should pass through, got %q", stdout.String())
	}
}

func TestRunCommandNotFoundReports127(t *testing.T) {
	cfgPath, _ := writeRunConfig(t)
	err := runRun(context.Background(), []string{"/nonexistent/sbr-bin"}, runOptions{
		configPath: cfgPath,
		stdout:     &bytes.Buffer{},
		stderr:     &bytes.Buffer{},
		quiet:      true,
	})
	var ec exitErr
	if !errors.As(err, &ec) {
		t.Fatalf("expected exitErr, got %v", err)
	}
	if int(ec) != 127 {
		t.Fatalf("exit code: got %d want 127", int(ec))
	}
}

// ---- helpers -------------------------------------------------------------

func writeRunConfig(t *testing.T) (cfgPath, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "run.db")
	cfgPath = filepath.Join(dir, "config.toml")
	body := "[observer]\n" +
		"db_path = \"" + filepath.ToSlash(dbPath) + "\"\n" +
		"log_level = \"error\"\n" +
		"[compression.shell]\n" +
		"enabled = true\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath, dbPath
}

func writeRunConfigShellDisabled(t *testing.T) (cfgPath, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "run.db")
	cfgPath = filepath.Join(dir, "config.toml")
	body := "[observer]\n" +
		"db_path = \"" + filepath.ToSlash(dbPath) + "\"\n" +
		"log_level = \"error\"\n" +
		"[compression.shell]\n" +
		"enabled = false\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath, dbPath
}

func writeRunConfigExclude(t *testing.T, exclude string) (cfgPath, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "run.db")
	cfgPath = filepath.Join(dir, "config.toml")
	body := "[observer]\n" +
		"db_path = \"" + filepath.ToSlash(dbPath) + "\"\n" +
		"log_level = \"error\"\n" +
		"[compression.shell]\n" +
		"enabled = true\n" +
		"exclude_commands = [\"" + exclude + "\"]\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath, dbPath
}

func assertObserverLogRow(t *testing.T, dbPath string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	var count int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM observer_log WHERE component = 'run'`).Scan(&count); err != nil {
		t.Fatalf("query observer_log: %v", err)
	}
	if count == 0 {
		t.Fatal("expected at least one observer_log row with component='run'")
	}
	var details sql.NullString
	if err := database.QueryRowContext(ctx,
		`SELECT details FROM observer_log WHERE component = 'run' ORDER BY id DESC LIMIT 1`).Scan(&details); err != nil {
		t.Fatalf("query details: %v", err)
	}
	if !details.Valid || !strings.Contains(details.String, "bytes_in") {
		t.Fatalf("expected JSON details with bytes_in, got %q", details.String)
	}
}
