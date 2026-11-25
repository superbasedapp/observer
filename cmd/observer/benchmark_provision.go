//go:build !sbo_omit_benchmark

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/benchmark"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/procgroup"
)

// benchmark_provision.go holds the REAL workspace + home preparers the CLI wires
// into the runner (the fakes live in the test). These are the only components
// that clone untrusted repository code and copy credentials, so their contracts
// (timeouts, isolation) are explicit (plan §3.9).

const defaultSetupTimeoutSec = 300

// gitCloneProvisioner clones repo@ref into <attemptDir>/repo, optionally strips
// .git (per-task choice), and runs the setup command under its own timeout +
// process-group kill. Any failure returns an error ⇒ the attempt is recorded
// setup_error (counted, retryable as infra).
type gitCloneProvisioner struct{}

func (gitCloneProvisioner) Provision(ctx context.Context, task benchmark.Task, attemptDir string) (string, error) {
	repoDir := filepath.Join(attemptDir, "repo")
	if err := os.MkdirAll(attemptDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir attempt dir: %w", err)
	}
	if err := runProvisionCmd(ctx, attemptDir, 600, "git", "clone", "--quiet", task.Repo, repoDir); err != nil {
		return "", fmt.Errorf("git clone: %w", err)
	}
	if task.Ref != "" {
		if err := runProvisionCmd(ctx, repoDir, 120, "git", "checkout", "--quiet", task.Ref); err != nil {
			return "", fmt.Errorf("git checkout %q: %w", task.Ref, err)
		}
	}
	if task.StripGit {
		_ = os.RemoveAll(filepath.Join(repoDir, ".git"))
	}
	if task.Setup != "" {
		timeout := task.SetupTimeoutSec
		if timeout <= 0 {
			timeout = defaultSetupTimeoutSec
		}
		if err := runProvisionCmd(ctx, repoDir, timeout, "sh", "-c", task.Setup); err != nil {
			return "", fmt.Errorf("setup command: %w", err)
		}
	}
	return repoDir, nil
}

func runProvisionCmd(ctx context.Context, dir string, timeoutSec int, name string, args ...string) error {
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()
	c := exec.CommandContext(runCtx, name, args...)
	c.Dir = dir
	procgroup.Set(c)
	c.Cancel = func() error { return killProcGroup(c) }
	if out, err := c.CombinedOutput(); err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timed out after %ds", timeoutSec)
		}
		return fmt.Errorf("%w: %s", err, truncateForRow(string(out), 200))
	}
	return nil
}

// codexHomePrep sets up an isolated CODEX_HOME for a codex attempt: it copies
// ~/.codex/auth.json (required — a fresh CODEX_HOME has no credentials, spike
// §3.9) and config.toml (if present) into the attempt's home dir. The launcher's
// --proxy injection handles base_url routing, so no config rewrite is needed.
// Non-codex harnesses need no prep in v1.
type codexHomePrep struct{}

func (codexHomePrep) Prepare(_ context.Context, harness, homeDir, _ string) error {
	if harness != "codex" {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}
	src := filepath.Join(home, ".codex")
	authSrc := filepath.Join(src, "auth.json")
	if _, err := os.Stat(authSrc); err != nil {
		return fmt.Errorf("codex auth.json not found at %s (run `codex login` first): %w", authSrc, err)
	}
	if err := benchCopyFile(authSrc, filepath.Join(homeDir, "auth.json"), 0o600); err != nil {
		return fmt.Errorf("copy auth.json: %w", err)
	}
	// config.toml is best-effort (preserves model_provider etc.).
	if _, err := os.Stat(filepath.Join(src, "config.toml")); err == nil {
		_ = benchCopyFile(filepath.Join(src, "config.toml"), filepath.Join(homeDir, "config.toml"), 0o600)
	}
	return nil
}

// attemptHomePrep is the one homePreparer wired into the runner. It switches
// on the harness name: codex copies ~/.codex/auth.json into CODEX_HOME;
// claude-code writes a throwaway CLAUDE_CONFIG_DIR whose settings.json
// registers the observer hook set pointed at the benchmark daemon's --config
// (mirroring `observer init`, via internal/hook) and copies the account's
// .credentials.json in. This is the
// codex CODEX_HOME/auth.json lifecycle, one layer over (re-spike §6.2).
type attemptHomePrep struct {
	binaryPath string // os.Executable() — the hook command target
	configPath string // benchmark daemon --config the claude-code hooks write into
}

func (p attemptHomePrep) Prepare(ctx context.Context, harness, homeDir, proxyURL string) error {
	switch harness {
	case "codex":
		return codexHomePrep{}.Prepare(ctx, harness, homeDir, proxyURL)
	case "claude-code":
		return p.prepareClaude(homeDir)
	default:
		return nil
	}
}

// prepareClaude builds the sandbox CLAUDE_CONFIG_DIR: it registers the observer
// hook set (pointed at the benchmark daemon's --config, so the hooks write the
// ISOLATED DB — the source of the correlation seam, since the watcher won't see
// sandbox transcripts) and copies the account's .credentials.json. Hooks stay
// ON deliberately (re-spike §6.4): fast on a small DB and load-bearing for the
// sessions row. The credentials copy is best-effort — an API-key operator has
// no .credentials.json and relies on the inherited ANTHROPIC_API_KEY instead.
func (p attemptHomePrep) prepareClaude(homeDir string) error {
	cfgDir := claudeSandboxConfigDir(homeDir)
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		return fmt.Errorf("mkdir claude config dir: %w", err)
	}
	reg, err := hook.NewRegistry(hook.Options{
		BinaryPath: p.binaryPath,
		HomeDir:    homeDir, // registrar writes <homeDir>/.claude/settings.json
		ConfigPath: p.configPath,
		// Sandbox the checksums file so registration never touches the
		// operator's ~/.observer/hook_checksums.json.
		ChecksumsPath: filepath.Join(cfgDir, "hook_checksums.json"),
	})
	if err != nil {
		return fmt.Errorf("hook registry: %w", err)
	}
	if res := reg.Register("claude-code"); res.Error != nil {
		return fmt.Errorf("register claude-code hooks: %w", res.Error)
	}
	if src := claudeCredentialsPath(); src != "" {
		if _, statErr := os.Stat(src); statErr == nil {
			_ = benchCopyFile(src, filepath.Join(cfgDir, ".credentials.json"), 0o600)
		}
	}
	return nil
}

func benchCopyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	_, err = io.Copy(out, in)
	return err
}
