package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/defaultworkspace"
)

// workspaceGitInitTimeout bounds the one `git init` of a new workspace.
const workspaceGitInitTimeout = 20 * time.Second

// defaultWorkspaceEnv is the host facts the default workspace rules compare
// against for this config: the home folder and the database's folder.
func defaultWorkspaceEnv(cfg config.Config) defaultworkspace.Env {
	home, _ := os.UserHomeDir()
	return defaultworkspace.EnvFor(home, cfg.Observer.DBPath)
}

// workspaceGitInit is the one git invocation that sets up a default
// workspace (defaultworkspace.InitRepo; the dashboard gets it through
// dashapi.Options.WorkspaceGitInit). Fixed argv, no shell: `git init` of
// exactly dir, with no template directory (so no hook samples or a global
// template's hooks are copied in), repository hooks and fsmonitor off, no
// prompt, a timeout, and the variables that would point git at another
// repository dropped. defaultworkspace.Ensure calls it only for a folder
// Observer marked that is not yet a repository.
func workspaceGitInit(ctx context.Context, dir string) error {
	ctx, cancel := context.WithTimeout(ctx, workspaceGitInitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", //nolint:gosec // G204: fixed program and verbs; dir is the checked workspace folder, passed as one argument
		"-c", "core.hooksPath="+os.DevNull,
		"-c", "core.fsmonitor=false",
		"-c", "init.defaultBranch=main",
		"init", "--quiet", "--template=", dir)
	cmd.Env = append(workspaceGitEnv(os.Environ()), "LC_ALL=C", "GIT_TERMINAL_PROMPT=0")
	var errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = io.Discard, &errb
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errors.New("git is not installed or not on PATH")
		}
		return fmt.Errorf("git init: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}

// workspaceGitDrop is every variable workspaceGitEnv removes: the ones that
// would point git at another repository, index or template, and every way
// the environment can inject configuration (GIT_CONFIG_PARAMETERS, the
// GIT_CONFIG_COUNT / GIT_CONFIG_KEY_<n> / GIT_CONFIG_VALUE_<n> set, and the
// GIT_CONFIG, GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM file overrides).
var workspaceGitDrop = map[string]bool{
	"GIT_DIR": true, "GIT_WORK_TREE": true, "GIT_INDEX_FILE": true, "GIT_COMMON_DIR": true,
	"GIT_OBJECT_DIRECTORY": true, "GIT_TEMPLATE_DIR": true,
	"GIT_CONFIG_PARAMETERS": true, "GIT_CONFIG_COUNT": true,
	"GIT_CONFIG": true, "GIT_CONFIG_GLOBAL": true, "GIT_CONFIG_SYSTEM": true, "GIT_CONFIG_NOSYSTEM": true,
}

// workspaceGitDropPrefixes are the numbered variables of the
// GIT_CONFIG_COUNT set.
var workspaceGitDropPrefixes = []string{"GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"}

// workspaceGitEnv returns env without workspaceGitDrop and the numbered
// GIT_CONFIG_KEY_/VALUE_ variables, plus GIT_CONFIG_NOSYSTEM=1 and
// GIT_CONFIG_GLOBAL pointed at the null device (review finding 9,
// 2026-11-12): the workspace's `git init` reads no user or system git
// configuration (no init.templateDir, core.hooksPath or include from the
// person's own files); only the -c values on the fixed argv apply.
func workspaceGitEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		// Upper-cased: Windows environment names are case-insensitive.
		k = strings.ToUpper(k)
		if workspaceGitDrop[k] || hasAnyPrefix(k, workspaceGitDropPrefixes) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
}

// hasAnyPrefix reports whether s starts with one of prefixes.
func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// workspaceInitRepo binds workspaceGitInit to ctx for defaultworkspace.Ensure.
func workspaceInitRepo(ctx context.Context) defaultworkspace.InitRepo {
	return func(dir string) error { return workspaceGitInit(ctx, dir) }
}

// ensureDefaultWorkspace sets up Observer's default workspace when it is
// missing or unfinished (`observer start`, `observer init`): the folder, its
// marker and its git repository. It never writes config.toml and never
// fails the command: a folder that breaks a rule or cannot be set up is one
// WARN line on w.
func ensureDefaultWorkspace(ctx context.Context, w io.Writer, cfg config.Config) {
	env := defaultWorkspaceEnv(cfg)
	r := defaultworkspace.Resolve(cfg.Workspace.DefaultDir, env.Home)
	if r.Dir == "" {
		fmt.Fprintln(w, "WARN default workspace: no home folder resolves, so none was created; set [workspace] default_dir")
		return
	}
	res, err := defaultworkspace.Ensure(env, r.Dir, workspaceInitRepo(ctx))
	switch {
	case err != nil:
		fmt.Fprintf(w, "WARN default workspace %s is not ready: %v. Change it in Terminals > Settings > Default workspace.\n", r.Dir, err)
	case res.Created:
		fmt.Fprintf(w, "default workspace: created %s\n", r.Dir)
	case res.Initialized:
		fmt.Fprintf(w, "default workspace: finished setting up %s\n", r.Dir)
	}
}

// initDefaultWorkspaceStep is the `observer init` step: load the config the
// init wrote against and set up the default workspace. A config that does
// not load is left to the rest of init to report.
func initDefaultWorkspaceStep(ctx context.Context, w io.Writer, configPath string) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return
	}
	ensureDefaultWorkspace(ctx, w, cfg)
}
