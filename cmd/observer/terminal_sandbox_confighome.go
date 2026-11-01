//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// errToolNotOnboarded refuses a sandboxed launch of a tool whose first-run
// screens were never finished (Windows 11 Pro rerun 2026-10-25, D3: Claude
// Code's onboarding calls the provider hosts the box blocks, so a first run
// in the box exits 1 before it renders).
var errToolNotOnboarded = errors.New("has not been onboarded")

// mxcConfigHomePlan is the plan's run-local config folder: the helper makes
// <box dir>\config, writes File there with Seed, grants the folder
// read-write and sets Env to it in the box.
type mxcConfigHomePlan struct {
	Env  string          `json:"env"`
	File string          `json:"file"`
	Seed json.RawMessage `json:"seed"`
}

// sandboxConfigHomeFor decides, from the tool's row, whether a sandboxed
// run may start and whether it needs a run-local config folder. A row with
// no config home needs neither. The tool's state file (in the folder its
// Env names, else in the home) must mark its first run done, or the launch
// is refused with the remedy. When Env is already set, or the home's
// config folder exists (StateRW grants it read-write), the tool keeps its
// own folder and nothing is planned. Otherwise the run gets a folder of its
// own seeded with the row's non-secret keys only.
func sandboxConfigHomeFor(c *integration.SandboxConfigHome, tool, home string, getenv func(string) string, read func(string) ([]byte, error), exists func(string) bool) (*mxcConfigHomePlan, error) {
	if c == nil {
		return nil, nil
	}
	moved := strings.TrimSpace(getenv(c.Env))
	state := filepath.Join(home, filepath.FromSlash(c.StateFile))
	if moved != "" {
		state = filepath.Join(moved, c.RelocatedStateFile)
	}
	b, err := read(state)
	if err != nil || !c.Onboarded(b) {
		return nil, fmt.Errorf("terminal_sandbox: %s %w (%s does not mark its first run done): onboard %s once outside the sandbox, then launch it sandboxed (its first-run screens call provider hosts the sandbox blocks)", tool, errToolNotOnboarded, state, tool)
	}
	if moved != "" || exists(filepath.Join(home, filepath.FromSlash(c.Dir))) {
		return nil, nil
	}
	seed, err := c.Seed(b)
	if err != nil {
		return nil, fmt.Errorf("terminal_sandbox: %s state file %s: %w", tool, state, err)
	}
	return &mxcConfigHomePlan{Env: c.Env, File: c.RelocatedStateFile, Seed: seed}, nil
}

// mxcConfigHomeDir is the run's config folder inside its box directory.
func mxcConfigHomeDir(boxDir string) string {
	return strings.TrimRight(boxDir, `\/`) + `\config`
}

var mxcEnvName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// mxcCheckConfigHome is the helper's own check of the plan's config home:
// a plain variable name, a plain file name and a small JSON object of
// scalar values only (the daemon wrote it; the helper does not trust it
// further than that).
func mxcCheckConfigHome(ch *mxcConfigHomePlan) error {
	if ch == nil {
		return nil
	}
	if !mxcEnvName.MatchString(ch.Env) {
		return fmt.Errorf("config home: variable %q refused", ch.Env)
	}
	if ch.File == "" || ch.File == "." || ch.File == ".." || strings.ContainsAny(ch.File, `\/:`) {
		return fmt.Errorf("config home: file name %q refused", ch.File)
	}
	if len(ch.Seed) > 4<<10 {
		return errors.New("config home: seed too large")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(ch.Seed, &doc); err != nil || doc == nil {
		return errors.New("config home: seed is not a JSON object")
	}
	for k, v := range doc {
		if !integration.ScalarJSON(v) {
			return fmt.Errorf("config home: seed key %q is not a scalar", k)
		}
	}
	return nil
}

// mxcWithConfigHome sets the plan's config variable to the run's folder in
// the box environment, replacing any value already there.
func mxcWithConfigHome(env []string, ch *mxcConfigHomePlan, boxDir string) []string {
	if ch == nil {
		return env
	}
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if k, _, _ := strings.Cut(kv, "="); strings.EqualFold(k, ch.Env) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, ch.Env+"="+mxcConfigHomeDir(boxDir))
}
