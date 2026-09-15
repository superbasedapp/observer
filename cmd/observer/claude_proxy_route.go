// SPDX-License-Identifier: BUSL-1.1
//
// Copyright (c) 2026 Marmut App

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// bypassFilePrefix is the os.CreateTemp prefix for the one-shot CLI-scope
// `--settings` bypass file writeClaudeBypassSettings mints. Shared with
// sweepStaleBypassFiles so the reaper matches exactly what the writer produces.
const bypassFilePrefix = "observer-claude-bypass-"

// anthropicDefaultBaseURL is Claude Code's built-in provider endpoint. The
// neutralize path pins it so claude reaches Anthropic directly on a
// deliberately-unrouted launch — either into a launcher-written CLI-scope
// `--settings` override (when a persistent settings.json route must be
// overridden; CLI scope beats user scope, probe 2026-07-20) or into the child
// process env (when there is no baked-in route, so the env is the only route to
// defeat). An empty value is NOT used: the same probe showed an empty
// `env.ANTHROPIC_BASE_URL` in a `--settings` file is treated as unset and does
// NOT fall back to the process env, so an explicit URL is required.
const anthropicDefaultBaseURL = "https://api.anthropic.com"

// claudeSettingsPath resolves where Claude Code reads its USER-scope
// settings.json, honoring CLAUDE_CONFIG_DIR / ANTHROPIC_CONFIG_DIR before
// falling back to ~/.claude/. Mirrors claudeCredentialsPath so the launcher
// inspects the SAME file claude will actually load (and `observer init` /
// internal/proxyroute.RegisterClaudeCode writes) for the env.ANTHROPIC_BASE_URL
// route. Returns "" only when the home dir cannot be resolved and no override is
// set.
func claudeSettingsPath() string {
	for _, env := range []string{"CLAUDE_CONFIG_DIR", "ANTHROPIC_CONFIG_DIR"} {
		if dir := os.Getenv(env); dir != "" {
			return filepath.Join(dir, "settings.json")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", "settings.json")
}

// readClaudeSettingsBaseURL returns the env.ANTHROPIC_BASE_URL value persisted
// in the settings.json at path, or "" when the file is missing, unparseable, or
// carries no such key. Best-effort by design: a routing DECISION must never be
// blocked by a malformed settings file (the routed/neutralize verdict is the
// safe default; only a POSITIVE observer-route match ever escalates to a
// fail-closed). Preserves nothing else — it reads exactly the one key.
func readClaudeSettingsBaseURL(path string) string {
	v, _ := readClaudeSettingsBaseURLPresent(path)
	return v
}

// readClaudeSettingsBaseURLPresent is readClaudeSettingsBaseURL with an extra
// PRESENCE bit: present is true when the settings file exists, parses, and its
// env block CONTAINS the ANTHROPIC_BASE_URL key — even when its value is the
// empty string. The multi-scope resolver needs to tell "key present but empty"
// (which acts as UNSET for provider selection, and — being higher precedence —
// nullifies any lower-scope value) apart from "key absent" (fall through to the
// next scope). Best-effort: a missing/malformed file returns ("", false).
func readClaudeSettingsBaseURLPresent(path string) (value string, present bool) {
	if path == "" {
		return "", false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var doc struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", false
	}
	v, ok := doc.Env["ANTHROPIC_BASE_URL"]
	return v, ok
}

// claudeBackendEnvKeys are provider switches that move Claude Code away from
// the first-party Anthropic HTTP API. The observer proxy route is not proof of
// budget coverage for these native cloud backends, so a managed hard budget
// must refuse unless every effective setting is known to leave them disabled.
var claudeBackendEnvKeys = []string{
	"CLAUDE_CODE_USE_BEDROCK",
	"CLAUDE_CODE_USE_VERTEX",
	"CLAUDE_CODE_USE_FOUNDRY",
}

// claudeProxyBackendProven reports whether the final Claude launch can be
// proven to use the proxy's first-party Anthropic route. It inspects only
// provider-selection metadata; credentials and token values are never read.
// Any enabled or unreadable provider selector downgrades the result to
// unknown. The check is deliberately conservative because a settings/env
// provider switch can make ANTHROPIC_BASE_URL irrelevant while leaving the
// process apparently proxy-configured.
func claudeProxyBackendProven(environ []string, cwd string, args []string) bool {
	for _, key := range claudeBackendEnvKeys {
		if value, present := lookupEnvValue(environ, key); present {
			enabled, known := claudeBackendFlag(value)
			if !known || enabled {
				return false
			}
		}
	}
	if cwd == "" {
		cwd, _ = os.Getwd()
	}

	// Inspect every settings scope Claude can merge. A lower scope containing
	// an enabled selector is treated as unsafe even if another scope currently
	// appears to override it: this avoids making a positive budget admission
	// claim from a hand-rolled precedence model when the CLI changes versions.
	paths := []string{
		managedClaudeSettingsPath(),
		projectClaudeSettingsPath(cwd, "settings.local.json"),
		projectClaudeSettingsPath(cwd, "settings.json"),
		claudeSettingsPath(),
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		env, present, readable := readClaudeSettingsEnv(path)
		if !present {
			continue
		}
		if !readable {
			return false
		}
		if claudeBackendEnvEnabled(env) {
			return false
		}
	}
	if cliVal := claudeArgsSettingsFile(args); cliVal != "" {
		env, readable := readClaudeCLISettingsEnv(cliVal, cwd)
		if !readable || claudeBackendEnvEnabled(env) {
			return false
		}
	}
	return true
}

// readClaudeSettingsEnv reads the non-secret env map from a settings file.
// present distinguishes a missing file from a present but malformed file;
// malformed settings are unknown and therefore fail closed at admission.
func readClaudeSettingsEnv(path string) (env map[string]string, present, readable bool) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, true
	}
	if err != nil {
		return nil, true, false
	}
	var doc struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, true, false
	}
	return doc.Env, true, true
}

// readClaudeCLISettingsEnv mirrors --settings' file-or-inline-JSON forms.
// The returned bool is false for a value Claude may accept but Observer cannot
// parse, which must remain unknown for managed budget admission.
func readClaudeCLISettingsEnv(value, cwd string) (map[string]string, bool) {
	t := strings.TrimSpace(value)
	if t == "" {
		return nil, true
	}
	var raw []byte
	if strings.HasPrefix(t, "{") {
		raw = []byte(t)
	} else {
		path := t
		if !filepath.IsAbs(path) && cwd != "" {
			path = filepath.Join(cwd, path)
		}
		var err error
		raw, err = os.ReadFile(path)
		if err != nil {
			return nil, false
		}
	}
	var doc struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false
	}
	return doc.Env, true
}

func claudeBackendEnvEnabled(env map[string]string) bool {
	for _, key := range claudeBackendEnvKeys {
		if value, ok := env[key]; ok {
			enabled, known := claudeBackendFlag(value)
			if !known || enabled {
				return true
			}
		}
	}
	return false
}

func claudeBackendFlag(value string) (enabled, known bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "false", "no", "off":
		return false, true
	case "1", "true", "yes", "on":
		return true, true
	default:
		return false, false
	}
}

// claudeRouteClass classifies the EFFECTIVE settings-scope ANTHROPIC_BASE_URL
// route for a claude launch (the value that WINS after the per-key merge across
// all settings scopes claude honors).
type claudeRouteClass int

const (
	// claudeRouteNone: no effective settings-scope route — NO scope sets the key
	// at all. The process env (prepareClaudeEnv's injection) is free to route.
	claudeRouteNone claudeRouteClass = iota
	// claudeRouteObserver: the effective route points at the observer proxy.
	claudeRouteObserver
	// claudeRouteThirdParty: the effective route points somewhere else (a
	// corporate/third-party gateway the operator chose) — NOT observer's to touch.
	claudeRouteThirdParty
	// claudeRouteEmptyUnset: the highest-precedence scope that mentions the key
	// sets env.ANTHROPIC_BASE_URL to "" (finding N3). Per the 2026-07-20 probe an
	// empty value at the winning scope acts as UNSET *and DEFEATS the process
	// environment* (no fall-through), so — unlike claudeRouteNone — a routed
	// launch's prepareClaudeEnv injection is silently nullified and claude goes
	// DIRECT (zero capture). It is a DISTINCT outcome so the routed path can pin
	// a higher-scope CLI --settings back to the proxy instead of trusting env.
	claudeRouteEmptyUnset
)

// claudeSettingsScope names which settings scope OWNS the effective route, in
// claude's documented precedence order (Managed > CLI --settings > Local >
// Project > User; probe-confirmed 2026-07-20). The owning scope decides whether
// an observer route is NEUTRALIZABLE (user/project/local — beaten by our
// one-shot CLI-scope --settings) or BLOCKING (managed — beats CLI; or the
// operator's own CLI --settings — which we refuse to stack).
type claudeSettingsScope int

const (
	claudeScopeNone claudeSettingsScope = iota
	claudeScopeUser
	claudeScopeProject
	claudeScopeLocal
	claudeScopeCLI
	claudeScopeManaged
)

// claudeScopeLabel is a human-readable name for a scope, for notices/refusal copy.
func claudeScopeLabel(s claudeSettingsScope) string {
	switch s {
	case claudeScopeManaged:
		return "managed settings"
	case claudeScopeCLI:
		return "your --settings file"
	case claudeScopeLocal:
		return "project-local settings"
	case claudeScopeProject:
		return "project settings"
	case claudeScopeUser:
		return "user settings"
	case claudeScopeNone:
		return "settings"
	default:
		return "settings"
	}
}

// claudeRouteResolution is the resolved effective settings-scope route: its
// class, the scope that OWNS it, the file that scope reads (for copy/notice), and
// the effective base-URL value (for the third-party notice).
type claudeRouteResolution struct {
	class claudeRouteClass
	scope claudeSettingsScope
	file  string
	value string
	// cliUnreadable is set when the operator's own `--settings` value (CLI scope)
	// could not be read/parsed as a settings object (finding N1) — a missing/
	// unreadable file, or unparseable inline JSON. observer cannot tell whether it
	// routes to the proxy, so it is classified conservatively as an un-neutralizable
	// CLI-scope observer route (class=claudeRouteObserver, scope=claudeScopeCLI) and
	// this flag lets the caller print an honest "couldn't read your --settings"
	// fail-closed message instead of asserting a proxy route it never proved.
	cliUnreadable bool
}

// managedClaudeSettingsPath is the OS-specific enterprise managed-settings file
// claude reads at the HIGHEST precedence (docs "Settings precedence"; the
// managed scope beats even a CLI-scope --settings, so a managed observer route is
// genuinely un-overridable by the launcher). Linux/WSL is the daemon's OS;
// macOS/Windows are covered for a native launcher.
func managedClaudeSettingsPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/ClaudeCode/managed-settings.json"
	case "windows":
		// v2.1.75+ path; the legacy C:\ProgramData\ClaudeCode is no longer read.
		return `C:\Program Files\ClaudeCode\managed-settings.json`
	default: // linux + wsl (the daemon's OS) and other unix
		return "/etc/claude-code/managed-settings.json"
	}
}

// claudeArgsSettingsFile returns the operator's own `--settings <file>` value
// from the forwarded claude args (both `--settings X` and `--settings=X`), or ""
// when absent. The scan STOPS at the first bare `--` (tokens after it are
// positional prompt text, not flags), mirroring claudeArgsHaveSettings.
func claudeArgsSettingsFile(args []string) string {
	for i, a := range args {
		if a == "--" {
			return ""
		}
		if a == "--settings" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if v, ok := strings.CutPrefix(a, "--settings="); ok {
			return v
		}
	}
	return ""
}

// readClaudeCLISettingsBaseURL resolves env.ANTHROPIC_BASE_URL from the operator's
// own `--settings` value (CLI scope). claude 2.1.215 accepts `--settings` as
// EITHER a file path OR an inline JSON literal (finding N1), so a value whose
// first non-space byte is '{' is parsed as an inline settings object; anything
// else is read as a file. It returns (value, present, unreadable):
//
//   - present mirrors readClaudeSettingsBaseURLPresent — true when the settings
//     object parsed AND its env block CONTAINS the ANTHROPIC_BASE_URL key (even
//     when empty), so an explicit empty value can be told apart from an absent key.
//   - unreadable is true ONLY when the value could not be read/parsed at all (a
//     missing/unreadable PATH, or inline JSON that does not parse). The caller must
//     NOT silently fall through on unreadable (the pre-fix bug that let an inline
//     JSON --settings routing to the proxy classify as no-route) — it is treated as
//     an operator-CLI-scope unknown and fails closed. A file that reads+parses fine
//     but simply lacks the key is (present=false, unreadable=false): a legitimate
//     --settings that just doesn't set the base URL, so it falls through to lower
//     scopes.
//
// F1 (relative-path reality mirror): a RELATIVE `--settings` PATH is resolved
// against cwd — the directory the claude child will ACTUALLY run in
// (claudeRouteCwd: the --continue-from source root when set, else the launcher's
// cwd). claude is a Node CLI, so it reads a relative fs path against its own
// process.cwd(), and the launcher sets the child's Dir to exactly that cwd — so
// mirroring reality means classifying the SAME file claude will load. Reading a
// relative path against the wrapper's own cwd instead (the pre-fix bug) could
// classify a DIFFERENT file than the child loads and silently invert a
// --no-proxy-route into capture (or vice versa). An empty cwd or an absolute/
// inline value is left untouched.
func readClaudeCLISettingsBaseURL(val, cwd string) (value string, present, unreadable bool) {
	t := strings.TrimSpace(val)
	if t == "" {
		return "", false, false // no --settings at all → CLI scope absent
	}
	var raw []byte
	if strings.HasPrefix(t, "{") {
		raw = []byte(t) // inline JSON literal
	} else {
		// F1: resolve a relative path against the child's run dir, not the
		// wrapper's cwd, so observer reads the file claude itself will load.
		p := t
		if !filepath.IsAbs(p) && cwd != "" {
			p = filepath.Join(cwd, p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return "", false, true // path form, unreadable → CLI-scope unknown
		}
		raw = b
	}
	var doc struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", false, true // present but unparseable → CLI-scope unknown
	}
	v, ok := doc.Env["ANTHROPIC_BASE_URL"]
	return v, ok, false
}

// claudeCLISettingsDisplay names the operator's CLI `--settings` source for
// notice/refusal copy: the path verbatim for a file, or a generic phrase for an
// inline JSON literal (which has no path to name).
func claudeCLISettingsDisplay(val string) string {
	if strings.HasPrefix(strings.TrimSpace(val), "{") {
		return "your inline --settings JSON"
	}
	return val
}

// claudeRouteCwd returns the directory the claude child will ACTUALLY run in —
// the --continue-from source project root when set (continueDir), else the
// launcher's own working directory. The effective settings-scope route MUST be
// resolved against this dir (finding N2): with --continue-from the child's
// child.Dir is overridden to the source project root, whose .claude/settings*.json
// can carry an observer route that a launch-cwd resolution would miss.
func claudeRouteCwd(launchCwd, continueDir string) string {
	if continueDir != "" {
		return continueDir
	}
	return launchCwd
}

// projectClaudeSettingsPath resolves <cwd>/.claude/<name> — the project- and
// local-scope settings files claude reads relative to the launch working
// directory (NOT relocated by CLAUDE_CONFIG_DIR, which only moves the user
// scope). Empty cwd yields "" (scope skipped).
func projectClaudeSettingsPath(cwd, name string) string {
	if cwd == "" {
		return ""
	}
	return filepath.Join(cwd, ".claude", name)
}

// resolveClaudeEffectiveRoute resolves the EFFECTIVE env.ANTHROPIC_BASE_URL a
// claude launch will use, across every settings scope claude honors, in
// precedence order (finding 1). It walks scopes HIGHEST precedence first
// (Managed > CLI --settings > Local > Project > User) and the FIRST scope that
// mentions the key wins (per-key merge). An empty value at the winning scope is
// treated as UNSET (docs: "" overrides a shell export and is unset for provider
// selection) → claudeRouteNone. A non-empty value is classified against the
// observer proxy via the shared loopback-tolerant urlRoutesToProxy: a match is a
// neutralizable/blocking OBSERVER route (per the owning scope); anything else is
// a THIRD-PARTY route the operator chose, which observer must honor untouched.
//
// cwd is the launch working directory (os.Getwd() for a bare/inner launcher; the
// child's Dir). Only the settings FILES are read here — the process env is a
// separate concern handled by prepareClaudeEnv (proceed path) / runClaudeBareDirect
// (finding 2, neutralize path).
func resolveClaudeEffectiveRoute(proxyURL, cwd string, args []string) claudeRouteResolution {
	cliVal := claudeArgsSettingsFile(args)
	scopes := []struct {
		scope claudeSettingsScope
		path  string
	}{
		{claudeScopeManaged, managedClaudeSettingsPath()},
		{claudeScopeCLI, ""}, // resolved from cliVal below (may be inline JSON, N1)
		{claudeScopeLocal, projectClaudeSettingsPath(cwd, "settings.local.json")},
		{claudeScopeProject, projectClaudeSettingsPath(cwd, "settings.json")},
		{claudeScopeUser, claudeSettingsPath()},
	}
	for _, s := range scopes {
		var (
			val, file       string
			present, unread bool
		)
		if s.scope == claudeScopeCLI {
			// CLI --settings is a value, not a fixed path: it may be an inline JSON
			// literal or a path, and an unreadable/unparseable one must NOT silently
			// fall through (finding N1).
			val, present, unread = readClaudeCLISettingsBaseURL(cliVal, cwd)
			if unread {
				// Conservatively classify as an un-neutralizable CLI-scope observer
				// route (the operator passed a --settings we can't reason about — it
				// could route to the proxy). cliUnreadable flags it so the caller
				// prints an honest "couldn't read your --settings" message.
				disp := claudeCLISettingsDisplay(cliVal)
				return claudeRouteResolution{class: claudeRouteObserver, scope: claudeScopeCLI, file: disp, value: disp, cliUnreadable: true}
			}
			file = claudeCLISettingsDisplay(cliVal)
		} else {
			if s.path == "" {
				continue
			}
			val, present = readClaudeSettingsBaseURLPresent(s.path)
			file = s.path
		}
		if !present {
			continue // key absent at this scope → fall through to the next
		}
		if strings.TrimSpace(val) == "" {
			// Highest-precedence scope that mentions the key sets it empty → UNSET,
			// which nullifies lower scopes AND defeats the process env (finding N3).
			// Distinct from claudeRouteNone so the routed path re-pins via CLI scope.
			return claudeRouteResolution{class: claudeRouteEmptyUnset, scope: s.scope, file: file}
		}
		if urlRoutesToProxy(val, proxyURL) {
			return claudeRouteResolution{class: claudeRouteObserver, scope: s.scope, file: file, value: val}
		}
		return claudeRouteResolution{class: claudeRouteThirdParty, scope: s.scope, file: file, value: val}
	}
	return claudeRouteResolution{class: claudeRouteNone}
}

// claudeConfigRoutesToProxy reports whether the EFFECTIVE settings-scope route
// (resolved across all scopes claude honors) points at the observer proxy, plus
// the owning file. Thin compatibility wrapper over resolveClaudeEffectiveRoute
// (cwd = os.Getwd(), no CLI args) retained for the direct unit tests; the live
// launcher calls resolveClaudeEffectiveRoute directly so it can also see the
// scope + third-party class.
func claudeConfigRoutesToProxy(proxyURL string) (routed bool, settingsPath string) {
	cwd, _ := os.Getwd()
	r := resolveClaudeEffectiveRoute(proxyURL, cwd, nil)
	if r.file == "" {
		// No scope set the key at all — report the user-scope path so callers
		// still have a file to name (mirrors the pre-multiscope behavior).
		return false, claudeSettingsPath()
	}
	return r.class == claudeRouteObserver, r.file
}

// claudeArgsHaveSettings reports whether the operator's forwarded claude args
// already carry their own `--settings` flag (either `--settings X` or
// `--settings=X`). When they do, the launcher must NOT stack a second
// `--settings` bypass override (claude's merge/last-wins semantics for two
// CLI-scope settings sources are ambiguous and could clobber the operator's),
// so canNeutralizePersistent is false and a baked-in route fails closed instead.
// The scan STOPS at the first bare `--`: claude treats tokens after its own `--`
// as positional, so a `--settings` appearing there is literal prompt text, not
// the flag.
func claudeArgsHaveSettings(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--settings" || strings.HasPrefix(a, "--settings=") {
			return true
		}
	}
	return false
}

// writeClaudeSettingsPin writes a one-shot CLI-scope settings file that pins
// env.ANTHROPIC_BASE_URL to baseURL, for `claude --settings <path>` to load.
// CLI-scope settings outrank user/project/local settings.json (docs "How scopes
// interact"; probe-confirmed 2026-07-20), so this OVERRIDES a lower-scope route
// the process env can't touch. Two callers: the neutralize path pins the provider
// default (anthropicDefaultBaseURL) to bypass a dead/unwanted proxy; the finding-
// N3 empty-unset path pins the PROXY URL to RESTORE capture that a lower-scope
// empty value would otherwise nullify. Only the one env key is set, so claude
// still merges the operator's hooks / MCP / other env keys from their own scopes.
// The caller removes the file after the child exits.
//
// F4: onCreate (when non-nil) is invoked with the temp path the INSTANT
// os.CreateTemp returns — BEFORE any content is written — so a signal-visible
// cleanup holder can be published while the file is still empty. This closes the
// window where a SIGINT/SIGTERM arriving between CreateTemp and a
// caller-set-after-return holder would strand the file. The idempotent remove
// tolerates a partially-written or empty file.
func writeClaudeSettingsPin(baseURL string, onCreate func(path string)) (string, error) {
	body, err := json.Marshal(map[string]any{
		"env": map[string]string{"ANTHROPIC_BASE_URL": baseURL},
	})
	if err != nil {
		return "", fmt.Errorf("marshal bypass settings: %w", err)
	}
	f, err := os.CreateTemp("", bypassFilePrefix+"*.json")
	if err != nil {
		return "", fmt.Errorf("create bypass settings: %w", err)
	}
	// F4: publish the path before writing content so a signal in the write window
	// still finds it.
	if onCreate != nil {
		onCreate(f.Name())
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("write bypass settings: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("close bypass settings: %w", err)
	}
	return f.Name(), nil
}

// writeClaudeBypassSettings pins the provider default (the neutralize path). Thin
// wrapper over writeClaudeSettingsPin retained for its direct unit test.
func writeClaudeBypassSettings() (string, error) {
	return writeClaudeSettingsPin(anthropicDefaultBaseURL, nil)
}

// bypassWriteError wraps a failure to MINT the one-shot `--settings` file so the
// caller can distinguish it from an error returned by the launch callback and
// print the specific "could not write the override" refusal.
type bypassWriteError struct{ err error }

func (e *bypassWriteError) Error() string { return e.err.Error() }
func (e *bypassWriteError) Unwrap() error { return e.err }

// withClaudeBypassSettings mints a one-shot CLI-scope `--settings` file pinning
// env.ANTHROPIC_BASE_URL to baseURL, invokes fn with its path, and GUARANTEES
// removal on normal exit AND on SIGINT/SIGTERM.
//
// Finding N5/F4: the signal handler is installed BEFORE the file is created,
// and reads the path from a mutex-guarded holder whose lock is HELD ACROSS
// creation+publication — a signal arriving in the create/write window blocks in
// remove() until the path is published, so it can never observe a created file
// with an empty holder (remove is idempotent on an empty/absent path). After cleanup it re-raises the signal so
// observer's original signal-death behavior is preserved (the child shares the
// terminal's process group and receives the same signal independently, so this
// never changes what the child sees); a done channel stops the goroutine when fn
// returns normally so it never leaks. A write failure is returned wrapped in
// *bypassWriteError. It also best-effort reaps stranded files from prior crashes
// (finding N6) before minting ours.
func withClaudeBypassSettings(baseURL string, fn func(settingsPath string) error) error {
	sweepStaleBypassFiles(os.TempDir(), 24*time.Hour)

	var (
		mu   sync.Mutex
		path string
	)
	remove := func() {
		mu.Lock()
		p := path
		mu.Unlock()
		if p != "" {
			_ = os.Remove(p)
		}
	}

	// Install the signal handler FIRST (N5), before the file exists.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case sig := <-sigCh:
			remove()
			signal.Stop(sigCh)
			if p, perr := os.FindProcess(os.Getpid()); perr == nil {
				_ = p.Signal(sig)
			}
		case <-done:
		}
	}()

	// F4 (round-4 shape): hold the holder mutex ACROSS creation and publication,
	// so the signal handler's remove() BLOCKS until the file's path is published
	// (or creation failed with nothing to publish) — there is no instant where a
	// created file exists with an empty holder. The onCreate callback runs with mu
	// already held by this goroutine and must not lock it. A write/close failure
	// inside writeClaudeSettingsPin removes its own partial file; the published
	// path then points at nothing and remove() is a no-op (idempotent).
	mu.Lock()
	p, werr := writeClaudeSettingsPin(baseURL, func(created string) {
		path = created
	})
	mu.Unlock()
	if werr != nil {
		return &bypassWriteError{werr}
	}
	defer remove()

	return fn(p)
}

// execClaudeChild runs claude with the given argv, env, and working dir, wiring
// stdio to the terminal and forwarding the child's exit code via exitErr. Shared
// by the direct/neutralize/empty-unset launch paths so they don't each re-spell
// the exec + exit-code plumbing. A "" dir inherits the caller's cwd. configPath
// (the launcher's --config value) feeds the best-effort launch-seed attribution
// row (migration 086); a config load failure just disables seeding.
func execClaudeChild(bin string, launchArgs, env []string, dir, configPath string, evidence budgetLaunchEvidence) error {
	if evidence.Route == budgetLaunchRouteObserverProxy &&
		!claudeProxyBackendProven(env, dir, launchArgs) {
		// ANTHROPIC_BASE_URL can coexist with Claude Code's native Bedrock,
		// Vertex, or Foundry switches. Preserve the launch for ordinary users,
		// but make managed hard-budget admission fail closed because the proxy
		// URL alone does not prove that the request will cross it.
		evidence = budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}
	}
	evidence.Executable = bin
	evidence.Arguments = launchArgs
	if err := enforceBudgetControlledLaunch(context.Background(), configPath, "claude-code", evidence); err != nil {
		return err
	}
	child := exec.Command(bin, launchArgs...)
	// Backstop for every claude child: the proxy-route callers build env from raw
	// os.Environ() (they don't all go through prepareClaudeEnv), so strip the
	// trusted OOB channel env here so the untrusted claude child never inherits it.
	//
	// DI-04b: every claude launch path funnels through here, so this is also the
	// one place the child's PATH is widened — the resolved binary's own dir
	// (an npm-channel node shim needs node beside it) plus the login-only
	// dirs the resolver saw; additive, the daemon PATH survives in order.
	child.Env = applyChildPATH(scrubOOBEnv(env), daemonLoginPathDirs(), bin)
	child.Dir = dir
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return fmt.Errorf("exec claude: %w", err)
	}
	// Direct process attribution (migration 086): record the child pid now
	// that Start has made it knowable; retract the seed when the child is
	// reaped. Best-effort both ways — a seeding failure never affects the
	// launch (see cmd/observer/launchseed.go). claude-code already carries
	// hook-based attribution; the daemon sweep never overwrites that row.
	dbPath := ""
	if cfg, cfgErr := config.Load(config.LoadOptions{GlobalPath: configPath}); cfgErr == nil {
		dbPath = cfg.Observer.DBPath
	}
	recordLaunchSeed(dbPath, "claude-code", dir, child.Process.Pid, os.Stderr)
	if err := child.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return exitErr(ee.ExitCode())
		}
		return fmt.Errorf("exec claude: %w", err)
	}
	return nil
}

// sweepStaleBypassFiles best-effort removes leaked one-shot bypass `--settings`
// files (bypassFilePrefix*.json) older than maxAge from dir (normally
// os.TempDir()). The per-launch removal is handled by a defer AND a signal
// handler (see runClaudeBareDirect), but a SIGKILL / power loss between the write
// and either can still strand a file; this reaper keeps TMPDIR from slowly
// accumulating them. Every error (unreadable dir, stat failure, remove failure)
// is ignored — a cleanup sweep must never disrupt a launch. It removes ONLY files
// owned by the current uid (finding N6) so a shared, non-sticky TMPDIR reaper
// never deletes another user's live bypass file.
func sweepStaleBypassFiles(dir string, maxAge time.Duration) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, bypassFilePrefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		// Finding N6: in a shared, non-sticky TMPDIR the same bypass-*.json name can
		// belong to ANOTHER user's live launch. Never delete a file we don't own.
		if !fileOwnedByCurrentUser(info) {
			continue
		}
		_ = os.Remove(filepath.Join(dir, name))
	}
}

// claudeBlockCause names WHY an observer settings-scope route could not be
// neutralized, so claudeProxyFailClosedMsg prints the matching fix. The two
// residual fail-closed causes (finding 1) are distinct: the operator's own
// CLI-scope --settings (we refuse to stack a second one), or a MANAGED-scope
// route (managed beats even CLI, so no --settings override can defeat it).
type claudeBlockCause int

const (
	// blockOwnSettings: a user/project/local (or CLI-scope) observer route the
	// launcher would normally bypass via a one-shot CLI-scope --settings file, BUT
	// the operator already passed their own --settings, so stacking ours risks
	// clobbering theirs.
	blockOwnSettings claudeBlockCause = iota
	// blockManaged: the effective observer route lives in the enterprise
	// managed-settings file, which outranks a CLI-scope --settings — there is no
	// launcher lever that can override it. The only fixes are admin-side.
	blockManaged
)

// claudeProxyFailClosedMsg builds the actionable refusal printed on a residual
// claude fail-closed: an effective observer settings-scope route the launcher
// cannot neutralize (canNeutralizePersistent=false). It branches on WHY
// (claudeBlockCause) — the operator's own --settings vs an un-overridable
// managed-settings route — and on the reason (escape-hatch lie vs dead proxy).
// It names the exact file and the fixes. attachNoticed condenses the proxy-down
// variants when the attach layer already printed its daemon-unreachable line
// (don't restate "unreachable"; the remedies always survive).
func claudeProxyFailClosedMsg(reason proxyFallbackReason, proxyURL, settingsPath string, cause claudeBlockCause, attachNoticed bool) string {
	if cause == blockManaged {
		switch reason {
		case reasonNoProxyRouteConflict:
			return fmt.Sprintf(
				"observer claude: refusing to launch under --no-proxy-route — the enterprise managed-settings file %s routes claude to the observer proxy (%s) via env.ANTHROPIC_BASE_URL, and managed settings OUTRANK every other scope (even a CLI --settings file cannot override them), so the launcher cannot bypass it — it would KEEP routing through the proxy and capture turns you asked not to capture. Fix it with your admin: remove env.ANTHROPIC_BASE_URL from %s (managed settings are admin-provisioned; observer cannot override them). Then re-run.",
				settingsPath, proxyURL, settingsPath,
			)
		default: // reasonProxyDownConflict
			if attachNoticed {
				return fmt.Sprintf(
					"observer claude: refusing to launch — the enterprise managed-settings file %s routes claude to the observer proxy via env.ANTHROPIC_BASE_URL, and managed settings OUTRANK every other scope (even a CLI --settings file cannot defeat them), so every API call would hit the dead proxy and fail. Fix it one of two ways: start the daemon with `observer start` (restores capture), OR have your admin remove env.ANTHROPIC_BASE_URL from %s. Then re-run.",
					settingsPath, settingsPath,
				)
			}
			return fmt.Sprintf(
				"observer claude: refusing to launch — the observer proxy at %s is unreachable, but the enterprise managed-settings file %s routes claude to it via env.ANTHROPIC_BASE_URL, and managed settings OUTRANK every other scope (even a CLI --settings file cannot defeat them), so every API call would hit the dead proxy and fail. Fix it one of two ways: start the daemon with `observer start` (restores capture), OR have your admin remove env.ANTHROPIC_BASE_URL from %s. Then re-run.",
				proxyURL, settingsPath, settingsPath,
			)
		}
	}
	switch reason {
	case reasonNoProxyRouteConflict:
		return fmt.Sprintf(
			"observer claude: refusing to launch under --no-proxy-route — %s routes claude to the observer proxy (%s) via env.ANTHROPIC_BASE_URL, and Claude Code's settings.json env WINS over the process environment. observer would normally bypass it with a one-shot --settings override, but you passed your OWN --settings and stacking a second one could clobber yours. Fix it: drop your --settings, OR remove the baked-in route with `observer init --claude-code --skip-proxy-route` (or delete env.ANTHROPIC_BASE_URL from %s), then re-run.",
			settingsPath, proxyURL, settingsPath,
		)
	default: // reasonProxyDownConflict
		if attachNoticed {
			return fmt.Sprintf(
				"observer claude: refusing to launch — %s routes claude to the observer proxy via env.ANTHROPIC_BASE_URL (which WINS over the process environment), so every API call would hit the dead proxy and fail. observer would normally bypass it with a one-shot --settings override, but you passed your OWN --settings and stacking a second one could clobber yours. Fix it one of three ways: start the daemon with `observer start` (restores capture); drop your --settings; or remove the baked-in route with `observer init --claude-code --skip-proxy-route` (or delete env.ANTHROPIC_BASE_URL from %s). Then re-run.",
				settingsPath, settingsPath,
			)
		}
		return fmt.Sprintf(
			"observer claude: refusing to launch — the observer proxy at %s is unreachable, but %s routes claude to it via env.ANTHROPIC_BASE_URL (which WINS over the process environment), so every API call would hit the dead proxy and fail. observer would normally bypass it with a one-shot --settings override, but you passed your OWN --settings and stacking a second one could clobber yours. Fix it one of three ways: start the daemon with `observer start` (restores capture); drop your --settings; or remove the baked-in route with `observer init --claude-code --skip-proxy-route` (or delete env.ANTHROPIC_BASE_URL from %s). Then re-run.",
			proxyURL, settingsPath, settingsPath,
		)
	}
}

// claudeNeutralizeNotice returns the honest one-line "turns are NOT captured"
// stderr notice for a bypass launch, branching on the reason (why we are
// bypassing) and whether a persistent settings.json route is being overridden
// (so the operator knows a one-shot --settings override is in play).
// attachNoticed condenses the proxy-down variants when the attach layer already
// printed its daemon-unreachable line (same dead daemon — restating
// "unreachable" would be the F3(a) redundancy in its bare-direct shape); the
// capture-loss half is NEW information and always survives. Pure so the exact
// copy is unit-testable without exec.
func claudeNeutralizeNotice(reason proxyFallbackReason, proxyURL, settingsPath string, overridingRoute, attachNoticed bool) string {
	if overridingRoute {
		switch reason {
		case reasonProxyDownClean:
			if attachNoticed {
				return fmt.Sprintf(
					"observer claude: bypassing the observer proxy route configured in %s for this run via a one-shot --settings override (traffic goes straight to Anthropic; turns are NOT captured until the daemon is back — start it with `observer start`).",
					settingsPath,
				)
			}
			return fmt.Sprintf(
				"observer claude: proxy unreachable at %s — bypassing the observer proxy route configured in %s for this run via a one-shot --settings override (traffic goes straight to Anthropic; turns are NOT captured until the daemon is back — start it with `observer start`).",
				proxyURL, settingsPath,
			)
		default: // reasonNoProxyRouteClean
			return fmt.Sprintf(
				"observer claude: --no-proxy-route set — bypassing the observer proxy route configured in %s for this run via a one-shot --settings override (traffic goes straight to Anthropic; turns are NOT captured).",
				settingsPath,
			)
		}
	}
	switch reason {
	case reasonProxyDownClean:
		if attachNoticed {
			return "observer claude: proxy routing skipped for this run (traffic goes straight to Anthropic; turns are NOT captured until the daemon is back — start it with `observer start`)."
		}
		return fmt.Sprintf(
			"observer claude: proxy unreachable at %s — launching claude WITHOUT proxy routing for this run (traffic goes straight to Anthropic; turns are NOT captured until the daemon is back — start it with `observer start`).",
			proxyURL,
		)
	default: // reasonNoProxyRouteClean
		return "observer claude: --no-proxy-route set — launching claude WITHOUT proxy routing (traffic goes straight to Anthropic; turns are NOT captured)."
	}
}

// neutralizeBypassEnv builds the child env for a NON-persistent-route bypass
// launch (finding 2). When the process env carries a THIRD-PARTY
// ANTHROPIC_BASE_URL (a value that does NOT point at the observer proxy), it is
// PRESERVED verbatim — the operator routes there deliberately and there is no
// observer route to defeat, so stripping it (the pre-fix behavior) would silently
// break their gateway. Otherwise — no value, or one that points AT the observer
// proxy — the key is stripped and pinned to the provider default so a stray
// shell-profile export can't send claude at the dead/undesired proxy. Pure over
// the injected environment so the strip/pin-vs-preserve decision is unit-tested.
func neutralizeBypassEnv(environ []string, proxyURL string) []string {
	if v, ok := lookupEnvValue(environ, "ANTHROPIC_BASE_URL"); ok && v != "" && !urlRoutesToProxy(v, proxyURL) {
		return append([]string{}, environ...)
	}
	return append(stripEnvKeys(environ, "ANTHROPIC_BASE_URL"),
		"ANTHROPIC_BASE_URL="+anthropicDefaultBaseURL)
}

// runClaudeThirdPartyDirect execs claude HONORING a third-party (non-observer)
// settings-scope route the operator deliberately configured (finding 1): it does
// NOT strip/pin the process env and does NOT write a --settings override, so the
// operator's own gateway route (in managed/CLI/local/project/user settings)
// stands. It prints one honest line that turns are NOT captured through the
// observer proxy, then launches with the caller's environment unchanged, honoring
// --continue-from. This is a PROCEED verdict (not a neutralize / fail-closed):
// there is no observer route to defeat, so refusing or clobbering would be wrong.
//
// launchArgs / continueDir are resolved ONCE upstream (finding N2): the caller
// runs --continue-from before the routing decision so the route is resolved
// against the SAME directory the child will run in; this function must not
// re-resolve it (that would double-render the handoff and re-answer the route).
func runClaudeThirdPartyDirect(opts claudeLauncherOptions, bin string, route claudeRouteResolution, launchArgs []string, continueDir string) error {
	fmt.Fprintf(opts.stderr,
		"observer claude: honoring your configured ANTHROPIC_BASE_URL route (%s, in %s) — launching claude with your own routing untouched; turns are NOT captured through the observer proxy.\n",
		route.value, claudeScopeLabel(route.scope))
	// Inherit the environment unchanged — the operator's route must stand.
	return execClaudeChild(bin, launchArgs, os.Environ(), continueDir, opts.configPath,
		budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
}

// runClaudeBareDirect execs claude BYPASSING the observer proxy (the neutralize
// verdict). Two mechanisms, chosen by whether a persistent settings.json route
// must be overridden:
//
//   - persistentRoute: a baked-in settings.json route the process env can't beat
//     (settings wins). Write a one-shot CLI-scope --settings file pinned to the
//     provider default and prepend `--settings <file>` — CLI scope outranks user
//     settings.json, so claude reaches Anthropic directly. Reached only when the
//     operator passed no --settings of their own (else decideProxyFallback failed
//     closed), so the stack is unambiguous. The temp file is removed on exit.
//   - no persistentRoute: the process env is the only possible route, so strip it
//     and pin the provider default there (cheap; no temp file).
//
// Either way it prints the honest "turns are NOT captured" notice and forwards
// the child's exit code. Generalizes the former --no-proxy-route launch block;
// honors operator decision #2 (notice + working launch, never a silent break)
// even when a route is baked in. launchArgs / continueDir are resolved ONCE
// upstream (finding N2) — this function never re-resolves --continue-from.
func runClaudeBareDirect(opts claudeLauncherOptions, bin string, reason proxyFallbackReason, proxyURL string, persistentRoute bool, settingsPath string, launchArgs []string, continueDir string, attachDownNoticed bool) error {
	if persistentRoute {
		// A baked-in settings.json route the process env can't beat (settings wins).
		// Mint a one-shot CLI-scope --settings file pinned to the provider default
		// and prepend `--settings <file>` — CLI scope outranks user/project/local
		// settings.json, so claude reaches Anthropic directly. The temp file is
		// created + removed (incl. on SIGINT/SIGTERM, finding N5) by the wrapper.
		err := withClaudeBypassSettings(anthropicDefaultBaseURL, func(settingsFile string) error {
			fmt.Fprintln(opts.stderr, claudeNeutralizeNotice(reason, proxyURL, settingsPath, true, attachDownNoticed))
			// Prepend --settings so it is claude's own global flag, ahead of the tool
			// remainder / injected continue-from prompt. CLI --settings outranks the
			// process env too, so inherit the environment unchanged.
			args := append([]string{"--settings", settingsFile}, launchArgs...)
			return execClaudeChild(bin, args, os.Environ(), continueDir, opts.configPath,
				budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
		})
		var bwe *bypassWriteError
		if errors.As(err, &bwe) {
			// Can't write the override → we cannot bypass the baked-in route. Refuse
			// rather than launch into the routed/dead proxy.
			fmt.Fprintf(opts.stderr,
				"observer claude: could not write the proxy-bypass --settings override (%v); refusing to launch into the configured proxy route in %s. Start `observer start`, or remove the route with `observer init --claude-code --skip-proxy-route`.\n",
				bwe.err, settingsPath)
			return exitErr(1)
		}
		return err
	}
	// No baked-in route: neutralize ONLY an observer-proxy process-env value; a
	// third-party gateway is preserved verbatim (finding 2).
	fmt.Fprintln(opts.stderr, claudeNeutralizeNotice(reason, proxyURL, settingsPath, false, attachDownNoticed))
	return execClaudeChild(bin, launchArgs, neutralizeBypassEnv(os.Environ(), proxyURL), continueDir, opts.configPath,
		budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
}

// claudeEmptyUnsetAction is what to do about a settings scope that explicitly
// UNSETS env.ANTHROPIC_BASE_URL (="") on a claude launch (finding N3). An empty
// value acts as unset AND defeats the process env, so the launch already goes
// DIRECT unless a HIGHER-scope value overrides it.
type claudeEmptyUnsetAction int

const (
	// emptyUnsetDirectSatisfied: the launch should go direct and that is already
	// what the operator wants (bypass intent) or the best available (proxy down) —
	// launch direct, no --settings tempfile needed.
	emptyUnsetDirectSatisfied claudeEmptyUnsetAction = iota
	// emptyUnsetPinProxy: routed intent, proxy up, and the empty value lives in a
	// scope a CLI --settings can outrank (user/project/local) and the operator did
	// not pass their own --settings — pin a one-shot CLI --settings to the PROXY to
	// RESTORE capture the empty value would otherwise nullify.
	emptyUnsetPinProxy
	// emptyUnsetWarnDirect: routed intent, proxy up, but the empty value is in a
	// scope no launcher lever can outrank (managed) or the operator passed their
	// own --settings (we won't stack) — honestly warn that proxy capture is
	// disabled and launch direct (the tool still works; only capture is lost).
	emptyUnsetWarnDirect
)

// decideClaudeEmptyUnset is the pure, table-driven verdict for an empty-unset
// settings route (finding N3). Rows walked top-down; first match wins:
//
//	scope×value-kind is already fixed to (empty-unset); the axes here are INTENT
//	and reachability + whether the empty scope is CLI-outrankable:
//	 1. bypass intent (--no-proxy-route)        → direct-satisfied (already direct)
//	 2. routed intent, proxy DOWN               → direct-satisfied (daemon-down fallback)
//	 3. routed intent, proxy up, CLI-outrankable → pin CLI --settings to the proxy
//	 4. routed intent, proxy up, managed/own-settings → warn + direct
func decideClaudeEmptyUnset(noProxyRoute, proxyUp, scopeOutrankable, ownSettings bool) claudeEmptyUnsetAction {
	switch {
	case noProxyRoute:
		return emptyUnsetDirectSatisfied
	case !proxyUp:
		return emptyUnsetDirectSatisfied
	case scopeOutrankable && !ownSettings:
		return emptyUnsetPinProxy
	default:
		return emptyUnsetWarnDirect
	}
}

// claudeEmptyUnsetNotice returns the honest stderr line for each empty-unset
// action (finding N3). Pure so the exact copy is unit-testable without exec.
func claudeEmptyUnsetNotice(action claudeEmptyUnsetAction, reason proxyFallbackReason, proxyURL, settingsFile string) string {
	switch action {
	case emptyUnsetPinProxy:
		return fmt.Sprintf(
			"observer claude: %s explicitly unsets ANTHROPIC_BASE_URL (=\"\"), which would defeat proxy routing and silently skip capture — pinning a one-shot --settings override back to the observer proxy (%s) for this run so turns ARE captured.",
			settingsFile, proxyURL,
		)
	case emptyUnsetWarnDirect:
		return fmt.Sprintf(
			"observer claude: %s explicitly unsets ANTHROPIC_BASE_URL (=\"\") and observer cannot override it, so proxy capture is DISABLED for this run — launching claude direct to Anthropic; turns are NOT captured.",
			settingsFile,
		)
	default: // emptyUnsetDirectSatisfied
		if reason == reasonProxyDownClean {
			return fmt.Sprintf(
				"observer claude: proxy unreachable at %s and %s already unsets ANTHROPIC_BASE_URL (=\"\") — launching claude direct to Anthropic; turns are NOT captured until the daemon is back (start it with `observer start`).",
				proxyURL, settingsFile,
			)
		}
		return fmt.Sprintf(
			"observer claude: --no-proxy-route set and %s already unsets ANTHROPIC_BASE_URL (=\"\") — launching claude direct to Anthropic; turns are NOT captured.",
			settingsFile,
		)
	}
}

// emptyUnsetNoticeRedundant reports whether the FULL empty-unset direct-launch
// notice would merely repeat a daemon-unreachable notice the attach layer
// already printed upstream (F3(a)). It is true ONLY for the proxy-down
// direct-satisfied row: the daemon IS the proxy, so "daemon unreachable" and
// "proxy unreachable" are the same root cause. The caller then prints the
// CONDENSED capture-loss line (round-5 — never silence: the attach line has no
// remedy). Every other row (no-proxy-route direct, pin-proxy, warn-direct
// capture-disabled) carries distinct information and prints its full notice.
// Pure so the dedup rule is unit-tested.
func emptyUnsetNoticeRedundant(attachDownNoticed bool, action claudeEmptyUnsetAction, reason proxyFallbackReason) bool {
	return attachDownNoticed &&
		action == emptyUnsetDirectSatisfied &&
		reason == reasonProxyDownClean
}

// runClaudeEmptyUnset launches claude when the effective settings route is an
// explicit empty-unset (finding N3). It resolves the action, prints the honest
// notice, and either pins a one-shot CLI --settings back to the proxy (restoring
// capture) or launches direct. launchArgs / continueDir are the upstream-resolved
// child argv + working dir (finding N2). attachDownNoticed reports whether the
// attach layer already printed its daemon-unreachable notice upstream, so the
// redundant proxy-down direct notice is suppressed (F3(a)).
func runClaudeEmptyUnset(opts claudeLauncherOptions, bin, proxyURL string, route claudeRouteResolution, launchArgs []string, continueDir string, attachDownNoticed bool) error {
	proxyUp := false
	if !opts.noProxyRoute {
		proxyUp = proxyReachable(proxyURL, 250*time.Millisecond)
	}
	scopeOutrankable := route.scope == claudeScopeUser ||
		route.scope == claudeScopeProject ||
		route.scope == claudeScopeLocal
	action := decideClaudeEmptyUnset(opts.noProxyRoute, proxyUp, scopeOutrankable, claudeArgsHaveSettings(opts.claudeArgs))

	// The reason only shapes the direct-satisfied copy (proxy-down vs no-proxy-route).
	reason := reasonNoProxyRouteClean
	if !opts.noProxyRoute && !proxyUp {
		reason = reasonProxyDownClean
	}

	if action == emptyUnsetPinProxy {
		credPath := claudeCredentialsPath()
		env, _, perr := prepareClaudeEnv(os.Environ(), proxyURL, credPath)
		if perr != nil {
			return perr
		}
		err := withClaudeBypassSettings(proxyURL, func(settingsFile string) error {
			// F3(b): print the "turns ARE captured" notice only AFTER the pin
			// tempfile exists — being inside the closure means writeClaudeSettingsPin
			// already succeeded (fn is invoked only on a successful write). Printing
			// it earlier would let a write failure follow a "captured" claim with the
			// contradictory "NOT captured" fallback line below.
			fmt.Fprintln(opts.stderr, claudeEmptyUnsetNotice(action, reason, proxyURL, route.file))
			// F2: this pin-proxy sub-path IS proxy-routed and captured, so it must
			// get the same session-id correlation every other routed launch gets —
			// force a known session id and OOB-announce it (no-op for a bare,
			// non-daemon-spawned launch) so a daemon-attach empty-unset launch still
			// correlates to its observer session. Done INSIDE the closure (the pin
			// is in place, so the launch really will be captured under this id) and
			// skipped under --continue-from, mirroring the routed proceed path in
			// runClaudeLauncher. On a write failure the closure never runs, so the
			// un-captured fallback below never announces a spurious correlation.
			pinArgs := launchArgs
			if opts.continueFrom == "" {
				pinArgs = forceClaudeSessionID(pinArgs)
			}
			args := append([]string{"--settings", settingsFile}, pinArgs...)
			return execClaudeChild(bin, args, env, continueDir, opts.configPath,
				budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: proxyURL})
		})
		var bwe *bypassWriteError
		if errors.As(err, &bwe) {
			fmt.Fprintf(opts.stderr,
				"observer claude: could not write the capture-restoring --settings override (%v); launching direct instead — turns are NOT captured this run.\n",
				bwe.err)
			return execClaudeChild(bin, launchArgs, os.Environ(), continueDir, opts.configPath,
				budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
		}
		return err
	}

	// direct-satisfied / warn-direct: not captured, so NO session-id correlation
	// (matches runClaudeThirdPartyDirect / runClaudeBareDirect). The empty value
	// already forces direct, so the process env is irrelevant (it is defeated by
	// the empty value) — inherit it. F3(a)/round-5: when the full notice would
	// merely repeat the attach layer's daemon-unreachable line (proxy-down direct
	// row), print the CONDENSED no-"unreachable" line instead of going silent —
	// the attach line carries neither the capture-loss half nor the `observer
	// start` remedy, so full suppression lost the only actionable hint.
	if emptyUnsetNoticeRedundant(attachDownNoticed, action, reason) {
		fmt.Fprintln(opts.stderr, claudeNeutralizeNotice(reasonProxyDownClean, proxyURL, route.file, false, true))
	} else {
		fmt.Fprintln(opts.stderr, claudeEmptyUnsetNotice(action, reason, proxyURL, route.file))
	}
	return execClaudeChild(bin, launchArgs, os.Environ(), continueDir, opts.configPath,
		budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
}
