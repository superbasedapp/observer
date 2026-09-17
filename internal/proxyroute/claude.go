package proxyroute

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// claudeBaseURL is the proxy URL we write into Claude Code's settings.
// Localhost-only because the observer proxy refuses non-loopback
// connections (see internal/proxy/proxy.go).
func claudeBaseURL(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

// RegisterClaudeCode writes `"env": { "ANTHROPIC_BASE_URL": "<proxy>" }`
// into ~/.claude/settings.json so Claude Code routes through the
// observer proxy across shell sessions without the operator needing to
// `export ANTHROPIC_BASE_URL` manually.
//
// Idempotent — re-running with the same port returns AlreadySet.
// Refuses without Force when ANTHROPIC_BASE_URL is set to a value the
// caller probably wants to keep (any non-loopback URL); other
// 127.0.0.1/localhost URLs (another observer install on a different
// port) are treated as AlreadySet rather than clobbered.
//
// Preserves every other top-level key in settings.json (hooks,
// mcpServers, permissions, etc.) and every other key in the env map.
//
// Added v1.8.2 to close N4 in docs/audits/teams-test-regression-2026-06-03.md:
// the prior `observer enroll` flow PRINTED the env-var hint but never
// applied it, so accurate api_turns capture required manual operator
// action despite the claim of "auto-wire proxy routing".
func (r *Registrar) RegisterClaudeCode() RegistrationResult {
	dir := filepath.Join(r.opts.HomeDir, ".claude")
	return r.registerClaudeCodeAt(dir, claudeBaseURL(r.opts.ProxyPort), "claude-code")
}

// registerClaudeCodeAt is the parameterized core of RegisterClaudeCode:
// it writes env.ANTHROPIC_BASE_URL=<want> into <dir>/settings.json,
// tagging the result with toolLabel. The native RegisterClaudeCode
// passes ~/.claude + the loopback URL + "claude-code"; the cross-OS
// RegisterClaudeCodeWindows (windows.go) passes a Windows-side .claude
// + the localhost URL + "claude-code-windows". Behaviour for the native
// call is byte-identical to the pre-refactor method.
func (r *Registrar) registerClaudeCodeAt(dir, want, toolLabel string) RegistrationResult {
	path := filepath.Join(dir, "settings.json")
	res := RegistrationResult{
		Tool:       toolLabel,
		ConfigPath: path,
		BaseURL:    want,
		DryRun:     r.opts.DryRun,
	}

	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("proxyroute.claude: read: %w", err)
		return res
	}
	// Preserve unknown top-level fields (hooks, mcpServers, ...) by
	// round-tripping every value as json.RawMessage.
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &settings); err != nil {
			res.Error = fmt.Errorf("proxyroute.claude: parse %s: %w", path, err)
			return res
		}
	}

	env := map[string]any{}
	if existing, ok := settings["env"]; ok {
		if err := json.Unmarshal(existing, &env); err != nil {
			res.Error = fmt.Errorf("proxyroute.claude: parse env: %w", err)
			return res
		}
	}

	if cur, _ := env["ANTHROPIC_BASE_URL"].(string); cur != "" {
		switch {
		case cur == want:
			res.AlreadySet = true
			res.BaseURL = cur
			return res
		case IsObserverBaseURL(cur) && !r.opts.Force:
			// Another local observer install (different port). Don't
			// clobber it — operator can pass --force to switch.
			res.AlreadySet = true
			res.BaseURL = cur
			return res
		case !r.opts.Force:
			res.Error = fmt.Errorf(
				"proxyroute.claude: env.ANTHROPIC_BASE_URL already set to %q; pass --force to overwrite",
				cur,
			)
			return res
		}
	}

	env["ANTHROPIC_BASE_URL"] = want
	patched, err := json.Marshal(env)
	if err != nil {
		res.Error = fmt.Errorf("proxyroute.claude: marshal env: %w", err)
		return res
	}
	settings["env"] = patched

	if r.opts.DryRun {
		res.Added = true
		return res
	}
	if err := writeClaudeSettings(dir, path, settings); err != nil {
		res.Error = err
		return res
	}
	res.Added = true
	return res
}

// UnregisterClaudeCode removes ANTHROPIC_BASE_URL from
// `~/.claude/settings.json`'s env block IF it currently points at THIS
// registrar's own route: a loopback URL on the registrar's configured
// proxy port. Preserves a third-party proxy entry the operator
// deliberately configured AND another observer install's loopback route
// on a different port (ledger B5.25: a scratch node's unenroll, built
// with port 18820, used to strip a real install's :8820 route because
// this method matched any loopback URL). Idempotent: if
// the key is absent, returns AlreadySet=false + Added=false with no
// error and no file mutation.
//
// Called from `observer unenroll` to undo the route written by
// RegisterClaudeCode — without this, every Claude Code session on
// the host keeps routing through the (now-stopped) observer proxy
// after the operator unenrolls, breaking sessions until they edit
// settings.json by hand. N4 caveat in
// docs/audits/teams-test-regression-v1.8.2-2026-06-04.md.
//
// The DryRun field's semantics differ here vs RegisterClaudeCode:
// Added=true means "would remove"; AlreadySet=true means "found
// nothing to remove."
func (r *Registrar) UnregisterClaudeCode() RegistrationResult {
	dir := filepath.Join(r.opts.HomeDir, ".claude")
	path := filepath.Join(dir, "settings.json")
	res := RegistrationResult{
		Tool:       "claude-code",
		ConfigPath: path,
		DryRun:     r.opts.DryRun,
	}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		res.AlreadySet = true
		return res
	}
	if err != nil {
		res.Error = fmt.Errorf("proxyroute.claude.unreg: read: %w", err)
		return res
	}
	settings := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &settings); err != nil {
		res.Error = fmt.Errorf("proxyroute.claude.unreg: parse %s: %w", path, err)
		return res
	}
	envRaw, ok := settings["env"]
	if !ok {
		res.AlreadySet = true
		return res
	}
	env := map[string]any{}
	if err := json.Unmarshal(envRaw, &env); err != nil {
		res.Error = fmt.Errorf("proxyroute.claude.unreg: parse env: %w", err)
		return res
	}
	cur, _ := env["ANTHROPIC_BASE_URL"].(string)
	if cur == "" {
		res.AlreadySet = true
		return res
	}
	if !isOwnClaudeBaseURL(cur, r.opts.ProxyPort) {
		// Third-party, non-loopback, or another observer install's
		// loopback route on a different port — leave the operator's
		// choice alone. Don't error: unenroll is best-effort cleanup.
		res.AlreadySet = true
		res.BaseURL = cur
		return res
	}

	delete(env, "ANTHROPIC_BASE_URL")
	if len(env) == 0 {
		// Don't leave an empty env block — drop the key entirely so
		// the file diff is symmetric with RegisterClaudeCode's "create
		// env" case.
		delete(settings, "env")
	} else {
		patched, err := json.Marshal(env)
		if err != nil {
			res.Error = fmt.Errorf("proxyroute.claude.unreg: marshal env: %w", err)
			return res
		}
		settings["env"] = patched
	}

	res.BaseURL = cur
	res.Added = true // "would remove" / "removed"
	if r.opts.DryRun {
		return res
	}
	if err := writeClaudeSettings(dir, path, settings); err != nil {
		res.Error = err
		return res
	}
	return res
}

// isOwnClaudeBaseURL reports whether raw is the loopback route THIS
// registrar's install owns: a loopback host on exactly the registrar's
// configured proxy port. RegisterClaudeCode always writes an explicit
// port, so a loopback URL without one (or with an unparsable one) is
// never ours and stays untouched.
func isOwnClaudeBaseURL(raw string, port int) bool {
	if !IsObserverBaseURL(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Port() == strconv.Itoa(port)
}

// writeClaudeSettings emits settings as stable-keyed, 2-space-indented
// JSON. Mirrors internal/hook.writeJSONIndented so the two writers
// produce diff-clean updates against the same file.
func writeClaudeSettings(dir, path string, settings map[string]json.RawMessage) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("proxyroute.claude: mkdir: %w", err)
	}
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf []byte
	buf = append(buf, '{', '\n')
	for i, k := range keys {
		buf = append(buf, ' ', ' ')
		kk, _ := json.Marshal(k)
		buf = append(buf, kk...)
		buf = append(buf, ':', ' ')
		var tmp any
		if err := json.Unmarshal(settings[k], &tmp); err == nil {
			pretty, _ := json.MarshalIndent(tmp, "  ", "  ")
			buf = append(buf, pretty...)
		} else {
			buf = append(buf, settings[k]...)
		}
		if i < len(keys)-1 {
			buf = append(buf, ',')
		}
		buf = append(buf, '\n')
	}
	buf = append(buf, '}', '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return fmt.Errorf("proxyroute.claude: write: %w", err)
	}
	return os.Rename(tmp, path)
}
