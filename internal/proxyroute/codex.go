package proxyroute

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// ProviderName is the custom codex model_provider key our routing
// config registers. Codex 0.128.0+ rejects overriding the reserved
// built-in `openai` provider (config-load fails with
// "model_providers contains reserved built-in provider IDs"), so we
// register a sibling provider and switch model_provider to it.
const ProviderName = "openai-observer"

// providerDisplayName is what shows up in codex's TUI provider picker.
const providerDisplayName = "OpenAI (via Observer)"

// RegisterOptions parameterizes Registrar.
type RegisterOptions struct {
	// ProxyPort is the port the observer proxy listens on (e.g. 8820).
	// Required when codex registration is invoked.
	ProxyPort int
	// HomeDir overrides $HOME (used by tests).
	HomeDir string
	// DryRun computes the result without writing.
	DryRun bool
	// Force overwrites an existing model_providers.<ProviderName>.base_url
	// that points at a different host, deletes a reserved [model_providers.openai]
	// block (which codex 0.128.0+ rejects), and replaces a top-level
	// model_provider that points at a different provider.
	Force bool
	// WindowsClaudeHome / WindowsCodexHome override the auto-detected
	// Windows-side home used by the cross-OS route writers
	// (RegisterClaudeCodeWindows / RegisterCodexWindows in windows.go).
	// Empty = walk crossmount.AllHomes() for the first OS==windows home
	// carrying the tool's config dir (the production path). Set by tests
	// to point at a temp dir; mirrors hook.Options.WindowsClaudeHome /
	// WindowsCursorHome.
	WindowsClaudeHome string
	WindowsCodexHome  string
}

// RegistrationResult summarizes one routing registration.
type RegistrationResult struct {
	Tool       string // "codex"
	ConfigPath string // ~/.codex/config.toml
	BaseURL    string // value written or already set
	Added      bool
	AlreadySet bool
	DryRun     bool
	Error      error
	// ConfigMissing is set by the probe-route writers (kimi-code / crush /
	// qwen-code) when the tool's config file is absent — the tool isn't
	// installed/configured, so there is nothing to route. It is a benign
	// skip signal (Error stays nil), letting `observer init` iterate every
	// registry probe-route candidate and silently pass over the ones the
	// operator doesn't have. The verified writers (codex/claude/hermes)
	// never set it (they error on a missing config instead).
	ConfigMissing bool
	// SkipReason, when non-empty, explains a deliberate no-write that is
	// NOT "the tool isn't installed": today only the cross-OS sandbox gate
	// (a caller pinned HomeDir but named no Windows-side home — see
	// crossmount.AutoDetectSuppressed, incident 2026-07-31). Set alongside
	// ConfigMissing so existing callers keep treating it as a benign skip;
	// Error stays nil.
	SkipReason string
	// PriorBaseURL / UpstreamID / UpstreamRoot are populated by writers that
	// route through a /up/<id> prefix (hermes): the upstream the operator must
	// add to [proxy.upstreams]. Zero for the fixed-upstream writers (codex).
	PriorBaseURL string
	UpstreamID   string
	UpstreamRoot string
	// GatewayHintsAdded is set by the Claude Code writers when they add
	// env.CLAUDE_CODE_GATEWAY_HINT_HEADERS=1 beside the route (claude.go).
	// It can be true alongside AlreadySet: an existing route is topped up
	// with the hint switch without the route itself changing. On an
	// unregister it means the switch was (or would be) removed.
	GatewayHintsAdded bool
}

// Registrar dispatches proxy-routing config writes per tool.
type Registrar struct {
	opts RegisterOptions
	// homeOverride is the caller-supplied RegisterOptions.HomeDir VERBATIM,
	// kept before NewRegistrar defaults it to the real $HOME. Non-empty
	// means "the caller pinned this registrar's home", which switches OFF
	// crossmount auto-detection for the cross-OS "-windows" route writers —
	// see crossmount.AutoDetectSuppressed (incident 2026-07-31).
	homeOverride string
}

// NewRegistrar validates opts and returns a Registrar.
func NewRegistrar(opts RegisterOptions) (*Registrar, error) {
	if opts.ProxyPort <= 0 || opts.ProxyPort > 65535 {
		return nil, fmt.Errorf("proxyroute.NewRegistrar: ProxyPort %d out of range", opts.ProxyPort)
	}
	homeOverride := opts.HomeDir
	if opts.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("proxyroute.NewRegistrar: UserHomeDir: %w", err)
		}
		opts.HomeDir = home
	}
	return &Registrar{opts: opts, homeOverride: homeOverride}, nil
}

// codexBaseURL is the value we write into the custom provider's base_url.
// Localhost-only because the proxy never accepts non-loopback connections
// (see internal/proxy/proxy.go).
func codexBaseURL(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d/v1", port)
}

// IsObserverBaseURL reports whether url is a 127.0.0.1 base_url that this
// registrar would treat as already-routing-through-observer regardless of
// port. Used to distinguish "user already pointed codex at observer (maybe
// a different port)" from "user pointed codex at a third-party proxy."
func IsObserverBaseURL(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// RegisterCodex writes a custom [model_providers.openai-observer] block
// into ~/.codex/config.toml and sets top-level model_provider to point
// at it. Idempotent — re-running with the same port returns AlreadySet.
//
// Refuses without Force when:
//   - a [model_providers.openai] block exists (codex 0.128.0+ fails to
//     load that — our write would land in a config codex won't read),
//   - the openai-observer provider points at a non-loopback host, or
//   - the top-level model_provider is set to a third provider.
//
// Other 127.0.0.1 URLs (e.g. user's own observer on a different port)
// are treated as AlreadySet — we don't clobber another local observer
// install by default.
func (r *Registrar) RegisterCodex() RegistrationResult {
	dir := filepath.Join(r.opts.HomeDir, ".codex")
	return r.registerCodexAt(dir, codexBaseURL(r.opts.ProxyPort), "codex")
}

// registerCodexAt is the parameterized core of RegisterCodex: it writes
// the custom [model_providers.openai-observer] block + top-level
// model_provider into <dir>/config.toml with base_url=<want>, tagging
// the result with toolLabel. The native RegisterCodex passes ~/.codex +
// the loopback /v1 URL + "codex"; the cross-OS RegisterCodexWindows
// (windows.go) passes a Windows-side .codex + the localhost /v1 URL +
// "codex-windows". Behaviour for the native call is byte-identical to
// the pre-refactor method.
func (r *Registrar) registerCodexAt(dir, want, toolLabel string) RegistrationResult {
	path := filepath.Join(dir, "config.toml")
	res := RegistrationResult{
		Tool:       toolLabel,
		ConfigPath: path,
		BaseURL:    want,
		DryRun:     r.opts.DryRun,
	}

	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("proxyroute.codex: read: %w", err)
		return res
	}
	root := map[string]any{}
	if len(raw) > 0 {
		if err := toml.Unmarshal(raw, &root); err != nil {
			res.Error = fmt.Errorf("proxyroute.codex: parse %s: %w", path, err)
			return res
		}
	}

	providers, _ := root["model_providers"].(map[string]any)
	if providers == nil {
		providers = map[string]any{}
	}

	// Codex 0.128.0+ rejects [model_providers.openai] outright. If we
	// silently leave it, codex won't load any of our changes either.
	if _, hasReserved := providers["openai"]; hasReserved {
		if !r.opts.Force {
			res.Error = fmt.Errorf(
				"proxyroute.codex: %s contains [model_providers.openai] which codex 0.128.0+ rejects (reserved built-in); pass --force to remove it",
				path,
			)
			return res
		}
		delete(providers, "openai")
	}

	ours, _ := providers[ProviderName].(map[string]any)
	if ours == nil {
		ours = map[string]any{}
	}

	if existing, ok := ours["base_url"].(string); ok && existing != "" {
		switch {
		case existing == want:
			// Provider block matches. Verify model_provider is also
			// pointed at us — only then is the registration AlreadySet.
			if mp, _ := root["model_provider"].(string); mp == ProviderName {
				res.AlreadySet = true
				res.BaseURL = existing
				return res
			}
			// Else fall through and set the top-level switch.
		case IsObserverBaseURL(existing) && !r.opts.Force:
			res.AlreadySet = true
			res.BaseURL = existing
			return res
		case !r.opts.Force:
			res.Error = fmt.Errorf(
				"proxyroute.codex: model_providers.%s.base_url already set to %q; pass --force to overwrite",
				ProviderName, existing,
			)
			return res
		}
	}

	// Refuse to clobber a third-party model_provider unless forced.
	if mp, _ := root["model_provider"].(string); mp != "" && mp != ProviderName && !r.opts.Force {
		res.Error = fmt.Errorf(
			"proxyroute.codex: top-level model_provider is set to %q; pass --force to switch to %q",
			mp, ProviderName,
		)
		return res
	}

	ours["name"] = providerDisplayName
	ours["base_url"] = want
	ours["wire_api"] = "responses"
	ours["requires_openai_auth"] = true
	providers[ProviderName] = ours
	root["model_providers"] = providers
	root["model_provider"] = ProviderName

	if r.opts.DryRun {
		res.Added = true
		return res
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(root); err != nil {
		res.Error = fmt.Errorf("proxyroute.codex: encode: %w", err)
		return res
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		res.Error = fmt.Errorf("proxyroute.codex: mkdir: %w", err)
		return res
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		res.Error = fmt.Errorf("proxyroute.codex: write: %w", err)
		return res
	}
	if err := os.Rename(tmp, path); err != nil {
		res.Error = fmt.Errorf("proxyroute.codex: rename: %w", err)
		return res
	}
	res.Added = true
	return res
}

// CodexHint returns the human-readable, no-mutation guidance string for
// pointing codex at the observer proxy. Caller picks where to print.
func CodexHint(port int) string {
	url := codexBaseURL(port)
	var b strings.Builder
	fmt.Fprintln(&b, "next: route Codex through the observer proxy for accurate token capture.")
	fmt.Fprintln(&b, "  start the proxy:    observer proxy start")
	fmt.Fprintln(&b, "  add to ~/.codex/config.toml:")
	fmt.Fprintf(&b, "      model_provider = %q\n", ProviderName)
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "      [model_providers.%s]\n", ProviderName)
	fmt.Fprintf(&b, "      name = %q\n", providerDisplayName)
	fmt.Fprintf(&b, "      base_url = %q\n", url)
	fmt.Fprintln(&b, "      wire_api = \"responses\"")
	fmt.Fprintln(&b, "      requires_openai_auth = true")
	fmt.Fprintln(&b, "  why a custom provider name: codex 0.128.0+ rejects [model_providers.openai].")
	return b.String()
}
