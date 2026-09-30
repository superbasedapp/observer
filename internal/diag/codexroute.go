package diag

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// codex.proxy_route (post-Agent-Access backlog item 14): is codex's SELECTED
// model provider one the observer proxy can capture, and does a managed codex
// application network policy forbid the loopback route?
//
// Two facts a routed-looking codex can hide:
//
//  1. Provider bypass. The observer route only covers the provider it names
//     (openai-observer, or the built-in openai provider via openai_base_url).
//     model_provider = "amazon-bedrock" signs requests with AWS SigV4 and
//     sends them to Bedrock directly; any other provider with its own
//     base_url, or none, also never reaches the proxy. Those turns are
//     session-log tokens only, never proxy-exact (classification:
//     proxyroute.ClassifyCodexProvider).
//  2. Application network policy (codex 0.157.0, PRs #47389/#47407). A
//     managed requirements file with an enabled [application.network] block
//     restricts codex's own HTTP/WebSocket traffic to "HTTPS or WSS to that
//     exact host" (codex-rs/http-client/src/network_policy.rs,
//     DestinationPolicy::Restricted). The observer proxy is plain http on
//     loopback, so no allow entry can admit it. Only the SYSTEM layer is
//     readable here (/etc/codex/requirements.toml on Unix,
//     %ProgramData%\OpenAI\Codex\requirements.toml on Windows); macOS MDM and
//     ChatGPT-workspace cloud requirements can set the same block and are
//     not visible to this check.
//  3. Managed provider selection (item 14 follow-up 5). The same
//     requirements file can pin `model_provider` (and replace a provider's
//     definition), which beats config.toml, every profile and `-c` flags;
//     a forced provider that bypasses the proxy is reported as
//     admin-enforced (see resolveCodexSelection). The system config.toml
//     beside it is merged BELOW the user's config.toml.

const codexRouteCheckName = "codex.proxy_route"

// codexSystemRequirementsPath is codex's system requirements.toml location
// (codex-rs/config/src/loader/mod.rs). A var so tests can point it at a
// fixture.
var codexSystemRequirementsPath = func() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "OpenAI", "Codex", "requirements.toml")
	}
	return "/etc/codex/requirements.toml"
}

// codexProviderConfig is the provider-selection subset of a codex config
// file (base config.toml, a legacy [profiles.<name>] table, or a
// <name>.config.toml overlay).
type codexProviderConfig struct {
	OpenAIBaseURL  string `toml:"openai_base_url"`
	ModelProvider  string `toml:"model_provider"`
	ModelProviders map[string]struct {
		BaseURL string `toml:"base_url"`
	} `toml:"model_providers"`
	Profiles map[string]struct {
		ModelProvider string `toml:"model_provider"`
	} `toml:"profiles"`
}

// codexProviderRequirements is the provider-selection subset of a managed
// requirements.toml (codex-rs/config/src/config_requirements.rs
// ConfigRequirementsToml): `model_provider` is an "Exact provider selection,
// overriding local and session configuration" and each
// `[model_providers.<id>]` is a "Complete provider definition" that
// replaces the configured one (core/src/config/requirements.rs
// apply_to_config; core/src/config/mod.rs selects
// required_model_provider() before the runtime override and config.toml).
type codexProviderRequirements struct {
	ModelProvider  string `toml:"model_provider"`
	ModelProviders map[string]struct {
		BaseURL string `toml:"base_url"`
	} `toml:"model_providers"`
}

// readCodexProviderRequirements parses the provider subset of the
// requirements file at path. Missing or unparseable reads as empty.
func readCodexProviderRequirements(path string) codexProviderRequirements {
	var req codexProviderRequirements
	if path == "" {
		return req
	}
	_, _ = toml.DecodeFile(path, &req)
	return req
}

// mergeSystemCodexConfig fills the provider-selection keys the user's
// config.toml leaves unset from the system config.toml layer
// (/etc/codex/config.toml, %ProgramData%\OpenAI\Codex\config.toml), which
// codex loads BELOW the user layer (codex-rs/config/src/loader/mod.rs).
// User values win; provider tables union with the user's winning per id.
func mergeSystemCodexConfig(user, system codexProviderConfig) codexProviderConfig {
	if strings.TrimSpace(user.ModelProvider) == "" {
		user.ModelProvider = system.ModelProvider
	}
	if strings.TrimSpace(user.OpenAIBaseURL) == "" {
		user.OpenAIBaseURL = system.OpenAIBaseURL
	}
	for id, p := range system.ModelProviders {
		if user.ModelProviders == nil {
			user.ModelProviders = map[string]struct {
				BaseURL string `toml:"base_url"`
			}{}
		}
		if _, ok := user.ModelProviders[id]; !ok {
			user.ModelProviders[id] = p
		}
	}
	return user
}

// codexSelection is the provider codex will actually use for a plain run.
type codexSelection struct {
	provider string
	baseURL  string
	// forced: a managed requirement pins the provider id.
	forced bool
	// ownProvider is the id config.toml itself selects (before the
	// requirement), for the "your route was overridden" message.
	ownProvider string
}

// resolveCodexSelection applies codex's precedence: a required
// model_provider wins over config.toml's; a required provider definition
// replaces the configured one's base_url.
func resolveCodexSelection(cfg codexProviderConfig, req codexProviderRequirements) codexSelection {
	sel := codexSelection{ownProvider: strings.TrimSpace(cfg.ModelProvider)}
	sel.provider = sel.ownProvider
	if forced := strings.TrimSpace(req.ModelProvider); forced != "" {
		sel.provider, sel.forced = forced, true
	}
	if p, ok := cfg.ModelProviders[sel.provider]; ok {
		sel.baseURL = p.BaseURL
	}
	if p, ok := req.ModelProviders[sel.provider]; ok {
		sel.baseURL = p.BaseURL
	}
	return sel
}

// codexRequirementsVisibility is the honest scope note: only the system
// requirements file is readable here.
const codexRequirementsVisibility = "managed requirements visible to this check: the system requirements.toml only; macOS managed preferences (MDM) and ChatGPT-workspace cloud requirements can also force model_provider and are not visible here"

// checkCodexProviderRoute implements codex.proxy_route for the codex home
// under homeDir, reading the system requirements file at requirementsPath
// (and the system config.toml beside it).
func checkCodexProviderRoute(homeDir, requirementsPath string) Check {
	codexHome := filepath.Join(homeDir, ".codex")
	cfgPath := filepath.Join(codexHome, "config.toml")

	var cfg codexProviderConfig
	if _, err := toml.DecodeFile(cfgPath, &cfg); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Check{Name: codexRouteCheckName, Status: StatusOK, Message: "no codex config.toml - codex not set up on this host"}
		}
		return Check{Name: codexRouteCheckName, Status: StatusWarn, Message: "parse codex config.toml: " + err.Error()}
	}
	if requirementsPath != "" {
		var system codexProviderConfig
		if _, err := toml.DecodeFile(filepath.Join(filepath.Dir(requirementsPath), "config.toml"), &system); err == nil {
			cfg = mergeSystemCodexConfig(cfg, system)
		}
	}

	req := readCodexProviderRequirements(requirementsPath)
	sel := resolveCodexSelection(cfg, req)
	posture := proxyroute.ClassifyCodexProvider(proxyroute.CodexProviderInput{
		Provider:        sel.provider,
		ProviderBaseURL: sel.baseURL,
		OpenAIBaseURL:   cfg.OpenAIBaseURL,
	})

	var details []string
	details = append(details, "config: "+cfgPath)
	if sel.forced {
		details = append(details, fmt.Sprintf(
			"managed requirements %s force model_provider=%q: it overrides config.toml, every profile and `-c` overrides (including the openai_base_url `observer codex` injects when the forced provider is not the built-in openai)",
			requirementsPath, sel.provider))
	} else {
		// Profiles only matter when no requirement pins the provider.
		details = append(details, codexProfileBypasses(codexHome, cfg)...)
	}
	details = append(details, codexRequirementsVisibility)

	status := StatusOK
	var msg string
	switch {
	case posture == proxyroute.CodexPostureProxy:
		msg = "codex's selected provider routes to the observer proxy (proxy-exact tokens)"
	case posture == proxyroute.CodexPostureUnrouted && sel.forced && sel.ownProvider != "" && sel.ownProvider != proxyroute.CodexBuiltinOpenAI:
		status = StatusWarn
		msg = fmt.Sprintf("managed requirements force the built-in openai provider over config.toml's model_provider=%q, so that route is ignored; only an `observer codex` launch (or openai_base_url) reaches the proxy", sel.ownProvider)
	case posture == proxyroute.CodexPostureUnrouted:
		msg = "codex uses the built-in openai provider with no durable route; `observer codex` launches are captured by the proxy, a plain `codex` run is session-log only"
	default:
		status = StatusWarn
		msg = proxyroute.CodexBypassExplanation(posture, sel.provider)
		if sel.forced {
			msg += " - the provider is forced by managed requirements"
			details = append(details,
				"fix: the provider is admin-enforced; only a requirements change (a proxy-routed provider, or model_provider removed) restores proxy capture - otherwise accept session-log capture")
		} else {
			details = append(details,
				"fix: route through the observer proxy with `observer init --codex` (writes model_provider=\""+proxyroute.ProviderName+"\"), or accept session-log capture for this provider")
		}
	}

	if restricted, src := codexApplicationNetworkRestricted(requirementsPath); restricted {
		status = StatusWarn
		details = append(details,
			"managed requirements "+src+" enable [application.network]: codex then allows only HTTPS/WSS to allow-listed hosts, so the observer proxy route (plain http on loopback) is expected to be DENIED - routed codex turns fail until that policy is lifted or the route is removed")
		if posture == proxyroute.CodexPostureProxy {
			msg = "codex routes to the observer proxy, but a managed codex application network policy is expected to deny that plain-http loopback route"
		}
	}
	return Check{Name: codexRouteCheckName, Status: status, Message: msg, Details: details}
}

// codexProfileBypasses lists the codex profiles (legacy [profiles.<name>]
// tables in config.toml, and <name>.config.toml overlays in codexHome) that
// select a provider which bypasses the observer proxy. A `codex -p <name>`
// run under one of them is session-log capture only.
func codexProfileBypasses(codexHome string, base codexProviderConfig) []string {
	type prof struct{ name, provider, baseURL string }
	var profiles []prof
	for name, p := range base.Profiles {
		mp := strings.TrimSpace(p.ModelProvider)
		if mp == "" {
			continue
		}
		profiles = append(profiles, prof{name: name, provider: mp, baseURL: base.ModelProviders[mp].BaseURL})
	}
	overlays, _ := filepath.Glob(filepath.Join(codexHome, "*.config.toml"))
	for _, path := range overlays {
		var ov codexProviderConfig
		if _, err := toml.DecodeFile(path, &ov); err != nil {
			continue
		}
		mp := strings.TrimSpace(ov.ModelProvider)
		if mp == "" {
			continue
		}
		baseURL := base.ModelProviders[mp].BaseURL
		if p, ok := ov.ModelProviders[mp]; ok && strings.TrimSpace(p.BaseURL) != "" {
			baseURL = p.BaseURL
		}
		profiles = append(profiles, prof{name: strings.TrimSuffix(filepath.Base(path), ".config.toml"), provider: mp, baseURL: baseURL})
	}
	var out []string
	for _, p := range profiles {
		posture := proxyroute.ClassifyCodexProvider(proxyroute.CodexProviderInput{
			Provider: p.provider, ProviderBaseURL: p.baseURL, OpenAIBaseURL: base.OpenAIBaseURL,
		})
		if posture.Bypasses() {
			out = append(out, fmt.Sprintf("profile %q selects model_provider=%q: `codex -p %s` runs bypass the observer proxy (session-log tokens only)", p.name, p.provider, p.name))
		}
	}
	sort.Strings(out)
	return out
}

// codexApplicationNetworkRestricted reports whether the requirements file at
// path enables codex's application network policy: an [application.network]
// table whose `enabled` is true or absent (codex defaults a present block to
// enabled = true). Missing or unparseable files read as not restricted.
func codexApplicationNetworkRestricted(path string) (bool, string) {
	if path == "" {
		return false, ""
	}
	var req struct {
		Application *struct {
			Network *struct {
				Enabled *bool `toml:"enabled"`
			} `toml:"network"`
		} `toml:"application"`
	}
	if _, err := toml.DecodeFile(path, &req); err != nil {
		return false, ""
	}
	if req.Application == nil || req.Application.Network == nil {
		return false, ""
	}
	if n := req.Application.Network; n.Enabled != nil && !*n.Enabled {
		return false, ""
	}
	return true, path
}
