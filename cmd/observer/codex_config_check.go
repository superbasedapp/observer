// codex_config_check.go — V6-2 pre-flight: warn if
// $CODEX_HOME/config.toml lacks `openai_base_url` pointing at the
// proxy.
//
// V6-2 (docs/observer-platform-issues-v6.md): codex 0.130+ silently
// drops the wrapper's argv-injected `-c openai_base_url=…` override.
// The outer `codex exec` parses the override but the inner
// `codex app-server` child reads its own config from
// $CODEX_HOME/config.toml, so only the file value reaches the HTTP
// client. The wrapper's pre-flight reads the file, detects the
// missing/wrong key, and emits ONE stderr line naming the manual
// fix. Honors --no-app-server-check.
//
// True fix is upstream: codex should forward -c overrides to the
// inner. Until then, the operator either edits config.toml manually
// (one-time) or accepts zero captures. This check makes the
// otherwise-silent capture loss loudly visible at pre-flight.

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// codexConfigMisconfig records one misconfigured CODEX_HOME root so the
// wrapper can both warn AND auto-fix from the same scan.
type codexConfigMisconfig struct {
	ConfigPath   string
	Status       configTOMLStatus
	CurrentValue string // populated for the mismatch statuses (configTOMLOK / configTOMLProviderMismatch)
	WantURL      string // the URL we'd write if --write-config is set
	// Provider is the selected model_provider id for a
	// configTOMLProviderMismatch (the table whose base_url is wrong).
	Provider string
}

// fixable reports whether --write-config can repair this misconfig. The
// writer only rewrites the TOP-LEVEL openai_base_url key; a wrong
// [model_providers.<id>].base_url is reported, never rewritten here (the
// provider-shape writer is `observer init --codex --force`).
func (m codexConfigMisconfig) fixable() bool {
	return m.Status != configTOMLProviderMismatch
}

// codexRouteFacts is what one CODEX_HOME root's effective route looks like
// to the misconfig table: the base file's readability plus the merged
// (base + active profile) route.
type codexRouteFacts struct {
	fileMissing bool
	unreadable  bool
	eff         codexEffectiveRoute
	proxyURL    string
}

func (f codexRouteFacts) customProvider() bool {
	return f.eff.provider != "" && f.eff.provider != proxyroute.CodexBuiltinOpenAI
}

// codexMisconfigVerdict is what the table decides for one root.
type codexMisconfigVerdict int

const (
	verdictClean codexMisconfigVerdict = iota
	verdictSkip
	verdictMissingFile
	verdictMissingKey
	verdictOpenAIMismatch
	verdictProviderMismatch
)

// codexMisconfigRules is walked top-down; the first match wins (CLAUDE.md
// #5). It judges the route codex will actually USE for this launch: the
// SELECTED provider after the active profile overlay (item 14 follow-up 4).
//
// Grounding (openai/codex rust-v0.157.1): openai_base_url only overrides the
// BUILT-IN openai provider (model-provider-info/src/lib.rs
// built_in_model_providers); a selected [model_providers.<id>] uses its own
// base_url; a `<name>.config.toml` profile layers over config.toml
// (codex-rs/config/src/loader/mod.rs layer list). So a custom provider that
// already routes to the proxy (the `openai-observer` shape `observer init`
// writes) is clean even with no openai_base_url - the check used to flag it.
var codexMisconfigRules = []struct {
	name    string
	match   func(codexRouteFacts) bool
	verdict codexMisconfigVerdict
}{
	{"file_missing", func(f codexRouteFacts) bool { return f.fileMissing }, verdictMissingFile},
	{"unreadable", func(f codexRouteFacts) bool { return f.unreadable }, verdictSkip},
	{"provider_routes_to_proxy", func(f codexRouteFacts) bool {
		return f.customProvider() && urlRoutesToProxy(f.eff.providerURL, f.proxyURL)
	}, verdictClean},
	// A loopback observer URL on another port/path: the operator meant to
	// route here, the route is just stale. A non-observer provider (Bedrock,
	// a third-party host, a self-resolved OSS provider) is a deliberate
	// bypass reported once by codexProviderBypassNotice, not a misconfig.
	{"provider_other_observer", func(f codexRouteFacts) bool {
		return f.customProvider() && proxyroute.IsObserverBaseURL(f.eff.providerURL)
	}, verdictProviderMismatch},
	{"provider_bypass", codexRouteFacts.customProvider, verdictSkip},
	{"openai_routes_to_proxy", func(f codexRouteFacts) bool {
		return urlRoutesToProxy(f.eff.openaiURL, f.proxyURL)
	}, verdictClean},
	{"openai_missing_key", func(f codexRouteFacts) bool { return f.eff.openaiURL == "" }, verdictMissingKey},
	{"openai_mismatch", func(codexRouteFacts) bool { return true }, verdictOpenAIMismatch},
}

func decideCodexMisconfig(f codexRouteFacts) (codexMisconfigVerdict, string) {
	for _, r := range codexMisconfigRules {
		if r.match(f) {
			return r.verdict, r.name
		}
	}
	return verdictClean, ""
}

// codexRouteFactsFor reads one root's facts for the active profile.
func codexRouteFactsFor(root, proxyURL, profile string) codexRouteFacts {
	f := codexRouteFacts{proxyURL: proxyURL}
	base := filepath.Join(root, "config.toml")
	if _, err := os.Stat(base); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			f.fileMissing = true
		} else {
			f.unreadable = true
		}
		return f
	}
	var probe map[string]any
	if _, err := toml.DecodeFile(base, &probe); err != nil {
		f.unreadable = true
		return f
	}
	f.eff = resolveCodexEffectiveRoute(root, profile)
	return f
}

// findCodexConfigMisconfigs returns every CODEX_HOME root whose EFFECTIVE
// route (base config.toml + the active `-p` profile overlay) does not reach
// the proxy: the built-in openai provider with a missing or wrong
// openai_base_url, or a selected custom provider whose base_url is a stale
// observer route. Unreadable files and deliberate provider bypasses are
// skipped (best-effort; the bypass has its own launch notice).
func findCodexConfigMisconfigs(codexHomeRootsList []string, proxyURL, profile string) []codexConfigMisconfig {
	if len(codexHomeRootsList) == 0 {
		return nil
	}
	primary := primaryAcceptedURL(acceptedProxyBaseURLs(proxyURL))
	var out []codexConfigMisconfig
	for _, root := range codexHomeRootsList {
		configPath := filepath.Join(root, "config.toml")
		f := codexRouteFactsFor(root, proxyURL, profile)
		verdict, _ := decideCodexMisconfig(f)
		switch verdict {
		case verdictMissingFile:
			out = append(out, codexConfigMisconfig{ConfigPath: configPath, Status: configTOMLMissingFile, WantURL: primary})
		case verdictMissingKey:
			out = append(out, codexConfigMisconfig{ConfigPath: configPath, Status: configTOMLMissingKey, WantURL: primary})
		case verdictOpenAIMismatch:
			// The file that SUPPLIED the wrong value is the one to fix: a
			// profile overlay's openai_base_url wins over the base file.
			out = append(out, codexConfigMisconfig{
				ConfigPath: f.eff.openaiSrc, Status: configTOMLOK,
				CurrentValue: f.eff.openaiURL, WantURL: primary,
			})
		case verdictProviderMismatch:
			out = append(out, codexConfigMisconfig{
				ConfigPath: f.eff.providerSrc, Status: configTOMLProviderMismatch,
				CurrentValue: f.eff.providerURL, WantURL: primary, Provider: f.eff.provider,
			})
		}
	}
	return out
}

// checkCodexConfigTOMLBaseURL inspects every plausible CODEX_HOME for
// a config.toml file and verifies the top-level openai_base_url key
// matches the proxy. Returns one stderr-ready warning line per
// misconfigured root, or "" when all roots are correctly set up
// (silent happy path).
//
// Tolerance: trailing slash differences accepted; "<proxy>" and
// "<proxy>/v1" both treated as correct. File missing is a warning
// (operator hasn't run codex from this home yet). File unreadable is
// silent (best-effort — observer must not fail the wrapper on FS
// hiccup).
//
// codexHomeRoots is the caller-supplied list (typically from
// codexHomeRoots() in codex_capture_check.go) so this function is
// platform-agnostic and trivial to test.
func checkCodexConfigTOMLBaseURL(codexHomeRootsList []string, proxyURL, profile string) string {
	misconfigs := findCodexConfigMisconfigs(codexHomeRootsList, proxyURL, profile)
	if len(misconfigs) == 0 {
		return ""
	}
	var warnings []string
	for _, m := range misconfigs {
		switch m.Status {
		case configTOMLOK:
			warnings = append(warnings, fmt.Sprintf(
				"observer codex: %s sets openai_base_url=%q but the proxy is %s. Codex 0.130+ silently drops the -c openai_base_url override (V6-2); update the file or expect 0 captures. See docs/codex-shared-app-server-gotcha.md.",
				m.ConfigPath, m.CurrentValue, m.WantURL,
			))
		case configTOMLMissingKey:
			warnings = append(warnings, fmt.Sprintf(
				"observer codex: %s has no openai_base_url; codex 0.130+ silently drops the -c override (V6-2). Add `openai_base_url = %q` to the file or expect 0 captures. See docs/codex-shared-app-server-gotcha.md.",
				m.ConfigPath, m.WantURL,
			))
		case configTOMLMissingFile:
			warnings = append(warnings, fmt.Sprintf(
				"observer codex: %s does not exist; codex 0.130+ silently drops the -c openai_base_url override (V6-2). Create the file with `openai_base_url = %q` or expect 0 captures. See docs/codex-shared-app-server-gotcha.md.",
				m.ConfigPath, m.WantURL,
			))
		case configTOMLProviderMismatch:
			warnings = append(warnings, fmt.Sprintf(
				"observer codex: %s selects model_provider=%q whose base_url=%q is not the observer proxy (%s); codex sends that provider's turns there, so the proxy captures none. Point [model_providers.%s].base_url at %s (or run `observer init --codex --force`).",
				m.ConfigPath, m.Provider, m.CurrentValue, m.WantURL, m.Provider, m.WantURL,
			))
		}
	}
	return strings.Join(warnings, "\n")
}

// codexConfigsRoutingToProxy returns every codex config FILE that currently
// routes codex AT the observer proxy for THIS launch — a persistent route that
// `--no-proxy-route` does NOT neutralize (B2-3). It covers BOTH shapes observer
// can write: the legacy top-level `openai_base_url` key (what `observer codex
// --write-config` writes) AND the managed provider shape (`model_provider =
// "openai-observer"` + `[model_providers.openai-observer] base_url = ...`, what
// `observer init`/internal/proxyroute writes).
//
// profile is the ACTIVE `-p/--profile <name>` for this launch (finding 3a): when
// set, codex layers `$CODEX_HOME/<name>.config.toml` ON TOP of the base
// config.toml (codex CONFIG_PROFILE_V2), so the effective route is the merge and
// the profile file may be the actual offender. When profile is "", only the base
// config.toml is consulted. Matching is loopback- and suffix-tolerant (see
// urlRoutesToProxy). Missing/unreadable files are skipped (best-effort). The
// returned list is the DISTINCT set of files whose effective value routes to us.
func codexConfigsRoutingToProxy(codexHomeRootsList []string, proxyURL, profile string) []string {
	if strings.TrimSpace(proxyURL) == "" {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	for _, root := range codexHomeRootsList {
		for _, src := range codexEffectiveRoutedSources(root, profile) {
			if src.file == "" || !urlRoutesToProxy(src.url, proxyURL) {
				continue
			}
			if _, dup := seen[src.file]; dup {
				continue
			}
			seen[src.file] = struct{}{}
			out = append(out, src.file)
		}
	}
	return out
}

// codexActiveProfile parses the active codex profile from a launch's forwarded
// args (finding 3a). codex's `-p/--profile` is a GLOBAL flag that layers
// `$CODEX_HOME/<name>.config.toml` on top of the base config (CONFIG_PROFILE_V2).
// It accepts every spelling clap does: `-p NAME`, `-p=NAME`, the ATTACHED short
// form `-pNAME` (e.g. `-pwork` — finding N4), `--profile NAME`, and
// `--profile=NAME`. The scan STOPS at the first bare `--` (mirrors
// argsAreCodexHeadless) and returns "" when no profile is set.
//
// The scan is value-flag aware: a `-p…`-looking token that is actually the VALUE
// of a preceding value-taking flag (e.g. `-m -pfoo`, model=`-pfoo`) is skipped
// via codexValueFlags rather than mis-parsed as the profile flag (finding N4).
func codexActiveProfile(args []string) string {
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			return ""
		}
		switch {
		case a == "-p" || a == "--profile":
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		case strings.HasPrefix(a, "--profile="):
			return strings.TrimPrefix(a, "--profile=")
		case strings.HasPrefix(a, "-p="):
			return strings.TrimPrefix(a, "-p=")
		case strings.HasPrefix(a, "-p"):
			// Attached short form `-pNAME` (`-p` bare and `-p=` are handled above).
			// codex short flags are single-letter, so `-pX` is unambiguously -p=X.
			return strings.TrimPrefix(a, "-p")
		case codexValueFlags[a]:
			// A DIFFERENT value-taking flag (e.g. `-m gpt`): skip its separate value
			// token so a `-p…`-looking value isn't mistaken for the profile flag.
			i += 2
			continue
		}
		i++
	}
	return ""
}

// codexRouteConfig is the routing-relevant subset of a codex config.toml (or a
// profile overlay file) — the two shapes observer can write.
type codexRouteConfig struct {
	OpenAIBaseURL  string `toml:"openai_base_url"`
	ModelProvider  string `toml:"model_provider"`
	ModelProviders map[string]struct {
		BaseURL string `toml:"base_url"`
	} `toml:"model_providers"`
}

// codexRoutedSource is one base_url codex would route through, tagged with the
// file that provided it (for the fail-closed copy).
type codexRoutedSource struct {
	url  string
	file string
}

// decodeCodexRouteConfig parses the routing subset of a codex config file,
// returning the zero value when the file is missing or unreadable (best-effort).
func decodeCodexRouteConfig(path string) codexRouteConfig {
	var cfg codexRouteConfig
	if path == "" {
		return cfg
	}
	if _, err := os.Stat(path); err != nil {
		return cfg
	}
	_, _ = toml.DecodeFile(path, &cfg)
	return cfg
}

// codexEffectiveRoutedSources returns every base_url codex would actually route
// through for a launch with the given CODEX_HOME root and active profile,
// tagged with the source file. It layers the profile overlay
// `<root>/<profile>.config.toml` ON TOP of the base `<root>/config.toml`
// (finding 3a): a non-empty profile openai_base_url / model_provider overrides
// the base, and provider tables union with the profile winning per name. Only
// the SELECTED provider's base_url is returned — an unselected provider table is
// inert and must not trigger a conflict.
func codexEffectiveRoutedSources(root, profile string) []codexRoutedSource {
	eff := resolveCodexEffectiveRoute(root, profile)
	var out []codexRoutedSource
	if eff.openaiURL != "" {
		out = append(out, codexRoutedSource{eff.openaiURL, eff.openaiSrc})
	}
	if eff.providerURL != "" {
		out = append(out, codexRoutedSource{eff.providerURL, eff.providerSrc})
	}
	return out
}

// codexEffectiveRoute is the merged routing view of one CODEX_HOME for one
// launch: the top-level openai_base_url, the SELECTED model_provider, and
// that provider's base_url, each tagged with the file that supplied it.
type codexEffectiveRoute struct {
	openaiURL, openaiSrc     string
	provider                 string
	providerURL, providerSrc string
}

// resolveCodexEffectiveRoute layers the profile overlay
// `<root>/<profile>.config.toml` ON TOP of the base `<root>/config.toml`
// (finding 3a): a non-empty profile openai_base_url / model_provider overrides
// the base, and provider tables union with the profile winning per name. Only
// the SELECTED provider's base_url is resolved — an unselected provider table
// is inert.
func resolveCodexEffectiveRoute(root, profile string) codexEffectiveRoute {
	baseFile := filepath.Join(root, "config.toml")
	base := decodeCodexRouteConfig(baseFile)

	var profFile string
	var prof codexRouteConfig
	if strings.TrimSpace(profile) != "" {
		profFile = filepath.Join(root, profile+".config.toml")
		prof = decodeCodexRouteConfig(profFile)
	}

	var eff codexEffectiveRoute
	// Top-level openai_base_url: profile wins when it sets a non-empty value.
	eff.openaiURL, eff.openaiSrc = strings.TrimSpace(base.OpenAIBaseURL), baseFile
	if v := strings.TrimSpace(prof.OpenAIBaseURL); v != "" {
		eff.openaiURL, eff.openaiSrc = v, profFile
	}
	if eff.openaiURL == "" {
		eff.openaiSrc = ""
	}

	// Selected provider: profile wins when it sets a non-empty value.
	eff.provider = strings.TrimSpace(base.ModelProvider)
	if v := strings.TrimSpace(prof.ModelProvider); v != "" {
		eff.provider = v
	}

	// Provider tables: union, profile overriding by name.
	if eff.provider != "" {
		if p, ok := base.ModelProviders[eff.provider]; ok {
			if v := strings.TrimSpace(p.BaseURL); v != "" {
				eff.providerURL, eff.providerSrc = v, baseFile
			}
		}
		if p, ok := prof.ModelProviders[eff.provider]; ok {
			if v := strings.TrimSpace(p.BaseURL); v != "" {
				eff.providerURL, eff.providerSrc = v, profFile
			}
		}
	}
	return eff
}

// codexProviderBypassNotice returns a one-line launch notice when the codex
// provider this launch will select (effective CODEX_HOME roots + active
// profile) never reaches the observer proxy — e.g. model_provider =
// "amazon-bedrock" — so the `-c openai_base_url` injection cannot capture it.
// "" when every root's selected provider is proxy-capturable.
func codexProviderBypassNotice(roots []string, profile string) string {
	for _, root := range roots {
		eff := resolveCodexEffectiveRoute(root, profile)
		if eff.provider == "" || eff.provider == proxyroute.CodexBuiltinOpenAI {
			// The launcher's own openai_base_url injection covers the built-in
			// provider; a config.toml value pointing elsewhere is handled by
			// the existing preflight (checkCodexConfigTOMLBaseURL).
			continue
		}
		posture := proxyroute.ClassifyCodexProvider(proxyroute.CodexProviderInput{
			Provider:        eff.provider,
			ProviderBaseURL: eff.providerURL,
			OpenAIBaseURL:   eff.openaiURL,
		})
		if posture.Bypasses() {
			return "observer codex: note — " + proxyroute.CodexBypassExplanation(posture, eff.provider) +
				" (" + filepath.Join(root, "config.toml") + "). Run `observer doctor codex` for details."
		}
	}
	return ""
}

// isLoopbackHost reports whether h is one of the interchangeable spellings of
// the local machine. The observer proxy binds loopback-only, so any of these
// with the proxy's port is the same route.
func isLoopbackHost(h string) bool {
	switch strings.ToLower(strings.TrimSpace(h)) {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

// urlRoutesToProxy reports whether got (a base_url read from config.toml) points
// at the observer proxy identified by proxyURL. It treats the loopback host
// spellings 127.0.0.1 / localhost / [::1] as equivalent, requires the same
// port, and accepts the path with or without a trailing "/v1" (trailing-slash
// tolerant). A non-loopback host or a different port never matches. When
// proxyURL is not a usable loopback URL (unexpected — the wrapper always passes
// http://127.0.0.1:<port>), it falls back to the exact accepted-string forms.
func urlRoutesToProxy(got, proxyURL string) bool {
	got = strings.TrimSpace(got)
	if got == "" {
		return false
	}
	proxyU, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil || proxyU.Port() == "" || !isLoopbackHost(proxyU.Hostname()) {
		return matchesAnyURL(got, acceptedProxyBaseURLs(proxyURL))
	}
	gotU, err := url.Parse(got)
	if err != nil {
		return false
	}
	if !isLoopbackHost(gotU.Hostname()) || gotU.Port() != proxyU.Port() {
		return false
	}
	p := strings.TrimRight(gotU.EscapedPath(), "/")
	return p == "" || p == "/v1"
}

// codexNoProxyRouteConflict returns a non-nil error when --no-proxy-route is
// requested but a persistent $CODEX_HOME/config.toml still routes
// openai_base_url to the observer proxy. Codex 0.130+ reads that file, so
// launching would KEEP routing through the proxy DESPITE the flag — silently
// capturing turns the operator asked NOT to capture. We FAIL CLOSED (B3-1):
// refuse to launch (the caller returns a non-zero exit) and name the exact
// file(s) + key + how to revert. We deliberately do NOT inject a stock-default
// override to neutralize it — codex's effective default base URL depends on the
// auth shape (API-key vs ChatGPT-Plus JWT), so a forced value could mis-route a
// ChatGPT-Plus session. The honest refusal wins over a silent, possibly-wrong
// override. Returns nil (launch proceeds) when no config routes to the proxy.
func codexNoProxyRouteConflict(codexHomeRootsList []string, proxyURL, profile string) error {
	offenders := codexConfigsRoutingToProxy(codexHomeRootsList, proxyURL, profile)
	if len(offenders) == 0 {
		return nil
	}
	joined := strings.Join(offenders, ", ")
	return fmt.Errorf(
		"observer codex: refusing to launch under --no-proxy-route — %s still routes codex to the observer proxy (%s), either via the top-level openai_base_url key or via model_provider=%q + [model_providers.%s].base_url, and codex 0.130+ reads that file, so it would KEEP routing through the proxy and capture turns you asked not to capture. This was written by `observer codex --write-config` or `observer init` (or hand-edited); remove that routing from %s (or restore its config.toml.bak.* backup) and re-run.",
		joined, primaryAcceptedURL(acceptedProxyBaseURLs(proxyURL)),
		proxyroute.ProviderName, proxyroute.ProviderName, joined,
	)
}

type configTOMLStatus int

const (
	configTOMLOK configTOMLStatus = iota
	configTOMLMissingKey
	configTOMLMissingFile
	configTOMLUnreadable
	// configTOMLProviderMismatch: the SELECTED custom provider's base_url
	// is a loopback observer route that is not this proxy. Reported only;
	// --write-config does not rewrite provider tables.
	configTOMLProviderMismatch
)

// acceptedProxyBaseURLs returns every URL form an operator might
// legitimately set in config.toml to point at our proxy. The wrapper
// itself injects `<proxy>/v1`; operators sometimes write `<proxy>`
// and rely on codex to append the path. Both work for codex's HTTP
// routing, so both are accepted.
func acceptedProxyBaseURLs(proxyURL string) []string {
	base := strings.TrimRight(proxyURL, "/")
	if base == "" {
		return nil
	}
	return []string{base, base + "/v1"}
}

func primaryAcceptedURL(urls []string) string {
	if len(urls) == 0 {
		return ""
	}
	// Prefer the "/v1" form — matches what the wrapper itself injects.
	for _, u := range urls {
		if strings.HasSuffix(u, "/v1") {
			return u
		}
	}
	return urls[0]
}

// matchesAnyURL accepts trailing-slash differences ("foo/" == "foo").
func matchesAnyURL(got string, wants []string) bool {
	got = strings.TrimRight(strings.TrimSpace(got), "/")
	for _, w := range wants {
		if strings.TrimRight(w, "/") == got {
			return true
		}
	}
	return false
}
