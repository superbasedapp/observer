package proxyroute

import (
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/credfile"
)

// openAICompatProxyURL is the OpenAI-compatible base URL the probe-route
// writers point a tool at: the proxy's /v1 endpoint on loopback (the proxy
// refuses non-loopback connections — see internal/proxy/proxy.go).
func openAICompatProxyURL(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d/v1", port)
}

// resolveKimiCodeConfigPath returns <kimi-home>/config.toml. Precedence:
// KIMI_CODE_HOME env > homeDir/.kimi-code (the kimi-code/user-config
// artifact's rule). The proxy/route writer runs on the daemon OS (Linux for
// the cross-OS WSL case), where kimi-code stores its config under
// ~/.kimi-code. The inspector passes its inspection environment; the
// writers resolve with the registrar's own lookup (kimiCodeConfigPath).
func resolveKimiCodeConfigPath(homeDir string, getenv func(string) string) (string, error) {
	return routeArtifactPath("proxyroute.kimi-code", kimiConfigArtifact, homeDir, getenv)
}

// kimiCodeConfigPath is the config.toml this registrar routes, resolved
// with RegisterOptions.Getenv.
func (r *Registrar) kimiCodeConfigPath(what string) (string, error) {
	return routeArtifactPath(what, kimiConfigArtifact, r.opts.HomeDir, r.opts.Getenv)
}

// RegisterKimiCode points kimi-code's OpenAI-compatible provider at the
// observer proxy by ADDITIVELY writing `base_url` under [providers.openai]
// in ~/.kimi-code/config.toml. kimi-code carries NO base_url key today, so
// the common path is a pure add: it NEVER touches the provider's api_key,
// the [models.*] blocks, [thinking], or any other key.
//
// Guard semantics:
//   - config file absent   -> ConfigMissing (benign skip; kimi-code not set up)
//   - no [providers.openai] -> Error (nothing to route)
//   - base_url absent       -> add it (Added)
//   - base_url already a loopback/observer URL -> AlreadySet (idempotent; a
//     different local port is left untouched, not clobbered)
//   - base_url points elsewhere -> Error (refuse to overwrite a foreign URL)
//
// config.toml holds the provider's api_key, so the write follows the
// probe-writer credential-file discipline (probe_write.go, T-657): one line
// added through cfgfmt, no re-serialization, no backup copy, mode kept, a
// symlinked or inline-table layout refused, and no error quotes the file.
func (r *Registrar) RegisterKimiCode() RegistrationResult {
	return r.note(r.writeKimiCode(), openAICompatProxyURL(r.opts.ProxyPort))
}

// writeKimiCode is RegisterKimiCode without the provenance record.
func (r *Registrar) writeKimiCode() RegistrationResult {
	const what = "proxyroute.kimicode"
	path, perr := r.kimiCodeConfigPath(what)
	want := openAICompatProxyURL(r.opts.ProxyPort)
	res := RegistrationResult{Tool: "kimi-code", ConfigPath: path, BaseURL: want, DryRun: r.opts.DryRun}
	if perr != nil {
		res.Error = perr
		return res
	}
	res.AlreadySet, res.Added, res.Error = r.addProbeBaseURL(what, cfgfmt.FormatTOML, path, kimiBaseURLPath, want, &res)
	return res
}

// addProbeBaseURL is the shared add-only writer for kimi-code and crush: it
// adds base_url under providers.openai when absent. It sets
// res.ConfigMissing / res.BaseURL / res.PriorBaseURL as it decides and
// returns (alreadySet, added, err).
func (r *Registrar) addProbeBaseURL(what string, f cfgfmt.Format, path string, key cfgfmt.Path, want string, res *RegistrationResult) (bool, bool, error) {
	raw, err := readOwnedRouteFile(what, path)
	if errors.Is(err, errRouteFileMissing) {
		res.ConfigMissing = true
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	doc, err := parseOwnedRouteFile(what, f, path, raw)
	if err != nil {
		return false, false, err
	}
	table := key[:len(key)-1]
	if _, ok := getTable(doc, table); !ok {
		return false, false, credfile.SafeErrorf("%s: %s has no %s to route", what, path, table)
	}
	prior, present, err := routeStringAt(what, path, doc, key)
	if err != nil {
		return false, false, err
	}
	if present && prior != "" {
		if prior == want || IsObserverBaseURL(prior) {
			// This proxy, or another local observer install (maybe a
			// different port): leave a working loopback route alone. The
			// value is Observer's own loopback URL, never a credential.
			res.PriorBaseURL, res.BaseURL = prior, prior
			return true, false, nil
		}
		return false, false, foreignRouteError(what, path, key)
	}
	if r.opts.DryRun {
		return false, true, nil
	}
	if err := doc.Set(key, want); err != nil {
		return false, false, routeEditError(what, path, key, err)
	}
	if err := commitRouteDoc(what, path, doc); err != nil {
		return false, false, err
	}
	return false, true, nil
}
