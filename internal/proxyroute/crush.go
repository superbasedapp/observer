package proxyroute

import (
	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
)

// resolveCrushConfigPath returns the global Crush config (crush.json) the
// way Crush's own GlobalConfig() finds it (charmbracelet/crush
// internal/config/load.go, with home.Config() in internal/home/home.go):
// $CRUSH_GLOBAL_CONFIG/crush.json (the variable names a DIRECTORY) >
// $XDG_CONFIG_HOME/crush/crush.json > homeDir/.config/crush/crush.json, the
// same chain on every OS. Crush never reads a CRUSH_CONFIG variable, so this
// resolver does not either: before S-17 it took CRUSH_CONFIG as a file path
// and could route a file Crush never loads. The route writer runs on the
// daemon OS. Higher layers Crush also loads (the data-dir crush.json under
// CRUSH_GLOBAL_DATA / XDG_DATA_HOME, a same-directory crushrc, project files)
// are not written here; they wait for the Wave 4 effective-layer work. (The
// project-local .crush/crush.json is a per-repo override, out of scope for a
// global route write.)
//
// The chain is the crush/user-json artifact's relocation rules (Wave 4); the
// inspector passes its inspection environment, and the writer resolves with
// the registrar's own lookup (crushConfigPath).
func resolveCrushConfigPath(homeDir string, getenv func(string) string) (string, error) {
	return routeArtifactPath("proxyroute.crush", crushConfigArtifact, homeDir, getenv)
}

// crushConfigPath is the crush.json this registrar routes, resolved with
// RegisterOptions.Getenv (audit finding 3's note: never os.Getenv).
func (r *Registrar) crushConfigPath(what string) (string, error) {
	return routeArtifactPath(what, crushConfigArtifact, r.opts.HomeDir, r.opts.Getenv)
}

// RegisterCrush points Crush's OpenAI-compatible provider at the observer
// proxy by ADDITIVELY setting `base_url` on the `providers.openai` entry in
// crush.json. crush.json embeds literal provider keys, so only the base_url
// member of the openai provider is added and nothing else is read into a
// result or an error.
//
// Guard semantics mirror RegisterKimiCode:
//   - config file absent      -> ConfigMissing (benign skip)
//   - no providers.openai     -> Error (nothing to route)
//   - base_url absent         -> add it (Added)
//   - base_url already loopback/observer -> AlreadySet (idempotent)
//   - base_url points elsewhere -> Error (refuse to overwrite a foreign URL)
//
// The write follows the probe-writer credential-file discipline
// (probe_write.go, T-657): one member spliced in through cfgfmt (every other
// byte and key order kept), no backup copy, mode kept, a symlinked layout
// refused, and no error quotes the file.
func (r *Registrar) RegisterCrush() RegistrationResult {
	return r.note(r.writeCrush(), openAICompatProxyURL(r.opts.ProxyPort))
}

// writeCrush is RegisterCrush without the provenance record.
func (r *Registrar) writeCrush() RegistrationResult {
	const what = "proxyroute.crush"
	path, perr := r.crushConfigPath(what)
	want := openAICompatProxyURL(r.opts.ProxyPort)
	res := RegistrationResult{Tool: "crush", ConfigPath: path, BaseURL: want, DryRun: r.opts.DryRun}
	if perr != nil {
		res.Error = perr
		return res
	}
	res.AlreadySet, res.Added, res.Error = r.addProbeBaseURL(what, cfgfmt.FormatJSON, path, crushBaseURLPath, want, &res)
	return res
}
