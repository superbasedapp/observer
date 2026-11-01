package proxyroute

import (
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/credfile"
)

// qwenDefaultBaseURL is the stock value Qwen Code ships in
// ~/.qwen/settings.json's model.baseUrl. The writer only rewrites this
// known default (or an existing observer URL), never a custom host.
const qwenDefaultBaseURL = "https://api.openai.com/v1"

// resolveQwenConfigPath returns <qwen-home>/settings.json. Precedence:
// QWEN_HOME env > homeDir/.qwen (the qwen-code/user-settings artifact's
// rule). The inspector passes its inspection environment; the writers
// resolve with the registrar's own lookup (qwenConfigPath).
func resolveQwenConfigPath(homeDir string, getenv func(string) string) (string, error) {
	return routeArtifactPath("proxyroute.qwen-code", qwenConfigArtifact, homeDir, getenv)
}

// qwenConfigPath is the settings.json this registrar routes, resolved with
// RegisterOptions.Getenv.
func (r *Registrar) qwenConfigPath(what string) (string, error) {
	return routeArtifactPath(what, qwenConfigArtifact, r.opts.HomeDir, r.opts.Getenv)
}

// RegisterQwenCode points Qwen Code at the observer proxy by rewriting
// `model.baseUrl` in ~/.qwen/settings.json. Unlike the other probe writers
// this MODIFIES an existing key: live-grounded 2026-07-10, the OPENAI_BASE_URL
// env knob is INERT (settings.json's model.baseUrl takes precedence and pins
// the host), so the persisted baseUrl is the only working lane.
//
// Because a rewrite is destructive, the guard is stricter than the add-only
// writers: it rewrites ONLY when the current value is safe to replace:
//   - config file absent                     -> ConfigMissing (benign skip)
//   - no model.baseUrl                        -> Error (nothing to route)
//   - baseUrl == the known default (api.openai.com/v1) -> rewrite (Added)
//   - baseUrl already this observer URL       -> AlreadySet (idempotent)
//   - baseUrl already a different loopback URL -> AlreadySet (don't clobber
//     another local observer install)
//   - baseUrl is any other custom host        -> Error (refuse)
//
// Rewriting model.baseUrl ALONE is insufficient on the live build: Qwen Code
// resolves the active model by the (id, baseUrl) pair, so once model.baseUrl is
// the proxy URL it needs a matching modelProviders entry with the SAME baseUrl,
// else it warns "no longer matches any provider ... using the first id match"
// and goes direct to api.openai.com, bypassing the proxy (grounded NEGATIVE
// probe 2026-07-09). So on the rewrite path the writer ALSO retargets every
// modelProviders openai-lane entry currently on the known default host to the
// proxy URL, carrying each entry's own id + envKey untouched (the operator's
// real OpenAI key still forwards through the proxy). Providers on other hosts
// (deepseek / z.ai / dashscope) are left alone.
//
// It NEVER touches an api key or an envKey. settings.json can hold
// plaintext keys, so the write follows the probe-writer credential-file
// discipline (probe_write.go, T-657): model.baseUrl and the changed
// modelProviders openai list are edited in place through cfgfmt (every other
// byte and key order kept, no re-serialization), no backup copy is made, the
// mode is kept, a symlinked layout or a modelProviders value of another shape
// is refused, and no error quotes the file.
func (r *Registrar) RegisterQwenCode() RegistrationResult {
	return r.note(r.writeQwenCode(), openAICompatProxyURL(r.opts.ProxyPort))
}

// writeQwenCode is RegisterQwenCode without the provenance record.
func (r *Registrar) writeQwenCode() RegistrationResult {
	const what = "proxyroute.qwencode"
	path, perr := r.qwenConfigPath(what)
	want := openAICompatProxyURL(r.opts.ProxyPort)
	res := RegistrationResult{Tool: "qwen-code", ConfigPath: path, BaseURL: want, DryRun: r.opts.DryRun}
	if perr != nil {
		res.Error = perr
		return res
	}

	raw, err := readOwnedRouteFile(what, path)
	if errors.Is(err, errRouteFileMissing) {
		res.ConfigMissing = true
		return res
	}
	if err != nil {
		res.Error = err
		return res
	}
	doc, err := parseOwnedRouteFile(what, cfgfmt.FormatJSON, path, raw)
	if err != nil {
		res.Error = err
		return res
	}
	model, ok := getTable(doc, cfgfmt.Path{"model"})
	if !ok {
		res.Error = credfile.SafeErrorf("%s: %s has no model.baseUrl to route", what, path)
		return res
	}
	prior, _, err := routeStringAt(what, path, doc, qwenBaseURLPath)
	if err != nil {
		res.Error = err
		return res
	}
	if prior == "" {
		res.Error = credfile.SafeErrorf("%s: %s has no model.baseUrl to route", what, path)
		return res
	}

	switch {
	case prior == want, IsObserverBaseURL(prior):
		// This proxy, or another local observer install (maybe a different
		// port): leave it.
		res.PriorBaseURL, res.AlreadySet, res.BaseURL = prior, true, prior
		return res
	case prior != qwenDefaultBaseURL:
		// The custom host is not quoted: it was read from a file that may
		// hold credentials beside it.
		res.Error = credfile.SafeErrorf(
			"%s: model.baseUrl in %s is a custom host, not the known default %q; refusing to overwrite",
			what, path, qwenDefaultBaseURL,
		)
		return res
	}
	res.PriorBaseURL = qwenDefaultBaseURL

	if r.opts.DryRun {
		res.Added = true
		return res
	}
	if err := doc.Set(qwenBaseURLPath, want); err != nil {
		res.Error = routeEditError(what, path, qwenBaseURLPath, err)
		return res
	}
	// Make the rewritten model.baseUrl resolvable: retarget every openai-lane
	// provider on the known default host to the proxy URL (keeps id + envKey).
	// If none matched (e.g. an empty modelProviders map), add a matching
	// entry for the selected model so it still resolves against the proxy.
	matched, err := retargetQwenOpenAIProviders(doc, qwenDefaultBaseURL, want)
	if err == nil && matched == 0 {
		err = ensureQwenProxyProvider(doc, model, want)
	}
	if err != nil {
		res.Error = routeEditError(what, path, cfgfmt.Path{"modelProviders", "openai"}, err)
		return res
	}
	if err := commitRouteDoc(what, path, doc); err != nil {
		res.Error = err
		return res
	}
	res.Added = true
	return res
}

// errQwenProviderShape is returned when modelProviders (or its openai lane)
// holds a value of a shape the writer does not own; nothing is written.
var errQwenProviderShape = fmt.Errorf("modelProviders shape: %w", cfgfmt.ErrTypeMismatch)

// qwenProviderListPath locates the openai-lane provider list in either live
// schema shape: the array form (modelProviders.openai = [ {...}, ... ], the
// operator's live build) or the newer object form (modelProviders.openai =
// {protocol, models: [...]}). found=false means no openai lane exists.
func qwenProviderListPath(doc cfgfmt.Doc) (path cfgfmt.Path, list []any, found bool, err error) {
	mp, mpFound, gerr := doc.Get(cfgfmt.Path{"modelProviders"})
	if gerr != nil || !mpFound {
		return nil, nil, false, nil //nolint:nilerr // absent modelProviders: no lane
	}
	m, ok := mp.(map[string]any)
	if !ok {
		return nil, nil, false, errQwenProviderShape
	}
	lane, present := m["openai"]
	if !present {
		return nil, nil, false, nil
	}
	switch v := lane.(type) {
	case []any:
		return cfgfmt.Path{"modelProviders", "openai"}, v, true, nil
	case map[string]any:
		models, has := v["models"]
		if !has {
			return cfgfmt.Path{"modelProviders", "openai", "models"}, nil, true, nil
		}
		list, ok := models.([]any)
		if !ok {
			return nil, nil, false, errQwenProviderShape
		}
		return cfgfmt.Path{"modelProviders", "openai", "models"}, list, true, nil
	default:
		return nil, nil, false, errQwenProviderShape
	}
}

// retargetQwenOpenAIProviders rewrites the baseUrl of every openai-lane
// provider entry whose baseUrl currently equals from -> to, leaving each
// entry's id, name, envKey, and any unknown fields untouched, and writes the
// list back only when it changed. It returns the number of entries changed.
// Providers on any other host are not touched.
func retargetQwenOpenAIProviders(doc cfgfmt.Doc, from, to string) (int, error) {
	path, list, found, err := qwenProviderListPath(doc)
	if err != nil || !found {
		return 0, err
	}
	changed := 0
	out := make([]any, len(list))
	for i, e := range list {
		out[i] = e
		entry, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if b, _ := entry["baseUrl"].(string); strings.TrimSpace(b) == from {
			c := make(map[string]any, len(entry))
			for k, v := range entry {
				c[k] = v
			}
			c["baseUrl"] = to
			out[i] = c
			changed++
		}
	}
	if changed == 0 {
		return 0, nil
	}
	return changed, doc.Set(path, out)
}

// ensureQwenProxyProvider appends a minimal openai-lane provider entry
// pointing at the proxy URL for the currently-selected model, so that a
// config with no openai-default provider (e.g. an empty modelProviders map)
// still resolves model.baseUrl. The entry's id mirrors model.name (how Qwen
// Code matches a provider to the active model); envKey defaults to
// OPENAI_API_KEY. It creates the modelProviders object / openai array as
// needed and keeps the existing schema shape (array vs {models:[]}); a
// modelProviders value of any other shape is refused (errQwenProviderShape).
func ensureQwenProxyProvider(doc cfgfmt.Doc, model map[string]any, proxyURL string) error {
	id, _ := model["name"].(string)
	id = strings.TrimSpace(id)
	if id == "" {
		id = "observer-proxy"
	}
	entry := map[string]any{
		"id":      id,
		"name":    id,
		"baseUrl": proxyURL,
		"envKey":  "OPENAI_API_KEY",
	}
	path, list, found, err := qwenProviderListPath(doc)
	if err != nil {
		return err
	}
	if !found {
		// Absent openai lane: seed the array form the operator's build uses.
		return doc.Set(cfgfmt.Path{"modelProviders", "openai"}, []any{entry})
	}
	return doc.Set(path, append(append([]any(nil), list...), entry))
}
