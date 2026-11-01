package proxyroute

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// lane.go: the third-party-provider LANE writers (lane P1, operator ruling
// 2026-10-18 "qwen-code and kimi-code: build lane writers now").
//
// The fixed writers (kimicode.go, qwencode.go) route a tool only while it
// talks to the fixed OpenAI upstream, and refuse a tool whose provider is a
// third-party OpenAI-compatible host (Qwen Code on OpenRouter, a Kimi Code
// custom provider). A lane writer routes exactly that case without changing
// where the traffic ends up: it rewrites the provider's base URL to
//
//	http://127.0.0.1:<port>/up/<lane id>/<the provider's own path>
//
// and the proxy's `/up/<id>/` lane forwards to the host root the tool used
// before (a node-local ROUTE LANE, internal/proxy/routelanes.go). The lane id
// and its upstream are recorded in route provenance with the base URL the
// write replaced, so the daemon re-installs the lane at every start before it
// accepts a request, and removing the route puts the original host back.
//
// Only the managed daemon's route maintenance calls these writers, and only
// for a registry row that declares the capability (ProxyRoute.ForeignLane).
// Like the fixed writers they change only the base-URL keys: an api key, an
// envKey or a key-bearing env var is never read into a message, copied or
// moved, the file is edited in place through cfgfmt with no re-serialization,
// no backup copy, the mode kept, and no error quotes the file.
//
// LIVE-VERIFIED 2026-10-18 (RETEST5 F3, demo node 1): a qwen-code prompt
// through the route-openrouter-ai lane landed 2 api_turns rows (OpenRouter
// gen- request ids) and `kimi -p` through the route-inference-baseten-co lane
// landed 1 (a Baseten request id), so ForeignProviderLane.LiveVerified is
// true on both rows. api_turns has no lane column (T-904), so the lane name
// itself is read from the config URL and the proxy's lane set, not the row.

// RouteLanePrefix starts every route lane id. It must equal
// internal/proxy.RouteLanePrefix (held by a test in cmd/observer, which
// links both packages).
const RouteLanePrefix = "route-"

// laneTarget splits a third-party provider base URL into the route lane id,
// the lane's upstream host root and the provider's own base path. ok is false
// for anything a lane must not carry: not https, no host, a user-info part
// (a credential in the URL), a query or fragment (which could carry a key),
// or an Observer URL.
func laneTarget(prior string) (id, root, basePath string, ok bool) {
	prior = strings.TrimSpace(prior)
	if prior == "" || IsObserverBaseURL(prior) {
		return "", "", "", false
	}
	u, err := url.Parse(prior)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", "", "", false
	}
	host := strings.ToLower(u.Host)
	var b strings.Builder
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == ':', r == '-':
			b.WriteByte('-')
		default:
			return "", "", "", false
		}
	}
	return RouteLanePrefix + b.String(), "https://" + host, strings.TrimRight(u.EscapedPath(), "/"), true
}

// laneProxyURL is the base URL a lane route writes.
func laneProxyURL(port int, id, basePath string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/up/%s%s", port, id, basePath)
}

// RegisterKimiCodeLane routes Kimi Code's ACTIVE provider through a route
// lane: default_model names a [models] alias, whose provider names a
// [providers] table; when that provider is OpenAI-compatible (type "openai")
// and its base_url is a third-party https host, base_url is rewritten to the
// lane URL. Refusals: no active provider, a provider of another type, no
// base_url (the implicit host is not grounded), or a base_url a lane must not
// carry. An active provider already on an Observer URL is AlreadySet.
func (r *Registrar) RegisterKimiCodeLane() RegistrationResult {
	res := r.writeKimiCodeLane()
	return r.note(res, res.BaseURL)
}

func (r *Registrar) writeKimiCodeLane() RegistrationResult {
	const what = "proxyroute.kimicode.lane"
	path, perr := r.kimiCodeConfigPath(what)
	res := RegistrationResult{Tool: "kimi-code", ConfigPath: path, DryRun: r.opts.DryRun}
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
	doc, err := parseOwnedRouteFile(what, cfgfmt.FormatTOML, path, raw)
	if err != nil {
		res.Error = err
		return res
	}
	key, ok := kimiActiveProviderKey(doc)
	if !ok {
		res.Error = credfile.SafeErrorf("%s: %s selects no OpenAI-compatible provider to route", what, path)
		return res
	}
	return r.rewriteLaneKey(what, path, doc, key, res, nil)
}

// kimiActiveProviderKey resolves the base_url key of Kimi Code's active
// provider: default_model -> models.<alias>.provider -> providers.<name>,
// accepted only when that provider's type is "openai".
func kimiActiveProviderKey(doc cfgfmt.Doc) (cfgfmt.Path, bool) {
	alias := docString(doc, cfgfmt.Path{"default_model"})
	if alias == "" {
		return nil, false
	}
	provider := docString(doc, cfgfmt.Path{"models", alias, "provider"})
	if provider == "" {
		return nil, false
	}
	if docString(doc, cfgfmt.Path{"providers", provider, "type"}) != "openai" {
		return nil, false
	}
	return cfgfmt.Path{"providers", provider, "base_url"}, true
}

// docString reads a trimmed string at key ("" when absent or not a string).
func docString(doc cfgfmt.Doc, key cfgfmt.Path) string {
	v, found, err := doc.Get(key)
	if err != nil || !found {
		return ""
	}
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// RegisterQwenCodeLane routes Qwen Code's model.baseUrl at a third-party
// https host through a route lane, and retargets every openai-lane
// modelProviders entry on that same host to the lane URL (keeping each
// entry's id and envKey), because Qwen Code matches the active model by
// (id, baseUrl). Refusals: no model.baseUrl, the known default host (the
// fixed writer's case), a base URL a lane must not carry, or openai-lane
// entries none of which sits on that host (the active model then resolves
// to a provider elsewhere, and the rewrite would not route it).
func (r *Registrar) RegisterQwenCodeLane() RegistrationResult {
	res := r.writeQwenCodeLane()
	return r.note(res, res.BaseURL)
}

func (r *Registrar) writeQwenCodeLane() RegistrationResult {
	const what = "proxyroute.qwencode.lane"
	path, perr := r.qwenConfigPath(what)
	res := RegistrationResult{Tool: "qwen-code", ConfigPath: path, DryRun: r.opts.DryRun}
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
	prior := docString(doc, qwenBaseURLPath)
	if prior == qwenDefaultBaseURL {
		res.Error = credfile.SafeErrorf("%s: model.baseUrl in %s is the known default host; the fixed route covers it", what, path)
		return res
	}
	if prior != "" && !IsObserverBaseURL(prior) {
		_, list, found, lerr := qwenProviderListPath(doc)
		if lerr != nil {
			res.Error = routeEditError(what, path, cfgfmt.Path{"modelProviders", "openai"}, lerr)
			return res
		}
		if found && len(list) > 0 && qwenEntriesOn(list, prior) == 0 {
			res.Error = credfile.SafeErrorf("%s: no modelProviders openai entry in %s is on the model.baseUrl host, so the active model resolves elsewhere", what, path)
			return res
		}
	}
	return r.rewriteLaneKey(what, path, doc, qwenBaseURLPath, res, func(doc cfgfmt.Doc, from, to string) error {
		_, err := retargetQwenOpenAIProviders(doc, from, to)
		return err
	})
}

// qwenEntriesOn counts the openai-lane provider entries whose baseUrl is base.
func qwenEntriesOn(list []any, base string) int {
	n := 0
	for _, e := range list {
		entry, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if b, _ := entry["baseUrl"].(string); strings.TrimSpace(b) == base {
			n++
		}
	}
	return n
}

// rewriteLaneKey is the shared lane rewrite: key must hold a third-party
// https base URL; it becomes the lane URL (also applies extra, which edits
// the rest of the document from the old value to the new one). An Observer
// URL already there is AlreadySet. res carries Tool / ConfigPath / DryRun.
func (r *Registrar) rewriteLaneKey(what, path string, doc cfgfmt.Doc, key cfgfmt.Path, res RegistrationResult, extra func(doc cfgfmt.Doc, from, to string) error) RegistrationResult {
	prior, present, err := routeStringAt(what, path, doc, key)
	if err != nil {
		res.Error = err
		return res
	}
	res.RouteKey = []string(key)
	if present && IsObserverBaseURL(prior) {
		res.AlreadySet, res.BaseURL = true, prior
		return res
	}
	if !present || prior == "" {
		res.Error = credfile.SafeErrorf("%s: %s in %s is not set, and its default host is not grounded; nothing was written", what, key, path)
		return res
	}
	id, root, basePath, ok := laneTarget(prior)
	if !ok {
		// The value is never quoted: it was read from a file that may hold
		// credentials beside it.
		res.Error = credfile.SafeErrorf("%s: %s in %s is not an https host a proxy lane can carry; nothing was written", what, key, path)
		return res
	}
	want := laneProxyURL(r.opts.ProxyPort, id, basePath)
	res.BaseURL, res.PriorBaseURL, res.LaneID, res.LaneRoot = want, prior, id, root
	if r.opts.DryRun {
		res.Added = true
		return res
	}
	if err := doc.Set(key, want); err != nil {
		res.Error = routeEditError(what, path, key, err)
		return res
	}
	if extra != nil {
		if err := extra(doc, prior, want); err != nil {
			res.Error = routeEditError(what, path, key, err)
			return res
		}
	}
	if err := commitRouteDoc(what, path, doc); err != nil {
		res.Error = err
		return res
	}
	res.Added = true
	return res
}

// readKimiRouteFor reads a recorded Kimi Code route: at the key a lane route
// recorded, else at the fixed [providers.openai].base_url.
func readKimiRouteFor(path string, rec *routeprov.Record) (string, bool, error) {
	if rec != nil && len(rec.RouteKey) > 0 {
		return readRouteKeyAt("proxyroute.readKimiRouteFor", cfgfmt.FormatTOML, path, cfgfmt.Path(rec.RouteKey))
	}
	return readKimiRouteAt(path)
}

// removeKimiRouteFor undoes a recorded Kimi Code route: a lane route puts the
// provider's original base_url back (it rewrote one); the fixed route deletes
// the key it added.
func removeKimiRouteFor(path string, rec routeprov.Record) error {
	if len(rec.RouteKey) == 0 {
		return removeKimiRouteAt(path, rec.Value, rec.PriorProvider)
	}
	key := cfgfmt.Path(rec.RouteKey)
	return editRouteFile("proxyroute.removeKimiRouteFor", cfgfmt.FormatTOML, path, key, rec.Value, func(doc cfgfmt.Doc) error {
		if rec.PriorBaseURL == "" {
			_, err := doc.Delete(key)
			return err
		}
		return doc.Set(key, rec.PriorBaseURL)
	})
}

// removeQwenRouteFor undoes a recorded Qwen Code route: model.baseUrl and
// every openai-lane entry still on the route URL go back to the host the
// write replaced (the known default for the fixed route).
func removeQwenRouteFor(path string, rec routeprov.Record) error {
	restore := rec.PriorBaseURL
	if restore == "" {
		restore = qwenDefaultBaseURL
	}
	return removeQwenRouteTo(path, rec.Value, restore)
}
