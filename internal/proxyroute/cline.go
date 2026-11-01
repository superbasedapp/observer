package proxyroute

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// The Cline VS Code extension's route (surface-gap IDE-8, D9). Current
// builds keep their settings in a file-backed store shared by the extension,
// the CLI and Cline for JetBrains: ~/.cline/data/globalState.json (relocated
// by CLINE_DATA_DIR > CLINE_DIR). The provider each mode uses is
// actModeApiProvider / planModeApiProvider, and its endpoint is a
// per-provider member (openAiBaseUrl, anthropicBaseUrl, ...); a value there
// beats providers.json (cline/cline apps/vscode/src/sdk/cline-session-
// factory.ts resolveBaseUrl, fetched 2026-10-25). The old registry reason,
// "VS Code state.vscdb only, manual paste", described pre-SDK builds.
//
// The extension reads globalState.json once when it starts and writes its
// whole in-memory copy back on every state change (ClineFileStorage), so an
// edit made while Cline runs is overwritten by its next state write: the
// route takes effect at the extension's next start. A write made while it is
// closed is read in and then kept by every later write.
//
// The file is extension-managed state beside a separate secrets.json, but it
// is treated as credential-adjacent (D9): the writer follows the probe-writer
// discipline (probe_write.go): one member set through cfgfmt with
// re-serialization forbidden, no backup, mode kept, a symlinked layout
// refused, and no error quotes the file. It never reads or writes a key, and
// it never touches secrets.json or providers.json.

// clineGlobalStateArtifact is the agentconfig FileRow that owns the file's
// path and relocation rules.
const clineGlobalStateArtifact = "cline/global-state"

// clineProviderRoute is one Cline provider the proxy can carry: the
// globalState member that holds its endpoint and the proxy URL its client
// expects there.
type clineProviderRoute struct {
	field string
	want  func(port int) string
}

// clineProviderRoutes is the routable-provider table, keyed by the provider
// id Cline stores in actModeApiProvider / planModeApiProvider. Only providers
// whose default endpoint is a host the proxy forwards to are listed: the
// OpenAI-compatible provider (base URL with /v1, like the CLI's
// openai-compatible lane) and Anthropic (the SDK appends /v1/messages, so
// the bare proxy root, like ANTHROPIC_BASE_URL).
var clineProviderRoutes = map[string]clineProviderRoute{
	"openai":            {field: "openAiBaseUrl", want: openAICompatProxyURL},
	"openai-compatible": {field: "openAiBaseUrl", want: openAICompatProxyURL},
	"anthropic":         {field: "anthropicBaseUrl", want: claudeBaseURL},
}

// clineModeProviderKeys are the members naming the provider of each mode.
var clineModeProviderKeys = []string{"actModeApiProvider", "planModeApiProvider"}

// resolveClineGlobalStatePath is globalState.json under homeDir with
// getenv's CLINE_DATA_DIR / CLINE_DIR applied. getenv is the registrar's
// injected lookup (RegisterOptions.Getenv), never the process environment
// directly, so a pinned or isolated home is never relocated by the
// developer's shell; nil reads no variables. A relative CLINE_DATA_DIR or
// CLINE_DIR is an error, never the default file (FU-31: Cline itself reads
// the relative value against its own working directory).
func resolveClineGlobalStatePath(what, homeDir string, getenv func(string) string) (string, error) {
	return routeArtifactPath(what, clineGlobalStateArtifact, homeDir, getenv)
}

// RegisterCline points the Cline extension's active provider at the observer
// proxy by setting that provider's base-URL member in globalState.json.
//
// Guard semantics (the probe writers' rules, one row each in the test):
//   - globalState.json absent -> ConfigMissing (Cline never started here)
//   - no mode provider set    -> Error (nothing to route)
//   - a mode provider the proxy cannot carry, or Act and Plan on providers
//     whose endpoints are different members -> Error (a partial route would
//     leave one mode's traffic unrouted)
//   - base URL absent or empty -> set it (Added)
//   - base URL already a loopback/observer URL -> AlreadySet
//   - base URL points elsewhere -> Error (refuse to overwrite a foreign URL:
//     the provider's key belongs to that host)
func (r *Registrar) RegisterCline() RegistrationResult {
	res, want := r.writeCline()
	if errors.Is(res.Error, errClineStateMoved) {
		// A running Cline saved its state between the read and the rename:
		// read it again and redo the one-member edit on the new bytes, once.
		res, want = r.writeCline()
	}
	return r.note(res, want)
}

// errClineStateMoved marks a globalState.json that changed while the route
// write was in flight (audit finding 3): Cline rewrites the whole file when
// it saves its state, so renaming Observer's edit of the older bytes over it
// would drop Cline's change.
var errClineStateMoved = errors.New("globalState.json changed during the route write")

// clineBeforeRename runs just before the globalState.json precondition
// check; tests use it to stand in for a Cline that saves in that window.
var clineBeforeRename = func(string) {}

// clineStateUnchanged is the commit precondition: the file still holds the
// exact bytes the edit was made from (a content comparison, so an mtime
// that did not move on a fast write cannot hide a change).
func clineStateUnchanged(what, path string, raw []byte) func() error {
	return func() error {
		clineBeforeRename(path)
		now, err := os.ReadFile(path)
		if err != nil {
			return credfile.Withhold(what, path, err)
		}
		if !bytes.Equal(now, raw) {
			return fmt.Errorf("%s: %w; nothing was written", what, errClineStateMoved)
		}
		return nil
	}
}

// writeCline is RegisterCline without the provenance record. It returns the
// URL the route wants, for the provenance outcome.
func (r *Registrar) writeCline() (RegistrationResult, string) {
	const what = "proxyroute.cline"
	path, perr := resolveClineGlobalStatePath(what, r.opts.HomeDir, r.opts.Getenv)
	res := RegistrationResult{Tool: "cline", ConfigPath: path, DryRun: r.opts.DryRun}
	if perr != nil {
		res.Error = perr
		return res, ""
	}
	raw, err := readOwnedRouteFile(what, path)
	if err != nil {
		res.ConfigMissing = errors.Is(err, errRouteFileMissing)
		if !res.ConfigMissing {
			res.Error = err
		}
		return res, ""
	}
	doc, err := parseOwnedRouteFile(what, cfgfmt.FormatJSON, path, raw)
	if err != nil {
		res.Error = err
		return res, ""
	}
	route, err := clineActiveRoute(what, path, doc)
	if err != nil {
		res.Error = err
		return res, ""
	}
	key := cfgfmt.Path{route.field}
	want := route.want(r.opts.ProxyPort)
	res.BaseURL, res.RouteKey = want, []string{route.field}
	prior, present, err := routeStringAt(what, path, doc, key)
	if err != nil {
		res.Error = err
		return res, want
	}
	if present && prior != "" {
		if prior == want || IsObserverBaseURL(prior) {
			res.PriorBaseURL, res.BaseURL, res.AlreadySet = prior, prior, true
			return res, want
		}
		res.Error = foreignRouteError(what, path, key)
		return res, want
	}
	if r.opts.DryRun {
		res.Added = true
		return res, want
	}
	if err := doc.Set(key, want); err != nil {
		res.Error = routeEditError(what, path, key, err)
		return res, want
	}
	if err := writeFileKeepModeIf(path, doc.Bytes(), clineStateUnchanged(what, path, raw)); err != nil {
		if errors.Is(err, errClineStateMoved) {
			res.Error = err
		} else {
			res.Error = credfile.Withhold(what, path, fmt.Errorf("write: %w", err))
		}
		return res, want
	}
	res.Added = true
	return res, want
}

// clineActiveRoute resolves the one provider route both modes use. Provider
// ids are read only to look them up; none is quoted in an error.
func clineActiveRoute(what, path string, doc cfgfmt.Doc) (clineProviderRoute, error) {
	var routes []clineProviderRoute
	for _, k := range clineModeProviderKeys {
		id, present, err := routeStringAt(what, path, doc, cfgfmt.Path{k})
		if err != nil {
			return clineProviderRoute{}, err
		}
		if !present || id == "" {
			continue
		}
		route, ok := clineProviderRoutes[id]
		if !ok {
			return clineProviderRoute{}, credfile.SafeErrorf("%s: %s selects a provider the observer proxy cannot carry in %s (OpenAI Compatible and Anthropic can be routed); nothing was written", what, k, path)
		}
		routes = append(routes, route)
	}
	if len(routes) == 0 {
		return clineProviderRoute{}, credfile.SafeErrorf("%s: %s names no provider yet (finish Cline's provider setup first); nothing was written", what, path)
	}
	for _, rt := range routes[1:] {
		if rt.field != routes[0].field {
			return clineProviderRoute{}, credfile.SafeErrorf("%s: Act and Plan mode use providers with different endpoints in %s; Observer routes one, so nothing was written", what, path)
		}
	}
	return routes[0], nil
}

// readClineRouteFor reads the recorded Cline route member (Leave's reader).
func readClineRouteFor(path string, rec *routeprov.Record) (string, bool, error) {
	key, ok := clineRecordKey(rec)
	if !ok {
		return "", false, nil
	}
	return readRouteKeyAt("proxyroute.readClineRouteFor", cfgfmt.FormatJSON, path, key)
}

// removeClineRouteFor deletes the base-URL member RegisterCline set, when it
// still holds the recorded value (the writer only ever sets an absent or
// empty member, so removal is the undo).
func removeClineRouteFor(path string, rec routeprov.Record) error {
	key, ok := clineRecordKey(&rec)
	if !ok {
		return credfile.SafeErrorf("proxyroute.removeClineRouteFor: the record for %s names no Cline route member", path)
	}
	return editRouteFile("proxyroute.removeClineRouteFor", cfgfmt.FormatJSON, path, key, rec.Value, func(doc cfgfmt.Doc) error {
		_, err := doc.Delete(key)
		return err
	})
}

// moveClineRouteFor rewrites a recorded Cline route at another port.
func moveClineRouteFor(path string, rec routeprov.Record, to string) error {
	key, ok := clineRecordKey(&rec)
	if !ok {
		return credfile.SafeErrorf("proxyroute.moveClineRouteFor: the record for %s names no Cline route member", path)
	}
	return editRouteFile("proxyroute.moveClineRouteFor", cfgfmt.FormatJSON, path, key, rec.Value, func(doc cfgfmt.Doc) error {
		return doc.Set(key, to)
	})
}

// clineWant is the URL a recorded Cline route wants at port.
func clineWant(rec routeprov.Record, port int) (string, bool) {
	for _, rt := range clineProviderRoutes {
		if slices.Equal(rec.RouteKey, []string{rt.field}) {
			return rt.want(port), true
		}
	}
	return "", false
}

// clineRecordKey is the member a provenance record names, accepted only when
// it is one the writer owns.
func clineRecordKey(rec *routeprov.Record) (cfgfmt.Path, bool) {
	if rec == nil || len(rec.RouteKey) != 1 {
		return nil, false
	}
	for _, rt := range clineProviderRoutes {
		if rec.RouteKey[0] == rt.field {
			return cfgfmt.Path{rt.field}, true
		}
	}
	return nil, false
}
