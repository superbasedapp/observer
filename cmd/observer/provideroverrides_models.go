// provideroverrides_models.go: on a managed node, the pi-family launchers
// point the tool's BUILT-IN providers at their proxy lanes for the session
// (T-035, PROVIDER-SWITCH-1), so switching provider mid-session no longer
// leaves the proxy's prompt guard and budget admission.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// launcherManagedNode reports whether this node holds a managed (org)
// enrolment. A package variable so tests can stand in for the database.
var launcherManagedNode = resolveLauncherManagedNode

// resolveLauncherManagedNode is launcherManagedNode's real implementation.
// An unreadable database answers false: the launch then behaves as on an
// individual node, and the managed launch budget check (which opens the same
// database) reports the failure on its own path.
func resolveLauncherManagedNode(ctx context.Context, configPath string) bool {
	_, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return false
	}
	defer cleanup()
	managed, err := orgclient.NodeManaged(ctx, store.New(database)) // P-204: switched nodes too
	return err == nil && managed
}

// providerOverridesSpec describes one launcher's built-in provider table.
type providerOverridesSpec struct {
	tool      string // stderr label, e.g. "pi"
	path      string // absolute models.json path
	display   string // home-relative spelling for terminal text
	proxyRoot string // the proxy root URL, no suffix
	ownName   string // the launcher's own session provider ("observer")
	overrides []integration.ProviderOverride
}

// providerOverridesRoute is prepareProviderOverrides' plain result.
type providerOverridesRoute struct {
	routed    []string // built-in providers pointed at the proxy
	kept      []string // built-in providers with the operator's own entry, left as is
	uncovered []string // built-in providers no proxy path can carry
	custom    []string // the operator's own providers that do not point at a loopback proxy
	// restore removes the entries this launch wrote; nil when none.
	restore func() error
}

// providerOverrideAction is one row's outcome in providerOverrideRules.
type providerOverrideAction int

const (
	// providerOverrideWrite: write the base-URL override, remove it after.
	providerOverrideWrite providerOverrideAction = iota
	// providerOverrideKeep: the operator has their own entry for this
	// provider; never overwrite it.
	providerOverrideKeep
	// providerOverrideSkip: no proxy path can carry this provider.
	providerOverrideSkip
)

// providerOverrideState is the routing-relevant shape of one provider.
type providerOverrideState struct {
	covered bool
	// hasEntry: models.json already has an entry for the provider.
	hasEntry bool
	// sameAsOurs: that entry is exactly the override this launch would
	// write (a concurrent or interrupted launch left it).
	sameAsOurs bool
}

// providerOverrideRules is the ordered decision table, walked top-down; the
// first matching row wins (CLAUDE.md #5). One test case per row.
var providerOverrideRules = []struct {
	name   string
	match  func(providerOverrideState) bool
	action providerOverrideAction
}{
	{"no proxy path for this provider", func(s providerOverrideState) bool { return !s.covered }, providerOverrideSkip},
	{"an override this launcher writes is already there", func(s providerOverrideState) bool { return s.hasEntry && s.sameAsOurs }, providerOverrideWrite},
	{"the operator's own entry for this provider", func(s providerOverrideState) bool { return s.hasEntry }, providerOverrideKeep},
	{"point the provider at its proxy lane", func(providerOverrideState) bool { return true }, providerOverrideWrite},
}

// decideProviderOverride walks providerOverrideRules for s.
func decideProviderOverride(s providerOverrideState) providerOverrideAction {
	for _, r := range providerOverrideRules {
		if r.match(s) {
			return r.action
		}
	}
	return providerOverrideWrite // unreachable: the last row matches everything
}

// providerOverrideEntry is the models.json entry for one covered provider:
// a base URL only, so the tool keeps the provider's models and its own
// credential (no key is ever written).
func providerOverrideEntry(proxyRoot string, o integration.ProviderOverride) map[string]any {
	return map[string]any{"baseUrl": strings.TrimRight(proxyRoot, "/") + o.Path}
}

// prepareProviderOverrides writes a base-URL override for every covered
// built-in provider the operator has no entry for, preserving every other key
// of models.json, and returns a restore that removes exactly those entries
// again (compare-and-swap per entry: an edit during the session wins).
func prepareProviderOverrides(spec providerOverridesSpec) (providerOverridesRoute, error) {
	root, existed, err := readModelsJSON(spec.path, spec.tool, spec.display)
	if err != nil {
		return providerOverridesRoute{}, err
	}
	providers, _ := root["providers"].(map[string]any)
	builtin := map[string]bool{}
	var out providerOverridesRoute
	wrote := map[string]map[string]any{}
	for _, o := range spec.overrides {
		builtin[o.Provider] = true
		entry := providerOverrideEntry(spec.proxyRoot, o)
		current, has := providers[o.Provider]
		state := providerOverrideState{covered: o.Covered(), hasEntry: has, sameAsOurs: has && sameJSON(current, entry)}
		switch decideProviderOverride(state) {
		case providerOverrideSkip:
			out.uncovered = append(out.uncovered, o.Provider)
		case providerOverrideKeep:
			out.kept = append(out.kept, o.Provider)
		case providerOverrideWrite:
			wrote[o.Provider] = entry
			out.routed = append(out.routed, o.Provider)
		}
	}
	for name, raw := range providers {
		if builtin[name] || name == spec.ownName {
			continue
		}
		entry, _ := raw.(map[string]any)
		if base, _ := entry["baseUrl"].(string); !loopbackURL(base) {
			out.custom = append(out.custom, name)
		}
	}
	sort.Strings(out.custom)
	if len(wrote) == 0 {
		return out, nil
	}
	if providers == nil {
		providers = map[string]any{}
	}
	for name, entry := range wrote {
		providers[name] = entry
	}
	root["providers"] = providers
	if err := writeJSONFileAtomic(spec.path, root); err != nil {
		return providerOverridesRoute{}, newVisibleLauncherError(err, fmt.Sprintf(
			"observer %s: cannot write %s; check the directory's permissions, then relaunch", spec.tool, spec.display))
	}
	out.restore = func() error { return restoreProviderOverrides(spec.path, wrote, existed) }
	return out, nil
}

// notice is the one stderr line a managed launch prints ("" when there is
// nothing to say). It names providers, never URLs or keys.
func (r providerOverridesRoute) notice(tool string) string {
	var parts []string
	if len(r.routed) > 0 {
		parts = append(parts, fmt.Sprintf("%d built-in providers routed through the proxy for this session", len(r.routed)))
	}
	if len(r.kept) > 0 {
		parts = append(parts, "your own entries kept (not routed): "+strings.Join(r.kept, ", "))
	}
	if len(r.uncovered) > 0 {
		parts = append(parts, "no proxy route for: "+strings.Join(r.uncovered, ", "))
	}
	if len(r.custom) > 0 {
		parts = append(parts, "your custom providers are not routed: "+strings.Join(r.custom, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf("observer %s: managed node: %s. A turn sent to a provider that is not routed is flagged after send.", tool, strings.Join(parts, "; "))
}

// applyManagedProviderOverrides is the launchers' one entry point: on a
// managed node it writes the covered overrides and prints the notice; it
// returns the restore to defer (nil when nothing was written).
func applyManagedProviderOverrides(ctx context.Context, configPath string, spec providerOverridesSpec, stderr io.Writer) (func(), error) {
	if len(spec.overrides) == 0 || !launcherManagedNode(ctx, configPath) {
		return nil, nil
	}
	route, err := prepareProviderOverrides(spec)
	if err != nil {
		return nil, err
	}
	if n := route.notice(spec.tool); n != "" {
		fmt.Fprintln(stderr, n)
	}
	if route.restore == nil {
		return nil, nil
	}
	return func() {
		if rerr := route.restore(); rerr != nil {
			fmt.Fprintf(stderr, "observer %s: could not remove the session provider overrides from %s; remove the entries that point at the observer proxy by hand\n",
				spec.tool, spec.display)
		}
	}, nil
}

// restoreProviderOverrides removes each entry this launch wrote that is still
// exactly what was written. A file the launch created and that now holds
// nothing else is removed too.
func restoreProviderOverrides(path string, wrote map[string]map[string]any, existed bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	root := map[string]any{}
	if err := json.Unmarshal(data, &root); err != nil || root == nil {
		return fmt.Errorf("parse %s: not valid JSON, left as is", path)
	}
	providers, _ := root["providers"].(map[string]any)
	changed := false
	for name, entry := range wrote {
		if current, ok := providers[name]; ok && sameJSON(current, entry) {
			delete(providers, name)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if !existed && len(providers) == 0 && len(root) == 1 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		return nil
	}
	return writeJSONFileAtomic(path, root)
}

// loopbackURL reports whether raw is an http(s) URL on a loopback host.
func loopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
