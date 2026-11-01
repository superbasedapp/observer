// observerprovider_models.go — the session-scoped `observer` provider that
// the pi and prime-agent launchers put into the tool's models.json.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// observerProviderAPIKeyEnv is the env var NAME written as the provider's
// apiKey. The tool resolves it at runtime; no secret is ever written.
const observerProviderAPIKeyEnv = "OPENAI_API_KEY" //nolint:gosec // G101: env-var NAME, not a credential

// observerModelsProviderSpec describes one launcher's models.json provider.
type observerModelsProviderSpec struct {
	tool    string // stderr label, e.g. "pi"
	path    string // absolute models.json path
	display string // home-relative spelling for terminal text
	name    string // provider name, e.g. "observer"
	baseURL string // the proxy's OpenAI-compatible endpoint (…/v1)
	models  []any  // the provider's model list
	// hasCredential reports that the child will have a key for the provider:
	// OPENAI_API_KEY in its environment, or a forwarded --api-key.
	hasCredential bool
}

// observerModelsRoute is prepareObserverModelsProvider's plain result.
type observerModelsRoute struct {
	// routed is true when the provider is in place and the launcher should
	// select it (`--provider <name>`).
	routed bool
	// note is a one-line explanation to print before the tool starts (empty
	// when routed).
	note string
	// restore removes the provider this launch wrote, after the tool exits.
	// Nil when nothing was written.
	restore func() error
}

// observerModelsAction is one row's outcome in observerModelsRules.
type observerModelsAction int

const (
	// observerModelsWrite: write the session provider, select it, remove it
	// after the session.
	observerModelsWrite observerModelsAction = iota
	// observerModelsNoCredential: launch unrouted. Writing a provider whose
	// key cannot resolve would force a keyless launch that fails on its
	// first prompt (Sol A5-08).
	observerModelsNoCredential
	// observerModelsCollision: the operator has their OWN provider under the
	// same name. Never overwrite it; launch unrouted (Sol A5-08).
	observerModelsCollision
)

// observerModelsState is the routing-relevant shape of models.json plus the
// credential fact. No credential value is read.
type observerModelsState struct {
	hasCredential bool
	// foreignEntry is true when a provider with our name exists and is not
	// one an Observer launcher wrote.
	foreignEntry bool
}

// observerModelsRules is the ordered decision table, walked top-down; the
// first matching row wins (CLAUDE.md #5). One test case per row.
var observerModelsRules = []struct {
	name   string
	match  func(observerModelsState) bool
	action observerModelsAction
}{
	{"no credential for the provider", func(s observerModelsState) bool { return !s.hasCredential }, observerModelsNoCredential},
	{"the operator's own provider has our name", func(s observerModelsState) bool { return s.foreignEntry }, observerModelsCollision},
	{"route through the session provider", func(observerModelsState) bool { return true }, observerModelsWrite},
}

// decideObserverModels walks observerModelsRules for s.
func decideObserverModels(s observerModelsState) observerModelsAction {
	for _, r := range observerModelsRules {
		if r.match(s) {
			return r.action
		}
	}
	return observerModelsWrite // unreachable: the last row matches everything
}

// observerProviderEntry is the provider object the launchers write.
func observerProviderEntry(baseURL string, models []any) map[string]any {
	return map[string]any{
		"baseUrl": baseURL,
		"api":     "openai-completions",
		"apiKey":  observerProviderAPIKeyEnv, // env var NAME, resolved by the tool; no secret on disk
		"models":  models,
	}
}

// observerOwnedProviderEntry reports whether entry has the shape an Observer
// launcher writes: the openai-completions API, the OPENAI_API_KEY env-var
// NAME as its key, and a loopback …/v1 base URL. Anything else under the same
// name is the operator's own provider and must not be overwritten.
func observerOwnedProviderEntry(entry map[string]any) bool {
	if entry["api"] != "openai-completions" || entry["apiKey"] != observerProviderAPIKeyEnv {
		return false
	}
	raw, _ := entry["baseUrl"].(string)
	u, err := url.Parse(raw)
	if err != nil || strings.TrimRight(u.Path, "/") != "/v1" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// launcherHasOpenAIKey reports whether a pi-family child launched with args
// will have a key for the observer provider.
func launcherHasOpenAIKey(args []string) bool {
	if strings.TrimSpace(os.Getenv(observerProviderAPIKeyEnv)) != "" {
		return true
	}
	for i, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "--api-key=") && len(a) > len("--api-key=") {
			return true
		}
		if a == "--api-key" && i+1 < len(args) && args[i+1] != "" {
			return true
		}
	}
	return false
}

// prepareObserverModelsProvider applies observerModelsRules to spec.path.
// When it routes, it writes ONLY the `spec.name` provider (every other key is
// preserved) and returns a restore that removes it again after the session.
// It never writes a credential.
func prepareObserverModelsProvider(spec observerModelsProviderSpec) (observerModelsRoute, error) {
	root, existed, err := readModelsJSON(spec.path, spec.tool, spec.display)
	if err != nil {
		return observerModelsRoute{}, err
	}
	providers, _ := root["providers"].(map[string]any)
	existing, hasEntry := providers[spec.name].(map[string]any)

	state := observerModelsState{
		hasCredential: spec.hasCredential,
		foreignEntry:  hasEntry && !observerOwnedProviderEntry(existing),
	}
	if _, isOther := providers[spec.name]; isOther && !hasEntry {
		state.foreignEntry = true // a non-object value under our name is not ours either
	}
	switch decideObserverModels(state) {
	case observerModelsNoCredential:
		return observerModelsRoute{note: fmt.Sprintf("observer %s: NOT routing through the observer proxy: %s is not set "+
			"and no --api-key was given, so %s starts with its own provider (sessions are still captured). Set %s (or "+
			"pass `-- --api-key <key>`) to route through Observer.", spec.tool, observerProviderAPIKeyEnv, spec.tool,
			observerProviderAPIKeyEnv)}, nil
	case observerModelsCollision:
		return observerModelsRoute{note: fmt.Sprintf("observer %s: NOT routing through the observer proxy: %s already "+
			"has your own provider named %q, which Observer will not overwrite, so %s starts with its own provider "+
			"selection (sessions are still captured). Rename that provider to route through Observer.",
			spec.tool, spec.display, spec.name, spec.tool)}, nil
	}

	if providers == nil {
		providers = map[string]any{}
	}
	wrote := observerProviderEntry(spec.baseURL, spec.models)
	providers[spec.name] = wrote
	root["providers"] = providers
	if err := writeJSONFileAtomic(spec.path, root); err != nil {
		return observerModelsRoute{}, newVisibleLauncherError(err, fmt.Sprintf(
			"observer %s: cannot write %s; check the directory's permissions, then relaunch", spec.tool, spec.display))
	}
	return observerModelsRoute{
		routed:  true,
		restore: func() error { return restoreObserverModelsProvider(spec.path, spec.name, wrote, existed) },
	}, nil
}

// readModelsJSON reads a pi-family models.json: root is the decoded object
// (empty when the file is missing or blank) and existed says the file was
// there. A malformed or unreadable file is a visible launcher error.
func readModelsJSON(path, tool, display string) (root map[string]any, existed bool, err error) {
	root = map[string]any{}
	data, rerr := os.ReadFile(path)
	switch {
	case rerr == nil && len(bytes.TrimSpace(data)) > 0:
		if jerr := json.Unmarshal(data, &root); jerr != nil || root == nil {
			if jerr == nil {
				jerr = errors.New("top level is null")
			}
			return nil, false, newVisibleLauncherError(fmt.Errorf("parse %s: %w", path, jerr), fmt.Sprintf(
				"observer %s: %s is not valid JSON; fix it or move it aside, then relaunch", tool, display))
		}
		return root, true, nil
	case rerr == nil:
		return root, true, nil
	case !errors.Is(rerr, os.ErrNotExist):
		return nil, false, newVisibleLauncherError(fmt.Errorf("read %s: %w", path, rerr), fmt.Sprintf(
			"observer %s: cannot read %s; check its permissions, then relaunch", tool, display))
	}
	return root, false, nil
}

// restoreObserverModelsProvider removes the provider this launch wrote, as a
// compare-and-swap: only when the entry is still exactly what was written
// (an edit made during the session wins). A file the launch created and that
// now holds nothing else is removed too, so a launch leaves no residue.
func restoreObserverModelsProvider(path, name string, wrote map[string]any, existed bool) error {
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
	current, ok := providers[name]
	if !ok || !sameJSON(current, wrote) {
		return nil // removed or changed during the session: theirs wins
	}
	delete(providers, name)
	if !existed && len(providers) == 0 && len(root) == 1 {
		if err := testwriteguard.Check("remove", path); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		return nil
	}
	return writeJSONFileAtomic(path, root)
}

// sameJSON reports whether a and b encode to the same JSON.
func sameJSON(a, b any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// writeJSONFileAtomic writes v to path as indented JSON (0600, parent 0700)
// through a temp file and rename, so a crash cannot truncate the file.
func writeJSONFileAtomic(path string, v any) error {
	if err := testwriteguard.Check("write", path); err != nil {
		return err
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s: %w", tmp, err)
	}
	return nil
}
