package proxyroute

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/credfile"
)

// Leave's readers and removers for the probe-lane routes (T-156a): kimi-code
// (~/.kimi-code/config.toml), qwen-code (~/.qwen/settings.json) and crush
// (crush.json). Until these existed Leave recorded the routes enrolment wrote
// for these three tools but named them for manual removal (D-173).
//
// Each remover undoes exactly what its tool's own writer (kimicode.go,
// qwencode.go, crush.go) changed, and nothing else:
//
//   - kimi-code / crush: the writer only ever ADDS base_url under the openai
//     provider (it refuses when one is set), so the remover deletes that one
//     key.
//   - qwen-code: the writer rewrites model.baseUrl from the known default and
//     retargets the openai-lane modelProviders entries on that default to the
//     proxy URL, so the remover puts model.baseUrl back to the default and
//     every openai-lane entry still on the recorded proxy URL back to the
//     default. An entry the writer had to synthesize (no openai-default
//     entry existed) is not deleted: it cannot be told apart from one the
//     developer added, so it is pointed back at the default host, which is
//     what the selected model resolved to before the route.
//
// All three files can hold plaintext provider keys, so they follow the
// D-268 / D-270 credential-file rules: the edit goes through the comment-
// and order-preserving cfgfmt engine (no re-serialization: an edit it cannot
// make in place is refused), only the route keys change, the file keeps its
// mode, no backup is left and no error quotes the file (credfile.Withhold).
// Since T-657 the writers follow the same discipline (probe_write.go), and
// both refuse a symlinked or non-regular config path.
// The remover refuses (and Leave keeps the route) when the value is no longer
// the one enrolment wrote.

// probeRouteKeys are the cfgfmt paths of a tool's base-URL key.
var (
	kimiBaseURLPath  = cfgfmt.Path{"providers", "openai", "base_url"}
	crushBaseURLPath = cfgfmt.Path{"providers", "openai", "base_url"}
	qwenBaseURLPath  = cfgfmt.Path{"model", "baseUrl"}
)

// readRouteKeyAt reads one string key from a config file through cfgfmt. A
// missing file is "not set", never an error.
func readRouteKeyAt(what string, f cfgfmt.Format, path string, key cfgfmt.Path) (string, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, credfile.Withhold(what, path, err)
	}
	doc, err := cfgfmt.Parse(f, raw)
	if err != nil {
		return "", false, credfile.Withhold(what, path, err)
	}
	v, _, err := doc.Get(key)
	if err != nil {
		// The path crosses a non-table value: nothing of ours is there.
		return "", false, nil //nolint:nilerr // a foreign shape is "not set", not a read failure
	}
	s, _ := v.(string)
	s = strings.TrimSpace(s)
	return s, s != "", nil
}

// editRouteFile parses path with f (refusing a re-serialization), checks the
// route key still holds value, runs edit and writes the result keeping the
// file's mode.
func editRouteFile(what string, f cfgfmt.Format, path string, key cfgfmt.Path, value string, edit func(doc cfgfmt.Doc) error) error {
	raw, err := readOwnedRouteFile(what, path)
	if errors.Is(err, errRouteFileMissing) {
		return credfile.SafeErrorf("%s: %s is gone", what, path)
	}
	if err != nil {
		return err
	}
	doc, err := cfgfmt.ParseWith(f, raw, cfgfmt.Options{ForbidReserialize: true})
	if err != nil {
		return credfile.Withhold(what, path, err)
	}
	cur, _, _ := doc.Get(key)
	if s, _ := cur.(string); strings.TrimSpace(s) != value {
		// Paths and key names only: the current value is not quoted, the
		// file may hold credentials beside it.
		return credfile.SafeErrorf("%s: %s in %s is no longer the value enrolment wrote", what, key, path)
	}
	if err := edit(doc); err != nil {
		return routeEditError(what, path, key, err)
	}
	return commitRouteDoc(what, path, doc)
}

// readKimiRouteAt reads [providers.openai].base_url from a kimi-code
// config.toml.
func readKimiRouteAt(path string) (string, bool, error) {
	return readRouteKeyAt("proxyroute.readKimiRouteAt", cfgfmt.FormatTOML, path, kimiBaseURLPath)
}

// removeKimiRouteAt deletes the base_url RegisterKimiCode added.
func removeKimiRouteAt(path, value, _ string) error {
	return editRouteFile("proxyroute.removeKimiRouteAt", cfgfmt.FormatTOML, path, kimiBaseURLPath, value, func(doc cfgfmt.Doc) error {
		_, err := doc.Delete(kimiBaseURLPath)
		return err
	})
}

// readCrushRouteAt reads providers.openai.base_url from crush.json.
func readCrushRouteAt(path string) (string, bool, error) {
	return readRouteKeyAt("proxyroute.readCrushRouteAt", cfgfmt.FormatJSON, path, crushBaseURLPath)
}

// removeCrushRouteAt deletes the base_url RegisterCrush added.
func removeCrushRouteAt(path, value, _ string) error {
	return editRouteFile("proxyroute.removeCrushRouteAt", cfgfmt.FormatJSON, path, crushBaseURLPath, value, func(doc cfgfmt.Doc) error {
		_, err := doc.Delete(crushBaseURLPath)
		return err
	})
}

// readQwenRouteAt reads model.baseUrl from Qwen Code's settings.json.
func readQwenRouteAt(path string) (string, bool, error) {
	return readRouteKeyAt("proxyroute.readQwenRouteAt", cfgfmt.FormatJSON, path, qwenBaseURLPath)
}

// removeQwenRouteAt puts model.baseUrl and every openai-lane modelProviders
// entry still on the proxy URL back to the known default host.
func removeQwenRouteAt(path, value, _ string) error {
	return removeQwenRouteTo(path, value, qwenDefaultBaseURL)
}

// removeQwenRouteTo puts model.baseUrl and every openai-lane modelProviders
// entry still on the route URL value back to restore.
func removeQwenRouteTo(path, value, restore string) error {
	return editRouteFile("proxyroute.removeQwenRouteAt", cfgfmt.FormatJSON, path, qwenBaseURLPath, value, func(doc cfgfmt.Doc) error {
		if err := doc.Set(qwenBaseURLPath, restore); err != nil {
			return err
		}
		return restoreQwenProviders(doc, value, restore)
	})
}

// restoreQwenProviders points every openai-lane modelProviders entry whose
// baseUrl is proxyURL back at restore, in either schema shape the
// writer handles (an array, or {models: [...]}). Only the list that changed
// is rewritten; every other key keeps its bytes.
func restoreQwenProviders(doc cfgfmt.Doc, proxyURL, restore string) error {
	for _, listPath := range []cfgfmt.Path{
		{"modelProviders", "openai"},
		{"modelProviders", "openai", "models"},
	} {
		v, found, err := doc.Get(listPath)
		if err != nil || !found {
			continue // the other schema shape
		}
		list, ok := v.([]any)
		if !ok {
			continue
		}
		changed := false
		out := make([]any, len(list))
		for i, e := range list {
			out[i] = e
			entry, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if b, _ := entry["baseUrl"].(string); strings.TrimSpace(b) == proxyURL {
				c := make(map[string]any, len(entry))
				for k, ev := range entry {
					c[k] = ev
				}
				c["baseUrl"] = restore
				out[i] = c
				changed = true
			}
		}
		if changed {
			if err := doc.Set(listPath, out); err != nil {
				return fmt.Errorf("modelProviders: %w", err)
			}
		}
	}
	return nil
}
