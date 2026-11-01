package guard

import (
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// hookSwitchReadLimit bounds the settings file the R-162 rows read.
const hookSwitchReadLimit = 1 << 20

// hookSwitchesForPolicy projects internal/hookdisable's switch table (the
// one owner of which settings turn hooks off) onto the R-162 rows' path
// globs (T-910). A user-scope row gets its home-anchored glob plus the
// cross-flavor Windows fallback R-160 also carries, a project-scope row
// matches its file under any directory, and a managed row its absolute
// path on every OS, taken from its agentconfig FileRow (the one owner of
// the path, surface-gap CC-5). Only key switches project: an environment
// variable, a list entry or a deny-list hash is not a JSON boolean an edit
// could be judged on.
func hookSwitchesForPolicy() []policy.HookSwitch {
	var out []policy.HookSwitch
	for _, s := range hookdisable.Switches {
		if !s.KeySwitch() {
			continue
		}
		for _, g := range hookSwitchGlobs(s) {
			out = append(out, policy.HookSwitch{Glob: g, Key: s.Key, Off: s.Off, Desc: "hook switch " + s.ID})
		}
	}
	return out
}

// hookSwitchGlobs is the path globs one switch row's file has.
func hookSwitchGlobs(s hookdisable.Switch) []string {
	switch s.Scope {
	case hookdisable.ScopeUser:
		out := []string{"~/" + s.HomeRel, "?:/users/*/" + s.HomeRel}
		for _, goos := range slices.Sorted(maps.Keys(s.HomeRelOS)) {
			out = append(out, "~/"+s.HomeRelOS[goos], "?:/users/*/"+s.HomeRelOS[goos])
		}
		return out
	case hookdisable.ScopeProject:
		return []string{"**/" + s.ProjectRel}
	case hookdisable.ScopeManaged:
		var out []string
		for _, f := range agentconfig.Files() {
			if f.ID != s.ManagedFile {
				continue
			}
			for _, p := range f.Paths.All() {
				p = strings.ReplaceAll(p, `\`, "/")
				out = append(out, p)
				// FU-35: the drop-ins the tool merges into the file (Claude
				// Code's managed-settings.d/*.json) carry the same switch.
				if f.DropInDir != "" {
					out = append(out, path.Join(path.Dir(p), f.DropInDir, "*.json"))
				}
			}
		}
		sort.Strings(out)
		return slices.Compact(out)
	}
	return nil
}

// readHookSwitchFile is the R-162 rows' injected reader
// (policy.Config.ReadFile): the current content of a hook-bearing settings
// file, so an edit is judged on the whole file it produces. p is the
// engine's normalized forward-slash form; a path that is not absolute on
// this machine's flavor, a missing file and a file over the bound all read
// as unknown (ok=false).
func readHookSwitchFile(p string) ([]byte, bool) {
	native := filepath.FromSlash(p)
	if p == "" || !filepath.IsAbs(native) {
		return nil, false
	}
	f, err := os.Open(native)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, hookSwitchReadLimit+1))
	if err != nil || len(b) > hookSwitchReadLimit {
		return nil, false
	}
	return b, true
}
