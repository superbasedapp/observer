package depscan

import (
	"path"
	"sort"

	"github.com/BurntSushi/toml"
)

// Gap is one part of a project a run could not check: a dependency file an
// extractor failed on (a lockfile caught mid-write, a parse error), the
// unpinned or unchecked packages of one file, or a manifest with no
// lockfile. Any gap makes the run partial, never clean, and keeps its
// ecosystem out of Coverage.Scanned, so it closes no finding.
type Gap struct {
	Ecosystem string `json:"ecosystem"`
	// Path is the dependency file, relative to the project root, forward
	// slashes; "" when the engine named no file.
	Path   string `json:"path"`
	Reason string `json:"reason"`
	// Packages is how many packages the gap left unchecked (0 when unknown,
	// as for a file that failed to parse).
	Packages int `json:"packages,omitempty"`
}

// Finalize turns a response's raw facts into gaps: the packages a drop
// rule with a Gap column removed, the manifests with no lockfile and the
// files of each failed extractor. It sets each ecosystem's Gaps count and
// adds a not-scanned row for an ecosystem that has gaps but no result (a
// project whose only Python file is an unpinned requirements.txt is "not
// scanned", not "no packages"). Gaps come back sorted by ecosystem, path
// and reason. The drivers' shared result path calls it once, after online
// matching.
func Finalize(resp ChildResponse) (ChildResponse, []Gap) {
	type key struct{ eco, path, reason string }
	counts := map[key]int{}
	add := func(k key, n int) { counts[k] += n }
	for _, p := range resp.Packages {
		if r := dropRuleFor(p); r != nil && r.Gap != "" {
			add(key{p.Ecosystem, p.Path, r.Gap}, 1)
		}
	}
	for _, m := range resp.Unlocked {
		add(key{m.Ecosystem, m.Path, ReasonNoLockfile}, 0)
	}
	for _, x := range resp.Extractors {
		if x.OK {
			continue
		}
		if len(x.Files) == 0 {
			add(key{x.Ecosystem, "", ReasonExtractorFailed}, 0)
		}
		for _, f := range x.Files {
			add(key{x.Ecosystem, f, ReasonExtractorFailed}, 0)
		}
	}
	gaps := make([]Gap, 0, len(counts))
	for k, n := range counts {
		gaps = append(gaps, Gap{Ecosystem: k.eco, Path: k.path, Reason: k.reason, Packages: n})
	}
	sort.Slice(gaps, func(i, j int) bool {
		a, b := gaps[i], gaps[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Reason < b.Reason
	})
	out := resp
	out.Ecosystems = append([]EcoResult(nil), resp.Ecosystems...)
	at := map[string]int{}
	for i, e := range out.Ecosystems {
		at[e.Ecosystem] = i
	}
	for _, g := range gaps {
		if g.Ecosystem == "" {
			continue
		}
		i, ok := at[g.Ecosystem]
		if !ok {
			out.Ecosystems = append(out.Ecosystems, EcoResult{Ecosystem: g.Ecosystem, Outcome: EcoNotScanned, Reason: g.Reason})
			i = len(out.Ecosystems) - 1
			at[g.Ecosystem] = i
		}
		out.Ecosystems[i].Gaps++
	}
	sort.SliceStable(out.Ecosystems, func(i, j int) bool { return out.Ecosystems[i].Ecosystem < out.Ecosystems[j].Ecosystem })
	return out, gaps
}

// lockedManifest is one row of the manifest table: a manifest whose
// declared dependencies are version ranges, and the lockfiles that resolve
// them. A lockfile in the manifest's directory or any directory above it
// (up to the project root) counts: a Cargo or uv workspace keeps one
// lockfile at its root.
type lockedManifest struct {
	Name      string
	Ecosystem string
	Lockfiles []string // path.Match patterns over a directory entry's name
	Declares  func([]byte) bool
}

var lockedManifests = []lockedManifest{
	{Name: "Cargo.toml", Ecosystem: "crates.io", Lockfiles: []string{"Cargo.lock"}, Declares: cargoDeclares},
	{Name: "pyproject.toml", Ecosystem: "PyPI", Lockfiles: []string{
		"uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock", "pylock.toml", "pylock.*.toml", "requirements*.txt",
	}, Declares: pyprojectDeclares},
}

// ManifestFor returns the manifest row's ecosystem and lockfile patterns for
// a file name, ok false when the name is not a manifest the table knows.
func ManifestFor(name string) (eco string, lockfiles []string, ok bool) {
	for _, m := range lockedManifests {
		if m.Name == name {
			return m.Ecosystem, append([]string(nil), m.Lockfiles...), true
		}
	}
	return "", nil, false
}

// ManifestNames returns the manifest table's file names.
func ManifestNames() []string {
	out := make([]string, 0, len(lockedManifests))
	for _, m := range lockedManifests {
		out = append(out, m.Name)
	}
	return out
}

// ManifestDeclares reports whether a manifest's body declares at least one
// dependency (a manifest that only configures tools needs no lockfile). A
// body that does not parse is taken to declare some: unknown is never
// treated as nothing to check.
func ManifestDeclares(name string, body []byte) bool {
	for _, m := range lockedManifests {
		if m.Name == name {
			return m.Declares(body)
		}
	}
	return false
}

// IsLockfile reports whether a directory entry's name is one of the
// patterns.
func IsLockfile(name string, patterns []string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

func nonEmpty(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		return len(t) > 0
	case []any:
		return len(t) > 0
	case []map[string]any:
		return len(t) > 0
	}
	return v != nil
}

// cargoDeclares: [dependencies], [dev-dependencies], [build-dependencies],
// [workspace.dependencies] or any [target.*.*dependencies] table with an
// entry.
func cargoDeclares(body []byte) bool {
	var doc map[string]any
	if _, err := toml.Decode(string(body), &doc); err != nil {
		return true
	}
	tables := []string{"dependencies", "dev-dependencies", "build-dependencies"}
	for _, t := range tables {
		if nonEmpty(doc[t]) {
			return true
		}
	}
	if ws, ok := doc["workspace"].(map[string]any); ok && nonEmpty(ws["dependencies"]) {
		return true
	}
	if targets, ok := doc["target"].(map[string]any); ok {
		for _, tv := range targets {
			tm, ok := tv.(map[string]any)
			if !ok {
				continue
			}
			for _, t := range tables {
				if nonEmpty(tm[t]) {
					return true
				}
			}
		}
	}
	return false
}

// pyprojectDeclares: [project] dependencies or optional-dependencies,
// [dependency-groups], or a Poetry dependency table with an entry besides
// "python".
func pyprojectDeclares(body []byte) bool {
	var doc map[string]any
	if _, err := toml.Decode(string(body), &doc); err != nil {
		return true
	}
	if proj, ok := doc["project"].(map[string]any); ok {
		if nonEmpty(proj["dependencies"]) || nonEmpty(proj["optional-dependencies"]) {
			return true
		}
	}
	if nonEmpty(doc["dependency-groups"]) {
		return true
	}
	tool, _ := doc["tool"].(map[string]any)
	poetry, _ := tool["poetry"].(map[string]any)
	if deps, ok := poetry["dependencies"].(map[string]any); ok {
		for name := range deps {
			if name != "python" {
				return true
			}
		}
	}
	if nonEmpty(poetry["dev-dependencies"]) || nonEmpty(poetry["group"]) {
		return true
	}
	return false
}

// reasonWords are the plain words of each reason a run, an ecosystem or a
// gap carries, for the CLI and the dashboard.
var reasonWords = map[string]string{
	ReasonNoDatabase:       "no local database",
	ReasonMatchFailed:      "matching failed",
	ReasonSelfTestFailed:   "self-test failed",
	ReasonNoCanary:         "no self-test for this ecosystem",
	ReasonUnsupported:      "unsupported platform",
	ReasonNotCompiled:      "not in this build",
	ReasonNotInstalled:     "not installed",
	ReasonEngineFailed:     "engine failed",
	ReasonIsolationRefused: "isolation refused the run",
	ReasonDBNotAccepted:    "databases not downloaded: waiting for your one-time accept",
	ReasonExtractorFailed:  "could not be read",
	ReasonUnpinned:         "no exact version pinned",
	ReasonLockfileTooLarge: "lockfile too large to check local entries",
	ReasonNoLockfile:       "no lockfile",
}

// ReasonWords returns a reason's plain words, or the reason itself.
func ReasonWords(reason string) string {
	if w, ok := reasonWords[reason]; ok {
		return w
	}
	return reason
}
