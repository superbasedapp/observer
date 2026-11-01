package opengrep

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
)

// MaxJSONCopyBytes caps the JSON copy read back (its results duplicate the
// SARIF's; the driver reads only its paths and errors).
const MaxJSONCopyBytes = 64 << 20

// Scanned is what the JSON copy says about the files of one run.
type Scanned struct {
	// Files are the project files the run scanned, relative to the project
	// root (forward slashes), sorted; the canary is not among them.
	Files []string
	// Partial are project files Opengrep reported an error for (a parse
	// error, a timeout on one file): they were not read in full, so they
	// never close a finding.
	Partial []string
	// Canary reports the canary file was among the scanned paths.
	Canary bool
}

// jsonCopy is the part of Opengrep's JSON output the driver reads.
type jsonCopy struct {
	Paths struct {
		Scanned []string `json:"scanned"`
	} `json:"paths"`
	Errors []struct {
		Path  string `json:"path"`
		Spans []struct {
			File string `json:"file"`
		} `json:"spans"`
	} `json:"errors"`
}

// ParseJSONCopy reads the JSON copy. A path is kept only when it lies
// under the project (it is relative, or absolute under root) and has no
// ".." element; the canary is recognised by its absolute path.
func ParseJSONCopy(b []byte, root, canary string) (Scanned, error) {
	var j jsonCopy
	if err := json.Unmarshal(b, &j); err != nil {
		return Scanned{}, fmt.Errorf("opengrep.ParseJSONCopy: %w", err)
	}
	var s Scanned
	files := map[string]bool{}
	for _, p := range j.Paths.Scanned {
		if samePath(p, canary) {
			s.Canary = true
			continue
		}
		if rel, ok := projectRel(p, root); ok {
			files[rel] = true
		}
	}
	partial := map[string]bool{}
	for _, e := range j.Errors {
		paths := []string{e.Path}
		for _, sp := range e.Spans {
			paths = append(paths, sp.File)
		}
		for _, p := range paths {
			if rel, ok := projectRel(p, root); ok && p != "" {
				partial[rel] = true
				delete(files, rel)
			}
		}
	}
	s.Files = sortedKeys(files)
	s.Partial = sortedKeys(partial)
	return s, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func slash(p string) string { return strings.ReplaceAll(p, `\`, "/") }

func samePath(a, b string) bool {
	return b != "" && path.Clean(slash(a)) == path.Clean(slash(b))
}

// projectRel returns p relative to root: p is relative to the working
// directory (the root), or absolute under it.
func projectRel(p, root string) (string, bool) {
	if p == "" {
		return "", false
	}
	q := path.Clean(slash(p))
	r := strings.TrimRight(slash(root), "/")
	switch {
	case strings.HasPrefix(q, r+"/"):
		q = strings.TrimPrefix(q, r+"/")
	case path.IsAbs(q) || (len(q) > 1 && q[1] == ':'):
		return "", false
	}
	q = strings.TrimPrefix(q, "./")
	if q == "." || q == ".." || strings.HasPrefix(q, "../") {
		return "", false
	}
	return q, true
}

// splitCanary removes the canary rule's results from a run and reports
// whether one of them was located in the canary file. A canary-rule
// result anywhere else (a project that calls the marker) is dropped and
// proves nothing.
func splitCanary(run sarif.Run, canaryRule, rulePrefix, canary string) (sarif.Run, bool) {
	out := run
	out.Results = nil
	hit := false
	for _, r := range run.Results {
		id := r.RuleID
		if id == "" && r.RuleIndex >= 0 && r.RuleIndex < len(run.Tool.Rules) {
			id = run.Tool.Rules[r.RuleIndex].ID
		}
		if rulePrefix != "" {
			id = strings.TrimPrefix(strings.TrimPrefix(id, rulePrefix), ".")
		}
		if id != canaryRule {
			out.Results = append(out.Results, r)
			continue
		}
		for _, l := range r.Locations {
			if samePath(strings.TrimPrefix(l.URI, "file://"), canary) {
				hit = true
			}
		}
	}
	return out, hit
}
