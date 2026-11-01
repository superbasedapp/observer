package seciac

import (
	"path"
	"strings"
)

// PathClass is one IaC path class of the post_write trigger (lane
// GATES-SEC decision 4): an agent write to a matching path queues a scan;
// any other write queues nothing.
type PathClass struct {
	Class string
	Match func(rel string) bool
}

func base(rel string) string { return path.Base(rel) }

func underAny(rel string, dirs ...string) bool {
	for _, el := range strings.Split(path.Dir(rel), "/") {
		for _, d := range dirs {
			if strings.EqualFold(el, d) {
				return true
			}
		}
	}
	return false
}

func yamlFile(rel string) bool {
	return strings.HasSuffix(rel, ".yaml") || strings.HasSuffix(rel, ".yml")
}

// pathClasses is the table, walked top-down; the first match names the
// class (forward-slash, project-relative paths).
var pathClasses = []PathClass{
	{"dockerfile", func(rel string) bool {
		b := base(rel)
		return b == "Dockerfile" || strings.HasPrefix(b, "Dockerfile.") || strings.HasSuffix(b, ".dockerfile") || b == "Containerfile"
	}},
	{"terraform", func(rel string) bool {
		return strings.HasSuffix(rel, ".tf") || strings.HasSuffix(rel, ".tf.json") || strings.HasSuffix(rel, ".tfvars")
	}},
	{"helm", func(rel string) bool {
		b := base(rel)
		return b == "Chart.yaml" || (yamlFile(rel) && (b == "values.yaml" || underAny(rel, "templates") && underAny(rel, "charts", "chart", "helm")))
	}},
	{"cloudformation", func(rel string) bool {
		b := strings.ToLower(base(rel))
		return strings.HasSuffix(b, ".template") || strings.Contains(b, ".cfn.") || strings.Contains(b, "cloudformation")
	}},
	{"kubernetes", func(rel string) bool {
		return yamlFile(rel) && underAny(rel, "k8s", "kubernetes", "manifests", "kustomize", "deploy", "deployment", "deployments")
	}},
}

// ClassOf returns the IaC class of a project-relative path, "" when none.
func ClassOf(rel string) string {
	rel = strings.TrimPrefix(path.Clean(strings.ReplaceAll(rel, `\`, "/")), "./")
	for _, c := range pathClasses {
		if c.Match(rel) {
			return c.Class
		}
	}
	return ""
}

// PathClassNames lists the classes in table order.
func PathClassNames() []string {
	out := make([]string, 0, len(pathClasses))
	for _, c := range pathClasses {
		out = append(out, c.Class)
	}
	return out
}

// IaCPaths keeps the paths of an agent's writes that are IaC files, in
// order, without duplicates.
func IaCPaths(rels []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rels {
		if ClassOf(r) != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// RepoConfigPresent returns the engine's repository-local config files
// found among a project's top-level names (the run ignores them unless
// allowed, and says so in a note).
func RepoConfigPresent(e Engine, names []string) []string {
	var out []string
	for _, n := range names {
		for _, c := range e.RepoConfigs {
			if n == c {
				out = append(out, n)
			}
		}
	}
	return out
}
