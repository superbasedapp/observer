package secciwf

import (
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// actions.go lists the remote actions and reusable workflows a workflow
// uses, the input of S-779 (an action whose version has a known advisory in
// OSV's GitHub Actions ecosystem). The rules here only extract: matching
// needs the OSV database and runs where the database is (the dependency
// scan child on a node), never in this package.

// VersionSource says where an ActionRef's Version came from.
type VersionSource string

// The VersionSource values.
const (
	// VersionFromRef: the ref after @ is a tag or branch, matched as written.
	VersionFromRef VersionSource = "ref"
	// VersionFromComment: the ref is a commit SHA and the line carries the
	// conventional trailing version comment (`@<sha> # v4.1.0`, written by
	// Renovate, Dependabot and pinact). The comment is not verified against
	// the SHA.
	VersionFromComment VersionSource = "comment"
	// VersionUnknown: the ref is a commit SHA with no version comment, so
	// the action cannot be matched without resolving the SHA (a gap, never
	// clean).
	VersionUnknown VersionSource = ""
)

// RefKind says what a `uses:` names.
type RefKind string

// The RefKind values.
const (
	RefStep             RefKind = "step"
	RefReusableWorkflow RefKind = "reusable_workflow"
)

// ActionRef is one remote action or reusable workflow a workflow uses.
// Local (./) and docker:// references are not listed: they are not
// packages of the GitHub Actions ecosystem.
type ActionRef struct {
	// Repo is owner/name, lowercased (GitHub names are case-insensitive and
	// OSV records name them in lower case).
	Repo string
	// SubPath is the path after owner/name ("" for the repository root).
	SubPath string
	// Ref is the text after @ as written.
	Ref string
	// SHA reports that Ref is a full commit SHA.
	SHA bool
	// Version is what a matcher compares (Ref, or the comment's version for
	// a SHA pin); "" when VersionSource is VersionUnknown.
	Version       string
	VersionSource VersionSource
	Kind          RefKind
	// Line is the 1-based line of the uses: value.
	Line int
}

// commentVersion matches the version token of a trailing comment such as
// "# v4.1.0", "# tag=v4.1.0" or "# pin @v2".
var commentVersion = regexp.MustCompile(`(?:^|[\s=@])(v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?)\b`)

// ActionRefs lists the remote actions and reusable workflows of one
// workflow file, in file order. Status follows Check: a file over the cap
// or one that does not parse lists nothing and is never read as "uses no
// action".
func ActionRefs(content []byte) ([]ActionRef, Status) {
	if len(content) > MaxWorkflowBytes {
		return nil, StatusOverCap
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, StatusUnparsed
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, StatusComplete
	}
	jobs := get(doc.Content[0], "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil, StatusComplete
	}
	var out []ActionRef
	for i := 1; i < len(jobs.Content); i += 2 {
		job := jobs.Content[i]
		if job.Kind != yaml.MappingNode {
			continue
		}
		if u := get(job, "uses"); u != nil && u.Kind == yaml.ScalarNode {
			if r, ok := parseActionRef(u, RefReusableWorkflow); ok {
				out = append(out, r)
			}
		}
		steps := get(job, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for _, st := range steps.Content {
			if st.Kind != yaml.MappingNode {
				continue
			}
			if u := get(st, "uses"); u != nil && u.Kind == yaml.ScalarNode {
				if r, ok := parseActionRef(u, RefStep); ok {
					out = append(out, r)
				}
			}
		}
	}
	return out, StatusComplete
}

// parseActionRef reads one uses: scalar; ok is false for a local or docker
// reference or a value that names no owner/name@ref.
func parseActionRef(n *yaml.Node, kind RefKind) (ActionRef, bool) {
	uses := strings.TrimSpace(n.Value)
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "../") || strings.HasPrefix(uses, "docker://") {
		return ActionRef{}, false
	}
	at := strings.LastIndex(uses, "@")
	if at <= 0 || at == len(uses)-1 {
		return ActionRef{}, false
	}
	repoPath, ref := uses[:at], uses[at+1:]
	parts := strings.SplitN(repoPath, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ActionRef{}, false
	}
	r := ActionRef{
		Repo: strings.ToLower(parts[0] + "/" + parts[1]),
		Ref:  ref, Kind: kind, Line: n.Line,
		SHA: commitSHA.MatchString(strings.ToLower(ref)),
	}
	if len(parts) == 3 {
		r.SubPath = parts[2]
	}
	switch {
	case !r.SHA:
		r.Version, r.VersionSource = ref, VersionFromRef
	default:
		if m := commentVersion.FindStringSubmatch(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(n.LineComment), "#"))); m != nil {
			r.Version, r.VersionSource = m[1], VersionFromComment
		}
	}
	return r, true
}
