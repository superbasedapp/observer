package cloudagents

// ProjectRef is how a pulled task finds its project (CA-D3): by normalized
// git remote when one is known, else under the connector's placeholder
// project root.
type ProjectRef struct {
	// Remote is a hosted git remote ("github.com/owner/repo"), resolved by
	// the store's ResolveRemoteProject; "" when unknown.
	Remote string
	// Placeholder is the project root used when Remote is "" (the
	// "[cursor]" precedent: an honest "project unknown", never a path).
	Placeholder string
	// Inferred is true when Remote came from an inference the connector row
	// declares (an environment label), not a repository field.
	Inferred bool
	// Note is the honest caption of a placeholder filing
	// (NoteRepositoryNotReported); "" when a repository was found.
	Note string
	// Rule names the rule that decided.
	Rule string
}

// NoteRepositoryNotReported captions a task filed under its connector's
// placeholder project because the vendor named no repository Observer can
// trust (CA-D16). Shown beside the bucket; never a project name.
const NoteRepositoryNotReported = "repository not reported"

// PlaceholderRoot is the placeholder project root of a connector.
func PlaceholderRoot(connector string) string { return "[" + connector + "]" }

// KnownRemote reports whether a hosted remote ("github.com/owner/repo") is
// already the remote of a project the node knows. The service injects the
// store lookup (Store.ProjectByRemote); nil means no project is known.
type KnownRemote func(remote string) bool

// projectRule is one row of the project resolution table, walked top-down.
type projectRule struct {
	name string
	try  func(c Connector, t Task, known KnownRemote) (ProjectRef, bool)
}

var projectRules = []projectRule{
	{"repository field", func(_ Connector, t Task, _ KnownRemote) (ProjectRef, bool) {
		return ProjectRef{Remote: t.RepoRemote}, t.RepoRemote != ""
	}},
	// CA-D16: an environment label is a hint, not a repository field, so it
	// may only point at a project the node already knows. It never creates
	// a project (synthetic or otherwise) of its own.
	{"environment label matches a known project remote", func(c Connector, t Task, known KnownRemote) (ProjectRef, bool) {
		if !c.InferRepoFromEnvLabel || !ValidRepoSlug(t.EnvironmentLabel) || known == nil {
			return ProjectRef{}, false
		}
		remote := "github.com/" + t.EnvironmentLabel
		if !known(remote) {
			return ProjectRef{}, false
		}
		return ProjectRef{Remote: remote, Inferred: true}, true
	}},
	{"placeholder", func(c Connector, _ Task, _ KnownRemote) (ProjectRef, bool) {
		return ProjectRef{Placeholder: PlaceholderRoot(c.ID), Note: NoteRepositoryNotReported}, true
	}},
}

// ResolveProject returns how task t of connector c finds its project; known
// answers whether a remote is already a known project's remote.
func ResolveProject(c Connector, t Task, known KnownRemote) ProjectRef {
	for _, r := range projectRules {
		if ref, ok := r.try(c, t, known); ok {
			ref.Rule = r.name
			return ref
		}
	}
	return ProjectRef{Placeholder: PlaceholderRoot(c.ID), Note: NoteRepositoryNotReported, Rule: "placeholder"}
}

// IsPlaceholderRoot reports whether root is a bracketed placeholder project
// root ("[codex-cloud]", the "[cursor]" precedent).
func IsPlaceholderRoot(root string) bool {
	return len(root) > 2 && root[0] == '[' && root[len(root)-1] == ']'
}

// rootRule is one row of the table that picks the project root a pulled
// session's events carry, given the root the session row already has (""
// when the row does not exist yet) and the root the task resolves to now.
// Ingest rewrites sessions.project_id from the events, so this table is what
// keeps a pull from moving a session another rail already filed.
type rootRule struct {
	name string
	pick func(existing, resolved string) (string, bool)
}

var rootRules = []rootRule{
	{"new session takes the resolved root", func(existing, resolved string) (string, bool) {
		return resolved, existing == ""
	}},
	{"a real root is never replaced", func(existing, _ string) (string, bool) {
		return existing, !IsPlaceholderRoot(existing)
	}},
	{"a placeholder upgrades to a resolved repository", func(_, resolved string) (string, bool) {
		return resolved, !IsPlaceholderRoot(resolved)
	}},
	{"otherwise keep", func(existing, _ string) (string, bool) { return existing, true }},
}

// ChooseProjectRoot returns the root a pulled session's events carry.
func ChooseProjectRoot(existing, resolved string) string {
	for _, r := range rootRules {
		if root, ok := r.pick(existing, resolved); ok {
			return root
		}
	}
	return existing
}
