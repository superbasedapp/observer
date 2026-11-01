package agentconfig

import (
	"slices"
	"sort"
	"strings"
	"sync"
)

// Conditional rows of the repository trust path table (lane SBX-P3B, N2):
// a row that matters only where a capability is active, so it is read by
// the trust check only when the caller says the capability holds. The
// default table (TrustPaths) never includes them: adding them to every
// trust check (security.trust is offered by default, P-044) would newly
// warn in every repository that carries the file, which needs an
// orchestrator ruling first.

// TrustDevcontainer is a .devcontainer/devcontainer.json: read through the
// container sandbox driver's own parser (internal/sandboxoci), and every
// host-executing or privilege-raising field it ignores is reported.
const TrustDevcontainer TrustClass = "devcontainer"

// TrustCondition names a capability a conditional row needs. The
// vocabulary is closed and names a capability, never a tool.
type TrustCondition string

// The closed TrustCondition vocabulary.
const (
	// TrustCondOCISandbox: the container sandbox driver is active (the
	// sandbox on, the terminals.sandbox.oci component selected and an oci-*
	// row among the enabled backends), so a repository's devcontainer.json
	// can be adopted for a run.
	TrustCondOCISandbox TrustCondition = "oci_sandbox_active"
	// TrustCondDevcontainerHost: a devcontainer field that runs on the host
	// whenever any devcontainer tool opens the folder (initializeCommand),
	// the same class as the unconditional .vscode/tasks.json folder-open
	// row. It holds wherever the trust check runs and the reader is
	// compiled in, as long as a devcontainerFields row names it (N2, the
	// orchestrator's proposed ruling, lane SBX-P3D).
	TrustCondDevcontainerHost TrustCondition = "devcontainer_host_command"
)

// ConditionalRepositoryFile is a RepositoryFile read only under Condition.
type ConditionalRepositoryFile struct {
	RepositoryFile
	Condition TrustCondition
}

// conditionalRepositoryFiles is the conditional extra-row table.
var conditionalRepositoryFiles = []ConditionalRepositoryFile{
	{
		RepositoryFile: RepositoryFile{
			ID: "repo/devcontainer", Rel: ".devcontainer/devcontainer.json", Class: TrustDevcontainer, RepoRootOnly: true,
			Grounding: Grounding{Kind: GroundSource, Source: "internal/devcontainer/devcontainer.go (ignoredFields); containers.dev devcontainer.json reference", Date: "2026-10-22"},
			Note:      "The container sandbox adopts only its digest-pinned image and allow-listed containerEnv; every field that would run on the host or raise the container's privilege (initializeCommand, runArgs, privileged, capAdd, securityOpt, mounts, build and the rest) is ignored and reported here, because another devcontainer tool would honour it.",
		},
		Condition: TrustCondOCISandbox,
	},
	devcontainerHostRow,
}

// devcontainerHostRow reads .devcontainer/devcontainer.json for its
// host-executing fields only (TrustCondDevcontainerHost); the same file,
// class and parser as repo/devcontainer, which reports every ignored field
// where the container sandbox is active.
var devcontainerHostRow = ConditionalRepositoryFile{
	RepositoryFile: RepositoryFile{
		ID: "repo/devcontainer-host", Rel: ".devcontainer/devcontainer.json", Class: TrustDevcontainer, RepoRootOnly: true,
		Grounding: Grounding{Kind: GroundSource, Source: "containers.dev devcontainer.json reference (initializeCommand: a command run on the host machine during initialization); internal/sandboxoci/devcontainer.go", Date: "2026-10-23"},
		Note:      "initializeCommand runs on the host, not in the container, whenever a devcontainer tool (VS Code Dev Containers, the devcontainer CLI, Codespaces prebuilds) opens the folder: the same class as a .vscode/tasks.json folder-open task, so it is reported with or without Observer's container sandbox.",
	},
	Condition: TrustCondDevcontainerHost,
}

// DevcontainerField is one row of which ignored devcontainer field the
// trust check reports under which condition; "*" names every field the
// container driver's parser ignores.
type DevcontainerField struct {
	Field     string
	Condition TrustCondition
}

// devcontainerFields is THE table (N2). A field is reported when any row
// naming it (or "*") has a condition that holds. The first row is the
// orchestrator's proposed ruling (lane SBX-P3D): initializeCommand is
// reported wherever the trust check runs, because it runs on the host;
// every other field matters only when Observer's container adopts the file
// or runs inside a container, so it stays OCI-active only (P-087).
// Reversing the ruling is this one row: give it TrustCondOCISandbox (or
// delete it) and nothing is read outside the container sandbox again.
var devcontainerFields = []DevcontainerField{
	{Field: "initializeCommand", Condition: TrustCondDevcontainerHost},
	{Field: "*", Condition: TrustCondOCISandbox},
}

// DevcontainerFieldReported reports whether field is reported under conds.
func DevcontainerFieldReported(field string, conds ...TrustCondition) bool {
	for _, r := range devcontainerFields {
		if (r.Field == field || r.Field == "*") && slices.Contains(conds, r.Condition) {
			return true
		}
	}
	return false
}

// DevcontainerFieldsNamed lists the fields rows held under conds name ("*"
// included as itself).
func DevcontainerFieldsNamed(conds ...TrustCondition) []string {
	var out []string
	for _, r := range devcontainerFields {
		if slices.Contains(conds, r.Condition) {
			out = append(out, r.Field)
		}
	}
	return out
}

// DevcontainerConditionUsed reports whether any field row names cond, so a
// condition with no field to report reads nothing.
func DevcontainerConditionUsed(cond TrustCondition) bool {
	for _, r := range devcontainerFields {
		if r.Condition == cond {
			return true
		}
	}
	return false
}

// ConditionalRepositoryFiles returns the conditional extra-row table (a
// copy).
func ConditionalRepositoryFiles() []ConditionalRepositoryFile {
	return append([]ConditionalRepositoryFile(nil), conditionalRepositoryFiles...)
}

var (
	trustWithMu    sync.Mutex
	trustWithCache = map[string][]TrustPath{}
)

// TrustPathsWith returns the trust path table with the conditional rows of
// the given conditions added. With no condition it is TrustPaths. Compiled
// once per condition set.
func TrustPathsWith(conds ...TrustCondition) []TrustPath {
	var extra []RepositoryFile
	var names []string
	for _, r := range conditionalRepositoryFiles {
		if slices.Contains(conds, r.Condition) {
			extra = append(extra, r.RepositoryFile)
			names = append(names, r.ID)
		}
	}
	if len(extra) == 0 {
		return TrustPaths()
	}
	sort.Strings(names)
	key := strings.Join(names, "\x00")
	trustWithMu.Lock()
	compiled, ok := trustWithCache[key]
	if !ok {
		compiled = compileTrustPaths(extra)
		trustWithCache[key] = compiled
	}
	trustWithMu.Unlock()
	out := make([]TrustPath, len(compiled))
	for i, p := range compiled {
		p.Sources = append([]string(nil), p.Sources...)
		out[i] = p
	}
	return out
}
