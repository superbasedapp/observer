package sandboxadopt

// Engine names the container engine, as the OCI driver identifies it.
type Engine string

// The engines the OCI rows drive.
const (
	EngineDocker Engine = "docker"
	EnginePodman Engine = "podman"
)

// Mode is the engine's privilege mode.
type Mode string

// The engine modes.
const (
	ModeRootful  Mode = "rootful"
	ModeRootless Mode = "rootless"
)

// EngineFacts are what the engine itself says about keeping a container
// when the process that attached to it goes away.
type EngineFacts struct {
	Engine Engine
	Mode   Mode
	// LiveRestore is Docker's /info LiveRestoreEnabled.
	LiveRestore bool
	// Conmon is Podman's /libpod/info host.conmon.path being set: conmon,
	// not the API service, holds the container's terminal.
	Conmon bool
}

// engineRow is one row of the engine table: the facts it matches and
// whether that engine mode keeps a container, with why.
type engineRow struct {
	name  string
	match func(EngineFacts) bool
	keeps bool
	why   string
}

// engineTable is walked top-down (sandbox plan v2 section 5.5, revision 6
// [JSP-4]): rootful Docker keeps a container only with live-restore,
// rootless Docker never does, Podman does through conmon in either mode.
var engineTable = []engineRow{
	{"docker rootful with live-restore", func(f EngineFacts) bool {
		return f.Engine == EngineDocker && f.Mode == ModeRootful && f.LiveRestore
	}, true, "rootful Docker with live-restore keeps containers across an engine restart"},
	{"docker rootful without live-restore", func(f EngineFacts) bool {
		return f.Engine == EngineDocker && f.Mode == ModeRootful
	}, false, "rootful Docker without live-restore ends its containers when the engine restarts, so the run ends as before"},
	{"docker rootless", func(f EngineFacts) bool {
		return f.Engine == EngineDocker && f.Mode == ModeRootless
	}, false, "rootless Docker ends its containers when the engine restarts, so the run ends as before"},
	{"podman with conmon", func(f EngineFacts) bool {
		return f.Engine == EnginePodman && f.Conmon
	}, true, "Podman keeps the container's terminal in conmon, outside the API service"},
	{"podman without conmon", func(f EngineFacts) bool {
		return f.Engine == EnginePodman
	}, false, "Podman did not report conmon, so nothing is known to hold the container's terminal"},
}

// EngineKeeps reports whether the engine mode keeps a container that lost
// its attached process, and why. An engine the table does not know keeps
// nothing.
func EngineKeeps(f EngineFacts) (bool, string) {
	for _, r := range engineTable {
		if r.match(f) {
			return r.keeps, r.why
		}
	}
	return false, "the engine is not one the container rows drive"
}
