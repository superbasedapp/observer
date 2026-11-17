package config

// WorkspaceConfig is the [workspace] block: Observer's own default
// workspace, a scratch folder Observer offers when a step needs a folder
// that is not one of the developer's projects (first user: the hosted
// sandbox consent step in Terminals > Settings). It is a top-level block,
// not a [terminal] key, because the folder is not a terminal setting: it is
// created at install whatever components are active, and later surfaces
// that need a neutral folder read it too.
//
// LOCAL-ONLY: never distributed to an org and never a server-forced value.
// The zero value (DefaultDir empty) means the built-in default,
// <home>/observer-workspace; `observer start` and `observer init` set that
// folder up when it is missing or empty (the folder, a .observer-workspace
// marker file and its own git repository, which the hosted consent screen
// needs) without writing this block. The one reader
// of "what is the default workspace" is internal/defaultworkspace.Resolve;
// the one writer of the key from the dashboard is the "Default workspace"
// card (PUT /api/workspace/default), which validates the folder and
// creates it before saving.
type WorkspaceConfig struct {
	// DefaultDir is the absolute path of the default workspace folder.
	// Empty (default) = <home>/observer-workspace. A leading "~/" expands
	// against the home directory. The folder must not be the home folder or
	// hold it, must not be a filesystem root, must not be inside Observer's
	// data folder (~/.observer), must not be inside a git repository other
	// than its own (rooted there and carrying the marker), must not hold git
	// repositories, and must be new, empty or already marked; a value that
	// breaks a rule is reported at start and the folder is not set up.
	DefaultDir string `toml:"default_dir"`
}
