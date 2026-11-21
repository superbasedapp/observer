// Package defaultworkspace owns Observer's default workspace: a scratch
// folder Observer offers when a step needs a folder that is not one of the
// developer's projects (first user: the hosted sandbox consent step), so
// such work never leaves debris in a real project.
//
// It is the ONE owner of three answers:
//
//   - Resolve: what the default workspace is (the [workspace].default_dir
//     value, else the built-in <home>/observer-workspace). Pure.
//   - Validate: whether a folder may be the default workspace, as an
//     ordered rule table walked top-down (absolute, not a filesystem root,
//     not the home folder or a folder holding it, not inside or holding
//     Observer's data folder, not a git repository unless it is an Observer
//     workspace, not a parent of git repositories, not a folder that already
//     holds files without the marker). Pure: every disk fact is injected.
//   - Ensure: set the folder up, after Check ran the rules on both the typed
//     and the symlink-resolved spelling: create it when it is missing (0700),
//     write the marker (MarkerName) into a folder it created or found empty,
//     and make a marked folder its own git repository through an injected
//     InitRepo, because the hosted consent screen uploads a repository's
//     files only. A folder that holds files without the marker, and any
//     existing repository, are never touched. This is the only place the
//     folder is set up; `observer start`, `observer init` and the dashboard's
//     Default workspace card all call it.
//
// An Observer workspace is a git repository rooted exactly at the folder
// that carries the marker; the marker is the only thing that tells it apart
// from a real project.
//
// The package reads and creates directories and the marker file (os) and
// asks internal/git where a working tree starts; it never runs a subprocess
// (git init is injected), opens a database or makes a network call
// (imports_test.go).
package defaultworkspace
