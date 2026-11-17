package defaultworkspace

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/git"
)

// DataDirName is Observer's data folder under the home folder.
const DataDirName = ".observer"

// MarkerName is the file at the root of a workspace Observer set up. It is
// the only thing that tells an Observer workspace (its own git repository)
// apart from a real project.
const MarkerName = ".observer-workspace"

// markerText is the marker's whole content: what the folder is, no paths.
const markerText = "This folder is Observer's default workspace: a scratch folder Observer created for steps that need a folder that is not one of your projects.\n" +
	"Observer made it a git repository so the hosted sandbox consent screen can list its files. Keep this file: it is how Observer tells this folder apart from your projects.\n"

// childScanLimit bounds the shallow look for child repositories.
const childScanLimit = 4096

// maxChildRepos bounds how many child repositories are collected.
const maxChildRepos = 50

// InitRepo makes dir a git repository. The package runs no subprocess: the
// caller injects it (cmd/observer's fixed `git init`).
type InitRepo func(dir string) error

// ErrNoInit is returned when a folder needs a repository and no InitRepo
// was given.
var ErrNoInit = errors.New("no git init was available")

// Env is the host facts the rules compare a folder against.
type Env struct {
	// Home is the home folder ("" when none resolves).
	Home string
	// DataDirs are Observer's data folders.
	DataDirs []string
}

// EnvFor builds the Env for a home folder and the database path: the data
// folders are <home>/.observer and the database's own folder.
func EnvFor(home, dbPath string) Env {
	var dirs []string
	add := func(d string) {
		d = strings.TrimSpace(d)
		if d == "" || d == "." {
			return
		}
		for _, have := range dirs {
			if samePath(have, d) {
				return
			}
		}
		dirs = append(dirs, filepath.Clean(d))
	}
	if strings.TrimSpace(home) != "" {
		add(filepath.Join(home, DataDirName))
	}
	if strings.TrimSpace(dbPath) != "" && filepath.IsAbs(dbPath) {
		add(filepath.Dir(dbPath))
	}
	return Env{Home: home, DataDirs: dirs}
}

// diskInput fills the disk facts of an Input from this host.
func diskInput(path, home string, dataDirs []string) Input {
	return Input{
		Path: path, Home: home, DataDirs: dataDirs,
		RepoRoot: RepoRoot, Marked: Marked, ChildRepos: ChildRepos, HoldsFiles: HoldsFiles,
	}
}

// Check runs Validate with this host's disk facts on the folder as typed
// and, when it differs, on its symlink-resolved spelling against the
// resolved home and data folders, so a link cannot carry the workspace into
// the home root, ~/.observer or a project.
func Check(env Env, dir string) error {
	if err := Validate(diskInput(dir, env.Home, env.DataDirs)); err != nil {
		return err
	}
	var dataDirs []string
	for _, d := range env.DataDirs {
		dataDirs = append(dataDirs, canonical(d))
	}
	return Validate(diskInput(canonical(filepath.Clean(strings.TrimSpace(dir))), canonical(env.Home), dataDirs))
}

// Result says what Ensure did.
type Result struct {
	// Created: the folder was made by this call.
	Created bool
	// Marked: the marker was written by this call.
	Marked bool
	// Initialized: the folder was made a git repository by this call.
	Initialized bool
}

// Ensure checks dir and sets it up: it creates the folder when it is
// missing (owner-only, 0700); writes the marker into a folder it created or
// found empty; and makes a marked folder that is not yet a repository one
// (initRepo). A folder that holds files without the marker is refused by
// Check, so it is never marked or made a repository, and an existing
// repository is never touched. The marker is written before the repository,
// so an interrupted set-up is finished on the next call.
func Ensure(env Env, dir string, initRepo InitRepo) (Result, error) {
	var res Result
	if err := Check(env, dir); err != nil {
		return res, err
	}
	dir = filepath.Clean(strings.TrimSpace(dir))
	st, err := os.Stat(dir) //nolint:gosec // G703: the owner's own workspace folder from config.toml or the confirmed dashboard edit, checked by the rule table above; only stat'd
	switch {
	case err == nil && !st.IsDir():
		return res, &Refusal{Rule: "not_a_folder", Msg: "Something that is not a folder is already at that path."}
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return res, fmt.Errorf("defaultworkspace.Ensure: %w", err)
	case err != nil:
		if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // G703: as above; MkdirAll only creates the missing folders
			return res, fmt.Errorf("defaultworkspace.Ensure: %w", err)
		}
		res.Created = true
	}
	if !Marked(dir) && !HoldsFiles(dir) {
		if err := writeMarker(dir); err != nil {
			return res, fmt.Errorf("defaultworkspace.Ensure: %w", err)
		}
		res.Marked = true
	}
	if !Marked(dir) {
		return res, nil
	}
	if root, ok := RepoRoot(dir); ok && samePath(root, dir) {
		// Check let it through, so it is the workspace's own repository.
		// A repository above it (only the home folder's, which Check
		// allows) is not: the workspace still gets its own.
		return res, nil
	}
	if initRepo == nil {
		return res, ErrNoInit
	}
	if err := initRepo(dir); err != nil {
		return res, fmt.Errorf("git could not make it a repository: %w", err)
	}
	res.Initialized = true
	return res, nil
}

// writeMarker creates the marker; one that is already there is kept.
func writeMarker(dir string) error {
	f, err := os.OpenFile(filepath.Join(dir, MarkerName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G703: a fixed file name inside the checked workspace folder
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := f.WriteString(markerText); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Status is the default workspace as the dashboard shows it.
type Status struct {
	Resolved
	// Configured is the raw [workspace].default_dir value ("" = unset).
	Configured string
	// Exists reports a folder at Dir.
	Exists bool
	// Ready reports a folder Observer finished setting up: it exists,
	// carries the marker and is its own git repository.
	Ready bool
	// Problem says what keeps the folder from being used, in plain words
	// ("" when it is ready, or when it is missing and passes the rules).
	Problem string
}

// notSetUp is the Problem of a folder that passes the rules but that
// Observer has not finished setting up.
const notSetUp = "Observer has not finished setting this folder up (its marker file and git repository); it does when it starts, or when you save the folder here."

// Inspect resolves the configured value and reports whether the folder
// exists, passes the rules and is set up. It creates nothing.
func Inspect(env Env, configured string) Status {
	s := Status{Resolved: Resolve(configured, env.Home), Configured: strings.TrimSpace(configured)}
	if s.Dir == "" {
		s.Problem = "No home folder resolves on this machine, so there is no built-in workspace; set a folder."
		return s
	}
	st, statErr := os.Stat(s.Dir) //nolint:gosec // G703: the owner's own workspace folder; only stat'd
	s.Exists = statErr == nil && st.IsDir()
	if s.Exists && Marked(s.Dir) {
		root, ok := RepoRoot(s.Dir)
		s.Ready = ok && samePath(root, s.Dir)
	}
	switch err := Check(env, s.Dir); {
	case err != nil:
		s.Problem = err.Error()
		s.Ready = false
	case statErr == nil && !st.IsDir():
		s.Problem = "Something that is not a folder is already at that path."
	case s.Exists && !s.Ready:
		s.Problem = notSetUp
	}
	return s
}

// RepoRoot reports the top level of the git checkout holding dir, looked up
// from the nearest folder that exists. When that top level is dir itself
// (whatever the spelling, symlinks resolved) it answers dir unchanged.
func RepoRoot(dir string) (string, bool) {
	a, ok := nearestExisting(dir)
	if !ok {
		return "", false
	}
	root, ok := git.FindCheckoutRoot(a)
	if !ok {
		return "", false
	}
	if samePath(canonical(dir), canonical(root)) {
		return filepath.Clean(dir), true
	}
	return root, true
}

// InsideGitRepo reports whether dir, or the nearest folder above it that
// exists, is inside a git working tree.
func InsideGitRepo(dir string) bool {
	_, ok := RepoRoot(dir)
	return ok
}

// Marked reports a regular marker file at dir's root.
func Marked(dir string) bool {
	fi, err := os.Lstat(filepath.Join(dir, MarkerName)) //nolint:gosec // G703: a fixed file name in the owner's workspace folder; only stat'd
	return err == nil && fi.Mode().IsRegular()
}

// HoldsFiles reports that dir exists and has at least one entry.
func HoldsFiles(dir string) bool {
	f, err := os.Open(dir) //nolint:gosec // G703: the owner's workspace folder; only its first entry name is read
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	names, _ := f.Readdirnames(1)
	return len(names) > 0
}

// ChildRepos names dir's immediate subfolders holding a .git entry,
// looking at no more than childScanLimit entries and collecting no more
// than maxChildRepos names, sorted as the directory returned them.
func ChildRepos(dir string) []string {
	f, err := os.Open(dir) //nolint:gosec // G703: the owner's workspace folder; only entry names are read
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	entries, _ := f.ReadDir(childScanLimit)
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Lstat(filepath.Join(dir, e.Name(), ".git")); err == nil { //nolint:gosec // G703: a fixed name under a child of the owner's folder; only stat'd
			out = append(out, e.Name())
			if len(out) >= maxChildRepos {
				break
			}
		}
	}
	return out
}

// nearestExisting walks up from p to the first path that exists.
func nearestExisting(p string) (string, bool) {
	if strings.TrimSpace(p) == "" {
		return "", false
	}
	cur := filepath.Clean(p)
	for {
		if _, err := os.Lstat(cur); err == nil { //nolint:gosec // G703: a parent of the owner's own workspace folder; only stat'd
			return cur, true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", false
		}
		cur = parent
	}
}

// canonical resolves symlinks in the longest existing prefix of p and keeps
// the missing remainder as typed. A path that cannot be resolved is
// returned cleaned.
func canonical(p string) string {
	if strings.TrimSpace(p) == "" {
		return p
	}
	clean := filepath.Clean(p)
	base, ok := nearestExisting(clean)
	if !ok {
		return clean
	}
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		return clean
	}
	rest, err := filepath.Rel(base, clean)
	if err != nil || rest == "." {
		return resolved
	}
	return filepath.Join(resolved, rest)
}
