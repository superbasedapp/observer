package defaultworkspace

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hostRoot is this host's filesystem root ("/" or the temp folder's drive).
func hostRoot(t *testing.T) string {
	t.Helper()
	return filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
}

func TestResolve(t *testing.T) {
	home := filepath.Join(hostRoot(t), "home", "dev")
	builtin := filepath.Join(home, BuiltinName)
	other := filepath.Join(hostRoot(t), "scratch", "ws")
	cases := []struct {
		name       string
		configured string
		home       string
		wantDir    string
		wantBuilt  bool
	}{
		{"unset uses the built-in folder", "", home, builtin, true},
		{"blank counts as unset", "   ", home, builtin, true},
		{"configured folder wins", other, home, other, false},
		{"configured value is cleaned", other + string(filepath.Separator), home, other, false},
		{"configured built-in spelling is still built-in", builtin, home, builtin, true},
		{"no home and nothing configured", "", "", "", false},
		{"no home but configured", other, "", other, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Resolve(tc.configured, tc.home)
			if got.Dir != tc.wantDir || got.Builtin != tc.wantBuilt {
				t.Fatalf("Resolve(%q, %q) = %+v, want dir %q builtin %v", tc.configured, tc.home, got, tc.wantDir, tc.wantBuilt)
			}
		})
	}
}

// fakeDisk is the injected disk facts for the pure rule table: repository
// roots, marked folders, folders holding files, and child repositories.
type fakeDisk struct {
	repos    []string
	marked   map[string]bool
	nonEmpty map[string]bool
	children map[string][]string
}

func (d fakeDisk) input(path, home string, dataDirs []string) Input {
	return Input{
		Path: path, Home: home, DataDirs: dataDirs,
		RepoRoot: func(dir string) (string, bool) {
			// The innermost repository holding dir.
			best := ""
			for _, r := range d.repos {
				if (samePath(dir, r) || within(dir, r)) && len(r) > len(best) {
					best = r
				}
			}
			if best == "" {
				return "", false
			}
			if samePath(dir, best) {
				return dir, true
			}
			return best, true
		},
		Marked:     func(dir string) bool { return d.marked[dir] },
		HoldsFiles: func(dir string) bool { return d.nonEmpty[dir] },
		ChildRepos: func(dir string) []string { return d.children[dir] },
	}
}

func TestValidateRules(t *testing.T) {
	root := hostRoot(t)
	home := filepath.Join(root, "home", "dev")
	data := filepath.Join(home, DataDirName)
	dbDir := filepath.Join(root, "var", "observer")
	repo := filepath.Join(home, "code", "proj")
	markedWS := filepath.Join(home, "ws-marked")
	unmarkedRepo := filepath.Join(home, "ws-unmarked")
	nestedMarked := filepath.Join(repo, "ws")
	codeDir := filepath.Join(home, "code")
	busy := filepath.Join(home, "busy")
	empty := filepath.Join(home, "empty")
	disk := fakeDisk{
		repos:    []string{repo, markedWS, unmarkedRepo, nestedMarked},
		marked:   map[string]bool{markedWS: true, nestedMarked: true},
		nonEmpty: map[string]bool{markedWS: true, unmarkedRepo: true, nestedMarked: true, codeDir: true, busy: true, repo: true},
		children: map[string][]string{codeDir: {"proj", "alpha", "beta", "gamma", "delta"}},
	}
	cases := []struct {
		name string
		path string
		rule string // "" = accepted
	}{
		{"built-in folder, not there yet", filepath.Join(home, BuiltinName), ""},
		{"folder outside home", filepath.Join(root, "scratch", "ws"), ""},
		{"plain empty folder (Ensure sets it up)", empty, ""},
		{"marked repository rooted at the folder", markedWS, ""},
		{"empty", "", "empty"},
		{"blank", "  ", "empty"},
		{"too long", filepath.Join(root, strings.Repeat("a", MaxPathBytes)), "length"},
		{"control character", filepath.Join(home, "a\nb"), "control"},
		{"relative", filepath.Join("rel", "ws"), "absolute"},
		{"filesystem root", root, "root"},
		{"home folder", home, "home"},
		{"home folder with trailing separator", home + string(filepath.Separator), "home"},
		{"folder holding home", filepath.Join(root, "home"), "holds_home"},
		{"data folder", data, "data_dir"},
		{"inside data folder", filepath.Join(data, "ws"), "data_dir"},
		{"database folder", filepath.Join(dbDir, "ws"), "data_dir"},
		{"folder holding the database folder", filepath.Join(root, "var"), "holds_data_dir"},
		{"unmarked repository rooted at the folder", unmarkedRepo, "git"},
		{"project root", repo, "git"},
		{"inside a project", filepath.Join(repo, "scratch"), "git"},
		{"marked folder inside another repository", nestedMarked, "git"},
		{"parent of repositories", codeDir, "holds_repos"},
		{"folder that already holds files, no marker", busy, "not_empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(disk.input(tc.path, home, []string{data, dbDir}))
			if tc.rule == "" {
				if err != nil {
					t.Fatalf("Validate(%q) = %v, want accepted", tc.path, err)
				}
				return
			}
			var r *Refusal
			if !errors.As(err, &r) {
				t.Fatalf("Validate(%q) = %v, want refusal %q", tc.path, err, tc.rule)
			}
			if r.Rule != tc.rule {
				t.Fatalf("Validate(%q) refused by %q (%s), want %q", tc.path, r.Rule, r.Msg, tc.rule)
			}
			if r.Msg == "" || strings.Contains(r.Msg, "_") {
				t.Fatalf("refusal message %q must be plain words", r.Msg)
			}
		})
	}
}

// TestValidateHomeIsARepository (review finding 5, 2026-11-12): a
// repository rooted exactly at the home folder (a dotfiles checkout) is not
// "another repository" for the git rule, so the built-in workspace can be
// set up inside it; a workspace inside any other repository, nested in the
// home one or not, is still refused.
func TestValidateHomeIsARepository(t *testing.T) {
	root := hostRoot(t)
	home := filepath.Join(root, "home", "dev")
	data := filepath.Join(home, DataDirName)
	project := filepath.Join(home, "code", "proj")
	markedWS := filepath.Join(home, "ws-marked")
	unmarked := filepath.Join(home, "ws-unmarked")
	markedInProject := filepath.Join(project, "ws")
	busy := filepath.Join(home, "busy")
	disk := fakeDisk{
		repos:    []string{home, project, markedWS, unmarked, markedInProject},
		marked:   map[string]bool{markedWS: true, markedInProject: true},
		nonEmpty: map[string]bool{markedWS: true, unmarked: true, markedInProject: true, project: true, busy: true},
	}
	for _, tc := range []struct {
		name string
		path string
		rule string
	}{
		{"built-in folder inside the home repository", filepath.Join(home, BuiltinName), ""},
		{"new folder deeper inside the home repository", filepath.Join(home, "scratch", "ws"), ""},
		{"marked workspace whose outer repository is the home one", markedWS, ""},
		{"unmarked repository rooted at the folder", unmarked, "git"},
		{"inside a project nested in the home repository", filepath.Join(project, "scratch"), "git"},
		{"marked workspace inside a project", markedInProject, "git"},
		{"folder holding files, no marker", busy, "not_empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(disk.input(tc.path, home, []string{data}))
			var r *Refusal
			switch {
			case tc.rule == "" && err != nil:
				t.Fatalf("Validate(%q) = %v, want accepted", tc.path, err)
			case tc.rule != "" && (!errors.As(err, &r) || r.Rule != tc.rule):
				t.Fatalf("Validate(%q) = %v, want refusal %q", tc.path, err, tc.rule)
			}
		})
	}
}

// TestEnsureInsideAHomeRepository: with the home folder itself a git
// checkout, Ensure still gives the built-in workspace its own repository and
// Inspect reports it ready.
func TestEnsureInsideAHomeRepository(t *testing.T) {
	home, env := fakeHome(t)
	calls := 0
	if err := fakeInit(&calls)(home); err != nil {
		t.Fatal(err)
	}
	calls = 0
	dir := Resolve("", home).Dir
	res, err := Ensure(env, dir, fakeInit(&calls))
	if err != nil || !res.Created || !res.Marked || !res.Initialized || calls != 1 {
		t.Fatalf("Ensure = %+v, %v (init calls %d); want created, marked, initialized", res, err, calls)
	}
	if root, ok := RepoRoot(dir); !ok || !samePath(root, dir) {
		t.Fatalf("the workspace is not its own repository: %q %v", root, ok)
	}
	if s := Inspect(env, ""); !s.Ready || s.Problem != "" {
		t.Fatalf("the workspace must be ready: %+v", s)
	}
}

func TestHoldsReposNamesWhatItFound(t *testing.T) {
	root := hostRoot(t)
	dir := filepath.Join(root, "code")
	disk := fakeDisk{children: map[string][]string{dir: {"a", "b", "c", "d", "e"}}}
	err := Validate(disk.input(dir, "", nil))
	if err == nil || !strings.Contains(err.Error(), "a, b, c and 2 more") {
		t.Fatalf("want the found repositories named, got %v", err)
	}
}

func TestValidateWithoutDiskFacts(t *testing.T) {
	root := hostRoot(t)
	if err := Validate(Input{Path: filepath.Join(root, "ws")}); err != nil {
		t.Fatalf("no home, no data folders, no disk facts: %v", err)
	}
}

func TestEnvFor(t *testing.T) {
	root := hostRoot(t)
	home := filepath.Join(root, "home", "dev")
	env := EnvFor(home, filepath.Join(home, DataDirName, "observer.db"))
	if len(env.DataDirs) != 1 || env.DataDirs[0] != filepath.Join(home, DataDirName) {
		t.Fatalf("db in ~/.observer must dedupe to one data folder: %v", env.DataDirs)
	}
	env = EnvFor(home, filepath.Join(root, "var", "observer.db"))
	if len(env.DataDirs) != 2 {
		t.Fatalf("db elsewhere adds its folder: %v", env.DataDirs)
	}
	env = EnvFor("", "relative.db")
	if len(env.DataDirs) != 0 {
		t.Fatalf("no home and a relative db path add nothing: %v", env.DataDirs)
	}
}

// fakeHome is a temp home with its data folder; it is never inside a git
// repository (t.TempDir lives under the OS temp folder).
func fakeHome(t *testing.T) (string, Env) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, DataDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	if InsideGitRepo(home) {
		t.Skip("the temp folder is inside a git repository on this host")
	}
	return home, EnvFor(home, filepath.Join(home, DataDirName, "observer.db"))
}

// fakeInit stands in for `git init`: it makes the .git folder git.FindRoot
// looks for and counts its calls.
func fakeInit(calls *int) InitRepo {
	return func(dir string) error {
		*calls++
		if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600)
	}
}

func TestEnsureSetsUpOnceAndLeavesContents(t *testing.T) {
	home, env := fakeHome(t)
	dir := Resolve("", home).Dir
	calls := 0
	res, err := Ensure(env, dir, fakeInit(&calls))
	if err != nil || !res.Created || !res.Marked || !res.Initialized || calls != 1 {
		t.Fatalf("first Ensure = %+v, %v (init calls %d); want created, marked, initialized", res, err, calls)
	}
	if !Marked(dir) {
		t.Fatal("marker not written")
	}
	b, _ := os.ReadFile(filepath.Join(dir, MarkerName))
	if strings.Contains(string(b), home) || strings.Contains(string(b), string(filepath.Separator)+"Users") {
		t.Fatalf("the marker must not name a path: %q", b)
	}
	if root, ok := RepoRoot(dir); !ok || !samePath(root, dir) {
		t.Fatalf("not a repository rooted at the workspace: %q %v", root, ok)
	}
	keep := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(keep, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = Ensure(env, dir, fakeInit(&calls))
	if err != nil || res != (Result{}) || calls != 1 {
		t.Fatalf("second Ensure = %+v, %v (init calls %d); want nothing done", res, err, calls)
	}
	if b, err := os.ReadFile(keep); err != nil || string(b) != "mine" {
		t.Fatalf("existing contents changed: %q %v", b, err)
	}
	if s := Inspect(env, ""); !s.Ready || s.Problem != "" {
		t.Fatalf("a set-up workspace must be ready: %+v", s)
	}
}

func TestEnsureFinishesAnEmptyOrInterruptedFolder(t *testing.T) {
	home, env := fakeHome(t)
	empty := filepath.Join(home, "empty")
	if err := os.MkdirAll(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	res, err := Ensure(env, empty, fakeInit(&calls))
	if err != nil || res.Created || !res.Marked || !res.Initialized {
		t.Fatalf("empty folder: %+v, %v", res, err)
	}
	// Marked but no repository (git was missing last time): finish it.
	half := filepath.Join(home, "half")
	if err := os.MkdirAll(half, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(half); err != nil {
		t.Fatal(err)
	}
	if s := Inspect(env, half); s.Ready || s.Problem == "" {
		t.Fatalf("a half set-up folder must report it: %+v", s)
	}
	if _, err := Ensure(env, half, nil); !errors.Is(err, ErrNoInit) {
		t.Fatalf("no init available: %v", err)
	}
	res, err = Ensure(env, half, fakeInit(&calls))
	if err != nil || res.Marked || !res.Initialized {
		t.Fatalf("half set-up folder: %+v, %v", res, err)
	}
}

func TestEnsureRefusals(t *testing.T) {
	home, env := fakeHome(t)
	file := filepath.Join(home, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mkRepo := func(dir string) {
		if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	repo := filepath.Join(home, "proj")
	mkRepo(repo)
	code := filepath.Join(home, "code")
	mkRepo(filepath.Join(code, "one"))
	mkRepo(filepath.Join(code, "two"))
	busy := filepath.Join(home, "busy")
	if err := os.MkdirAll(busy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(busy, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		dir  string
		rule string
	}{
		{"home", home, "home"},
		{"data folder", filepath.Join(home, DataDirName, "ws"), "data_dir"},
		{"a file is in the way", file, "not_a_folder"},
		{"an existing repository without the marker", repo, "git"},
		{"inside a project (missing folder)", filepath.Join(repo, "new", "ws"), "git"},
		{"a parent of repositories", code, "holds_repos"},
		{"a folder that holds files without the marker", busy, "not_empty"},
	}
	calls := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Ensure(env, tc.dir, fakeInit(&calls))
			var r *Refusal
			if res != (Result{}) || !errors.As(err, &r) || r.Rule != tc.rule {
				t.Fatalf("Ensure(%q) = %+v, %v; want refusal %q", tc.dir, res, err, tc.rule)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("a refused folder was made a repository (%d calls)", calls)
	}
	if _, err := os.Stat(filepath.Join(repo, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused folder must not be created: %v", err)
	}
	for _, d := range []string{repo, busy, code} {
		if Marked(d) {
			t.Fatalf("a refused folder %s was marked", d)
		}
	}
}

func TestCheckFollowsSymlinks(t *testing.T) {
	home, env := fakeHome(t)
	outside := t.TempDir()
	link := filepath.Join(outside, "ws-link")
	if err := os.Symlink(filepath.Join(home, DataDirName), link); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}
	var r *Refusal
	if err := Check(env, filepath.Join(link, "ws")); !errors.As(err, &r) || r.Rule != "data_dir" {
		t.Fatalf("a link into the data folder must be refused, got %v", err)
	}
}

func TestInspect(t *testing.T) {
	home, env := fakeHome(t)
	s := Inspect(env, "")
	if !s.Builtin || s.Exists || s.Ready || s.Problem != "" || s.Dir != filepath.Join(home, BuiltinName) {
		t.Fatalf("fresh built-in: %+v", s)
	}
	calls := 0
	if _, err := Ensure(env, s.Dir, fakeInit(&calls)); err != nil {
		t.Fatal(err)
	}
	if s = Inspect(env, ""); !s.Exists || !s.Ready {
		t.Fatalf("after Ensure: %+v", s)
	}
	if s = Inspect(env, home); s.Problem == "" || s.Builtin || s.Ready {
		t.Fatalf("home configured must report a problem: %+v", s)
	}
	if s = Inspect(Env{}, ""); s.Dir != "" || s.Problem == "" {
		t.Fatalf("no home: %+v", s)
	}
}
