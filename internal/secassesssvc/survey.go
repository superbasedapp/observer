package secassesssvc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// The survey's limits (depth plan W3.2 and W4.2): it is a bounded look, not a
// walk, and it returns what it has when a limit is hit.
const (
	// surveyMaxEntries is how many top-level entries are listed.
	surveyMaxEntries = 300
	// surveyScanCap is how many directory entries are examined before the
	// listing gives up (a folder with more is listed from the first batch,
	// sorted, and reported as truncated).
	surveyScanCap = 5000
	// surveyMaxTotal is the most bytes of project files read in all.
	surveyMaxTotal = 2 << 20
	// surveyBudget is the survey's own time budget.
	surveyBudget = 2 * time.Second
	// surveyPrefixMax is how many files one prefix entry (vite.config*) opens.
	surveyPrefixMax = 4
	// surveyBatch is the directory read batch size.
	surveyBatch = 256
)

// surveyMoreFiles are the allow-listed files read beyond the dev-server set.
var surveyMoreFiles = []string{
	"go.mod", "requirements.txt", "pyproject.toml", "Pipfile", "Gemfile", "composer.json", "Cargo.toml",
	"pom.xml", "build.gradle", "build.gradle.kts",
	"Procfile", "Makefile",
	"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
	".env.example", ".env.sample", ".env.template",
	"openapi.json", "swagger.json", "docs/openapi.json", "api/openapi.json", "openapi/openapi.json",
}

// SurveyFiles is the fixed allow-list of project-relative files the survey
// reads: the dev-server file set (a copy of secdast's, pinned by the drift
// test), the manifests the facts parse, the Procfile and Makefile, the compose
// files, the three EXAMPLE environment files, and the OpenAPI JSON paths. An
// entry ending in "*" is a prefix, matched against the top-level file names.
// No real environment file (.env, .env.local, .envrc, ...) is ever on it.
var SurveyFiles = append(slices.Clone(secassess.DevServerFiles), surveyMoreFiles...)

// surveyProbes are the directories whose existence the survey probes (the ids
// SurveyInput.Present carries).
var surveyProbes = []string{"node_modules", ".venv", "venv", "vendor", "target", ".github/workflows"}

// surveyEnvExamples are the only environment files the survey may read.
var surveyEnvExamples = []string{".env.example", ".env.sample", ".env.template"}

// surveyAllowed is the last guard before a file is opened: the allow-list never
// holds a real environment or key file, and this says so once more at the point
// of reading, by the one table the plan and the refuse setting use
// (secassess.ClassifyEnvKey): only the three exact example files may be opened.
func surveyAllowed(rel string) bool {
	return secassess.SurveyMayOpen(rel, surveyEnvExamples)
}

// Survey takes the bounded look at a project that the grounding digest, the
// start plan and the preflight notes are built from: the top-level listing, a
// fixed allow-list of project files read through os.Root, and a few existence
// probes. It reads no .env file (only their names are listed), follows no
// symlink out of the project and stops at its own caps or when ctx is done.
//
// Limits: 300 listed entries, files of at most secassess.MaxProjectFile bytes,
// 2 MiB of files in all, regular files only (a link, pipe or device is
// skipped, the open is non-blocking where the platform has one, so a FIFO
// swapped in for a file cannot hang it, and the opened handle must be the very
// file the Lstat saw, so a link swapped in after the check is not read), and a
// 2 second budget. A limit that
// was hit, or a context that ended, returns what was gathered with Truncated
// set; a missing or unreadable single file is skipped, never an error. Only a
// project folder that cannot be opened is an error.
func Survey(ctx context.Context, root string) (secassess.SurveyInput, error) {
	var in secassess.SurveyInput
	if root == "" {
		return in, errors.New("secassesssvc.Survey: no project folder")
	}
	ctx, cancel := context.WithTimeout(ctx, surveyBudget)
	defer cancel()
	if ctx.Err() != nil {
		in.Truncated = true
		return in, nil
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return in, fmt.Errorf("secassesssvc.Survey: %w", err)
	}
	defer func() { _ = r.Close() }()
	surveyList(ctx, r, &in)
	surveyRead(ctx, r, &in)
	surveyProbe(ctx, r, &in)
	return in, nil
}

// surveyList records the top-level directory and file names, sorted, hidden
// ones included.
func surveyList(ctx context.Context, r *os.Root, in *secassess.SurveyInput) {
	d, err := r.Open(".")
	if err != nil {
		in.Truncated = true
		return
	}
	defer func() { _ = d.Close() }()
	type entry struct {
		name string
		dir  bool
	}
	var all []entry
	for len(all) < surveyScanCap {
		if ctx.Err() != nil {
			in.Truncated = true
			break
		}
		batch, err := d.ReadDir(surveyBatch)
		for _, e := range batch {
			all = append(all, entry{e.Name(), e.IsDir()})
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				in.Truncated = true
			}
			break
		}
		if len(all) >= surveyScanCap {
			in.Truncated = true
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })
	if len(all) > surveyMaxEntries {
		all, in.Truncated = all[:surveyMaxEntries], true
	}
	for _, e := range all {
		if e.dir {
			in.Dirs = append(in.Dirs, e.name)
		} else {
			in.Names = append(in.Names, e.name)
		}
	}
}

// surveyFileList expands SurveyFiles against the top-level file names: a prefix
// entry becomes the names that start with it.
func surveyFileList(names []string) []string {
	var out []string
	for _, p := range SurveyFiles {
		if !strings.HasSuffix(p, "*") {
			out = append(out, p)
			continue
		}
		prefix, n := strings.TrimSuffix(p, "*"), 0
		for _, name := range names {
			if strings.HasPrefix(name, prefix) && n < surveyPrefixMax {
				out = append(out, name)
				n++
			}
		}
	}
	return out
}

// surveyRead reads the allow-listed files that exist, within the caps.
func surveyRead(ctx context.Context, r *os.Root, in *secassess.SurveyInput) {
	total := 0
	for _, rel := range surveyFileList(in.Names) {
		if ctx.Err() != nil {
			in.Truncated = true
			return
		}
		if !surveyAllowed(rel) {
			continue
		}
		data, over := surveyReadOne(r, rel, surveyMaxTotal-total)
		if over {
			in.Truncated = true
		}
		if len(data) == 0 {
			continue
		}
		total += len(data)
		in.Files = append(in.Files, secassess.ProjectFile{Rel: rel, Data: data})
	}
}

// surveyReadOne reads one project-relative file through the root: it must be a
// regular file (Lstat), of at most secassess.MaxProjectFile bytes and at most
// room bytes, and the handle opened afterwards must be that same file
// (surveyReadOpened). over reports that a size cap kept it out. A missing or
// unreadable file reads as (nil, false).
func surveyReadOne(r *os.Root, rel string, room int) (data []byte, over bool) {
	name := filepath.FromSlash(rel)
	fi, err := r.Lstat(name)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
		return nil, false
	}
	if fi.Size() > secassess.MaxProjectFile || fi.Size() > int64(room) {
		return nil, true
	}
	return surveyReadOpened(r, name, fi, room)
}

// surveyReadOpened opens name through the root and reads it only if the opened
// handle is the very file the Lstat saw (seen): same device and inode (the
// os.SameFile identity) and still a regular file. os.Root opens the last path
// element with O_NOFOLLOW itself but, on the link error, resolves a link that
// stays inside the root and opens its target, so a symlink swapped in after the
// Lstat (to a .env inside the project, say) would otherwise be read; its target
// is a different file than the one the Lstat saw and is refused here. The open
// is non-blocking (openFlags), so a FIFO swapped in cannot hang it.
func surveyReadOpened(r *os.Root, name string, seen os.FileInfo, room int) (data []byte, over bool) {
	f, err := r.OpenFile(name, openFlags, 0)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || !os.SameFile(seen, st) {
		return nil, false
	}
	limit := min(int64(secassess.MaxProjectFile), int64(room))
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false
	}
	if int64(len(data)) > limit {
		return nil, true
	}
	return data, false
}

// surveyProbe records which of the probe directories exist. A link is not a
// directory here: nothing is followed.
func surveyProbe(ctx context.Context, r *os.Root, in *secassess.SurveyInput) {
	for _, id := range surveyProbes {
		if ctx.Err() != nil {
			in.Truncated = true
			return
		}
		if fi, err := r.Lstat(filepath.FromSlash(id)); err == nil && fi.Mode().Type() == fs.ModeDir {
			in.Present = append(in.Present, id)
		}
	}
}
