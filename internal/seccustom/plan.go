package seccustom

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// RunDirs are the directories of one run, all absolute and Observer-owned
// except Project. Output holds the targets file and the SARIF; Cache is the
// driver's own cache (cache per_driver) or a per-run directory (cache
// none), never under ~/.observer (the isolation engine refuses that).
type RunDirs struct {
	Project string
	Output  string
	Cache   string
}

// RunSpec is a run ready for the hardened runner.
type RunSpec struct {
	Request extrun.Request
	// OutputFile is where the SARIF lands for output sarif_file.
	OutputFile string
	// TargetsFile and TargetsBody are the targets file for input
	// targets_file (the caller writes it before the run).
	TargetsFile string
	TargetsBody []byte
	// SkippedTargets counts targets refused for a control character (a
	// newline in a file name would split the list).
	SkippedTargets int
	// OneShot are the directories the isolation one-shot binds.
	OneShot extrun.OneShotDirs
	// Isolable is false when the manifest needs a network the one-shot
	// (egress none) cannot give; such a run is "not isolated".
	Isolable bool
}

// The file names inside RunDirs.Output.
const (
	outputName  = "result.sarif"
	targetsName = "targets.txt"
	homeName    = "home"
)

// join joins an absolute directory and a name with goos's separator.
func join(goos, dir, name string) string {
	sep := "/"
	if goos == "windows" {
		sep = `\`
	}
	return strings.TrimRight(dir, `/\`) + sep + name
}

// parent returns the directory of an absolute path.
func parent(goos, p string) string {
	cut := "/"
	if goos == "windows" {
		cut = `/\`
	}
	i := strings.LastIndexAny(p, cut)
	switch {
	case i <= 0:
		return p[:1]
	case goos == "windows" && i == 2 && p[1] == ':':
		return p[:3]
	}
	return p[:i]
}

// BuildRun turns an accepted record into the runner request (section 8.6
// execution rules): the absolute pinned executable, its digest re-checked
// by the runner immediately before the run (a mismatch refuses it), no
// shell, no PATH beyond the declared companions' directories, the closed
// environment table only, HOME inside the cache (cache per_driver) or the
// run's own directory (cache none), the working directory the project
// root (the isolation one-shot requires it), the caps from the steps, and
// target paths never interpolated into a string: they are whole lines of a
// file or of stdin.
func BuildRun(goos string, rec Record, dirs RunDirs, targets []string) (RunSpec, error) {
	m := rec.Manifest
	for name, d := range map[string]string{"project": dirs.Project, "output": dirs.Output, "cache": dirs.Cache} {
		if !extrun.IsAbs(goos, d) {
			return RunSpec{}, fmt.Errorf("the %s directory is not absolute", name)
		}
	}
	if m.ExecutableSHA256 == "" {
		return RunSpec{}, errors.New("the driver has no pinned executable digest")
	}
	spec := RunSpec{
		OutputFile:  join(goos, dirs.Output, outputName),
		TargetsFile: join(goos, dirs.Output, targetsName),
		Isolable:    m.Network.Mode == NetworkNone,
	}
	var body strings.Builder
	for _, t := range targets {
		if hasControl(t) || !strings.HasPrefix(t, dirs.Project) {
			spec.SkippedTargets++
			continue
		}
		body.WriteString(t)
		body.WriteByte('\n')
	}
	spec.TargetsBody = []byte(body.String())

	args := make([]string, len(m.Argv))
	for i, a := range m.Argv {
		switch a {
		case PlaceholderTargets:
			args[i] = spec.TargetsFile
		case PlaceholderOutput:
			args[i] = spec.OutputFile
		case PlaceholderProject:
			args[i] = dirs.Project
		default:
			args[i] = a
		}
	}
	prog := extrun.Program{Path: m.Executable}
	programDirs := []string{parent(goos, m.Executable)}
	if t, ok := TemplateByID(m.Template); ok && t.Interpreted {
		// A launcher's packages live beside its bin directory (a virtual
		// environment's lib), so that tree is bound read-only too.
		programDirs = append(programDirs, parent(goos, parent(goos, m.Executable)))
	}
	for _, c := range m.Companions {
		if c.SHA256 == "" {
			return RunSpec{}, fmt.Errorf("the companion %s has no pinned digest", c.Path)
		}
		ce := extrun.CompanionExec{Path: c.Path, Expect: c.SHA256, OnPath: c.OnPath}
		if len(c.VersionArgv) > 0 {
			ce.Version = &extrun.VersionProbe{Args: append([]string(nil), c.VersionArgv...), Pattern: versionFormats[c.VersionFormat]}
		}
		prog.CompanionExecs = append(prog.CompanionExecs, ce)
		programDirs = append(programDirs, parent(goos, c.Path))
	}
	engine := EngineFor(m)
	env := extrun.EnvSpec{Set: append([]string(nil), m.Env...)}
	if !engine.OwnHome {
		env.Set = append(env.Set, "HOME="+join(goos, dirs.Cache, homeName))
	}
	req := extrun.Request{
		Component: ComponentID,
		Program:   prog,
		Args:      args,
		Expect:    &extrun.Digests{Binary: m.ExecutableSHA256},
		Env:       env,
		Dir:       dirs.Project,
		Limits:    m.Limits.RunLimits(),
		CacheDir:  dirs.Cache,
		Engine:    &engine,
	}
	if m.Input == InputStdin {
		req.Stdin = spec.TargetsBody
	}
	spec.Request = req
	spec.OneShot = extrun.OneShotDirs{Project: dirs.Project, Output: dirs.Output, Cache: dirs.Cache, ProgramDirs: programDirs}
	return spec, nil
}

// HomeDir is the HOME a run without its own cache gets, for the caller to
// create before the run.
func HomeDir(goos string, dirs RunDirs) string { return join(goos, dirs.Cache, homeName) }

// hasControl reports a control or format character.
func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}
