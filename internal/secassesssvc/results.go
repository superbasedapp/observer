package secassesssvc

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// The caps on one result file read.
const (
	MaxReportBytes   = 512 << 10
	MaxCommandsBytes = 64 << 10
)

// Errors a result read can return.
var (
	// ErrAbsent: the file does not exist.
	ErrAbsent = errors.New("secassesssvc: the file is not there")
	// ErrNotRegular: the path is a link, a directory, a device or a pipe.
	ErrNotRegular = errors.New("secassesssvc: the path is not a regular file")
	// ErrTooLarge: the file is over its cap.
	ErrTooLarge = errors.New("secassesssvc: the file is over its size cap")
)

// ReadResult reads one fixed project-relative file (a result path
// secassess.ResultPaths returned, or .claude/launch.json), at most max bytes;
// rel is never taken from a client. The project root is opened with
// os.OpenRoot, so nothing an agent wrote can lead the read outside the
// project; the final component is Lstat-ed and a link is refused (os.Root
// follows a link that stays inside the root), and the opened handle is
// checked to be a regular file again.
func ReadResult(projectRoot, rel string, max int64) ([]byte, error) {
	data, _, err := readResultStat(projectRoot, rel, max)
	return data, err
}

// readResultStat is ReadResult that also returns the opened file's info (its
// size and modification time), for a caller that records which file it read.
// The open is non-blocking where the platform has one: the result files are
// fixed paths, but an agent controls what sits at them.
func readResultStat(projectRoot, rel string, max int64) ([]byte, os.FileInfo, error) {
	if projectRoot == "" || rel == "" {
		return nil, nil, ErrAbsent
	}
	root, err := os.OpenRoot(projectRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, ErrAbsent
		}
		return nil, nil, fmt.Errorf("secassesssvc.ReadResult: %w", err)
	}
	defer func() { _ = root.Close() }()
	return readFromRoot(root, rel, max)
}

// readFromRoot is the confined read itself, on an open project root: the final
// component is Lstat-ed (a link is refused), opened without blocking, and the
// opened handle is checked to be a regular file again before it is read. It is
// the one place that read lives (the request helper's writer uses it too).
func readFromRoot(root *os.Root, rel string, max int64) ([]byte, os.FileInfo, error) {
	fi, err := root.Lstat(rel)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, ErrAbsent
		}
		return nil, nil, fmt.Errorf("secassesssvc.ReadResult: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, ErrNotRegular
	}
	f, err := root.OpenFile(rel, openFlags, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, ErrAbsent
		}
		return nil, nil, fmt.Errorf("secassesssvc.ReadResult: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("secassesssvc.ReadResult: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, nil, ErrNotRegular
	}
	if st.Size() > max {
		return nil, st, ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, nil, fmt.Errorf("secassesssvc.ReadResult: %w", err)
	}
	if int64(len(data)) > max {
		return nil, st, ErrTooLarge
	}
	return data, st, nil
}

// present reports whether rel is a non-empty regular file under the root.
func present(root *os.Root, rel string) (bool, int64) {
	fi, err := root.Lstat(rel)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
		return false, 0
	}
	return true, fi.Size()
}

// View is a run with what its directory holds now.
type View struct {
	Run   Run
	State secassess.State
	Files secassess.FilesPresent
	// ReportBytes is the report's size.
	ReportBytes int64
	// Cloud is the classified commands.txt (a kind that writes one).
	Cloud *secassess.CloudCounts
	// ProjectGone: the project's folder could not be read.
	ProjectGone bool
	// ModelStale: assessment.json is not the file the recorded validation
	// looked at (its size or time differ), so the validation is out of date.
	ModelStale bool
}

// stateOf derives the run's state under the contract it was launched under,
// then folds in whether its terminal has ended: a run that is over and wrote
// nothing is "ended_empty", never "started" (a launch that died within seconds
// read "running" for hours otherwise).
func (v *View) stateOf(imp secassess.ImportOutcome) secassess.State {
	ended := !v.Run.EndedAt.IsZero()
	if secassess.Contract(v.Run.Contract).Schema() == "" {
		return secassess.StateWhenEnded(secassess.StateOf(v.Files, imp), ended)
	}
	m := secassess.ModelState{Stale: v.ModelStale}
	if r := v.Run.Validation; r != nil {
		m.Validation = secassess.ValidationState(r.State)
	}
	return secassess.StateWhenEnded(secassess.StateOfModel(v.Files, m, imp), ended)
}

// modelStat reports whether rel is a non-empty regular file under the root, with
// its size and modification time (Unix nanoseconds).
func modelStat(root *os.Root, rel string) (ok bool, size, mod int64) {
	fi, err := root.Lstat(rel)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
		return false, 0, 0
	}
	return true, fi.Size(), fi.ModTime().UnixNano()
}

// Describe derives a run's view from its directory under projectRoot ("" when
// the project's folder is not known: every file reads as absent).
func Describe(projectRoot string, r Run) View {
	v := View{Run: r}
	paths := secassess.ResultPaths(r.ID)
	var imp secassess.ImportOutcome
	if r.Import != nil {
		imp = secassess.ImportOutcome(r.Import.Outcome)
	}
	if projectRoot == "" || paths.Dir == "" {
		v.ProjectGone = true
		v.State = v.stateOf(imp)
		return v
	}
	root, err := os.OpenRoot(projectRoot)
	if err != nil {
		v.ProjectGone = true
		v.State = v.stateOf(imp)
		return v
	}
	defer func() { _ = root.Close() }()
	v.Files.Report, v.ReportBytes = present(root, paths.Report)
	v.Files.SARIF, _ = present(root, paths.SARIF)
	v.Files.Commands, _ = present(root, paths.Commands)
	var size, mod int64
	v.Files.Model, size, mod = modelStat(root, paths.Model)
	if rec := r.Validation; rec != nil && v.Files.Model {
		v.ModelStale = rec.ModelBytes != size || (rec.ModelMod != 0 && rec.ModelMod != mod)
	}
	v.State = v.stateOf(imp)
	if v.Files.Commands {
		if body, err := ReadResult(projectRoot, paths.Commands, MaxCommandsBytes); err == nil {
			c := secassess.CountCloudCommands(string(body))
			v.Cloud = &c
		}
	}
	return v
}
