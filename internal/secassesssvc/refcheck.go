package secassesssvc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// The reference walk's budget (plan W1b): the validator opens up to a number of
// distinct files the agent named, reads at most so much in all, and stops
// looking at its deadline. A file past a limit is "unchecked", never "found",
// and the validation says so (state partial, a count on the card). The three
// numbers are settings (ref_budget_files, ref_budget_mib, ref_budget_seconds);
// these are their defaults. One file is read up to maxRefFileBytes whatever the
// settings, a structural bound on what a single source file may be.
const (
	maxRefFiles      = 500
	maxRefTotalBytes = 128 << 20
	maxRefFileBytes  = 4 << 20
	// RefDeadline is how long a validation may look at project files.
	RefDeadline = 10 * time.Second
)

// RefBudget is the limit of one reference walk.
type RefBudget struct {
	// Files is how many distinct files the walk opens.
	Files int
	// TotalBytes is how much it reads in all.
	TotalBytes int64
	// Deadline is how long it looks.
	Deadline time.Duration
}

// DefaultRefBudget is the budget when none is set.
func DefaultRefBudget() RefBudget {
	return RefBudget{Files: maxRefFiles, TotalBytes: maxRefTotalBytes, Deadline: RefDeadline}
}

// orDefault fills what is not set (zero or negative) with the default.
func (b RefBudget) orDefault() RefBudget {
	d := DefaultRefBudget()
	if b.Files <= 0 {
		b.Files = d.Files
	}
	if b.TotalBytes <= 0 {
		b.TotalBytes = d.TotalBytes
	}
	if b.Deadline <= 0 {
		b.Deadline = d.Deadline
	}
	return b
}

// FileStamp identifies a project file as the validation saw it, so a later
// read can say the file changed.
type FileStamp struct {
	Path  string `json:"path"`
	SHA   string `json:"sha"`
	Lines int    `json:"lines"`
}

// RefChecker implements secassess.RefChecker over a project root opened with
// os.Root: a symlink in the project cannot lead a read outside it, the final
// component must be a regular file (Lstat), the opened handle is checked
// again, and the open is non-blocking where the platform has one. Each file is
// read at most once and kept as lines.
type RefChecker struct {
	root     *os.Root
	deadline time.Time
	now      func() time.Time
	files    map[string]*refFile
	order    []string
	total    int64
	maxFiles int
	maxTotal int64
}

type refFile struct {
	st    secassess.LookupStatus
	lines []string
	sha   string
}

// NewRefChecker opens the project root. deadline is when the checker stops
// reading (the zero time: never); now is the clock (nil: time.Now).
func NewRefChecker(projectRoot string, deadline time.Time, now func() time.Time) (*RefChecker, error) {
	root, err := os.OpenRoot(projectRoot)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &RefChecker{root: root, deadline: deadline, now: now, files: map[string]*refFile{}, maxFiles: maxRefFiles, maxTotal: maxRefTotalBytes}, nil
}

// WithBudget sets the file and byte limits (the deadline is given to
// NewRefChecker). It returns c.
func (c *RefChecker) WithBudget(b RefBudget) *RefChecker {
	b = b.orDefault()
	c.maxFiles, c.maxTotal = b.Files, b.TotalBytes
	return c
}

// Close closes the project root.
func (c *RefChecker) Close() { _ = c.root.Close() }

// Lines implements secassess.RefChecker.
func (c *RefChecker) Lines(rel string, first, last int) ([]string, int, secassess.LookupStatus) {
	f := c.load(rel)
	if f.st != secassess.LookupOK {
		return nil, 0, f.st
	}
	total := len(f.lines)
	if first < 1 {
		first = 1
	}
	if last > total {
		last = total
	}
	if first > last {
		return nil, total, secassess.LookupOK
	}
	return f.lines[first-1 : last], total, secassess.LookupOK
}

// Files returns the stamps of the files that were read, in the order they were
// first asked for.
func (c *RefChecker) Files() []FileStamp {
	out := make([]FileStamp, 0, len(c.order))
	for _, p := range c.order {
		if f := c.files[p]; f.st == secassess.LookupOK {
			out = append(out, FileStamp{Path: p, SHA: f.sha, Lines: len(f.lines)})
		}
	}
	return out
}

func (c *RefChecker) load(rel string) *refFile {
	if f, ok := c.files[rel]; ok {
		return f
	}
	f := &refFile{}
	c.files[rel] = f
	c.order = append(c.order, rel)
	switch {
	case len(c.files) > c.maxFiles:
		f.st = secassess.LookupBudget
		return f
	case !c.deadline.IsZero() && c.now().After(c.deadline):
		f.st = secassess.LookupBudget
		return f
	}
	data, st := c.read(rel)
	f.st = st
	if st != secassess.LookupOK {
		return f
	}
	sum := sha256.Sum256(data)
	f.sha = hex.EncodeToString(sum[:8])
	f.lines = splitLines(data)
	return f
}

// read opens one project file safely and returns its bytes.
func (c *RefChecker) read(rel string) ([]byte, secassess.LookupStatus) {
	name := filepath.FromSlash(rel)
	fi, err := c.root.Lstat(name)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, secassess.LookupMissing
	}
	if fi.Size() > maxRefFileBytes || c.total+fi.Size() > c.maxTotal {
		return nil, secassess.LookupBudget
	}
	fh, err := c.root.OpenFile(name, openFlags, 0)
	if err != nil {
		return nil, secassess.LookupMissing
	}
	defer func() { _ = fh.Close() }()
	st, err := fh.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, secassess.LookupMissing
	}
	if st.Size() > maxRefFileBytes || c.total+st.Size() > c.maxTotal {
		return nil, secassess.LookupBudget
	}
	data, err := io.ReadAll(io.LimitReader(fh, maxRefFileBytes+1))
	if err != nil {
		return nil, secassess.LookupMissing
	}
	if len(data) > maxRefFileBytes {
		return nil, secassess.LookupBudget
	}
	c.total += int64(len(data))
	return data, secassess.LookupOK
}

// splitLines splits a file into lines without their terminators ("\n" or
// "\r\n"); a final line with no terminator counts, an empty file has no lines.
func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	parts := strings.Split(string(data), "\n")
	for i, p := range parts {
		parts[i] = strings.TrimSuffix(p, "\r")
	}
	return parts
}

// StampsDrift is StampsDriftWithin under the default budget.
func StampsDrift(projectRoot string, stamps []FileStamp) ([]string, error) {
	return StampsDriftWithin(projectRoot, stamps, DefaultRefBudget())
}

// StampsDriftWithin returns the paths of stamped files that no longer read the
// way they did when the model was validated (changed, gone or no longer a
// regular file). It uses the same safe open as the checker, under the budget
// the validation ran with (the file limit is raised to the number of stamps, so
// a file the validation read is always looked at again).
func StampsDriftWithin(projectRoot string, stamps []FileStamp, budget RefBudget) ([]string, error) {
	rep, err := StampsDriftReport(projectRoot, stamps, budget)
	return rep.Changed, err
}

// DriftReport is the outcome of looking at the stamped files again.
type DriftReport struct {
	// Changed are the stamped files that read differently now (changed, gone or
	// no longer a regular file).
	Changed []string
	// Unread are the stamped files the read budget ran out on: they are neither
	// known to be unchanged nor known to have changed.
	Unread []string
}

// StampsDriftReport is StampsDriftWithin that also names the files it could not
// look at, so a caller can say "unknown" instead of "unchanged".
func StampsDriftReport(projectRoot string, stamps []FileStamp, budget RefBudget) (DriftReport, error) {
	var rep DriftReport
	if len(stamps) == 0 {
		return rep, nil
	}
	budget = budget.orDefault()
	budget.Files = max(budget.Files, len(stamps))
	c, err := NewRefChecker(projectRoot, time.Now().Add(budget.Deadline), nil)
	if err == nil {
		c.WithBudget(budget)
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			for _, s := range stamps {
				rep.Changed = append(rep.Changed, s.Path)
			}
			return rep, nil
		}
		return rep, err
	}
	defer c.Close()
	for _, s := range stamps {
		f := c.load(s.Path)
		switch {
		case f.st == secassess.LookupBudget:
			rep.Unread = append(rep.Unread, s.Path)
		case f.st != secassess.LookupOK || f.sha != s.SHA:
			rep.Changed = append(rep.Changed, s.Path)
		}
	}
	return rep, nil
}
