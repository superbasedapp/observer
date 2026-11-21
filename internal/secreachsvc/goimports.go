package secreachsvc

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secreach"
)

// Limits bound the imports-only parse. A bound that is hit stops the scan
// and makes the list incomplete (ScanStats.Stopped), never silently short.
type Limits struct {
	// MaxFiles caps the .go files read.
	MaxFiles int
	// MaxDirs caps the directories walked.
	MaxDirs int
	// HeadBytes is the first read of a file; the whole file is read only
	// when its imports run past it.
	HeadBytes int
	// MaxFileBytes caps a whole-file read; a file whose imports need more
	// is a parse error.
	MaxFileBytes int64
	// Timeout caps the whole scan.
	Timeout time.Duration
	// Workers is the number of parallel file readers (0: GOMAXPROCS).
	Workers int
}

// DefaultLimits are the bounds Tiers uses unless WithLimits says
// otherwise.
func DefaultLimits() Limits {
	return Limits{
		MaxFiles:     50000,
		MaxDirs:      50000,
		HeadBytes:    4 << 10,
		MaxFileBytes: 2 << 20,
		Timeout:      5 * time.Second,
	}
}

// Stopped reasons (ScanStats.Stopped).
const (
	StoppedMaxFiles = "max_files"
	StoppedMaxDirs  = "max_dirs"
	StoppedTimeout  = "timeout"
	StoppedCanceled = "canceled"
	StoppedNoRoot   = "no_root"
)

// ScanStats are the counters of one scan (for the doctor and the timing
// reports).
type ScanStats struct {
	Dirs        int
	Files       int
	TestFiles   int
	FullReads   int
	ParseErrors int
	Bytes       int64
	Elapsed     time.Duration
	// Stopped is the bound that stopped the scan, "" when it ran to the
	// end.
	Stopped string
}

// ModuleImports is one Go module's imports: the files under its directory
// (its nested modules excluded).
type ModuleImports struct {
	// Dir is the module directory relative to the project root, slash form,
	// "" for the root.
	Dir string
	// Uses maps an import path to its use.
	Uses map[string]secreach.Use
	// Incomplete: a file of the module did not parse (or, for codeintel, a
	// site could not be placed).
	Incomplete bool
	// Modules are the module paths go.mod and go.sum name.
	Modules []string
}

// GoImports is a project's Go import list per module.
type GoImports struct {
	// Source is secreach.SourceGoImports or secreach.SourceCodeIntel.
	Source  string
	Root    string
	Modules map[string]*ModuleImports
	Stats   ScanStats
}

// skipDir reports a directory the go command (or any build) never
// compiles from the project: vendor/, testdata/, node_modules/, and names
// starting with "_" or ".".
func skipDir(name string) bool {
	return name == "vendor" || name == "testdata" || name == "node_modules" ||
		strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".")
}

// goSourceFile reports a .go file the go command reads (not "_" or "."
// prefixed).
func goSourceFile(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasPrefix(name, "_") && !strings.HasPrefix(name, ".")
}

// isTestFile reports a Go test file.
func isTestFile(name string) bool { return strings.HasSuffix(name, "_test.go") }

type goJob struct {
	abs, mod string
	test     bool
}

type goResult struct {
	mod      string
	test     bool
	imports  []string
	bytes    int64
	fullRead bool
	err      error
}

// ScanGoImports runs the bounded imports-only parse of the .go files under
// root. It returns an error only when root is not a readable directory;
// every other problem (a bound, an unreadable or unparsable file) is in the
// result as incompleteness.
func ScanGoImports(ctx context.Context, root string, lim Limits) (*GoImports, error) {
	start := time.Now()
	lim = lim.withDefaults()
	out := &GoImports{Source: secreach.SourceGoImports, Root: root, Modules: map[string]*ModuleImports{}}
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		if err == nil {
			err = errors.New("not a directory")
		}
		return nil, fmt.Errorf("secreachsvc.ScanGoImports: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()

	jobs := make(chan goJob, 256)
	results := make(chan goResult, 256)
	var wg sync.WaitGroup
	for i := 0; i < lim.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					continue
				}
				imps, n, full, err := readImports(j.abs, lim)
				results <- goResult{mod: j.mod, test: j.test, imports: imps, bytes: n, fullRead: full, err: err}
			}
		}()
	}
	// The walker owns its summary; it is read only after results closes
	// (which happens after the walk returned), so out has one writer.
	var walk walkSummary
	go func() {
		walk = walkGo(ctx, root, lim, jobs)
		close(jobs)
		wg.Wait()
		close(results)
	}()
	for r := range results {
		m := out.module(r.mod)
		out.Stats.Bytes += r.bytes
		if r.fullRead {
			out.Stats.FullReads++
		}
		if r.err != nil {
			out.Stats.ParseErrors++
			m.Incomplete = true
			continue
		}
		for _, p := range r.imports {
			u := m.Uses[p]
			if r.test {
				u.Test = true
			} else {
				u.NonTest = true
			}
			m.Uses[p] = u
		}
	}
	out.Stats.Stopped = walk.stopped
	out.Stats.Dirs, out.Stats.Files, out.Stats.TestFiles = walk.dirs, walk.files, walk.testFiles
	out.module("")
	for _, dir := range walk.modules {
		out.module(dir)
	}
	for _, dir := range walk.unreadable {
		out.module(dir).Incomplete = true
	}
	if out.Stats.Stopped == "" {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			out.Stats.Stopped = StoppedTimeout
		case ctx.Err() != nil:
			out.Stats.Stopped = StoppedCanceled
		}
	}
	for dir, m := range out.Modules {
		m.Modules = readModulePaths(filepath.Join(root, filepath.FromSlash(dir)))
	}
	out.Stats.Elapsed = time.Since(start)
	return out, nil
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFiles <= 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxDirs <= 0 {
		l.MaxDirs = d.MaxDirs
	}
	if l.HeadBytes <= 0 {
		l.HeadBytes = d.HeadBytes
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.Timeout <= 0 {
		l.Timeout = d.Timeout
	}
	if l.Workers <= 0 {
		l.Workers = runtime.GOMAXPROCS(0)
	}
	return l
}

// module returns (creating) the module entry of dir.
func (g *GoImports) module(dir string) *ModuleImports {
	m, ok := g.Modules[dir]
	if !ok {
		m = &ModuleImports{Dir: dir, Uses: map[string]secreach.Use{}}
		g.Modules[dir] = m
	}
	return m
}

// walkSummary is what the walk found besides the files it sent.
type walkSummary struct {
	stopped                string
	dirs, files, testFiles int
	modules, unreadable    []string
}

// walkGo walks root depth first, sending each Go source file with the
// module directory it belongs to; the summary names the nested module
// directories, the directories it could not read and the bound that
// stopped it ("" when none).
func walkGo(ctx context.Context, root string, lim Limits, jobs chan<- goJob) (sum walkSummary) {
	type frame struct{ rel, mod string }
	stack := []frame{{rel: "", mod: ""}}
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			sum.stopped = StoppedCanceled
			if errors.Is(err, context.DeadlineExceeded) {
				sum.stopped = StoppedTimeout
			}
			return sum
		}
		fr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if sum.dirs >= lim.MaxDirs {
			sum.stopped = StoppedMaxDirs
			return sum
		}
		sum.dirs++
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(fr.rel)))
		if err != nil {
			sum.unreadable = append(sum.unreadable, fr.mod)
			continue
		}
		mod := fr.mod
		for _, e := range entries {
			if e.Name() == "go.mod" && e.Type().IsRegular() && fr.rel != "" {
				mod = fr.rel
				sum.modules = append(sum.modules, mod)
				break
			}
		}
		var subdirs []string
		for _, e := range entries {
			name := e.Name()
			switch {
			case e.Type()&os.ModeSymlink != 0:
				// Never followed: a link may leave the project.
			case e.IsDir():
				if !skipDir(name) {
					subdirs = append(subdirs, name)
				}
			case e.Type().IsRegular() && goSourceFile(name):
				if sum.files >= lim.MaxFiles {
					sum.stopped = StoppedMaxFiles
					return sum
				}
				sum.files++
				test := isTestFile(name)
				if test {
					sum.testFiles++
				}
				select {
				case jobs <- goJob{abs: filepath.Join(root, filepath.FromSlash(fr.rel), name), mod: mod, test: test}:
				case <-ctx.Done():
					sum.stopped = StoppedTimeout
					return sum
				}
			}
		}
		for i := len(subdirs) - 1; i >= 0; i-- {
			stack = append(stack, frame{rel: path.Join(fr.rel, subdirs[i]), mod: mod})
		}
	}
	return sum
}

// readImports parses a file's imports from its head, reading the whole
// file (up to MaxFileBytes) only when the head does not parse.
func readImports(abs string, lim Limits) (imports []string, n int64, full bool, err error) {
	f, err := os.Open(abs)
	if err != nil {
		return nil, 0, false, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, lim.HeadBytes)
	k, rerr := io.ReadFull(f, buf)
	n = int64(k)
	atEOF := errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF)
	if rerr != nil && !atEOF {
		return nil, n, false, rerr
	}
	imports, perr := parseImports(buf[:k])
	if perr == nil || atEOF {
		return imports, n, false, perr
	}
	rest, rerr := io.ReadAll(io.LimitReader(f, lim.MaxFileBytes-n+1))
	n += int64(len(rest))
	if rerr != nil {
		return nil, n, true, rerr
	}
	if n > lim.MaxFileBytes {
		return nil, n, true, errors.New("imports past the file size cap")
	}
	imports, perr = parseImports(append(buf[:k], rest...))
	return imports, n, true, perr
}

// parseImports is the imports-only parse of one source.
func parseImports(src []byte) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "", src, parser.ImportsOnly|parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(file.Imports))
	for _, spec := range file.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// Caps on the module files read for the build graph's module paths.
const (
	maxGoModBytes = 1 << 20
	maxGoSumBytes = 16 << 20
)

// readModulePaths returns the module paths dir's go.mod (its module and
// requires) and go.sum name, sorted and deduplicated; nil when neither
// reads.
func readModulePaths(dir string) []string {
	seen := map[string]bool{}
	if b, err := readCapped(filepath.Join(dir, "go.mod"), maxGoModBytes); err == nil {
		for _, p := range goModPaths(string(b)) {
			seen[p] = true
		}
	}
	if b, err := readCapped(filepath.Join(dir, "go.sum"), maxGoSumBytes); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if fields := strings.Fields(line); len(fields) >= 2 {
				seen[fields[0]] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// goModPaths reads the module line and the require paths of a go.mod
// (single-line and block form; comments dropped).
func goModPaths(src string) []string {
	var out []string
	inRequire := false
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch {
		case inRequire && fields[0] == ")":
			inRequire = false
		case inRequire:
			out = append(out, unquotePath(fields[0]))
		case fields[0] == "module" && len(fields) >= 2:
			out = append(out, unquotePath(fields[1]))
		case fields[0] == "require" && len(fields) >= 2 && fields[1] == "(":
			inRequire = true
		case fields[0] == "require" && len(fields) >= 3:
			out = append(out, unquotePath(fields[1]))
		}
	}
	return out
}

func unquotePath(s string) string {
	if u, err := strconv.Unquote(s); err == nil {
		return u
	}
	return s
}

// readCapped reads a regular file of at most limit bytes.
func readCapped(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file over its cap")
	}
	return b, nil
}
