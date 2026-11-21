package scalibrchild

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/secreachgo"
	"github.com/marmutapp/superbased-observer/internal/secreachgovuln"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// reach.go is the child's Go symbol check (OS and CI vulnerability
// scanning plan section 14.5 item 3b, spike RG-0 "Answer" step 1, component
// security.reach.go): after the match, for each Go binary the artifact
// extractors read (item 4: executables under bin/, dist/, target/release/
// and the --artifacts directories) whose packages matched an advisory, it
// runs govulncheck's binary mode in this process (internal/secreachgovuln)
// against the matched records written as a flat <id>.json directory, and
// decides each advisory through Observer's own table (internal/secreachgo,
// internal/secreach). A stripped binary is detected first and never run.
// No network (the database is a local directory), no toolchain (binary
// mode), inside the child's existing caps (RG-0 measured 80 to 192 MiB and
// under 2 s per real binary).

// MaxReachBinaries caps the binaries one scan checks; the rest are
// reported unknown (secreach.ReasonBinaryCap).
const MaxReachBinaries = 16

// reachTimeout bounds one binary's check.
var reachTimeout = 90 * time.Second

// maxReachOutput caps govulncheck's JSON stream for one binary.
const maxReachOutput = 32 << 20

// goEcosystem is the OSV ecosystem of Go modules and the standard library.
const goEcosystem = "Go"

// reachRunner is the govulncheck run and reachInspect the stripped check
// (a test swaps them).
var (
	reachRunner  = secreachgovuln.Run
	reachInspect = secreachgo.Inspect
)

// reachGo runs the symbol check over resp's Go binaries. It never changes
// resp's findings data; it only returns the runs.
func reachGo(ctx context.Context, req depscan.ChildRequest, resp depscan.ChildResponse) []secreach.SymbolRun {
	byBinary := map[string][]secreachgo.Advisory{}
	for _, e := range resp.Ecosystems {
		if e.Ecosystem != goEcosystem || e.Outcome != depscan.EcoScanned {
			continue
		}
		for _, a := range e.Advisories {
			if a.Index < 0 || a.Index >= len(resp.Packages) {
				continue
			}
			p := resp.Packages[a.Index]
			if !p.Artifact || p.Ecosystem != goEcosystem || !cleanRel(p.Path) {
				continue
			}
			byBinary[p.Path] = append(byBinary[p.Path], secreachgo.Advisory{ID: a.ID, Aliases: a.Aliases, Module: p.Name, Version: p.Version})
		}
	}
	if len(byBinary) == 0 {
		return nil
	}
	paths := make([]string, 0, len(byBinary))
	for p := range byBinary {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var ids []string
	for _, p := range paths {
		for _, a := range byBinary[p] {
			ids = append(ids, a.ID)
		}
	}
	db, records, cleanup, err := flatDatabase(req, ids)
	if cleanup != nil {
		defer cleanup()
	}
	out := make([]secreach.SymbolRun, 0, len(paths))
	for i, p := range paths {
		run := secreach.SymbolRun{Source: secreach.SourceGovulncheckBinary, Target: p}
		switch {
		case i >= MaxReachBinaries:
			run.Reason = secreach.ReasonBinaryCap
		case err != nil:
			run.Reason = secreach.ReasonSymbolCheckFailed
		default:
			run = checkBinary(ctx, req.Root, db, p, byBinary[p], records)
		}
		out = append(out, run)
	}
	return out
}

// flatDatabase reads the matched records out of the Go export and writes
// them as a flat directory under the run's scratch directory.
func flatDatabase(req depscan.ChildRequest, ids []string) (string, map[string]secreachgo.RecordImports, func(), error) {
	if req.DBDir == "" {
		return "", nil, nil, errors.New("no database directory")
	}
	raw, err := osvdb.ExportRecords(req.DBDir, goEcosystem, dedupe(ids))
	if err != nil {
		return "", nil, nil, err
	}
	dir, err := os.MkdirTemp(req.ScratchDir, "observer-reach-")
	if err != nil {
		return "", nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := osvdb.WriteFlatRecords(dir, raw); err != nil {
		return "", nil, cleanup, err
	}
	parsed := make(map[string]secreachgo.RecordImports, len(raw))
	for id, b := range raw {
		if r, err := secreachgo.ParseRecord(b); err == nil {
			parsed[id] = r
		}
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", nil, cleanup, err
	}
	return abs, parsed, cleanup, nil
}

// checkBinary inspects one binary and, when it keeps its symbols, runs
// govulncheck over it.
func checkBinary(ctx context.Context, root, db, rel string, advs []secreachgo.Advisory, records map[string]secreachgo.RecordImports) secreach.SymbolRun {
	run := secreach.SymbolRun{Source: secreach.SourceGovulncheckBinary, Target: rel}
	bin := filepath.Join(root, filepath.FromSlash(rel))
	f, err := os.Open(bin) //nolint:gosec // G304: a binary of the project the developer scans, under its root, that the artifact extractor already read
	if err != nil {
		run.Reason = secreach.ReasonSymbolCheckFailed
		return run
	}
	in := reachInspect(f)
	_ = f.Close()
	if !in.Checkable {
		run.Reason = in.Reason
		return run
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		run.Reason = secreach.ReasonSymbolCheckFailed
		return run
	}
	cctx, cancel := context.WithTimeout(ctx, reachTimeout)
	defer cancel()
	var stdout cappedBuffer
	stdout.max = maxReachOutput
	err = reachRunner(cctx, db, abs, &stdout, io.Discard)
	switch {
	case errors.Is(cctx.Err(), context.DeadlineExceeded):
		run.Reason = secreach.ReasonTimedOut
		return run
	case err != nil || stdout.over:
		run.Reason = secreach.ReasonSymbolCheckFailed
		return run
	}
	traces, err := secreachgo.ParseStream(bytes.NewReader(stdout.b.Bytes()))
	if err != nil {
		run.Reason = secreach.ReasonSymbolCheckFailed
		return run
	}
	run.Records = secreachgo.Verdicts(secreachgo.Input{Advisories: advs, Records: records, Traces: traces})
	return run
}

// cappedBuffer keeps at most max bytes and remembers it was passed.
type cappedBuffer struct {
	b    bytes.Buffer
	max  int
	over bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.over || c.b.Len()+len(p) > c.max {
		c.over = true
		return len(p), nil
	}
	return c.b.Write(p)
}

// cleanRel reports a clean project-relative path (forward slashes).
func cleanRel(p string) bool {
	if p == "" || strings.Contains(p, `\`) || path.IsAbs(p) {
		return false
	}
	c := path.Clean(p)
	return c == p && c != "." && c != ".." && !strings.HasPrefix(c, "../")
}

func dedupe(ids []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	if len(out) > osvdb.MaxExportRecords {
		out = out[:osvdb.MaxExportRecords]
	}
	return out
}
