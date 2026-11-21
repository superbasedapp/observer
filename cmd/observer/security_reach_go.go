//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/secreachgovuln"
	"github.com/marmutapp/superbased-observer/internal/secreachsvc"
	"github.com/marmutapp/superbased-observer/internal/secscan/depdriver"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// security_reach_go.go is the cmd seam of the Go symbol check, 3b-bin (OS
// and CI vulnerability scanning plan section 14.5 item 3b, spike RG-0,
// component security.reach.go): while the component is selected (opt-in,
// securityOptIn) and golang.org/x/vuln is compiled in, the linked
// dependency driver asks its scan child to run govulncheck's binary mode
// over each Go binary the artifact extractors read, and the child's answers
// are stored per project (secreachsvc.ReplaceSymbolRuns, the one owner of
// <security dir>/reach/). Every scan replaces the project's binary checks,
// so a scan that did not run the step (the component off, a build without
// x/vuln) clears them rather than leave an older build's answers. The
// views (the Code security page, get_security_findings) read them through
// secsignal. Nothing here makes a request or runs a toolchain.

// reachGoComponent is the component id.
const reachGoComponent = "security.reach.go"

// reachGoSelected reports whether this env's scans run the symbol check.
func (e *depsScanEnv) reachGoSelected() bool {
	return secreachgovuln.Compiled && securitySelected(componentSnapshotForConfig(e.cfg), reachGoComponent)
}

// wireReachGo sets the driver's symbol-check fields.
func (e *depsScanEnv) wireReachGo(env *depdriver.Env) {
	env.ReachGo = e.reachGoSelected()
	env.ReachScratch = reachScratch
	dir, logger := e.dir, e.logger
	env.ReachSink = func(root string, runs []secreach.SymbolRun, ran bool) {
		if !ran {
			runs = nil
		}
		if err := secreachsvc.ReplaceSymbolRuns(dir, secposture.ProjectRootHash(root), secreach.SourceGovulncheckBinary, nil, runs, time.Now()); err != nil && logger != nil {
			logger.Warn("security: the Go symbol checks could not be stored", "err", err)
		}
	}
}

// reachScratch is an unisolated child's writable directory: a fresh one
// under the per-user scan cache (outside ~/.observer), removed after the
// run.
func reachScratch() (string, func(), error) {
	base, err := depsScanCacheRoot()
	if err != nil {
		return "", nil, err
	}
	runs := filepath.Join(base, "runs")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp(runs, "reach-")
	if err != nil {
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// reachGoRunsAfterScan returns the project's stored binary checks after a
// CLI scan that ran the linked driver with the symbol check selected; nil
// otherwise (the opt-in component prints nothing when it is not chosen).
func (e *depsScanEnv) reachGoRunsAfterScan(root string, components []string) []secreach.SymbolRun {
	if !e.reachGoSelected() || !slices.Contains(components, depscan.ScalibrComponent) {
		return nil
	}
	runs := []secreach.SymbolRun{}
	for _, r := range secreachsvc.LoadSymbolRuns(e.dir, secposture.ProjectRootHash(root)) {
		if r.Source == secreach.SourceGovulncheckBinary {
			runs = append(runs, r)
		}
	}
	return runs
}

// writeReachGoSummary prints one line per checked binary: how many
// advisories a listed function of reaches, how many it does not, or why
// the binary could not be checked. Ranking and labels only: no finding
// changes.
func writeReachGoSummary(w io.Writer, runs []secreach.SymbolRun) {
	if runs == nil {
		return
	}
	if len(runs) == 0 {
		fmt.Fprintln(w, "Go symbol check (govulncheck-binary): no Go binary with a matched advisory under the artifact directories.")
		return
	}
	fmt.Fprintln(w, "Go symbol check (govulncheck-binary; ranks and labels only, `not called` is for that binary only):")
	for _, r := range runs {
		if r.Reason != "" {
			fmt.Fprintf(w, "  %s: not checked (%s)\n", r.Target, r.Reason.Text())
			continue
		}
		called, not := map[string]bool{}, map[string]bool{}
		for _, rec := range r.Records {
			key := rec.Module + "@" + rec.Version
			switch rec.Verdict {
			case secreach.VerdictCalled:
				called[key] = true
			case secreach.VerdictNotCalled:
				not[key] = true
			}
		}
		for k := range called {
			delete(not, k)
		}
		fmt.Fprintf(w, "  %s: %d packages with a listed function called, %d with none called\n", r.Target, len(called), len(not))
	}
}
