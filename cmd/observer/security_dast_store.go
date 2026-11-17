//go:build !sbo_omit_security && !sbo_omit_security_dast

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/secdast"
	"github.com/marmutapp/superbased-observer/internal/secdastnet"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_dast_store.go stores passive DAST runs against a project
// (security coverage gaps plan item 1): the run's findings go through
// secsvc.RecordRun, the one writer of findings, and a small per-project
// record (<security dir>/dast/<project_root_hash>.json, owner-only, written
// only here) remembers each origin's last complete run: the local keys it
// reported, its time and outcome. A complete run closes, as not
// reproduced, exactly the keys this origin reported before and not now
// (Gone.Removed): a DAST finding has no file and its local key is a digest,
// so neither a path nor the key can name the origin. The origin is never
// written to sec_scan_runs or anything shipped to an org. It also lists a
// project's dev-server candidates (the project's own files, and on Linux
// the kernel's listen table, never a dial).

// dastRecordMaxOrigins caps the origins one project's record keeps (the
// oldest run is dropped first).
const dastRecordMaxOrigins = 32

// dastOriginRecord is one origin's last run.
type dastOriginRecord struct {
	Keys     []string  `json:"keys"`
	At       time.Time `json:"at"`
	Outcome  string    `json:"outcome"`
	Findings int       `json:"findings"`
}

// dastProjectRecord is one project's record.
type dastProjectRecord struct {
	Version int                         `json:"version"`
	Origins map[string]dastOriginRecord `json:"origins"`
}

func dastRecordPath(secDir, rootHash string) string {
	return filepath.Join(secDir, "dast", rootHash+".json")
}

func loadDASTRecord(secDir, rootHash string) dastProjectRecord {
	rec := dastProjectRecord{Version: 1, Origins: map[string]dastOriginRecord{}}
	b, err := os.ReadFile(dastRecordPath(secDir, rootHash)) //nolint:gosec // G304: our own record under the security directory.
	if err != nil || len(b) > 1<<20 {
		return rec
	}
	var got dastProjectRecord
	if json.Unmarshal(b, &got) != nil || got.Version != 1 || got.Origins == nil {
		return rec
	}
	return got
}

func saveDASTRecord(secDir, rootHash string, rec dastProjectRecord) error {
	if len(rec.Origins) > dastRecordMaxOrigins {
		origins := make([]string, 0, len(rec.Origins))
		for o := range rec.Origins {
			origins = append(origins, o)
		}
		sort.Slice(origins, func(i, j int) bool { return rec.Origins[origins[i]].At.Before(rec.Origins[origins[j]].At) })
		for _, o := range origins[:len(origins)-dastRecordMaxOrigins] {
			delete(rec.Origins, o)
		}
	}
	path := dastRecordPath(secDir, rootHash)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("dast record: %w", err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("dast record: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dast-*.json")
	if err != nil {
		return fmt.Errorf("dast record: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("dast record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("dast record: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("dast record: %w", err)
	}
	return nil
}

// dastCoverageOutcome maps a run outcome onto the scan-run outcome: a
// complete or partial run (the page answered) is clean or findings; an
// unreachable page is unknown, which closes nothing and never reads clean.
func dastCoverageOutcome(rep secdast.Report, findings int) secscan.Outcome {
	switch {
	case rep.Outcome == secdast.OutcomeUnreachable:
		return secscan.OutcomeUnknown
	case findings > 0:
		return secscan.OutcomeFindings
	}
	return secscan.OutcomeClean
}

// recordDASTRun stores one run's findings against the project and updates
// the project's DAST record. Only a complete run closes anything (a
// partial run did not hear every probe, so a missing finding proves
// nothing). It returns how many findings were new.
func recordDASTRun(ctx context.Context, st secsvc.RunStore, secDir, projectRoot string, t secdast.Target, rep secdast.Report, findings []secfinding.Finding, started time.Time, took time.Duration) (int, error) {
	hash := secposture.ProjectRootHash(projectRoot)
	if hash == "" {
		return 0, errors.New("dast: no project to record against")
	}
	origin := t.Origin()
	rec := loadDASTRecord(secDir, hash)
	keys := make([]string, 0, len(findings))
	for _, f := range findings {
		keys = append(keys, f.LocalKey)
	}
	gone := secsvc.Gone{}
	if rep.Outcome == secdast.OutcomeComplete {
		gone.Pack = secdast.Driver
		for _, k := range rec.Origins[origin].Keys {
			if !slices.Contains(keys, k) {
				gone.Removed = append(gone.Removed, store.SecSighting{Key: k, Path: ""})
			}
		}
		if len(gone.Removed) > 256 {
			gone.Removed = gone.Removed[:256]
		}
	}
	res := secscan.Result{
		Findings: findings,
		Coverage: secscan.Coverage{Outcome: dastCoverageOutcome(rep, len(findings)), FilesScanned: 0},
		Engine:   secscan.EngineIdentity{Name: secdast.Driver, Version: secdast.Version, RulePackVersion: secdast.Version},
	}
	if rep.Outcome == secdast.OutcomeUnreachable {
		res.Coverage.Reason = "unreachable"
	}
	target := secscan.Target{ProjectRoot: projectRoot, Scope: policy.FindingScopeManual}
	created, err := secsvc.RecordRun(ctx, st, target, res, started, took, gone, nil)
	if err != nil {
		return created, err
	}
	if rep.Outcome != secdast.OutcomeUnreachable {
		prev := rec.Origins[origin]
		if rep.Outcome == secdast.OutcomePartial {
			// A partial run keeps what the last complete run saw, plus what
			// it saw itself.
			for _, k := range prev.Keys {
				if !slices.Contains(keys, k) {
					keys = append(keys, k)
				}
			}
		}
		rec.Origins[origin] = dastOriginRecord{Keys: keys, At: started.UTC(), Outcome: rep.Outcome, Findings: len(findings)}
		if err := saveDASTRecord(secDir, hash, rec); err != nil {
			return created, err
		}
	}
	return created, nil
}

// dastRun is one run through the lane: the report, its findings (stamped
// with the project when there is one) and the round trips made.
type dastRun struct {
	Report     secdast.Report
	Findings   []secfinding.Finding
	RoundTrips int
	Started    time.Time
	Took       time.Duration
}

// runDASTLane runs the checks against t under the run timeout.
func runDASTLane(ctx context.Context, t secdast.Target, opts secdastnet.Options, now time.Time) (dastRun, error) {
	ctx, cancel := context.WithTimeout(ctx, secdast.RunTimeout)
	defer cancel()
	client, err := secdastnet.New(ctx, t, opts)
	if err != nil {
		return dastRun{}, err
	}
	defer client.Close()
	start := time.Now()
	rep := secdast.Run(ctx, t, dastToken(), client.Fetch)
	return dastRun{
		Report:     rep,
		Findings:   secdast.Findings(t, rep.Hits, now, scrub.New().String),
		RoundTrips: client.RoundTrips(),
		Started:    now,
		Took:       time.Since(start),
	}, nil
}

// readDASTProjectFiles reads the project files the candidate table names,
// each capped (secdast.MaxProjectFile); missing files are skipped.
func readDASTProjectFiles(root string) []secdast.ProjectFile {
	var out []secdast.ProjectFile
	read := func(rel string) {
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel))) //nolint:gosec // G304: the project's own files, read and parsed only.
		if err != nil {
			return
		}
		defer func() { _ = f.Close() }()
		if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
			return
		}
		b, err := io.ReadAll(io.LimitReader(f, secdast.MaxProjectFile+1))
		if err != nil || len(b) > secdast.MaxProjectFile {
			return
		}
		out = append(out, secdast.ProjectFile{Rel: rel, Data: b})
	}
	for _, rel := range secdast.DevServerFiles {
		prefix, isPrefix := strings.CutSuffix(rel, "*")
		if !isPrefix {
			read(rel)
			continue
		}
		entries, err := os.ReadDir(filepath.Join(root, filepath.Dir(filepath.FromSlash(prefix))))
		if err != nil {
			continue
		}
		base := filepath.Base(prefix)
		for _, e := range entries {
			if !e.IsDir() && strings.HasPrefix(e.Name(), base) {
				read(filepath.ToSlash(filepath.Join(filepath.Dir(prefix), e.Name())))
			}
		}
	}
	return out
}

// dastListenTable reads the kernel's listen table where the operating
// system exposes one without a dial (Linux /proc); ok false elsewhere.
func dastListenTable() (ports []int, ok bool) {
	if runtime.GOOS != "linux" {
		return nil, false
	}
	var bodies []string
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if b, err := os.ReadFile(p); err == nil {
			bodies = append(bodies, string(b))
		}
	}
	if len(bodies) == 0 {
		return nil, false
	}
	return secdast.ListeningPorts(bodies...), true
}

// dastProjectCandidates lists a project's dev-server candidates, each
// marked listening where the kernel's table says so. Nothing is dialed.
func dastProjectCandidates(root string) []secdast.Candidate {
	cands := secdast.ProjectCandidates(readDASTProjectFiles(root))
	ports, ok := dastListenTable()
	if !ok {
		return cands
	}
	for i := range cands {
		cands[i].Listening = "no"
		if slices.Contains(ports, secdast.CandidatePort(cands[i].URL)) {
			cands[i].Listening = "yes"
		}
	}
	return cands
}
