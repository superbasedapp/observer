package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seccorpus"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
)

// repoStatus is one repository's row of the run record.
type repoStatus struct {
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
	Cloned bool   `json:"cloned"`
	// Outcome is the driver's coverage outcome; empty when not scanned.
	Outcome      string `json:"outcome,omitempty"`
	Reason       string `json:"reason,omitempty"`
	FilesScanned int    `json:"files_scanned,omitempty"`
	// Partial counts files Opengrep did not parse in full.
	Partial   int  `json:"partially_parsed,omitempty"`
	Truncated bool `json:"truncated,omitempty"`
	// PrivateOnly counts this repository's findings under its private-only
	// trees: they are counted and dropped, so no corpus file names them.
	PrivateOnly int `json:"private_only_dropped,omitempty"`
	Findings    int `json:"findings,omitempty"`
	Seconds     int `json:"seconds,omitempty"`
}

// runRecord is corpus/run.json.
type runRecord struct {
	Date         string         `json:"date"`
	Engine       string         `json:"engine"`
	EngineDigest string         `json:"engine_digest"`
	PackVersion  string         `json:"pack_version"`
	PackDigest   string         `json:"pack_digest"`
	Platform     string         `json:"platform"`
	Repos        []repoStatus   `json:"repos"`
	Candidates   int            `json:"candidates"`
	Excluded     map[string]int `json:"excluded"`
	// DroppedInvalid and DroppedDuplicate are the findings dedupe dropped:
	// those that failed Validate and repeats of one rule on one line. The
	// committed run.json predates them (lane SEC-G3's run of 2026-10-21).
	DroppedInvalid   int `json:"dropped_invalid"`
	DroppedDuplicate int `json:"dropped_duplicate"`
}

// memState is the driver's state for one corpus run.
type memState struct{ s opengrep.State }

func (m *memState) Load() (opengrep.State, error) { return m.s, nil }
func (m *memState) Save(s opengrep.State) error   { m.s = s; return nil }

// readCapped reads at most limit bytes of a file.
func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", path, limit)
	}
	return b, nil
}

// writePack writes the pack's files under dir.
func writePack(pack *secrulepack.Pack, dir string) error {
	for name, b := range pack.Files() {
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// scanAll scans every cloned repository through the G1 driver and writes
// the candidates, the per-rule counts and the run record.
func scanAll(p paths, dest, bin string, jobs int) error {
	if dest == "" || bin == "" {
		return fmt.Errorf("scan: -dest and -opengrep are required")
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		return err
	}
	// The driver resolves Opengrep by name through the runner's resolver;
	// the pinned binary's directory goes first on PATH for this process.
	if filepath.Base(abs) != "opengrep" {
		return fmt.Errorf("scan: the binary must be named opengrep (got %s)", filepath.Base(abs))
	}
	if err := os.Setenv("PATH", filepath.Dir(abs)+string(os.PathListSeparator)+os.Getenv("PATH")); err != nil {
		return err
	}
	digest, err := sha256File(abs)
	if err != nil {
		return err
	}
	pack, err := secrulepack.Floor()
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp(dest, "scan-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	packDir := filepath.Join(work, "pack")
	if err := writePack(pack, packDir); err != nil {
		return err
	}
	repos, err := readRepos(p.file("repos.tsv"))
	if err != nil {
		return err
	}
	var cloned []repoStatus
	_ = readJSON(p.file("clone.json"), &cloned)
	clonedOK := map[string]bool{}
	for _, c := range cloned {
		clonedOK[c.Repo+"@"+c.Commit] = c.Cloned
	}
	rec := runRecord{
		Date: time.Now().UTC().Format("2006-01-02"), Engine: "opengrep " + "1.30.1", EngineDigest: digest,
		PackVersion: pack.Version(), PackDigest: pack.Digest(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
	st := &memState{}
	var all []seccorpus.Finding
	for _, r := range repos {
		row := repoStatus{Repo: r.URL, Commit: r.Commit, Cloned: clonedOK[r.URL+"@"+r.Commit]}
		dir := filepath.Join(dest, r.dir())
		if head, err := git(context.Background(), dir, "rev-parse", "HEAD"); err != nil || head != r.Commit {
			row.Cloned = false
			if row.Reason == "" {
				row.Reason = "clone_failed: not at the pinned commit"
			}
			rec.Repos = append(rec.Repos, row)
			fmt.Printf("%-60s not cloned\n", r.URL)
			continue
		}
		row.Cloned = true
		var private []string
		if r.URL == selfURL {
			if private, err = privateOnlyPaths(dir); err != nil {
				return fmt.Errorf("scan: this repository's private-only paths: %w", err)
			}
		}
		out, err := os.MkdirTemp(work, "run-")
		if err != nil {
			return err
		}
		d := opengrep.New(opengrep.Env{
			Runner: extrunhost.NewRunner(extrunhost.Options{}),
			Pack:   pack, PackDir: packDir, CacheDir: filepath.Join(work, "engine"), OutDir: out,
			State: st, ReadFile: readCapped, Jobs: jobs, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		})
		start := time.Now()
		res, _, err := d.ScanFiles(context.Background(), secscan.Target{ProjectRoot: dir, Scope: policy.FindingScopeManual})
		row.Seconds = int(time.Since(start).Seconds())
		_ = os.RemoveAll(out)
		if err != nil {
			row.Reason = "scan_error: " + firstLine(err.Error())
		}
		row.Outcome, row.FilesScanned, row.Truncated = string(res.Coverage.Outcome), res.Coverage.FilesScanned, res.Coverage.Truncated
		if row.Reason == "" {
			row.Reason = res.Coverage.Reason
		}
		for _, s := range res.Coverage.Skipped {
			if s.Reason == "partially_parsed" {
				row.Partial++
			}
		}
		for _, f := range res.Findings {
			if private != nil && underAny(f.Location.RelPath, private) {
				row.PrivateOnly++
				continue
			}
			all = append(all, seccorpus.Finding{Repo: r.URL, Commit: r.Commit, Path: f.Location.RelPath, Line: f.Location.StartLine, Rule: f.Rule.ID})
		}
		row.Findings = len(res.Findings)
		rec.Repos = append(rec.Repos, row)
		fmt.Printf("%-60s %-10s %5d files %5d findings %4ds %s\n", r.URL, row.Outcome, row.FilesScanned, row.Findings, row.Seconds, row.Reason)
	}
	all, rec.DroppedInvalid, rec.DroppedDuplicate = dedupe(all)
	kept, excluded := seccorpus.Partition(all)
	rec.Candidates, rec.Excluded = len(kept), excluded
	fmt.Printf("dedupe dropped %d invalid and %d repeated findings\n", rec.DroppedInvalid, rec.DroppedDuplicate)
	if err := writeJSONL(p.file("candidates.jsonl"), kept); err != nil {
		return err
	}
	if err := writeCounts(p.file("counts.tsv"), pack, all, kept); err != nil {
		return err
	}
	return writeJSON(p.file("run.json"), rec)
}

// privateOnlyPaths reads PRIVATE_ONLY_PATHS from this repository's
// scripts/release.sh (in the clone, at the pinned commit): the paths that
// never reach the public repository. Corpus files never name a path under
// one of them. A release script that cannot be read is an error, never an
// empty list.
func privateOnlyPaths(clone string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(clone, "scripts", "release.sh"))
	if err != nil {
		return nil, err
	}
	_, body, ok := strings.Cut(string(b), "readonly PRIVATE_ONLY_PATHS=(")
	if !ok {
		return nil, fmt.Errorf("release.sh has no PRIVATE_ONLY_PATHS")
	}
	body, _, ok = strings.Cut(body, "\n)")
	if !ok {
		return nil, fmt.Errorf("release.sh: PRIVATE_ONLY_PATHS does not end")
	}
	var out []string
	for _, l := range strings.Split(body, "\n") {
		l, _, _ = strings.Cut(l, "#")
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, strings.TrimSuffix(l, "/"))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("release.sh: PRIVATE_ONLY_PATHS is empty")
	}
	return out, nil
}

// underAny reports whether rel is one of paths or lies under one.
func underAny(rel string, paths []string) bool {
	for _, p := range paths {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}

// dedupe drops findings that fail Validate and repeated findings (one rule,
// one line), counts each, and sorts the rest by key. run.json records both
// counts, so no finding disappears without a count.
func dedupe(in []seccorpus.Finding) (out []seccorpus.Finding, invalid, repeated int) {
	seen := map[string]bool{}
	for _, f := range in {
		switch {
		case f.Validate() != nil:
			invalid++
			continue
		case seen[f.Key()]:
			repeated++
			continue
		}
		seen[f.Key()] = true
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, invalid, repeated
}

// writeCounts writes rule, results kept, results excluded, repositories,
// for every rule of the pack (a rule with no result is listed with 0).
func writeCounts(path string, pack *secrulepack.Pack, all, kept []seccorpus.Finding) error {
	type c struct {
		kept, excl int
		repos      map[string]bool
	}
	per := map[string]*c{}
	for _, r := range pack.Manifest.Rules {
		per[r.ID] = &c{repos: map[string]bool{}}
	}
	keptKey := map[string]bool{}
	for _, f := range kept {
		keptKey[f.Key()] = true
	}
	for _, f := range all {
		x := per[f.Rule]
		if x == nil {
			continue
		}
		if keptKey[f.Key()] {
			x.kept++
			x.repos[f.Repo] = true
		} else {
			x.excl++
		}
	}
	ids := make([]string, 0, len(per))
	for id := range per {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	b.WriteString("rule\tresults\texcluded\trepositories\n")
	for _, id := range ids {
		fmt.Fprintf(&b, "%s\t%d\t%d\t%d\n", id, per[id].kept, per[id].excl, len(per[id].repos))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
