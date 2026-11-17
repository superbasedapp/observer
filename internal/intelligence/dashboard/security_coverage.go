//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_coverage.go serves GET /api/security/coverage, the Code
// security page's Coverage tab (redesign plan
// docs/plans/code-security-page-redesign-plan-2026-11-06.md section 4.5):
// which ecosystems and files the dependency scanners read, whether each
// one's local database is installed, and, per project, what each
// dependency driver's newest recorded run scanned and skipped, with the
// words of every gap reason. It captures nothing new and starts no
// process: the supported list is composed from the existing tables (the
// depscan ecosystem, manifest and dependency-file tables, and the SCALIBR
// facade's extractor table through the scan seam, since the dashboard may
// not import the facade), the projects part reads sec_scan_runs. A
// feature-owned file of security.deps: with sbo_omit_security_deps (or
// sbo_omit_security) security_coverage_omit.go answers instead.

// securityCoverageMaxSkipped caps the skipped parts listed per run
// (skipped_total counts every one).
const securityCoverageMaxSkipped = 50

// securityCoverageLegend are the gap reasons the Coverage tab explains
// whether or not a run named them (plan section 4.5's list).
var securityCoverageLegend = []string{
	depscan.ReasonNoExtractor, depscan.ReasonNoAdvisoryData, depscan.ReasonNeedsOnline,
	depscan.ReasonUnpinned, depscan.ReasonNoLockfile, depscan.ReasonIsolationRefused,
}

// securityCoverageSupportedJS is one ecosystem the scanners know.
type securityCoverageSupportedJS struct {
	Ecosystem string `json:"ecosystem"`
	// Files are the file names and path.Match patterns the scanners read
	// for the ecosystem: its extractor rows' files (and the online lookup's
	// own files). Without the extractor seam (a build with no SCALIBR) the
	// manifest and dependency-file tables' patterns stand in, as before.
	Files []string `json:"files"`
	// UnreadFiles are the ecosystem's files Observer finds but no linked
	// extractor reads: a manifest checked only through its lockfile
	// (package.json, mix.exs), a file with no extractor (bun.lockb,
	// rebar.lock, Podfile.lock), or one no database covers (conanfile.txt).
	// A scan reports each one it meets as a gap, never a clean result.
	UnreadFiles []string `json:"unread_files"`
	// Drivers are the driver ids in this build that read it.
	Drivers []string `json:"drivers"`
	// AdvisorySource is where its advisories come from ("OSV npm"); "" when
	// no database covers it.
	AdvisorySource    string `json:"advisory_source"`
	DatabaseInstalled bool   `json:"database_installed"`
	OnlineOnly        bool   `json:"online_only"`
	Note              string `json:"note,omitempty"`
}

// securityCoverageSkipJS is one part a run did not scan, and why. A path
// that starts with "ecosystem:" (depscan.EcosystemSkipPrefix) names a
// whole ecosystem; every other path is a dependency file.
type securityCoverageSkipJS struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// securityCoverageRunJS is one dependency driver's newest recorded run on
// one project.
type securityCoverageRunJS struct {
	Driver       string                   `json:"driver"`
	StartedAt    string                   `json:"started_at"`
	Outcome      string                   `json:"outcome"`
	Reason       string                   `json:"reason,omitempty"`
	FilesScanned int                      `json:"files_scanned"`
	Scanned      []string                 `json:"scanned"`
	Skipped      []securityCoverageSkipJS `json:"skipped"`
	SkippedTotal int                      `json:"skipped_total"`
}

// securityCoverageProjectJS is one project with its dependency runs.
type securityCoverageProjectJS struct {
	ProjectRootHash string                  `json:"project_root_hash"`
	ProjectID       int64                   `json:"project_id,omitempty"`
	Name            string                  `json:"name"`
	Active          bool                    `json:"active"`
	Runs            []securityCoverageRunJS `json:"runs"`
}

// securityCoverageResponse is GET /api/security/coverage. Reasons maps each
// reason it names (and the legend's) to depscan's words for it; a reason
// depscan has no words for is left out.
type securityCoverageResponse struct {
	Supported []securityCoverageSupportedJS `json:"supported"`
	Projects  []securityCoverageProjectJS   `json:"projects"`
	Reasons   map[string]string             `json:"reasons"`
	// Families is "what is checked": one row per checking family with its
	// components and state (security_coverage_families.go).
	Families []securityCheckFamilyJS `json:"families"`
}

// handleSecurityCoverage serves GET /api/security/coverage.
func (s *Server) handleSecurityCoverage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st := store.New(s.db())
	now := time.Now()
	roots, err := st.SecActiveProjectRoots(ctx, now.Add(-secsvc.DefaultActiveWithin))
	if err != nil {
		http.Error(w, "load projects: "+err.Error(), http.StatusInternalServerError)
		return
	}
	index, err := securityProjectIndex(ctx, st)
	if err != nil {
		http.Error(w, "load projects: "+err.Error(), http.StatusInternalServerError)
		return
	}
	runs, err := st.SecLatestCoverageRuns(ctx, []string{depscan.ScalibrID, depscan.OSVID}, securityCoverageMaxSkipped)
	if err != nil {
		http.Error(w, "load scan runs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resolved, _ := config.ResolveGlobalPath(s.opts.ConfigPath)
	eps, _ := osvdb.Open(filepath.Join(secposture.LayoutFor(resolved).Dir, "osv")).Epochs()
	var extractors []dashapi.SecurityExtractor
	if sn := s.opts.SecurityScanNow; sn != nil && sn.Extractors != nil {
		extractors = sn.Extractors()
	}
	resp := securityCoverageResponse{
		Supported: securityCoverageSupported(extractors, func(eco string) bool {
			e, ok := eps[eco]
			return ok && e.Installed()
		}),
		Projects: securityCoverageProjects(roots, index, runs),
		Reasons:  map[string]string{},
		Families: s.securityCoverageFamilies(ctx),
	}
	addReason := func(reason string) {
		if reason == "" {
			return
		}
		if words := depscan.ReasonWords(reason); words != reason {
			resp.Reasons[reason] = words
		}
	}
	for _, reason := range securityCoverageLegend {
		addReason(reason)
	}
	for _, p := range resp.Projects {
		for _, run := range p.Runs {
			addReason(run.Reason)
			for _, sk := range run.Skipped {
				addReason(sk.Reason)
			}
		}
	}
	writeJSON(w, resp)
}

// securityCoverageProjects is every project with a recorded dependency run
// and every active project (with no runs yet), named like
// /api/security/status names them, sorted by name then hash.
func securityCoverageProjects(roots []string, index map[string]store.SecProjectRef, runs []store.SecCoverageRun) []securityCoverageProjectJS {
	active := map[string]bool{}
	for _, root := range roots {
		active[secposture.ProjectRootHash(root)] = true
	}
	byHash := map[string]*securityCoverageProjectJS{}
	var order []string
	project := func(hash string) *securityCoverageProjectJS {
		if p, ok := byHash[hash]; ok {
			return p
		}
		p := &securityCoverageProjectJS{ProjectRootHash: hash, Active: active[hash], Runs: []securityCoverageRunJS{}}
		if ref, ok := index[hash]; ok {
			p.ProjectID, p.Name = ref.ID, securityProjectName(ref)
		}
		byHash[hash] = p
		order = append(order, hash)
		return p
	}
	for _, run := range runs {
		p := project(run.ProjectRootHash)
		js := securityCoverageRunJS{
			Driver: run.Driver, Outcome: run.Outcome, Reason: run.Reason, FilesScanned: run.FilesScanned,
			Scanned: append([]string{}, run.Scanned...), Skipped: []securityCoverageSkipJS{}, SkippedTotal: run.SkippedTotal,
		}
		if !run.StartedAt.IsZero() {
			js.StartedAt = run.StartedAt.UTC().Format(time.RFC3339)
		}
		for _, sk := range run.Skipped {
			js.Skipped = append(js.Skipped, securityCoverageSkipJS{Path: sk.Path, Reason: sk.Reason})
		}
		p.Runs = append(p.Runs, js)
	}
	for _, root := range roots {
		project(secposture.ProjectRootHash(root))
	}
	out := make([]securityCoverageProjectJS, 0, len(order))
	for _, h := range order {
		out = append(out, *byHash[h])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ProjectRootHash < out[j].ProjectRootHash
	})
	return out
}

// coverageFileLists are each ecosystem's file patterns, split into the
// files the scanners read and the files found but unread, each pattern once
// per ecosystem; tableOrder is the extractor table's ecosystem order.
type coverageFileLists struct {
	read, unread map[string][]string
	seen         map[string]map[string]bool
	tableOrder   []string
}

// add appends pattern to the ecosystem's list in into unless the ecosystem
// already lists it (read or unread).
func (l *coverageFileLists) add(into map[string][]string, eco, pattern string) {
	if l.seen[eco] == nil {
		l.seen[eco] = map[string]bool{}
	}
	if pattern == "" || l.seen[eco][pattern] {
		return
	}
	l.seen[eco][pattern] = true
	into[eco] = append(into[eco], pattern)
}

// securityCoverageFileLists gathers the file lists in order: the extractor
// rows' files (read), then the manifest table's manifests and the
// dependency-file table's rows. With the extractor seam a manifest is checked
// only through its lockfile, which an extractor row already lists when one
// reads it, so it is unread, as is a dependency-file row no extractor
// pattern names; the online lookup's own files are read. Without the seam
// every pattern stays read, as before the split.
func securityCoverageFileLists(extractors []dashapi.SecurityExtractor) *coverageFileLists {
	l := &coverageFileLists{read: map[string][]string{}, unread: map[string][]string{}, seen: map[string]map[string]bool{}}
	haveExtractors := len(extractors) > 0
	for _, x := range extractors {
		if _, ok := l.read[x.Ecosystem]; !ok {
			l.read[x.Ecosystem] = nil
			l.tableOrder = append(l.tableOrder, x.Ecosystem)
		}
		for _, p := range securityExtractorPatterns(x.Files) {
			l.add(l.read, x.Ecosystem, p)
		}
	}
	for _, name := range depscan.ManifestNames() {
		eco, locks, ok := depscan.ManifestFor(name)
		if !ok {
			continue
		}
		if haveExtractors {
			l.add(l.unread, eco, name)
			continue
		}
		l.add(l.read, eco, name)
		for _, lock := range locks {
			l.add(l.read, eco, lock)
		}
	}
	for _, d := range depscan.DepFiles() {
		into := l.read
		if haveExtractors && !d.Online {
			into = l.unread
		}
		l.add(into, d.Ecosystem, d.Pattern)
	}
	return l
}

// advisoriesPublishedWords is the supported-row note of an ecosystem whose
// advisories a database publishes but whose files this build cannot read
// (depscan.DepFile.AdvisoriesPublished).
const advisoriesPublishedWords = "not read in this build: OSV publishes advisories for this ecosystem, but Observer has no reader for its files yet"

// securityCoverageSupported is the supported list: first every ecosystem
// the drivers scan (depscan.Ecosystems, the canary table the extractor
// table feeds; in the extractor table's display order when the seam
// carries it), then every ecosystem the dependency-file table knows that
// no driver matches (Observer finds its files but cannot check them: no
// extractor, no advisory data anywhere, or online only). Files read come
// from the extractor rows and the online lookup's own files; a manifest the
// manifest table knows and a dependency-file row no extractor pattern names
// are unread files. Each pattern is listed once. Without the extractor seam
// nothing says what the drivers read, so every pattern stays in Files.
func securityCoverageSupported(extractors []dashapi.SecurityExtractor, installed func(eco string) bool) []securityCoverageSupportedJS {
	lists := securityCoverageFileLists(extractors)
	files, unread, tableOrder := lists.read, lists.unread, lists.tableOrder
	type depEco struct {
		online, noData, published bool
	}
	depEcos := map[string]*depEco{}
	var depOrder []string
	for _, d := range depscan.DepFiles() {
		e, ok := depEcos[d.Ecosystem]
		if !ok {
			e = &depEco{}
			depEcos[d.Ecosystem] = e
			depOrder = append(depOrder, d.Ecosystem)
		}
		e.online = e.online || d.Online
		e.noData = e.noData || d.NoAdvisoryData
		e.published = e.published || d.AdvisoriesPublished
	}

	scanned := map[string]bool{}
	for _, eco := range depscan.Ecosystems() {
		scanned[eco] = true
	}
	var order []string
	for _, eco := range tableOrder {
		if scanned[eco] {
			order = append(order, eco)
		}
	}
	for _, eco := range depscan.Ecosystems() {
		if !slices.Contains(order, eco) {
			order = append(order, eco)
		}
	}
	out := make([]securityCoverageSupportedJS, 0, len(order)+len(depOrder))
	for _, eco := range order {
		row := securityCoverageSupportedJS{
			Ecosystem: eco, Files: append([]string{}, files[eco]...), UnreadFiles: append([]string{}, unread[eco]...), Drivers: []string{},
			AdvisorySource: "OSV " + eco, DatabaseInstalled: installed(eco),
		}
		if scalibrDriverCompiled {
			row.Drivers = append(row.Drivers, depscan.ScalibrID)
		}
		if osvDriverCompiled && depscan.OSVScannerReads(eco) {
			row.Drivers = append(row.Drivers, depscan.OSVID)
		}
		if len(row.Drivers) == 0 {
			row.Note = depscan.ReasonWords(depscan.ReasonNotCompiled)
		}
		out = append(out, row)
	}
	for _, eco := range depOrder {
		if scanned[eco] {
			continue
		}
		e := depEcos[eco]
		row := securityCoverageSupportedJS{Ecosystem: eco, Files: append([]string{}, files[eco]...), UnreadFiles: append([]string{}, unread[eco]...), Drivers: []string{}}
		switch {
		case e.noData:
			row.Note = depscan.ReasonWords(depscan.ReasonNoAdvisoryData)
		case e.published:
			row.Note = advisoriesPublishedWords
		case e.online:
			// Only the online lookup checks it (the linked driver's online
			// matching, with its consent: the scan dialog's "Also check
			// online" or `observer security scan --online`).
			row.AdvisorySource, row.OnlineOnly = "OSV "+eco, true
			if scalibrDriverCompiled {
				row.Drivers = append(row.Drivers, depscan.ScalibrID)
			}
			row.Note = depscan.ReasonWords(depscan.ReasonNeedsOnline)
		default:
			row.Note = depscan.ReasonWords(depscan.ReasonNoExtractor)
		}
		out = append(out, row)
	}
	return out
}

// securityExtractorPatterns turns an extractor row's Files text (the
// facade table's own words, "*.csproj, *.fsproj, *.vbproj (a
// PackageReference with no version ...)") into the file patterns it names:
// parentheticals dropped, the list split at "," and " and ", a token that
// is not one file pattern (it holds a space, names a directory or a flag)
// dropped, and a bare "*.ext" after a pattern with a directory read in
// that directory (".github/workflows/*.yml, *.yaml").
func securityExtractorPatterns(text string) []string {
	var b strings.Builder
	depth := 0
	for _, r := range text {
		switch {
		case r == '(':
			depth++
		case r == ')':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			b.WriteRune(r)
		}
	}
	var out []string
	dir := ""
	for _, part := range strings.Split(b.String(), ",") {
		for _, tok := range strings.Split(part, " and ") {
			tok = strings.TrimSpace(tok)
			if tok == "" || strings.ContainsAny(tok, " \t") || strings.HasSuffix(tok, "/") || strings.HasPrefix(tok, "-") {
				continue
			}
			if i := strings.LastIndex(tok, "/"); i >= 0 {
				dir = tok[:i+1]
			} else if dir != "" && strings.HasPrefix(tok, "*.") {
				tok = dir + tok
			}
			out = append(out, tok)
		}
	}
	return out
}
