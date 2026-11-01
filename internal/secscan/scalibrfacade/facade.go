//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/csproj"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packagesconfig"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradlelockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
	jsmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	scalibrlog "github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"google.golang.org/grpc"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// Compiled reports whether SCALIBR is linked into this binary.
const Compiled = true

// tableRow is one extractor of the closed table.
type tableRow struct {
	info ExtractorInfo
	new  func(*cpb.PluginConfig) (filesystem.Extractor, error)
}

// extractorTable is the closed list of extractors the facade links: the
// ecosystems the install gate names (npm with package-lock, pnpm, yarn and
// bun lockfiles and installed package.json files; PyPI lockfiles and
// requirements files; crates.io, Go, RubyGems, Packagist and NuGet) plus
// Maven and Gradle. Table order is display order.
//
// Two of the spike's 22 rows are left out on purpose: pyproject.toml (the
// extractor emits only the project's own package, with its dependency
// list as metadata, so it adds nothing to match but noise) and Cargo.toml
// (its first package is the crate itself and its dependencies are version
// requirements, not resolved versions; Cargo.lock carries the resolved
// set).
var extractorTable = []tableRow{
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "npm", Files: "package-lock.json, npm-shrinkwrap.json"}, newNPMLock},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "npm", Files: "pnpm-lock.yaml"}, pnpmlock.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "npm", Files: "yarn.lock"}, yarnlock.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "npm", Files: "bun.lock"}, bunlock.New},
	{ExtractorInfo{Kind: "manifest", Ecosystem: "npm", Files: "node_modules/**/package.json"}, packagejson.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "PyPI", Files: "uv.lock"}, uvlock.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "PyPI", Files: "poetry.lock"}, poetrylock.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "PyPI", Files: "Pipfile.lock"}, pipfilelock.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "PyPI", Files: "pdm.lock"}, pdmlock.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "PyPI", Files: "pylock.toml"}, pylock.New},
	{ExtractorInfo{Kind: "manifest", Ecosystem: "PyPI", Files: "requirements*.txt"}, requirements.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "crates.io", Files: "Cargo.lock"}, cargolock.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "Go", Files: "go.mod (with go.sum)"}, gomod.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "RubyGems", Files: "Gemfile.lock, gems.locked"}, gemfilelock.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "Packagist", Files: "composer.lock"}, composerlock.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "NuGet", Files: "packages.lock.json"}, packageslockjson.New},
	{ExtractorInfo{Kind: "manifest", Ecosystem: "NuGet", Files: "*.csproj"}, csproj.New},
	{ExtractorInfo{Kind: "manifest", Ecosystem: "NuGet", Files: "packages.config"}, packagesconfig.New},
	{ExtractorInfo{Kind: "manifest", Ecosystem: "Maven", Files: "pom.xml"}, pomxml.New},
	{ExtractorInfo{Kind: "lockfile", Ecosystem: "Maven", Files: "gradle.lockfile, buildscript-gradle.lockfile"}, gradlelockfile.New},
}

// purlTypes maps an OSV ecosystem to the PURL type a canary package is
// built with (canaries only; extracted packages carry their own).
var purlTypes = map[string]string{
	"npm":       purl.TypeNPM,
	"PyPI":      purl.TypePyPi,
	"crates.io": purl.TypeCargo,
	"Go":        purl.TypeGolang,
	"RubyGems":  purl.TypeGem,
	"Packagist": purl.TypeComposer,
	"NuGet":     purl.TypeNuget,
	"Maven":     purl.TypeMaven,
}

// Extractors returns the closed extractor table with each extractor's name
// and declared OS requirement.
func Extractors() ([]ExtractorInfo, error) {
	out := make([]ExtractorInfo, 0, len(extractorTable))
	for _, row := range extractorTable {
		ex, err := row.new(&cpb.PluginConfig{})
		if err != nil {
			return nil, fmt.Errorf("scalibrfacade.Extractors: %w", err)
		}
		info := row.info
		info.Name = ex.Name()
		info.RequiresOS = osName(ex.Requirements().OS)
		out = append(out, info)
	}
	return out, nil
}

// osNames spells SCALIBR's OS requirement.
var osNames = map[plugin.OS]string{
	plugin.OSAny:     "any",
	plugin.OSLinux:   "linux",
	plugin.OSWindows: "windows",
	plugin.OSMac:     "darwin",
	plugin.OSUnix:    "unix",
}

func osName(o plugin.OS) string {
	if n, ok := osNames[o]; ok {
		return n
	}
	return fmt.Sprintf("os(%d)", int(o))
}

// ExtractOptions tunes one extraction pass.
type ExtractOptions struct {
	// SkipDirs are absolute directories under the root the walk skips.
	SkipDirs []string
	// MaxInodes caps the walk; 0 means no cap.
	MaxInodes int
	// MaxFileSize skips larger files; 0 means no cap.
	MaxFileSize int
	// Log receives SCALIBR's log lines; nil discards them.
	Log io.Writer
}

// Extract runs the extractor table over root (a real directory). Paths in
// the result are relative to root.
func Extract(ctx context.Context, root string, opts ExtractOptions) (*Inventory, error) {
	installLogger(opts.Log)
	exs := make([]filesystem.Extractor, 0, len(extractorTable)+1)
	for _, row := range extractorTable {
		ex, err := row.new(&cpb.PluginConfig{})
		if err != nil {
			return nil, fmt.Errorf("scalibrfacade.Extract: %w", err)
		}
		exs = append(exs, ex)
	}
	probe := &manifestProbe{}
	exs = append(exs, probe)
	inv, statuses, err := filesystem.Run(ctx, &filesystem.Config{
		Extractors:   exs,
		ScanRoots:    scalibrfs.RealFSScanRoots(root),
		DirsToSkip:   opts.SkipDirs,
		UseGitignore: false,
		ReadSymlinks: false,
		MaxInodes:    opts.MaxInodes,
		MaxFileSize:  opts.MaxFileSize,
		// filesystem.Run does not default this (only scalibr.Scan does); a
		// nil collector panics on the first file.
		Stats: stats.NoopCollector{},
	})
	if err != nil {
		return nil, fmt.Errorf("scalibrfacade.Extract: %w", err)
	}
	out := &Inventory{impl: inv.Packages, Unlocked: probe.result()}
	for _, s := range statuses {
		if s.Name == probe.Name() {
			continue
		}
		st := Status{Extractor: s.Name, OK: true}
		if s.Status != nil && s.Status.Status != plugin.ScanStatusSucceeded {
			st.OK = false
			st.Detail = s.Status.FailureReason
			st.FilesWithErrors = len(s.Status.FileErrors)
			for _, fe := range s.Status.FileErrors {
				if fe != nil && fe.FilePath != "" {
					st.Files = append(st.Files, filepath.ToSlash(fe.FilePath))
				}
			}
			sort.Strings(st.Files)
		}
		out.Statuses = append(out.Statuses, st)
	}
	sort.Slice(out.Statuses, func(i, j int) bool { return out.Statuses[i].Extractor < out.Statuses[j].Extractor })
	for _, p := range inv.Packages {
		out.Packages = append(out.Packages, plainPackage(p))
	}
	return out, nil
}

// plainPackage maps one SCALIBR package to the facade's row.
func plainPackage(p *extractor.Package) Package {
	row := Package{
		Ecosystem: string(p.Ecosystem().Ecosystem),
		Name:      p.Name,
		Version:   p.Version,
		Path:      p.Location.PathOrEmpty(),
	}
	if len(p.Plugins) > 0 {
		row.Extractor = p.Plugins[0]
	}
	switch m := p.Metadata.(type) {
	case *jsmeta.JavascriptPackageMetadata:
		row.Local = m.Source == jsmeta.Local
	case *restoredMetadata:
		row.Restored = true
	case *uncheckedMetadata:
		row.Local = m.Source == jsmeta.Local
		row.LockfileTooLarge = true
	case *requirements.Metadata:
		row.Unpinned = unpinnedComparator(m.VersionComparator)
	}
	return row
}

// unpinnedComparator reports whether a requirements line's comparator
// names a range rather than one exact version. The extractor drops a line
// with no version and keeps the range's lowest bound as the version, which
// is not what pip installs; "==" and "===" pin.
func unpinnedComparator(c string) bool {
	return c != "" && c != "==" && c != "==="
}

// manifestProbe is the facade's own extractor beside SCALIBR's: it emits no
// package, and records each Cargo.toml or pyproject.toml that declares
// dependencies with no lockfile in its directory or above it, up to the
// root (depscan's manifest table). Those manifests carry version ranges,
// not resolved versions, so they are reported "not scanned: no lockfile"
// and make the run partial, never clean. Manifests under node_modules are
// published package contents, not the project's own, and are ignored.
type manifestProbe struct {
	mu    sync.Mutex
	found []Manifest
}

// maxManifestBytes bounds the manifest body the probe reads; a larger one
// is taken to declare dependencies.
const maxManifestBytes = 4 << 20

func (*manifestProbe) Name() string                       { return "observer/manifestprobe" }
func (*manifestProbe) Version() int                       { return 0 }
func (*manifestProbe) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

func (*manifestProbe) FileRequired(api filesystem.FileAPI) bool {
	p := filepath.ToSlash(api.Path())
	if strings.Contains("/"+p+"/", "/node_modules/") {
		return false
	}
	_, _, ok := depscan.ManifestFor(path.Base(p))
	return ok
}

func (m *manifestProbe) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	rel := filepath.ToSlash(input.Path)
	name := path.Base(rel)
	eco, locks, ok := depscan.ManifestFor(name)
	if !ok {
		return inventory.Inventory{}, nil
	}
	body, err := io.ReadAll(io.LimitReader(input.Reader, maxManifestBytes+1))
	declares := err != nil || len(body) > maxManifestBytes || depscan.ManifestDeclares(name, body)
	if !declares || hasLockfile(input.FS, path.Dir(rel), locks) {
		return inventory.Inventory{}, nil
	}
	m.mu.Lock()
	m.found = append(m.found, Manifest{Ecosystem: eco, Path: rel})
	m.mu.Unlock()
	return inventory.Inventory{}, nil
}

func (m *manifestProbe) result() []Manifest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]Manifest(nil), m.found...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// hasLockfile walks from dir up to the root (".") looking for a directory
// entry that matches one of the lockfile patterns. A directory that cannot
// be read is skipped.
func hasLockfile(fsys fs.FS, dir string, patterns []string) bool {
	for {
		if fsys != nil {
			if entries, err := fs.ReadDir(fsys, dir); err == nil {
				for _, e := range entries {
					if !e.IsDir() && depscan.IsLockfile(e.Name(), patterns) {
						return true
					}
				}
			}
		}
		if dir == "." || dir == "/" || dir == "" {
			return false
		}
		dir = path.Dir(dir)
	}
}

// Match runs SCALIBR's own OSV matcher over one ecosystem's packages.
// Observer writes no version-ordering code here. A missing local database
// answers ErrNoDatabase; every other failure is an error.
func Match(ctx context.Context, inv *Inventory, req MatchRequest, opts MatchOptions) (MatchResult, error) {
	if inv == nil {
		return MatchResult{}, errors.New("scalibrfacade.Match: nil inventory")
	}
	all, _ := inv.impl.([]*extractor.Package)
	sub := inventory.Inventory{}
	index := map[*extractor.Package]int{}
	for _, i := range req.Indices {
		if i < 0 || i >= len(all) {
			return MatchResult{}, fmt.Errorf("scalibrfacade.Match: index %d out of range", i)
		}
		p := all[i]
		if p == nil || string(p.Ecosystem().Ecosystem) != req.Ecosystem {
			continue
		}
		sub.Packages = append(sub.Packages, p)
		index[p] = i
	}
	var canary *extractor.Package
	if req.Canary != nil {
		pt, ok := purlTypes[req.Ecosystem]
		if !ok {
			return MatchResult{}, fmt.Errorf("scalibrfacade.Match: no canary type for ecosystem %q", req.Ecosystem)
		}
		canary = &extractor.Package{Name: req.Canary.Name, Version: req.Canary.Version, PURLType: pt}
		sub.Packages = append(sub.Packages, canary)
	}
	if len(sub.Packages) == 0 {
		return MatchResult{}, nil
	}
	e, err := newEnricher(opts)
	if err != nil {
		return MatchResult{}, fmt.Errorf("scalibrfacade.Match: %w", err)
	}
	runCtx := ctx
	if opts.Online {
		timeout := opts.OnlineTimeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if err := e.Enrich(runCtx, &enricher.ScanInput{}, &sub); err != nil {
		if !opts.Online && strings.Contains(err.Error(), "no offline version") {
			return MatchResult{Matcher: e.Name()}, ErrNoDatabase
		}
		return MatchResult{Matcher: e.Name()}, fmt.Errorf("scalibrfacade.Match: %w", err)
	}
	res := MatchResult{Matcher: e.Name()}
	for _, pv := range sub.PackageVulns {
		if pv.Vulnerability == nil || pv.Package == nil {
			continue
		}
		if canary != nil && pv.Package == canary {
			res.CanaryHit = true
			continue
		}
		i, ok := index[pv.Package]
		if !ok {
			continue
		}
		res.Vulns = append(res.Vulns, Vuln{
			ID:       pv.Vulnerability.GetId(),
			Aliases:  slices.Clone(pv.Vulnerability.GetAliases()),
			Severity: severityLabel(pv),
			Index:    i,
		})
	}
	sort.Slice(res.Vulns, func(a, b int) bool {
		if res.Vulns[a].Index != res.Vulns[b].Index {
			return res.Vulns[a].Index < res.Vulns[b].Index
		}
		return res.Vulns[a].ID < res.Vulns[b].ID
	})
	return res, nil
}

// severityLabel reads the advisory's database_specific severity label.
func severityLabel(pv *inventory.PackageVuln) string {
	ds := pv.Vulnerability.GetDatabaseSpecific()
	if ds == nil {
		return ""
	}
	return ds.GetFields()["severity"].GetStringValue()
}

// newEnricher builds the matcher for opts: osvlocal with Download false, or
// osvdev with the injected client.
func newEnricher(opts MatchOptions) (enricher.Enricher, error) {
	client := opts.HTTPClient
	if client == nil {
		// The local path never opens a connection (Download is false), but
		// osvlocal refuses a nil client; hand it one that cannot dial.
		client = &http.Client{Transport: refuseTransport{}}
	}
	pc := &config.PluginConfig{ClientFactories: staticFactories{c: client}}
	if opts.Online {
		if opts.HTTPClient == nil {
			return nil, errors.New("online matching needs the egress lane's client")
		}
		secs := int64(opts.OnlineTimeout / time.Second)
		if secs <= 0 {
			secs = 30
		}
		pc.ProtoConfig = &cpb.PluginConfig{PluginSpecific: []*cpb.PluginSpecificConfig{{Config: &cpb.PluginSpecificConfig_Osvdev{Osvdev: &cpb.OSVDevConfig{InitialQueryTimeoutSeconds: secs}}}}}
		return osvdev.New(pc)
	}
	if opts.DBDir == "" {
		return nil, errors.New("local matching needs a database directory")
	}
	pc.ProtoConfig = &cpb.PluginConfig{PluginSpecific: []*cpb.PluginSpecificConfig{{Config: &cpb.PluginSpecificConfig_Osvlocal{Osvlocal: &cpb.OSVLocalConfig{
		// Never contacted: Download is false. Kept equal to the store's
		// host so a stray refresh could only ever reach the declared one.
		RemoteHost: "https://osv-vulnerabilities.storage.googleapis.com",
		LocalPath:  opts.DBDir,
		Download:   false,
	}}}}}
	return osvlocal.New(pc)
}

// refuseTransport is the round tripper of the local path's placeholder
// client: it never dials.
type refuseTransport struct{}

func (refuseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("scalibrfacade: the local matcher may not open a connection")
}

// staticFactories hands SCALIBR one injected HTTP client and refuses gRPC
// and Google clients.
type staticFactories struct{ c *http.Client }

func (s staticFactories) HTTPClient() *http.Client { return s.c }

func (staticFactories) GRPCClientConn(string, ...grpc.DialOption) (grpc.ClientConnInterface, error) {
	return nil, errors.New("scalibrfacade: gRPC clients are not allowed")
}

func (staticFactories) GoogleHTTPClient(context.Context, ...string) (*http.Client, error) {
	return nil, errors.New("scalibrfacade: Google clients are not allowed")
}

// The facade's logger: SCALIBR logs to stderr by default. One process
// installs it once; later calls only change the writer.
var (
	logOnce sync.Once
	logSink = &facadeLogger{}
)

func installLogger(w io.Writer) {
	logOnce.Do(func() { scalibrlog.SetLogger(logSink) })
	logSink.set(w)
}

// facadeLogger implements SCALIBR's Logger over one writer (nil discards).
// Debug lines are always dropped.
type facadeLogger struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *facadeLogger) set(w io.Writer) {
	l.mu.Lock()
	l.w = w
	l.mu.Unlock()
}

func (l *facadeLogger) line(level, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w == nil {
		return
	}
	fmt.Fprintf(l.w, "scalibr %s: %s\n", level, strings.TrimRight(msg, "\n"))
}

func (l *facadeLogger) Errorf(format string, args ...any) {
	l.line("error", fmt.Sprintf(format, args...))
}
func (l *facadeLogger) Error(args ...any) { l.line("error", fmt.Sprint(args...)) }
func (l *facadeLogger) Warnf(format string, args ...any) {
	l.line("warn", fmt.Sprintf(format, args...))
}
func (l *facadeLogger) Warn(args ...any) { l.line("warn", fmt.Sprint(args...)) }
func (l *facadeLogger) Infof(format string, args ...any) {
	l.line("info", fmt.Sprintf(format, args...))
}
func (l *facadeLogger) Info(args ...any)      { l.line("info", fmt.Sprint(args...)) }
func (l *facadeLogger) Debugf(string, ...any) {}
func (l *facadeLogger) Debug(...any)          {}

// NewInventory rebuilds an inventory from plain rows (the scan child's
// answer), for online matching in the calling process: each row becomes a
// SCALIBR package of its ecosystem's PURL type with no metadata. A row of
// an ecosystem the canary table does not know keeps a nil package, which
// Match skips.
func NewInventory(pkgs []Package) *Inventory {
	impl := make([]*extractor.Package, len(pkgs))
	for i, p := range pkgs {
		pt, ok := purlTypes[p.Ecosystem]
		if !ok {
			continue
		}
		impl[i] = &extractor.Package{Name: p.Name, Version: p.Version, PURLType: pt}
	}
	return &Inventory{Packages: append([]Package(nil), pkgs...), impl: impl}
}
