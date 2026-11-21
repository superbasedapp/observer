package secreachsvc

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secreach"
)

// Lookup returns a dependency finding's advisory data by finding id, ok
// false when the finding names no package (NewLookup builds one).
type Lookup func(findingID string) (secreach.Advisory, bool)

// NewLookup builds the Lookup a surface passes to Tiers, over secdepdetail's
// local OSV record read: evidence maps a finding id to its redacted
// dependency evidence (store.SecDependencyEvidence), record reads one OSV
// record from the local database (the finding drawer's securityOSVLookup).
// Only each record's affected import paths are read, never its prose.
func NewLookup(findings []secfinding.Finding, evidence map[string]string, record func(eco, id string) ([]byte, error)) Lookup {
	byID := make(map[string]secfinding.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}
	return func(id string) (secreach.Advisory, bool) {
		f, ok := byID[id]
		if !ok {
			return secreach.Advisory{}, false
		}
		pkg, recs, ok := secdepdetail.LookupAffectedImports(secdepdetail.Input{
			Category: string(f.Category), Evidence: evidence[id], RuleID: f.Rule.ID, Message: f.Message,
			LookupRecord: record,
		})
		if !ok {
			return secreach.Advisory{}, false
		}
		adv := AdvisoryFrom(pkg, recs)
		adv.Artifact = IsGoBinaryStdlib(pkg.Ecosystem, pkg.Name, f.Location.RelPath)
		return adv, true
	}
}

// AdvisoryFrom is the advisory data secreach decides on, from
// secdepdetail's package and record read (each record's affected import
// paths and functions; nothing else).
func AdvisoryFrom(pkg secdepdetail.Package, recs []secdepdetail.AffectedImports) secreach.Advisory {
	adv := secreach.Advisory{Ecosystem: pkg.Ecosystem, Package: pkg.Name}
	for _, r := range recs {
		adv.Records = append(adv.Records, secreach.Record{ID: r.ID, ImportPaths: r.ImportPaths, Functions: r.Functions})
	}
	return adv
}

// Option configures Tiers.
type Option func(*options)

type options struct {
	binary          BinaryEvidenceFunc
	limits          Limits
	codeIntel       CodeIntelReader
	preferCodeIntel bool
	cache           *Cache
}

// BinaryEvidenceFunc returns what is known about one binary beyond its build
// info, by the binary's project-relative path (slash form). It is the seam
// 3b-bin's symbol evidence enters by; a nil func, or a zero result, means
// nothing was collected and a Go binary's standard library stays
// "potentially affected" (secreach.ClassifyArtifact).
type BinaryEvidenceFunc func(relPath string) secreach.BinaryEvidence

// WithBinaryEvidence supplies symbol evidence for binaries (3b-bin).
func WithBinaryEvidence(fn BinaryEvidenceFunc) Option { return func(o *options) { o.binary = fn } }

// goDependencyFiles are the Go files a dependency finding can sit at; a
// Go "stdlib" finding anywhere else was read out of a binary.
var goDependencyFiles = map[string]bool{"go.mod": true, "go.sum": true, "go.work": true, "go.work.sum": true}

// IsGoBinaryStdlib reports a Go standard-library (or toolchain) finding that
// was read out of a build artifact: the dependency finding of a binary's
// embedded standard library, which has no import list to be decided
// against. A module a binary embeds is decided like any other. Every path
// that builds a secreach.Advisory sets Advisory.Artifact from it.
func IsGoBinaryStdlib(ecosystem, pkg, relPath string) bool {
	if ecosystem != "Go" || (pkg != "stdlib" && pkg != "toolchain") {
		return false
	}
	base := path.Base(filepath.ToSlash(relPath))
	return !goDependencyFiles[base]
}

// WithLimits sets the parse bounds (DefaultLimits otherwise).
func WithLimits(l Limits) Option { return func(o *options) { o.limits = l } }

// WithCodeIntel lets Tiers use the project's codeintel index: as the
// fallback when the parse is incomplete, or first with PreferCodeIntel.
func WithCodeIntel(r CodeIntelReader) Option { return func(o *options) { o.codeIntel = r } }

// PreferCodeIntel tries the codeintel index before the parse (skipping
// the parse when the index holds the whole project). Off by default: the
// parse is as fresh as the files, the index only as fresh as its last pass.
func PreferCodeIntel() Option { return func(o *options) { o.preferCodeIntel = true } }

// sourceStep is one row of the import-list source ladder.
type sourceStep struct {
	Name  string
	Build func(ctx context.Context, o options, root string) (*GoImports, bool)
}

var (
	stepParse = sourceStep{Name: secreach.SourceGoImports, Build: func(ctx context.Context, o options, root string) (*GoImports, bool) {
		g, err := ScanGoImports(ctx, root, o.limits)
		return g, err == nil
	}}
	stepCodeIntel = sourceStep{Name: secreach.SourceCodeIntel, Build: func(ctx context.Context, o options, root string) (*GoImports, bool) {
		return CodeIntelGoImports(ctx, o.codeIntel, root)
	}}
)

// sourceLadder is the order the import-list sources are tried in: the
// first COMPLETE list wins; when none is complete the first list built is
// used (it can still prove "imported").
func sourceLadder(o options) []sourceStep {
	if o.codeIntel == nil {
		return []sourceStep{stepParse}
	}
	if o.preferCodeIntel {
		return []sourceStep{stepCodeIntel, stepParse}
	}
	return []sourceStep{stepParse, stepCodeIntel}
}

// goImportsFor walks the ladder.
func goImportsFor(ctx context.Context, o options, root string) *GoImports {
	var first *GoImports
	for _, step := range sourceLadder(o) {
		g, ok := step.Build(ctx, o, root)
		if !ok || g == nil {
			continue
		}
		if g.complete() {
			return g
		}
		if first == nil {
			first = g
		}
	}
	return first
}

// complete reports a list that ran to the end with every module complete.
func (g *GoImports) complete() bool {
	if g.Stats.Stopped != "" {
		return false
	}
	for _, m := range g.Modules {
		if m.Incomplete {
			return false
		}
	}
	return true
}

// Tiers returns the reachability tier of every dependency finding of
// findings (other findings are not in the map), keyed by finding id. Each
// import list (the Go parse, each codeintel language list, each
// directory's Python metadata, the Rust call sites) is built at most once,
// and only when some finding needs it. An empty projectRoot, or one that
// cannot be read, makes those findings Unknown (no import data); without
// WithCodeIntel, or with an index that holds no file of the language, a
// JavaScript, TypeScript, Python or Rust finding is Unknown (no codeintel
// index).
func Tiers(ctx context.Context, projectRoot string, findings []secfinding.Finding, lookup Lookup, opts ...Option) map[string]secreach.Tier {
	o := options{limits: DefaultLimits()}
	for _, opt := range opts {
		opt(&o)
	}
	out := map[string]secreach.Tier{}
	type pending struct {
		f    secfinding.Finding
		adv  secreach.Advisory
		lang string
	}
	var todo []pending
	b := &listBuilder{ctx: ctx, o: o, root: projectRoot, callNames: map[string]bool{}}
	for _, f := range findings {
		if f.Category != policy.FindingVulnerableDependency {
			continue
		}
		if lookup == nil {
			out[f.ID] = secreach.UnknownTier(secreach.ReasonNoAdvisory)
			continue
		}
		adv, ok := lookup(f.ID)
		if !ok {
			out[f.ID] = secreach.UnknownTier(secreach.ReasonNoAdvisory)
			continue
		}
		if adv.Artifact {
			var ev secreach.BinaryEvidence
			if o.binary != nil {
				ev = o.binary(filepath.ToSlash(f.Location.RelPath))
			}
			out[f.ID] = secreach.ClassifyArtifact(adv, ev)
			continue
		}
		lang, mapped := secreach.LanguageFor(adv.Ecosystem)
		if !mapped || (secreach.NeedsRecords(adv.Ecosystem) && len(adv.Records) == 0) {
			out[f.ID] = secreach.Classify(adv, nil)
			continue
		}
		todo = append(todo, pending{f: f, adv: adv, lang: lang})
		for _, n := range secreach.CallNames(adv) {
			if !b.callNames[n] {
				b.callNames[n] = true
				b.callOrder = append(b.callOrder, n)
			}
		}
	}
	for _, p := range todo {
		var imports map[string]secreach.ImportSet
		if build, ok := langBuilders[p.lang]; ok && projectRoot != "" {
			if set, ok := build(b, p.f, p.lang); ok {
				imports = map[string]secreach.ImportSet{p.lang: set}
			}
		}
		out[p.f.ID] = secreach.Classify(p.adv, imports)
	}
	return out
}

// listBuilder builds and memoizes one Tiers call's import lists.
type listBuilder struct {
	ctx  context.Context
	o    options
	root string

	goBuilt bool
	goList  *GoImports

	callNames map[string]bool
	callOrder []string
	callsDone bool
	calls     []secreach.Call
	callsOK   bool
}

// langBuilders is the per-language table of how a finding's import list
// is built (ok false: no import data for it).
var langBuilders = map[string]func(b *listBuilder, f secfinding.Finding, lang string) (secreach.ImportSet, bool){
	secreach.LangGo:     (*listBuilder).goSet,
	secreach.LangJS:     (*listBuilder).codeIntelSet,
	secreach.LangPython: (*listBuilder).pythonSet,
	secreach.LangRust:   (*listBuilder).rustSet,
}

// goSet is the Go list of the finding's module.
func (b *listBuilder) goSet(f secfinding.Finding, _ string) (secreach.ImportSet, bool) {
	if !b.goBuilt {
		b.goBuilt = true
		b.goList = b.o.cache.get(b.ctx, b.o, b.root)
	}
	if b.goList == nil {
		return secreach.ImportSet{}, false
	}
	return b.goList.ImportSet(f.Location.RelPath), true
}

// codeIntelSet is the project-wide codeintel list of the finding's
// language (cached per root and language).
func (b *listBuilder) codeIntelSet(_ secfinding.Finding, lang string) (secreach.ImportSet, bool) {
	return b.codeIntelList(lang)
}

func (b *listBuilder) codeIntelList(lang string) (secreach.ImportSet, bool) {
	if b.o.codeIntel == nil || lang == "" {
		return secreach.ImportSet{}, false
	}
	v := b.o.cache.load(b.ctx, b.root+"\x00codeintel\x00"+lang+"\x00"+optionKey(b.o), func(ctx context.Context) built {
		set, ok := CodeIntelLangImports(ctx, b.o.codeIntel, b.root, lang)
		if !ok {
			return built{val: (*secreach.ImportSet)(nil), complete: true}
		}
		return built{val: set, complete: set.Complete}
	})
	set, _ := v.(*secreach.ImportSet)
	if set == nil {
		return secreach.ImportSet{}, false
	}
	return *set, true
}

// pythonSet is the codeintel Python list with the installed metadata of
// the finding's lockfile directory and of the project root (the lockfile
// directory's wins for a distribution both hold).
func (b *listBuilder) pythonSet(f secfinding.Finding, lang string) (secreach.ImportSet, bool) {
	set, ok := b.codeIntelList(lang)
	if !ok {
		return set, false
	}
	provides := map[string][]string{}
	for _, dir := range metaDirs(b.root, f.Location.RelPath) {
		for dist, mods := range b.pythonMeta(dir).Provides {
			if _, ok := provides[dist]; !ok {
				provides[dist] = mods
			}
		}
	}
	set.Provides = provides
	return set, true
}

// metaDirs are the directories whose virtual environments a Python
// finding reads: its lockfile's directory (when inside the project), then
// the root.
func metaDirs(root, lockfileRel string) []string {
	out := []string{}
	rel := strings.TrimPrefix(filepath.ToSlash(lockfileRel), "./")
	if dir := path.Dir(rel); rel != "" && dir != "." && dir != "/" && !strings.HasPrefix(dir, "../") && dir != ".." && !path.IsAbs(dir) {
		if _, ok := relUnder(root, filepath.Join(root, filepath.FromSlash(dir))); ok {
			out = append(out, filepath.Join(root, filepath.FromSlash(dir)))
		}
	}
	return append(out, root)
}

// pythonMeta is dir's installed metadata (cached per directory).
func (b *listBuilder) pythonMeta(dir string) *PythonMeta {
	v := b.o.cache.load(b.ctx, dir+"\x00pymeta", func(ctx context.Context) built {
		m := ReadPythonMeta(ctx, dir)
		return built{val: m, complete: m.Stopped == "", canceled: m.Stopped == StoppedCanceled}
	})
	m, _ := v.(*PythonMeta)
	if m == nil {
		return &PythonMeta{}
	}
	return m
}

// rustSet is the codeintel Rust list with the call sites of every listed
// function's name (one read per Tiers call, for all Rust findings).
func (b *listBuilder) rustSet(_ secfinding.Finding, lang string) (secreach.ImportSet, bool) {
	set, ok := b.codeIntelList(lang)
	if !ok {
		return set, false
	}
	if !b.callsDone {
		b.callsDone = true
		b.calls, b.callsOK = CodeIntelRustCalls(b.ctx, b.o.codeIntel, b.root, b.callOrder)
	}
	set.Calls, set.CallsRead = b.calls, b.callsOK
	return set, true
}

// ImportSet is the import list a finding whose lockfile is lockfileRel
// (project-relative, slash or OS form) is decided against: the module of
// that go.mod or go.sum, else every module of the project.
func (g *GoImports) ImportSet(lockfileRel string) secreach.ImportSet {
	rel := strings.TrimPrefix(filepath.ToSlash(lockfileRel), "./")
	dir, base := path.Split(rel)
	dir = strings.TrimSuffix(dir, "/")
	if base == "go.mod" || base == "go.sum" {
		if m, ok := g.Modules[dir]; ok {
			return g.setOf([]*ModuleImports{m})
		}
		if dir != "" && !skippedPath(dir) && regularFile(filepath.Join(g.Root, filepath.FromSlash(dir), "go.mod")) {
			// A module the list holds no file of: nothing imported.
			return g.setOf([]*ModuleImports{{Dir: dir, Uses: map[string]secreach.Use{}, Modules: readModulePaths(filepath.Join(g.Root, filepath.FromSlash(dir)))}})
		}
	}
	all := make([]*ModuleImports, 0, len(g.Modules))
	for _, m := range g.Modules {
		all = append(all, m)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Dir < all[j].Dir })
	return g.setOf(all)
}

func (g *GoImports) setOf(mods []*ModuleImports) secreach.ImportSet {
	set := secreach.ImportSet{Source: g.Source, Complete: g.Stats.Stopped == "", Uses: map[string]secreach.Use{}}
	seen := map[string]bool{}
	for _, m := range mods {
		if m.Incomplete {
			set.Complete = false
		}
		for p, u := range m.Uses {
			cur := set.Uses[p]
			cur.NonTest = cur.NonTest || u.NonTest
			cur.Test = cur.Test || u.Test
			set.Uses[p] = cur
		}
		for _, mp := range m.Modules {
			if !seen[mp] {
				seen[mp] = true
				set.Modules = append(set.Modules, mp)
			}
		}
	}
	sort.Strings(set.Modules)
	return set
}

func regularFile(name string) bool {
	st, err := os.Stat(name)
	return err == nil && st.Mode().IsRegular()
}
