//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/csproj"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/nugetcpm"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/projectassetsjson"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
)

// dotnet.go holds the facade's two .NET extraction rules. Neither orders a
// version; each only decides which (name, version) pairs a file names.
//
// Central package management (CPM). A project that manages its versions
// centrally writes <PackageReference Include="X" /> with no version in its
// project file and <PackageVersion Include="X" Version="1.2.3" /> in a
// Directory.Packages.props, which MSBuild imports from the project's
// directory or the nearest one above it. SCALIBR's csproj and nugetcpm
// extractors read only a PackageReference that carries its own Version
// attribute and skip the rest, so a CPM project's dependencies went
// unlisted. The rule wraps both: SCALIBR still reads every reference with a
// version (unchanged), and a reference without one takes, in MSBuild's
// order, its VersionOverride, then a Version element, then every
// PackageVersion of the nearest Directory.Packages.props (each distinct
// version once: a conditioned item per target framework is a real second
// version). A reference none of them resolves stays in the inventory with no
// version, so depscan reports its file "no exact version pinned", never
// silently clean. GlobalPackageReference items (CPM's references that apply
// to every project) are read too. The lookup walks up to the scan root
// only, follows no symbolic link and reads no file over maxMSBuildBytes.
//
// The restored graph (obj/project.assets.json). SCALIBR's extractor emits
// every "Name/Version" key of "libraries" and "targets" (the packages NuGet
// restored) and also every entry of each target's "dependencies" map, whose
// values are the versions a package asked for (a minimum such as "2.10.0",
// or an interval), not the version NuGet chose. The rule keeps a package
// only when the file says it was restored at that version, so a minimum
// that NuGet raised is not matched as if it were installed.

// maxMSBuildBytes bounds an MSBuild file the rule reads: SCALIBR's csproj
// and nugetcpm extractors refuse a larger one in FileRequired, and the
// Directory.Packages.props a project resolves through is held to the same
// cap.
const maxMSBuildBytes = 20 << 20

// maxAssetsBytes bounds the project.assets.json the rule reads (SCALIBR's
// extractor sets no cap of its own). A larger file fails the extractor on
// that file: a gap, never a silent pass.
const maxAssetsBytes = 256 << 20

// centralPackagesFile is the MSBuild central package management file.
const centralPackagesFile = "Directory.Packages.props"

// msbuildItem is one PackageReference, PackageVersion or
// GlobalPackageReference item: the attributes and the child elements
// MSBuild accepts for its version.
type msbuildItem struct {
	Include             string `xml:"Include,attr"`
	Version             string `xml:"Version,attr"`
	VersionOverride     string `xml:"VersionOverride,attr"`
	VersionElem         string `xml:"Version"`
	VersionOverrideElem string `xml:"VersionOverride"`
}

// msbuildItemGroup is one ItemGroup of an MSBuild file.
type msbuildItemGroup struct {
	PackageReferences       []msbuildItem `xml:"PackageReference"`
	PackageVersions         []msbuildItem `xml:"PackageVersion"`
	GlobalPackageReferences []msbuildItem `xml:"GlobalPackageReference"`
}

// msbuildDoc is the part of an MSBuild file the CPM rule reads.
type msbuildDoc struct {
	ItemGroups []msbuildItemGroup `xml:"ItemGroup"`
}

// firstNonEmpty returns the first value that is not blank, trimmed.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// cpmExtractor wraps one of SCALIBR's MSBuild extractors (csproj or
// nugetcpm) with the CPM rule.
type cpmExtractor struct {
	filesystem.Extractor
}

func newCSProj(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	inner, err := csproj.New(cfg)
	if err != nil {
		return nil, err
	}
	return cpmExtractor{Extractor: inner}, nil
}

func newNuGetCPM(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	inner, err := nugetcpm.New(cfg)
	if err != nil {
		return nil, err
	}
	return cpmExtractor{Extractor: inner}, nil
}

// Extract reads the file once, hands SCALIBR a copy, and adds the
// references SCALIBR skipped for having no Version attribute.
func (e cpmExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	b, err := io.ReadAll(io.LimitReader(input.Reader, maxMSBuildBytes+1))
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read: %w", err)
	}
	if len(b) > maxMSBuildBytes {
		return inventory.Inventory{}, fmt.Errorf("MSBuild file over %d bytes", maxMSBuildBytes)
	}
	in := *input
	in.Reader = bytes.NewReader(b)
	inv, err := e.Extractor.Extract(ctx, &in)
	if err != nil {
		return inv, err
	}
	var doc msbuildDoc
	if err := xml.Unmarshal(b, &doc); err != nil {
		return inv, fmt.Errorf("could not read the MSBuild items: %w", err)
	}
	rel := filepath.ToSlash(input.Path)
	resolver := &centralResolver{fsys: input.FS, dir: path.Dir(rel)}
	for _, ig := range doc.ItemGroups {
		for _, it := range ig.PackageReferences {
			name := strings.TrimSpace(it.Include)
			if name == "" || strings.TrimSpace(it.Version) != "" {
				// No package, or SCALIBR's extractor already read it.
				continue
			}
			for _, v := range resolver.versions(name, firstNonEmpty(it.VersionOverride, it.VersionOverrideElem, it.VersionElem)) {
				inv.Packages = append(inv.Packages, nugetPackage(name, v, rel))
			}
		}
		for _, it := range ig.GlobalPackageReferences {
			if name := strings.TrimSpace(it.Include); name != "" {
				inv.Packages = append(inv.Packages, nugetPackage(name, firstNonEmpty(it.Version, it.VersionElem), rel))
			}
		}
	}
	for _, p := range inv.Packages {
		p.Version = exactNuGetVersion(p.Version)
	}
	return inv, nil
}

// nugetPackage is one NuGet package row of an MSBuild file.
func nugetPackage(name, version, rel string) *extractor.Package {
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeNuget,
		Location: extractor.LocationFromPath(rel),
	}
}

// centralResolver finds a project's Directory.Packages.props once, on the
// first reference that needs it.
type centralResolver struct {
	fsys   fs.FS
	dir    string
	loaded bool
	byName map[string][]string
}

// versions returns the versions a reference with no Version attribute
// resolves to: its own (a VersionOverride or a Version element) when it has
// one, else every central version of its package id (compared without
// case, as NuGet does), else one empty version (unpinned).
func (r *centralResolver) versions(name, own string) []string {
	if own != "" {
		return []string{own}
	}
	if !r.loaded {
		r.byName, r.loaded = centralVersions(r.fsys, r.dir), true
	}
	if vs := r.byName[strings.ToLower(name)]; len(vs) > 0 {
		return vs
	}
	return []string{""}
}

// centralVersions finds the Directory.Packages.props MSBuild imports for a
// project in dir (the first one walking up to the scan root; an import of
// a parent file from a nested one is not followed) and returns its
// PackageVersion items by lower-cased package id. A file that cannot be
// read, is over maxMSBuildBytes or does not parse answers nothing: the
// references stay unpinned, and the walk does not go past it (MSBuild would
// not either).
func centralVersions(fsys fs.FS, dir string) map[string][]string {
	if fsys == nil {
		return nil
	}
	for {
		if p, ok := centralFileIn(fsys, dir); ok {
			return readCentralVersions(fsys, p)
		}
		if dir == "." || dir == "/" || dir == "" {
			return nil
		}
		dir = path.Dir(dir)
	}
}

// centralFileIn returns the regular Directory.Packages.props in dir (the
// name compared without case, as Windows and MSBuild there do; a symbolic
// link is not followed).
func centralFileIn(fsys fs.FS, dir string) (string, bool) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if e.Type().IsRegular() && strings.EqualFold(e.Name(), centralPackagesFile) {
			return path.Join(dir, e.Name()), true
		}
	}
	return "", false
}

// readCentralVersions reads one Directory.Packages.props.
func readCentralVersions(fsys fs.FS, p string) map[string][]string {
	f, err := fsys.Open(p)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxMSBuildBytes+1))
	if err != nil || len(b) > maxMSBuildBytes {
		return nil
	}
	var doc msbuildDoc
	if err := xml.Unmarshal(b, &doc); err != nil {
		return nil
	}
	out := map[string][]string{}
	for _, ig := range doc.ItemGroups {
		for _, it := range ig.PackageVersions {
			name, v := strings.TrimSpace(it.Include), firstNonEmpty(it.Version, it.VersionElem)
			if name == "" || v == "" {
				continue
			}
			key := strings.ToLower(name)
			if !slices.Contains(out[key], v) {
				out[key] = append(out[key], v)
			}
		}
	}
	return out
}

// projectAssetsExtractor wraps SCALIBR's project.assets.json extractor with
// the restored-graph rule.
type projectAssetsExtractor struct {
	filesystem.Extractor
}

func newProjectAssets(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	inner, err := projectassetsjson.New(cfg)
	if err != nil {
		return nil, err
	}
	return projectAssetsExtractor{Extractor: inner}, nil
}

// Extract reads the file once, hands SCALIBR a copy and keeps only the
// packages the file says NuGet restored at that version.
func (e projectAssetsExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	b, err := io.ReadAll(io.LimitReader(input.Reader, maxAssetsBytes+1))
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read: %w", err)
	}
	if len(b) > maxAssetsBytes {
		return inventory.Inventory{}, fmt.Errorf("project.assets.json over %d bytes", maxAssetsBytes)
	}
	in := *input
	in.Reader = bytes.NewReader(b)
	inv, err := e.Extractor.Extract(ctx, &in)
	if err != nil {
		return inv, err
	}
	restored := restoredNuGetPackages(b)
	kept := inv.Packages[:0]
	for _, p := range inv.Packages {
		if restored[strings.ToLower(p.Name)+"@"+p.Version] {
			kept = append(kept, p)
		}
	}
	inv.Packages = kept
	return inv, nil
}

// assetsEntry is the part of a "libraries" or "targets" entry the rule
// reads.
type assetsEntry struct {
	Type string `json:"type"`
}

// restoredNuGetPackages returns the lower-cased id@version keys of the
// packages a project.assets.json says NuGet restored: the "Name/Version"
// keys of type "package" under "libraries" and under each target framework
// of "targets" (a project reference has type "project" and is the
// solution's own code).
func restoredNuGetPackages(assets []byte) map[string]bool {
	var f struct {
		Targets   map[string]map[string]assetsEntry `json:"targets"`
		Libraries map[string]assetsEntry            `json:"libraries"`
	}
	out := map[string]bool{}
	if err := json.Unmarshal(assets, &f); err != nil {
		return out
	}
	add := func(key string, ent assetsEntry) {
		name, version, ok := strings.Cut(key, "/")
		if !ok || ent.Type != "package" || name == "" || version == "" || strings.Contains(version, "/") {
			return
		}
		out[strings.ToLower(name)+"@"+version] = true
	}
	for _, t := range f.Targets {
		for k, ent := range t {
			add(k, ent)
		}
	}
	for k, ent := range f.Libraries {
		add(k, ent)
	}
	return out
}
