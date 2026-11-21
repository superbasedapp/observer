//go:build !sbo_omit_security_scan_scalibr && !sbo_omit_security_scan_os

package scalibrfacade

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

// osimage.go is the facade's part of route A of phase OS-2 (component
// security.scan.os, compiled out with sbo_omit_security_scan_os): SCALIBR's
// three OS package extractors and osrelease, over an image root that
// internal/secimage extracted, and the same osvlocal matcher as the
// language ecosystems. It links extractor/filesystem/os/{dpkg,apk,rpm} and
// osrelease ONLY: never artifact/image (container scanning) and never
// extractor/filesystem/list. os/rpm is `//go:build !windows` upstream; on
// Windows its dummy twin finds nothing, and the caller reports an
// rpm-based release "not scanned: not_supported_on_windows".
//
// Two metadata repairs (no version logic, spike JSP-OS S1 and S4), applied
// to the image's packages and to the canary alike, so the canary proves
// them:
//
//   - Ubuntu LTS: SCALIBR v0.5.3 derives "Ubuntu:24.04" while every OSV
//     Ubuntu record says "Ubuntu:24.04:LTS", so nothing matched; ":LTS" is
//     appended to dpkg OSVersionID when os-release VERSION says LTS (never
//     twice, so an upstream fix makes it a no-op).
//   - Red Hat: OSCPEName is kept EMPTY. The stripped per-major-release file
//     (osvdb's "Red Hat:enterprise_linux:9::" row: baseos, appstream, crb)
//     makes SCALIBR's base-only ecosystem fallback exact, while a CPE
//     repair ("Red Hat:enterprise_linux:9::baseos" from CPE_NAME) would
//     narrow every package to baseos and miss AppStream advisories
//     (TestRedHatRepairKeepsAppStream proves it).

// OSCompiled reports whether the OS package extractors are linked.
const OSCompiled = true

// osExtractors are the three OS package extractors, in display order.
var osExtractors = []func(*cpb.PluginConfig) (filesystem.Extractor, error){dpkg.New, apk.New, rpm.New}

// osImpl is an image inventory's SCALIBR side.
type osImpl struct {
	pkgs    []*extractor.Package
	release map[string]string
}

// ExtractOS runs the OS package extractors over an image root (a directory
// secimage wrote: etc/os-release and the package databases only), applies
// the repairs, and returns the packages. Paths are relative to root.
func ExtractOS(ctx context.Context, root string, opts OSExtractOptions) (*Inventory, error) {
	installLogger(opts.Log)
	exs := make([]filesystem.Extractor, 0, len(osExtractors))
	for _, n := range osExtractors {
		ex, err := n(&cpb.PluginConfig{})
		if err != nil {
			return nil, fmt.Errorf("scalibrfacade.ExtractOS: %w", err)
		}
		exs = append(exs, ex)
	}
	roots := scalibrfs.RealFSScanRoots(root)
	release, err := osrelease.GetOSRelease(roots[0].FS)
	if err != nil {
		release = map[string]string{}
	}
	inv, statuses, err := filesystem.Run(ctx, &filesystem.Config{
		Extractors:   exs,
		ScanRoots:    roots,
		ReadSymlinks: false,
		MaxInodes:    opts.MaxInodes,
		Stats:        stats.NoopCollector{},
	})
	if err != nil {
		return nil, fmt.Errorf("scalibrfacade.ExtractOS: %w", err)
	}
	repairOS(release, inv.Packages)
	out := &Inventory{impl: &osImpl{pkgs: inv.Packages, release: release}}
	for _, s := range statuses {
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
		out.Packages = append(out.Packages, plainOSPackage(p))
	}
	return out, nil
}

// repairOS applies the two metadata repairs (file comment).
func repairOS(release map[string]string, pkgs []*extractor.Package) {
	lts := strings.Contains(release["VERSION"], "LTS")
	for _, p := range pkgs {
		switch md := p.Metadata.(type) {
		case *dpkgmeta.Metadata:
			if md.OSID == "ubuntu" && lts && md.OSVersionID != "" && !strings.HasSuffix(md.OSVersionID, ":LTS") {
				md.OSVersionID += ":LTS"
			}
		case *rpmmeta.Metadata:
			if md.OSID == "rhel" {
				md.OSCPEName = ""
			}
		}
	}
}

// osMatchName is the name the matcher uses for an OS package (SCALIBR's
// internal osvutil rule, mirrored for display only): the dpkg source name,
// the apk origin name, else the binary name.
func osMatchName(p *extractor.Package) string {
	switch m := p.Metadata.(type) {
	case *dpkgmeta.Metadata:
		if m.SourceName != "" {
			return m.SourceName
		}
	case *apkmeta.Metadata:
		if m.OriginName != "" {
			return m.OriginName
		}
	}
	return p.Name
}

func plainOSPackage(p *extractor.Package) Package {
	eco := p.Ecosystem()
	row := Package{
		Ecosystem:   string(eco.Ecosystem),
		OSEcosystem: eco.String(),
		Name:        osMatchName(p),
		Version:     p.Version,
		Path:        p.Location.PathOrEmpty(),
	}
	if row.Name != p.Name {
		row.Binary = p.Name
	}
	if len(p.Plugins) > 0 {
		row.Extractor = p.Plugins[0]
	}
	return row
}

// osCanaryPackage builds the canary as the extractors would have built it
// from the image's os-release.
func osCanaryPackage(c OSCanary, release map[string]string) (*extractor.Package, error) {
	p := &extractor.Package{Name: c.Name, Version: c.Version}
	switch c.Kind {
	case "deb":
		p.PURLType = purl.TypeDebian
		p.Metadata = &dpkgmeta.Metadata{
			PackageName: c.Name, PackageVersion: c.Version, SourceName: c.Source, Status: "install ok installed",
			OSID: release["ID"], OSVersionID: release["VERSION_ID"], OSVersionCodename: release["VERSION_CODENAME"],
		}
	case "apk":
		p.PURLType = purl.TypeApk
		p.Metadata = &apkmeta.Metadata{PackageName: c.Name, OriginName: c.Source, OSID: release["ID"], OSVersionID: release["VERSION_ID"]}
	case "rpm":
		p.PURLType = purl.TypeRPM
		p.Metadata = &rpmmeta.Metadata{PackageName: c.Name, OSID: release["ID"], OSVersionID: release["VERSION_ID"], OSCPEName: release["CPE_NAME"]}
	default:
		return nil, fmt.Errorf("scalibrfacade: unknown canary kind %q", c.Kind)
	}
	repairOS(release, []*extractor.Package{p})
	return p, nil
}

// MatchOS matches an image's OS packages against the one release database
// under opts.DBDir (<DBDir>/osv-scalibr/<Base>/all.zip), in one call. A
// missing database answers ErrNoDatabase.
func MatchOS(ctx context.Context, inv *Inventory, req OSMatchRequest, opts MatchOptions) (MatchResult, error) {
	if inv == nil {
		return MatchResult{}, errors.New("scalibrfacade.MatchOS: nil inventory")
	}
	im, ok := inv.impl.(*osImpl)
	if !ok {
		return MatchResult{}, errors.New("scalibrfacade.MatchOS: not an image inventory")
	}
	if opts.Online {
		return MatchResult{}, errors.New("scalibrfacade.MatchOS: OS packages are matched locally only")
	}
	sub := inventory.Inventory{}
	index := map[*extractor.Package]int{}
	for _, i := range req.Indices {
		if i < 0 || i >= len(im.pkgs) {
			return MatchResult{}, fmt.Errorf("scalibrfacade.MatchOS: index %d out of range", i)
		}
		sub.Packages = append(sub.Packages, im.pkgs[i])
		index[im.pkgs[i]] = i
	}
	var canary *extractor.Package
	if req.Canary != nil {
		c, err := osCanaryPackage(*req.Canary, im.release)
		if err != nil {
			return MatchResult{}, err
		}
		canary = c
		sub.Packages = append(sub.Packages, canary)
	}
	if len(sub.Packages) == 0 {
		return MatchResult{}, nil
	}
	return runEnrich(ctx, &sub, canary, index, opts)
}

// OSRelease returns the os-release the image inventory was extracted with.
func OSRelease(inv *Inventory) map[string]string {
	if im, ok := inv.impl.(*osImpl); ok {
		out := make(map[string]string, len(im.release))
		for k, v := range im.release {
			out[k] = v
		}
		return out
	}
	return nil
}
