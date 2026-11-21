package scalibrchild

import (
	"context"
	"errors"
	"io"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
)

// osimage.go is the child's image request (depscan.KindOSImage, phase OS-2
// route A): the caller extracted the image's allow-listed files into
// req.Root (internal/secimage) and linked the one release's stripped export
// under req.DBDir as osv-scalibr/<Base>/all.zip; the child extracts the OS
// packages, leaves the kernel packages out (depscan's drop table), and
// matches the rest with the release's canary in ONE call, under the same
// runner caps as a project scan. The release outcome is depscan's table.

// runOS answers an image request.
func runOS(ctx context.Context, req depscan.ChildRequest, log io.Writer, goos string) depscan.ChildResponse {
	resp := depscan.ChildResponse{Version: depscan.ProtocolVersion, Compiled: scalibrfacade.Compiled, Kind: depscan.KindOSImage}
	if req.OS == nil || req.OS.Ecosystem == "" || req.OS.Base == "" {
		resp.Error = "image request names no release"
		return resp
	}
	eco := req.OS.Ecosystem
	facts := depscan.OSFacts{Compiled: scalibrfacade.Compiled && scalibrfacade.OSCompiled, RPMOnWindows: req.OS.RPM && goos == "windows"}
	canary, hasCanary := depscan.OSCanaryFor(eco)
	facts.HasCanary = hasCanary
	facts.DatabaseInstalled = req.OS.Epoch != "" && req.DBDir != ""
	res := depscan.EcoResult{Ecosystem: eco}
	if !facts.Compiled || facts.RPMOnWindows {
		res.Outcome, res.Reason = depscan.DecideOSRelease(facts)
		resp.Ecosystems = []depscan.EcoResult{res}
		return resp
	}
	inv, err := scalibrfacade.ExtractOS(ctx, req.Root, scalibrfacade.OSExtractOptions{MaxInodes: req.MaxInodes, Log: log})
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	for _, s := range inv.Statuses {
		files := s.Files
		if len(files) > depscan.MaxFailedFiles {
			files = files[:depscan.MaxFailedFiles]
		}
		resp.Extractors = append(resp.Extractors, depscan.ExtractorStatus{Extractor: s.Extractor, OK: s.OK, Ecosystem: eco, Files: files})
	}
	for _, p := range inv.Packages {
		resp.Packages = append(resp.Packages, depscan.Package{
			Ecosystem: eco, Name: p.Name, Binary: p.Binary, Version: p.Version, Path: p.Path, Extractor: p.Extractor,
			// The image's os-release names one release; a package whose base
			// ecosystem is another one's cannot be answered by its database.
			OtherRelease: p.Ecosystem != req.OS.Base,
		})
	}
	keep, dropped := depscan.Prepare(resp.Packages)
	resp.Dropped = dropped
	idx := keep[eco]
	res.Packages = len(idx)
	if len(resp.Packages) == 0 {
		// No package database the extractors read: nothing to match, and
		// nothing to call clean (Coverage reads "no_packages").
		return resp
	}
	if facts.HasCanary && facts.DatabaseInstalled {
		m, err := scalibrfacade.MatchOS(ctx, inv, scalibrfacade.OSMatchRequest{
			Indices: idx,
			Canary:  &scalibrfacade.OSCanary{Kind: canary.Kind, Name: canary.Name, Source: canary.Source, Version: canary.Version},
		}, scalibrfacade.MatchOptions{DBDir: req.DBDir})
		switch {
		case errors.Is(err, scalibrfacade.ErrNoDatabase):
			facts.NoDatabase = true
		case err != nil:
			facts.MatchError = true
		default:
			facts.CanaryHit = m.CanaryHit
			for _, v := range m.Vulns {
				res.Advisories = append(res.Advisories, depscan.Advisory{ID: v.ID, Aliases: v.Aliases, Severity: v.Severity, Index: v.Index})
			}
		}
	}
	res.Outcome, res.Reason = depscan.DecideOSRelease(facts)
	if res.Outcome == depscan.EcoScanned {
		res.Epoch = req.OS.Epoch
	} else {
		res.Advisories = nil
	}
	resp.Ecosystems = []depscan.EcoResult{res}
	return resp
}

// childGOOS is the platform an image request is decided for.
func childGOOS(req depscan.ChildRequest) string {
	if req.GOOS != "" {
		return req.GOOS
	}
	return runtime.GOOS
}
