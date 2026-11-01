package scalibrchild

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
)

// Run answers one request. log receives SCALIBR's log lines (the child's
// stderr, capped by the runner); nil discards them.
func Run(ctx context.Context, req depscan.ChildRequest, log io.Writer) depscan.ChildResponse {
	resp := depscan.ChildResponse{Version: depscan.ProtocolVersion, Compiled: scalibrfacade.Compiled}
	if req.Version != depscan.ProtocolVersion {
		resp.Error = fmt.Sprintf("protocol version %d, want %d", req.Version, depscan.ProtocolVersion)
		return resp
	}
	if !scalibrfacade.Compiled {
		return resp
	}
	if req.Root == "" {
		resp.Error = "no project root"
		return resp
	}
	goos := req.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	infos, err := scalibrfacade.Extractors()
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	names := make([]string, 0, len(infos))
	ecoOf := map[string]string{}
	for _, i := range infos {
		names = append(names, i.Name)
		ecoOf[i.Name] = i.Ecosystem
	}
	row := depscan.ScalibrRow(names)
	inv, err := scalibrfacade.Extract(ctx, req.Root, scalibrfacade.ExtractOptions{SkipDirs: req.SkipDirs, MaxInodes: req.MaxInodes, Log: log})
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	for _, s := range inv.Statuses {
		files := s.Files
		if len(files) > depscan.MaxFailedFiles {
			files = files[:depscan.MaxFailedFiles]
		}
		resp.Extractors = append(resp.Extractors, depscan.ExtractorStatus{
			Extractor: s.Extractor, OK: s.OK, Ecosystem: ecoOf[s.Extractor], Files: files,
			Platform: string(depscan.PlatformSupport(row, goos, runtime.GOARCH, s.Extractor)),
		})
	}
	for _, p := range inv.Packages {
		resp.Packages = append(resp.Packages, depscan.Package{
			Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, Path: p.Path,
			Extractor: p.Extractor, Local: p.Local, Restored: p.Restored,
			Unpinned: p.Unpinned, LockfileTooLarge: p.LockfileTooLarge,
		})
	}
	for _, m := range inv.Unlocked {
		resp.Unlocked = append(resp.Unlocked, depscan.Manifest{Ecosystem: m.Ecosystem, Path: m.Path})
	}
	keep, dropped := depscan.Prepare(resp.Packages)
	resp.Dropped = dropped
	for _, eco := range depscan.SortedEcosystems(keep) {
		resp.Ecosystems = append(resp.Ecosystems, matchOne(ctx, inv, eco, keep[eco], req, unsupported(row, goos, resp.Packages, keep[eco])))
	}
	return resp
}

// unsupported reports whether every extractor that fed the ecosystem is
// unsupported on goos.
func unsupported(row secscan.DriverRow, goos string, pkgs []depscan.Package, idx []int) bool {
	if len(idx) == 0 {
		return false
	}
	for _, i := range idx {
		if depscan.PlatformSupport(row, goos, runtime.GOARCH, pkgs[i].Extractor) != secscan.SupportUnsupported {
			return false
		}
	}
	return true
}

// matchOne matches one ecosystem and decides its outcome through depscan's
// table.
func matchOne(ctx context.Context, inv *scalibrfacade.Inventory, eco string, idx []int, req depscan.ChildRequest, unsup bool) depscan.EcoResult {
	res := depscan.EcoResult{Ecosystem: eco, Packages: len(idx)}
	epoch, installed := req.Epochs[eco]
	canary, hasCanary := depscan.CanaryFor(eco)
	facts := depscan.MatchFacts{Unsupported: unsup, DatabaseInstalled: installed && req.DBDir != "", HasCanary: hasCanary}
	if !facts.Unsupported && facts.HasCanary && facts.DatabaseInstalled {
		m, err := scalibrfacade.Match(ctx, inv, scalibrfacade.MatchRequest{
			Ecosystem: eco, Indices: idx, Canary: &scalibrfacade.Canary{Name: canary.Name, Version: canary.Version},
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
	res.Outcome, res.Reason = depscan.DecideEcosystem(facts)
	if res.Outcome == depscan.EcoScanned {
		res.Epoch = epoch
	} else {
		res.Advisories = nil
	}
	return res
}
