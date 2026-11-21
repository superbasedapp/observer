package scalibrchild

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
)

// sbom.go is the child's SBOM request (depscan.KindSBOM, security coverage
// gaps plan item 2): the caller read the packages from an SBOM file
// (internal/secsbom) and hands them in; the child extracts nothing and
// matches them per ecosystem through the same table, canaries and outcome
// rules as a project scan (matchOne). Only the request's own rows are
// answered.

// MaxSBOMPackages caps the rows one request matches.
const MaxSBOMPackages = 100_000

// runSBOM answers an SBOM request.
func runSBOM(ctx context.Context, req depscan.ChildRequest) depscan.ChildResponse {
	resp := depscan.ChildResponse{Version: depscan.ProtocolVersion, Compiled: scalibrfacade.Compiled, Kind: depscan.KindSBOM}
	if !scalibrfacade.Compiled {
		return resp
	}
	pkgs := req.Packages
	if len(pkgs) > MaxSBOMPackages {
		pkgs = pkgs[:MaxSBOMPackages]
	}
	plain := make([]scalibrfacade.Package, 0, len(pkgs))
	for _, p := range pkgs {
		row := depscan.Package{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, Path: p.Path, Extractor: p.Extractor}
		resp.Packages = append(resp.Packages, row)
		plain = append(plain, scalibrfacade.Package{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, Path: p.Path, Extractor: p.Extractor})
	}
	inv := scalibrfacade.NewInventory(plain)
	keep, dropped := depscan.Prepare(resp.Packages)
	resp.Dropped = dropped
	for _, eco := range depscan.SortedEcosystems(keep) {
		resp.Ecosystems = append(resp.Ecosystems, matchOne(ctx, inv, eco, keep[eco], req, false))
	}
	return resp
}
