//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"errors"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secinventory"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// security_sbom_dashboard.go is the dashboard seam of the Projects tab's
// "Export SBOM" (dashapi.SecurityProjectSBOM; security coverage gaps plan
// section 3): the same stored inventory snapshot and renderer `observer
// security sbom export` uses. The project root is one the dashboard
// resolved from its own project index.

// securityProjectSBOMDash returns the seam for the config at configPath.
func securityProjectSBOMDash(configPath string) dashapi.SecurityProjectSBOM {
	return func(_ context.Context, root string) ([]byte, bool, error) {
		if root == "" {
			return nil, false, errors.New("sbom: no project")
		}
		resolved, err := config.ResolveGlobalPath(configPath)
		if err != nil {
			return nil, false, err
		}
		dir := secposture.LayoutFor(resolved).Dir
		if dir == "" {
			return nil, false, errors.New("sbom: no security directory")
		}
		snap, ok := secinventory.Load(dir, secposture.ProjectRootHash(root))
		if !ok {
			return nil, false, nil
		}
		doc, err := renderProjectSBOM(root, snap, projectLicenceMap(root, snap))
		if err != nil {
			return nil, false, err
		}
		return doc, true, nil
	}
}
