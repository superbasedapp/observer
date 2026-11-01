//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// depsDoctorTenancy reads the node's tenancy the way a lookup does (lane
// SEC-D1FIX2 milestone 2f: the doctor no longer assumes individual). The
// database is opened only when it exists: the doctor never creates one.
func depsDoctorTenancy(ctx context.Context, cfg config.Config, configPath string) (managed bool, line string) {
	if _, err := os.Stat(cfg.Observer.DBPath); err != nil {
		return false, "tenancy unreadable (no database yet): no online lookup runs"
	}
	_, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return false, "tenancy unreadable: no online lookup runs"
	}
	defer cleanup()
	switch depsTenancyOf(store.New(database))(ctx) {
	case depsManaged:
		return true, "managed: lookups go only to the org relay, never to a public source"
	case depsIndividual:
		return false, "individual: lookups go to the public sources listed in the disclosure"
	}
	return false, "tenancy unreadable: no online lookup runs"
}

// security_deps_doctor.go is the install gate's doctor row (security
// pillar plan section 4.11): the component, the online setting and its
// disclosure, whether package checks are set up, and each signed index
// kind with its last refresh failure.
func securityDepsDoctorCheck(ctx context.Context, configPath string) diag.Check {
	c := diag.Check{Name: "security.deps", Status: diag.StatusOK}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		c.Status, c.Message = diag.StatusWarn, "Package checks: config not readable: "+err.Error()
		return c
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		c.Status, c.Message = diag.StatusWarn, "Package checks: config path not resolvable: "+err.Error()
		return c
	}
	active := securitySelected(componentSnapshotForConfig(cfg), securityDepsComponent)
	if !active {
		c.Message = "Package checks: not active; Settings > Components"
		return c
	}
	// Read the floors and the managed pull in force, as the daemon does
	// (P-051), so the online setting shown is the floored one.
	bindDepsFloorsForCLI(ctx, cfg, configPath)
	managed, tenancy := depsDoctorTenancy(ctx, cfg, configPath)
	st := packageChecksStatus(ctx, cfg, resolved, active, managed)
	c.Details = append(c.Details, "node: "+tenancy)
	online := "off (offline lists only)"
	switch {
	case st.Online && st.Accepted:
		online = "on"
	case st.Online:
		online = "waiting for the disclosure to be accepted (Code security page, or observer security deps disclosure)"
	}
	c.Details = append(c.Details, "online checks: "+online)
	c.Details = append(c.Details, depsIndexDownloadLine(cfg.Security.Deps))
	for _, i := range st.Index {
		line := fmt.Sprintf("index %s: %s", i.Kind, i.State)
		if i.State == "installed" {
			line += fmt.Sprintf(", version %d, %s", i.Version, i.Freshness)
			if i.Freshness == "unknown" {
				c.Status = diag.StatusWarn
			}
		}
		if i.LastFailure != "" {
			line += ", last refresh failed: " + i.LastFailure
		}
		c.Details = append(c.Details, line)
	}
	c.Message = "Package checks: active"
	if !st.IndexDownload {
		c.Message = "Package checks: active, index download off (using the index on disk)"
	}
	if st.NotSetUp {
		c.Message = "Package checks: active, not set up yet (no signed index installed and online checks not on); installs are noted once per session, not checked"
		if !st.IndexDownload {
			c.Message += "; the index download is off, so none will arrive until it is on (security.deps.index_download)"
		}
	}
	return c
}
