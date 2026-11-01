//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_deps_dash.go is the install gate's dashboard seam (milestone 3b
// of lane sec-d1fix): the Code security page's Package checks card reads
// the state and records the developer's accept of the online checks'
// disclosure there, through the same disclosure record the CLI writes (one
// owner: recordDepsDisclosure).

// packageChecksDash returns the seam for the config at configPath.
func packageChecksDash(configPath string, database *sql.DB) *dashapi.PackageChecks {
	load := func() (config.Config, string, bool, error) {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return config.Config{}, "", false, err
		}
		resolved, err := config.ResolveGlobalPath(configPath)
		if err != nil {
			return config.Config{}, "", false, err
		}
		return cfg, resolved, securitySelected(componentSnapshotForConfig(cfg), securityDepsComponent), nil
	}
	return &dashapi.PackageChecks{
		Status: func(ctx context.Context) (dashapi.PackageChecksStatus, error) {
			cfg, resolved, active, err := load()
			if err != nil {
				return dashapi.PackageChecksStatus{}, err
			}
			var st *store.Store
			if database != nil {
				st = store.New(database)
			}
			return packageChecksStatus(ctx, cfg, resolved, active, depsTenancyOf(st)(ctx) == depsManaged), nil
		},
		Accept: func(context.Context) error {
			_, resolved, active, err := load()
			if err != nil {
				return err
			}
			if !active {
				return errors.New("package checks (security.deps) are not active on this node")
			}
			_, err = recordDepsDisclosure(secposture.LayoutFor(resolved).Dir, "dashboard", time.Now())
			return err
		},
	}
}

// packageChecksStatus assembles the card's state.
func packageChecksStatus(_ context.Context, cfg config.Config, resolved string, active, managed bool) dashapi.PackageChecksStatus {
	dir := secposture.LayoutFor(resolved).Dir
	d := readDepsDisclosure(dir)
	out := dashapi.PackageChecksStatus{
		// The setting in force: a floor's allow.online_checks = forbidden
		// shows as off (SEC-E merge audit finding 3).
		Active: active, Online: depsInForce(cfg.Security).Online, Managed: managed, Accepted: d.Shown(), Text: secfeed.DisclosureText,
		IndexDownload: depsIndexDownloadAllowed(cfg.Security.Deps),
	}
	if managed {
		out.Text = secfeed.DisclosureTextManaged
	}
	if d.Shown() {
		out.AcceptedAt, out.AcceptedOn = d.ShownAt.UTC().Format(time.RFC3339), d.Surface
	}
	cs := depsContentStore(resolved)
	out.NotSetUp = depsNotSetUp(cs, dir)
	for _, k := range depsFeedKinds {
		row := dashapi.PackageChecksIndex{Kind: string(k.kind), State: "not_installed"}
		st, err := cs.State(k.kind)
		switch {
		case err != nil:
			row.State = "unreadable"
		case st.Accepted != nil:
			row.State, row.Version = "installed", st.Accepted.ManifestVersion
			if l, err := cs.Load(k.kind, depsTrust(), depsAdvisoryFloor(cfg.Security)); err == nil {
				row.Freshness = string(l.Freshness)
			} else {
				row.Freshness = "unknown"
			}
		}
		if err == nil {
			row.LastFailure = string(st.LastFailure)
		}
		out.Index = append(out.Index, row)
	}
	return out
}
