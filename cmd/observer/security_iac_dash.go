//go:build !sbo_omit_security

package main

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/seciac"
)

// security_iac_dash.go is the dashboard seam of the IaC engines (lane
// GATES-SEC): the rows of the Code security page's data-driven Scanners
// card and the guided install's POST. A row for an engine that is not
// selected reads only the selection: nothing is probed, planned or written.

// iacDash returns the seam.
func iacDash(configPath string, database *sql.DB) *dashapi.IaC {
	return &dashapi.IaC{
		Rows: func(ctx context.Context) []dashapi.IaCScannerRow { return iacDashRows(ctx, configPath, database) },
		Install: func(ctx context.Context, engine, sha256 string) error {
			id, err := iacEngineFlag(engine)
			if err != nil {
				return err
			}
			e, err := iacEnvFor(configPath, database, id)
			if err != nil {
				return err
			}
			if e == nil {
				return errIaCNotSelected(id)
			}
			p := seciac.PlanInstall(e.installInput(ctx))
			if !strings.EqualFold(p.Pin.AssetSHA256, strings.TrimSpace(sha256)) {
				return fmt.Errorf("the %s pin changed since the dialog was shown (now sha256 %q); nothing was recorded: review the new pin and accept again", id, p.Pin.AssetSHA256)
			}
			_, err = e.installIaCEngine(ctx, "dashboard", true)
			return err
		},
	}
}

func iacDashRows(ctx context.Context, configPath string, database *sql.DB) []dashapi.IaCScannerRow {
	var out []dashapi.IaCScannerRow
	for _, eng := range seciac.Engines() {
		_, compiled := iacBindings[eng.ID]
		row := dashapi.IaCScannerRow{Component: iacComponent(eng.ID), Driver: string(eng.ID), Kind: "process", Compiled: compiled, Platform: "untested", Beta: true, Labels: []string{}}
		e, err := iacEnvFor(configPath, database, eng.ID)
		switch {
		case !compiled:
			row.Platform, row.Note = "unsupported", "Not in this build."
		case err != nil || e == nil:
			row.Note = "Not selected: IaC checks are opt-in (add " + row.Component + " and security.code under [components]). Nothing is installed, downloaded or run."
		default:
			row.Selected = true
			in := e.inspector().Inspect()
			row.Note = iacStatusLine(eng, in)
			if eng.RequireIsolation {
				row.Labels = append(row.Labels, "isolated only")
			}
			p := seciac.PlanInstall(e.installInput(ctx))
			row.Installed = p.Installed
			if p.Blocked != "" {
				row.InstallBlocked = seciac.BlockedWords(eng.ID, p.Blocked, runtime.GOOS, runtime.GOARCH)
			} else if !p.Installed {
				row.InstallPin, row.InstallBytes, row.InstallConsent = p.Pin.AssetSHA256, p.DownloadBytes, seciac.ConsentText(p)
			}
		}
		out = append(out, row)
	}
	return out
}
