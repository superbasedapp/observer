//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_scan_dash.go is the dashboard seam of the scanners' one-time
// database accept (operator ruling PT-19 (2)): the Scanners card reads the
// download gate's state through it and records the developer's accept
// given in its confirm dialog, through the same record the CLI writes
// (osvdb.RecordConsent) and the same gate the daemon walks
// (depsDownloadGate).

// scannerDBDash returns the seam for the config at configPath.
func scannerDBDash(configPath string, database *sql.DB) *dashapi.ScannerDB {
	open := func() (*depsScanEnv, bool, error) {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return nil, false, err
		}
		resolved, err := config.ResolveGlobalPath(configPath)
		if err != nil {
			return nil, false, err
		}
		dir := secposture.LayoutFor(resolved).Dir
		e := &depsScanEnv{cfg: cfg, dir: dir, db: osvdb.Open(filepath.Join(dir, "osv")), disclose: readDepsDisclosure(dir), consent: osvdb.ReadConsent(dir, depsRecordKey(dir))}
		if database != nil {
			if lk := managedTenancyLookup(store.New(database)); lk != nil {
				e.managed = lk()
			}
		}
		return e, depsScanSelected(componentSnapshotForConfig(cfg)), nil
	}
	return &dashapi.ScannerDB{
		Status: func(context.Context) (dashapi.ScannerDBStatus, error) {
			e, _, err := open()
			if err != nil {
				return dashapi.ScannerDBStatus{}, err
			}
			return scannerDBStatus(e), nil
		},
		Accept: func(context.Context) error {
			e, active, err := open()
			if err != nil {
				return err
			}
			if !active {
				return errors.New("no dependency driver is selected on this node")
			}
			if e.managed {
				return errors.New("a managed node's OSV databases come from its organization's mirror: there is nothing to accept")
			}
			key, err := depsRecordSigningKey(e.dir)
			if err != nil {
				return err
			}
			_, err = osvdb.RecordConsent(e.dir, "dashboard", depsLocalAccount(), time.Now(), key)
			return err
		},
	}
}

// scannerDBStatus assembles the card's state.
func scannerDBStatus(e *depsScanEnv) dashapi.ScannerDBStatus {
	out := dashapi.ScannerDBStatus{
		Accepted: e.consent.Accepted(), ApproxMB: osvdb.ApproxDownloadMB, Source: osvdb.Source, Text: osvdb.ConsentText,
		Managed: e.managed, Blocked: e.downloadBlocked(),
	}
	if out.Accepted {
		out.AcceptedAt, out.AcceptedOn, out.By = e.consent.AcceptedAt.UTC().Format(time.RFC3339), e.consent.Surface, e.consent.By
	}
	if eps, err := e.db.Installed(); err == nil {
		out.Installed = len(eps)
	}
	return out
}
