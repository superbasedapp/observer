//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
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
		e := &depsScanEnv{cfg: cfg, dir: dir, db: osvdb.Open(filepath.Join(dir, "osv")), disclose: readDepsDisclosure(dir), consent: osvdb.ReadConsent(dir, depsRecordKey(dir)), osConsent: osvdb.ReadOSConsent(dir, depsRecordKey(dir))}
		// The package lookup posture's records (lane RM-2).
		e.remoteConsent, e.remotePrivate = osvdb.ReadRemoteConsent(dir, depsRecordKey(dir)), osvdb.ReadRemotePrivateConsent(dir, depsRecordKey(dir))
		e.configPath, e.logger = configPath, slog.Default()
		if database != nil {
			if lk := managedTenancyLookup(store.New(database)); lk != nil {
				e.managed = lk()
			}
		}
		return e, depsScanSelected(componentSnapshotForConfig(cfg)), nil
	}
	seam := &dashapi.ScannerDB{
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
		// The OS release databases' one accept (ruling Q1 (b)), its own
		// signed record (osvdb.RecordOSConsent).
		AcceptOS: func(context.Context) error {
			e, active, err := open()
			if err != nil {
				return err
			}
			if !active {
				return errors.New("no dependency driver is selected on this node")
			}
			if e.managed {
				return errors.New("a managed node's OS release databases come from its organization's mirror: there is nothing to accept")
			}
			key, err := depsRecordSigningKey(e.dir)
			if err != nil {
				return err
			}
			_, err = osvdb.RecordOSConsent(e.dir, "dashboard", depsLocalAccount(), time.Now(), key)
			return err
		},
	}
	// The package lookup posture (lane RM-2, plan section 13.10): the
	// Privacy page's card reads it and changes it through the one writer
	// the CLI uses (applyLookupChange); a managed node refuses every change.
	seam.Lookup = func(ctx context.Context) (dashapi.PackageLookupStatus, error) {
		e, _, err := open()
		if err != nil {
			return dashapi.PackageLookupStatus{}, err
		}
		return lookupStatus(ctx, e), nil
	}
	seam.SetLookup = func(ctx context.Context, ch dashapi.PackageLookupChange) error {
		e, active, err := open()
		if err != nil {
			return err
		}
		if !active {
			return errors.New("no dependency driver is selected on this node")
		}
		return applyLookupChange(ctx, e, lookupChange{PackageLookupChange: ch, surface: "dashboard"})
	}
	// The artifact folders (M3L-2 item 4, ruling 2026-11-05): a project's
	// candidate build output folders and the developer's per-folder choice.
	// Local to this machine and the developer's call (guard rule R-165
	// denies an agent the route and the file); a managed node's developer
	// keeps the choice too, since artifacts are the developer's own build
	// output.
	seam.Artifacts = func(_ context.Context, root string) (dashapi.ArtifactFolders, error) {
		e, _, err := open()
		if err != nil {
			return dashapi.ArtifactFolders{}, err
		}
		return artifactFolders(e.dir, root), nil
	}
	seam.SetArtifact = func(_ context.Context, root string, ch dashapi.ArtifactChange) error {
		e, active, err := open()
		if err != nil {
			return err
		}
		if !active {
			return errors.New("no dependency driver is selected on this node")
		}
		if !scalibrfacade.Compiled {
			return errors.New("the SCALIBR driver, which reads build artifacts, is not in this build")
		}
		_, err = setArtifactDir(e.dir, root, ch.Dir, ch.Enabled)
		return err
	}
	// The Go source check (3b-src): the project's signed opt-in, its status
	// and a run started from the card. The developer's (R-165 denies an
	// agent the route and the record).
	wireReachSourceDash(seam, open)
	// Trivy's database accept (lane OS-2 T), its own signed record
	// (osvdb.RecordTrivyConsent); nil in a build without the Trivy image
	// driver, so the route answers 404.
	if trivyImageCompiled() {
		seam.AcceptTrivyDB = func(context.Context) error {
			e, _, err := open()
			if err != nil {
				return err
			}
			return acceptTrivyDBDash(e)
		}
	}
	return seam
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
	out.DBSource, out.SourceOrder = e.dbSetting(), e.sourcePlan()
	if rec, ok := readDepsOSVSource(e.dir); ok {
		out.LastSource, out.LastSourceAt, out.Fallback, out.SourceError = rec.Source, rec.At.UTC().Format(time.RFC3339), rec.Fallback, rec.Error
	}
	out.OS = osDBStatus(e)
	out.Image = imageDriverStatus(e)            // lane OS-2 T
	lk := lookupStatus(context.Background(), e) // lane RM-2
	out.Lookup = &lk
	return out
}
