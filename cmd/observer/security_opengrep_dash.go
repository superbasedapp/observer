//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_opengrep_dash.go is the dashboard seam of the code rules (lane
// SEC-G2): the Code rules card reads the state through it, and its install
// dialog gives the developer's size consent and starts the guided install
// through installEngine, the same seam the CLI calls.

// codeInstallTimeout bounds one dashboard install (a 47 MB download).
const codeInstallTimeout = 20 * time.Minute

// codeEnvForDash builds the env over the dashboard's own database handle;
// nil when the component is not selected.
func codeEnvForDash(configPath string, database *sql.DB) (*codeEnv, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return nil, err
	}
	snap := componentSnapshotForConfig(cfg)
	if !codeScanSelected(snap) {
		return nil, nil
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return nil, err
	}
	e := &codeEnv{cfg: cfg, resolved: resolved, secDir: secposture.LayoutFor(resolved).Dir, snap: snap, configPath: configPath, cleanup: func() {}}
	if database != nil {
		e.st = store.New(database)
		if lk := managedTenancyLookup(e.st); lk != nil {
			e.managed = lk()
		}
	}
	cs := codeRulesStore(resolved)
	if e.pack, err = loadCodePack(cs, codeRulesTrust()); err != nil {
		return nil, err
	}
	e.manifest = loadEngineManifest(cs, codeRulesTrust())
	return e, nil
}

// opengrepDash returns the seam for the config at configPath.
func opengrepDash(configPath string, database *sql.DB) *dashapi.Opengrep {
	return &dashapi.Opengrep{
		Status: func(ctx context.Context) (dashapi.OpengrepStatus, error) {
			e, err := codeEnvForDash(configPath, database)
			if err != nil || e == nil {
				return dashapi.OpengrepStatus{}, err
			}
			return e.dashStatus(ctx), nil
		},
		Install: func(ctx context.Context, sha256 string) error {
			e, err := codeEnvForDash(configPath, database)
			if err != nil {
				return err
			}
			if e == nil {
				return errors.New("the code rules are not selected on this node")
			}
			return startCodeInstallJob(ctx, e, sha256)
		},
	}
}

// startCodeInstallJob checks the plan, records the consent at once (the
// dialog's accept IS the consent), and runs the download in the background;
// the card polls the job through Status. seen is the sha256 the dialog
// showed: a plan whose pin is another (a manifest that landed between the
// card's GET and the accept, an old card that sends none) is refused with
// *dashapi.OpengrepPinChanged before anything is recorded (lane SEC-G2
// audit finding 3).
func startCodeInstallJob(ctx context.Context, e *codeEnv, seen string) error {
	p := secengine.PlanInstall(e.installInput(ctx))
	switch {
	case p.Blocked != "":
		return errors.New("the install is blocked: " + codeBlockedWords(p.Blocked))
	case p.Installed:
		return nil
	case !strings.EqualFold(strings.TrimSpace(seen), p.Pin.SHA256) || p.Pin.SHA256 == "":
		return &dashapi.OpengrepPinChanged{SHA256: p.Pin.SHA256}
	}
	if !e.managed && !readCodeInstallConsent(e.secDir).Covers(p) {
		c, err := secengine.NewInstallConsent(p, codeSurfaceDashboard, depsLocalAccountName(), time.Now())
		if err != nil {
			return err
		}
		if _, err := recordCodeInstallConsent(e.secDir, c); err != nil {
			return err
		}
	}
	codeInstallJob.mu.Lock()
	if codeInstallJob.running {
		codeInstallJob.mu.Unlock()
		return errors.New("an install is already running")
	}
	codeInstallJob.running, codeInstallJob.lastErr = true, ""
	codeInstallJob.mu.Unlock()
	go func() {
		// The download outlives the request: the job keeps the request's
		// values but not its cancellation.
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), codeInstallTimeout)
		defer cancel()
		_, err := e.installEngine(bg, codeSurfaceDashboard, false)
		codeInstallJob.mu.Lock()
		defer codeInstallJob.mu.Unlock()
		codeInstallJob.running, codeInstallJob.doneAt = false, time.Now()
		if err != nil {
			codeInstallJob.lastErr = err.Error()
		}
	}()
	return nil
}

// dashStatus assembles the card's state; it starts no process.
func (e *codeEnv) dashStatus(ctx context.Context) dashapi.OpengrepStatus {
	out := dashapi.OpengrepStatus{Selected: true, Managed: e.managed}
	p := secengine.PlanInstall(e.installInput(ctx))
	if p.Blocked != "" {
		out.Blocked, out.BlockedText = p.Blocked, codeBlockedWords(p.Blocked)
	} else {
		out.Source, out.PinFrom, out.URL = string(p.Source), p.PinFrom, p.URL
		out.Version, out.OS, out.Arch, out.SHA256 = p.Pin.Version, p.Pin.OS, p.Pin.Arch, p.Pin.SHA256
		out.DownloadBytes, out.TreeBytes, out.TreeFiles = p.DownloadBytes, p.TreeBytes, p.TreeFiles
		out.Installed = p.Installed
		if !e.managed {
			out.ConsentText = secengine.ConsentText(p)
		}
	}
	if c := readCodeInstallConsent(e.secDir); c.Covers(p) {
		out.Consented, out.ConsentedAt, out.ConsentedOn, out.By = true, c.AcceptedAt.UTC().Format(time.RFC3339), c.Surface, c.By
	}
	if s, ok := readCodeInstallState(e.secDir); ok {
		out.InstalledAt = s.At.UTC().Format(time.RFC3339)
	}
	codeInstallJob.mu.Lock()
	out.Installing, out.LastError = codeInstallJob.running, codeInstallJob.lastErr
	codeInstallJob.mu.Unlock()
	if d, err := e.inspector(); err == nil {
		if pr := d.Probe(ctx); pr.Installed {
			info := d.Inspect()
			out.Engine, out.Verification = info.Binary, decisionWords(info.Decision)
		}
	}
	out.PackVersion, out.PackSource, out.PackNote = e.pack.Pack.Version(), string(e.pack.Source), e.pack.Note
	out.PackFreshness = string(e.pack.Freshness)
	if f, ok := readCodeFetch(e.secDir)[string(content.RulePack)]; ok {
		out.FetchSource, out.FetchAt, out.FetchError = f.Source, f.At.UTC().Format(time.RFC3339), f.Error
	}
	if e.st != nil {
		if r, ok, err := e.st.SecLatestRun(ctx, opengrep.DriverID); err == nil && ok {
			out.LastRunAt, out.LastRunOutcome, out.LastRunLabels = r.StartedAt.UTC().Format(time.RFC3339), r.Outcome, codeRunLabels(r.Notes)
		}
		if words, at, ok := codeLastTaintPass(ctx, e.st); ok {
			out.LastTaintPass, out.LastTaintPassAt = words, at.UTC().Format(time.RFC3339)
		}
	}
	oc := e.cfg.Security.Scan.Opengrep
	out.PostWrite, out.CommitDiff, out.ScheduleHours = oc.PostWrite, oc.CommitDiff, oc.ScheduleHours
	out.Isolation = "not isolated: runs are labelled (no bwrap, or the isolation component is off)"
	if isolationFactoryFor(e.snap, filepath.Dir(e.resolved), nil) != nil && isolationAvailable() {
		out.Isolation = "isolated: bwrap one-shot with no network"
	}
	return out
}
