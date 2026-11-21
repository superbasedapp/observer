//go:build !sbo_omit_security && !sbo_omit_security_dast

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/secdast"
	"github.com/marmutapp/superbased-observer/internal/secdast/dastconsent"
	"github.com/marmutapp/superbased-observer/internal/secdastnet"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_dast_dashboard.go is the dashboard seam of the Code security
// page's DAST card (dashapi.SecurityDAST; security coverage gaps plan
// section 2): the same selection, accept record, lane run and per-project
// record the CLI verb uses (security_dast.go, security_dast_store.go), so
// the dashboard never links the lane (internal/secdastnet). The URL comes
// only from the developer's request body; the project root is one the
// dashboard resolved from its own project index. One run at a time.

// dastDashRun serializes the dashboard's runs.
var dastDashRun sync.Mutex

// securityDASTDash returns the seam for the config at configPath.
func securityDASTDash(configPath string, database *sql.DB) *dashapi.SecurityDAST {
	return &dashapi.SecurityDAST{
		State: func(context.Context) dashapi.DASTState {
			st := dashapi.DASTState{AcceptText: dastconsent.Text}
			e, err := openDASTEnvAt(configPath)
			if err != nil {
				return st
			}
			st.Selected = true
			if c := e.consent(); c.Accepted() {
				st.Accepted, st.AcceptedOn = true, c.Surface
				st.AcceptedAt = c.AcceptedAt.UTC().Format(time.RFC3339)
			}
			return st
		},
		Candidates: func(_ context.Context, root string) []dashapi.DASTCandidate {
			if _, err := openDASTEnvAt(configPath); err != nil || root == "" {
				return []dashapi.DASTCandidate{}
			}
			cands := dastProjectCandidates(root)
			out := make([]dashapi.DASTCandidate, 0, len(cands))
			for _, c := range cands {
				out = append(out, dashapi.DASTCandidate{URL: c.URL, Name: c.Name, Source: c.Source, Listening: c.Listening})
			}
			return out
		},
		LastRuns: func(_ context.Context, root string) []dashapi.DASTOriginRun {
			e, err := openDASTEnvAt(configPath)
			if err != nil || root == "" {
				return []dashapi.DASTOriginRun{}
			}
			return dastOriginRuns(loadDASTRecord(e.dir, secposture.ProjectRootHash(root)))
		},
		Accept: func(context.Context) error {
			e, err := dastDashEnv(configPath)
			if err != nil {
				return err
			}
			if e.consent().Accepted() {
				return nil
			}
			key, err := guardposture.LoadOrCreateKeyBeforePosture(e.keyPath())
			if err != nil {
				return err
			}
			_, err = dastconsent.Record(e.dir, "dashboard", dastLocalAccount(), time.Now(), key)
			return err
		},
		Run: func(ctx context.Context, root, rawURL string, insecureTLS bool) (dashapi.DASTRunResult, error) {
			return dastDashRunOnce(ctx, configPath, database, root, rawURL, insecureTLS)
		},
	}
}

// dastDashEnv opens the DAST env, mapping "not selected" onto the seam's
// refusal.
func dastDashEnv(configPath string) (dastEnv, error) {
	e, err := openDASTEnvAt(configPath)
	if errors.Is(err, errDASTNotSelected) {
		return dastEnv{}, dashapi.ErrDASTNotSelected
	}
	return e, err
}

// dastDashRunOnce is the card's Run: refused unless selected and accepted
// and the URL is a loopback dev server; then the lane's run, recorded
// against root.
func dastDashRunOnce(ctx context.Context, configPath string, database *sql.DB, root, rawURL string, insecureTLS bool) (dashapi.DASTRunResult, error) {
	if !dastDashRun.TryLock() {
		return dashapi.DASTRunResult{}, dashapi.ErrDASTBusy
	}
	defer dastDashRun.Unlock()
	e, err := dastDashEnv(configPath)
	if err != nil {
		return dashapi.DASTRunResult{}, err
	}
	if !e.consent().Accepted() {
		return dashapi.DASTRunResult{}, dashapi.ErrDASTNotAccepted
	}
	t, err := secdast.ParseTarget(rawURL)
	if err != nil {
		return dashapi.DASTRunResult{}, fmt.Errorf("%w: %w", dashapi.ErrDASTBadTarget, err)
	}
	if root == "" {
		return dashapi.DASTRunResult{}, errors.New("dast: no project to record against")
	}
	if database == nil {
		return dashapi.DASTRunResult{}, errors.New("dast: no database to record the run in")
	}
	run, err := runDASTLane(ctx, t, secdastnet.Options{InsecureTLS: insecureTLS}, time.Now())
	if err != nil {
		return dashapi.DASTRunResult{}, err
	}
	created, err := recordDASTRun(ctx, store.New(database), e.dir, root, t, run.Report, run.Findings, run.Started, run.Took)
	if err != nil {
		return dashapi.DASTRunResult{}, err
	}
	securityRT.notify()
	res := dashapi.DASTRunResult{
		Target: run.Report.Target, Outcome: run.Report.Outcome, Requests: run.RoundTrips,
		Checks: run.Report.Checks, Findings: len(run.Findings), New: created,
	}
	if run.Report.Outcome == secdast.OutcomeUnreachable && len(run.Report.Errors) > 0 {
		res.Reason = run.Report.Errors[0].Error
	}
	return res, nil
}

// dastOriginRuns lists a project's record, newest run first.
func dastOriginRuns(rec dastProjectRecord) []dashapi.DASTOriginRun {
	out := make([]dashapi.DASTOriginRun, 0, len(rec.Origins))
	for origin, r := range rec.Origins {
		out = append(out, dashapi.DASTOriginRun{Origin: origin, At: r.At.UTC().Format(time.RFC3339), Outcome: r.Outcome, Findings: r.Findings})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].At != out[j].At {
			return out[i].At > out[j].At
		}
		return out[i].Origin < out[j].Origin
	})
	return out
}
