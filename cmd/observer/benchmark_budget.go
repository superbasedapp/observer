package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/benchmark"
)

// enforceBenchmarkBudget keeps the originating node's authority across an
// isolated benchmark daemon. Vendor/provider overrides and isolated spend
// accounting do not establish coverage by that node's managed hard cap.
//
// It carries no executable evidence, for two reasons that both hold: the
// process a driver starts is Observer's own harness launcher (which runs this
// gate again with the vendor binary's real evidence), and "benchmark" is not a
// registry adapter at all — it has no installed surface a process cutoff could
// be attested over, so there is nothing to recover to.
func enforceBenchmarkBudget(ctx context.Context, configPath string) error {
	return enforceBudgetControlledLaunch(ctx, configPath, "benchmark",
		budgetLaunchEvidence{Route: budgetLaunchRouteUnknown})
}

// budgetControlledBenchmarkDrivers wraps every production driver at the
// registry boundary. Each attempt rechecks the originating node so a budget
// delivered after the matrix started still prevents the next AI process.
func budgetControlledBenchmarkDrivers(observerBin, dbPath, configPath string) map[string]HarnessDriver {
	drivers := newBenchmarkDrivers(observerBin, dbPath)
	for name, driver := range drivers {
		drivers[name] = budgetControlledBenchmarkDriver{HarnessDriver: driver, configPath: configPath}
	}
	return drivers
}

type budgetControlledBenchmarkDriver struct {
	HarnessDriver
	configPath string
}

func (d budgetControlledBenchmarkDriver) Drive(ctx context.Context, req DriveRequest) (DriveResult, error) {
	if err := enforceBenchmarkBudget(ctx, d.configPath); err != nil {
		return DriveResult{}, err
	}
	return d.HarnessDriver.Drive(ctx, req)
}

// Preflight preserves a wrapped driver's existing isolation requirements.
// Dry runs perform preflight but do not invoke the spending admission check.
func (d budgetControlledBenchmarkDriver) Preflight() error {
	if inner, ok := d.HarnessDriver.(preflightDriver); ok {
		return inner.Preflight()
	}
	return nil
}

type budgetControlledBenchmarkScorer struct {
	inner      attemptScorer
	configPath string
}

func (s budgetControlledBenchmarkScorer) Score(ctx context.Context, in scoreInput) ([]benchmark.ScoreRecord, error) {
	if err := enforceBenchmarkBudget(ctx, s.configPath); err != nil {
		return nil, err
	}
	return s.inner.Score(ctx, in)
}
