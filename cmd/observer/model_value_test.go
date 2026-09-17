package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/intelligence/modelvalue"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestModelValue_EndToEnd runs the report CLI over the simulate corpus
// and pins the headline output: caveat present, cells populated, JSON
// decodable.
func TestModelValue_EndToEnd(t *testing.T) {
	cfgPath := seedRoutingSimCorpus(t)

	cmd := newModelValueCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--config", cfgPath, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("model-value: %v\n%s", err, out.String())
	}
	var rep modelvalue.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v\n%s", err, out.String())
	}
	if rep.Caveat == "" {
		t.Error("report missing the attribution caveat")
	}
	if len(rep.GlobalCells) == 0 || rep.GlobalCells[0].Turns != 3 {
		t.Errorf("global cells = %+v, want one cell with 3 turns", rep.GlobalCells)
	}

	// Human output leads with the caveat.
	human := newModelValueCmd()
	var hout bytes.Buffer
	human.SetOut(&hout)
	human.SetErr(&hout)
	human.SetArgs([]string{"--config", cfgPath})
	if err := human.Execute(); err != nil {
		t.Fatalf("model-value (human): %v", err)
	}
	if !strings.Contains(hout.String(), "correlational") {
		t.Errorf("human output missing correlational caveat:\n%s", hout.String())
	}
}

// TestModelValue_SaveCalibration pins the one-owner write path: cells
// persist through store.UpsertModelCalibrations and re-running upserts
// rather than duplicating.
func TestModelValue_SaveCalibration(t *testing.T) {
	cfgPath := seedRoutingSimCorpus(t)

	run := func() {
		cmd := newModelValueCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"--config", cfgPath, "--save-calibration", "--json"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("model-value --save-calibration: %v\n%s", err, out.String())
		}
	}
	run()

	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)

	first, err := st.CountModelCalibrations(ctx)
	if err != nil {
		t.Fatalf("CountModelCalibrations: %v", err)
	}
	if first == 0 {
		t.Fatal("no calibration cells persisted")
	}
	run() // idempotent re-run
	second, err := st.CountModelCalibrations(ctx)
	if err != nil {
		t.Fatalf("CountModelCalibrations (2nd): %v", err)
	}
	if second != first {
		t.Errorf("calibration cells %d → %d after re-run; want upsert-stable", first, second)
	}
}

// TestRoutingStatusAndLint_EndToEnd smoke-tests the two status surfaces
// over the same corpus.
func TestRoutingStatusAndLint_EndToEnd(t *testing.T) {
	cfgPath := seedRoutingSimCorpus(t)

	status := newRoutingCmd()
	var sout bytes.Buffer
	status.SetOut(&sout)
	status.SetErr(&sout)
	status.SetArgs([]string{"status", "--config", cfgPath})
	if err := status.Execute(); err != nil {
		t.Fatalf("routing status: %v\n%s", err, sout.String())
	}
	for _, want := range []string{"phase P0", "off", "value", "frugal", "plan-exec"} {
		if !strings.Contains(sout.String(), want) {
			t.Errorf("status output missing %q:\n%s", want, sout.String())
		}
	}

	lint := newRoutingCmd()
	var lout bytes.Buffer
	lint.SetOut(&lout)
	lint.SetErr(&lout)
	lint.SetArgs([]string{"lint"})
	if err := lint.Execute(); err != nil {
		t.Fatalf("routing lint (shipped templates must be clean): %v\n%s", err, lout.String())
	}
	if !strings.Contains(lout.String(), "OK") {
		t.Errorf("lint output missing OK:\n%s", lout.String())
	}

	unknown := newRoutingCmd()
	unknown.SetOut(&lout)
	unknown.SetErr(&lout)
	unknown.SetArgs([]string{"lint", "--policy", "bogus"})
	if err := unknown.Execute(); err == nil {
		t.Error("lint --policy bogus succeeded, want error")
	}
}
