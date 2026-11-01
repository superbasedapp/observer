package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestAddHookLiveness: silent tools become the closed hook_silent_surface
// label located on each tool, which survives the wire normalization; no
// source, a failed read or no silent tool adds nothing.
func TestAddHookLiveness(t *testing.T) {
	now := time.Now()
	silent := func(context.Context, time.Time) ([]string, error) { return []string{"claude-code", "dimcode"}, nil }
	rep := orgcontract.ManagedIntegrityReport{CaptureCheckVersion: orgcontract.ManagedCaptureCheckVersion}
	addHookLiveness(context.Background(), silent, now, &rep)
	norm := rep.NormalizeLabels()
	if !reflect.DeepEqual(norm.CaptureRisks, []string{orgcontract.CaptureRiskHookSilentSurface}) {
		t.Fatalf("CaptureRisks = %v", norm.CaptureRisks)
	}
	var tools []string
	for _, it := range norm.CaptureRiskItems {
		if it.Risk != orgcontract.CaptureRiskHookSilentSurface || it.File != "" || it.At != "" {
			t.Fatalf("item %+v", it)
		}
		tools = append(tools, it.Tool)
	}
	if !reflect.DeepEqual(tools, []string{"claude-code", "dimcode"}) {
		t.Fatalf("located tools %v", tools)
	}
	for name, src := range map[string]hookSilentSource{
		"no source":  nil,
		"read fails": func(context.Context, time.Time) ([]string, error) { return nil, errors.New("db busy") },
		"all live":   func(context.Context, time.Time) ([]string, error) { return nil, nil },
	} {
		var r orgcontract.ManagedIntegrityReport
		addHookLiveness(context.Background(), src, now, &r)
		if len(r.CaptureRisks) != 0 || len(r.CaptureRiskItems) != 0 {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if storeHookSilentSource(nil) != nil {
		t.Error("no store must mean no source")
	}
}
