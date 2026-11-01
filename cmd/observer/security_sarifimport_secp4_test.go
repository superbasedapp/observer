//go:build !sbo_omit_security && !sbo_omit_security_scan_sarif_import

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secscan/sarifimport"
)

// TestSARIFImportDashSeam (lane SEC-P4 decision 13): the dashboard upload
// carries the CLI's own picker and cap and calls importSARIFFile; a file
// the adapter refuses and an unknown tool read as input errors (400), with
// the adapter's own text kept for the CLI.
func TestSARIFImportDashSeam(t *testing.T) {
	if sarifImportDash(nil) != nil {
		t.Fatal("no database: no seam")
	}
	st, database := openTestStore(t)
	seam := sarifImportDash(database)
	if seam == nil || seam.MaxBytes != sarif.MaxBytes || len(seam.Tools) != len(sarifimport.Tools) {
		t.Fatalf("seam = %+v", seam)
	}
	ctx := context.Background()
	root := t.TempDir()
	if _, err := seam.Import(ctx, root, "nmap", []byte(testSARIF)); !errors.Is(err, dashapi.ErrSARIFImportInput) {
		t.Fatalf("unknown tool: %v", err)
	}
	_, err := seam.Import(ctx, root, "gosec", []byte(`{"version":"1.0.0"}`))
	if !errors.Is(err, dashapi.ErrSARIFImportInput) {
		t.Fatalf("a refused file: %v, want an input error", err)
	}
	if _, cliErr := importSARIFFile(ctx, st, root, "gosec", []byte(`{"version":"1.0.0"}`)); cliErr == nil || cliErr.Error() != err.Error() {
		t.Fatalf("the CLI's text changed: %v", cliErr)
	}
	got, err := seam.Import(ctx, root, "gosec", []byte(testSARIF))
	if err != nil {
		t.Fatal(err)
	}
	if rep, ok := got.(sarifImportReport); !ok || rep.Findings == 0 || rep.Tool != "gosec" {
		t.Fatalf("report = %#v", got)
	}
}
