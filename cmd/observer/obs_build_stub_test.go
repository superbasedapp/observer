//go:build no_obs || sbo_omit_obs || sbo_omit_judge_client

package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
)

// TestObsBuildDoctorCheck_NotCompiled pins W0-4 / F06: in a build without
// Plane A, [observability].enabled = true is a doctor WARN and a start-time
// WARN naming the edition, never a silent no-op.
func TestObsBuildDoctorCheck_NotCompiled(t *testing.T) {
	cfg := config.Default()
	if c := obsBuildDoctorCheck(cfg); c.Status != diag.StatusOK {
		t.Fatalf("disabled: %+v", c)
	}
	cfg.Observability.Enabled = true
	c := obsBuildDoctorCheck(cfg)
	if c.Status != diag.StatusWarn || !strings.Contains(c.Message, "does not include AI Apps") {
		t.Fatalf("enabled: %+v", c)
	}
	var buf bytes.Buffer
	if h := newObsTraceHandler(t.Context(), cfg, nil, slog.New(slog.NewTextHandler(&buf, nil))); h != nil {
		t.Fatal("stub must serve nothing")
	}
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "edition=") {
		t.Fatalf("missing WARN naming the edition: %s", buf.String())
	}
}
