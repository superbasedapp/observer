//go:build sbo_omit_ingest_otlp

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
)

// init_otlp_omit.go is the off side of init_otlp.go: `observer init
// --otlp-export` refuses in a `-tags sbo_omit_ingest_otlp` build, because
// there is no OTLP receiver here for an exporter to send to. Operator rule
// D-514: the refusal names the build and the fix, and exits 3 like every
// compiled-out verb (componentstate.RefusalExitCode).
func runOTLPExportInit(_ io.Writer, _ string, _ []string, _, _ bool) error {
	fmt.Fprintf(os.Stderr, "--otlp-export: OTLP ingest (ingest.otlp) is not in this build; %s. Install a build that includes it, or run `observer init` without --otlp-export.\n",
		components.DistrosHaving("ingest.otlp"))
	return exitErr(componentstate.RefusalExitCode)
}

// runOTLPCloudEnvironment is the off side of `observer init
// --otlp-cloud-endpoint`: no receiver in this build, so no exporter can
// point at it.
func runOTLPCloudEnvironment(_ io.Writer, _, _ string) error {
	fmt.Fprintf(os.Stderr, "--otlp-cloud-endpoint: OTLP ingest (ingest.otlp) is not in this build; %s. Install a build that includes it.\n",
		components.DistrosHaving("ingest.otlp"))
	return exitErr(componentstate.RefusalExitCode)
}
