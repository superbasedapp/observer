//go:build !sbo_omit_security

package seccustomsvc

import (
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun/host"
)

// TestMain offers the runner's trampoline exactly as the observer binary
// does (first thing in main), so the real-process tests apply their caps
// before exec.
func TestMain(m *testing.M) {
	if code, ok := host.TrampolineDispatch(os.Args); ok {
		os.Exit(code)
	}
	os.Exit(m.Run())
}
