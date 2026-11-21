//go:build sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// Reads answers false: no extractor is linked in this build.
func Reads(string) bool { return false }

// UnreadFiles answers ErrNotCompiled: nothing is extracted in this build,
// so the driver reports the project "not scanned", never clean.
func UnreadFiles(context.Context, string, ExtractOptions) ([]depscan.Gap, error) {
	return nil, ErrNotCompiled
}
