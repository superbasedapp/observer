//go:build sbo_omit_capture_browser

package diag

import (
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// browserExtensionHealthNote is the off side of browserextension.go: in a
// `-tags sbo_omit_capture_browser` build there is no native-messaging host
// to probe, so the browser rows say so instead, and diag does not import
// internal/browserhost (modular packaging plan 5.1, lane MP-L1B).
func browserExtensionHealthNote(_ string, _ config.Config, note func(Status, string), _ func(remedy.Remediation)) {
	note(StatusOK, "browser capture is not in this build (compiled out)")
}
