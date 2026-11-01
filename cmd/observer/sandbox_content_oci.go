//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandbox_content_oci.go hooks the container driver's image resolution to
// the sandbox content fetch (lane SBX-P3D) without changing the driver's
// own file: a resolve in the daemon that needs Observer's default image (an
// empty [terminal.sandbox.oci].image) while nothing is installed starts one
// background fetch of sandbox.image (sandboxContentEnsure: the oci driver
// active, never blocking, retried hourly, daily when the source does not
// publish the kind), then resolves exactly as before from what is installed
// now. The availability probe goes through this resolve, so it never waits
// on the network (SBX-P3D audit finding 3).
func init() {
	base := ociResolveImageFn
	ociResolveImageFn = func(cfg config.TerminalSandboxOCIConfig, observerDir string) ociImageTrust {
		if strings.TrimSpace(cfg.Image) == "" {
			sandboxContentEnsureFn(content.SandboxImage, observerDir)
		}
		return base(cfg, observerDir)
	}
}
