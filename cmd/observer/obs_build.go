package main

import (
	"slices"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// obs_build.go holds the build-agnostic half of the observability.build
// doctor row and the start-time WARN (W0-4, F06): the wording a build
// WITHOUT Plane A uses when [observability] is turned on, so the obs and the
// no_obs halves (obs_wire.go / obs_wire_stub.go) share one vocabulary.

// obsBuildCheckName is the doctor row naming whether Plane A is in the build.
const obsBuildCheckName = "observability.build"

// obsEditionLabel names this binary's edition for a message: the stamped
// distro, else "full" when obs is compiled and "custom" when it is not (an
// unstamped build without obs was built with omit tags by hand).
func obsEditionLabel() string {
	if d := components.BuildDistro(); d != "" {
		return string(d) + " edition"
	}
	if slices.Contains(components.Omitted(), "obs") {
		return "custom"
	}
	return "full edition"
}
