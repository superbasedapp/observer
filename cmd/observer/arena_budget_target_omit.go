//go:build sbo_omit_benchmark

package main

import "context"

// arenaAdmissionTarget finds no target in a build without the benchmark
// module (Arena is not built, so nothing calls the seam).
func arenaAdmissionTarget(context.Context) (dir, source string, addEnv func([]string), ok bool) {
	return "", "", nil, false
}

// arenaAdmissionProjectRoot: no arena in this build, so no project root.
func arenaAdmissionProjectRoot(context.Context) string { return "" }
