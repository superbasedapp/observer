package sandboxapple

import (
	"fmt"
	"strings"
)

// env.go builds the container's environment (written to the run's env file,
// never put on the argv).

// envDenied are variables the container never carries: engine endpoints,
// loader and runtime hooks, and host-only paths a Linux guest cannot use
// (the macOS PATH and TMPDIR; the image's own PATH applies).
var envDenied = []string{
	"DOCKER_HOST", "CONTAINER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
	"LD_PRELOAD", "LD_LIBRARY_PATH", "NODE_OPTIONS", "PATH", "TMPDIR",
}

// ContainerEnv filters environ for the container: every denied variable,
// every DYLD_* loader variable and each name in alsoDrop is removed, and
// entries without a name are skipped. The order is kept.
func ContainerEnv(environ, alsoDrop []string) []string {
	drop := map[string]bool{}
	for _, k := range envDenied {
		drop[k] = true
	}
	for _, k := range alsoDrop {
		drop[k] = true
	}
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" || drop[k] || strings.HasPrefix(k, "DYLD_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// MergeEnv is the agent's environment inside the guest: base (the
// container's own, the image's PATH included) without the names in drop,
// then each entry of over (the launch environment the host sent through the
// tunnel), an entry of over replacing base's of the same name. The order is
// base's, then over's new names.
func MergeEnv(base, over, drop []string) []string {
	skip := map[string]bool{}
	for _, k := range drop {
		skip[k] = true
	}
	set := map[string]string{}
	var order []string
	put := func(kv string) {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" || skip[k] {
			return
		}
		if _, seen := set[k]; !seen {
			order = append(order, k)
		}
		set[k] = kv
	}
	for _, kv := range base {
		put(kv)
	}
	for _, kv := range over {
		put(kv)
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, set[k])
	}
	return out
}

// RenderEnvFile renders env as an env file (one NAME=value per line). A
// value holding a newline cannot be expressed and is refused, never split.
func RenderEnvFile(env []string) ([]byte, error) {
	var sb strings.Builder
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !envKeyRE.MatchString(k) {
			// A name the file format cannot carry is dropped, not guessed.
			continue
		}
		if strings.ContainsAny(v, "\n\r") {
			return nil, fmt.Errorf("sandboxapple.RenderEnvFile: %s holds a newline", k)
		}
		sb.WriteString(k + "=" + v + "\n")
	}
	return []byte(sb.String()), nil
}
