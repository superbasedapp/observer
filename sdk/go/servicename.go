package superbased

import (
	"regexp"
	"runtime/debug"
	"strings"
)

// The service name ladder (SDK quickstart plan section 3.2, contract
// sdk-api-surface.md section 15), first set wins:
//
//	| # | source                                                        | ServiceNameSource |
//	| 1 | Options.ServiceName                                           | argument          |
//	| 2 | SUPERBASED_SERVICE_NAME, OTEL_SERVICE_NAME, service.name in   | env               |
//	|   | OTEL_RESOURCE_ATTRIBUTES                                      |                   |
//	| 3 | the last element of the main module's path (build info), a    | manifest          |
//	|   | /vN major-version suffix dropped                              |                   |
//	| 5 | custom-app                                                    | default           |
//
// Rung 4 (the entry script's folder) is Python's and TypeScript's: a Go
// binary has no entry script. Rungs 1 and 2 are used as given (trimmed; a
// blank one is unset); only rung 3 is normalised.

// Where a service name came from (Settings.ServiceNameSource).
const (
	serviceSourceArgument = "argument"
	serviceSourceEnv      = "env"
	serviceSourceManifest = "manifest"
	serviceSourceDefault  = "default"
)

// serviceNameMax is the longest normalised project name.
const serviceNameMax = 64

var (
	serviceNameBadRun = regexp.MustCompile(`[^a-z0-9._-]+`)
	serviceNameDashes = regexp.MustCompile(`-{2,}`)
	majorVersionElem  = regexp.MustCompile(`^v[0-9]+$`)
)

// mainModulePath is the main module's path from the build info ("" when
// there is none). A variable so tests can stand in for a binary.
var mainModulePath = func() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi == nil {
		return ""
	}
	return bi.Main.Path
}

// normaliseServiceName is a project-derived name as a service name:
// lowercase, every character outside [a-z0-9._-] becomes -, runs of - become
// one, no leading or trailing -, . or _, at most 64 characters (cut, then
// trimmed again); "" when nothing is left.
func normaliseServiceName(raw string) string {
	s := serviceNameBadRun.ReplaceAllString(strings.ToLower(raw), "-")
	s = serviceNameDashes.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-._")
	if len(s) > serviceNameMax {
		s = s[:serviceNameMax]
	}
	return strings.TrimRight(s, "-._")
}

// moduleServiceName is rung 3's name from a main module path: its last
// element, walking past a /vN major-version suffix; "" for no module (a
// file run with `go run` outside a module is command-line-arguments).
func moduleServiceName(modPath string) string {
	modPath = strings.Trim(strings.TrimSpace(modPath), "/")
	if modPath == "" || modPath == "command-line-arguments" {
		return ""
	}
	elems := strings.Split(modPath, "/")
	last := elems[len(elems)-1]
	if majorVersionElem.MatchString(last) && len(elems) > 1 {
		last = elems[len(elems)-2]
	}
	return last
}

// serviceNameLadder is the ladder, pure: the name and the rung it came from.
// project is rung 3's raw name ("" when there is none).
func serviceNameLadder(explicit string, env envFunc, project string) (string, string) {
	if v := strings.TrimSpace(explicit); v != "" {
		return v, serviceSourceArgument
	}
	if v := envStr(env, "SUPERBASED_SERVICE_NAME", "OTEL_SERVICE_NAME"); v != "" {
		return v, serviceSourceEnv
	}
	if v := strings.TrimSpace(parseKVList(env.get("OTEL_RESOURCE_ATTRIBUTES"))["service.name"]); v != "" {
		return v, serviceSourceEnv
	}
	if v := normaliseServiceName(project); v != "" {
		return v, serviceSourceManifest
	}
	return DefaultServiceName, serviceSourceDefault
}
