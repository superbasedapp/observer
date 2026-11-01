package sandboxoci

import (
	"fmt"
	"strconv"
	"strings"
)

// API version negotiation (sandbox plan v2 section 4.2 "Version pins are
// data", section 4.6): the client speaks the highest Engine API version it
// was tested against that the server also offers, and refuses a server below
// the path floor. The Docker Engine floor is 1.44 (the first API with every
// endpoint the driver uses); Podman's Docker-compatible API reports its own
// number (1.41 on Podman 4 and 5), so Podman is pinned by its engine version
// instead (engineFloors).
const (
	// MaxAPI is the highest Engine API version a recorded test covers.
	MaxAPI = "1.56"
	// MinPathAPI is the lowest API version the driver puts in a path; below
	// it no engine is driven.
	MinPathAPI = "1.41"
	// DockerMinAPI is the Docker Engine API floor (section 4.6).
	DockerMinAPI = "1.44"
)

// engineFloor is one engine's required minimum and tested range, on the
// version the probe reads from the authenticated socket: the API version
// for Docker, the engine version for Podman.
type engineFloor struct {
	engine                             Engine
	field                              string // "api" or "engine"
	requiredMin, testedLow, testedHigh string
}

// engineFloors is the version table, one row per engine. Docker 28.1.1
// (API 1.49) and 29.9.1 (API 1.52) and Podman 4.9.3 and 5.6.2 are the
// versions spike JSP-4 drove.
var engineFloors = []engineFloor{
	{engine: EngineDocker, field: "api", requiredMin: DockerMinAPI, testedLow: DockerMinAPI, testedHigh: MaxAPI},
	{engine: EnginePodman, field: "engine", requiredMin: "4.9.3", testedLow: "4.9.3", testedHigh: "5.6.2"},
}

// VersionStatus is what an engine's version means against its floor.
type VersionStatus string

// The VersionStatus values.
const (
	VersionTested  VersionStatus = "tested"
	VersionBeta    VersionStatus = "beta"
	VersionRefused VersionStatus = "refused"
)

// JudgeVersion classifies the engine's authenticated version. Below the
// required minimum (or unreadable) it is refused; outside the tested range
// in either direction it is beta, never refused (section 4.2).
func JudgeVersion(id Identity) (VersionStatus, string) {
	for _, f := range engineFloors {
		if f.engine != id.Engine {
			continue
		}
		have := id.APIVersion
		if f.field == "engine" {
			have = id.Version
		}
		v, err := ParseVersion(have)
		if err != nil {
			return VersionRefused, fmt.Sprintf("the %s %s version %q could not be read", id.Engine, f.field, have)
		}
		if CompareVersions(v, mustParse(f.requiredMin)) < 0 {
			return VersionRefused, fmt.Sprintf("%s %s version %s is below the required minimum %s", id.Engine, f.field, have, f.requiredMin)
		}
		if CompareVersions(v, mustParse(f.testedLow)) < 0 || CompareVersions(v, mustParse(f.testedHigh)) > 0 {
			return VersionBeta, fmt.Sprintf("%s %s version %s is outside the tested range %s to %s", id.Engine, f.field, have, f.testedLow, f.testedHigh)
		}
		return VersionTested, ""
	}
	return VersionRefused, "no version floor for engine " + quote(string(id.Engine))
}

// NegotiateAPI returns the API version to put in request paths: the lower
// of the server's version and MaxAPI, never below MinPathAPI.
func NegotiateAPI(server string) (string, error) {
	v, err := ParseVersion(server)
	if err != nil {
		return "", fmt.Errorf("sandboxoci: the engine reported API version %q", server)
	}
	if CompareVersions(v, mustParse(MinPathAPI)) < 0 {
		return "", fmt.Errorf("sandboxoci: the engine's API version %s is below %s", server, MinPathAPI)
	}
	if CompareVersions(v, mustParse(MaxAPI)) > 0 {
		return MaxAPI, nil
	}
	return fmt.Sprintf("%d.%d", v[0], v[1]), nil
}

// ParseVersion reads a dotted numeric version ("1.44", "v29.9.1",
// "4.9.3-dev"): an optional leading "v", up to three numeric parts, a
// trailing pre-release or build suffix ignored. Anything else is an error.
func ParseVersion(s string) ([3]int, error) {
	var out [3]int
	v := strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(v, "-+~"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if v == "" || len(parts) > 3 {
		return out, fmt.Errorf("version %q", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, fmt.Errorf("version %q", s)
		}
		out[i] = n
	}
	return out, nil
}

// CompareVersions returns -1, 0 or 1.
func CompareVersions(a, b [3]int) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

func mustParse(s string) [3]int {
	v, err := ParseVersion(s)
	if err != nil {
		return [3]int{1 << 30}
	}
	return v
}

func quote(s string) string { return strconv.Quote(s) }
