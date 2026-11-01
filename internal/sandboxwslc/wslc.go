package sandboxwslc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The verdict spellings (the shared probe vocabulary).
const (
	VerdictAvailable           = "available"
	VerdictUnsupportedPlatform = "unsupported_platform"
	VerdictDisabledByConfig    = "disabled_by_config"
	VerdictOSTooOld            = "os_too_old"
	VerdictBackendMissing      = "backend_missing"
	VerdictVersionUntested     = "backend_version_untested"
	VerdictImageMissing        = "image_missing"
)

// MinBuild is the lowest Windows 11 build the plan names for wslc.
const MinBuild = 26100

// Verdict is a probe outcome.
type Verdict struct {
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
}

// OK reports an available verdict.
func (v Verdict) OK() bool { return v.Code == VerdictAvailable }

// Facts are what the helper gathered.
type Facts struct {
	Windows, Active bool
	Build           int
	// WSL: wsl.exe answered --version.
	WSL bool
	// Path is wslc.exe ("" when not found); Version its --version.
	Path, Version string
	// Help is `wslc run --help`.
	Help string
	// Image is the configured digest-pinned image.
	Image string
}

// recordedVersions are the wslc versions whose help and JSON are recorded
// as fixtures (none yet: register WIN-5 captures the first).
var recordedVersions = map[string]bool{}

// RequiredFlags are the run flags the plan needs; a version whose help
// lacks one is refused naming it.
var RequiredFlags = []string{"--name", "--network", "--volume", "--interactive", "--tty"}

var flagRE = regexp.MustCompile(`--[a-z][a-z0-9-]*`)

// Flags reads the long flags a help text names.
func Flags(help string) map[string]bool {
	out := map[string]bool{}
	for _, f := range flagRE.FindAllString(help, -1) {
		out[f] = true
	}
	return out
}

var imageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$`)

type rule struct {
	code  string
	fails func(Facts) (bool, string)
}

var rules = []rule{
	{VerdictUnsupportedPlatform, func(f Facts) (bool, string) { return !f.Windows, "wslc runs on Windows 11 only" }},
	{VerdictDisabledByConfig, func(f Facts) (bool, string) { return !f.Active, "the wslc row is not selected or not listed" }},
	{VerdictOSTooOld, func(f Facts) (bool, string) {
		return f.Build < MinBuild, fmt.Sprintf("Windows build %d is below %d", f.Build, MinBuild)
	}},
	{VerdictBackendMissing, func(f Facts) (bool, string) { return !f.WSL, "WSL is not installed (wsl --version did not answer)" }},
	{VerdictBackendMissing, func(f Facts) (bool, string) { return f.Path == "", "wslc was not found" }},
	{VerdictImageMissing, func(f Facts) (bool, string) {
		return !imageRE.MatchString(f.Image), "[terminal.sandbox.wslc].image is not set to a digest-pinned image"
	}},
	{VerdictVersionUntested, func(f Facts) (bool, string) {
		missing := MissingFlags(Flags(f.Help))
		return len(missing) > 0, "this wslc's run help lacks " + strings.Join(missing, ", ")
	}},
	{VerdictVersionUntested, func(f Facts) (bool, string) {
		return !recordedVersions[strings.TrimSpace(f.Version)], "no recorded help and JSON for wslc " + strings.TrimSpace(f.Version) + " (register WIN-5 captures the first); the row is probe-only in this release"
	}},
}

// Probe walks the ladder.
func Probe(f Facts) Verdict {
	for _, r := range rules {
		if bad, why := r.fails(f); bad {
			return Verdict{Code: r.code, Reason: why}
		}
	}
	return Verdict{Code: VerdictAvailable}
}

// MissingFlags lists the required flags have does not name, sorted.
func MissingFlags(have map[string]bool) []string {
	var out []string
	for _, f := range RequiredFlags {
		if !have[f] {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// Mount is one bind into the container.
type Mount struct {
	Host, Container string
	ReadOnly        bool
}

// RunPlan is one run's container.
type RunPlan struct {
	Path, Name, Image string
	Mounts            []Mount
	Workdir           string
	Entrypoint        []string
}

// NamePrefix starts every container name.
const NamePrefix = "observer-sbx-"

var nameRE = regexp.MustCompile(`^observer-sbx-[A-Za-z0-9_-]{8,64}$`)

// RunArgv is the run's argv, built only from flags have names: --network
// none always, the PTY interactive (resize is claimed until WIN-5).
func RunArgv(p RunPlan, have map[string]bool) ([]string, error) {
	if m := MissingFlags(have); len(m) > 0 {
		return nil, fmt.Errorf("sandboxwslc: this wslc lacks %s", strings.Join(m, ", "))
	}
	if !nameRE.MatchString(p.Name) || !imageRE.MatchString(p.Image) || len(p.Entrypoint) == 0 {
		return nil, fmt.Errorf("sandboxwslc: the plan's name, image or entrypoint is not valid")
	}
	argv := []string{p.Path, "run", "--name", p.Name, "--network", "none", "--interactive", "--tty"}
	for _, m := range p.Mounts {
		if m.Host == "" || !strings.HasPrefix(m.Container, "/") || strings.ContainsAny(m.Host+m.Container, ",\x00") {
			return nil, fmt.Errorf("sandboxwslc: mount %q -> %q", m.Host, m.Container)
		}
		v := m.Host + ":" + m.Container
		if m.ReadOnly {
			v += ":ro"
		}
		argv = append(argv, "--volume", v)
	}
	argv = append(argv, p.Image)
	return append(argv, p.Entrypoint...), nil
}

// ExecRelayArgv is the exec that carries the relay over its stdio (the
// hosted exec_stdio precedent): no TTY, stdin kept open.
func ExecRelayArgv(path, name string, guest []string) ([]string, error) {
	if !nameRE.MatchString(name) || len(guest) == 0 {
		return nil, fmt.Errorf("sandboxwslc: exec plan")
	}
	return append([]string{path, "exec", "--interactive", name}, guest...), nil
}

// ListArgv lists the containers (JSON) for the teardown's before and after.
func ListArgv(path string) []string { return []string{path, "list", "--format", "json"} }

// RemoveArgv removes one container.
func RemoveArgv(path, name string) []string { return []string{path, "rm", "--force", name} }

// ParseList reads a list answer's container names (each object's Name or
// name). The shape is RECONSTRUCTED until WIN-5 records a real answer.
func ParseList(b []byte) ([]string, error) {
	var rows []map[string]any
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, fmt.Errorf("sandboxwslc: list: %w", err)
	}
	var out []string
	for _, r := range rows {
		for _, k := range []string{"Name", "name"} {
			if s, ok := r[k].(string); ok && s != "" {
				out = append(out, s)
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// TeardownPlan is what to remove and what must be gone after.
type TeardownPlan struct {
	Remove []string
}

// PlanTeardown removes the run's own container and every leftover of this
// install's prefix that no live run owns.
func PlanTeardown(before []string, run string, live func(name string) bool) TeardownPlan {
	var p TeardownPlan
	for _, n := range before {
		if !strings.HasPrefix(n, NamePrefix) {
			continue
		}
		if n == run || (live != nil && !live(n)) {
			p.Remove = append(p.Remove, n)
		}
	}
	return p
}

// Leftovers is what a list after the teardown still shows of what it
// removed.
func Leftovers(after []string, p TeardownPlan) []string {
	gone := map[string]bool{}
	for _, n := range p.Remove {
		gone[n] = true
	}
	var out []string
	for _, n := range after {
		if gone[n] {
			out = append(out, n)
		}
	}
	return out
}
