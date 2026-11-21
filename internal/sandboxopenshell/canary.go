package sandboxopenshell

import (
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// The runtime canary (probe row P8) runs Observer's own binary, bound
// read-only, as the entrypoint of OpenShell's supervisor image: the image
// every box of the gateway's version starts a container from, so it is on
// any host whose gateway can run a box, and a fresh install holds it
// (the O1B live run, 2026-10-31: a fresh v0.1.6 host held only the
// supervisor and sandbox images; the default workload image is pulled at
// the first box create). The supervisor image has no shell and no perl,
// which is why the binary is Observer's own; the query it makes is lane
// O0's (landlock_create_ruleset with the VERSION flag) under the runtime's
// DEFAULT seccomp profile, the profile OpenShell's own containers run
// under. The canary never pulls (--pull never).

// CanaryImageRepo is the repository of OpenShell's supervisor image.
const CanaryImageRepo = "ghcr.io/nvidia/openshell/supervisor"

// CanaryVerb is the observer helper verb the canary container runs: it
// prints CanaryMarker and the query's "<return> <errno>".
const CanaryVerb = "sandbox-openshell-canary"

// CanaryMarker prefixes the canary's answer line (lane O0's spelling).
const CanaryMarker = "O0:canary="

// canaryBinTarget is where the canary container sees Observer's binary.
const canaryBinTarget = "/observer-canary"

// CanaryImage is the default supervisor image of a gateway version (its
// tag is the bare MAJOR.MINOR.PATCH; probe row P5 has already refused a
// pre-release or a build). The canary runs in the gateway's own supervisor
// image (EffectiveRuntimeImages), which is this one only when the
// gateway's config names none.
func CanaryImage(v Version) string { return DefaultRuntimeImages(v).Supervisor }

// CanaryInput is what the canary's docker argv is built from.
type CanaryInput struct {
	// Image is the image to run (CanaryImage).
	Image string
	// ObserverBin is Observer's own binary on the host, bound read-only.
	ObserverBin string
	// UID and GID are the user the canary runs as (the host user, who can
	// execute their own binary; the box's workload runs as them too).
	UID, GID int
}

// ErrCanaryInput refuses a canary input the argv cannot carry safely.
var ErrCanaryInput = errors.New("sandboxopenshell: the runtime canary cannot be built")

// CanaryArgv is the canary's docker argv (without the program): a
// throwaway container with no network, a read-only root, every capability
// dropped (review finding V7: Landlock needs none, and a root daemon's
// --user 0:0 would otherwise hold Docker's default set), no new
// privileges and the runtime's default seccomp profile, which never pulls.
// The binary goes in through --mount, whose fields are comma-separated, so
// a path with a comma, a quote or a control character is refused.
func CanaryArgv(in CanaryInput) ([]string, error) {
	bin := in.ObserverBin
	switch {
	case bin == "":
		return nil, fmt.Errorf("%w: %s", ErrCanaryInput, "Observer's own binary path is not known")
	case !path.IsAbs(bin) || path.Clean(bin) != bin:
		return nil, fmt.Errorf("%w: %s", ErrCanaryInput, "Observer's binary path "+strconv.Quote(bin)+" is not absolute and clean")
	case strings.ContainsAny(bin, ",\"'=") || strings.IndexFunc(bin, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0:
		return nil, fmt.Errorf("%w: %s", ErrCanaryInput, "Observer's binary path "+strconv.Quote(bin)+" holds a character a docker --mount value cannot carry")
	}
	if in.Image == "" || strings.HasPrefix(in.Image, "-") || strings.ContainsAny(in.Image, " \t\n") {
		return nil, fmt.Errorf("%w: %s", ErrCanaryInput, "the canary image "+strconv.Quote(in.Image)+" is not an image reference")
	}
	if in.UID < 0 || in.GID < 0 {
		return nil, fmt.Errorf("%w: %s", ErrCanaryInput, "the canary user is not known")
	}
	return []string{
		"run", "--rm", "--network", "none", "--pull", "never", "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--user", strconv.Itoa(in.UID) + ":" + strconv.Itoa(in.GID),
		"--mount", "type=bind,source=" + bin + ",target=" + canaryBinTarget + ",readonly",
		"--entrypoint", canaryBinTarget,
		in.Image, CanaryVerb,
	}, nil
}

// CanaryRun is what the docker call answered.
type CanaryRun struct {
	// Started: the docker CLI itself started (false: it is missing, or the
	// runner refused or could not start it).
	Started bool
	// TimedOut: the call was stopped before it finished (the probe's time
	// limit, or the probe being canceled), so whether the container ever
	// ran is not known.
	TimedOut bool
	// ExitCode is docker's exit code (-1 when it did not exit on its own:
	// a timeout, or a signal).
	ExitCode int
	// Stdout and Stderr are its output.
	Stdout, Stderr string
}

// canaryRunRow is one row of the canary outcome table.
type canaryRunRow struct {
	id    string
	match func(r CanaryRun) bool
	out   func(r CanaryRun) (Canary, string)
}

// canaryNoImage is the docker CLI's text for an image the host does not
// hold under --pull never (Docker 29.9.2, live O1B run: exit 125 with
// "Unable to find image ... locally" and "No such image").
var canaryNoImage = []string{"no such image", "unable to find image"}

// canaryRunRows is the canary outcome table, walked top-down; the first
// matching row wins. Docker's own failures (exit 125: the daemon refused
// the run; 126 and 127: the entrypoint could not be executed or found) are
// "not started", never a Landlock answer; a call stopped before it finished
// is its own outcome (review finding V4), never "ran but answered neither".
var canaryRunRows = []canaryRunRow{
	{"C1 docker did not start", func(r CanaryRun) bool { return !r.Started }, func(CanaryRun) (Canary, string) {
		return CanaryNotStarted, "the docker CLI could not be started"
	}},
	{"C2 the call did not finish", func(r CanaryRun) bool { return r.TimedOut }, func(r CanaryRun) (Canary, string) {
		return CanaryTimedOut, canaryDetail(r.Stderr)
	}},
	{"C3 the image is not on this host", func(r CanaryRun) bool {
		if r.ExitCode != 125 {
			return false
		}
		low := strings.ToLower(r.Stderr)
		for _, s := range canaryNoImage {
			if strings.Contains(low, s) {
				return true
			}
		}
		return false
	}, func(CanaryRun) (Canary, string) { return CanaryImageMissing, "" }},
	{"C4 docker could not run the container", func(r CanaryRun) bool {
		return r.ExitCode == 125 || r.ExitCode == 126 || r.ExitCode == 127
	}, func(r CanaryRun) (Canary, string) { return CanaryNotStarted, canaryDetail(r.Stderr) }},
	{"C5 the canary answered", func(r CanaryRun) bool { return CanaryAnswer(r.Stdout) != "" }, func(r CanaryRun) (Canary, string) {
		c, _ := ParseCanary(CanaryAnswer(r.Stdout))
		return c, ""
	}},
	{"C6 no answer", func(CanaryRun) bool { return true }, func(r CanaryRun) (Canary, string) {
		return CanaryError, canaryDetail(r.Stderr)
	}},
}

// ClassifyCanary reads a canary run into its outcome and, for a failure, a
// short detail (the first line of docker's error output).
func ClassifyCanary(r CanaryRun) (Canary, string) {
	for _, row := range canaryRunRows {
		if row.match(r) {
			return row.out(r)
		}
	}
	return CanaryError, ""
}

// CanaryAnswer returns the "<return> <errno>" of the canary's marker line
// ("" when there is none).
func CanaryAnswer(stdout string) string {
	for _, l := range strings.Split(stdout, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), CanaryMarker); ok {
			return v
		}
	}
	return ""
}

// maxDetail caps a detail shown in a probe reason.
const maxDetail = 200

// canaryDetail is s's first non-empty line, trimmed and capped.
func canaryDetail(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			if len(l) > maxDetail {
				l = l[:maxDetail] + "..."
			}
			return l
		}
	}
	return ""
}

// CanaryImageMissingReason is probe row P8's reason when the canary's image
// is not on this machine (review finding V2, tracker F-023). The canary
// runs in the gateway's own supervisor image (its config's
// supervisor_image, else CanaryImage of its version; lane FU7) and never
// pulls, so the remedy names that reference and the two ways to make it
// available: pull it, or, on a host that takes OpenShell's images from a
// mirror or an offline copy, tag the mirror's copy of the same version as
// that reference. image is "" when the version was not read.
func CanaryImageMissingReason(image string) string {
	ref := image
	if !validImageRef(ref) {
		ref = CanaryImageRepo + ":<gateway version>"
	}
	return "the image Observer's runtime canary runs in (" + quoteOr(image, "OpenShell's supervisor image") + ", the gateway's own supervisor image) is not on this machine, so the Landlock query did not run; the probe never pulls and looks for exactly " + ref +
		": run `docker pull " + ref + "`, or, if this machine takes OpenShell's images from a mirror or an offline copy, pull the mirror's supervisor image of the same version and `docker tag` it as " + ref +
		" (a running gateway pulls the image it is configured with at its start, so restarting the gateway also brings it)"
}
