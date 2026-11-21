package trivyimage

import (
	"regexp"
	"strings"
)

// args.go is the image driver's own flag table (lane OS-2 T, plan 6.7), in
// internal/seciac's shape, read from `trivy image --help` and `trivy rootfs
// --help` at v0.75.0 (testdata/trivy-0.75.0-{image,rootfs}-help.txt).
//
// Trivy never downloads anything in a run: its vulnerability database is
// Observer's download (internal/secscan/trivydb), reached through the run's
// --cache-dir, and every database, VEX, Java and version check is skipped
// by a flag. The input is always a local file or directory the developer
// or CI produced (an image tar for `image --input`, a root filesystem for
// `rootfs`): never a registry reference, a container daemon or a Trivy
// server. The flags are not proven to turn off every network path, so the
// run is also isolated (Engine.RequireIsolation, as the config driver).

// Mode is how Trivy reads the input.
type Mode string

// The two modes.
const (
	// ModeImage: `trivy image --input <tar>`, a `docker save` or OCI-layout
	// tar.
	ModeImage Mode = "image"
	// ModeRootfs: `trivy rootfs <dir>`, a root filesystem directory (and
	// the canary).
	ModeRootfs Mode = "rootfs"
)

// commonRequiredFlags are passed on every run and must be listed by both
// subcommands' --help: the vulnerability scanner over OS packages only, the
// whole package list (for the kernel note and the package count), every
// download and check skipped, telemetry off, Observer's cache directory, an
// in-memory analysis cache (never a remote one), an empty module directory,
// no repository config or ignore file, and the output shape.
var commonRequiredFlags = []string{
	"--scanners", "--pkg-types", "--list-all-pkgs",
	"--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update", "--offline-scan",
	"--skip-version-check", "--disable-telemetry",
	"--cache-dir", "--cache-backend", "--module-dir", "--config", "--ignorefile",
	"--format", "--output", "--exit-code", "--quiet", "--no-progress", "--timeout",
}

// NeverFlags are refused on a run: a server or a remote cache, credentials,
// a database or checks repository, extra request headers, a container
// daemon, WASM modules, custom checks, online signature or SBOM lookups.
var NeverFlags = []string{
	"--server", "--token", "--token-header", "--username", "--password", "--password-stdin", "--registry-token",
	"--db-repository", "--java-db-repository", "--checks-bundle-repository", "--custom-headers",
	"--docker-host", "--podman-host", "--image-src", "--insecure", "--enable-modules",
	"--config-check", "--config-data", "--sbom-sources", "--rekor-url", "--download-db-only", "--download-java-db-only",
	"--redis-ca", "--redis-cert", "--redis-key", "--redis-tls",
}

// RequiredFlags returns the flags a run of mode passes that its --help must
// list.
func RequiredFlags(m Mode) []string {
	out := append([]string(nil), commonRequiredFlags...)
	if m == ModeImage {
		out = append(out, "--input")
	}
	return out
}

// HelpArgs are the arguments whose output lists mode's flags.
func HelpArgs(m Mode) []string { return []string{string(m), "--help"} }

// VersionArgs print Trivy's version.
func VersionArgs() []string { return []string{"--version"} }

// VersionPattern reads Trivy's version line ("Version: 0.75.0").
var VersionPattern = regexp.MustCompile(`(?m)^Version:\s*v?(\d+\.\d+\.\d+)\s*$`)

// TestedVersion is the version the flag table and the report mapping were
// built against (seciac's pin).
const TestedVersion = "0.75.0"

// MissingFlags returns the flags of mode that help does not list (a version
// lacking one is refused: engine_flags_missing).
func MissingFlags(m Mode, help []byte) []string {
	text := string(help)
	var out []string
	for _, f := range RequiredFlags(m) {
		re := regexp.MustCompile(`(^|[\s,])` + regexp.QuoteMeta(f) + `([\s=]|$)`)
		if !re.MatchString(text) {
			out = append(out, f)
		}
	}
	return out
}

// Paths are one run's absolute paths, in the GOOS spelling.
type Paths struct {
	// Target is the image tar (ModeImage) or the root filesystem (ModeRootfs).
	Target string
	// Cache is the run's Trivy cache directory: db/ inside it reaches the
	// installed database.
	Cache string
	// Report is the JSON report Trivy writes.
	Report string
	// Sep is the path separator ("/" when empty).
	Sep string
}

func (p Paths) join(a, b string) string {
	sep := p.Sep
	if sep == "" {
		sep = "/"
	}
	return strings.TrimRight(a, `/\`) + sep + strings.Trim(b, `/\`)
}

// ModuleDir is the run's (empty) WASM module directory.
func (p Paths) ModuleDir() string { return p.join(p.Cache, "modules") }

// Args returns the fixed argument list of one run. The target is always
// last.
func Args(m Mode, p Paths) []string {
	args := []string{
		string(m),
		"--scanners", "vuln", "--pkg-types", "os", "--list-all-pkgs",
		"--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update", "--offline-scan",
		"--skip-version-check", "--disable-telemetry",
		"--cache-dir", p.Cache, "--cache-backend", "memory", "--module-dir", p.ModuleDir(),
		"--config", "", "--ignorefile", "",
		"--format", "json", "--output", p.Report, "--exit-code", "0", "--quiet", "--no-progress", "--timeout", "9m",
	}
	if m == ModeImage {
		return append(args, "--input", p.Target)
	}
	return append(args, p.Target)
}
