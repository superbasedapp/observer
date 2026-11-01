package seciac

import (
	"regexp"
	"strings"
)

// The Trivy flag table (lane GATES-SEC decision 1), read from
// `trivy config --help` at v0.75.0 (testdata/trivy-0.75.0-config-help.txt).
// Misconfiguration only: the `config` subcommand, never `fs`, `image` or a
// vulnerability scanner, so no vulnerability database is ever fetched.
var (
	// TrivyRequiredFlags turn off every network path a flag can: no check
	// bundle update (the embedded checks only), no version or announcement
	// check, no telemetry, an in-memory cache (never a remote one), no WASM
	// modules from the user's home, no trivy.yaml and no .trivyignore from
	// the project unless allowed; plus the output shape. They are not
	// proven to turn off every path (the Terraform scanner fetches remote
	// modules), so Trivy also runs only isolated (Engine.RequireIsolation,
	// audit finding F3).
	TrivyRequiredFlags = []string{
		"--skip-check-update", "--skip-version-check", "--disable-telemetry",
		"--cache-backend", "--cache-dir", "--module-dir",
		"--config", "--ignorefile", "--misconfig-scanners", "--tf-exclude-downloaded-modules",
		"--format", "--output", "--exit-code", "--quiet", "--timeout",
	}
	// TrivyNeverFlags are refused: a remote cache or server, a checks
	// bundle from a registry, custom Rego from the repository, credentials.
	TrivyNeverFlags = []string{
		"--checks-bundle-repository", "--server", "--token", "--password", "--username", "--registry-token",
		"--config-check", "--config-data", "--enable-modules", "--insecure",
	}
	// TrivyMisconfigScanners are the scanners a run enables (plan 5.6:
	// Dockerfiles, Kubernetes, Terraform, CloudFormation, Helm).
	TrivyMisconfigScanners = []string{"cloudformation", "dockerfile", "helm", "kubernetes", "terraform"}
)

// The KICS flag table, read from `kics scan --help` at v2.2.0
// (testdata/kics-2.2.0-scan-help.txt, captured from a source build of the
// tag through the Go module proxy).
//
// KICS v2.2.0 has NO flag that turns off its one network call: the scan
// client asks api.github.com for the latest release on every start
// (pkg/scan/client.go CheckVersion, unconditional unless the binary is a
// development build), and the --disable-full-descriptions flag of KICS 1.x
// is gone. So a KICS run is refused unless it runs inside the isolation
// component's no-network one-shot (Engine.RequireIsolation; lane GATES-SEC
// decision 1): the flags below turn off what can be turned off, the
// isolation turns off the rest.
var (
	// KICSRequiredFlags pin the queries Observer recorded, keep the scan to
	// the given path (no remote source resolution, no secrets queries:
	// secrets belong to security.secrets), and fix the output shape.
	KICSRequiredFlags = []string{
		"--path", "--queries-path", "--libraries-path", "--output-path", "--output-name",
		"--report-formats", "--ignore-on-exit", "--no-progress", "--no-color", "--silent",
		"--config", "--disable-secrets", "--strict-source-resolution", "--type", "--timeout",
	}
	// KICSNeverFlags are refused: cloud and cluster sources, extra inputs.
	KICSNeverFlags = []string{"--cloud-provider", "--input-data", "--secrets-regexes-path", "--terraform-vars-path", "--payload-path", "--log-path"}
	// KICSTypes are the platforms a run scans.
	KICSTypes = []string{"CloudFormation", "DockerCompose", "Dockerfile", "Kubernetes", "Terraform"}
)

// MissingFlags returns the required flags of e that help does not list (a
// version lacking one is refused by the probe, lane GATES-SEC decision 1).
func MissingFlags(e Engine, help []byte) []string {
	text := string(help)
	var out []string
	for _, f := range e.RequiredFlags {
		re := regexp.MustCompile(`(^|[\s,])` + regexp.QuoteMeta(f) + `([\s=]|$)`)
		if !re.MatchString(text) {
			out = append(out, f)
		}
	}
	return out
}

// versionPatterns read the version line of each engine's --version.
var versionPatterns = map[EngineID]*regexp.Regexp{
	Trivy: regexp.MustCompile(`(?m)^Version:\s*v?(\d+\.\d+\.\d+)\s*$`),
	KICS:  regexp.MustCompile(`(?m)\bv?(\d+\.\d+\.\d+)\b`),
}

// VersionPattern is the version regexp of engine id.
func VersionPattern(id EngineID) *regexp.Regexp { return versionPatterns[id] }

// VersionArgs are the arguments that print an engine's version.
func VersionArgs(id EngineID) []string {
	if id == KICS {
		return []string{"version"}
	}
	return []string{"--version"}
}

// RunPaths are one run's absolute directories, in the GOOS spelling.
type RunPaths struct {
	// Target is the checkout the run reads.
	Target string
	// Out is the run's output directory; the SARIF lands at SARIFPath.
	Out string
	// Cache is the engine-owned cache and HOME root.
	Cache string
	// Queries is KICS's recorded queries tree; Libraries its Rego library
	// directory beside it.
	Queries   string
	Libraries string
	// EmptyConfig is an empty file in Out passed where an engine would
	// otherwise read a repository config (KICS reads ./kics.config).
	EmptyConfig string
	Sep         string
}

func (p RunPaths) join(elem ...string) string {
	sep := p.Sep
	if sep == "" {
		sep = "/"
	}
	for i := range elem {
		if i > 0 {
			elem[i] = strings.Trim(elem[i], `/\`)
		} else {
			elem[i] = strings.TrimRight(elem[i], `/\`)
		}
	}
	return strings.Join(elem, sep)
}

// SARIFPath is where a run writes its SARIF.
func SARIFPath(id EngineID, p RunPaths) string {
	if id == KICS {
		return p.join(p.Out, "kics.sarif")
	}
	return p.join(p.Out, "trivy.sarif")
}

// Args returns the fixed argument list of one run. allowRepoConfig keeps
// the engine's own reading of the project's scanner configs (it is never
// a default; the org or the developer must allow it).
func Args(id EngineID, p RunPaths, allowRepoConfig bool) []string {
	switch id {
	case Trivy:
		args := []string{
			"config", "--quiet", "--format", "sarif", "--output", SARIFPath(id, p), "--exit-code", "0",
			"--skip-check-update", "--skip-version-check", "--disable-telemetry",
			"--cache-backend", "memory", "--cache-dir", p.join(p.Cache, "trivy-cache"), "--module-dir", p.join(p.Cache, "trivy-modules"),
			"--misconfig-scanners", strings.Join(TrivyMisconfigScanners, ","), "--tf-exclude-downloaded-modules",
			"--timeout", "9m",
		}
		if !allowRepoConfig {
			args = append(args, "--config", "", "--ignorefile", "")
		}
		return append(args, p.Target)
	case KICS:
		args := []string{
			"scan", "--path", p.Target, "--queries-path", p.Queries, "--libraries-path", p.Libraries,
			"--output-path", p.Out, "--output-name", "kics", "--report-formats", "sarif",
			"--ignore-on-exit", "results", "--no-progress", "--no-color", "--silent",
			"--disable-secrets", "--strict-source-resolution", "--type", strings.Join(KICSTypes, ","), "--timeout", "60",
		}
		if !allowRepoConfig {
			args = append(args, "--config", p.EmptyConfig)
		}
		return args
	}
	return nil
}
