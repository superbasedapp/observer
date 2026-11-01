package seciac

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secengine"
)

// EngineID names one IaC engine. It is also the driver id and the prefix
// of the engine's entries in the shared security.engine manifest.
type EngineID string

// The two engines (security pillar plan section 5.6: Trivy first,
// misconfiguration only; then KICS).
const (
	Trivy EngineID = "trivy"
	KICS  EngineID = "kics"
)

// SignatureMethod is how an engine's release is signed upstream.
type SignatureMethod string

// The SignatureMethod values.
const (
	// SigCosignKeylessBundle: every release asset has a sigstore bundle
	// (<asset>.sigstore.json, since Trivy v0.68.1) whose certificate names
	// a pinned identity and issuer. The guided install pre-checks it
	// offline (PrecheckBundle); a manifest entry counts only when it was
	// verified keyless online under that identity where it was built.
	SigCosignKeylessBundle SignatureMethod = "cosign_keyless_bundle"
	// SigNone: the vendor publishes no signature. A pin is digest-only
	// and labelled so, everywhere it is shown.
	SigNone SignatureMethod = "none"
)

// Engine is one engine's data row. Dispatch is on these fields, never on
// the engine's name (CLAUDE.md module rule 3).
type Engine struct {
	ID EngineID
	// Title is the human name.
	Title string
	// ComponentID is the catalog row ("security.scan." + ID).
	ComponentID string
	// TestedVersion is the version whose --help and SARIF shape the driver
	// was built against; MinVersion equals it (never "latest").
	TestedVersion string
	MinVersion    string
	// Licence is the licence matrix verdict (plan 8.7).
	Licence string
	// Signature is how its releases are signed.
	Signature SignatureMethod
	// Identity and Issuer are the keyless signing identity pinned for a
	// version (Identity(version) on the row) and the OIDC issuer.
	identityPrefix string
	Issuer         string
	// ReleaseBase is the vendor's release download base; "" when the
	// vendor publishes no release binaries (the guided install is then
	// not offered).
	ReleaseBase string
	// Binary is the executable's base name (".exe" added on Windows).
	Binary string
	// HelpArgs are the arguments whose output lists the flags the driver
	// passes (the probe refuses a version that lacks one).
	HelpArgs []string
	// RequiredFlags are the flags every run passes that the probe checks
	// in HelpArgs' output, each turning off a network path or pinning the
	// output.
	RequiredFlags []string
	// NeverFlags are refused on a run.
	NeverFlags []string
	// RepoConfigs are the repository-local scanner config files a run
	// ignores unless the developer or the org allows them (plan 4.4
	// ConfigInputs): the repository is untrusted input.
	RepoConfigs []string
	// RequireIsolation: the engine has a network path no flag is proven to
	// turn off, so a run is refused unless the isolation one-shot (no
	// network) wraps it. IsolationWhy names that path for the refusal.
	RequireIsolation bool
	IsolationWhy     string
	// QueriesTree reports the engine reads a tree of query files beside
	// its binary (KICS's assets/queries): the tree is digest-recorded after
	// the first verified run and re-checked before each later run (X9).
	QueriesTree bool
	// ApproxBytes is the release asset's size, about, for the consent.
	ApproxBytes int64
}

// Identity is the pinned signing identity of version ("" when the engine
// publishes no signature).
func (e Engine) Identity(version string) string {
	if e.identityPrefix == "" {
		return ""
	}
	return e.identityPrefix + strings.TrimPrefix(version, "v")
}

// GuidedInstall reports whether the vendor publishes release binaries the
// guided install can fetch.
func (e Engine) GuidedInstall() bool { return e.ReleaseBase != "" }

// engines is the engine table.
var engines = []Engine{
	{
		ID: Trivy, Title: "Trivy", ComponentID: "security.scan.trivy",
		TestedVersion: "0.75.0", MinVersion: "0.75.0",
		Licence:   "Apache-2.0, run only as a separately installed process; never bundled or linked",
		Signature: SigCosignKeylessBundle,
		// Trivy's own signature-verification page at v0.75.0: since v0.68.1
		// every release asset has a sigstore bundle signed by the
		// reusable-release workflow at the release tag.
		identityPrefix: "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v",
		Issuer:         "https://token.actions.githubusercontent.com",
		ReleaseBase:    "https://github.com/aquasecurity/trivy/releases/download/v",
		Binary:         "trivy",
		HelpArgs:       []string{"config", "--help"},
		RequiredFlags:  TrivyRequiredFlags,
		NeverFlags:     TrivyNeverFlags,
		RepoConfigs:    []string{".trivyignore", ".trivyignore.yaml", "trivy.yaml"},
		ApproxBytes:    50_000_000,
		// Audit finding F3, orchestrator ruling P-143: `trivy config` at
		// v0.75.0 has no offline flag, and its Terraform scanner fetches the
		// remote modules a repository names (--tf-exclude-downloaded-modules
		// only filters the results), so a repository could make the scan
		// reach arbitrary URLs. Like KICS it runs only isolated.
		RequireIsolation: true,
		IsolationWhy:     "Trivy's Terraform scanner fetches the remote modules a repository names and no flag turns that off",
	},
	{
		ID: KICS, Title: "KICS", ComponentID: "security.scan.kics",
		TestedVersion: "2.2.0", MinVersion: "2.2.0",
		Licence: "Apache-2.0, run only as a separately installed process; never bundled or linked",
		// KICS v2.2.0 publishes no release binaries and no signature (its
		// getting-started page offers the Docker image or a source build):
		// a KICS on this machine is the developer's own install, its digest
		// recorded at first use and labelled.
		Signature:     SigNone,
		Binary:        "kics",
		HelpArgs:      []string{"scan", "--help"},
		RequiredFlags: KICSRequiredFlags,
		NeverFlags:    KICSNeverFlags,
		RepoConfigs:   []string{"kics.config", "kics.config.json", "kics.config.yaml", "kics.config.yml", "kics.config.toml", "kics.config.hcl"},
		QueriesTree:   true,
		// pkg/scan/client.go asks api.github.com for the latest release on
		// every start and no flag turns it off at v2.2.0.
		RequireIsolation: true,
		IsolationWhy:     "KICS asks api.github.com for its latest release on every start and no flag turns that off",
	},
}

// Engines returns a copy of the engine table.
func Engines() []Engine { return append([]Engine(nil), engines...) }

// Lookup returns the engine row for id.
func Lookup(id EngineID) (Engine, bool) {
	for _, e := range engines {
		if e.ID == id {
			return e, true
		}
	}
	return Engine{}, false
}

// Tested reports whether v is the engine's tested version.
func (e Engine) Tested(v string) bool { return secengine.CompareVersions(v, e.TestedVersion) == 0 }
