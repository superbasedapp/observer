package sandboxoci

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
)

// installscripts.go is the reviewed allowance for a vendor's own package
// install script in the first-start install (lane LEFT-SBX, follow-up of
// P-135, operator ruling P-136). The install still runs npm with
// --ignore-scripts; when the tool's install source needs its own script, the
// setup container's guest then runs exactly the package's lifecycle scripts
// (preinstall, install, postinstall, in npm's order) ONLY when each script
// file's sha256 matches a pin for that tool and package version, under the
// same host allow-list, server-name and port rules as the download. A
// mismatch refuses the install naming the script and both hashes; nothing
// is run.
//
// Which pins count is the effective script policy (ScriptPolicy): the mode
// (none never runs a script; pinned, the default, runs a tool's scripts
// only when they match a pin), the tool allow list (empty means every tool
// of the install-source catalog) and the pins themselves, each carrying
// where it came from (built-in, user, org). Everything here is pure: the cmd
// layer composes the policy from the config, the governance pins and the
// managed sandbox body, and the guest reads the files.

// The script policy modes.
const (
	// ScriptsNone never runs a package install script.
	ScriptsNone = "none"
	// ScriptsPinned runs a tool's scripts only when they match a pin.
	ScriptsPinned = "pinned"
)

// ScriptModes is the closed mode vocabulary, most restrictive first.
func ScriptModes() []string { return []string{ScriptsNone, ScriptsPinned} }

// The script pin sources.
const (
	// PinSourceBuiltin: a pin shipped in the install-source table, grounded
	// from the vendor's published package.
	PinSourceBuiltin = "builtin"
	// PinSourceUser: a pin the developer added (config or dashboard).
	PinSourceUser = "user"
	// PinSourceOrg: a pin the organization published in the signed managed
	// sandbox body (honoured only on a managed node holding enforce.sandbox).
	PinSourceOrg = "org"
)

// VerdictInstallScriptsUnpinned: the tool's install source needs its own
// script and no pin covers this package version.
const VerdictInstallScriptsUnpinned = "install_scripts_unpinned"

// VerdictInstallScriptMismatch: the fetched package's script is not one a
// pin names (refused in the setup container, nothing run).
const VerdictInstallScriptMismatch = "install_script_mismatch"

// VerdictInstallPackageUnpinned: an artifact the install fetched (the
// package itself or a package its script would place) is not the one a pin
// names by its registry integrity value (refused in the setup container
// before any script runs; ruling P-142).
const VerdictInstallPackageUnpinned = "install_package_unpinned"

// ScriptPin is one reviewed script: tool, package version and the sha256 of
// the script file its lifecycle command runs.
type ScriptPin struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Source  string `json:"source"`
	// Note says how the pin was grounded or who added it (shown with it).
	Note string `json:"note,omitempty"`
	// Packages are the artifacts an install under this pin fetches, each
	// pinned by the registry's integrity value (ruling P-142): the package
	// itself and every package its script may place. A built-in, user or org
	// pin may carry them (R-014); a tool whose script installs more packages
	// runs its scripts only under a pin that has them, and a pin for such a
	// tool without them does not count.
	Packages []PackagePin `json:"packages,omitempty"`
}

// PackagePin is one fetched artifact pinned by the registry's integrity
// value (sha512 of the published tarball), not by its version alone.
type PackagePin struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Integrity string `json:"integrity"`
}

// PackageIntegrityFlag is the setup container's guest flag carrying one
// PackagePin as name@version=integrity.
const PackageIntegrityFlag = "--package-integrity"

// integrityRE is an npm registry sha512 integrity value (64 bytes, base64).
var integrityRE = regexp.MustCompile(`^sha512-[A-Za-z0-9+/]{86}==$`)

// ValidPackagePin reports why p cannot be a package pin ("" when it can).
func ValidPackagePin(p PackagePin) string {
	switch {
	case !installPackageRE.MatchString(p.Name):
		return "the name is not a package name"
	case !ValidInstallVersion(p.Version):
		return "the version is not a plain package version"
	case !integrityRE.MatchString(p.Integrity):
		return "the integrity is not a registry sha512 value"
	}
	return ""
}

// Flag renders p as the guest flag's value.
func (p PackagePin) Flag() string { return p.Name + "@" + p.Version + "=" + p.Integrity }

// ParsePackagePinFlag reads a PackageIntegrityFlag value.
func ParsePackagePinFlag(v string) (PackagePin, error) {
	spec, integ, ok := strings.Cut(v, "=")
	at := strings.LastIndex(spec, "@")
	if !ok || at <= 0 {
		return PackagePin{}, fmt.Errorf("%q is not name@version=integrity", v)
	}
	p := PackagePin{Name: spec[:at], Version: spec[at+1:], Integrity: integ}
	if why := ValidPackagePin(p); why != "" {
		return PackagePin{}, fmt.Errorf("%q: %s", v, why)
	}
	return p, nil
}

// IntegrityContentPath is where npm's content-addressed cache (cacache,
// content-v2) keeps the artifact with this integrity, relative to the
// cache's _cacache directory, and the raw sha512 the file must hash to.
func IntegrityContentPath(integrity string) (string, []byte, error) {
	if !integrityRE.MatchString(integrity) {
		return "", nil, fmt.Errorf("%q is not a registry sha512 value", integrity)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(integrity, "sha512-"))
	if err != nil || len(raw) != sha512.Size {
		return "", nil, fmt.Errorf("%q does not decode to a sha512", integrity)
	}
	h := hex.EncodeToString(raw)
	return path.Join("content-v2", "sha512", h[:2], h[2:4], h[4:]), raw, nil
}

// ScriptPolicy is the effective install-script policy of one node.
type ScriptPolicy struct {
	Mode  string
	Tools []string
	Pins  []ScriptPin
	// Fetching names the tools whose install script installs more packages
	// (the install-source table says so): their scripts run only under a pin
	// that names every fetched artifact's integrity (ruling P-142).
	Fetching []string
}

// sha256HexRE is a lowercase sha256 in hex.
var sha256HexRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

// toolIDRE is a registry tool id.
var toolIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidToolID reports whether s has the shape of a registry tool id.
func ValidToolID(s string) bool { return toolIDRE.MatchString(s) }

// ValidScriptPin reports why p cannot be a pin ("" when it can).
func ValidScriptPin(p ScriptPin) string {
	switch {
	case !ValidToolID(p.Tool):
		return "the tool is not a registry tool id"
	case !ValidInstallVersion(p.Version):
		return "the version is not a plain package version"
	case !sha256HexRE.MatchString(p.SHA256):
		return "the sha256 is not 64 lowercase hex characters"
	}
	return ""
}

// ScriptDecision is what the plan carries for one install: the accepted
// script hashes for the tool and version ("" none when the source needs no
// script), the pins they came from (for the consent line) and, for a tool
// whose script installs more packages, every artifact the install may fetch
// with its pinned integrity (the guest checks them before a script runs).
type ScriptDecision struct {
	SHA256   []string
	Pins     []ScriptPin
	Packages []PackagePin
}

// DecideInstallScripts decides, before anything is downloaded, whether an
// install of tool at version may run its package's scripts. needs is the
// install source's NeedsInstallScripts. A source that needs no script gets
// an empty decision (npm keeps --ignore-scripts, nothing else runs). One
// that needs its script is refused install_scripts_required under mode
// none or when the tool is not on a non-empty allow list, and
// install_scripts_unpinned when no pin names the tool and version, or when
// the tool's script installs more packages (pol.Fetching) and no pin for the
// version names their registry integrity (ruling P-142: a version alone does
// not pin what the script fetches); else the pins' hashes are the only
// scripts the guest may run.
func DecideInstallScripts(tool, version string, needs bool, pol ScriptPolicy) (ScriptDecision, error) {
	if !needs {
		return ScriptDecision{}, nil
	}
	mode := pol.Mode
	if mode == "" {
		mode = ScriptsPinned
	}
	if mode != ScriptsPinned {
		return ScriptDecision{}, fmt.Errorf("%s: the tool's package needs its own install script and [terminal.sandbox.oci].install_scripts is %q, so no package script runs", VerdictInstallScriptsRequired, mode)
	}
	if len(pol.Tools) > 0 && !slices.Contains(pol.Tools, tool) {
		return ScriptDecision{}, fmt.Errorf("%s: the tool's package needs its own install script and %s is not in [terminal.sandbox.oci].install_scripts_tools (%s)", VerdictInstallScriptsRequired, tool, strings.Join(pol.Tools, ", "))
	}
	var d ScriptDecision
	var others, noIntegrity []string
	fetching := slices.Contains(pol.Fetching, tool)
	for _, p := range pol.Pins {
		if p.Tool != tool || ValidScriptPin(p) != "" {
			continue
		}
		if p.Version != version {
			others = append(others, p.Version)
			continue
		}
		if fetching && !pinCarriesIntegrity(p) {
			// A script hash alone does not pin what this script fetches
			// (ruling P-142): the pin does not count, whatever its source.
			noIntegrity = append(noIntegrity, pinLabel(p))
			continue
		}
		if !slices.Contains(d.SHA256, p.SHA256) {
			d.SHA256 = append(d.SHA256, p.SHA256)
		}
		d.Pins = append(d.Pins, p)
		for _, pk := range p.Packages {
			if ValidPackagePin(pk) == "" && !slices.Contains(d.Packages, pk) {
				d.Packages = append(d.Packages, pk)
			}
		}
	}
	if len(noIntegrity) > 0 && len(d.SHA256) == 0 {
		return ScriptDecision{}, fmt.Errorf("%s: the install script of %s@%s installs more packages, and the pin(s) %s name no registry integrity (sha512) for the package and its platform packages; a script hash alone does not pin what the script fetches, so add the integrity values to the pin or pick a version with a built-in pin", VerdictInstallScriptsUnpinned, tool, version, strings.Join(noIntegrity, ", "))
	}
	if len(d.SHA256) == 0 {
		have := "no pin for this tool"
		if len(others) > 0 {
			slices.Sort(others)
			have = "pins exist for " + strings.Join(slices.Compact(others), ", ")
		}
		return ScriptDecision{}, fmt.Errorf("%s: the tool's package needs its own install script and no pin covers %s@%s (%s); add a reviewed pin (tool, version, script sha256) or pick a pinned version", VerdictInstallScriptsUnpinned, tool, version, have)
	}
	if fetching && len(d.Packages) == 0 {
		return ScriptDecision{}, fmt.Errorf("%s: the install script of %s@%s installs more packages, and no pin for this version names their registry integrity (sha512); a script hash alone does not pin what the script fetches, so pick a version with a built-in pin", VerdictInstallScriptsUnpinned, tool, version)
	}
	return d, nil
}

// pinCarriesIntegrity reports whether p names at least one fetched artifact
// by a well-formed registry integrity value, and no malformed one.
func pinCarriesIntegrity(p ScriptPin) bool {
	if len(p.Packages) == 0 {
		return false
	}
	for _, pk := range p.Packages {
		if ValidPackagePin(pk) != "" {
			return false
		}
	}
	return true
}

// pinLabel names a pin in a refusal: its source and the start of its hash.
func pinLabel(p ScriptPin) string {
	src := p.Source
	if src == "" {
		src = "unknown source"
	}
	return p.SHA256[:12] + " (" + src + ")"
}

// PackageFacts is what the guest read of an installed npm package: its
// package.json name, version and declared dependencies, and which declared
// packages are installed at which version.
type PackageFacts struct {
	Name     string
	Version  string
	Required []string
	Optional []string
	// Installed returns the installed version of a dependency named by the
	// package.json, ok false when it is not installed.
	Installed func(name string) (version string, ok bool, err error)
	// Cached reports whether the install's own npm cache holds an artifact
	// whose sha512 is the integrity's (the guest hashes the file).
	Cached func(integrity string) (bool, error)
}

// ParsePackageFacts reads the name, version and dependency names of an
// installed package.json.
func ParsePackageFacts(pkgJSON []byte) (PackageFacts, error) {
	var m struct {
		Name     string            `json:"name"`
		Version  string            `json:"version"`
		Deps     map[string]string `json:"dependencies"`
		Optional map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(pkgJSON, &m); err != nil {
		return PackageFacts{}, fmt.Errorf("%s: the installed package.json does not parse: %w", VerdictInstallPackageUnpinned, err)
	}
	f := PackageFacts{Name: m.Name, Version: m.Version}
	for _, n := range append(slices.Collect(maps.Keys(m.Deps)), slices.Collect(maps.Keys(m.Optional))...) {
		if !installPackageRE.MatchString(n) {
			return PackageFacts{}, fmt.Errorf("%s: the installed package.json names a dependency %q that is not a package name", VerdictInstallPackageUnpinned, n)
		}
	}
	for n := range m.Deps {
		f.Required = append(f.Required, n)
	}
	for n := range m.Optional {
		if _, dup := m.Deps[n]; !dup {
			f.Optional = append(f.Optional, n)
		}
	}
	slices.Sort(f.Required)
	slices.Sort(f.Optional)
	return f, nil
}

// CheckFetchedPackages is the integrity check the guest runs after the
// installer and before any package script (ruling P-142). With no pins it
// checks nothing (the tool's script fetches nothing). Otherwise every
// artifact the install fetched must be one a pin names: the package itself,
// every required dependency and every optional dependency npm installed
// must each match a pin's name and version, and the install's own fresh npm
// cache must hold an artifact with that pin's sha512 integrity. When the
// package declares optional dependencies and npm installed none of them,
// the script would fetch one itself, outside this check, so the install is
// refused before it runs. Every refusal names the package.
func CheckFetchedPackages(f PackageFacts, pins []PackagePin) error {
	if len(pins) == 0 {
		return nil
	}
	pinFor := func(name string) (PackagePin, bool) {
		for _, p := range pins {
			if p.Name == name {
				return p, true
			}
		}
		return PackagePin{}, false
	}
	check := func(name, version string) error {
		p, ok := pinFor(name)
		if !ok {
			return fmt.Errorf("%s: the install fetched %s@%s, which no pin names by its registry integrity; no script was run", VerdictInstallPackageUnpinned, name, version)
		}
		if p.Version != version {
			return fmt.Errorf("%s: the install fetched %s@%s, but the pin names %s; no script was run", VerdictInstallPackageUnpinned, name, version, p.Version)
		}
		ok, err := f.Cached(p.Integrity)
		if err != nil {
			return fmt.Errorf("%s: check the fetched %s@%s against its pinned integrity: %w; no script was run", VerdictInstallPackageUnpinned, name, version, err)
		}
		if !ok {
			return fmt.Errorf("%s: the install's npm cache holds no artifact with the pinned integrity of %s@%s (%s), so the fetched tarball is not the pinned one; no script was run", VerdictInstallPackageUnpinned, name, version, p.Integrity)
		}
		return nil
	}
	if err := check(f.Name, f.Version); err != nil {
		return err
	}
	for _, n := range f.Required {
		v, ok, err := f.Installed(n)
		if err != nil {
			return fmt.Errorf("%s: read the installed %s: %w; no script was run", VerdictInstallPackageUnpinned, n, err)
		}
		if !ok {
			return fmt.Errorf("%s: the required dependency %s is not installed; no script was run", VerdictInstallPackageUnpinned, n)
		}
		if err := check(n, v); err != nil {
			return err
		}
	}
	placed := 0
	for _, n := range f.Optional {
		v, ok, err := f.Installed(n)
		if err != nil {
			return fmt.Errorf("%s: read the installed %s: %w; no script was run", VerdictInstallPackageUnpinned, n, err)
		}
		if !ok {
			continue
		}
		if err := check(n, v); err != nil {
			return err
		}
		placed++
	}
	if len(f.Optional) > 0 && placed == 0 {
		return fmt.Errorf("%s: npm installed none of %s's platform packages, so its install script would fetch one itself, outside the integrity check; no script was run", VerdictInstallPackageUnpinned, f.Name)
	}
	return nil
}

// packageLifecycles are the install lifecycle scripts npm runs for the
// installed package itself, in npm's order.
var packageLifecycles = []string{"preinstall", "install", "postinstall"}

// scriptCommandRE is the one lifecycle command shape the guest runs:
// `node <relative file>`, a file name with no shell syntax. Anything else
// (a shell pipeline, a download, an argument) is refused by shape.
var scriptCommandRE = regexp.MustCompile(`^node ([A-Za-z0-9._][A-Za-z0-9._/-]{0,200})$`)

// ScriptStep is one script the guest runs: its lifecycle, the file
// relative to the package directory and the file's sha256.
type ScriptStep struct {
	Lifecycle string
	File      string
	SHA256    string
}

// Argv is the step's command: node and the file, run in the package dir.
func (s ScriptStep) Argv() []string { return []string{"node", s.File} }

// PlanPackageScripts checks the installed package's own lifecycle scripts
// against the accepted hashes and returns the steps to run, in npm's order.
// pkgJSON is the package.json npm installed; readFile reads a file relative
// to the package directory (no link followed, capped, by the caller);
// hasFile reports whether a relative name exists (for binding.gyp, whose
// presence makes npm run node-gyp as an implicit install script). An empty
// allowed list means the source needs no script: nothing is run, whatever
// the package declares (npm already ran with --ignore-scripts). Every
// refusal names the lifecycle and, for a hash mismatch, both hashes.
func PlanPackageScripts(pkgJSON []byte, allowed []string, readFile func(rel string) ([]byte, error), hasFile func(rel string) bool) ([]ScriptStep, error) {
	if len(allowed) == 0 {
		return nil, nil
	}
	var m struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(pkgJSON, &m); err != nil {
		return nil, fmt.Errorf("%s: the installed package.json does not parse: %w", VerdictInstallScriptMismatch, err)
	}
	if _, explicit := m.Scripts["install"]; !explicit && m.Scripts["preinstall"] == "" && hasFile != nil && hasFile("binding.gyp") {
		return nil, fmt.Errorf("%s: the package holds binding.gyp, so npm would run node-gyp as its install script, which no pin covers", VerdictInstallScriptMismatch)
	}
	var out []ScriptStep
	for _, lc := range packageLifecycles {
		cmd, ok := m.Scripts[lc]
		if !ok {
			continue
		}
		sm := scriptCommandRE.FindStringSubmatch(strings.TrimSpace(cmd))
		if sm == nil {
			return nil, fmt.Errorf("%s: the package's %s script %q is not `node <file>`, the one shape a pinned script may take", VerdictInstallScriptMismatch, lc, cmd)
		}
		rel := strings.TrimPrefix(sm[1], "./")
		if c := path.Clean(rel); c != rel || strings.HasPrefix(c, "../") || c == ".." || strings.HasPrefix(c, "/") {
			return nil, fmt.Errorf("%s: the package's %s script names %q, outside the package", VerdictInstallScriptMismatch, lc, rel)
		}
		b, err := readFile(rel)
		if err != nil {
			return nil, fmt.Errorf("%s: read the package's %s script %s: %w", VerdictInstallScriptMismatch, lc, rel, err)
		}
		sum := sha256.Sum256(b)
		h := hex.EncodeToString(sum[:])
		if !slices.Contains(allowed, h) {
			return nil, fmt.Errorf("%s: the package's %s script %s has sha256 %s, which no pin names (pinned: %s); nothing was run", VerdictInstallScriptMismatch, lc, rel, h, strings.Join(allowed, ", "))
		}
		out = append(out, ScriptStep{Lifecycle: lc, File: rel, SHA256: h})
	}
	return out, nil
}

// NPMPackageDir is the installed package's directory under an npm global
// prefix (npm's own layout on Linux: <prefix>/lib/node_modules/<name>).
func NPMPackageDir(prefix, pkg string) string {
	return path.Join(prefix, "lib", "node_modules", pkg)
}

// FloorScriptPolicy applies an organization's floor to the node's policy:
// the more restrictive mode wins (none beats pinned), a non-empty org tool
// list intersects the node's (an empty node list stands for the whole
// catalog, so the org's list is then taken as is), and the org's own pins
// are added (they only allow what the mode and the list still allow). The
// floor never widens the node: an empty org list and an empty org mode
// leave the node's values.
func FloorScriptPolicy(node, org ScriptPolicy) ScriptPolicy {
	out := ScriptPolicy{Mode: node.Mode, Tools: append([]string(nil), node.Tools...), Pins: append([]ScriptPin(nil), node.Pins...), Fetching: append([]string(nil), node.Fetching...)}
	if out.Mode == "" {
		out.Mode = ScriptsPinned
	}
	if org.Mode == ScriptsNone {
		out.Mode = ScriptsNone
	}
	if len(org.Tools) > 0 {
		if len(out.Tools) == 0 {
			out.Tools = append([]string(nil), org.Tools...)
		} else {
			var keep []string
			for _, t := range out.Tools {
				if slices.Contains(org.Tools, t) {
					keep = append(keep, t)
				}
			}
			out.Tools = keep
			if len(keep) == 0 {
				// Nothing left in common: no tool's scripts may run. An empty
				// list would read as the whole catalog, so the mode closes.
				out.Mode = ScriptsNone
			}
		}
	}
	for _, p := range org.Pins {
		p.Source = PinSourceOrg
		out.Pins = append(out.Pins, p)
	}
	return out
}
