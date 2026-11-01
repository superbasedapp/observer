//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// terminal_sandbox_oci_install.go is the daemon's half of the first-start
// install into a per-image cache volume (sandbox plan v2 section 5.4 "Agent
// tool delivery", ledger SBX-IMG-1, lane SBX-P3C). It runs only with
// [terminal.sandbox.oci].install_cache = true; off, nothing here is called
// and the delivery table refuses as before.
//
// At Create the daemon decides: the tool's install source (the registry's
// side table, internal/integration installsource.go; no row refuses
// install_source_unknown), the version to pin (the host's installed copy of
// the same tool, ociHostToolVersion; none refuses install_version_unknown),
// the installer's runtime in the image (probed with the tool's own probe;
// absent refuses install_runtime_missing), and the cache volume's state on
// the engine (ClassifyCache over the labelled volumes and the host's own
// completion record). A current cache is mounted read-only; an absent or
// stale one puts an install step in the run's plan file, which the host
// helper runs (terminal_sandbox_oci_install_linux.go) after it has asked
// the user on the run's own terminal, the one place the dashboard and the
// CLI launch both show.

// ociInstallStep is the plan file's install step: names and paths only (no
// secret, TestOCIPlanFileHoldsNoSecrets).
type ociInstallStep struct {
	Tool    string   `json:"tool"`
	Kind    string   `json:"kind"`
	Package string   `json:"package"`
	Bin     string   `json:"bin"`
	Hosts   []string `json:"hosts"`
	DocURL  string   `json:"doc_url"`
	Version string   `json:"version"`
	// NeedsScripts and ScriptSHA256: the package's own lifecycle scripts
	// the setup container runs after the installer, only those whose file
	// hash is one of these (lane LEFT-SBX, ruling P-136).
	NeedsScripts bool     `json:"needs_scripts,omitempty"`
	ScriptSHA256 []string `json:"script_sha256,omitempty"`
	// ScriptPackages: every artifact the install may fetch, pinned by its
	// registry integrity, which the setup container checks before it runs
	// a script (ruling P-142); empty for a script that fetches nothing.
	ScriptPackages []sandboxoci.PackagePin `json:"script_packages,omitempty"`
	// Image is the image's digest (the cache key).
	Image  string `json:"image"`
	Volume string `json:"volume"`
	// Others are the stale caches of this image and tool, removed once the
	// new one is complete.
	Others []string `json:"others,omitempty"`
	// Refresh: the cache was stale (the host's version changed).
	Refresh bool `json:"refresh,omitempty"`
	// Line is the consent line the helper shows.
	Line string `json:"line"`
}

// ociCacheChoice is what Create decided about the tool cache for one run.
type ociCacheChoice struct {
	// volume is the cache volume the agent's container mounts read-only.
	volume string
	// binDir is the cache's bin directory in the box (prepended to PATH).
	binDir string
	// install is set when the volume must be filled first.
	install *ociInstallStep
}

// ociHostVersionFn reads the host's installed version of a tool (a
// variable so a test can feed one).
var ociHostVersionFn = ociHostToolVersion

// ociHostToolVersion is the host's installed version of the tool whose
// resolved binary is bin: first the version of the package's own
// package.json above the binary (an npm install, read, never run), then the
// binary's own --version answer (bounded to 5 s, no stdin, run with the
// host's PATH and HOME only). "" when neither gives a plain version.
func ociHostToolVersion(bin, pkg string) string {
	if bin == "" {
		return ""
	}
	dir := filepath.Dir(bin)
	for i := 0; i < 8 && dir != filepath.Dir(dir); i++ {
		if v := ociPackageVersion(filepath.Join(dir, "package.json"), pkg); v != "" {
			return v
		}
		dir = filepath.Dir(dir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	//nolint:gosec // G204: the tool's own resolved host binary, asked only for its version
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	cmd.Stdin = nil
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	if len(out) > 4096 {
		out = out[:4096]
	}
	v, _ := extrun.ParseVersion(out, nil)
	if !sandboxoci.ValidInstallVersion(v) {
		return ""
	}
	return v
}

// ociPackageVersion reads the version of p when it is the package.json of
// pkg (a regular file, capped).
func ociPackageVersion(p, pkg string) string {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return ""
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: a package.json above the tool's own resolved binary, lstat-checked and capped
	if err != nil {
		return ""
	}
	var m struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(b, &m) != nil || m.Name != pkg || !sandboxoci.ValidInstallVersion(m.Version) {
		return ""
	}
	return m.Version
}

// ociInstallSourceFor is the tool's install source in the planner's shape.
func ociInstallSourceFor(tool string) (integration.InstallSource, sandboxoci.InstallSource, bool) {
	src, ok := integration.InstallSourceFor(tool)
	if !ok {
		return src, sandboxoci.InstallSource{}, false
	}
	return src, sandboxoci.InstallSource{Kind: string(src.Kind), Package: src.Package, Bin: src.Bin, Hosts: src.Hosts, NeedsScripts: src.NeedsInstallScripts}, true
}

// ociCacheDecision classifies the run's cache on the engine and returns the
// mount and, when the cache is absent or stale, the install step.
func (d *ociDriver) ociCacheDecision(ctx context.Context, c *sandboxengine.Client, installID, image, tool, version string) (ociCacheChoice, string, error) {
	src, psrc, ok := ociInstallSourceFor(tool)
	if !ok {
		return ociCacheChoice{}, "", fmt.Errorf("%s: no grounded install source for %s", sandboxoci.VerdictInstallSourceUnknown, tool)
	}
	scripts, err := sandboxoci.DecideInstallScripts(tool, version, psrc.NeedsScripts, d.ociScriptPolicy())
	if err != nil {
		return ociCacheChoice{}, "", err
	}
	psrc.ScriptSHA256 = scripts.SHA256
	psrc.ScriptPackages = scripts.Packages
	digest, ok := sandboxoci.ImageDigestOf(image)
	if !ok {
		return ociCacheChoice{}, "", fmt.Errorf("%s: the image %s is not pinned by digest, so its tool cache has no key", sandboxoci.VerdictToolUnavailable, image)
	}
	lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	vols, err := c.VolumeList(lctx, sandboxoci.CacheFilter(installID, digest, tool))
	if err != nil {
		return ociCacheChoice{}, "", fmt.Errorf("list the tool caches: %w", err)
	}
	facts := make([]sandboxoci.CacheVolumeFact, 0, len(vols))
	for _, v := range vols {
		facts = append(facts, sandboxoci.CacheVolumeFact{Name: v.Name, Labels: v.Labels})
	}
	done := ociCacheRecords(d.r.observerDir)
	// A record whose volume the engine no longer lists is forgotten (audit
	// finding 4): the cache is then absent and its install is planned again.
	listed := map[string]bool{}
	for _, v := range vols {
		listed[v.Name] = true
	}
	for name, rec := range done {
		if rec.Tool == tool && rec.Image == digest && !listed[name] {
			_ = setOCICacheRecord(d.r.observerDir, name, nil)
			delete(done, name)
		}
	}
	verdict := sandboxoci.ClassifyCache(facts, func(name string) bool { _, ok := done[name]; return ok }, installID, digest, tool, version)
	choice := ociCacheChoice{binDir: sandboxoci.CacheBinDir(psrc.Kind)}
	if verdict.State == sandboxoci.CacheCurrent {
		choice.volume = verdict.Current
		return choice, " tool=cache(" + psrc.Package + "@" + version + ")", nil
	}
	vol := sandboxoci.CacheVolumeName(installID, digest, tool, version)
	refresh := verdict.State == sandboxoci.CacheStale
	choice.volume = vol
	choice.install = &ociInstallStep{
		Tool: tool, Kind: psrc.Kind, Package: psrc.Package, Bin: psrc.Bin, Hosts: psrc.Hosts, DocURL: src.DocURL,
		Version: version, Image: digest, Volume: vol, Others: verdict.Others, Refresh: refresh,
		NeedsScripts: psrc.NeedsScripts, ScriptSHA256: scripts.SHA256, ScriptPackages: scripts.Packages,
		Line: sandboxoci.InstallLine(tool, psrc, version, vol, refresh) + ociScriptLine(scripts),
	}
	state := "first start"
	if refresh {
		state = "stale, refreshed"
	}
	return choice, fmt.Sprintf(" tool=install(%s@%s from %s, %s; the terminal asks first)", psrc.Package, version, strings.Join(psrc.Hosts, ","), state), nil
}

// ociScriptLine is the consent line's note on the package's own install
// script: which pinned scripts the setup container may run, with where each
// pin came from.
func ociScriptLine(d sandboxoci.ScriptDecision) string {
	if len(d.Pins) == 0 {
		return ""
	}
	var parts []string
	for _, p := range d.Pins {
		parts = append(parts, p.SHA256[:12]+" ("+p.Source+")")
	}
	line := "; then it runs the package's own install script only if its sha256 matches a reviewed pin: " + strings.Join(parts, ", ")
	if n := len(d.Packages); n > 0 {
		names := make([]string, 0, n)
		for _, pk := range d.Packages {
			names = append(names, pk.Name+"@"+pk.Version+" "+ociIntegrityShort(pk.Integrity))
		}
		line += fmt.Sprintf(", and only after every package it fetched matches one of %d pinned by registry integrity (sha512): %s", n, strings.Join(names, ", "))
	}
	return line
}

// ociIntegrityShort is the start of an integrity value, enough to compare
// with the registry's.
func ociIntegrityShort(integrity string) string {
	if len(integrity) <= 19 {
		return integrity
	}
	return integrity[:19] + "..."
}

// ociInstallVersion is the version the first-start install pins: the one
// [terminal.sandbox.oci].install_versions picks for the tool, else the
// host's installed version (only when the host has the tool), else "" (the
// delivery table refuses install_version_unknown).
func (d *ociDriver) ociInstallVersion(tool string, src sandboxoci.InstallSource, hostHasTool bool) string {
	if v := strings.TrimSpace(d.cfg.InstallVersions[tool]); sandboxoci.ValidInstallVersion(v) {
		return v
	}
	if src.Kind == "" || !hostHasTool {
		return ""
	}
	return ociHostVersionFn(d.r.toolBinary(tool), src.Package)
}

// ociScriptPolicy is the node's effective install-script policy (lane
// LEFT-SBX, ruling P-136): the effective [terminal.sandbox.oci]
// install_scripts and install_scripts_tools (already floored by any
// governance pin config.Load applied and, on a managed node holding
// enforce.sandbox, by the managed body's install_scripts, whose compose row
// is sandbox_managed.go's), then the pins: Observer's built-in ones, the
// developer's own and the organization's signed ones. A pin only allows; a
// tool still needs the mode and the list.
func (d *ociDriver) ociScriptPolicy() sandboxoci.ScriptPolicy {
	pol := sandboxoci.ScriptPolicy{Mode: d.cfg.InstallScripts, Tools: append([]string(nil), d.cfg.InstallScriptsTools...)}
	if pol.Mode == "" {
		pol.Mode = sandboxoci.ScriptsPinned
	}
	for _, src := range integration.InstallSources() {
		if src.ScriptFetchesPackages {
			pol.Fetching = append(pol.Fetching, src.Tool)
		}
		for _, p := range src.ScriptPins {
			pin := sandboxoci.ScriptPin{Tool: src.Tool, Version: p.Version, SHA256: p.SHA256, Source: sandboxoci.PinSourceBuiltin, Note: p.Grounding}
			for _, pk := range p.Packages {
				pin.Packages = append(pin.Packages, sandboxoci.PackagePin{Name: pk.Name, Version: pk.Version, Integrity: pk.Integrity})
			}
			pol.Pins = append(pol.Pins, pin)
		}
	}
	for _, p := range d.cfg.InstallScriptPins {
		note := "added by you"
		if p.Added != "" {
			note += " on " + p.Added
		}
		pol.Pins = append(pol.Pins, sandboxoci.ScriptPin{Tool: p.Tool, Version: p.Version, SHA256: p.SHA256, Source: sandboxoci.PinSourceUser, Note: note, Packages: ociPackagePins(p.Packages)})
	}
	for _, p := range d.cfg.OrgInstallScriptPins {
		pol.Pins = append(pol.Pins, sandboxoci.ScriptPin{Tool: p.Tool, Version: p.Version, SHA256: p.SHA256, Source: sandboxoci.PinSourceOrg, Note: p.Added, Packages: ociPackagePins(p.Packages)})
	}
	return pol
}

// ociPackagePins carries a config pin's package integrity values into the
// policy (R-014): user and org pins check what the install fetched exactly
// as built-in pins do.
func ociPackagePins(in []config.TerminalSandboxOCIPackagePin) []sandboxoci.PackagePin {
	if len(in) == 0 {
		return nil
	}
	out := make([]sandboxoci.PackagePin, 0, len(in))
	for _, pk := range in {
		out = append(out, sandboxoci.PackagePin{Name: pk.Name, Version: pk.Version, Integrity: pk.Integrity})
	}
	return out
}

// ---- the host's record of completed caches -----------------------------------

// ociCacheRecord is one completed cache.
type ociCacheRecord struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	Image       string    `json:"image"`
	Package     string    `json:"package"`
	CompletedAt time.Time `json:"completed_at"`
}

// ociCacheRecordsFile is the host's record of completed caches: a volume
// the setup container did not finish is never a cache.
func ociCacheRecordsFile(observerDir string) string {
	return filepath.Join(ociStateDir(observerDir), "tool-caches.json")
}

// ociCacheRecords reads the record (empty when none or unreadable).
func ociCacheRecords(observerDir string) map[string]ociCacheRecord {
	b, err := readOwnedNoFollow(ociCacheRecordsFile(observerDir), 1<<20)
	if err != nil {
		return map[string]ociCacheRecord{}
	}
	var m map[string]ociCacheRecord
	if json.Unmarshal(b, &m) != nil || m == nil {
		return map[string]ociCacheRecord{}
	}
	return m
}

// setOCICacheRecord records (rec != nil) or forgets (nil) a cache volume.
func setOCICacheRecord(observerDir, volume string, rec *ociCacheRecord) error {
	m := ociCacheRecords(observerDir)
	if rec == nil {
		if _, ok := m[volume]; !ok {
			return nil
		}
		delete(m, volume)
	} else {
		m[volume] = *rec
	}
	return writeOCIStateFile(ociCacheRecordsFile(observerDir), m)
}

// ociCacheDir is the owner-only host directory behind a cache volume (the
// volume is the local driver's bind of it, so what the setup container
// writes belongs to the host user on every engine mode).
func ociCacheDir(observerDir, volume string) string {
	return filepath.Join(ociStateDir(observerDir), "tool-cache", volume)
}

// ociRemoveCacheDir removes a cache volume's host directory, only when it
// is a plain directory under the cache root.
func ociRemoveCacheDir(observerDir, volume string) error {
	if !strings.HasPrefix(volume, sandboxoci.CacheVolumePrefix) || strings.ContainsAny(volume, `/\`) {
		return fmt.Errorf("%q is not a tool cache volume", volume)
	}
	p := ociCacheDir(observerDir, volume)
	st, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory, left alone", p)
	}
	return os.RemoveAll(p)
}

// sandboxManagedInstallScriptsFloor applies the managed body's
// install_scripts floor onto dst (the compose row of sandbox_managed.go,
// lane LEFT-SBX, ruling P-136): the one rule sandboxoci.FloorScriptPolicy
// lowers the mode and narrows the tools, and the org's signed pins are
// recorded beside the developer's own. It reports whether it set anything.
func sandboxManagedInstallScriptsFloor(dst *config.TerminalSandboxConfig, f orgcontract.SandboxManagedInstallScriptsV1) bool {
	org := sandboxoci.ScriptPolicy{Mode: f.Mode, Tools: f.Tools}
	for _, pin := range f.Pins {
		sp := sandboxoci.ScriptPin{Tool: pin.Tool, Version: pin.Version, SHA256: pin.SHA256, Note: pin.Note}
		for _, pk := range pin.Packages {
			sp.Packages = append(sp.Packages, sandboxoci.PackagePin{Name: pk.Name, Version: pk.Version, Integrity: pk.Integrity})
		}
		org.Pins = append(org.Pins, sp)
	}
	eff := sandboxoci.FloorScriptPolicy(sandboxoci.ScriptPolicy{Mode: dst.OCI.InstallScripts, Tools: dst.OCI.InstallScriptsTools}, org)
	dst.OCI.InstallScripts, dst.OCI.InstallScriptsTools = eff.Mode, eff.Tools
	dst.OCI.OrgInstallScriptPins = nil
	for _, pin := range eff.Pins {
		note := "published by your organization"
		if pin.Note != "" {
			note += ": " + pin.Note
		}
		cp := config.TerminalSandboxOCIScriptPin{Tool: pin.Tool, Version: pin.Version, SHA256: pin.SHA256, Added: note}
		for _, pk := range pin.Packages {
			cp.Packages = append(cp.Packages, config.TerminalSandboxOCIPackagePin{Name: pk.Name, Version: pk.Version, Integrity: pk.Integrity})
		}
		dst.OCI.OrgInstallScriptPins = append(dst.OCI.OrgInstallScriptPins, cp)
	}
	return true
}

// sandboxInstallScriptsDoctorChecks is doctor's line for the effective
// install-script policy (lane LEFT-SBX, ruling P-136), shown only while
// [terminal.sandbox.oci].install_cache is on (where it is read): the mode,
// the tool list and how many pins of each source count.
func sandboxInstallScriptsDoctorChecks(eff config.TerminalSandboxConfig) []diag.Check {
	if !eff.OCI.InstallCache {
		return nil
	}
	pol := (&ociDriver{r: &sandboxRuntime{}, cfg: eff.OCI}).ociScriptPolicy()
	count := map[string]int{}
	for _, p := range pol.Pins {
		count[p.Source]++
	}
	tools := "every install-source tool"
	if len(pol.Tools) > 0 {
		tools = strings.Join(pol.Tools, ", ")
	}
	msg := "first-start install scripts: " + pol.Mode
	if pol.Mode == sandboxoci.ScriptsPinned {
		msg += fmt.Sprintf(" (a package's own install script runs only when it matches a reviewed pin; tools: %s; pins: %d built in, %d yours, %d from your organization)",
			tools, count[sandboxoci.PinSourceBuiltin], count[sandboxoci.PinSourceUser], count[sandboxoci.PinSourceOrg])
	} else {
		msg += " (no package install script runs; a tool that needs one is refused naming why)"
	}
	return []diag.Check{{Name: "sandbox.oci.install_scripts", Status: diag.StatusOK, Message: msg}}
}

// sandboxInstallVersionsSeam backs the version picker's route (lane
// LEFT-SBX): the published versions of one install-source tool, read from
// that source's own registry hosts (sandboxnet.FetchInstallVersions), only
// while the container driver is selected and
// [terminal.sandbox.oci].install_cache is on in the config at configPath
// (read at each call, so turning it off stops the reads at once).
func sandboxInstallVersionsSeam(configPath string) func(ctx context.Context, tool string) ([]string, error) {
	return func(ctx context.Context, tool string) ([]string, error) {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return nil, fmt.Errorf("read the config: %w", err)
		}
		if !componentSnapshotForConfig(cfg).Active("terminals.sandbox.oci") || !effectiveSandboxConfig(cfg).OCI.InstallCache {
			return nil, errors.New("the first-start install is off ([terminal.sandbox.oci].install_cache), so no registry is read")
		}
		src, ok := integration.InstallSourceFor(tool)
		if !ok {
			return nil, fmt.Errorf("%s: no grounded install source for %s", sandboxoci.VerdictInstallSourceUnknown, tool)
		}
		fctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		return sandboxnet.FetchInstallVersions(fctx, nil, string(src.Kind), src.Package, src.Hosts)
	}
}
