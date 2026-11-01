//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxsignin"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_oci_tools.go holds the per-launch choices of the
// oci-runc driver that depend on the tool and the repository (sandbox plan
// v2 sections 5.4 and 13 P3): how the agent's CLI reaches the container
// (the host's own toolchain, bound read-only, when the image has the host
// binary's loader; asked of the image through the engine without running
// anything in it), and the repository's .devcontainer image, used only by
// digest and only after the user's consent for that repository and digest.

// ociRunChoice is what Create decided for one run and Attach composes.
type ociRunChoice struct {
	image    string
	extraEnv []string
	// source is the run's workspace source: a clone-local copy gets the
	// return step when the run ends.
	source workspace.Source
	// delivery is how the tool reaches the box (sandboxoci.PlanToolDelivery);
	// an image's own copy runs on a projected tool state on any row.
	delivery sandboxoci.Delivery
	// cache is the tool cache of a cache-installed tool (lane SBX-P3C).
	cache ociCacheChoice
	// notices are shown first on the run's terminal (lane SBX-P3C).
	notices []string
	// pending is a daemon launch whose default image is still to be pulled
	// (R-037): the pull and the image-dependent checks run after the
	// terminal opens, from Attach (terminal_sandbox_oci_deferred.go).
	pending *ociPendingPrep
	// signIn is the run's sign-in seeding decision (lane BOXSIGNIN), taken
	// in Create before the workspace and carried out in compose.
	signIn sandboxsignin.Decision
}

// ociABICache remembers, per image and loader, whether the image has the
// loader (images are pinned by digest, so a found loader cannot go away). A
// "no loader" answer is kept only for ociABINegativeTTL and then asked again
// (SBX-P3A merge finding F5: a failed probe is never cached as final), and an
// answer whose probe container went away during the check is not kept at all.
var ociABICache sync.Map

// ociABIEntry is one cached loader answer.
type ociABIEntry struct {
	facts sandboxoci.ToolFacts
	at    time.Time
}

// ociABINegativeTTL bounds how long a "no loader" answer is reused; ociABINow
// is the clock (both seams for tests).
var (
	ociABINegativeTTL = 10 * time.Minute
	ociABINow         = time.Now
)

// toolBinary resolves the tool's real host binary ("" when it does not
// resolve): the pinned [launch.tools] path first, then the registry's
// resolution ladder.
func (r *sandboxRuntime) toolBinary(tool string) string {
	real := func(p string) string {
		if p == "" {
			return ""
		}
		if rp, err := filepath.EvalSymlinks(p); err == nil {
			return rp
		}
		return ""
	}
	if tc, ok := r.launchTools[tool]; ok && tc.Path != "" {
		return real(tc.Path)
	}
	if ic, ok := integration.For(tool); ok && ic.Binary != nil {
		res := toolresolve.Resolve(*ic.Binary, dashResolveEnv())
		if res.Chosen != nil && res.Chosen.Real != "" {
			return real(res.Chosen.Real)
		}
		return real(res.Bin)
	}
	return ""
}

// hostLoader returns the program that actually runs for bin (bin itself,
// or the interpreter its #! line names, looked up in the tool's dirs and
// then PATH) and that program's ELF loader. ok is false when neither is
// readable as a binary.
func (r *sandboxRuntime) hostLoader(tool, bin string) (prog, interp string, ok bool) {
	prog = bin
	for hop := 0; hop < 2; hop++ {
		f, err := os.Open(prog) //nolint:gosec // G304: the resolved tool binary or its interpreter
		if err != nil {
			return "", "", false
		}
		head := make([]byte, 256)
		n, _ := io.ReadFull(f, head)
		interp, err = sandboxoci.ELFInterp(f)
		_ = f.Close()
		if err == nil {
			return prog, interp, true
		}
		next, isScript := sandboxoci.Shebang(head[:n])
		if !isScript {
			return "", "", false
		}
		prog = r.findProgram(tool, next)
		if prog == "" {
			return "", "", false
		}
	}
	return "", "", false
}

// findProgram resolves an interpreter name from a #! line: an absolute path
// as is, a bare name in the tool's own bin dirs first, then PATH.
func (r *sandboxRuntime) findProgram(tool, name string) string {
	if filepath.IsAbs(name) {
		if rp, err := filepath.EvalSymlinks(name); err == nil {
			return rp
		}
		return ""
	}
	for _, d := range r.toolBinDirs(tool) {
		if rp, err := filepath.EvalSymlinks(filepath.Join(d, name)); err == nil {
			return rp
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		if rp, err := filepath.EvalSymlinks(p); err == nil {
			return rp
		}
	}
	return ""
}

// toolFacts gathers the delivery facts for tool in image: the host binary
// and its loader, and, for a dynamically linked binary, whether the image
// holds that loader and a copy of the tool (read through the engine's path
// stat of a created, never-started container, removed at once; on an
// engine that cannot stat a created container, through the started check,
// ociStartedPathCheck, run as user).
//
// runtime, when set, names the programs the first-start installer needs
// (sandboxoci.InstallerRuntime): each is looked for with the tool's own
// probe, and ImageHasRuntime is set only when the image holds every one.
func (d *ociDriver) toolFacts(ctx context.Context, c *sandboxengine.Client, installID, image, tool, user string, runtime []string) (sandboxoci.ToolFacts, error) {
	var f sandboxoci.ToolFacts
	bin := d.r.toolBinary(tool)
	if bin == "" {
		return f, nil
	}
	prog, interp, ok := d.r.hostLoader(tool, bin)
	if !ok {
		return f, nil
	}
	f.HostBinary, f.Interp = prog, interp
	if interp == "" {
		return f, nil
	}
	key := image + "\x00" + interp + "\x00" + filepath.Base(bin) + "\x00" + strings.Join(runtime, ",")
	if v, ok := ociABICache.Load(key); ok {
		e, _ := v.(ociABIEntry)
		if e.facts.ImageHasInterp || ociABINow().Sub(e.at) < ociABINegativeTTL {
			f.ImageHasInterp, f.ImageHasTool, f.ImageHasRuntime = e.facts.ImageHasInterp, e.facts.ImageHasTool, e.facts.ImageHasRuntime
			return f, nil
		}
		ociABICache.Delete(key)
	}
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return f, err
	}
	probeRun := "abiprobe" + hex.EncodeToString(raw[:])
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// A created container is never started: nothing of the image runs.
	id, _, err := c.ContainerCreate(pctx, sandboxoci.ContainerName(installID, probeRun), map[string]any{
		"Image": image, "Entrypoint": []string{"/observer-abi-probe-never-runs"}, "Cmd": []string{},
		"Labels":     sandboxoci.ProbeLabels(installID, probeRun),
		"HostConfig": map[string]any{"NetworkMode": "none", "CapDrop": []string{"ALL"}, "LogConfig": map[string]string{"Type": "none"}},
	})
	if err != nil {
		return f, fmt.Errorf("ask the image for the tool's loader: %w", err)
	}
	defer func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rcancel()
		_ = c.ContainerRemove(rctx, id)
	}()
	toolPaths := sandboxoci.ImageToolPaths(filepath.Base(bin))
	f.ImageHasInterp, err = c.ContainerPathStat(pctx, id, interp)
	switch {
	case sandboxengine.IsServerError(err):
		// The engine cannot stat a created container (rootless Podman
		// 5.7.0 answers 500 for every path, live check D4): ask through a
		// started check of Observer's own binary instead.
		found, serr := d.ociStartedPathCheck(pctx, c, installID, image, user, append([]string{interp}, toolPaths...))
		if serr != nil {
			return f, fmt.Errorf("ask the image for the tool's loader: the engine cannot stat a created container (%w), and the started check failed: %w", err, serr)
		}
		f.ImageHasInterp = found[0]
		for _, ok := range found[1:] {
			f.ImageHasTool = f.ImageHasTool || ok
		}
		if len(runtime) > 0 {
			has := true
			for _, prog := range runtime {
				paths := sandboxoci.ImageToolPaths(prog)
				got, serr := d.ociStartedPathCheck(pctx, c, installID, image, user, paths)
				if serr != nil {
					return f, fmt.Errorf("ask the image for the installer's runtime %s: %w", prog, serr)
				}
				has = has && slices.Contains(got, true)
			}
			f.ImageHasRuntime = has
		}
	case err != nil:
		return f, fmt.Errorf("ask the image for the tool's loader: %w", err)
	default:
		for _, p := range toolPaths {
			if ok, err := c.ContainerPathStat(pctx, id, p); err == nil && ok {
				f.ImageHasTool = true
				break
			}
		}
		if len(runtime) > 0 {
			has := true
			for _, prog := range runtime {
				one := false
				for _, p := range sandboxoci.ImageToolPaths(prog) {
					if ok, err := c.ContainerPathStat(pctx, id, p); err == nil && ok {
						one = true
						break
					}
				}
				has = has && one
			}
			f.ImageHasRuntime = has
		}
	}
	// A path stat of a container that is gone answers 404, the same as a
	// missing file: the answer counts only if the probe container is still
	// there after it.
	if _, err := c.ContainerInspect(pctx, id); err != nil {
		return f, fmt.Errorf("ask the image for the tool's loader: the probe container went away during the check (%w); the answer is not kept, ask again", err)
	}
	ociABICache.Store(key, ociABIEntry{facts: f, at: ociABINow()})
	return f, nil
}

// ociPathCheckUser is the user the started path check runs as: the
// container's root on a rootless engine (it is the host user there), the
// host uid row on a rootful one, so either way it can read the bound
// observer binary as its owner.
func ociPathCheckUser(res sandboxoci.ProbeResult) string {
	if res.Identity.Mode == sandboxoci.ModeRootless {
		return "0:0"
	}
	return res.User.User
}

// ociStartedPathCheck asks the image whether each path exists by running
// Observer's own binary (bound read-only at its host path) as the probe
// container's only process: `observer sandbox-oci-pathcheck -- <paths>`
// stats them and exits sandboxoci.PathCheckBase plus one bit per path
// found. Nothing of the image runs. The container has no network, no
// capabilities, no new privileges, a read-only root and a small pids
// limit, carries the probe role (the reaper leaves it alone), and is
// removed at once.
func (d *ociDriver) ociStartedPathCheck(ctx context.Context, c *sandboxengine.Client, installID, image, user string, paths []string) ([]bool, error) {
	if len(paths) == 0 || len(paths) > sandboxoci.PathCheckMax {
		return nil, fmt.Errorf("the started path check takes 1 to %d paths", sandboxoci.PathCheckMax)
	}
	bin := d.r.observerBin
	if !filepath.IsAbs(bin) {
		return nil, fmt.Errorf("the observer binary path %q is not absolute", bin)
	}
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	probeRun := "abiprobe" + hex.EncodeToString(raw[:])
	id, _, err := c.ContainerCreate(ctx, sandboxoci.ContainerName(installID, probeRun), map[string]any{
		"Image": image, "User": user,
		"Entrypoint": append([]string{bin, ociPathCheckVerb, "--"}, paths...), "Cmd": []string{},
		"Env":    []string{},
		"Labels": sandboxoci.ProbeLabels(installID, probeRun),
		"HostConfig": map[string]any{
			"NetworkMode": sandboxoci.NetworkNone, "CapDrop": []string{sandboxoci.CapAll}, "CapAdd": []string{},
			"SecurityOpt": []string{sandboxoci.NoNewPrivileges}, "ReadonlyRootfs": true, "Privileged": false,
			"PidsLimit": 16, "Devices": []any{}, "LogConfig": map[string]string{"Type": "none"},
			"RestartPolicy": map[string]string{"Name": "no"},
			"Mounts":        []map[string]any{{"Type": "bind", "Source": bin, "Target": bin, "ReadOnly": true, "BindOptions": map[string]string{"Propagation": "rprivate"}}},
		},
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rcancel()
		_ = c.ContainerRemove(rctx, id)
	}()
	waitCh, err := c.ContainerWait(ctx, id, sandboxoci.WaitCondition)
	if err != nil {
		return nil, err
	}
	if err := c.ContainerStart(ctx, id); err != nil {
		return nil, err
	}
	select {
	case res := <-waitCh:
		if res.Err != nil {
			return nil, res.Err
		}
		return sandboxoci.DecodePathCheckExit(res.StatusCode, len(paths))
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// runOCIPathCheck is `observer sandbox-oci-pathcheck -- <path>...`, the
// started check's process inside the probe container: it only stats.
func runOCIPathCheck(args []string) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 || len(args) > sandboxoci.PathCheckMax {
		// Outside the check's range, so the host reads "did not run".
		return 2
	}
	found := make([]bool, len(args))
	for i, p := range args {
		_, err := os.Stat(p) //nolint:gosec // G703: the started check's own argument, stat only, inside the probe container
		found[i] = err == nil
	}
	return sandboxoci.PathCheckExit(found)
}

// ---- .devcontainer image, behind per-repository consent ---------------------

// devcontainerPath is a repository's devcontainer.json.
func devcontainerPath(repo string) string {
	return filepath.Join(repo, ".devcontainer", "devcontainer.json")
}

// readDevcontainer reads and parses a repository's devcontainer.json
// (no-follow, capped). ok is false when there is none.
func readDevcontainer(repo string) (sandboxoci.Devcontainer, bool, error) {
	p := devcontainerPath(repo)
	fi, err := os.Lstat(p)
	if err != nil {
		return sandboxoci.Devcontainer{}, false, nil
	}
	if !fi.Mode().IsRegular() {
		return sandboxoci.Devcontainer{}, false, fmt.Errorf("%s is not a regular file (a symlink is never followed)", p)
	}
	f, err := os.Open(p) //nolint:gosec // G304: the repository's own devcontainer.json, lstat-checked above
	if err != nil {
		return sandboxoci.Devcontainer{}, false, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, 256<<10+1))
	if err != nil {
		return sandboxoci.Devcontainer{}, false, err
	}
	d, err := sandboxoci.ParseDevcontainer(raw)
	return d, err == nil, err
}

// devcontainerConsentFile records the consents: repository root -> image.
func devcontainerConsentFile(observerDir string) string {
	return filepath.Join(ociStateDir(observerDir), "devcontainer-consent.json")
}

// devcontainerConsents reads the recorded consents.
func devcontainerConsents(observerDir string) map[string]string {
	b, err := readOwnedNoFollow(devcontainerConsentFile(observerDir), 1<<20)
	if err != nil {
		return nil
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

// setDevcontainerConsent records (image != "") or removes (image == "")
// the consent for repo.
func setDevcontainerConsent(observerDir, repo, image string) error {
	m := devcontainerConsents(observerDir)
	if m == nil {
		m = map[string]string{}
	}
	if image == "" {
		delete(m, repo)
	} else {
		m[repo] = image
	}
	return writeOCIStateFile(devcontainerConsentFile(observerDir), m)
}

// runChoice decides the run's image and the repository's extra environment.
// The configured image is the default; a repository's .devcontainer image
// replaces it only when allow_devcontainer_image is on and the user
// consented to exactly that image for exactly this repository. A
// devcontainer the user has not consented to is reported in the note and
// never used.
func (d *ociDriver) runChoice(projectRoot string) (ociRunChoice, string) {
	choice := ociRunChoice{image: d.imageTrust().image}
	if !d.cfg.AllowDevcontainerImage || projectRoot == "" {
		return choice, ""
	}
	dc, ok, err := readDevcontainer(projectRoot)
	switch {
	case err != nil:
		return choice, " devcontainer=unreadable (" + err.Error() + ")"
	case !ok:
		return choice, ""
	case dc.Image == "":
		return choice, " devcontainer=not used (" + dc.ImageRefused + ")"
	}
	if devcontainerConsents(d.r.observerDir)[projectRoot] != dc.Image {
		return choice, " devcontainer=awaiting consent (observer sandbox oci devcontainer accept)"
	}
	return ociRunChoice{image: dc.Image, extraEnv: dc.Env}, " devcontainer=" + dc.Image
}
