//go:build !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_vm_run.go is the microVM driver's lifecycle service
// (sandbox plan v2 section 4.6): Create checks the floors, the probe, the
// verified image set and the workspace mapping (sandbox plan section 6:
// copies are shared by a virtiofsd or, on request, delivered as a
// disk_image; live only through the confined virtiofsd); Attach writes the
// run record and the plan and returns the PTY child's argv:
//
//	observer sandbox-vm-host --plan <file> -- observer sandbox-host <relay
//	and network flags> -- observer-vm-inner <inner>
//
// The plan file holds no secret (the per-run relay secret is minted by
// the helper and handed to the guest on its boot share, removed after the
// handshake).

// The helper verbs the driver registers (sandboxHelperFuncs, from its own
// init: the Apple precedent).
const (
	// vmHostVerb is the per-run host helper: it starts the VMM and the
	// virtiofsd processes, reads the VM back, serves the relay mux over the
	// hybrid vsock socket and tears everything down.
	vmHostVerb = "sandbox-vm-host"
	// vmInitVerb is PID 1 inside the guest.
	vmInitVerb = "sandbox-vm-init"
	// vmInnerMarker separates the host services from the inner launch.
	vmInnerMarker = "observer-vm-inner"
)

// vmHostIDs is the user the agent runs as in the guest (a variable so a
// test running as root can stand in an ordinary user).
var vmHostIDs = func() (int, int) { return os.Getuid(), os.Getgid() }

// vmPlanVersion is the plan file's schema version.
const vmPlanVersion = 1

// vmGuestBin is the verified guest observer's path in the guest (its boot
// share).
const vmGuestBin = "/run/observer-boot/" + sandboxvm.GuestBinaryName

// The guest's two vsock ports.
const (
	vmPTYPort   = sandboxvm.DefaultGuestPort
	vmRelayPort = sandboxvm.DefaultGuestPort + 1
)

// vmShare is one virtio-fs share the helper serves through a virtiofsd.
type vmShare struct {
	Tag string `json:"tag"`
	// Dir is the host directory shared, at the same path in the guest.
	Dir string `json:"dir"`
	// ReadOnly shares the whole directory read-only.
	ReadOnly bool `json:"readonly,omitempty"`
	// Confined runs the virtiofsd inside a bwrap mount namespace that
	// applies the host-enforced git-dir execution paths (live delivery).
	Confined bool `json:"confined,omitempty"`
	// ReadOnlyPaths are binds made read-only inside that namespace; Pins
	// are directories bound onto themselves (a mount point, so the guest
	// cannot rename them aside).
	ReadOnlyPaths []string `json:"readonly_paths,omitempty"`
	Pins          []string `json:"pins,omitempty"`
}

// vmPlanFile is the per-run plan the host helper reads.
type vmPlanFile struct {
	Version int `json:"version"`
	// VM is the VM plan; its StateDir is the run's 0700 dir.
	VM        sandboxvm.Plan `json:"vm"`
	VMM       string         `json:"vmm"`
	Virtiofsd string         `json:"virtiofsd"`
	// Bwrap is the confining bwrap of a live share ("" otherwise).
	Bwrap string `json:"bwrap,omitempty"`
	// Image maps each bulk entry to its verified store path, GuestBinary
	// the verified guest observer and its entry.
	Image       map[string]string `json:"image"`
	GuestBinary string            `json:"guest_binary"`
	GuestSHA256 string            `json:"guest_sha256"`
	GuestSize   int64             `json:"guest_size"`
	Shares      []vmShare         `json:"shares"`
	DiskImages  []vmDiskImage     `json:"disk_images,omitempty"`
	// Mkfs and Debugfs are the e2fsprogs programs of a disk_image run;
	// DumpBwrap is the bwrap the read-back's debugfs runs inside.
	Mkfs          string                   `json:"mkfs,omitempty"`
	Debugfs       string                   `json:"debugfs,omitempty"`
	DumpBwrap     string                   `json:"dump_bwrap,omitempty"`
	Guest         sandboxvm.GuestSpec      `json:"guest"`
	GuestPrefix   []string                 `json:"guest_prefix,omitempty"`
	Dirs          macRunDirs               `json:"dirs"`
	Return        *workspace.ReturnRequest `json:"return,omitempty"`
	ReturnRefused string                   `json:"return_refused,omitempty"`
	ConfigPath    string                   `json:"config_path,omitempty"`
	Notices       []string                 `json:"notices,omitempty"`
}

// vmDiskImage is a disk_image workspace copy: mkfs.ext4 -d of Source into
// the run's state dir, attached as a writable disk.
type vmDiskImage struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Target string `json:"target"`
}

// vmShortSocketRoot is the per-user parent of the short socket dirs, the
// Apple driver's pattern (/private/tmp/obsbx-<uid>) on Linux: /tmp/obvm-
// <uid>, 0700, made by the helper (vmEnsureOwnedDir), refused when it is a
// link or not a private directory this user owns. A variable so a test can
// stand it in.
var vmShortSocketRoot = func() string { return filepath.Join("/tmp", "obvm-"+strconv.Itoa(os.Getuid())) }

// vmPickSocketDir is the run's socket dir: its state dir when every socket
// fits Linux's socket path limit there, else the short per-user dir; when
// neither can hold them the launch is refused by name.
func vmPickSocketDir(stateDir, runID string, tags []string) (string, error) {
	short := filepath.Join(vmShortSocketRoot(), runID)
	var why []string
	for _, c := range []string{stateDir, short} {
		if over := sandboxvm.SocketsTooLong(c, tags); len(over) > 0 {
			why = append(why, c+" is too deep ("+strings.Join(over, ", ")+")")
			continue
		}
		if c != stateDir && !macSocketParentUsable(filepath.Dir(c)) {
			why = append(why, filepath.Dir(c)+" is not a private directory this user owns")
			continue
		}
		return c, nil
	}
	return "", sandboxRefusalError{msg: "terminal_sandbox: cloud-hypervisor: " + sandboxvm.VerdictSocketPathTooLong + ": no directory can hold the run's sockets within the " + strconv.Itoa(sandboxvm.MaxSocketPath) + "-byte socket path limit: " + strings.Join(why, "; ")}
}

// vmHostSocketParents are the parents of a run's host-services socket dir
// (relay.sock and launch.json, which holds the run's box secret), in order:
// obsbx in the user's temp dir, else the per-user obsbx-<uid> beside it
// (the Apple driver's pattern with a Linux path: macOS's /private/tmp does
// not exist here). The helper makes the chosen one owner-only before use
// (vmEnsureSocketParent) and the sweep removes a dead run's dir under
// either.
func vmHostSocketParents() []string {
	base := filepath.Clean(os.TempDir())
	if resolved, err := filepath.EvalSymlinks(base); err == nil {
		base = resolved
	}
	return []string{filepath.Join(base, "obsbx"), filepath.Join(base, "obsbx-"+strconv.Itoa(os.Getuid()))}
}

// vmDirsFor is the run's host-services dirs (macDirsFor over this row's
// parents): the first parent whose relay socket fits and that is usable.
func vmDirsFor(runID string) (macRunDirs, error) {
	parents := vmHostSocketParents()
	parent, err := macPickSocketParent(parents, runID, macSocketParentUsable)
	if err != nil {
		return macRunDirs{}, fmt.Errorf("terminal_sandbox: %w", err)
	}
	return macRunDirs{
		SocketParent: parent,
		SocketDir:    filepath.Join(parent, runID),
		TempDir:      filepath.Join(filepath.Dir(parents[0]), "obsbx-tmp", runID),
	}, nil
}

// vmStateRoot is the driver's node-local directory under the observer dir.
func vmStateRoot(observerDir string) string { return macStateDir(observerDir, vmDriverName) }

// vmRunStateDir is a run's 0700 state dir.
func vmRunStateDir(observerDir, runID string) string {
	return filepath.Join(vmStateRoot(observerDir), "runs", runID)
}

// hostsPlainShell: the guest image set carries a shell and no agent tool,
// so a plain shell is this row's own launch (sandboxShellHost; the first
// live run, D2).
func (d *vmDriver) hostsPlainShell() bool { return true }

// vmToolRunnable is decision 8 as the first live run left it (D2): the
// guest image holds no agent tool and the install cache is owed (milestone
// 7), so a plain shell runs as is, and a tool runs only from a binary the
// launch names with the launcher's own binary-path flag (for example
// `observer claude --claude-path ./agent.sh --observer-sandbox
// cloud-hypervisor`), which vmToolInShare then requires inside the
// workspace the VM shares at the same path. It returns that binary's host
// path, relative to projectRoot when given relative ("" for the shell); a
// launch that names none is refused tool_unavailable_in_image naming the
// flag.
func vmToolRunnable(tool string, cfgInstallCache bool, toolArgs []string, projectRoot string) (string, error) {
	if tool == termsvc.ShellTool {
		return "", nil
	}
	flag := vmToolPathFlag(tool)
	if flag != "" {
		if p := sandboxCLIFlagValue(toolArgs, flag); p != "" {
			if !filepath.IsAbs(p) {
				p = filepath.Join(projectRoot, p)
			}
			return filepath.Clean(p), nil
		}
	}
	cache := "[terminal.sandbox.vm].install_cache is off"
	if cfgInstallCache {
		cache = "[terminal.sandbox.vm].install_cache is accepted but the install path is owed (lane SBX-P4 milestone 7)"
	}
	how := "a binary inside the workspace"
	if flag != "" {
		how = "--" + flag + " <a binary inside the workspace>"
	}
	return "", sandboxRefusalError{msg: fmt.Sprintf("terminal_sandbox: cloud-hypervisor: %s: the guest image set carries no agent tool (D-751 Q38), %s, and this launch names no %s binary the VM can run; name one with %s, or launch a plain shell", sandboxselect.VerdictToolUnavailableInImage, cache, tool, how)}
}

// vmToolPathFlag is tool's launcher binary-path flag ("claude-path" for
// claude-code; "" when its launcher has none).
func vmToolPathFlag(tool string) string {
	c, ok := integration.For(tool)
	if !ok || c.Handoff.Launch == nil || c.Handoff.Launch.Subcommand == "" {
		return ""
	}
	return sandboxCLIBinaryPathFlag(c.Handoff.Launch.Subcommand)
}

// vmToolInShare checks a named tool binary against the prepared workspace:
// the guest sees the share at its host path, so the binary, with every link
// resolved, must be an executable regular file inside it. The source of a
// copy, the host's own tree and a missing file are refused by name.
func vmToolInShare(tool, bin, wsDir string) error {
	if bin == "" {
		return nil
	}
	refuse := func(why string) error {
		return sandboxRefusalError{msg: fmt.Sprintf("terminal_sandbox: cloud-hypervisor: %s: %s's binary %s %s; the guest image set carries no agent tool, so a tool runs only from a binary inside the workspace the VM shares (%s)", sandboxselect.VerdictToolUnavailableInImage, tool, bin, why, wsDir)}
	}
	if !vmWithin(bin, wsDir) {
		return refuse("is not inside the workspace the VM shares")
	}
	real, err := filepath.EvalSymlinks(bin)
	if err != nil {
		return refuse("cannot be read (" + err.Error() + ")")
	}
	wsReal, err := filepath.EvalSymlinks(wsDir)
	if err != nil {
		wsReal = wsDir
	}
	if !vmWithin(real, wsReal) {
		return refuse("resolves to " + real + ", which is not inside the workspace the VM shares")
	}
	fi, err := os.Stat(real)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return refuse("is not an executable file")
	}
	return nil
}

// vmGuestRow is the row as this run sees it: N13's flag only when the
// verified descriptor declares it (the guest's self-test confirms it again
// before the agent starts).
func vmGuestRow(set vmImageSet) sandboxbackend.Capability {
	row := vmRow()
	row.GuestUnprivUserns = set.res.OK && set.res.Descriptor.GuestUserns
	return row
}

// Create checks the floors, the agent's own sandbox, the probe, the image
// set and the tool, then prepares the workspace with the shared step.
func (d *vmDriver) Create(ctx context.Context, req termsvc.PrepareRequest) (termsvc.CreateResult, error) {
	if err := macDriverFloor(vmRow(), launchFloorConfig(d.r.cfg, string(d.r.egress.Mode)), d.r.forceBackend); err != nil {
		return termsvc.CreateResult{}, err
	}
	if res := d.probeResult(); !res.Verdict.OK() {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: cloud-hypervisor is not available: %s", res.Verdict.Error())
	}
	set := d.imageSet()
	if err := vmImageSetError(set); err != nil {
		return termsvc.CreateResult{}, err
	}
	row := vmGuestRow(set)
	tier := vocab.Tier(d.r.egress.Mode)
	var nativeState vocab.NativeSandboxState
	if req.Tool != termsvc.ShellTool {
		if v, judged := sandboxNativeVerdictFor(row, req.Tool, tier); judged {
			if err := sandboxNativeRefusal(req.Tool, v); err != nil {
				return termsvc.CreateResult{}, err
			}
			nativeState = sandboxselect.NativeStateFor(v)
		}
	}
	bin, err := vmToolRunnable(req.Tool, d.cfg.InstallCache, req.ToolArgs, req.ProjectRoot)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	source := strings.TrimSpace(req.WorkspaceSource)
	if source == "" {
		source = string(workspace.SourceLive)
	}
	if src, perr := workspace.ParseSource(source); perr == nil && src == workspace.SourceLive && !vmLiveOK() {
		return termsvc.CreateResult{}, vmLiveRefusal
	}
	ws, err := d.r.prepareWorkspace(ctx, req)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	err = vmMappingFor(ws.src, ws.dir)
	if err == nil {
		err = vmDeliveryFor(ws.src, d.cfg.WorkspaceDelivery)
	}
	if err == nil {
		err = vmToolInShare(req.Tool, bin, ws.dir)
	}
	if err != nil {
		_, _ = d.r.destroyBwrap(termsvc.SandboxRun{ID: ws.id, Tool: req.Tool, Dir: ws.dir, ProjectRoot: req.ProjectRoot, Copy: !ws.live})
		return termsvc.CreateResult{}, err
	}
	d.sources.Store(ws.id, ws.src)
	routed, _ := d.r.launchRouted(req.Tool, ws.dir, req.ToolArgs)
	note := fmt.Sprintf("sandbox: backend=cloud-hypervisor (beta) image_set=%s source=%s workspace=%s egress=%s", set.res.Descriptor.Version, ws.src, ws.dir, d.r.egress.Mode)
	if set.res.Stale {
		note += " (the image set's manifest has expired; booting the last-known-good set)"
	}
	return termsvc.CreateResult{
		Run:         termsvc.SandboxRun{ID: ws.id, Tool: req.Tool, Dir: ws.dir, ProjectRoot: req.ProjectRoot, Copy: !ws.live},
		Note:        note,
		Isolation:   macIsolation(row, tier, routed, nativeState, d.r.cfg.EffectiveProviderDirect()),
		ProxyRouted: routed,
	}, nil
}

// imageSet loads the verified set (no cache: every launch re-hashes).
func (d *vmDriver) imageSet() vmImageSet {
	return loadVMImageSet(vmContentStore(d.r.observerDir), contentchan.Trust{VendorKeys: sandboxContentVendorKeys()}, d.cfg.ImageSet, version)
}

// vmMappingFor is the workspace mapping table (sandbox plan section 6) for
// this lane's rows: a copy is shared by a virtiofsd; live is refused until
// the confined virtiofsd's read-back passes on this host (vmLiveOK); every
// share's target is the host path, which must lie under a writable guest
// root.
func vmMappingFor(src workspace.Source, dir string) error {
	if src == workspace.SourceLive && !vmLiveOK() {
		return vmLiveRefusal
	}
	if !vmUnderGuestRoot(dir) {
		return sandboxRefusalError{msg: fmt.Sprintf("terminal_sandbox: cloud-hypervisor: %s: the workspace %s is not under one of the guest's writable roots (%s), so it cannot keep its path in the VM", sandboxselect.VerdictSourceUnsupported, dir, strings.Join(sandboxvm.GuestWritableRoots, ", "))}
	}
	return nil
}

// vmDiskProgs are the programs a disk_image delivery runs (no root
// needed): e2fsprogs, and the bwrap the read-back runs inside.
type vmDiskProgs struct {
	mkfs, debugfs, bwrap string
}

// vmDiskTools looks the disk_image programs up on PATH and in the sbin
// dirs; a variable so a test can stand the host in. Without bwrap the
// delivery is refused by name: debugfs never parses a guest-written image
// unconfined (SBX-BE-5).
var vmDiskTools = func() (vmDiskProgs, error) {
	var p vmDiskProgs
	var err error
	if p.mkfs, err = vmLookProgramFor("mkfs.ext4"); err != nil {
		return vmDiskProgs{}, fmt.Errorf("mkfs.ext4 (e2fsprogs 1.43 or later) is not installed")
	}
	if p.debugfs, err = vmLookProgramFor("debugfs"); err != nil {
		return vmDiskProgs{}, fmt.Errorf("debugfs (e2fsprogs) is not installed")
	}
	if p.bwrap, err = vmLookProgramFor("bwrap"); err != nil {
		return vmDiskProgs{}, fmt.Errorf("bwrap (bubblewrap) is not installed, and the image the guest wrote is read back only inside a bwrap namespace")
	}
	return p, nil
}

// vmDeliveryFor applies the mapping table to a source and the configured
// delivery; disk_image also needs its two programs.
func vmDeliveryFor(src workspace.Source, delivery string) error {
	row := sandboxvm.Mapping(string(src), delivery)
	if !row.OK {
		return sandboxRefusalError{msg: "terminal_sandbox: cloud-hypervisor: " + sandboxselect.VerdictSourceUnsupported + ": " + row.Why}
	}
	if row.Delivery == sandboxvm.DeliveryDiskImage {
		if _, err := vmDiskTools(); err != nil {
			return sandboxRefusalError{msg: "terminal_sandbox: cloud-hypervisor: " + sandboxselect.VerdictSourceUnsupported + ": the disk_image delivery needs " + err.Error() + "; set [terminal.sandbox.vm].workspace_delivery = \"virtiofs\""}
		}
	}
	return nil
}

// vmLiveRefusal is a live workspace on a host that cannot confine its
// virtiofsd.
var vmLiveRefusal = sandboxRefusalError{msg: "terminal_sandbox: cloud-hypervisor: " + sandboxselect.VerdictSourceUnsupported + ": a live workspace is shared only through a virtiofsd confined in a bwrap mount namespace that enforces the git-dir execution paths on the host, and that needs /usr/bin/bwrap and /usr/libexec/virtiofsd (the AppArmor user-namespace profile allows only those paths); use clone-local, clone-remote or worktree"}

// vmUnderGuestRoot reports whether p lies strictly inside a writable guest
// root.
func vmUnderGuestRoot(p string) bool {
	for _, r := range sandboxvm.GuestWritableRoots {
		if strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// Attach writes the run record and the plan file and returns the argv.
func (d *vmDriver) Attach(_ context.Context, created termsvc.CreateResult) (termsvc.AttachResult, error) {
	res := d.probeResult()
	if !res.Verdict.OK() {
		return termsvc.AttachResult{}, fmt.Errorf("terminal_sandbox: cloud-hypervisor is not available: %s", res.Verdict.Error())
	}
	set := d.imageSet()
	if err := vmImageSetError(set); err != nil {
		return termsvc.AttachResult{}, err
	}
	if err := d.r.writeRunRecord(created.Run); err != nil {
		return termsvc.AttachResult{}, err
	}
	wrap, err := d.compose(created, res, set)
	if err != nil {
		_ = sandboxrelayd.RemoveRun(d.r.observerDir, created.Run.ID)
		return termsvc.AttachResult{}, err
	}
	d.r.unattached.Delete(created.Run.ID)
	return termsvc.AttachResult{WrapArgv: wrap}, nil
}

// compose builds the VM plan, the guest spec and the host services' argv.
func (d *vmDriver) compose(created termsvc.CreateResult, res sandboxvm.ProbeResult, set vmImageSet) ([]string, error) {
	r := d.r
	run := created.Run
	dirs, err := vmDirsFor(run.ID)
	if err != nil {
		return nil, err
	}
	tier := vocab.Tier(r.egress.Mode)
	netReq := sandbox.NetRequest{Egress: r.egress.Mode, ProxyPort: r.proxyPort, EgressAllowCIDRs: r.cfg.EgressAllowCIDRs, HostSocketDir: dirs.SocketDir}
	if capture := sandboxRunCaptureFor(vmRow(), created.ProxyRouted, tier, r.cfg.EffectiveProviderDirect()); capture.ProviderBlock {
		netReq.ProviderBlock, netReq.ProviderHosts = true, r.providerHosts
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	var spec integration.SandboxSpec
	if run.Tool != termsvc.ShellTool {
		if spec, err = macToolSpec(run.Tool); err != nil {
			return nil, err
		}
	}
	overlays, pins, err := r.protection(home, run.Dir, spec)
	if err != nil {
		return nil, err
	}
	share := vmWorkspaceShare(run, overlays, pins)
	src, _ := d.sources.LoadAndDelete(run.ID)
	srcv, _ := src.(workspace.Source)
	disk := run.Copy && sandboxvm.Mapping(string(srcv), d.cfg.WorkspaceDelivery).Delivery == sandboxvm.DeliveryDiskImage
	var placeholders []sandbox.Overlay
	if share.Confined {
		placeholders = vmPlaceholders(overlays, run.Dir)
	}
	host, err := sandbox.RelayHostArgv(r.observerBin, netReq, placeholders, sandbox.RelayRequest{RunID: run.ID, HostObserverDir: r.observerDir})
	if err != nil {
		return nil, err
	}
	guest, err := sandbox.GuestArgv(vmGuestBin, netReq)
	if err != nil {
		return nil, err
	}
	stateDir := vmRunStateDir(r.observerDir, run.ID)
	sockDir, err := vmPickSocketDir(stateDir, run.ID, []string{sandboxvm.BootTag, sandboxvm.WorkspaceTag})
	if err != nil {
		return nil, err
	}
	img := filepath.Join(stateDir, "img")
	vm := sandboxvm.Plan{
		RunID: run.ID, StateDir: stateDir,
		Kernel: filepath.Join(img, sandboximage.VMKernelName), Initramfs: filepath.Join(img, sandboximage.VMInitramfsName),
		Rootfs: filepath.Join(img, sandboximage.VMRootfsName), Verity: filepath.Join(img, sandboximage.VMVerityName),
		VerityRootHash: set.res.Descriptor.VerityRootHash, CID: sandboxvm.GuestCIDMin, GuestPort: vmPTYPort,
		VCPUs: vmOr(d.cfg.VCPUs, 2), MemoryMiB: vmOr(d.cfg.MemoryMB, 4096),
	}
	if sockDir != stateDir {
		vm.SocketDir = sockDir
	}
	vm.Shares = []sandboxvm.Share{{Tag: sandboxvm.BootTag, Socket: vm.ShareSocket(sandboxvm.BootTag)}}
	var shares []vmShare
	var diskImages []vmDiskImage
	var progs vmDiskProgs
	if disk {
		if progs, err = vmDiskTools(); err != nil {
			return nil, fmt.Errorf("terminal_sandbox: cloud-hypervisor: %s: the disk_image delivery needs %w", sandboxselect.VerdictSourceUnsupported, err)
		}
		vm.Disks = []sandboxvm.Disk{{Name: sandboxvm.WorkspaceTag, Path: filepath.Join(stateDir, "ws.img")}}
		diskImages = []vmDiskImage{{Name: sandboxvm.WorkspaceTag, Source: run.Dir, Target: run.Dir}}
	} else {
		vm.Shares = append(vm.Shares, sandboxvm.Share{Tag: share.Tag, Socket: vm.ShareSocket(share.Tag)})
		shares = []vmShare{share}
	}
	if _, err := sandboxvm.CreateBody(vm); err != nil {
		return nil, fmt.Errorf("terminal_sandbox: cloud-hypervisor: %w", err)
	}
	uid, gid := vmHostIDs()
	if uid < 1 || gid < 1 {
		return nil, fmt.Errorf("terminal_sandbox: cloud-hypervisor: the daemon runs as root; the agent in the VM runs as the daemon's own user, never as root, so run the daemon as your own user")
	}
	gspec := sandboxvm.GuestSpec{
		Schema: sandboxvm.GuestSpecSchema, RunID: run.ID, UID: uid, GID: gid,
		HostBin: r.observerBin, HookBin: sandboxvm.GuestHookBinFor(r.observerBin), Workdir: run.Dir,
		PTYPort: vmPTYPort, RelayPort: vmRelayPort, Rows: 24, Cols: 80,
		WantUserns: set.res.Descriptor.GuestUserns,
		// A stand-in command: the helper puts the guest prefix and the
		// inner launch here.
		Command: []string{vmGuestBin},
	}
	// A disk_image run's workspace is the guest's disk only: no virtiofsd
	// serves it, so the guest spec names no share for it (the first live
	// run's guest mount of the missing share gave EINVAL, D7).
	if disk {
		gspec.Disks = []sandboxvm.GuestDisk{{Name: sandboxvm.WorkspaceTag, Target: run.Dir}}
	} else {
		gspec.Mounts = []sandboxvm.GuestMount{{Tag: share.Tag, Target: share.Dir}}
		gspec.ReadOnly = share.ReadOnlyPaths
	}
	if err := gspec.Validate(); err != nil {
		return nil, fmt.Errorf("terminal_sandbox: cloud-hypervisor: %w", err)
	}
	ret, returnRefused := vmReturnFor(r.managedRoot, run, srcv)
	plan := vmPlanFile{
		Version: vmPlanVersion, VM: vm, VMM: res.VMM, Virtiofsd: res.Virtiofsd,
		Image: set.paths, GuestBinary: set.guest, GuestSHA256: set.guestEntry.SHA256, GuestSize: set.guestEntry.SizeBytes,
		Shares: shares, DiskImages: diskImages, Mkfs: progs.mkfs, Debugfs: progs.debugfs, DumpBwrap: progs.bwrap, Guest: gspec, GuestPrefix: guest, Dirs: dirs,
		Return: ret, ReturnRefused: returnRefused, ConfigPath: vmPlanConfigPath(),
	}
	if share.Confined {
		plan.Bwrap = vmConfinedBwrap
	}
	if set.res.Stale {
		plan.Notices = append(plan.Notices, "the guest image set's manifest has expired; this run boots the last-known-good set "+set.res.Descriptor.Version)
	}
	if returnRefused != "" {
		plan.Notices = append(plan.Notices, returnRefused)
	}
	planPath, err := writeMacPlan(r.observerDir, vmDriverName, run.ID, plan)
	if err != nil {
		return nil, err
	}
	wrap := []string{r.observerBin, vmHostVerb, "--plan", planPath, "--"}
	wrap = append(wrap, host...)
	return append(wrap, vmInnerMarker), nil
}

func vmOr(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// vmConfinedBwrap is the only bwrap a confined virtiofsd runs under: the
// AppArmor user-namespace profile allows bwrap//&unpriv_bwrap//&virtiofsd
// only for /usr/bin/bwrap and /usr/libexec/virtiofsd (EM spike).
const vmConfinedBwrap = "/usr/bin/bwrap"

// vmConfinedVirtiofsd is the virtiofsd path the profile names.
const vmConfinedVirtiofsd = "/usr/libexec/virtiofsd"

// vmLiveOK reports whether this host can confine a live workspace's
// virtiofsd (a variable so a test can stand the host in).
var vmLiveOK = func() bool {
	for _, p := range []string{vmConfinedBwrap, vmConfinedVirtiofsd} {
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return false
		}
	}
	return true
}

// vmWorkspaceShare is the run's workspace share: a copy shared whole (its
// return is scanned before any host git, D4); a live workspace through the
// confined virtiofsd, with the protect table's read-only overlays inside
// the workspace and the git-dir pins (sandboxRuntime.protection) applied
// in the virtiofsd's own mount namespace.
func vmWorkspaceShare(run termsvc.SandboxRun, overlays []sandbox.Overlay, pins []string) vmShare {
	s := vmShare{Tag: sandboxvm.WorkspaceTag, Dir: run.Dir}
	if run.Copy {
		return s
	}
	s.Confined = true
	for _, o := range overlays {
		if o.Kind == sandbox.OverlayReadOnly && vmWithin(o.Path, run.Dir) {
			s.ReadOnlyPaths = append(s.ReadOnlyPaths, o.Path)
		}
	}
	mounts := []sandbox.PinMount{{Target: run.Dir, Writable: true}}
	for _, p := range pins {
		if vmWithin(p, run.Dir) && sandbox.PinWritable(p, mounts) {
			s.Pins = append(s.Pins, p)
		}
	}
	return s
}

// vmPlaceholders are the read-only overlays inside the workspace that need
// a placeholder made first (the helper records them in its ledger).
func vmPlaceholders(overlays []sandbox.Overlay, dir string) []sandbox.Overlay {
	var out []sandbox.Overlay
	for _, o := range overlays {
		if o.Kind == sandbox.OverlayReadOnly && o.Placeholder != sandbox.PlaceholderNone && vmWithin(o.Path, dir) {
			out = append(out, o)
		}
	}
	return out
}

// vmReturnFor plans a copy's return (the oci-runc rule): clone-local into
// the source repository, clone-remote into its bare return repository with
// the commit the host cloned as the base; worktree and live return nothing
// (a worktree's commits are already in the repository). A refusal is said
// on the run's terminal and kept in the plan, never a silent nil.
func vmReturnFor(managedRoot string, run termsvc.SandboxRun, src workspace.Source) (*workspace.ReturnRequest, string) {
	if !run.Copy {
		return nil, ""
	}
	switch src {
	case workspace.SourceCloneLocal:
		if run.ProjectRoot == "" {
			return nil, ""
		}
		rr := workspace.ReturnRequest{SourceRepo: run.ProjectRoot, CopyDir: run.Dir, ManagedRoot: managedRoot, RunID: run.ID}
		if _, err := workspace.PlanReturn(rr); err != nil {
			return nil, "the box's commits will not be returned from this copy: " + err.Error() + "; the copy is kept at " + run.Dir
		}
		return &rr, ""
	case workspace.SourceCloneRemote:
		rr, err := vmCloneRemoteReturn(managedRoot, run)
		if err != nil {
			return nil, "the box's commits will not be returned from this clone-remote copy: " + err.Error() + "; the copy is kept at " + run.Dir
		}
		return rr, ""
	}
	return nil, ""
}

// vmCloneRemoteReturn is a clone-remote run's return request (the oci-runc
// driver's ociCloneRemoteReturn, which this driver cannot link when that
// driver is omitted).
func vmCloneRemoteReturn(managedRoot string, run termsvc.SandboxRun) (*workspace.ReturnRequest, error) {
	repo, err := workspace.ReturnRepoPath(managedRoot, run.ID)
	if err != nil {
		return nil, err
	}
	rr := workspace.ReturnRequest{SourceRepo: repo, CopyDir: run.Dir, ManagedRoot: managedRoot, RunID: run.ID, Bare: true}
	plan, err := workspace.PlanReturn(rr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := runReturnGit(ctx, plan.CopyHead())
	if err != nil {
		return nil, fmt.Errorf("read the clone's HEAD: %w", err)
	}
	sha, err := workspace.ParseHead(out)
	if err != nil {
		return nil, err
	}
	rr.BaseCommit = sha
	if _, err := workspace.PlanReturn(rr); err != nil {
		return nil, err
	}
	return &rr, nil
}

// vmPlanConfigPath is the daemon's config path for the return step's scan
// ("" when unknown).
func vmPlanConfigPath() string {
	if p := daemonConfigPathSetting.Load(); p != nil {
		return *p
	}
	return ""
}

// Resize is carried by the guest helper on the relay mux's PTY stream.
func (d *vmDriver) Resize(context.Context, termsvc.SandboxRun, uint16, uint16) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "cloud-hypervisor: the host helper forwards the PTY's size to the guest helper over vsock"}, nil
}

// Signal is owned by the PTY: Ctrl-C reaches the guest helper's PTY.
func (d *vmDriver) Signal(context.Context, termsvc.SandboxRun, string) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "cloud-hypervisor: signals reach the agent through the guest PTY"}, nil
}

// Copy is not offered.
func (d *vmDriver) Copy(context.Context, termsvc.CopyRequest) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "cloud-hypervisor: the workspace is shared from the host; copy on the host"}, nil
}

// Checkpoint is not offered (the snapshot warm pool is later, SBX-BE-7).
func (d *vmDriver) Checkpoint(context.Context, termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "cloud-hypervisor: no checkpoint; the agent's native resume applies"}, nil
}

// Stop is owned by the PTY: closing the terminal ends the host helper,
// which tears the VM down.
func (d *vmDriver) Stop(context.Context, termsvc.SandboxRun, time.Duration) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "cloud-hypervisor: closing the terminal ends and removes the VM"}, nil
}

// Destroy releases a run that never started.
func (d *vmDriver) Destroy(_ context.Context, run termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	_ = removeMacPlan(d.r.observerDir, vmDriverName, run.ID)
	return d.r.destroyBwrap(run)
}

// vmWithin reports whether p is root or inside it.
func vmWithin(p, root string) bool {
	p, root = filepath.Clean(p), filepath.Clean(root)
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}
