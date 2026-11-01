//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// terminal_sandbox_oci_install_linux.go is the host helper's half of the
// first-start install (lane SBX-P3C, plan 5.4): it asks on the run's own
// terminal, creates the cache volume over an owner-only host directory,
// serves the install gateway (the tool's install hosts only, G23), creates
// the setup container (read back against its plan like the agent's), shows
// its output, waits, removes it, and records the cache as complete only
// after the install exited 0. A refused or failed install removes the volume
// and its directory, and the agent's container is never created.

// ociInstallTimeout bounds one setup container.
var ociInstallTimeout = 15 * time.Minute

// ociInstallAnswerTimeout bounds the wait for the user's answer; no answer
// refuses (a launch nobody watches never installs).
var ociInstallAnswerTimeout = 5 * time.Minute

// ociInstall runs the plan's install step, or skips it when a completed
// cache for it appeared since the launch was planned and the engine still
// has its volume. With no install step, the plan's cache volumes must still
// be on the engine (ociCheckCacheVolumes).
func ociInstall(ctx context.Context, c *sandboxengine.Client, id sandboxoci.Identity, plan ociPlanFile, t ociTerm) error {
	step := plan.Install
	observerDir := plan.Create.ObserverDir
	if step == nil {
		return ociCheckCacheVolumes(ctx, c, plan)
	}
	if _, ok := ociCacheRecords(observerDir)[step.Volume]; ok {
		present, err := ociVolumePresent(ctx, c, step.Volume)
		if err != nil {
			return fmt.Errorf("list the tool cache volume %s: %w", step.Volume, err)
		}
		if present {
			return nil
		}
		// Recorded complete, but the engine no longer has it (removed
		// outside Observer, audit finding 4): the record is forgotten and
		// the install runs again only after the user's yes, so the engine
		// never makes an empty volume of that name for the agent.
		_ = setOCICacheRecord(observerDir, step.Volume, nil)
		fmt.Fprintf(t.out, "observer sandbox: the tool cache %s was recorded complete but the engine no longer has it; it is installed again only after you say yes\r\n", step.Volume)
	}
	if !ociAskInstall(t, step) {
		return errors.New("install_not_consented: the first-start install was not accepted; nothing was downloaded")
	}
	dir := ociCacheDir(observerDir, step.Volume)
	if err := ociRemoveCacheDir(observerDir, step.Volume); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("create the cache directory: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = c.VolumeRemove(rctx, step.Volume)
			_ = ociRemoveCacheDir(observerDir, step.Volume)
		}
	}()
	vctx, vcancel := context.WithTimeout(ctx, 30*time.Second)
	err := c.VolumeCreate(vctx, step.Volume,
		sandboxoci.CacheLabels(plan.Create.InstallID, step.Image, step.Tool, step.Version, step.Package),
		map[string]string{"type": "none", "o": "bind", "device": dir})
	vcancel()
	if err != nil {
		return fmt.Errorf("create the cache volume: %w", err)
	}
	stopGW, sockDir, err := ociStartInstallGateway(step, t)
	if err != nil {
		return err
	}
	defer stopGW()
	ip := sandboxoci.InstallCreatePlan{
		RunID: plan.Create.RunID, InstallID: plan.Create.InstallID, Image: plan.Create.Image,
		EntrypointPrefix: []string{
			ociInstallObserverBin(plan), ociInstallVerb,
			"--gateway", sandbox.GuestSocketDir + "/" + sandbox.GatewaySocketName,
			"--port", strconv.Itoa(sandboxoci.InstallProxyPort), "--",
		},
		ObserverBin: ociInstallObserverBin(plan), SockDir: sockDir, GuestSockDir: sandbox.GuestSocketDir,
		Volume: step.Volume, Source: sandboxoci.InstallSource{Kind: step.Kind, Package: step.Package, Bin: step.Bin, Hosts: step.Hosts, NeedsScripts: step.NeedsScripts, ScriptSHA256: step.ScriptSHA256, ScriptPackages: step.ScriptPackages},
		Version: step.Version, User: plan.Create.User, Engine: id.Engine, Runtime: plan.Create.Runtime,
		EngineSocket: plan.Create.EngineSocket, ObserverDir: observerDir,
	}
	code, err := ociRunSetupContainer(ctx, c, id, ip, t)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("the install exited with status %d; the cache was removed", code)
	}
	if err := setOCICacheRecord(observerDir, step.Volume, &ociCacheRecord{
		Tool: step.Tool, Version: step.Version, Image: step.Image, Package: step.Package, CompletedAt: time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("record the cache: %w", err)
	}
	ok = true
	for _, old := range step.Others {
		rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		rerr := c.VolumeRemove(rctx, old)
		cancel()
		if rerr != nil {
			fmt.Fprintf(t.out, "observer sandbox: the stale cache %s was kept: %v\r\n", old, rerr)
			continue
		}
		_ = setOCICacheRecord(observerDir, old, nil)
		_ = ociRemoveCacheDir(observerDir, old)
	}
	fmt.Fprintf(t.out, "observer sandbox: %s@%s installed into %s\r\n", step.Package, step.Version, step.Volume)
	return nil
}

// ociVolumePresent reports whether the engine lists the volume name (the
// name filter is a substring match, so the answer is compared exactly).
func ociVolumePresent(ctx context.Context, c *sandboxengine.Client, name string) (bool, error) {
	lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	vols, err := c.VolumeList(lctx, map[string][]string{"name": {name}})
	if err != nil {
		return false, err
	}
	for _, v := range vols {
		if v.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// ociCheckCacheVolumes refuses, naming it, a plan whose tool cache volume
// the engine no longer has (lane SBX-P3C audit finding 4): creating the
// agent's container would make the engine create an empty volume of that
// name, and the tool would be missing in the box. The stale record is
// forgotten, so the next launch plans the install again (and asks).
func ociCheckCacheVolumes(ctx context.Context, c *sandboxengine.Client, plan ociPlanFile) error {
	for _, v := range plan.Create.Volumes {
		present, err := ociVolumePresent(ctx, c, v.Name)
		if err != nil {
			return fmt.Errorf("list the tool cache volume %s: %w", v.Name, err)
		}
		if !present {
			_ = setOCICacheRecord(plan.Create.ObserverDir, v.Name, nil)
			return fmt.Errorf("the tool cache volume %s is no longer on the engine (removed outside Observer); nothing was created, and the next launch installs it again after asking", v.Name)
		}
	}
	return nil
}

// ociInstallObserverBin is the observer binary the agent's plan binds (the
// entrypoint's first word).
func ociInstallObserverBin(plan ociPlanFile) string {
	if len(plan.Create.Entrypoint) > 0 {
		return plan.Create.Entrypoint[0]
	}
	return ""
}

// ociAskInstall shows the install line and reads a yes on the terminal (the
// run's own PTY: the dashboard's terminal and the CLI's both show it). A
// terminal that cannot answer, no answer in time, or anything but y or yes
// is a no.
func ociAskInstall(t ociTerm, step *ociInstallStep) bool {
	fmt.Fprintf(t.out, "observer sandbox: %s\r\n", step.Line)
	if step.DocURL != "" {
		fmt.Fprintf(t.out, "observer sandbox: install source documented at %s\r\n", step.DocURL)
	}
	if t.interactive == nil || !t.interactive() {
		fmt.Fprintf(t.out, "observer sandbox: this launch has no terminal to answer on, so nothing is installed\r\n")
		return false
	}
	fmt.Fprintf(t.out, "Install it now? [y/N] ")
	answer := make(chan string, 1)
	go func() { answer <- ociReadLine(t.in) }()
	select {
	case a := <-answer:
		a = strings.ToLower(strings.TrimSpace(a))
		return a == "y" || a == "yes"
	case <-time.After(ociInstallAnswerTimeout):
		fmt.Fprintf(t.out, "\r\nobserver sandbox: no answer, nothing is installed\r\n")
		return false
	}
}

// ociReadLine reads one line byte by byte (no read-ahead, so nothing meant
// for the agent is consumed), capped at 64 bytes.
func ociReadLine(r io.Reader) string {
	var b []byte
	one := make([]byte, 1)
	for len(b) < 64 {
		n, err := r.Read(one)
		if n == 1 {
			if one[0] == '\n' || one[0] == '\r' {
				break
			}
			b = append(b, one[0])
		}
		if err != nil {
			break
		}
	}
	return string(b)
}

// ociStartInstallGateway serves the install gateway on an owner-only socket
// directory: only the step's hosts (sandboxnet.HostRules), no private
// destination, refusals as one plain line on the terminal.
func ociStartInstallGateway(step *ociInstallStep, t ociTerm) (func(), string, error) {
	rules, err := sandboxnet.ParseHostRules(step.Hosts)
	if err != nil {
		return func() {}, "", err
	}
	dir, err := os.MkdirTemp("", "observer-sbx-inst-")
	if err != nil {
		return func() {}, "", err
	}
	ln, err := net.Listen("unix", filepath.Join(dir, sandbox.GatewaySocketName))
	if err != nil {
		_ = os.RemoveAll(dir)
		return func() {}, "", fmt.Errorf("listen for the install gateway: %w", err)
	}
	srv := &http.Server{
		Handler:           &sandboxnet.Gateway{Hosts: rules, Logger: ociInstallGatewayLogger(t)},
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return func() {
		_ = srv.Close()
		_ = os.RemoveAll(dir)
	}, dir, nil
}

// ociInstallGatewayLogger keeps the gateway's log off the screen: one plain
// line per refused host (P-111).
func ociInstallGatewayLogger(t ociTerm) *slog.Logger {
	return sandboxnet.RefusalLogger(nil, t.out)
}

// ociRunSetupContainer creates the setup container, reads it back, attaches
// its output, waits and returns its exit status; the container is removed
// whatever happened.
func ociRunSetupContainer(ctx context.Context, c *sandboxengine.Client, id sandboxoci.Identity, ip sandboxoci.InstallCreatePlan, t ociTerm) (int, error) {
	name, body, err := sandboxoci.BuildInstallCreate(ip)
	if err != nil {
		return 0, err
	}
	ictx, cancel := context.WithTimeout(ctx, ociInstallTimeout)
	defer cancel()
	cctx, ccancel := context.WithTimeout(ictx, 60*time.Second)
	cid, _, err := c.ContainerCreate(cctx, name, body)
	ccancel()
	if err != nil {
		ociRemoveByName(c, name)
		return 0, fmt.Errorf("create the setup container: %w", err)
	}
	run := &ociRun{c: c, id: cid, engine: id.Engine, term: t}
	defer run.remove()
	if v := run.readBack(ictx, id, sandboxoci.InstallReadBackPlan(ip)); !v.OK() {
		return 0, fmt.Errorf("the setup container: %s", v.Error())
	}
	stream, err := c.ContainerAttach(ictx, cid)
	if err != nil {
		return 0, fmt.Errorf("attach to the setup container: %w", err)
	}
	defer func() { _ = stream.Close() }()
	wait, err := c.ContainerWait(ictx, cid, sandboxoci.WaitCondition)
	if err != nil {
		return 0, fmt.Errorf("open the setup container's wait: %w", err)
	}
	if err := c.ContainerStart(ictx, cid); err != nil {
		return 0, fmt.Errorf("start the setup container: %w", err)
	}
	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(ociNoNUL{w: t.out}, stream)
		close(copied)
	}()
	select {
	case res := <-wait:
		select {
		case <-copied:
		case <-time.After(500 * time.Millisecond):
		}
		if res.Err != nil {
			return 0, fmt.Errorf("the setup container: %w", res.Err)
		}
		return res.StatusCode, nil
	case <-ictx.Done():
		return 0, fmt.Errorf("the install did not finish within %s", ociInstallTimeout)
	}
}

// runOCIInstallGuest is `observer sandbox-oci-install --gateway <sock>
// --port <n> [--run-scripts <pkgdir> --script-sha <hex>...] -- <installer
// argv>`, the setup container's process: it serves 127.0.0.1:<n> as a
// forward to the install gateway's socket, runs the installer with the
// container's environment, and then, only when --run-scripts names the
// installed package, runs that package's own lifecycle scripts whose file
// hash is one of the --script-sha values (sandboxoci.PlanPackageScripts,
// lane LEFT-SBX, ruling P-136), each as `node <file>` in the package
// directory with the same environment, so under the same gateway. Before
// any script, every artifact the install fetched is checked against the
// --package-integrity pins (ruling P-142, ociGuestCheckPackages). It exits
// with the first failing status; a script no pin names, or a fetched
// package no integrity pin covers, exits 3 with the mismatch named, having
// run nothing.
func runOCIInstallGuest(args []string) int {
	ga, err := parseOCIInstallArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer %s: %v\n", ociInstallVerb, err)
		return 2
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ga.port)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer %s: listen: %v\n", ociInstallVerb, err)
		return 2
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = sandboxnet.ServeForward(ctx, ln, func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", ga.sock)
		})
	}()
	if code := ociGuestRun(ga.argv, ""); code != 0 {
		return code
	}
	if ga.pkgDir == "" {
		return 0
	}
	if err := ociGuestCheckPackages(ga.pkgDir, ga.packages); err != nil {
		fmt.Fprintf(os.Stderr, "observer %s: %v\n", ociInstallVerb, err)
		return 3
	}
	steps, err := ociGuestPlanScripts(ga.pkgDir, ga.shas)
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer %s: %v\n", ociInstallVerb, err)
		return 3
	}
	for _, st := range steps {
		fmt.Fprintf(os.Stdout, "observer %s: running the package's %s script %s (sha256 %s, pinned)\n", ociInstallVerb, st.Lifecycle, st.File, st.SHA256)
		if code := ociGuestRun(st.Argv(), ga.pkgDir); code != 0 {
			return code
		}
	}
	return 0
}

// ociGuestRun runs argv (in dir when set) with the container's environment
// and returns its exit status.
func ociGuestRun(argv []string, dir string) int {
	//nolint:gosec // G204: the installer argv the host helper planned from the registry's install source table, or a pinned package script
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, os.Stdout, os.Stderr
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "observer %s: %v\n", ociInstallVerb, err)
		return 2
	}
	return 0
}

// ociGuestScriptMaxBytes caps a package.json or script file the guest reads.
const ociGuestScriptMaxBytes = 4 << 20

// ociGuestPlanScripts reads the installed package's package.json and its
// lifecycle script files under pkgDir (no link followed at the last
// component or in the package dir itself, regular files only, capped) and
// checks them against the accepted hashes.
func ociGuestPlanScripts(pkgDir string, shas []string) ([]sandboxoci.ScriptStep, error) {
	if fi, err := os.Lstat(pkgDir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("%s: the installed package directory %s is missing or not a directory", sandboxoci.VerdictInstallScriptMismatch, pkgDir)
	}
	read := func(rel string) ([]byte, error) {
		return ociGuestReadRegular(filepath.Join(pkgDir, filepath.FromSlash(rel)), pkgDir)
	}
	pj, err := read("package.json")
	if err != nil {
		return nil, fmt.Errorf("%s: read package.json: %w", sandboxoci.VerdictInstallScriptMismatch, err)
	}
	has := func(rel string) bool {
		_, err := os.Lstat(filepath.Join(pkgDir, filepath.FromSlash(rel))) //nolint:gosec // G703: a metadata read inside the package dir Observer unpacked
		return err == nil
	}
	return sandboxoci.PlanPackageScripts(pj, shas, read, has)
}

// ociGuestCheckPackages checks every artifact the installer fetched against
// the integrity pins (ruling P-142): the installed package, its required
// dependencies and the optional ones npm placed, each by name and version
// against a pin, and the setup container's own fresh npm cache must hold a
// file with the pin's sha512. No pins: nothing to check.
func ociGuestCheckPackages(pkgDir string, pins []sandboxoci.PackagePin) error {
	if len(pins) == 0 {
		return nil
	}
	pj, err := ociGuestReadRegular(filepath.Join(pkgDir, "package.json"), pkgDir)
	if err != nil {
		return fmt.Errorf("%s: read package.json: %w", sandboxoci.VerdictInstallPackageUnpinned, err)
	}
	f, err := sandboxoci.ParsePackageFacts(pj)
	if err != nil {
		return err
	}
	// npm's global layout nests a package's dependencies under its own
	// node_modules; a hoisted one sits beside it under the prefix's
	// node_modules.
	roots := []string{filepath.Join(pkgDir, "node_modules")}
	if top, ok := strings.CutSuffix(pkgDir, string(filepath.Separator)+filepath.FromSlash(f.Name)); ok && f.Name != "" {
		roots = append(roots, top)
	}
	f.Installed = func(name string) (string, bool, error) {
		for _, root := range roots {
			dir := filepath.Join(root, filepath.FromSlash(name))
			fi, err := os.Lstat(dir)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return "", false, err
			}
			if !fi.IsDir() {
				return "", false, fmt.Errorf("%s is not a directory", dir)
			}
			b, err := ociGuestReadRegular(filepath.Join(dir, "package.json"), dir)
			if err != nil {
				return "", false, err
			}
			var m struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if json.Unmarshal(b, &m) != nil || m.Name != name {
				return "", false, fmt.Errorf("%s/package.json does not name %s", dir, name)
			}
			return m.Version, true, nil
		}
		return "", false, nil
	}
	f.Cached = func(integrity string) (bool, error) {
		return ociGuestCacheHolds(filepath.Join(ociGuestNPMCache, "_cacache"), integrity)
	}
	return sandboxoci.CheckFetchedPackages(f, pins)
}

// ociGuestNPMCache is the setup container's npm cache (a variable so a test
// can point the check at its own directory).
var ociGuestNPMCache = sandboxoci.InstallNPMCache

// ociGuestCacheHolds reports whether npm's content store under cacheDir
// holds a regular file, reached through no symlink, whose sha512 is the
// integrity's.
func ociGuestCacheHolds(cacheDir, integrity string) (bool, error) {
	rel, want, err := sandboxoci.IntegrityContentPath(integrity)
	if err != nil {
		return false, err
	}
	p := filepath.Join(cacheDir, filepath.FromSlash(rel))
	if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if res, err := filepath.EvalSymlinks(p); err != nil || res != filepath.Clean(p) {
		return false, fmt.Errorf("%s is reached through a symlink", p)
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: npm's content store in the setup container's own /tmp, checked above
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", p)
	}
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return bytes.Equal(h.Sum(nil), want), nil
}

// ociGuestReadRegular reads p, a regular file inside root reached through no
// symlink, capped at ociGuestScriptMaxBytes.
func ociGuestReadRegular(p, root string) ([]byte, error) {
	if res, err := filepath.EvalSymlinks(p); err != nil || res != filepath.Clean(p) {
		return nil, fmt.Errorf("%s is missing or reached through a symlink", p)
	}
	if !isWithinPath(p, root) {
		return nil, fmt.Errorf("%s is outside the package", p)
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: a file of the installed package, checked above
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	b, err := io.ReadAll(io.LimitReader(f, ociGuestScriptMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > ociGuestScriptMaxBytes {
		return nil, fmt.Errorf("%s is over %d bytes", p, ociGuestScriptMaxBytes)
	}
	return b, nil
}

// ociInstallGuestArgs are the in-box verb's parsed flags.
type ociInstallGuestArgs struct {
	sock   string
	port   int
	pkgDir string
	shas   []string
	// packages are the --package-integrity pins (ruling P-142).
	packages []sandboxoci.PackagePin
	argv     []string
}

// parseOCIInstallArgs reads the in-box verb's flags: --gateway and --port
// first, then optionally --run-scripts <dir> and one or more --script-sha
// <hex>, then "--" and the installer argv.
func parseOCIInstallArgs(args []string) (ociInstallGuestArgs, error) {
	const usage = "usage: sandbox-oci-install --gateway <socket> --port <n> [--run-scripts <dir> --script-sha <hex>... [--package-integrity <name@version=sha512-...>...]] -- <installer...>"
	var ga ociInstallGuestArgs
	if len(args) < 6 || args[0] != "--gateway" || args[2] != "--port" {
		return ga, errors.New(usage)
	}
	port, err := strconv.Atoi(args[3])
	if err != nil || port < 1 || port > 65535 {
		return ga, fmt.Errorf("bad port %q", args[3])
	}
	if !filepath.IsAbs(args[1]) {
		return ga, fmt.Errorf("the gateway socket %q is not absolute", args[1])
	}
	ga.sock, ga.port = args[1], port
	i := 4
	for i < len(args) && args[i] != "--" {
		if i+1 >= len(args) {
			return ga, errors.New(usage)
		}
		switch args[i] {
		case sandboxoci.ScriptRunFlag:
			if ga.pkgDir != "" || !filepath.IsAbs(args[i+1]) || filepath.Clean(args[i+1]) != args[i+1] {
				return ga, fmt.Errorf("bad %s %q", sandboxoci.ScriptRunFlag, args[i+1])
			}
			ga.pkgDir = args[i+1]
		case sandboxoci.ScriptSHAFlag:
			ga.shas = append(ga.shas, args[i+1])
		case sandboxoci.PackageIntegrityFlag:
			pk, err := sandboxoci.ParsePackagePinFlag(args[i+1])
			if err != nil {
				return ga, fmt.Errorf("bad %s: %w", sandboxoci.PackageIntegrityFlag, err)
			}
			ga.packages = append(ga.packages, pk)
		default:
			return ga, errors.New(usage)
		}
		i += 2
	}
	if i >= len(args)-1 || (ga.pkgDir == "") != (len(ga.shas) == 0) || (ga.pkgDir == "" && len(ga.packages) > 0) {
		return ga, errors.New(usage)
	}
	ga.argv = args[i+1:]
	return ga, nil
}
