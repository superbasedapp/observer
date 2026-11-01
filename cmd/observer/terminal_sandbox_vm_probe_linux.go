//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
	toolhost "github.com/marmutapp/superbased-observer/internal/toolresolve/host"
)

// terminal_sandbox_vm_probe_linux.go is the probe ladder's I/O on Linux:
// local facts only (a stat and a read-write open of /dev/kvm closed at once,
// the CPU flags, no-follow stats of the two programs, the VMM's --version,
// the verified guest image set). Every func is reached only below the
// ladder's active row; none boots a VM, dials a socket or fetches.

// vmKVMPath is the KVM device.
const vmKVMPath = "/dev/kvm"

// vmProbeEnv builds the ladder's facts for one runtime.
func vmProbeEnv(r *sandboxRuntime, cfg config.TerminalSandboxVMConfig) sandboxvm.ProbeEnv {
	return sandboxvm.ProbeEnv{
		GOOS:          "linux",
		KVM:           func() sandboxvm.KVMFacts { return vmKVMFacts(vmKVMPath) },
		InVM:          vmHostIsVM,
		LookVMM:       func() (string, error) { return vmLookProgram(cfg.CloudHypervisorPath, "cloud-hypervisor", nil) },
		LookVirtiofsd: func() (string, error) { return vmLookProgram(cfg.VirtiofsdPath, "virtiofsd", vmVirtiofsdDirs) },
		StatProgram:   vmStatProgram,
		VMMVersion:    vmVMMVersion,
		ImageSet:      func() sandboxvm.ImageSetFacts { return vmImageSetFacts(r, cfg) },
	}
}

// vmKVMFacts stats the device and opens it read-write (closed at once): the
// only way to learn that this user may use it.
func vmKVMFacts(p string) sandboxvm.KVMFacts {
	fi, err := os.Stat(p)
	if err != nil {
		return sandboxvm.KVMFacts{}
	}
	f := sandboxvm.KVMFacts{Exists: true, CharDevice: fi.Mode()&fs.ModeCharDevice != 0}
	if !f.CharDevice {
		return f
	}
	h, err := os.OpenFile(p, os.O_RDWR, 0) //nolint:gosec // G304: the fixed KVM device path
	if err != nil {
		f.OpenErr = err.Error()
		f.PermissionDenied = errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
		return f
	}
	_ = h.Close()
	return f
}

// vmHostIsVM reports whether this host is a VM: WSL2, or the CPU's
// hypervisor flag in /proc/cpuinfo.
func vmHostIsVM() bool {
	if crossmount.IsWSL() {
		return true
	}
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "flags") {
			continue
		}
		_, flags, _ := strings.Cut(line, ":")
		for _, f := range strings.Fields(flags) {
			if f == "hypervisor" {
				return true
			}
		}
		return false
	}
	return false
}

// vmVirtiofsdDirs are where distributions put virtiofsd off PATH.
var vmVirtiofsdDirs = []string{"/usr/libexec", "/usr/lib/qemu"}

// vmLookProgram resolves a program: the configured absolute path as is, or
// the first PATH entry (then extra) that holds it, never from Observer's own
// shim directory nor a file carrying the shim marker (toolresolve's host
// environment).
func vmLookProgram(configured, name string, extra []string) (string, error) {
	if configured != "" {
		if !filepath.IsAbs(configured) {
			return "", errors.New("not an absolute path")
		}
		return configured, nil
	}
	env := toolhost.NewEnv(toolhost.Options{})
	excluded := func(dir string) bool {
		for _, d := range env.ExcludeDirs {
			if d != "" && filepath.Clean(d) == filepath.Clean(dir) {
				return true
			}
		}
		return false
	}
	dirs := append(append([]string(nil), env.ProcessPath...), extra...)
	for _, dir := range dirs {
		if dir == "" || !filepath.IsAbs(dir) || excluded(dir) {
			continue
		}
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p) //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if env.ExcludeMarker != "" && env.ReadHead != nil {
			if head, err := env.ReadHead(p, 512); err == nil && bytes.Contains(head, []byte(env.ExcludeMarker)) {
				continue
			}
		}
		return p, nil
	}
	return "", fs.ErrNotExist
}

// vmStatProgram is the no-follow stat of a resolved program.
func vmStatProgram(p string) (sandboxvm.ProgramFacts, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return sandboxvm.ProgramFacts{}, err
	}
	f := sandboxvm.ProgramFacts{Regular: fi.Mode().IsRegular(), Perm: uint32(fi.Mode().Perm())}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		f.OwnerOK = int(st.Uid) == os.Getuid() || st.Uid == 0
	}
	return f, nil
}

// vmVMMVersion runs `cloud-hypervisor --version` under a short deadline.
func vmVMMVersion(p string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p, "--version") //nolint:gosec // G204: the owner-checked VMM path
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	out, err := cmd.Output()
	if len(out) > 4096 {
		out = out[:4096]
	}
	return string(out), err
}

// vmLookProgramFor resolves a host tool on PATH and in the sbin dirs.
func vmLookProgramFor(name string) (string, error) {
	return vmLookProgram("", name, []string{"/usr/sbin", "/sbin"})
}

// vmImageSetFacts loads the set the runtime's content store holds.
func vmImageSetFacts(r *sandboxRuntime, cfg config.TerminalSandboxVMConfig) sandboxvm.ImageSetFacts {
	if r == nil {
		return sandboxvm.ImageSetFacts{}
	}
	return loadVMImageSet(vmContentStore(r.observerDir), contentchan.Trust{VendorKeys: sandboxContentVendorKeys()}, cfg.ImageSet, version).facts()
}
