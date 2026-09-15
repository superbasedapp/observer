//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/intervention/inspectionbroker"
)

type systemService struct {
	pid    int
	cgroup string
}

type serviceAuthorizer struct {
	uid        int
	unit       string
	executable string
	service    func(context.Context, string) (systemService, error)
}

func (a serviceAuthorizer) authorize(ctx context.Context, peer inspectionbroker.Peer) error {
	refused := errors.New("controller peer not authorized")
	if peer.UID != a.uid || peer.PID <= 1 {
		return refused
	}
	before, err := intervention.Inspect(ctx, peer.PID)
	if err != nil || before.UID != a.uid {
		return refused
	}
	service, err := a.service(ctx, a.unit)
	if err != nil || service.pid != peer.PID || service.cgroup == "" || service.cgroup == "/" {
		return refused
	}
	executable, err := rootExecutableIdentity(a.executable)
	if err != nil || executable != before.Executable {
		return refused
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(peer.PID), "cgroup"))
	if err != nil || !hasUnifiedCgroup(raw, service.cgroup) {
		return refused
	}
	after, err := intervention.Inspect(ctx, peer.PID)
	if err != nil || after != before {
		return refused
	}
	return nil
}

func rootExecutableIdentity(path string) (intervention.ExecutableIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || rootDirectory(filepath.Dir(path)) != nil {
		return intervention.ExecutableIdentity{}, errors.New("untrusted executable")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 {
		return intervention.ExecutableIdentity{}, errors.New("untrusted executable")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Dev == 0 || st.Ino == 0 {
		return intervention.ExecutableIdentity{}, errors.New("untrusted executable")
	}
	return intervention.ExecutableIdentity{Device: uint64(st.Dev), Inode: st.Ino}, nil //nolint:unconvert // dev_t differs across Linux architectures.
}

func readSystemService(ctx context.Context, unit string) (systemService, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--property=ControlGroup", "--", unit)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "SYSTEMD_PAGER="}
	raw, err := command.Output()
	if err != nil || len(raw) > 4096 {
		return systemService{}, errors.New("controller service unavailable")
	}
	return parseSystemService(raw)
}

func parseSystemService(raw []byte) (systemService, error) {
	var service systemService
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return systemService{}, errors.New("controller service metadata invalid")
		}
		seen[key] = true
		switch key {
		case "MainPID":
			service.pid, _ = strconv.Atoi(value)
		case "ControlGroup":
			service.cgroup = value
		default:
			return systemService{}, errors.New("controller service metadata invalid")
		}
	}
	if service.pid <= 1 || !strings.HasPrefix(service.cgroup, "/") || service.cgroup == "/" {
		return systemService{}, errors.New("controller service metadata unavailable")
	}
	return service, nil
}

func hasUnifiedCgroup(raw []byte, expected string) bool {
	if expected == "" || expected == "/" {
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if value, ok := strings.CutPrefix(line, "0::"); ok {
			return value == expected
		}
	}
	return false
}
