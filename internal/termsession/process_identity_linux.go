//go:build linux

package termsession

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	processStatLimit = 4 << 10
	processBootLimit = 128
)

func processStartIdentity(pid int) string {
	return processStartIdentityInProc("/proc", pid)
}

func processStartIdentityInProc(procRoot string, pid int) string {
	if pid <= 1 {
		return ""
	}
	stat, err := readBoundedProcessMetadata(filepath.Join(procRoot, strconv.Itoa(pid), "stat"), processStatLimit)
	if err != nil {
		return ""
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return ""
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
		return ""
	}
	start := fields[19]
	if ticks, parseErr := strconv.ParseUint(start, 10, 64); parseErr != nil || ticks == 0 {
		return ""
	}
	bootRaw, err := readBoundedProcessMetadata(filepath.Join(procRoot, "sys", "kernel", "random", "boot_id"), processBootLimit)
	if err != nil {
		return ""
	}
	boot := strings.TrimSpace(string(bootRaw))
	if boot == "" || strings.ContainsAny(boot, ":\x00\r\n") {
		return ""
	}
	return "linux:" + boot + ":" + start
}

func readBoundedProcessMetadata(path string, limit int64) ([]byte, error) {
	//nolint:gosec // paths are fixed procfs metadata plus a validated numeric PID.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("process metadata exceeds %d bytes", limit)
	}
	return raw, nil
}
