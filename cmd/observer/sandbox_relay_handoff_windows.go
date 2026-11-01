//go:build windows && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"golang.org/x/sys/windows"
)

// relayHandOff gives a relay child the channel record's read end on
// Windows, where exec.Cmd.ExtraFiles is not supported (lane SBX-P6): the
// handle is marked inheritable and named in the child's handle list
// (SysProcAttr.AdditionalInheritedHandles, PROC_THREAD_ATTRIBUTE_HANDLE_LIST),
// so it reaches that one child and no other process the daemon starts. The
// child's environment names the handle value.
func relayHandOff(cmd *exec.Cmd, r *os.File) (string, error) {
	h := windows.Handle(r.Fd())
	if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		return "", fmt.Errorf("mark the channel inheritable: %w", err)
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.AdditionalInheritedHandles = append(cmd.SysProcAttr.AdditionalInheritedHandles, syscall.Handle(h))
	return strconv.FormatUint(uint64(h), 10), nil
}

// relayChannelFile opens the inherited handle a relay child's environment
// names; it must be a pipe.
func relayChannelFile(fd string) (*os.File, error) {
	n, err := parseRelayChannelID(fd)
	if err != nil {
		return nil, fmt.Errorf("relay channel handle %q", fd)
	}
	h := windows.Handle(n)
	if t, err := windows.GetFileType(h); err != nil || t != windows.FILE_TYPE_PIPE {
		return nil, errors.New("relay channel handle is not an open pipe")
	}
	f := os.NewFile(uintptr(h), "relay-channel")
	if f == nil {
		return nil, errors.New("relay channel handle is not open")
	}
	return f, nil
}
