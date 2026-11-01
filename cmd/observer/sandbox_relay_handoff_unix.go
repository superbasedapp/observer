//go:build !windows && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// relayChildFD is the descriptor ExtraFiles[0] lands on.
const relayChildFD = 3

// relayChildEnv is relayChildEnvFD with fd 3.
func relayChildEnv(base []string, kind sandboxrelay.Kind) []string {
	return relayChildEnvFD(base, kind, strconv.Itoa(relayChildFD))
}

// relayHandOff gives a relay child the channel record's read end as fd 3
// (exec.Cmd.ExtraFiles[0]) and returns the descriptor the child's
// environment names.
func relayHandOff(cmd *exec.Cmd, r *os.File) (string, error) {
	cmd.ExtraFiles = []*os.File{r}
	return strconv.Itoa(relayChildFD), nil
}

// relayChannelFile opens the descriptor a relay child's environment names:
// only fd 3.
func relayChannelFile(fd string) (*os.File, error) {
	n, err := parseRelayChannelID(fd)
	if err != nil || n != relayChildFD {
		return nil, fmt.Errorf("relay channel descriptor %q", fd)
	}
	f := os.NewFile(uintptr(n), "relay-channel")
	if f == nil {
		return nil, errors.New("relay channel descriptor is not open")
	}
	return f, nil
}
