//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestNodeInterventionProbeChildProcess(t *testing.T) {
	if os.Getenv("OBSERVER_CONTROL_TEST_CHILD") != "1" {
		return
	}
	cmd := newNodeControlProbeChildCmd()
	cmd.SetContext(context.Background())
	cmd.SetIn(os.Stdin)
	cmd.SetOut(os.Stdout)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNodeInterventionOwnedChildProbe(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
	}{
		{name: "observed termination"}, {name: "cancelled", cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if tc.cancel {
				cancel()
			}
			err := probeNodeControlWith(ctx, func(childCtx context.Context) *exec.Cmd {
				cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestNodeInterventionProbeChildProcess$")
				cmd.Env = []string{"OBSERVER_CONTROL_TEST_CHILD=1"}
				return cmd
			})
			if tc.cancel && err == nil {
				t.Fatal("cancelled probe succeeded")
			}
			if !tc.cancel && err != nil {
				t.Fatal(err)
			}
		})
	}
}
