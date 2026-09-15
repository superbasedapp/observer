package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/store"
)

const nodeControlProbeReady = "observer-owned-control-probe-v1"

func printEnrolledNodeControl(ctx context.Context, out io.Writer, st *store.Store, dbPath string) {
	auth, err := nodeInterventionAuthority(ctx, st, os.Getuid(), time.Now().UTC())
	if err != nil {
		fmt.Fprintln(out, "Policy control: unavailable - managed authority could not be verified.")
		return
	}
	if !auth.Authorized {
		return
	}
	if os.Getuid() <= 0 || probeNodeControl(ctx) != nil {
		fmt.Fprintln(out, "Policy control: unavailable - a developer-user Linux controller with working process control is required.")
		return
	}
	fmt.Fprintln(out, "Policy control: owned-child process-control self-test passed. This does not establish adapter coverage.")
	fmt.Fprintf(out, "Daemon control: %s\n", nodeInterventionStatusLine(ctx, st, dbPath))
	fmt.Fprintln(out, "The daemon must be running to apply org policies to supported direct adapter processes. Check `observer guard status` for current coverage.")
}

// newNodeControlProbeChildCmd is a bounded, controller-owned child used only
// to test OS control. It opens no database, sockets, vendor tools or user files.
// Closing the parent's input pipe also ends the child after a failed probe.
func newNodeControlProbeChildCmd() *cobra.Command {
	return &cobra.Command{
		Use: "control-probe-child", Hidden: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), nodeControlProbeReady); err != nil {
				return err
			}
			done := make(chan struct{})
			go func() { _, _ = io.Copy(io.Discard, cmd.InOrStdin()); close(done) }()
			timer := time.NewTimer(15 * time.Second)
			defer timer.Stop()
			select {
			case <-done:
				return nil
			case <-timer.C:
				return nil
			case <-cmd.Context().Done():
				return cmd.Context().Err()
			}
		},
	}
}

// probeNodeControl tests the same stable-handle backend that policies use,
// against this executable's disposable child. It is capability evidence,
// never evidence that any vendor surface or budget is fully controlled.
func probeNodeControl(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return intervention.ErrUnsupported
	}
	return probeNodeControlWith(ctx, func(childCtx context.Context) *exec.Cmd {
		// Resolve the running executable, even during an atomic binary update.
		cmd := exec.CommandContext(childCtx, "/proc/self/exe", "guard", "control-probe-child")
		// Do not forward OOB-launch metadata, credentials or vendor settings.
		cmd.Env = []string{}
		return cmd
	})
}

func probeNodeControlWith(ctx context.Context, command func(context.Context) *exec.Cmd) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	self, err := intervention.Inspect(ctx, os.Getpid())
	if err != nil {
		return err
	}
	cmd := command(ctx)
	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	defer output.Close()
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = input.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(io.LimitReader(output, 128))
		ready <- scanner.Scan() && scanner.Text() == nodeControlProbeReady
	}()
	select {
	case ok := <-ready:
		if !ok {
			return errors.New("node control probe: child did not become ready")
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	id, err := intervention.Inspect(ctx, cmd.Process.Pid)
	if err != nil {
		return err
	}
	if id.UID != self.UID || id.BootID != self.BootID || id.Executable != self.Executable {
		return intervention.ErrIdentityMismatch
	}
	handle, err := intervention.Acquire(ctx, id)
	if err != nil {
		return err
	}
	defer handle.Close()
	result, err := handle.Terminate(ctx)
	if err != nil {
		return err
	}
	if !result.Observed || result.AlreadyExited {
		return errors.New("node control probe: requested exit was not observed")
	}
	return nil
}
