package main

import (
	"context"
	"io"
	"testing"
	"time"
)

// TestStartupStopGuardExitsWhenStartupIgnoresTheStop pins D-MU2: a SIGTERM
// during the part of startup before the stop watchdog exists ends the
// process within the bound.
func TestStartupStopGuardExitsWhenStartupIgnoresTheStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	exited := make(chan int, 1)
	handoff := startupStopGuard(ctx, 50*time.Millisecond, io.Discard, func(code int) { exited <- code })
	defer handoff()
	cancel()
	select {
	case code := <-exited:
		if code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stop during startup never ended the process")
	}
}

// TestStartupStopGuardStandsDownAfterHandoff pins that the guard never
// fires once the stop watchdog owns the bound.
func TestStartupStopGuardStandsDownAfterHandoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	exited := make(chan int, 1)
	handoff := startupStopGuard(ctx, 20*time.Millisecond, io.Discard, func(code int) { exited <- code })
	handoff()
	handoff()
	cancel()
	select {
	case <-exited:
		t.Fatal("the guard fired after handoff")
	case <-time.After(200 * time.Millisecond):
	}
}
