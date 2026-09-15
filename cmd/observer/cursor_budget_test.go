package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCursorBudgetLaunchEvidence(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want budgetLaunchRoute
	}{
		{name: "interactive", want: budgetLaunchRouteDirect},
		{name: "prompt", args: []string{"write code"}, want: budgetLaunchRouteDirect},
		{name: "headless", args: []string{"-p", "write code"}, want: budgetLaunchRouteDirect},
		{name: "resume", args: []string{"--resume=chat"}, want: budgetLaunchRouteDirect},
		{name: "worker", args: []string{"worker"}, want: budgetLaunchRouteDirect},
		{name: "bedrock", args: []string{"bedrock"}, want: budgetLaunchRouteDirect},
		{name: "bedrock test model", args: []string{"bedrock", "configure", "--test-model"}, want: budgetLaunchRouteDirect},
		{name: "mcp subtree", args: []string{"mcp", "list"}, want: budgetLaunchRouteDirect},
		{name: "plugin subtree", args: []string{"plugin", "list"}, want: budgetLaunchRouteDirect},
		{name: "create chat", args: []string{"create-chat"}, want: budgetLaunchRouteDirect},
		{name: "status", args: []string{"status"}, want: budgetLaunchRouteMaintenance},
		{name: "version", args: []string{"-v"}, want: budgetLaunchRouteMaintenance},
		{name: "mixed version prompt", args: []string{"--version", "write code"}, want: budgetLaunchRouteDirect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := cursorBudgetLaunchEvidence(tc.args).Route; got != tc.want {
				t.Fatalf("route = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCursorManagedHardBudgetRefusesBeforeProcessStart(t *testing.T) {
	t.Parallel()
	cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	bin := filepath.Join(dir, "cursor-agent")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n: > \""+marker+"\"\n"), 0o700); err != nil {
		t.Fatalf("write fake cursor-agent: %v", err)
	}

	cmd := newCursorCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--cursor-agent-path", bin,
		"--no-attach",
		"--", "write code",
	})
	err := cmd.Execute()
	if !errors.Is(err, errBudgetLaunchUncontrolled) {
		t.Fatalf("cursor launch error = %v, want managed hard-budget refusal (output %q)", err, output.String())
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("cursor-agent started before budget admission; marker error = %v", statErr)
	}
}
