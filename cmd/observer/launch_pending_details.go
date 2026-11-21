//go:build !sbo_omit_terminals

package main

import (
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// launch_pending_details.go renders what a held launch will run (lane cli-2
// fixes-2, audit M-B: the confirm card must show the human exactly what a
// confirm starts). One row per field of each request type the daemon holds;
// TestHeldDetailsCoverEveryBoundField walks each type's fields by reflection
// and fails on a field that is neither a row nor named in a notRun table
// with the reason it does not change what runs, so a new bound field cannot
// be hidden.

// unsandboxedLine is the sandbox detail of a launch that runs on the host.
const unsandboxedLine = "unsandboxed: runs on this machine with your access"

// launchSpecRow is one field of an `observer launch` request.
type launchSpecRow struct {
	field, label string
	value        func(s attachsock.LaunchSpec) (v string, warn bool)
	// always shows the row even when the field is empty (the sandbox:
	// empty means unsandboxed, which must be said).
	always bool
}

var launchSpecRows = []launchSpecRow{
	{field: "Tool", label: "tool", value: func(s attachsock.LaunchSpec) (string, bool) { return s.Tool, false }},
	{field: "Project", label: "project", value: func(s attachsock.LaunchSpec) (string, bool) { return s.Project, false }},
	{field: "Sandbox", label: "sandbox", always: true, value: func(s attachsock.LaunchSpec) (string, bool) {
		if s.Sandbox == "" || s.Sandbox == agentlaunch.SandboxNone {
			return unsandboxedLine, true
		}
		return s.Sandbox, false
	}},
	{field: "Workspace", label: "workspace", value: func(s attachsock.LaunchSpec) (string, bool) { return s.Workspace, false }},
	{field: "Remote", label: "clone remote", value: func(s attachsock.LaunchSpec) (string, bool) {
		return scrub.MaskCertainSecrets(s.Remote), s.Remote != ""
	}},
	{field: "Branch", label: "branch", value: func(s attachsock.LaunchSpec) (string, bool) { return s.Branch, false }},
	{field: "Model", label: "model", value: func(s attachsock.LaunchSpec) (string, bool) { return s.Model, false }},
}

// launchSpecNotRun are the LaunchSpec fields that do not change what runs.
var launchSpecNotRun = map[string]string{
	"AgentEnv":        "the caller's own agent marker, which held the launch",
	"AgentEnvSession": "the caller's own agent marker, which held the launch",
}

// launchSpecDetails is every bound field of a held `observer launch`.
func launchSpecDetails(s attachsock.LaunchSpec) []agentlaunch.PendingDetail {
	var out []agentlaunch.PendingDetail
	for _, r := range launchSpecRows {
		v, warn := r.value(s)
		if v == "" && !r.always {
			continue
		}
		out = append(out, agentlaunch.PendingDetail{Label: r.label, Value: v, Warn: warn})
	}
	return out
}

// spawnRow is one field of an attach launch (`observer <tool> --attach`).
type spawnRow struct {
	field, label string
	value        func(r attachsock.SpawnRequest) (v string, warn bool)
}

var spawnRows = []spawnRow{
	{field: "Tool", label: "tool", value: func(r attachsock.SpawnRequest) (string, bool) { return r.Tool, false }},
	{field: "Subcommand", label: "launcher", value: func(r attachsock.SpawnRequest) (string, bool) {
		if r.Subcommand == "" {
			return "", false
		}
		return "observer " + r.Subcommand, false
	}},
	{field: "Dir", label: "directory", value: func(r attachsock.SpawnRequest) (string, bool) { return r.Dir, false }},
	{field: "ExtraArgs", label: "tool arguments", value: func(r attachsock.SpawnRequest) (string, bool) {
		// A secret-looking flag's value is masked (fixes-3, audit L3);
		// the confirm runs the arguments as sent.
		return strings.Join(scrub.MaskSecretArgs(r.ExtraArgs), " "), len(r.ExtraArgs) > 0
	}},
	{field: "Env", label: "environment", value: func(r attachsock.SpawnRequest) (string, bool) {
		if len(r.Env) == 0 {
			return "", false
		}
		names := make([]string, 0, len(r.Env))
		for _, kv := range r.Env {
			k, _, _ := strings.Cut(kv, "=")
			names = append(names, k)
		}
		sort.Strings(names)
		return strings.Join(names, ", ") + " (values not shown; they may hold provider credentials)", true
	}},
	{field: "ResumeSession", label: "resumes session", value: func(r attachsock.SpawnRequest) (string, bool) { return r.ResumeSession, r.ResumeSession != "" }},
	{field: "AutoResume", label: "auto-resume", value: func(r attachsock.SpawnRequest) (string, bool) {
		if !r.AutoResume {
			return "", false
		}
		return "a daemon-death reattach", false
	}},
}

// spawnNotRun are the SpawnRequest fields that do not change what runs.
var spawnNotRun = map[string]string{
	"Rows":              "the terminal's size",
	"Cols":              "the terminal's size",
	"AutoResumeCapable": "the client's own protocol capability",
	"AgentEnv":          "the caller's own agent marker, which held the launch",
	"AgentEnvSession":   "the caller's own agent marker, which held the launch",
}

// spawnDetails is every bound field of a held attach launch; an attach
// launch is never sandboxed, which is said first.
func spawnDetails(r attachsock.SpawnRequest) []agentlaunch.PendingDetail {
	out := []agentlaunch.PendingDetail{{Label: "sandbox", Value: unsandboxedLine, Warn: true}}
	for _, row := range spawnRows {
		if v, warn := row.value(r); v != "" {
			out = append(out, agentlaunch.PendingDetail{Label: row.label, Value: v, Warn: warn})
		}
	}
	return out
}

// toRunDetails converts agentlaunch's details to the attach endpoint's.
func toRunDetails(ds []agentlaunch.PendingDetail) []attachsock.PendingDetail {
	if len(ds) == 0 {
		return nil
	}
	out := make([]attachsock.PendingDetail, 0, len(ds))
	for _, d := range ds {
		out = append(out, attachsock.PendingDetail{Label: d.Label, Value: d.Value, Warn: d.Warn})
	}
	return out
}
