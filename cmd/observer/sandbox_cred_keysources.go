//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// sandbox_cred_keysources.go is the New Terminal dialog's switch for a
// tool's opt-in in-box key sources (decision SBXD-4): "Also use the keys
// <tool> saved itself" and "Also copy my <tool> login". Each writes the
// tool's entry of [terminal.sandbox.hosted.tool_keys] or
// [terminal.sandbox.hosted.login_seed] (a structural patch: every other key
// and comment stays). The value is remembered for the tool, and the hosted
// consent binds the opted-in set, so the next upload asks again before the
// source is first used. Local, behind the confirm token, 404 while no
// hosted driver is active.

func init() {
	gatesSandboxRouteFuncs = append(gatesSandboxRouteFuncs, hostedKeySourceRoutes)
}

// hostedKeySources names the two switches by their config key.
var hostedKeySources = map[string]struct {
	get      func(*config.TerminalSandboxHostedConfig) *map[string]bool
	grounded func(string) bool
}{
	"tool_keys": {
		get:      func(h *config.TerminalSandboxHostedConfig) *map[string]bool { return &h.ToolKeys },
		grounded: func(t string) bool { _, ok := integration.SandboxSavedKeysFor(t); return ok },
	},
	"login_seed": {
		get:      func(h *config.TerminalSandboxHostedConfig) *map[string]bool { return &h.LoginSeed },
		grounded: func(t string) bool { _, ok := integration.SandboxLoginSeedFor(t); return ok },
	},
}

// hostedSetKeySource turns source on or off for tool in the config file at
// configPath ("" the daemon's own).
func hostedSetKeySource(configPath, source, tool string, on bool) error {
	src, ok := hostedKeySources[source]
	if !ok {
		return errors.New("unknown key source (tool_keys or login_seed)")
	}
	if !src.grounded(tool) {
		return errors.New("this agent has no grounded file for that key source")
	}
	path, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return err
	}
	mu := config.WriteLock()
	mu.Lock()
	defer mu.Unlock()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return err
	}
	next := cfg
	m := maps.Clone(*src.get(&cfg.Terminal.Sandbox.Hosted))
	if on {
		if m == nil {
			m = map[string]bool{}
		}
		m[tool] = true
	} else {
		delete(m, tool)
	}
	*src.get(&next.Terminal.Sandbox.Hosted) = m
	patches, err := config.StructuralPatches(cfg, next)
	if err != nil {
		return err
	}
	if _, err := config.PatchFile(path, next, patches); err != nil {
		return err
	}
	applySandboxConfigLive()
	return nil
}

// hostedKeySourceRoutes is the dialog's route (gatesSandboxRouteFuncs).
func hostedKeySourceRoutes(configPath string) []dashapi.ExtraRoute {
	return []dashapi.ExtraRoute{{
		Pattern: "POST /api/terminal/sandbox/hosted/key-sources", Capability: dashapi.CapabilityLocal,
		Handler: func(w http.ResponseWriter, r *http.Request) {
			if !hostedActive(r.Context(), configPath) {
				http.NotFound(w, r)
				return
			}
			if !hostedConfirmed(w, r) {
				return
			}
			var body struct {
				Tool   string `json:"tool"`
				Source string `json:"source"`
				On     bool   `json:"on"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
				http.Error(w, "a JSON body is required", http.StatusBadRequest)
				return
			}
			if err := hostedSetKeySource(configPath, strings.TrimSpace(body.Source), strings.TrimSpace(body.Tool), body.On); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		},
	}}
}

// hostedKeyDoctorChecks is the posture line of the hosted key settings for
// doctor and `observer sandbox status` (decision SBXD-11: printed where its
// siblings are): the custody, the per-tool values and the opt-in in-box
// sources, tool ids and setting names only, never a key.
func hostedKeyDoctorChecks(eff config.TerminalSandboxConfig) []diag.Check {
	h := eff.Hosted
	msg := "hosted key custody: " + hostedConsentCustody(h)
	if h.KeyCustody == "auto" {
		msg += " (per launch and tool: kept on this machine when credential injection or the org AI gateway serves the tool, else in the box)"
	}
	on := func(m map[string]bool) string {
		var ids []string
		for _, t := range slices.Sorted(maps.Keys(m)) {
			if m[t] {
				ids = append(ids, t)
			}
		}
		if len(ids) == 0 {
			return "none"
		}
		return strings.Join(ids, ", ")
	}
	msg += "; own saved keys (tool_keys): " + on(h.ToolKeys) + "; login access token (login_seed): " + on(h.LoginSeed)
	return []diag.Check{{Name: "sandbox.hosted.key_custody", Status: diag.StatusOK, Message: msg}}
}
