package diag

import (
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// AP-135 native-console doctor probes for the two Rail B artifacts
// `observer org emit-managed-settings` generates beyond Claude Code and
// Codex: Snowflake Cortex Code's managed-settings.json and IBM Bob's
// administrator policy. Like codex-teams they self-gate on the artifact's
// presence (absent = one informational OK) and report gaps as WARN, never
// FAIL. Kimchi has no Rail B artifact (its org policy is resolved by Cast AI
// server-side and cached by the CLI), so it has no node probe.

// cortexManagedSettingsPaths is the documented location per OS
// (https://docs.snowflake.com/en/user-guide/cortex-code/managed-settings).
func cortexManagedSettingsPaths() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"/Library/Application Support/Cortex/managed-settings.json"}
	case "windows":
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return []string{filepath.Join(pd, "Cortex", "managed-settings.json")}
	}
	return []string{"/etc/cortex/managed-settings.json"}
}

// bobPolicyPaths is IBM Bob's file policy source (Linux). Windows (registry)
// and macOS (managed preferences) deliver the policy outside a file; those
// are read through hook.ReadIBMBobPolicy (checkIBMBobTeamsPolicy).
func bobPolicyPaths() []string {
	if runtime.GOOS == "linux" {
		return []string{"/etc/bob/policy.json"}
	}
	return nil
}

func checkCortexTeams(cfg config.Config) Check {
	return checkCortexTeamsAt(cfg, cortexManagedSettingsPaths())
}

// checkCortexTeamsAt verifies a deployed Cortex Code managed-settings.json:
// valid JSON with "version" "1.0" (anything else puts the CLI in restricted
// mode), not writable by group or others and root-owned (Cortex refuses
// such a file), and, when it pins an admin mcp.json, that file present and
// npx on PATH.
func checkCortexTeamsAt(_ config.Config, paths []string) Check {
	const name = "cortex-code-teams"
	path := firstExisting(paths)
	if path == "" {
		return Check{Name: name, Status: StatusOK, Message: "cortex code managed-settings not deployed - run `observer org emit-managed-settings --provider cortex-code` to generate it"}
	}
	var details []string
	worst := StatusOK
	note := func(s Status, msg string) {
		details = append(details, msg)
		if s > worst {
			worst = s
		}
	}
	noteSystemFile(path, note)
	var doc struct {
		Version string `json:"version"`
		Files   struct {
			MCPFile string `json:"mcpFile"`
		} `json:"files"`
	}
	b, err := os.ReadFile(path)
	switch {
	case err != nil:
		note(StatusWarn, "cannot read "+path+": "+err.Error())
	case json.Unmarshal(b, &doc) != nil:
		note(StatusWarn, path+" is not valid JSON - Cortex Code falls back to restricted mode")
	case doc.Version != "1.0":
		note(StatusWarn, path+` lacks "version": "1.0" - Cortex Code falls back to restricted mode`)
	default:
		note(StatusOK, "managed-settings.json present and parseable ("+path+")")
	}
	if doc.Files.MCPFile != "" {
		if _, err := os.Stat(doc.Files.MCPFile); err != nil {
			note(StatusWarn, "files.mcpFile "+doc.Files.MCPFile+" is missing - the Observer MCP pin will not load")
		} else {
			note(StatusOK, "files.mcpFile present ("+doc.Files.MCPFile+")")
		}
		if _, err := exec.LookPath("npx"); err != nil {
			note(StatusWarn, "npx not on PATH - the `npx -y @superbased/observer` MCP pin will not start")
		}
	}
	msg := "cortex code managed-settings deployed - all checks passed"
	if worst != StatusOK {
		msg = "cortex code managed-settings deployed - see warnings below"
	}
	return Check{Name: name, Status: worst, Message: msg, Details: details}
}

func checkIBMBobTeams(cfg config.Config) Check {
	home, _ := os.UserHomeDir()
	if runtime.GOOS != "linux" {
		return checkIBMBobTeamsPolicy(cfg, hook.ReadIBMBobPolicy(), hook.ReadIBMBobPolicyDomains(home, true), home)
	}
	return checkIBMBobTeamsAt(cfg, bobPolicyPaths(), home)
}

// checkIBMBobTeamsAt verifies a deployed /etc/bob/policy.json: a JSON object
// whose OtelConfiguration is a JSON-encoded string map carrying an endpoint
// URL (Bob ignores the whole policy without one, and a non-string value
// outright), the file root-owned and not writable by others, and the
// endpoint's receiver reachable when [ingest.otel] is enabled; then, from
// the same document, whether EnforcedHooks carries Observer's hooks and the
// per-node registration under home stood down (noteBobPolicyHooks).
func checkIBMBobTeamsAt(cfg config.Config, paths []string, home string) Check {
	const name = "ibm-bob-teams"
	path := firstExisting(paths)
	if path == "" {
		return Check{Name: name, Status: StatusOK, Message: "ibm bob policy file not deployed - run `observer org emit-managed-settings --provider ibm-bob` to generate it"}
	}
	var details []string
	worst := StatusOK
	note := func(s Status, msg string) {
		details = append(details, msg)
		if s > worst {
			worst = s
		}
	}
	noteSystemFile(path, note)
	var rems []remedy.Remediation
	b, err := os.ReadFile(path)
	var policy map[string]json.RawMessage
	switch {
	case err != nil:
		note(StatusWarn, "cannot read "+path+": "+err.Error())
	case json.Unmarshal(b, &policy) != nil:
		note(StatusWarn, path+" is not a JSON object - Bob ignores it")
	}
	if raw, ok := policy["OtelConfiguration"]; ok {
		var encoded string
		var otel map[string]any
		switch {
		case json.Unmarshal(raw, &encoded) != nil:
			note(StatusWarn, "OtelConfiguration is not a string - Bob ignores a policy of the wrong type")
		case json.Unmarshal([]byte(encoded), &otel) != nil:
			note(StatusWarn, "OtelConfiguration is not a JSON object - Bob ignores it")
		default:
			ep, _ := otel["OTEL_EXPORTER_OTLP_ENDPOINT"].(string)
			if ep == "" {
				ep, _ = otel["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"].(string)
			}
			u, perr := url.Parse(ep)
			switch {
			case ep == "" || perr != nil || u.Host == "":
				note(StatusWarn, "OtelConfiguration has no valid OTEL_EXPORTER_OTLP_ENDPOINT - Bob ignores the policy")
			case !cfg.Ingest.OTel.Enabled:
				note(StatusWarn, "OtelConfiguration points Bob at "+ep+" but [ingest.otel].enabled is false - the traces have no receiver")
			case dialable(u.Host):
				note(StatusOK, "OTLP receiver reachable at "+u.Host+" (Bob OtelConfiguration target)")
			default:
				note(StatusWarn, "OTLP receiver NOT reachable at "+u.Host+" - is `observer start` running with [ingest.otel].enabled?")
			}
		}
	} else if err == nil {
		note(StatusOK, "policy file present without OtelConfiguration - Bob's OTLP export is not policy-managed")
	}
	if err == nil && policy != nil {
		pol := hook.ParseIBMBobPolicyDocument(path, b)
		if pol.Untrusted == "" {
			pol.Untrusted = systemFileUntrusted(path)
		}
		noteBobPolicyTelemetry(pol, note)
		rems = noteBobPolicyHooks(pol, home, note)
		noteBobPolicyGateway(pol, note)
	}
	msg := "ibm bob policy deployed - all checks passed"
	if worst != StatusOK {
		msg = "ibm bob policy deployed - see warnings below"
	}
	return Check{Name: name, Status: worst, Message: msg, Details: details, Remediations: rems}
}

// firstExisting returns the first path that exists, or "".
func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// noteSystemFile WARNs when a managed file is writable by group or others or
// (where the platform says) not owned by root: both vendors refuse or
// distrust such a file. Windows ACLs are not inspected.
func noteSystemFile(path string, note func(Status, string)) {
	if runtime.GOOS == "windows" {
		return
	}
	fi, err := os.Stat(path) //nolint:gosec // G703: a fixed system file path from the probe table
	if err != nil {
		return
	}
	if fi.Mode().Perm()&0o022 != 0 {
		note(StatusWarn, path+" is writable by group or others - the vendor refuses or distrusts it; chmod 644")
	}
	if root, known := ownedByRoot(fi); known && !root {
		note(StatusWarn, path+" is not owned by root - deploy it as root (MDM / configuration management)")
	}
}
