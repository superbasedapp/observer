package managedsettings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// IBM Bob administrator policy (AP-135, Rail B; docs/plans/
// native-console-ibm-bob-instance-2026-10-23.md). Bob Shell 2.0.6 and the Bob
// IDE read one flat policy object from three sources: /etc/bob/policy.json
// (Linux, root-owned), HKLM\Software\Policies\IBM\Bob (Windows, GPO / Intune
// ADMX) and the com.ibm.bob managed-preferences domain (macOS MDM). Each key
// is a policy name whose value has the policy's declared type (string or
// boolean); a value of the wrong type is ignored by Bob.
//
// Observer emits up to three policies:
//
//   - OtelConfiguration (default on): a JSON-encoded string map of OTEL_*
//     variables that switches Bob's external OTLP trace export on and points
//     it at the node's Observer receiver (Rail A). The policy wins over the
//     user's OTEL_* environment. Bob validates it itself: only the supported
//     variables are kept, the endpoint must be a valid URL, the protocol one
//     of http/json, http/protobuf, grpc, and the OTEL_INCLUDE_* switches "0"
//     or "1"; without an endpoint the whole policy is ignored.
//   - EnforcedHooks (default on, DECIDED 2026-10-24, Q2): a JSON string of
//     Claude-shaped hook groups keyed by event. Bob runs them in addition to
//     user hooks and keeps running them under disableGlobalHooks. The value
//     is built by the caller from the per-node ibm-bob hook writer
//     (internal/hook.IBMBobEnforcedHooks) so the command text has one owner;
//     a node whose policy carries them stands its per-node registration down
//     (SkipCovered), so nothing fires twice.
//   - EnableTelemetry=false (opt-in, DECIDED 2026-10-24): Bob's telemetry to
//     IBM. Bob gates EVERY telemetry client, the otel-external one included,
//     on that one setting (bundle: initializeTelemetry's isEnabled), so it is
//     refused together with OtelConfiguration.
//
// Grounded in the bobshell 2.0.6 bundle (2026-10-22/24), not in IBM's docs,
// which describe the IDE policies only. Rail A's receiving side (mapping
// Bob's spans to turns) is AP-131's node OTLP ingest, not this package.

// BobPolicyName is the policy carrying the OTLP redirect.
const BobPolicyName = "OtelConfiguration"

// BobEnforcedHooksPolicy and BobEnableTelemetryPolicy are the other two
// policies Observer emits.
const (
	BobEnforcedHooksPolicy   = "EnforcedHooks"
	BobEnableTelemetryPolicy = "EnableTelemetry"
)

// ErrBobTelemetryKillsExport is returned when DisableVendorTelemetry is
// combined with the OtelConfiguration export: Bob's telemetry.enabled gates
// every client, so EnableTelemetry=false would silence the export too.
var ErrBobTelemetryKillsExport = errors.New("managedsettings: EnableTelemetry=false also stops Bob's OtelConfiguration export to Observer " +
	"(bobshell 2.0.6: initializeTelemetry gives every telemetry client, otel-external included, the one isEnabled gate " +
	"runtime.getConfig().telemetry.enabled, and capture/startSpan return early when it is false); " +
	"omit the OTLP export (--no-otel-config) to disable vendor telemetry")

// bobOTelProtocols is the closed set Bob accepts for OTEL_EXPORTER_OTLP_PROTOCOL.
var bobOTelProtocols = map[string]bool{"http/json": true, "http/protobuf": true, "grpc": true}

// BobOptions configures IBM Bob policy generation.
type BobOptions struct {
	// OTLPEndpoint is the node's Observer OTLP receiver, e.g.
	// "http://127.0.0.1:4318" for OTLP/HTTP. Required unless OmitOTel.
	OTLPEndpoint string
	// Protocol is http/json (Bob's default), http/protobuf or grpc. It must
	// match the receiver the endpoint names.
	Protocol string
	// ServiceName is OTEL_SERVICE_NAME; empty leaves Bob's default.
	ServiceName string
	// IncludeContent sets OTEL_INCLUDE_USER_PROMPTS,
	// OTEL_INCLUDE_ASSISTANT_RESPONSES and OTEL_INCLUDE_TOOL_OUTPUT to "1"
	// (Bob redacts them otherwise). Off by default: an explicit admin choice.
	IncludeContent bool
	// OmitOTel leaves OtelConfiguration out of the policy.
	OmitOTel bool
	// EnforcedHooks is the EnforcedHooks value (a JSON object of hook groups
	// keyed by event) for the Linux and macOS channels; "" emits none.
	EnforcedHooks string
	// EnforcedHooksWindows is the value for the Windows channel when its
	// command differs (an install path); "" uses EnforcedHooks.
	EnforcedHooksWindows string
	// DisableVendorTelemetry writes EnableTelemetry=false. It cannot be
	// combined with the OTLP export (ErrBobTelemetryKillsExport).
	DisableVendorTelemetry bool
}

// BobArtifacts is the generated policy in its three channels.
type BobArtifacts struct {
	PolicyJSON   []byte // /etc/bob/policy.json
	Registry     string // .reg text (write as UTF-16LE with EncodeUTF16LE)
	MobileConfig string // .mobileconfig for the com.ibm.bob domain
	OTelConfig   map[string]string
	Readme       string
}

// GenerateBob builds the IBM Bob policy artifacts.
func GenerateBob(opts BobOptions) (BobArtifacts, error) {
	if opts.DisableVendorTelemetry && !opts.OmitOTel {
		return BobArtifacts{}, ErrBobTelemetryKillsExport
	}
	posixHooks, winHooks := strings.TrimSpace(opts.EnforcedHooks), strings.TrimSpace(opts.EnforcedHooksWindows)
	if winHooks == "" {
		winHooks = posixHooks
	}
	for _, v := range []string{posixHooks, winHooks} {
		if v == "" {
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(v), &m); err != nil || len(m) == 0 {
			return BobArtifacts{}, fmt.Errorf("managedsettings: Bob EnforcedHooks must be a non-empty JSON object of hook groups keyed by event")
		}
	}
	if opts.OmitOTel && posixHooks == "" && !opts.DisableVendorTelemetry {
		return BobArtifacts{}, fmt.Errorf("managedsettings: the Bob policy would be empty (no OtelConfiguration, no EnforcedHooks, no EnableTelemetry)")
	}

	posix := map[string]any{}
	var otel map[string]string
	if !opts.OmitOTel {
		var err error
		if otel, err = bobOTelConfig(opts); err != nil {
			return BobArtifacts{}, err
		}
		encoded, err := json.Marshal(otel)
		if err != nil {
			return BobArtifacts{}, fmt.Errorf("managedsettings: encode OtelConfiguration: %w", err)
		}
		posix[BobPolicyName] = string(encoded)
	}
	if opts.DisableVendorTelemetry {
		posix[BobEnableTelemetryPolicy] = false
	}
	win := map[string]any{}
	for k, v := range posix {
		win[k] = v
	}
	if posixHooks != "" {
		posix[BobEnforcedHooksPolicy] = posixHooks
		win[BobEnforcedHooksPolicy] = winHooks
	}

	policy, err := marshalIndent(posix)
	if err != nil {
		return BobArtifacts{}, err
	}
	reg, err := renderRegistry(RegistryChannel{Key: `SOFTWARE\Policies\IBM\Bob`, Mode: RegistryValues},
		bobRegistryComment(win), win, nil)
	if err != nil {
		return BobArtifacts{}, err
	}
	profile, err := renderProfile(ProfileChannel{Domain: "com.ibm.bob", Mode: ProfileKeysNative},
		"app.superbased.observer.ibm-bob", "IBM Bob: Observer policy",
		"Observer's IBM Bob administrator policy (OTLP export, enforced hooks, vendor telemetry).", posix, nil, policy)
	if err != nil {
		return BobArtifacts{}, err
	}
	out := BobArtifacts{PolicyJSON: policy, Registry: reg, MobileConfig: profile, OTelConfig: otel}
	out.Readme = bobReadme(out, opts, posixHooks != "", winHooks != posixHooks)
	return out, nil
}

// bobOTelConfig validates the export options into the OtelConfiguration map.
func bobOTelConfig(opts BobOptions) (map[string]string, error) {
	endpoint := strings.TrimSpace(opts.OTLPEndpoint)
	u, err := url.Parse(endpoint)
	if endpoint == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("managedsettings: Bob needs an http(s) OTLP endpoint URL, got %q", opts.OTLPEndpoint)
	}
	protocol := strings.TrimSpace(opts.Protocol)
	if protocol == "" {
		protocol = "http/json"
	}
	if !bobOTelProtocols[protocol] {
		return nil, fmt.Errorf("managedsettings: Bob OTLP protocol %q (want http/json, http/protobuf or grpc)", opts.Protocol)
	}
	otel := map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
		"OTEL_EXPORTER_OTLP_PROTOCOL": protocol,
	}
	if s := strings.TrimSpace(opts.ServiceName); s != "" {
		otel["OTEL_SERVICE_NAME"] = s
	}
	if opts.IncludeContent {
		for _, k := range []string{"OTEL_INCLUDE_USER_PROMPTS", "OTEL_INCLUDE_ASSISTANT_RESPONSES", "OTEL_INCLUDE_TOOL_OUTPUT"} {
			otel[k] = "1"
		}
	}
	return otel, nil
}

func bobRegistryComment(doc map[string]any) []string {
	c := []string{"IBM Bob administrator policy generated by Observer (observer org emit-managed-settings --provider ibm-bob)."}
	if _, ok := doc[BobPolicyName]; ok {
		c = append(c, "OtelConfiguration points Bob's OTLP trace export at the node's Observer receiver.")
	}
	if _, ok := doc[BobEnforcedHooksPolicy]; ok {
		c = append(c, "EnforcedHooks runs Observer's Bob hooks (the per-node registration stands down).")
	}
	if _, ok := doc[BobEnableTelemetryPolicy]; ok {
		c = append(c, "EnableTelemetry=0 turns Bob's own telemetry off (REG_DWORD).")
	}
	return c
}

func bobReadme(a BobArtifacts, opts BobOptions, hooks, winDiffers bool) string {
	var b strings.Builder
	b.WriteString("# Observer administrator policy for IBM Bob\n\n")
	b.WriteString("One policy object in three channels (deploy the one your fleet uses):\n\n")
	b.WriteString("- **Linux:** `policy.json` to `/etc/bob/policy.json`, owned by root, mode 644.\n")
	b.WriteString("- **Windows:** `ibm-bob-policy.reg` imports into `HKLM\\SOFTWARE\\Policies\\IBM\\Bob`\n")
	b.WriteString("  (the file is UTF-16LE, as regedit reads it); or set the same values via GPO / Intune\n")
	b.WriteString("  (strings as REG_SZ, EnableTelemetry as REG_DWORD).\n")
	b.WriteString("- **macOS:** `ibm-bob.mobileconfig` sets the `com.ibm.bob` managed preferences.\n\n")
	b.WriteString("## What it sets\n\n")
	if a.OTelConfig != nil {
		b.WriteString(fmt.Sprintf("- `OtelConfiguration` points Bob's OTLP trace export at `%s` (%s). The policy\n",
			a.OTelConfig["OTEL_EXPORTER_OTLP_ENDPOINT"], a.OTelConfig["OTEL_EXPORTER_OTLP_PROTOCOL"]))
		b.WriteString("  wins over a user's own OTEL_* environment; Observer's node OTLP ingest maps the\n")
		b.WriteString("  spans. The node must run `observer start` with `[ingest.otel].enabled = true` and\n")
		b.WriteString("  the receiver listening where the endpoint says. Bob keeps exporting its own\n")
		b.WriteString("  telemetry to IBM beside it (bobshell 2.0.6 has no per-destination switch).\n")
		if opts.IncludeContent {
			b.WriteString("  Content: prompts, responses and tool output are INCLUDED (OTEL_INCLUDE_* = 1).\n")
		} else {
			b.WriteString("  Content: prompts, responses and tool output stay redacted (Bob's default).\n")
		}
	}
	if hooks {
		b.WriteString("- `EnforcedHooks` runs Observer's Bob hooks (the same events, commands and timeouts\n")
		b.WriteString("  `observer init` registers per node) in addition to the user's own hooks, and keeps\n")
		b.WriteString("  running them when a user sets `disableGlobalHooks`. On a node whose policy carries\n")
		b.WriteString("  them, Observer's per-node registration stands down (reported as covered), so no\n")
		b.WriteString("  hook fires twice. The command is `observer` resolved on PATH (/bin/sh on Linux and\n")
		b.WriteString("  macOS, cmd.exe on Windows): install Observer on PATH, or regenerate with\n")
		b.WriteString("  `--hook-binary` / `--hook-binary-windows`.\n")
		if winDiffers {
			b.WriteString("  The Windows channel names a different binary than the Linux / macOS ones.\n")
		}
		b.WriteString("  Bob ignores the WHOLE value if any part breaks its hook schema; edit with care.\n")
		b.WriteString("  A WSL daemon that bridges hooks into a Windows Bob cannot read the Windows registry,\n")
		b.WriteString("  so on such a host its per-node bridge entries and this policy both fire.\n")
	}
	if opts.DisableVendorTelemetry {
		b.WriteString("- `EnableTelemetry` = false turns Bob's own telemetry to IBM off. Bob gates EVERY\n")
		b.WriteString("  telemetry client on this one setting, an OTLP export to Observer included, so this\n")
		b.WriteString("  policy carries no `OtelConfiguration`. It also stops Bobalytics collection.\n")
	}
	b.WriteString("\n## Not emitted\n\n")
	if !hooks {
		b.WriteString("- `EnforcedHooks` (left out with --no-enforced-hooks): each node registers Observer's\n")
		b.WriteString("  Bob hooks itself; a user who sets `disableGlobalHooks` then runs none of them.\n")
	}
	if !opts.DisableVendorTelemetry {
		b.WriteString("- `EnableTelemetry`: Bob's telemetry to IBM stays as Bob defaults (on). It cannot be\n")
		b.WriteString("  turned off together with the OTLP export (Bob gates both on the same setting).\n")
	}
	b.WriteString("- `ExcludePayloadFromTelemetry`: applies to every Bob telemetry client alike.\n")
	b.WriteString("- `GatewayUrl`: a locked inference host that overrides `BOB_GATEWAY_URL`. Observer\n")
	b.WriteString("  emits none, because no Bob proxy route is grounded yet (Bob's gateway base also\n")
	b.WriteString("  serves `/admin/v1`, which a route has to pass through). If your policy already\n")
	b.WriteString("  sets it, keep it when you merge this policy in; while it is set, a per-node route\n")
	b.WriteString("  to Observer's proxy is ignored (`observer doctor ibm-bob` names it).\n\n")
	b.WriteString("Grounded in the bobshell 2.0.6 bundle; IBM's documentation lists the IDE\n")
	b.WriteString("policies only. Not yet verified against a live managed Bob install.\n")
	return b.String()
}
