package managedsettings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Claude Desktop gateway route (surface-gap CC-1b / OBS-8c, decision D1).
//
// The Desktop Code tab ignores every settings-file ANTHROPIC_BASE_URL: under
// a Claude-account sign-in the app sets that variable itself, and a launch
// value beats a settings file. Its only route is its third-party gateway
// mode (inferenceProvider gateway, inferenceGatewayBaseUrl), which needs a
// gateway credential and drops Anthropic-hosted cloud environments and
// Remote Control (https://code.claude.com/docs/en/llm-gateway-connect,
// "Desktop app"). This generator renders that mode into the Desktop's own
// managed policy layer (cowork/managed-policy: the Linux root-owned file,
// the com.anthropic.claudefordesktop profile and the HKLM registry import),
// through the same placement walk lever A uses, so the channels, their
// strengths and the install steps have one owner.
//
// It continues the Claude Code CLI route policy for the desktop: on an
// org-managed node the org admin decides. It is an explicit admin option
// (GatewayRoute) and its README says the route is not live-verified: live
// check LC2 (is a loopback inferenceGatewayBaseUrl accepted, and does the
// proxy forward the gateway credential) has not run. The credential is
// never in the artifact: the Desktop runs an admin-deployed helper that
// prints it (inferenceCredentialKind helper-script).

// ClaudeDesktopLiveCheck is the live check the gateway route waits on.
const ClaudeDesktopLiveCheck = "LC2"

// ClaudeDesktopAuthSchemes is the closed set inferenceGatewayAuthScheme
// takes (the catalogue's enum).
var ClaudeDesktopAuthSchemes = []string{"x-api-key", "bearer"}

// DefaultClaudeDesktopAuthScheme is x-api-key: Observer's proxy forwards the
// header upstream, and an Anthropic API key travels as x-api-key.
const DefaultClaudeDesktopAuthScheme = "x-api-key"

// ErrClaudeDesktopGatewayNotChosen refuses a generation without the explicit
// admin option.
var ErrClaudeDesktopGatewayNotChosen = errors.New("managedsettings: the Claude Desktop gateway route is an explicit admin option " +
	"(not live-verified, " + ClaudeDesktopLiveCheck + "): set GatewayRoute (--desktop-gateway-route)")

// ErrClaudeDesktopNoHelper refuses the route without a credential helper:
// gateway mode needs a credential and Observer never writes a key.
var ErrClaudeDesktopNoHelper = errors.New("managedsettings: the Claude Desktop gateway route needs a credential helper " +
	"(an absolute path to an executable that prints the gateway credential); Observer never writes a key into the policy")

// ClaudeDesktopOptions configures the Claude Desktop gateway route.
type ClaudeDesktopOptions struct {
	// GatewayRoute is the explicit admin option; nothing is generated
	// without it.
	GatewayRoute bool
	// GatewayBaseURL is inferenceGatewayBaseUrl: the node proxy by default
	// (DefaultClaudeCodeProxyBaseURL), or an org gateway.
	GatewayBaseURL string
	// CredentialHelper and CredentialHelperWindows are the absolute paths of
	// the executable that prints the gateway credential (POSIX and
	// Windows). One is required.
	CredentialHelper, CredentialHelperWindows string
	// CredentialHelperArgs are its arguments. Optional.
	CredentialHelperArgs []string
	// AuthScheme is inferenceGatewayAuthScheme ("" = x-api-key).
	AuthScheme string
	// Identifier is the profile id stem ("" = DefaultIdentifier).
	Identifier string
}

// ClaudeDesktopArtifacts is the generated output: the Desktop policy layer's
// artifacts (file, profile, registry import) and a README.
type ClaudeDesktopArtifacts struct {
	Artifacts []Artifact
	Placed    []Placed
	Readme    string
}

// claudeDesktopTool is the catalogue tool the Desktop policy keys live
// under.
const claudeDesktopTool = "cowork"

// GenerateClaudeDesktop renders the Claude Desktop gateway route.
func GenerateClaudeDesktop(opts ClaudeDesktopOptions) (ClaudeDesktopArtifacts, error) {
	if !opts.GatewayRoute {
		return ClaudeDesktopArtifacts{}, ErrClaudeDesktopGatewayNotChosen
	}
	base := strings.TrimSpace(opts.GatewayBaseURL)
	if base == "" {
		base = DefaultClaudeCodeProxyBaseURL
	}
	if u, err := url.Parse(base); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ClaudeDesktopArtifacts{}, fmt.Errorf("managedsettings: Claude Desktop gateway base URL %q is not an http(s) URL", base)
	}
	helper, helperWin := strings.TrimSpace(opts.CredentialHelper), strings.TrimSpace(opts.CredentialHelperWindows)
	if helper == "" && helperWin == "" {
		return ClaudeDesktopArtifacts{}, ErrClaudeDesktopNoHelper
	}
	if helper != "" && !strings.HasPrefix(helper, "/") {
		return ClaudeDesktopArtifacts{}, fmt.Errorf("managedsettings: credential helper %q must be an absolute POSIX path", helper)
	}
	if helperWin != "" && !isAbsWindowsPath(helperWin) {
		return ClaudeDesktopArtifacts{}, fmt.Errorf("managedsettings: Windows credential helper %q must be an absolute Windows path (C:\\...)", helperWin)
	}
	scheme := strings.TrimSpace(opts.AuthScheme)
	if scheme == "" {
		scheme = DefaultClaudeDesktopAuthScheme
	}
	if !contains(ClaudeDesktopAuthSchemes, scheme) {
		return ClaudeDesktopArtifacts{}, fmt.Errorf("managedsettings: gateway auth scheme %q is not one of %s", scheme, strings.Join(ClaudeDesktopAuthSchemes, ", "))
	}

	type policyValue struct {
		key string
		v   any
	}
	values := []policyValue{
		{"inferenceProvider", "gateway"},
		{"inferenceGatewayBaseUrl", base},
		{"inferenceGatewayAuthScheme", scheme},
		{"inferenceCredentialKind", "helper-script"},
	}
	if helper != "" {
		values = append(values, policyValue{"inferenceCredentialHelper", helper})
	}
	if helperWin != "" {
		values = append(values, policyValue{"inferenceCredentialHelperWindows", helperWin})
	}
	if len(opts.CredentialHelperArgs) > 0 {
		values = append(values, policyValue{"inferenceCredentialHelperArgs", opts.CredentialHelperArgs})
	}
	body := orgcontract.AgentConfigPolicyBody{}
	for _, kv := range values {
		raw, err := json.Marshal(kv.v)
		if err != nil {
			return ClaudeDesktopArtifacts{}, fmt.Errorf("managedsettings: encode %s: %w", kv.key, err)
		}
		body.Directives = append(body.Directives, orgcontract.AgentConfigDirective{
			Setting: claudeDesktopTool + "/" + kv.key, Value: raw, Mode: orgcontract.AgentConfigModeEnforced,
		})
	}
	bundle, err := FromPolicy(PolicyInput{Body: body, Audience: "Claude Desktop gateway route", Identifier: opts.Identifier})
	if err != nil {
		return ClaudeDesktopArtifacts{}, err
	}
	if len(bundle.Unplaced) > 0 {
		return ClaudeDesktopArtifacts{}, fmt.Errorf("managedsettings: Claude Desktop policy key %s not placed: %s", bundle.Unplaced[0].Setting, bundle.Unplaced[0].Reason)
	}
	var out ClaudeDesktopArtifacts
	for _, t := range bundle.Tools {
		if t.Tool == claudeDesktopTool {
			out.Placed = t.Placed
			for _, a := range t.Artifacts {
				if claudeDesktopArtifactHasHelper(a, helper, helperWin) {
					out.Artifacts = append(out.Artifacts, a)
				}
			}
		}
	}
	if len(out.Artifacts) == 0 {
		return ClaudeDesktopArtifacts{}, fmt.Errorf("managedsettings: the Claude Desktop policy layer rendered no artifact")
	}
	out.Readme = claudeDesktopReadme(base, scheme, helper, helperWin, out.Artifacts)
	return out, nil
}

// claudeDesktopArtifactHasHelper reports whether every OS an artifact
// deploys to has its credential helper: the POSIX helper for Linux and
// macOS, the Windows helper for Windows. An artifact for an OS without one
// is dropped, or it would switch gateway mode on there with no credential
// source (the Desktop could no longer reach the model).
func claudeDesktopArtifactHasHelper(a Artifact, helper, helperWin string) bool {
	if len(a.OS) == 0 {
		return false
	}
	for _, o := range a.OS {
		switch {
		case o == "windows" && helperWin == "":
			return false
		case o != "windows" && helper == "":
			return false
		}
	}
	return true
}

// claudeDesktopReadme explains the route, its trade-off and its live check.
func claudeDesktopReadme(base, scheme, helper, helperWin string, arts []Artifact) string {
	var b strings.Builder
	b.WriteString("# Observer gateway route for Claude Desktop\n\n")
	b.WriteString("**Not live-verified (" + ClaudeDesktopLiveCheck + ").** Nobody has yet confirmed that Claude Desktop accepts\n")
	b.WriteString(fmt.Sprintf("`%s` as `inferenceGatewayBaseUrl` and that the proxy forwards the gateway\n", base))
	b.WriteString("credential upstream. Deploy it to one machine and check that a Code-tab session\n")
	b.WriteString("lands `api_turns` rows before a fleet rollout.\n\n")
	b.WriteString("The Desktop Code tab ignores `ANTHROPIC_BASE_URL` from every settings file,\n")
	b.WriteString("managed ones included: its only route is gateway mode. This policy sets\n")
	b.WriteString(fmt.Sprintf("`inferenceProvider = gateway`, `inferenceGatewayBaseUrl = %s`,\n", base))
	b.WriteString(fmt.Sprintf("`inferenceGatewayAuthScheme = %s` and `inferenceCredentialKind = helper-script`.\n\n", scheme))
	b.WriteString("## What it costs\n\n")
	b.WriteString(integration.RouteTradeoff(claudeDesktopTool) + "\n")
	b.WriteString("Use it for an API-key or org-gateway organization; a fleet that signs in to\n")
	b.WriteString("claude.ai keeps the direct route.\n\n")
	b.WriteString("## The credential\n\n")
	b.WriteString("Observer never writes a key into the policy. The Desktop runs the helper you\n")
	b.WriteString("deploy and sends what it prints as the gateway credential:\n\n")
	if helper != "" {
		b.WriteString(fmt.Sprintf("- Linux and macOS: `%s`\n", helper))
	}
	if helperWin != "" {
		b.WriteString(fmt.Sprintf("- Windows: `%s`\n", helperWin))
	}
	switch {
	case helper == "":
		b.WriteString("\nNo Linux / macOS helper was given, so no Linux file or macOS profile is generated:\n")
		b.WriteString("those machines keep the direct route.\n")
	case helperWin == "":
		b.WriteString("\nNo Windows helper was given, so no Windows registry import is generated: Windows\n")
		b.WriteString("machines keep the direct route.\n")
	}
	b.WriteString("\nKeep the helper administrator-owned: it runs on every launch. The proxy must be\n")
	b.WriteString("running on the node; with it down, Desktop inference fails instead of going\n")
	b.WriteString("direct.\n\n")
	b.WriteString("## Deploy (one channel per machine)\n\n")
	for _, a := range arts {
		for _, st := range a.Install {
			where := st.Path
			if where == "" {
				where = string(a.Channel)
			}
			b.WriteString(fmt.Sprintf("- `%s` (%s, %s):\n", a.Name, st.OS, where))
			for _, step := range st.Steps {
				b.WriteString("  - " + step + "\n")
			}
		}
	}
	return b.String()
}
