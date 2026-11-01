package managedsettings

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/golden/*.golden from the generators")

// goldenCase is one generator x target OS rendering, pinned byte for byte.
type goldenCase struct {
	name   string
	render func(t *testing.T) []byte
}

// goldenOSes are the target OSes every generator is pinned under. linux and
// darwin share the POSIX form, so their goldens are identical by design;
// the empty value (an unset TargetOS) must equal them too.
var goldenOSes = []string{"linux", "darwin", "windows"}

func goldenCases() []goldenCase {
	var out []goldenCase
	for _, goos := range goldenOSes {
		out = append(out,
			goldenCase{"claude-code-" + goos, func(t *testing.T) []byte { return renderClaudeCodeGolden(t, goos, false) }},
			goldenCase{"claude-code-exclusive-" + goos, func(t *testing.T) []byte { return renderClaudeCodeGolden(t, goos, true) }},
			goldenCase{"codex-" + goos, func(t *testing.T) []byte { return renderCodexGolden(t, goos) }},
		)
	}
	out = append(out, goldenCase{"codex-managed-hooks", renderCodexManagedHooksGolden})
	out = append(out, goldenCase{"codex-enforce-provider", renderCodexEnforceProviderGolden})
	out = append(out, goldenCase{"claude-desktop-gateway", renderClaudeDesktopGolden})
	return out
}

// TestGeneratorGoldens_UnsetTargetOSIsPOSIX pins that a caller that never
// sets TargetOS (every caller before it existed) keeps the linux bytes.
func TestGeneratorGoldens_UnsetTargetOSIsPOSIX(t *testing.T) {
	if got, want := renderClaudeCodeGolden(t, "", false), renderClaudeCodeGolden(t, "linux", false); !bytes.Equal(got, want) {
		t.Errorf("claude-code: unset TargetOS differs from linux\n--- unset ---\n%s\n--- linux ---\n%s", got, want)
	}
	if got, want := renderCodexGolden(t, ""), renderCodexGolden(t, "linux"); !bytes.Equal(got, want) {
		t.Errorf("codex: unset TargetOS differs from linux\n--- unset ---\n%s\n--- linux ---\n%s", got, want)
	}
}

func renderClaudeCodeGolden(t *testing.T, goos string, exclusiveMCP bool) []byte {
	t.Helper()
	arts, err := GenerateClaudeCode(ClaudeCodeOptions{
		OTelGRPCEndpoint: "http://127.0.0.1:4317",
		AnthropicBaseURL: DefaultClaudeCodeProxyBaseURL,
		TargetOS:         goos,
		IncludeMCP:       true,
		IncludeTelemetry: true,
		ExclusiveMCP:     exclusiveMCP,
	})
	if err != nil {
		t.Fatalf("GenerateClaudeCode: %v", err)
	}
	var b bytes.Buffer
	b.WriteString("===== managed-mcp.json =====\n")
	b.Write(arts.ManagedMCPJSON)
	b.WriteString("===== managed-settings.json =====\n")
	b.Write(arts.ManagedSettingsJSON)
	b.WriteString("===== allowed-mcp-server.json =====\n")
	b.Write(arts.AllowedMCPServerEntryJSON)
	b.WriteString("===== README.md =====\n")
	b.WriteString(arts.Readme)
	return b.Bytes()
}

func renderCodexGolden(t *testing.T, goos string) []byte {
	t.Helper()
	arts, err := GenerateCodex(CodexOptions{
		OpenAIBaseURL:     DefaultCodexProxyBaseURL,
		TargetOS:          goos,
		IncludeMCP:        true,
		IncludeProxyRoute: true,
	})
	if err != nil {
		t.Fatalf("GenerateCodex: %v", err)
	}
	var b bytes.Buffer
	b.WriteString("===== managed_config.toml =====\n")
	b.Write(arts.ManagedConfigTOML)
	b.WriteString("===== requirements.toml =====\n")
	b.Write(arts.RequirementsTOML)
	b.WriteString("===== README.md =====\n")
	b.WriteString(arts.Readme)
	return b.Bytes()
}

// renderCodexManagedHooksGolden pins the --enforce-managed-hooks artifact set
// (CX-2): requirements.toml with Observer's managed [hooks] and the two
// scripts the admin deploys into the managed directory.
func renderCodexManagedHooksGolden(t *testing.T) []byte {
	t.Helper()
	arts, err := GenerateCodex(CodexOptions{
		OpenAIBaseURL:           DefaultCodexProxyBaseURL,
		IncludeMCP:              true,
		IncludeProxyRoute:       true,
		EnforceManagedHooksOnly: true,
		ManagedHooks:            testCodexManagedHooks(),
	})
	if err != nil {
		t.Fatalf("GenerateCodex: %v", err)
	}
	var b bytes.Buffer
	b.WriteString("===== requirements.toml =====\n")
	b.Write(arts.RequirementsTOML)
	for _, s := range arts.HookScripts {
		b.WriteString("===== " + s.Name + " -> " + s.DeployPath + " =====\n")
		// .gitattributes stores goldens LF-only: spell the .cmd script's
		// CRLF line ends out so the pin survives a checkout.
		b.Write(bytes.ReplaceAll(s.Body, []byte("\r\n"), []byte("<CRLF>\n")))
	}
	b.WriteString("===== README.md =====\n")
	b.WriteString(arts.Readme)
	return b.Bytes()
}

// renderCodexEnforceProviderGolden pins the --enforce-proxy-provider
// requirements.toml and README (CX-3), together with managed hooks so the
// order of the top-level keys before every table is pinned too.
func renderCodexEnforceProviderGolden(t *testing.T) []byte {
	t.Helper()
	arts, err := GenerateCodex(CodexOptions{
		OpenAIBaseURL:           DefaultCodexProxyBaseURL,
		IncludeProxyRoute:       true,
		EnforceProxyProvider:    true,
		EnforceManagedHooksOnly: true,
		ManagedHooks:            testCodexManagedHooks(),
	})
	if err != nil {
		t.Fatalf("GenerateCodex: %v", err)
	}
	var b bytes.Buffer
	b.WriteString("===== requirements.toml =====\n")
	b.Write(arts.RequirementsTOML)
	b.WriteString("===== README.md =====\n")
	b.WriteString(arts.Readme)
	return b.Bytes()
}

// renderClaudeDesktopGolden pins the Claude Desktop gateway route (CC-1b):
// the Desktop policy layer on every channel, and the README.
func renderClaudeDesktopGolden(t *testing.T) []byte {
	t.Helper()
	arts, err := GenerateClaudeDesktop(ClaudeDesktopOptions{
		GatewayRoute:            true,
		CredentialHelper:        "/usr/local/bin/org-gateway-key",
		CredentialHelperWindows: `C:\Program Files\Org\gateway-key.exe`,
		CredentialHelperArgs:    []string{"--profile", "observer"},
	})
	if err != nil {
		t.Fatalf("GenerateClaudeDesktop: %v", err)
	}
	var b bytes.Buffer
	for _, a := range arts.Artifacts {
		b.WriteString("===== " + a.Name + " (" + string(a.Channel) + ") =====\n")
		b.WriteString(strings.ReplaceAll(a.Content, "\r\n", "<CRLF>\n"))
		b.WriteString("\n")
	}
	b.WriteString("===== README.md =====\n")
	b.WriteString(arts.Readme)
	return b.Bytes()
}

// TestGeneratorGoldens pins every generator x target OS artifact set byte
// for byte, so a change to the written config shape is a reviewable diff.
// Regenerate with: go test ./internal/managedsettings -run TestGeneratorGoldens -update
func TestGeneratorGoldens(t *testing.T) {
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.render(t)
			path := filepath.Join("testdata", "golden", tc.name+".golden")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil { //nolint:gosec // G306: test golden fixture, not a secret.
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (regenerate with -update): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s drifted from %s (regenerate with -update if intended)\n--- got ---\n%s\n--- want ---\n%s", tc.name, path, got, want)
			}
		})
	}
}
