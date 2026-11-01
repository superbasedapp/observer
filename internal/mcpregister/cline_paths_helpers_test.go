package mcpregister

import "github.com/marmutapp/superbased-observer/internal/mcp/locate"

// testClineMCPPath is locate.ClineMCPSettingsPath's path alone (the tests
// here set no relative relocation value).
func testClineMCPPath(home, goos string, getenv func(string) string) string {
	p, _ := locate.ClineMCPSettingsPath(home, goos, getenv)
	return p
}

// testClineDataDir is locate.ClineDataDir's directory alone.
func testClineDataDir(home, goos string, getenv func(string) string) string {
	d, _ := locate.ClineDataDir(home, goos, getenv)
	return d
}
