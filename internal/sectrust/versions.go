package sectrust

import (
	"strconv"
	"strings"
)

// Agent version hygiene (security pillar plan section 5.1 item 4): a
// CVE-to-tool-version table shipped as data, compared with a session's
// recorded tool_version. Later a signed feed (plan section 8.5). Each row
// names the integration-registry tool id, the first fixed version, and
// where the fixed version was read; a row is added only when the fixed
// version for the surface Observer records is published.
//
// Not listed, on purpose: CVE-2025-53773 (Copilot auto-approve). Microsoft
// published the fix as Visual Studio 2022 17.14.12, not as a VS Code or
// Copilot Chat extension version, which is what the copilot adapter
// records; a row would compare against the wrong product.

// VulnerableVersion is one row of the table.
type VulnerableVersion struct {
	// Tool is the integration-registry tool id.
	Tool string
	CVE  string
	// FixedIn is the first fixed version; every version below it is
	// affected.
	FixedIn string
	// Summary says what the flaw lets a repository do.
	Summary string
	// Source is where the fixed version was read, and Grounded when.
	Source   string
	Grounded string
}

// vulnerableVersions is the table, one row per (tool, CVE).
var vulnerableVersions = []VulnerableVersion{
	{
		Tool: "claude-code", CVE: "CVE-2025-59536", FixedIn: "1.0.111",
		Summary: "a project's code could run before the startup trust dialog was accepted",
		Source:  "https://osv.dev/vulnerability/CVE-2025-59536", Grounded: "2026-10-20",
	},
	{
		Tool: "claude-code", CVE: "CVE-2026-21852", FixedIn: "2.0.65",
		Summary: "a repository setting ANTHROPIC_BASE_URL could send API requests, and the key, before the trust prompt",
		Source:  "https://advisories.gitlab.com/pkg/npm/@anthropic-ai/claude-code/CVE-2026-21852/", Grounded: "2026-10-20",
	},
	{
		Tool: "codex", CVE: "CVE-2025-61260", FixedIn: "0.23.0",
		Summary: "a repository .env could move CODEX_HOME into the project and start its MCP servers",
		Source:  "https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/", Grounded: "2026-10-20",
	},
	{
		Tool: "codex", CVE: "CVE-2026-19592", FixedIn: "0.131.0",
		Summary: "a repository-local core.fsmonitor ran a helper outside the sandbox while Codex read git metadata",
		Source:  "https://app.opencve.io/cve/CVE-2026-19592", Grounded: "2026-10-20",
	},
	{
		Tool: "cursor", CVE: "CVE-2025-54136", FixedIn: "1.3",
		Summary: "an approved MCP configuration could be swapped for a malicious one without a new approval (MCPoison)",
		Source:  "https://www.tenable.com/cve/CVE-2025-54136", Grounded: "2026-10-20",
	},
}

// VulnerableVersions returns the table (a copy).
func VulnerableVersions() []VulnerableVersion {
	return append([]VulnerableVersion(nil), vulnerableVersions...)
}

// KnownVulnerable returns the rows whose flaw affects tool at version. A
// version that does not start with a dotted number (empty, a build name)
// matches nothing: unknown is never reported as vulnerable or as safe.
func KnownVulnerable(tool, version string) []VulnerableVersion {
	v, ok := parseVersion(version)
	if !ok {
		return nil
	}
	var out []VulnerableVersion
	for _, r := range vulnerableVersions {
		if r.Tool != tool {
			continue
		}
		fixed, ok := parseVersion(r.FixedIn)
		if ok && compareVersions(v, fixed) < 0 {
			out = append(out, r)
		}
	}
	return out
}

// parseVersion reads the leading dotted number of s ("v2.0.64 (Claude
// Code)" is 2.0.64), at most four parts.
func parseVersion(s string) ([]int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	end := 0
	for end < len(s) && (s[end] == '.' || (s[end] >= '0' && s[end] <= '9')) {
		end++
	}
	parts := strings.Split(strings.Trim(s[:end], "."), ".")
	if len(parts) == 0 || parts[0] == "" || len(parts) > 4 {
		return nil, false
	}
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// compareVersions compares two parsed versions, a missing part reading as
// zero.
func compareVersions(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
