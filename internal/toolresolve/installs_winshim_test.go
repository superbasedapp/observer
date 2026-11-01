package toolresolve

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestFilterInstallsNamesTheCmdShimOnWindows pins T-921: a Windows operator
// types the install hint into PowerShell, whose default execution policy
// refuses npm's `.ps1` shim, so the Display names `npm.cmd`. The Argv the
// guided install runs is untouched, and other OSes keep the bare form.
func TestFilterInstallsNamesTheCmdShimOnWindows(t *testing.T) {
	hints := []integration.InstallHint{
		{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "opencode-ai@latest"}, Display: "npm install -g opencode-ai@latest"},
		{OS: "windows", Channel: "winget", Display: "winget install SST.opencode"},
		{OS: "linux", Channel: "script", Display: "curl -fsSL https://opencode.ai/install | bash"},
	}
	cases := []struct {
		goos string
		want []string
	}{
		{"windows", []string{"npm.cmd install -g opencode-ai@latest", "winget install SST.opencode"}},
		{"linux", []string{"npm install -g opencode-ai@latest", "curl -fsSL https://opencode.ai/install | bash"}},
		{"darwin", []string{"npm install -g opencode-ai@latest"}},
	}
	for _, tc := range cases {
		t.Run(tc.goos, func(t *testing.T) {
			got := filterInstalls(hints, tc.goos)
			var displays []string
			for _, h := range got {
				displays = append(displays, h.Display)
			}
			if !reflect.DeepEqual(displays, tc.want) {
				t.Errorf("displays = %q, want %q", displays, tc.want)
			}
			if got[0].Argv[0] != "npm" {
				t.Errorf("argv[0] = %q, want the untouched npm", got[0].Argv[0])
			}
		})
	}
	if hints[0].Display != "npm install -g opencode-ai@latest" {
		t.Errorf("filterInstalls mutated the registry hint: %q", hints[0].Display)
	}
}
