package toolinstall

import (
	"errors"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestPlanUninstall is the install -> uninstall argv table, one row per
// channel shape the registry actually ships (plus the localized npm prefix
// the dashboard's permission-safe plan writes, and an absolute argv[0]).
func TestPlanUninstall(t *testing.T) {
	cases := []struct {
		name    string
		channel string
		install []string
		want    []string
		display string
		pkg     string
	}{
		{
			name: "npm plain global", channel: "npm",
			install: []string{"npm", "install", "-g", "@anthropic-ai/claude-code"},
			want:    []string{"npm", "uninstall", "--global", "@anthropic-ai/claude-code"},
			display: "npm uninstall --global @anthropic-ai/claude-code",
			pkg:     "@anthropic-ai/claude-code",
		},
		{
			name: "npm dist-tag stripped", channel: "npm",
			install: []string{"npm", "install", "-g", "opencode-ai@latest"},
			want:    []string{"npm", "uninstall", "--global", "opencode-ai"},
			display: "npm uninstall --global opencode-ai",
			pkg:     "opencode-ai",
		},
		{
			name: "npm scoped with version", channel: "npm",
			install: []string{"npm", "install", "-g", "@qwen-code/qwen-code@latest"},
			want:    []string{"npm", "uninstall", "--global", "@qwen-code/qwen-code"},
			display: "npm uninstall --global @qwen-code/qwen-code",
			pkg:     "@qwen-code/qwen-code",
		},
		{
			name: "npm install-only flags dropped", channel: "npm",
			install: []string{"npm", "install", "-g", "--allow-scripts=openclaw", "openclaw@latest"},
			want:    []string{"npm", "uninstall", "--global", "openclaw"},
			display: "npm uninstall --global openclaw",
			pkg:     "openclaw",
		},
		{
			name: "npm ignore-scripts dropped", channel: "npm",
			install: []string{"npm", "install", "-g", "--ignore-scripts", "@earendil-works/pi-coding-agent"},
			want:    []string{"npm", "uninstall", "--global", "@earendil-works/pi-coding-agent"},
			display: "npm uninstall --global @earendil-works/pi-coding-agent",
			pkg:     "@earendil-works/pi-coding-agent",
		},
		{
			name: "npm localized prefix kept, absolute program kept", channel: "npm",
			install: []string{"/home/u/.nvm/versions/node/v22/bin/npm", "install", "--global", "--prefix", "/home/u/.local", "cline"},
			want:    []string{"/home/u/.nvm/versions/node/v22/bin/npm", "uninstall", "--global", "--prefix", "/home/u/.local", "cline"},
			display: "npm uninstall --global --prefix /home/u/.local cline",
			pkg:     "cline",
		},
		{
			name: "uv tool", channel: "uv",
			install: []string{"uv", "tool", "install", "mistral-vibe"},
			want:    []string{"uv", "tool", "uninstall", "mistral-vibe"},
			display: "uv tool uninstall mistral-vibe",
			pkg:     "mistral-vibe",
		},
		{
			name: "uv specifier stripped", channel: "uv",
			install: []string{"uv", "tool", "install", "--python", "3.12", "aider-chat[playwright]>=0.80"},
			want:    []string{"uv", "tool", "uninstall", "aider-chat"},
			display: "uv tool uninstall aider-chat",
			pkg:     "aider-chat",
		},
		{
			name: "brew formula", channel: "brew",
			install: []string{"brew", "install", "block-goose-cli"},
			want:    []string{"brew", "uninstall", "block-goose-cli"},
			display: "brew uninstall block-goose-cli",
			pkg:     "block-goose-cli",
		},
		{
			name: "brew tap formula", channel: "brew",
			install: []string{"brew", "install", "Kilo-Org/tap/kilo"},
			want:    []string{"brew", "uninstall", "Kilo-Org/tap/kilo"},
			display: "brew uninstall Kilo-Org/tap/kilo",
			pkg:     "Kilo-Org/tap/kilo",
		},
		{
			name: "brew cask kept", channel: "brew",
			install: []string{"brew", "install", "--cask", "cursor"},
			want:    []string{"brew", "uninstall", "--cask", "cursor"},
			display: "brew uninstall --cask cursor",
			pkg:     "cursor",
		},
		{
			name: "winget positional id", channel: "winget",
			install: []string{"winget", "install", "Anthropic.ClaudeCode"},
			want:    []string{"winget", "uninstall", "--id", "Anthropic.ClaudeCode", "--exact"},
			display: "winget uninstall --id Anthropic.ClaudeCode --exact",
			pkg:     "Anthropic.ClaudeCode",
		},
		{
			name: "winget --id -e --source", channel: "winget",
			install: []string{"winget", "install", "--id", "Anysphere.Cursor", "-e", "--source", "winget"},
			want:    []string{"winget", "uninstall", "--id", "Anysphere.Cursor", "--exact"},
			display: "winget uninstall --id Anysphere.Cursor --exact",
			pkg:     "Anysphere.Cursor",
		},
		{
			name: "scoop", channel: "scoop",
			install: []string{"scoop", "install", "opencode"},
			want:    []string{"scoop", "uninstall", "opencode"},
			display: "scoop uninstall opencode",
			pkg:     "opencode",
		},
		{
			name: "scoop bucket + version stripped", channel: "scoop",
			install: []string{"scoop", "install", "extras/opencode@1.2.3"},
			want:    []string{"scoop", "uninstall", "opencode"},
			display: "scoop uninstall opencode",
			pkg:     "opencode",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PlanUninstall(tc.channel, tc.install)
			if err != nil {
				t.Fatalf("PlanUninstall: %v", err)
			}
			if !reflect.DeepEqual(got.Argv, tc.want) {
				t.Errorf("argv = %q, want %q", got.Argv, tc.want)
			}
			if got.Display != tc.display {
				t.Errorf("display = %q, want %q", got.Display, tc.display)
			}
			if got.Package != tc.pkg {
				t.Errorf("package = %q, want %q", got.Package, tc.pkg)
			}
			if p := PackageOf(tc.channel, tc.install); p != tc.pkg {
				t.Errorf("PackageOf = %q, want %q", p, tc.pkg)
			}
		})
	}
}

// TestPlanUninstallRefuses: a channel with no defined uninstall, an unknown
// channel, and argv that does not match its row are all REFUSED — never a
// guessed command.
func TestPlanUninstallRefuses(t *testing.T) {
	cases := []struct {
		name    string
		channel string
		install []string
		want    error
	}{
		{"vendor script (bash)", "script", []string{"bash", "-lc", "curl -fsSL https://claude.ai/install.sh | bash"}, ErrNoDefinedUninstall},
		{"vendor script (powershell)", "script", []string{"powershell", "-Command", "irm https://claude.ai/install.ps1 | iex"}, ErrNoDefinedUninstall},
		{"unknown channel", "choco", []string{"choco", "install", "x"}, ErrUnknownChannel},
		{"empty channel", "", []string{"npm", "install", "-g", "x"}, ErrUnknownChannel},
		{"wrong verb", "npm", []string{"npm", "ci"}, ErrUnrecognizedArgv},
		{"no package", "npm", []string{"npm", "install", "-g"}, ErrUnrecognizedArgv},
		{"two packages", "npm", []string{"npm", "install", "-g", "a", "b"}, ErrUnrecognizedArgv},
		{"uv missing tool verb", "uv", []string{"uv", "pip", "install", "x"}, ErrUnrecognizedArgv},
		{"prefix without value", "npm", []string{"npm", "install", "-g", "x", "--prefix"}, ErrUnrecognizedArgv},
		{"empty argv", "brew", nil, ErrUnrecognizedArgv},
		{"empty program", "brew", []string{"", "install", "x"}, ErrUnrecognizedArgv},
		{"winget id and positional", "winget", []string{"winget", "install", "--id", "A.B", "C.D"}, ErrUnrecognizedArgv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PlanUninstall(tc.channel, tc.install)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if HasDefinedUninstall("script") {
		t.Error("script must not report a defined uninstall")
	}
	if GuidanceFor("script") != NoDefinedUninstallGuidance {
		t.Error("script must carry the honest guidance")
	}
	if GuidanceFor("npm") != "" {
		t.Error("npm has a command; guidance must be empty")
	}
}

// TestChannelTableCoversRegistry pins the ONE-OWNER rule: every install
// channel the integration registry ships (adapter rows AND GUI launch rows)
// has a row in the channel table, and every non-script registry install hint
// derives an uninstall cleanly — so a newly grounded install can never land
// without an uninstall decision, and none of today's hints silently falls back
// to "unsupported".
func TestChannelTableCoversRegistry(t *testing.T) {
	var hints []integration.InstallHint
	for _, c := range integration.Capabilities() {
		if c.Binary != nil {
			hints = append(hints, c.Binary.Installs...)
		}
	}
	for _, g := range integration.GUILaunchables() {
		hints = append(hints, g.Spec.Binary.Installs...)
	}
	if len(hints) == 0 {
		t.Fatal("no install hints found in the registry")
	}
	for _, h := range hints {
		if _, ok := channelTable[h.Channel]; !ok {
			t.Errorf("channel %q (%s) has no row in the toolinstall channel table", h.Channel, h.Display)
			continue
		}
		_, err := PlanUninstall(h.Channel, h.Argv)
		if HasDefinedUninstall(h.Channel) {
			if err != nil {
				t.Errorf("%s: %q: %v", h.Channel, h.Display, err)
			}
		} else if !errors.Is(err, ErrNoDefinedUninstall) {
			t.Errorf("%s: %q: want ErrNoDefinedUninstall, got %v", h.Channel, h.Display, err)
		}
	}
}

// TestOSPackageManagerChannels is one row per OS package-manager channel: the
// argv InstallArgvFor builds reads back through PlanUninstall into a plain
// remove under the same sudo, never a purge or an autoremove.
func TestOSPackageManagerChannels(t *testing.T) {
	cases := []struct {
		channel   string
		install   []string
		uninstall []string
		display   string
	}{
		{"apt", []string{"sudo", "apt-get", "install", "-y", "bubblewrap"}, []string{"sudo", "apt-get", "remove", "-y", "bubblewrap"}, "sudo apt-get remove -y bubblewrap"},
		{"dnf", []string{"sudo", "dnf", "install", "-y", "bubblewrap"}, []string{"sudo", "dnf", "remove", "-y", "bubblewrap"}, "sudo dnf remove -y bubblewrap"},
		{"pacman", []string{"sudo", "pacman", "-S", "--needed", "--noconfirm", "bubblewrap"}, []string{"sudo", "pacman", "-R", "--noconfirm", "bubblewrap"}, "sudo pacman -R --noconfirm bubblewrap"},
		{"zypper", []string{"sudo", "zypper", "install", "-y", "bubblewrap"}, []string{"sudo", "zypper", "remove", "-y", "bubblewrap"}, "sudo zypper remove -y bubblewrap"},
		{"apk", []string{"sudo", "apk", "add", "bubblewrap"}, []string{"sudo", "apk", "del", "bubblewrap"}, "sudo apk del bubblewrap"},
	}
	for _, tc := range cases {
		t.Run(tc.channel, func(t *testing.T) {
			if !ElevatedChannel(tc.channel) {
				t.Errorf("%s must be Elevated", tc.channel)
			}
			if !HasDefinedUninstall(tc.channel) {
				t.Errorf("%s must have a defined uninstall", tc.channel)
			}
			pm, ok := PackageManagerByName(tc.channel)
			if !ok {
				t.Fatalf("PackageManagerByName(%q) not found", tc.channel)
			}
			ch, argv, ok := InstallArgvFor(pm, []string{"bubblewrap"})
			if !ok || ch != tc.channel || !reflect.DeepEqual(argv, tc.install) {
				t.Fatalf("InstallArgvFor = (%q, %q, %v), want (%q, %q, true)", ch, argv, ok, tc.channel, tc.install)
			}
			got, err := PlanUninstall(tc.channel, argv)
			if err != nil {
				t.Fatalf("PlanUninstall: %v", err)
			}
			if !reflect.DeepEqual(got.Argv, tc.uninstall) || got.Display != tc.display || got.Package != "bubblewrap" {
				t.Errorf("uninstall = %q %q %q, want %q %q bubblewrap", got.Argv, got.Display, got.Package, tc.uninstall, tc.display)
			}
			for _, a := range got.Argv {
				switch a {
				case "purge", "autoremove", "-Rs", "-Rn", "-Rns", "--clean-deps", "--purge":
					t.Errorf("derived uninstall carries %q", a)
				}
			}
			if p := PackageOf(tc.channel, argv); p != "bubblewrap" {
				t.Errorf("PackageOf = %q", p)
			}
		})
	}
	if ElevatedChannel("npm") || ElevatedChannel("brew") || ElevatedChannel("nope") {
		t.Error("only the OS package managers are Elevated")
	}
}

// TestOSPackageManagerReadBack covers the read-back edges of the elevated
// channels: an absolute program, an install without sudo, two packages, and
// the refusals (a program that is not the channel's, sudo with nothing after).
func TestOSPackageManagerReadBack(t *testing.T) {
	cases := []struct {
		name    string
		channel string
		install []string
		want    []string
		err     error
	}{
		{"absolute program kept", "apt", []string{"sudo", "/usr/bin/apt-get", "install", "-y", "e2fsprogs"}, []string{"sudo", "/usr/bin/apt-get", "remove", "-y", "e2fsprogs"}, nil},
		{"absolute sudo kept", "dnf", []string{"/usr/bin/sudo", "dnf", "install", "-y", "virtiofsd"}, []string{"/usr/bin/sudo", "dnf", "remove", "-y", "virtiofsd"}, nil},
		{"no sudo stays without", "apk", []string{"apk", "add", "podman"}, []string{"apk", "del", "podman"}, nil},
		{"two packages", "apt", []string{"sudo", "apt-get", "install", "-y", "virtiofsd", "e2fsprogs"}, []string{"sudo", "apt-get", "remove", "-y", "virtiofsd", "e2fsprogs"}, nil},
		{"wrong program", "apt", []string{"sudo", "apt", "install", "-y", "bubblewrap"}, nil, ErrUnrecognizedArgv},
		{"sudo only", "zypper", []string{"sudo"}, nil, ErrUnrecognizedArgv},
		{"no package", "pacman", []string{"sudo", "pacman", "-S", "--needed"}, nil, ErrUnrecognizedArgv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PlanUninstall(tc.channel, tc.install)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("PlanUninstall: %v", err)
			}
			if !reflect.DeepEqual(got.Argv, tc.want) {
				t.Errorf("argv = %q, want %q", got.Argv, tc.want)
			}
		})
	}
}
