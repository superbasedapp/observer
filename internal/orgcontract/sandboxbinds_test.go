package orgcontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/publictree"
)

// TestSandboxSensitiveWriteBind is one case per rule row and its exceptions
// (the SBX-P1C merge bind decision, docs/security.md SBX-GOV-3).
func TestSandboxSensitiveWriteBind(t *testing.T) {
	node := SandboxBindHost{Home: "/data/dev", Known: true, LocalRWBinds: []string{"/data/dev/.config/gh"}}
	cases := []struct {
		name string
		p    string
		host SandboxBindHost
		want bool
	}{
		{"root", "/", SandboxBindHost{}, true},
		{"etc", "/etc", SandboxBindHost{}, true},
		{"under usr", "/usr/local/bin", SandboxBindHost{}, true},
		{"lib64", "/lib64/x", SandboxBindHost{}, true},
		{"proc", "/proc/self", SandboxBindHost{}, true},
		{"opt", "/opt/tools", SandboxBindHost{}, true},
		{"var", "/var/lib/docker", SandboxBindHost{}, true},
		{"var tmp is fine", "/var/tmp/cache", SandboxBindHost{}, false},
		{"tilde bashrc", "~/.bashrc", SandboxBindHost{}, true},
		{"home bashrc", "/home/alice/.bashrc", SandboxBindHost{}, true},
		{"mac ssh", "/Users/alice/.ssh/id_ed25519", SandboxBindHost{}, true},
		{"root aws", "/root/.aws", SandboxBindHost{}, true},
		{"fish config", "/home/alice/.config/fish/config.fish", SandboxBindHost{}, true},
		{"config itself", "/home/alice/.config", SandboxBindHost{}, true},
		{"config subdir left to the node", "/home/alice/.config/gh", SandboxBindHost{}, false},
		{"local bin", "/home/alice/.local/bin", SandboxBindHost{}, true},
		{"git credentials", "/home/alice/.git-credentials", SandboxBindHost{}, true},
		{"observer dir", "/home/alice/.observer", SandboxBindHost{}, true},
		{"observer workspaces", "/home/alice/.observer/workspaces/w1", SandboxBindHost{}, false},
		{"git hooks", "/srv/repo/.git/hooks", SandboxBindHost{}, true},
		{"git config", "/home/alice/proj/.git/config", SandboxBindHost{}, true},
		{"git objects are fine", "/home/alice/proj/.git/objects", SandboxBindHost{}, false},
		{"project dir", "/home/alice/proj", SandboxBindHost{}, false},
		{"home itself (holds .ssh, ruling P-050)", "/home/alice", SandboxBindHost{}, true},
		{"tilde itself", "~", SandboxBindHost{}, true},
		{"root home itself", "/root", SandboxBindHost{}, true},
		{"mac home itself", "/Users/alice", SandboxBindHost{}, true},
		{"the directory of homes", "/home", SandboxBindHost{}, true},
		{"the mac directory of homes", "/Users", SandboxBindHost{}, true},
		{"a parent of .local/bin", "/home/alice/.local", SandboxBindHost{}, true},
		{"local share is fine", "/home/alice/.local/share/app", SandboxBindHost{}, false},
		{"a .git directory", "/home/alice/proj/.git", SandboxBindHost{}, true},
		{"a project under tilde", "~/proj", SandboxBindHost{}, false},
		{"real home itself", "/data/dev", node, true},
		{"a parent of the real home", "/data", node, true},
		{"a parent of the real home is the node's call", "/data", SandboxBindHost{}, false},
		{"a sibling of the real home", "/data/other", node, false},
		{"srv", "/srv/cache", SandboxBindHost{}, false},
		{"real home ssh", "/data/dev/.ssh", node, true},
		{"real home config not bound locally", "/data/dev/.config/other", node, true},
		{"real home config bound locally", "/data/dev/.config/gh/hosts", node, false},
		{"real home project", "/data/dev/work", node, false},
	}
	for _, tc := range cases {
		if got := SandboxSensitiveWriteBind(tc.p, tc.host); got != tc.want {
			t.Errorf("%s (%s): got %v want %v", tc.name, tc.p, got, tc.want)
		}
	}
}

// TestSandboxSensitiveWriteBindCaseAndWSL (ruling P-054, SBX-P2E audit
// finding 7): the comparison folds case where the platform or the mount
// does (the server's view, a macOS node, any /mnt/<letter> path), WSL's
// Windows mounts are the POSIX locations' equivalents, and a Windows drive
// spelling is checked as its mount.
func TestSandboxSensitiveWriteBindCaseAndWSL(t *testing.T) {
	server := SandboxBindHost{}
	linux := SandboxBindHost{Home: "/home/dev", Known: true, CaseSensitive: true}
	mac := SandboxBindHost{Home: "/Users/dev", Known: true, LocalRWBinds: []string{"/Users/dev/.config/gh"}}
	// A Windows node (case-insensitive) names its home and its own binds
	// with the drive spelling (Windows 11 Pro rerun 2026-10-25, D5 group 4).
	win := SandboxBindHost{Home: "C:/Users/dev", Known: true, LocalRWBinds: []string{"C:/Users/dev/.config/gh"}}
	cases := []struct {
		name string
		p    string
		host SandboxBindHost
		want bool
	}{
		{"server: ssh in another case", "/home/alice/.SSH", server, true},
		{"server: mac home in another case", "/USERS/alice", server, true},
		{"server: mac ssh in another case", "/Users/Alice/.Ssh/id_ed25519", server, true},
		{"server: etc in another case", "/ETC/passwd", server, true},
		{"server: git hooks in another case", "/srv/repo/.GIT/Hooks", server, true},
		{"server: a project in another case", "/home/alice/Proj", server, false},
		{"/mnt holds the drives", "/mnt", server, true},
		{"a drive holds homes", "/mnt/c", server, true},
		{"a drive letter in upper case", "/mnt/C", server, true},
		{"the drive's Users", "/mnt/c/Users", server, true},
		{"a Windows home", "/mnt/c/Users/Alice", server, true},
		{"a Windows home's ssh", "/mnt/c/users/alice/.ssh", server, true},
		{"AppData", "/mnt/c/Users/alice/AppData", server, true},
		{"under AppData", "/mnt/c/Users/alice/AppData/Roaming/Code", server, true},
		{"a Windows home's config", "/mnt/c/Users/alice/.config", server, true},
		{"a Windows home's config subdir left to the node", "/mnt/c/Users/alice/.config/gh", server, false},
		{"a Windows home's bashrc", "/mnt/c/Users/alice/.BASHRC", server, true},
		{"a project under a Windows home", "/mnt/c/Users/alice/proj", server, false},
		{"a Windows repository's hooks", "/mnt/c/Users/alice/proj/.git/hooks", server, true},
		{"Windows", "/mnt/c/Windows", server, true},
		{"under Windows in upper case", "/mnt/c/WINDOWS/System32", server, true},
		{"Program Files", "/mnt/c/Program Files/App", server, true},
		{"Program Files (x86)", "/mnt/c/Program Files (x86)", server, true},
		{"data on another drive", "/mnt/d/data", server, false},
		{"a non-drive mount", "/mnt/data/cache", server, false},
		{"the wsl mount", "/mnt/wsl/x", server, false},
		{"a Windows drive spelling's ssh", "C:/Users/alice/.ssh", server, true},
		{"a Windows drive spelling's Windows", "c:/Windows", server, true},
		{"a Windows drive itself", "C:/", server, true},
		{"a Windows drive spelling's project", "D:/work/proj", server, false},
		{"linux: ssh in another case is another path", "/home/dev/.SSH", linux, false},
		{"linux: ssh", "/home/dev/.ssh", linux, true},
		{"linux: a drive mount still folds", "/mnt/c/Users/Dev/.SSH", linux, true},
		{"linux: AppData on a drive mount", "/mnt/c/users/dev/appdata", linux, true},
		{"linux: an upper-case HOME is not a home", "/HOME/dev", linux, false},
		{"mac: the real home in another case", "/users/DEV", mac, true},
		{"mac: ssh in another case", "/users/dev/.SSH", mac, true},
		{"mac: config not bound locally", "/Users/dev/.Config/other", mac, true},
		{"mac: config bound locally in another case", "/Users/dev/.config/GH/hosts", mac, false},
		{"mac: a project", "/Users/dev/Work", mac, false},
		{"windows: config bound locally", "C:/Users/dev/.config/gh/hosts", win, false},
		{"windows: config bound locally in another case", "c:/users/DEV/.config/GH/hosts", win, false},
		{"windows: config not bound locally", "C:/Users/dev/.config/other", win, true},
		{"windows: ssh", "C:/Users/dev/.ssh", win, true},
	}
	for _, tc := range cases {
		if got := SandboxSensitiveWriteBind(tc.p, tc.host); got != tc.want {
			t.Errorf("%s (%s): got %v want %v", tc.name, tc.p, got, tc.want)
		}
	}
}

// TestSandboxManagedLintRefusesSensitiveWriteBinds: the publish lint
// (Validate) names the reason for a sensitive write bind, `~/.bashrc`
// included; a read bind of the same path and a project write bind pass.
func TestSandboxManagedLintRefusesSensitiveWriteBinds(t *testing.T) {
	// "~" and "/" are ancestors of denied locations (ruling P-050).
	// The WSL drive mounts and the case variants are ruling P-054.
	for _, p := range []string{"~/.bashrc", "/home/alice/.ssh", "/etc", "/srv/repo/.git/hooks", "~", "/", "/home/alice",
		"/mnt", "/mnt/c", "/mnt/c/Users", "/mnt/c/Users/alice", "/mnt/c/Users/alice/.ssh", "/mnt/c/Users/alice/AppData/Roaming",
		"/mnt/c/Windows/Temp", "/mnt/c/Program Files/App", "/home/alice/.SSH", "/Users/Alice"} {
		_, err := DecodeSandboxManagedPolicy([]byte(`{"schema":"sbo-sandbox-managed-v1","node":{"extra_rw_binds":["` + p + `"]}}`))
		if err == nil || !strings.Contains(err.Error(), string(SandboxRefusedSensitivePath)) {
			t.Errorf("%s: want refused as %s, got %v", p, SandboxRefusedSensitivePath, err)
		}
	}
	if _, err := DecodeSandboxManagedPolicy([]byte(`{"schema":"sbo-sandbox-managed-v1","node":{"extra_ro_binds":["/home/alice/.ssh","/home/alice","/mnt/c/Users/alice"],"extra_rw_binds":["/home/alice/proj","/mnt/c/Users/alice/proj"]}}`)); err != nil {
		t.Fatalf("read-only binds (the home included) and a project write bind pass: %v", err)
	}
}

// TestSandboxManagedWorkspacesDirIsNotOnThePull: the managed-workspace root
// is node-local (SBX-P1C merge finding 3), refused by name at any level.
func TestSandboxManagedWorkspacesDirIsNotOnThePull(t *testing.T) {
	for _, body := range []string{
		`{"schema":"sbo-sandbox-managed-v1","node":{"workspaces_dir":"/srv/ws"}}`,
		`{"schema":"sbo-sandbox-managed-v1","workspaces_dir":"/srv/ws"}`,
	} {
		_, err := DecodeSandboxManagedPolicy([]byte(body))
		if err == nil || !strings.Contains(err.Error(), string(SandboxRefusedNotOnPull)) {
			t.Errorf("%s: want refused as %s, got %v", body, SandboxRefusedNotOnPull, err)
		}
	}
}

// TestSandboxRefusalWordingCoversTheClosedReasons: the web2 per-node panel
// words every closed node refusal reason (web2/src/lib/sandboxManaged.ts),
// and nothing else.
func TestSandboxRefusalWordingCoversTheClosedReasons(t *testing.T) {
	publictree.Skip(t, "web2/src/lib/sandboxManaged.ts")
	src, err := os.ReadFile(filepath.Join("..", "..", "web2", "src", "lib", "sandboxManaged.ts"))
	if err != nil {
		t.Fatalf("read the panel wording: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "SANDBOX_REFUSAL_REASONS: Record<string, string> = {")
	end := strings.Index(body[start:], "\n};")
	if start < 0 || end < 0 {
		t.Fatal("SANDBOX_REFUSAL_REASONS not found")
	}
	var got []string
	for _, line := range strings.Split(body[start:start+end], "\n")[1:] {
		if k, _, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && k != "" {
			got = append(got, k)
		}
	}
	if strings.Join(got, ",") != strings.Join(SandboxNodeRefusalReasons, ",") {
		t.Fatalf("web2 words %v, the closed reasons are %v", got, SandboxNodeRefusalReasons)
	}
}

// TestClampSandboxManagedRefused: one row per case of the clamp table.
func TestClampSandboxManagedRefused(t *testing.T) {
	in := []SandboxManagedRefusedKeyRow{
		{Key: "mask_paths", Reason: "not_absolute"},
		{Key: "mask_paths", Reason: "dot_dot_segment"},
		{Key: "workspaces_dir", Reason: "not_absolute"},
		{Key: "egress", Reason: "a free text reason"},
	}
	out := ClampSandboxManagedRefused(in)
	if len(out) != 1 || out[0] != in[0] {
		t.Fatalf("clamped %+v", out)
	}
	if got := EncodeSandboxManagedRefused(in); got != "mask_paths:not_absolute" {
		t.Fatalf("encoded %q", got)
	}
	if got := DecodeSandboxManagedRefused("mask_paths:not_absolute,x"); len(got) != 1 {
		t.Fatalf("decoded %+v", got)
	}
	if DecodeSandboxManagedRefused("") != nil {
		t.Fatal("an empty column decodes to nothing")
	}
}
