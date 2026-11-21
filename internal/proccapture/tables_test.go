package proccapture

import "testing"

// TestFoldTableRows is one case per fold-table row (plan §4.3), plus the
// near misses that must NOT fold.
func TestFoldTableRows(t *testing.T) {
	tb := compileTables(Config{ExtraFoldBasenames: []string{"MyHelper.exe"}})
	cases := []struct {
		exe, argv, parent string
		want              bool
	}{
		{"conhost.exe", "conhost.exe 0xffffffff -ForceV1", "docker.exe", true},
		{"docker-buildx.exe", "docker-buildx.exe docker-cli-plugin-metadata", "com.docker.backend.exe", true},
		{"docker-buildx.exe", "docker-buildx.exe build .", "docker.exe", false},
		{"git-credential-manager.exe", "git-credential-manager.exe get", "git.exe", true},
		{"docker-credential-desktop.exe", "docker-credential-desktop.exe list", "docker.exe", true},
		{"wslhost.exe", "wslhost.exe --vm-id x", "wsl.exe", true},
		{"wslhost.exe", "wslhost.exe --vm-id x", "explorer.exe", false},
		{"myhelper", "", "", true},
		{"go.exe", "go build", "bash.exe", false},
	}
	for _, tc := range cases {
		if _, got := tb.foldMatch(tc.exe, tc.argv, tc.parent); got != tc.want {
			t.Errorf("foldMatch(%q, %q, %q) = %v, want %v", tc.exe, tc.argv, tc.parent, got, tc.want)
		}
	}
	if len(foldTable) != 5 {
		t.Fatalf("fold table has %d rows; add a case above for each new row", len(foldTable))
	}
}

// TestServiceTable pins the built-in service table and its extension.
func TestServiceTable(t *testing.T) {
	tb := compileTables(Config{ExtraServiceBasenames: []string{"MyDaemon.exe"}})
	for _, exe := range []string{"Docker Desktop.exe", "com.docker.backend.exe", "Code.exe", "explorer.exe", "devenv.exe", "idea64.exe", "mydaemon"} {
		if !tb.isService(exe) {
			t.Errorf("%q should be a service", exe)
		}
	}
	for _, exe := range []string{"gopls", "tsserver", "node", "docker.exe"} {
		if tb.isService(exe) {
			t.Errorf("%q must not be a service", exe)
		}
	}
}

// TestNormalizeExe pins the folding the tables match on.
func TestNormalizeExe(t *testing.T) {
	for in, want := range map[string]string{
		"Docker Desktop.exe":              "docker desktop",
		`C:\Windows\System32\conhost.exe`: "conhost",
		"/usr/bin/go":                     "go",
		"CODE.EXE":                        "code",
	} {
		if got := NormalizeExe(in); got != want {
			t.Errorf("NormalizeExe(%q) = %q, want %q", in, got, want)
		}
	}
}
